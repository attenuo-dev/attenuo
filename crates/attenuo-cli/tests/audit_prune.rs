//! `attenuo audit prune` against a running server with a file sink (design note
//! `docs/design/audit-retention.md`, section 10): the archive is written, verified and kept,
//! the prune commits, the shipped file holds both checkpoints and the anchor, the archives
//! and the retained export verify as one log with `audit verify --file ... --file ...`, and a
//! flipped byte in any file is reported at its seq. Then the refusals, which leave the server
//! as it was, and an export cut short, which leaves no file that looks complete.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

// The audit crate's record builders, under another name than this crate's `common`.
#[path = "../../attenuo-audit/tests/common/mod.rs"]
mod audit_common;
mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use attenuo_audit::{parse_shipped, parse_shipped_anchors, AuditSink};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{PruneMode, SinkKind, SinkSection};
use attenuo_server::{AppState, Config};
use attenuo_token::{Issuer, IssuerConfig};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use common::attenuo;

const ADMIN: &str = "audit-prune-test-admin";

/// A file-backed config with a checkpoint every 10 entries, a file sink, and `prune`.
fn config(dir: &Path, prune: PruneMode) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.audit.checkpoint_every = 10;
    let mut sink = SinkSection::new(SinkKind::File);
    sink.path = Some(dir.join("shipped.jsonl"));
    sink.initial_backoff_ms = 5;
    sink.max_backoff_seconds = 1;
    cfg.audit.sink = Some(sink);
    cfg.audit.retention.prune = prune;
    cfg.admin.token = Some(ADMIN.into());
    cfg.issuer.private_key_pem_path = Some(dir.join("issuer.pem"));
    cfg
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !f() {
        assert!(std::time::Instant::now() < end, "timed out");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

struct Server {
    dir: tempfile::TempDir,
    server: Spawned,
    state: Arc<AppState>,
}

impl Server {
    async fn start(prune: PruneMode) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), prune);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            server: spawn_router(router).await.unwrap(),
            state,
            dir,
        }
    }

    /// `n` records written 200 days ago (older than the 90-day minimum age), then wait until
    /// the sink has delivered the newest checkpoint.
    async fn fill(&self, n: usize) {
        let first = self.state.audit.head().unwrap().map_or(0, |h| h.seq);
        for i in 0..n {
            let mut r = audit_common::record(i);
            r.at = OffsetDateTime::now_utc() - Duration::days(200);
            self.state.audit.append(r).unwrap();
        }
        let last = ((first + n as u64) / 10) * 10;
        let sink = self.state.checkpoint_sink.as_ref().unwrap();
        wait_for(|| sink.delivered_through() >= Some(last)).await;
    }

    /// Finish the deletes of the last prune and wait until its anchor is delivered, so the
    /// next prune is not refused with `prune_in_progress` or `sink_behind`.
    async fn settle(&self) {
        attenuo_server::prune_audit_log(&self.state).await;
        let s = self.state.clone();
        wait_for(move || {
            s.audit
                .newest_anchor()
                .ok()
                .flatten()
                .is_some_and(|a| a.shipped_at.is_some())
        })
        .await;
        let head = self.state.audit.head().unwrap().unwrap().seq;
        let sink = self.state.checkpoint_sink.as_ref().unwrap();
        wait_for(|| sink.delivered_through() >= Some(head)).await;
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The CLI with the admin token and `--server` set.
    fn cli(&self) -> Command {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
            .args(["--server", &self.server.url("")]);
        c
    }

    fn first_retained(&self) -> u64 {
        self.state.audit.first_retained_seq().unwrap()
    }
}

/// Run the CLI off the async runtime (the server runs on it).
async fn run(cmd: Command) -> Output {
    let mut cmd = cmd;
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_exit(out: &Output, code: i32) -> String {
    let t = text(out);
    assert_eq!(out.status.code(), Some(code), "{t}");
    t
}

async fn prune(s: &Server, args: &[&str]) -> Output {
    let mut c = s.cli();
    c.args(["audit", "prune"]).args(args);
    run(c).await
}

async fn verify(s: &Server, files: &[&Path], extra: &[&str]) -> Output {
    let mut c = s.cli();
    c.args(["audit", "verify"]);
    for f in files {
        c.arg("--file").arg(f);
    }
    c.args(extra);
    run(c).await
}

async fn export_retained(s: &Server, out: &Path) {
    let mut c = s.cli();
    c.args(["audit", "export", "--out"]).arg(out);
    assert_exit(&run(c).await, 0);
}

/// A copy of `file` in which the entry at `seq` has one byte changed (its `reason` reads
/// `policy-allow` or `policy-deny`), still valid JSON.
fn flip(file: &Path, seq: u64, to: &Path) {
    let text = std::fs::read_to_string(file).unwrap();
    let mut done = false;
    let out: String = text
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            if !done && v["seq"] == seq && v.get("entry_hash").is_some() {
                done = true;
                let changed = l.replacen("\"policy_", "\"policy-", 1);
                assert_ne!(changed, l, "no byte to flip at seq {seq}");
                format!("{changed}\n")
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    assert!(done, "no entry at seq {seq} in {}", file.display());
    std::fs::write(to, out).unwrap();
}

/// The JWKS of a fresh key, which signed none of the server's checkpoints.
fn other_jwks(path: &Path) {
    let issuer = Issuer::generate(IssuerConfig {
        issuer: "https://other.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    });
    let keys: Vec<Value> = issuer
        .trusted_public_keys()
        .into_iter()
        .map(|(kid, pem)| {
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = STANDARD.decode(b64).unwrap();
            json!({"kty": "OKP", "crv": "Ed25519", "kid": kid,
                   "x": URL_SAFE_NO_PAD.encode(&der[der.len() - 32..])})
        })
        .collect();
    std::fs::write(path, json!({ "keys": keys }).to_string()).unwrap();
}

/// No file in `dir` whose name holds `.partial-`.
fn no_partial_files(dir: &Path) {
    for e in std::fs::read_dir(dir).unwrap() {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!name.contains(".partial-"), "left behind: {name}");
    }
}

#[tokio::test]
async fn a_prune_through_the_cli_end_to_end() {
    let s = Server::start(PruneMode::Manual).await;
    s.fill(35).await;
    let archive = s.path("archive-1.jsonl");

    // The dry run prints the plan and changes nothing.
    let out = prune(&s, &["--through", "27", "--dry-run"]).await;
    let t = assert_exit(&out, 0);
    assert!(t.contains("plan: prune seq 1..20 (20 entries)"), "{t}");
    assert!(t.contains("limited by: prune_not_at_checkpoint"), "{t}");
    assert!(t.contains("dry run: nothing was exported or pruned"), "{t}");
    assert_eq!(s.first_retained(), 1);

    let a = archive.to_str().unwrap();
    let out = prune(&s, &["--through", "27", "--archive", a]).await;
    let t = assert_exit(&out, 0);
    for want in [
        "seq 1..20, 20 entries, verified, sha256 ",
        "pruned through seq 20 (prune record at seq 36)",
        "checkpoint before: seq 35",
        "checkpoint after: seq 36",
        "previous boundary none",
        "being deleted in the background; reads already start at seq 21",
        "keep the archive off this host",
    ] {
        assert!(t.contains(want), "{want} not in {t}");
    }
    assert_eq!(s.first_retained(), 21);
    no_partial_files(s.dir.path());
    // Only the owner can read the archive (M7).
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&archive).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // The digest signed into the anchor is the archive's.
    let bytes = std::fs::read(&archive).unwrap();
    let digest = common::sha256_hex(std::str::from_utf8(&bytes).unwrap());
    let anchor = s.state.audit.newest_anchor().unwrap().unwrap().anchor;
    assert_eq!(anchor.archive_sha256.as_deref(), Some(digest.as_str()));
    assert!(t.contains(&format!("archive sha256 {digest}")), "{t}");

    // The shipped file holds both checkpoints and the anchor.
    s.settle().await;
    let shipped = std::fs::read_to_string(s.path("shipped.jsonl")).unwrap();
    let cps: Vec<u64> = parse_shipped(&shipped)
        .unwrap()
        .iter()
        .map(|l| l.checkpoint.seq)
        .collect();
    assert!(cps.contains(&35) && cps.contains(&36), "{cps:?}");
    let anchors = parse_shipped_anchors(&shipped).unwrap();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].1.anchor, anchor);

    // The live verify passes from the anchor.
    let mut c = s.cli();
    c.args(["audit", "verify"]);
    let t = assert_exit(&run(c).await, 0);
    assert!(t.contains("from seq 21 (pruned through 20"), "{t}");

    // The archive and the retained export, alone and as one log, with the shipped file.
    let retained = s.path("retained.jsonl");
    export_retained(&s, &retained).await;
    let shipped_path = s.path("shipped.jsonl");
    let sp = shipped_path.to_str().unwrap();
    let t = assert_exit(&verify(&s, &[&archive], &[]).await, 0);
    assert!(t.contains("export covers seq 1..20"), "{t}");
    let t = assert_exit(
        &verify(&s, &[&archive, &retained], &["--checkpoints", sp]).await,
        0,
    );
    for want in [
        "files link: 2 files hold seq 1..36 as one log",
        "all files: OK",
        "the file continues a pruned log",
        "shipped prune anchors: OK",
        "below it (pruned or archived)",
    ] {
        assert!(t.contains(want), "{want} not in {t}");
    }
    let out = verify(&s, &[&archive, &retained], &["--json"]).await;
    assert_exit(&out, 0);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["links"], json!([]));
    assert_eq!(v["files"][1]["from_anchor"], true);
    // Out of order, the files do not link, and the message names both.
    let t = assert_exit(&verify(&s, &[&retained, &archive], &[]).await, 2);
    assert!(t.contains("files do NOT link: "), "{t}");
    assert!(t.contains("retained.jsonl then "), "{t}");

    // A flipped byte in either file is reported at its seq, alone and in the pair.
    for (file, seq, name) in [
        (&archive, 7, "flipped-archive"),
        (&retained, 30, "flipped-retained"),
    ] {
        let bad = s.path(name);
        flip(file, seq, &bad);
        let t = assert_exit(&verify(&s, &[&bad], &[]).await, 2);
        assert!(
            t.contains(&format!("audit chain BROKEN at seq {seq}")),
            "{t}"
        );
        let pair: [&Path; 2] = if name == "flipped-archive" {
            [&bad, &retained]
        } else {
            [&archive, &bad]
        };
        let out = verify(&s, &pair, &["--json"]).await;
        assert_exit(&out, 2);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        let i = usize::from(name == "flipped-retained");
        assert_eq!(v["files"][i]["first_bad_seq"], seq, "{v}");
        let t = assert_exit(&verify(&s, &pair, &[]).await, 2);
        assert!(
            t.contains(&format!("audit chain BROKEN at seq {seq}")),
            "{t}"
        );
    }

    // The request repeated after it succeeded: the same anchor, nothing new.
    let out = prune(&s, &["--archive", a, "--reuse-archive"]).await;
    let t = assert_exit(&out, 0);
    assert!(
        t.contains("already pruned through seq 20 with this archive"),
        "{t}"
    );
    assert_eq!(
        s.state.audit.newest_anchor().unwrap().unwrap().anchor,
        anchor
    );
}

#[tokio::test]
async fn two_prunes_in_a_row_leave_three_files_that_link() {
    let s = Server::start(PruneMode::Manual).await;
    s.fill(45).await;
    let a1 = s.path("a1.jsonl");
    let a2 = s.path("a2.jsonl");
    let out = prune(&s, &["--through", "25", "--archive", a1.to_str().unwrap()]).await;
    assert_exit(&out, 0);
    s.settle().await;

    let before = (OffsetDateTime::now_utc() - Duration::days(100))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let out = prune(
        &s,
        &[
            "--before",
            &before,
            "--archive",
            a2.to_str().unwrap(),
            "--json",
        ],
    )
    .await;
    assert_exit(&out, 0);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let b2 = v["prune"]["pruned_through"].as_u64().unwrap();
    assert!(b2 > 20, "{v}");
    assert_eq!(v["plan"]["from"], 21);
    assert_eq!(v["archive"]["through"], b2);
    assert_eq!(v["prune"]["anchor"]["previous_through_seq"], 20);
    assert_eq!(
        v["archive"]["sha256"],
        common::sha256_hex(&std::fs::read_to_string(&a2).unwrap())
    );
    assert_eq!(s.first_retained(), b2 + 1);
    s.settle().await;

    let retained = s.path("retained.jsonl");
    export_retained(&s, &retained).await;
    let shipped = s.path("shipped.jsonl");
    let out = verify(
        &s,
        &[&a1, &a2, &retained],
        &["--checkpoints", shipped.to_str().unwrap()],
    )
    .await;
    let t = assert_exit(&out, 0);
    assert!(t.contains("files link: 3 files hold seq 1.."), "{t}");
    // Without the middle archive, the gap is named.
    let t = assert_exit(&verify(&s, &[&a1, &retained], &[]).await, 2);
    assert!(t.contains("the seqs are not contiguous"), "{t}");
    // The first archive, checked against the shipped anchors, is an older file: fine. The
    // retained export without its anchor's file is still checked against the anchors.
    let out = verify(&s, &[&a2], &["--checkpoints", shipped.to_str().unwrap()]).await;
    assert_exit(&out, 0);
}

#[tokio::test]
async fn refusals_leave_the_server_as_it_was() {
    let s = Server::start(PruneMode::Manual).await;
    s.fill(35).await;

    // An existing archive file is never overwritten.
    let existing = s.path("existing.jsonl");
    std::fs::write(&existing, "keep me").unwrap();
    let out = prune(
        &s,
        &["--through", "20", "--archive", existing.to_str().unwrap()],
    )
    .await;
    let t = assert_exit(&out, 1);
    assert!(t.contains("refusing to overwrite"), "{t}");
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep me");
    assert_eq!(s.first_retained(), 1);

    // A JWKS that signed none of the checkpoints: the archive does not verify, it is removed,
    // and nothing is sent.
    let jwks = s.path("other-jwks.json");
    other_jwks(&jwks);
    let archive = s.path("archive.jsonl");
    let out = prune(
        &s,
        &[
            "--through",
            "20",
            "--archive",
            archive.to_str().unwrap(),
            "--jwks",
            jwks.to_str().unwrap(),
        ],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(t.contains("the archive did not verify"), "{t}");
    assert!(!archive.exists());
    no_partial_files(s.dir.path());
    assert_eq!(s.first_retained(), 1);

    // Nothing to prune below the first checkpoint: the plan says why, exit 2.
    let out = prune(
        &s,
        &["--through", "5", "--archive", archive.to_str().unwrap()],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(t.contains("plan: nothing can be pruned"), "{t}");
    assert!(t.contains("limited by: prune_not_at_checkpoint"), "{t}");
    assert!(!archive.exists());

    // The prune, then a second one while its rows are still being deleted: the plan's guard.
    let out = prune(
        &s,
        &["--through", "20", "--archive", archive.to_str().unwrap()],
    )
    .await;
    assert_exit(&out, 0);
    let a2 = s.path("archive-2.jsonl");
    let out = prune(&s, &["--through", "30", "--archive", a2.to_str().unwrap()]).await;
    let t = assert_exit(&out, 2);
    assert!(t.contains("limited by: prune_in_progress"), "{t}");
    assert!(!a2.exists());

    // The same boundary with another digest (the archive with one more blank line still
    // verifies, but its bytes differ): the CLI sees the stored anchor and sends nothing.
    let changed = s.path("archive-changed.jsonl");
    let mut bytes = std::fs::read(&archive).unwrap();
    bytes.extend_from_slice(b"\n");
    std::fs::write(&changed, bytes).unwrap();
    let out = prune(
        &s,
        &["--archive", changed.to_str().unwrap(), "--reuse-archive"],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(t.contains("with another archive digest"), "{t}");
    assert!(t.contains("nothing was sent to the server"), "{t}");
    let out = prune(
        &s,
        &[
            "--archive",
            changed.to_str().unwrap(),
            "--reuse-archive",
            "--json",
        ],
    )
    .await;
    assert_exit(&out, 2);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["archive_problems"][0]
        .as_str()
        .unwrap()
        .contains("another archive digest"));

    // `--through` must match the archive's end.
    let out = prune(
        &s,
        &[
            "--through",
            "30",
            "--archive",
            archive.to_str().unwrap(),
            "--reuse-archive",
        ],
    )
    .await;
    let t = assert_exit(&out, 1);
    assert!(
        t.contains("the archive ends at seq 20, not at --through 30"),
        "{t}"
    );

    // After a later prune, the first archive lies wholly below the log's start.
    s.settle().await;
    s.fill(10).await;
    let out = prune(&s, &["--through", "30", "--archive", a2.to_str().unwrap()]).await;
    assert_exit(&out, 0);
    let out = prune(
        &s,
        &["--archive", archive.to_str().unwrap(), "--reuse-archive"],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(
        t.contains("already pruned through seq 30, past this archive's end at seq 20"),
        "{t}"
    );
}

/// I1: an archive of a window of the log (11..=20 on a log that starts at 1) must not prune
/// 1..=20: the CLI refuses it before it sends anything.
#[tokio::test]
async fn a_window_archive_is_refused_before_anything_is_sent() {
    let s = Server::start(PruneMode::Manual).await;
    s.fill(35).await;
    let window = s.path("window.jsonl");
    let mut c = s.cli();
    c.args(["audit", "export", "--from", "11", "--to", "20", "--out"])
        .arg(&window);
    assert_exit(&run(c).await, 0);
    // It verifies on its own, as a window.
    assert_exit(&verify(&s, &[&window], &[]).await, 0);
    let out = prune(
        &s,
        &["--archive", window.to_str().unwrap(), "--reuse-archive"],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(
        t.contains("the archive starts at seq 11, but the log starts at seq 1"),
        "{t}"
    );
    assert!(t.contains("nothing was sent to the server"), "{t}");
    assert_eq!(s.first_retained(), 1);
    assert!(s.state.audit.newest_anchor().unwrap().is_none());
}

#[tokio::test]
async fn prune_off_is_refused_before_anything_is_written() {
    let s = Server::start(PruneMode::Off).await;
    s.fill(20).await;
    let archive = s.path("archive.jsonl");
    let out = prune(
        &s,
        &["--through", "20", "--archive", archive.to_str().unwrap()],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(t.contains("prune refused: prune_disabled: "), "{t}");
    assert!(!archive.exists());
}

/// An answer of a scripted server: 200 with a JSON body, or with `status`.
fn http(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A scripted server: each request gets the raw answer of the first route whose needle is in
/// its request line (a 500 when none is), and every `POST` is counted.
fn scripted(routes: Vec<(&'static str, String)>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let posts = Arc::new(AtomicUsize::new(0));
    let seen = posts.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let first = head.lines().next().unwrap_or_default().to_string();
            if first.starts_with("POST") {
                seen.fetch_add(1, Ordering::SeqCst);
            }
            let answer = routes
                .iter()
                .find(|(needle, _)| first.contains(needle))
                .map_or_else(
                    || http("500 Internal Server Error", "{}"),
                    |(_, a)| a.clone(),
                );
            let _ = stream.write_all(answer.as_bytes());
            let _ = stream.flush();
        }
    });
    (url, posts)
}

/// A plan answer for `from..=through` whose checkpoint names `hash`.
fn plan_body(from: u64, through: u64, hash: &str) -> String {
    json!({
        "from": from, "through": through, "entries": through - from + 1,
        "checkpoint": {"seq": through, "head_hash": hash}, "at": "2026-01-01T00:00:00Z",
        "guards": {"limited_by": null}, "anchor": null,
    })
    .to_string()
}

/// The CLI against `url`, run off the runtime.
async fn run_at(url: &str, args: &[&str]) -> Output {
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", url])
        .args(args);
    run(c).await
}

#[test]
fn an_export_cut_short_leaves_no_file_and_sends_no_prune() {
    // A header that parses, then the body ends without its last chunk.
    let line = "{\"type\":\"header\",\"format\":\"attenuo-audit-export-v2\",\"from\":1,\"to\":20,\
                \"exported_at\":\"2026-01-01T00:00:00Z\"}\n";
    let cut = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/x-ndjson\r\ntransfer-encoding: chunked\r\n\
         connection: close\r\n\r\n{:x}\r\n{line}\r\n",
        line.len()
    );
    let (url, posts) = scripted(vec![
        (
            "/admin/audit/prune/plan",
            http("200 OK", &plan_body(1, 20, &"00".repeat(32))),
        ),
        ("/admin/audit/export", cut),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let jwks = dir.path().join("jwks.json");
    other_jwks(&jwks);

    let out_file = dir.path().join("export.jsonl");
    let out = attenuo()
        .env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &url, "audit", "export", "--out"])
        .arg(&out_file)
        .output()
        .unwrap();
    let t = assert_exit(&out, 1);
    assert!(t.contains("the server ended the export early"), "{t}");
    assert!(!out_file.exists(), "{t}");
    no_partial_files(dir.path());

    let archive = dir.path().join("archive.jsonl");
    let out = attenuo()
        .env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args([
            "--server",
            &url,
            "audit",
            "prune",
            "--through",
            "20",
            "--archive",
        ])
        .arg(&archive)
        .arg("--jwks")
        .arg(&jwks)
        .output()
        .unwrap();
    let t = assert_exit(&out, 1);
    assert!(
        t.contains("the archive was not written; the server was not changed"),
        "{t}"
    );
    assert!(t.contains("the server ended the export early"), "{t}");
    assert!(!archive.exists());
    no_partial_files(dir.path());
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

/// A real archive of 1..=20 and the JWKS that signed it, from a real server.
async fn real_archive(s: &Server) -> (String, PathBuf) {
    let file = s.path("real.jsonl");
    let mut c = s.cli();
    c.args(["audit", "export", "--from", "1", "--to", "20", "--out"])
        .arg(&file);
    assert_exit(&run(c).await, 0);
    let jwks = s.path("jwks.json");
    let body = reqwest::get(s.server.url("/.well-known/jwks.json"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    std::fs::write(&jwks, body).unwrap();
    (std::fs::read_to_string(&file).unwrap(), jwks)
}

fn ndjson(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/x-ndjson\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The archive the server streamed is checked against the plan: another range or another
/// last hash stops the prune before anything is sent, and the file is removed.
#[tokio::test]
async fn an_archive_that_is_not_the_plan_is_refused() {
    let s = Server::start(PruneMode::Manual).await;
    s.fill(35).await;
    let (text, jwks) = real_archive(&s).await;
    let hash20 = s.state.audit.entry_at(20).unwrap().unwrap().entry_hash;
    let j = jwks.to_str().unwrap();
    for (plan, want) in [
        (
            plan_body(1, 30, &hash20),
            "the archive ends at seq 20, not at seq 30",
        ),
        (
            plan_body(1, 20, &"00".repeat(32)),
            "the archive's last entry is not the one the server's checkpoint signs",
        ),
        (
            plan_body(5, 20, &hash20),
            "the archive starts at seq 1, but the log starts at seq 5",
        ),
    ] {
        let (url, posts) = scripted(vec![
            ("/admin/audit/prune/plan", http("200 OK", &plan)),
            ("/admin/audit/export", ndjson(&text)),
        ]);
        let archive = s.path("scripted.jsonl");
        let a = archive.to_str().unwrap();
        let out = run_at(
            &url,
            &[
                "audit",
                "prune",
                "--through",
                "20",
                "--archive",
                a,
                "--jwks",
                j,
            ],
        )
        .await;
        let t = assert_exit(&out, 2);
        assert!(t.contains(want), "{want} not in {t}");
        assert!(
            t.contains("it was removed and the server was not changed"),
            "{t}"
        );
        assert!(!archive.exists());
        no_partial_files(s.dir.path());
        assert_eq!(posts.load(Ordering::SeqCst), 0);
        // With --json, the same answer as an object on stdout.
        let out = run_at(
            &url,
            &[
                "audit",
                "prune",
                "--through",
                "20",
                "--archive",
                a,
                "--jwks",
                j,
                "--json",
            ],
        )
        .await;
        assert_exit(&out, 2);
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["ok"], false);
        assert!(
            v["archive_problems"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p.as_str().unwrap().contains(want)),
            "{v}"
        );
    }
}

/// A refusal of the POST itself, with --json, and an answer whose anchor does not match the
/// archive: the prune was committed, which the CLI says loudly, exit 2.
#[tokio::test]
async fn the_answer_of_the_prune_is_checked_against_the_archive() {
    let s = Server::start(PruneMode::Manual).await;
    s.fill(35).await;
    let (text, jwks) = real_archive(&s).await;
    let archive = s.path("kept.jsonl");
    std::fs::write(&archive, &text).unwrap();
    let a = archive.to_str().unwrap();
    let j = jwks.to_str().unwrap();
    let anchors = http("200 OK", r#"{"anchors":[],"next_cursor":null}"#);

    let refused = http(
        "409 Conflict",
        r#"{"error":"conflict","code":"prune_in_progress","detail":"still deleting"}"#,
    );
    let (url, posts) = scripted(vec![
        ("/admin/audit/anchors", anchors.clone()),
        ("/admin/audit/prune", refused),
    ]);
    let out = run_at(
        &url,
        &[
            "audit",
            "prune",
            "--archive",
            a,
            "--reuse-archive",
            "--jwks",
            j,
        ],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(
        t.contains("prune refused: prune_in_progress: still deleting"),
        "{t}"
    );
    assert!(t.contains("--reuse-archive"), "{t}");
    let out = run_at(
        &url,
        &[
            "audit",
            "prune",
            "--archive",
            a,
            "--reuse-archive",
            "--jwks",
            j,
            "--json",
        ],
    )
    .await;
    assert_exit(&out, 2);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["refused"]["code"], "prune_in_progress");
    assert_eq!(posts.load(Ordering::SeqCst), 2);
    // The request names the archive's first seq and last hash: checked by the real server
    // in `a_prune_through_the_cli_end_to_end`.

    // A committed prune whose anchor is not this archive's.
    let bogus = json!({
        "prune_seq": 36, "pruned_through": 20, "deleting": true, "already": false,
        "anchor": {"through_seq": 20, "through_hash": "00".repeat(32), "prune_seq": 36,
                   "prune_entry_hash": "11".repeat(32), "previous_through_seq": null,
                   "archive_sha256": "22".repeat(32), "at": "2026-01-01T00:00:00Z",
                   "kid": "nope", "signature": "AA"},
        "checkpoint_before": null, "checkpoint_after": null, "shipped": null,
    })
    .to_string();
    let (url, _) = scripted(vec![
        ("/admin/audit/anchors", anchors),
        ("/admin/audit/prune", http("200 OK", &bogus)),
    ]);
    let out = run_at(
        &url,
        &[
            "audit",
            "prune",
            "--archive",
            a,
            "--reuse-archive",
            "--jwks",
            j,
        ],
    )
    .await;
    let t = assert_exit(&out, 2);
    for want in [
        "PRUNE COMMITTED, BUT THE ANCHOR DOES NOT MATCH THE ARCHIVE",
        "unknown signing key `nope`",
        "through_hash is not the archive's last entry hash",
        "archive_sha256 is 2222",
    ] {
        assert!(t.contains(want), "{want} not in {t}");
    }
    let out = run_at(
        &url,
        &[
            "audit",
            "prune",
            "--archive",
            a,
            "--reuse-archive",
            "--jwks",
            j,
            "--json",
        ],
    )
    .await;
    assert_exit(&out, 2);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!((&v["ok"], &v["committed"]), (&json!(false), &json!(true)));
    assert!(!v["anchor_problems"].as_array().unwrap().is_empty());
}

/// `audit export --out` writes a symbolic link's target and a device directly, as before; a
/// regular file it replaces keeps its mode.
#[tokio::test]
async fn export_out_writes_links_and_devices_directly() {
    let s = Server::start(PruneMode::Manual).await;
    s.fill(10).await;
    let target = s.path("target.jsonl");
    std::fs::write(&target, "old").unwrap();
    let link = s.path("link.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let mut c = s.cli();
    c.args(["audit", "export", "--to", "10", "--out"])
        .arg(&link);
    assert_exit(&run(c).await, 0);
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(std::fs::read_to_string(&target)
        .unwrap()
        .contains("\"seq\":10,"));

    let mut c = s.cli();
    c.args(["audit", "export", "--to", "10", "--out", "/dev/stdout"]);
    let out = run(c).await;
    assert_exit(&out, 0);
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"seq\":10,"));

    use std::os::unix::fs::PermissionsExt;
    let plain = s.path("plain.jsonl");
    std::fs::write(&plain, "old").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o640)).unwrap();
    let mut c = s.cli();
    c.args(["audit", "export", "--to", "10", "--out"])
        .arg(&plain);
    assert_exit(&run(c).await, 0);
    let m = std::fs::metadata(&plain).unwrap();
    assert_eq!(m.permissions().mode() & 0o777, 0o640);
    assert!(std::fs::read_to_string(&plain)
        .unwrap()
        .contains("\"seq\":10,"));
    no_partial_files(s.dir.path());
}
