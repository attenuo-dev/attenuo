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

    // A guard refusal of the POST itself: the same boundary with another digest (the archive
    // with one more blank line still verifies, but its bytes differ). The code and detail are
    // printed, with how to repeat.
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
    assert!(t.contains("prune refused: prune_conflict: "), "{t}");
    assert!(t.contains("--reuse-archive"), "{t}");

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

    // After a later prune, the first request repeated still answers its own anchor, and
    // another digest for that old boundary is still a conflict.
    s.settle().await;
    s.fill(10).await;
    let out = prune(&s, &["--through", "30", "--archive", a2.to_str().unwrap()]).await;
    assert_exit(&out, 0);
    let out = prune(
        &s,
        &["--archive", archive.to_str().unwrap(), "--reuse-archive"],
    )
    .await;
    let t = assert_exit(&out, 0);
    assert!(
        t.contains("already pruned through seq 20 with this archive"),
        "{t}"
    );
    let out = prune(
        &s,
        &["--archive", changed.to_str().unwrap(), "--reuse-archive"],
    )
    .await;
    let t = assert_exit(&out, 2);
    assert!(t.contains("prune refused: prune_conflict: "), "{t}");
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

/// A scripted server whose export body is cut off after the header: the plan is answered,
/// the export ends without its last chunk, and a `POST` is counted.
fn cut_short_server() -> (String, Arc<AtomicUsize>) {
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
            if head.starts_with("POST") {
                seen.fetch_add(1, Ordering::SeqCst);
            }
            if head.contains("/admin/audit/prune/plan") {
                let body = json!({
                    "from": 1, "through": 20, "entries": 20,
                    "checkpoint": {"seq": 20, "head_hash": "00"}, "at": "2026-01-01T00:00:00Z",
                    "guards": {"limited_by": null}, "anchor": null,
                })
                .to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                     {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            } else if head.contains("/admin/audit/export") {
                let line = "{\"format\":\"attenuo-audit-export-v1\",\"from\":1,\"to\":20,\
                            \"exported_at\":\"2026-01-01T00:00:00Z\"}\n";
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/x-ndjson\r\n\
                     transfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n{line}\r\n",
                    line.len()
                );
                // No terminating chunk: the body ends with an error.
            } else {
                let _ = write!(
                    stream,
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: \
                     close\r\n\r\n"
                );
            }
            let _ = stream.flush();
        }
    });
    (url, posts)
}

#[test]
fn an_export_cut_short_leaves_no_file_and_sends_no_prune() {
    let (url, posts) = cut_short_server();
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
    assert!(t.contains("the server was not changed"), "{t}");
    assert!(!archive.exists());
    no_partial_files(dir.path());
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}
