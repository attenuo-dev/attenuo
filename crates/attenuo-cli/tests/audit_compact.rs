//! `attenuo audit compact` on a real server's file: refused while the server runs, a dry run
//! that changes no byte, a compaction that makes the pruned file smaller, and a server started
//! on the compacted file that passes its start-up checks, `audit verify` and the offline verify
//! of the archive and the retained export as one log. Then a refusal on another schema
//! version. The other refusals and the check after `VACUUM` are tested on the library, in
//! `crates/attenuo-audit/tests/compact.rs`, where the free-space probe and a fault can be
//! injected.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

#[path = "../../attenuo-audit/tests/common/mod.rs"]
mod audit_common;
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use attenuo_audit::AuditSink;
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{PruneMode, SinkKind, SinkSection};
use attenuo_server::{AppState, Config};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use common::attenuo;

const ADMIN: &str = "audit-compact-test-admin";

fn config(dir: &Path) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.audit.checkpoint_every = 10;
    let mut sink = SinkSection::new(SinkKind::File);
    sink.path = Some(dir.join("shipped.jsonl"));
    sink.initial_backoff_ms = 5;
    sink.max_backoff_seconds = 1;
    cfg.audit.sink = Some(sink);
    cfg.audit.retention.prune = PruneMode::Manual;
    cfg.admin.token = Some(ADMIN.into());
    cfg.issuer.private_key_pem_path = Some(dir.join("issuer.pem"));
    cfg
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !f() {
        assert!(std::time::Instant::now() < end, "timed out");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn start(dir: &Path) -> (Spawned, Arc<AppState>) {
    let (router, state) = attenuo_server::build(&config(dir)).unwrap();
    (spawn_router(router).await.unwrap(), state)
}

/// Stop the server and wait until it has let go of the file.
async fn stop(server: Spawned, state: Arc<AppState>) {
    drop(server);
    let released = state.released();
    drop(state);
    tokio::time::timeout(std::time::Duration::from_secs(10), released)
        .await
        .expect("the server let go of its state");
}

fn cli(server: &Spawned) -> Command {
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &server.url("")]);
    c
}

async fn run(cmd: Command) -> Output {
    let mut cmd = cmd;
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn assert_exit(out: &Output, code: i32) -> String {
    let t = format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(code), "{t}");
    t
}

/// `attenuo [--json] audit compact --db <file> [extra]`, with no server and no token.
async fn compact(db: &Path, json: bool, extra: &[&str]) -> Output {
    let mut c = attenuo();
    if json {
        c.arg("--json");
    }
    c.args(["audit", "compact", "--db"]).arg(db).args(extra);
    run(c).await
}

fn json_of(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

/// The file and its `-wal`, byte for byte.
fn bytes(db: &Path) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    (
        std::fs::read(db).unwrap(),
        std::fs::read(PathBuf::from(wal)).ok(),
    )
}

#[tokio::test]
async fn a_pruned_file_is_compacted_and_a_server_starts_on_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("audit.sqlite");
    let path = |name: &str| dir.path().join(name);
    let (server, state) = start(dir.path()).await;

    // 1200 old entries, the sink caught up, then a prune through 1100 with its archive.
    for i in 0..1200 {
        let mut r = audit_common::record(i);
        r.at = OffsetDateTime::now_utc() - Duration::days(200);
        state.audit.append(r).unwrap();
    }
    let sink = state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.delivered_through() >= Some(1200)).await;
    let archive = path("archive.jsonl");
    let mut c = cli(&server);
    c.args(["audit", "prune", "--through", "1100", "--archive"])
        .arg(&archive);
    assert_exit(&run(c).await, 0);
    assert_eq!(attenuo_server::prune_audit_log(&state).await, 1100);
    let s = state.clone();
    wait_for(move || s.audit.unshipped_anchors().is_ok_and(|u| u.is_empty())).await;
    let head = state.audit.head().unwrap().unwrap().seq;
    wait_for(|| sink.delivered_through() >= Some(head)).await;

    // Refused while the server runs, idle or not.
    let out = compact(&db, false, &[]).await;
    let t = assert_exit(&out, 2);
    assert!(
        t.contains("compact refused: in_use: the database is in use; stop the server first"),
        "{t}"
    );
    assert!(t.contains("the file was not changed"), "{t}");
    let out = compact(&db, true, &[]).await;
    assert_exit(&out, 2);
    assert_eq!(json_of(&out)["refused"]["code"], "in_use");

    stop(server, state).await;

    // The dry run changes no byte and says what it would free.
    let was = bytes(&db);
    let out = compact(&db, false, &["--dry-run"]).await;
    let t = assert_exit(&out, 0);
    assert!(
        t.contains("dry run: ") && t.contains("was not changed"),
        "{t}"
    );
    assert!(t.contains("would return:  at least "), "{t}");
    let out = compact(&db, true, &["--dry-run"]).await;
    assert_exit(&out, 0);
    let dry = json_of(&out);
    assert_eq!(dry["dry_run"], true);
    assert!(
        dry["free_bytes_before"].as_u64().unwrap() > 500_000,
        "{dry}"
    );
    assert_eq!(dry["bytes_returned"], 0);
    assert_eq!(bytes(&db), was);

    // The real run: smaller, no free pages left, nothing else changed.
    let out = compact(&db, true, &[]).await;
    assert_exit(&out, 0);
    let done = json_of(&out);
    let (before, after) = (
        done["size_before"].as_u64().unwrap(),
        done["size_after"].as_u64().unwrap(),
    );
    assert!(after < before, "{done}");
    assert!(done["bytes_returned"].as_u64().unwrap() > 500_000, "{done}");
    assert_eq!(done["free_bytes_after"], 0, "{done}");
    assert_eq!(done["pruned_through"], 1100);
    assert_eq!(done["head_seq"], head);
    assert_eq!(std::fs::metadata(&db).unwrap().len(), after);
    // A second run finds nothing more to give back, and says so in text.
    let out = compact(&db, false, &[]).await;
    let t = assert_exit(&out, 0);
    assert!(t.contains("returned:      0 bytes"), "{t}");
    assert!(t.contains(&format!("(head seq {head})")), "{t}");

    // A server starts on the compacted file, and the log verifies live and offline.
    let (server, state) = start(dir.path()).await;
    assert_eq!(state.audit.first_retained_seq().unwrap(), 1101);
    assert_eq!(state.audit.head().unwrap().unwrap().seq, head);
    let mut c = cli(&server);
    c.args(["audit", "verify"]);
    let t = assert_exit(&run(c).await, 0);
    assert!(t.contains("from seq 1101 (pruned through 1100"), "{t}");
    let retained = path("retained.jsonl");
    let mut c = cli(&server);
    c.args(["audit", "export", "--out"]).arg(&retained);
    assert_exit(&run(c).await, 0);
    let mut c = cli(&server);
    c.args(["audit", "verify", "--file"])
        .arg(&archive)
        .arg("--file")
        .arg(&retained)
        .arg("--checkpoints")
        .arg(path("shipped.jsonl"));
    let t = assert_exit(&run(c).await, 0);
    for want in [
        "as one log, from genesis",
        "all files: OK",
        "shipped prune anchors: OK",
    ] {
        assert!(t.contains(want), "{want} not in {t}");
    }
    // And it keeps writing where the log stopped.
    let next = state.audit.append(audit_common::record(5000)).unwrap();
    assert_eq!(next.seq, head + 1);
    stop(server, state).await;
}

/// A file at another schema version is refused with its code, and the file is not changed.
#[tokio::test]
async fn another_schema_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("audit.sqlite");
    let (server, state) = start(dir.path()).await;
    state.audit.append(audit_common::record(0)).unwrap();
    stop(server, state).await;
    rusqlite::Connection::open(&db)
        .unwrap()
        .pragma_update(None, "user_version", attenuo_audit::SCHEMA_VERSION + 1)
        .unwrap();
    let was = bytes(&db);
    let t = assert_exit(&compact(&db, false, &[]).await, 2);
    assert!(t.contains("compact refused: schema_version: "), "{t}");
    assert_eq!(bytes(&db), was);
}

/// A missing file is an error (exit 1) and is not created.
#[tokio::test]
async fn a_missing_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("none.sqlite");
    let t = assert_exit(&compact(&db, false, &[]).await, 1);
    assert!(t.contains("error: compacting "), "{t}");
    assert!(!db.exists());
}
