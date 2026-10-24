//! Syncs ahead of time that keep long pauses off the append path (see
//! `docs/design/performance.md`, "Single-client outliers"): the database file is synced
//! before the WAL checkpointer's locked pass, and the WAL is synced a little before a signed
//! audit checkpoint, whose commit syncs at `FULL`.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use attenuo_audit::{AuditSink, Durability, SqliteAudit, CHECKPOINT_PRESYNC_LEAD};
use common::record;

fn wal_path(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push("-wal");
    PathBuf::from(p)
}

fn wait_for(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn issuer() -> attenuo_token::Issuer {
    attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    })
}

/// A WAL past the restart size gets a locked pass, and that pass comes after a sync of the
/// database file, so it has only its own pages left to sync with appends paused.
#[test]
fn the_locked_pass_comes_after_a_sync_of_the_database_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let audit = SqliteAudit::open_with(&path, Durability::Normal)
        .unwrap()
        .with_wal_checkpoints(Duration::from_secs(3600))
        .unwrap();
    // With the checkpointer parked, grow the WAL past 64 MB (16,384 frames of 4 KiB plus
    // their headers).
    let parked = audit.park_wal_checkpointer().expect("a file store");
    let mut i = 0;
    while std::fs::metadata(wal_path(&path)).map_or(0, |m| m.len()) < 16_500 * 4120 {
        audit.append(record(i)).unwrap();
        i += 1;
    }
    // The commits since the last round have queued a round; let it run.
    drop(parked);
    wait_for("a locked pass", Duration::from_secs(60), || {
        audit
            .wal_timings()
            .rounds
            .iter()
            .any(|r| r.locked.is_some())
    });
    let timings = audit.wal_timings();
    let round = timings.rounds.iter().find(|r| r.locked.is_some()).unwrap();
    assert!(round.presynced, "{round:?}");
    assert!(round.last.complete(), "{round:?}");
    // SR-58: the sync must not have released this process's POSIX locks on the database
    // file. Closing any descriptor of a file drops every `fcntl` lock the process holds on it,
    // including the SHARED lock SQLite keeps on the database file in WAL mode, which tells
    // other processes the WAL is in use. Without it, another process that opens and closes the
    // file (an operator's `sqlite3`, a backup tool) can take it for unused, checkpoint it and
    // delete the WAL under the live store; SQLite 3.45's shell does.
    audit.append(record(i)).unwrap();
    i += 1;
    let probe = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probe_the_lock_on_the_store", "--nocapture"])
        .env(PROBE_DB, &path)
        .status()
        .unwrap();
    assert!(
        probe.success(),
        "another process could lock a store this process has open"
    );
    assert!(wal_path(&path).exists());
    let report = audit.verify_chain().unwrap();
    assert!(report.ok);
    assert_eq!(report.entries, i as u64);
}

/// Names the database the probe below opens.
const PROBE_DB: &str = "ATTENUO_TEST_PROBE_DB";

/// Run as a separate process by the test above (does nothing otherwise): open the store with
/// plain SQLite in exclusive locking mode, which reads only once it holds an EXCLUSIVE lock
/// on the database file. A store open in another process holds SHARED, so the read must fail
/// as busy.
#[test]
fn probe_the_lock_on_the_store() {
    let Some(path) = std::env::var_os(PROBE_DB) else {
        return;
    };
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")
        .unwrap();
    let read = conn.query_row("SELECT count(*) FROM audit", [], |r| r.get::<_, i64>(0));
    assert!(
        matches!(&read, Err(e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy)),
        "{read:?}"
    );
}

/// At `durability = "normal"` with signed checkpoints, the commit that brings the head within
/// `CHECKPOINT_PRESYNC_LEAD` entries of the next checkpoint has the checkpointer sync the
/// WAL: once per checkpoint. The checkpoints themselves are written as before.
#[test]
fn the_wal_is_synced_ahead_of_each_signed_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let every = 2 * CHECKPOINT_PRESYNC_LEAD;
    let audit = SqliteAudit::open_with(&path, Durability::Normal)
        .unwrap()
        .with_checkpointing(issuer().detached_signer(), every)
        .with_wal_checkpoints(Duration::from_secs(3600))
        .unwrap();
    // Two checkpoints and most of the way to a third, one entry per commit; fewer commits
    // than start a checkpoint round, so only the syncs ahead of checkpoints use the channel.
    let n = 2 * every + every / 4;
    for i in 0..n {
        audit.append(record(i as usize)).unwrap();
    }
    wait_for("two WAL syncs", Duration::from_secs(10), || {
        audit.wal_timings().wal_presyncs >= 2
    });
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(audit.wal_timings().wal_presyncs, 2);
    let cps = audit.checkpoints_between(0, n).unwrap();
    assert_eq!(
        cps.iter().map(|c| c.seq).collect::<Vec<_>>(),
        [every, 2 * every]
    );
}

/// A store at `durability = "full"` syncs every commit already: no sync ahead of time.
#[test]
fn a_full_store_does_not_sync_ahead_of_signed_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let every = 4 * CHECKPOINT_PRESYNC_LEAD;
    let audit = SqliteAudit::open_with(&path, Durability::Full)
        .unwrap()
        .with_checkpointing(issuer().detached_signer(), every)
        .with_wal_checkpoints(Duration::from_secs(3600))
        .unwrap();
    for i in 0..every + 1 {
        audit.append(record(i as usize)).unwrap();
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(audit.wal_timings().wal_presyncs, 0);
    assert_eq!(audit.checkpoints_between(0, every + 1).unwrap().len(), 1);
}
