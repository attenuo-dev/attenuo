//! WAL checkpoints off the writer (`SqliteAudit::with_wal_checkpoints`): concurrent appends
//! with verification running, size-triggered and idle checkpoints, the final checkpoint on
//! drop, and in-memory stores left alone.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use attenuo_audit::{
    AuditSink, Durability, SqliteAudit, SqliteLeaseStore, WAL_CHECKPOINT_COMMITS,
    WAL_WRITER_BACKSTOP_FRAMES,
};
use common::record;
use rusqlite::{Connection, OpenFlags};

fn wal_path(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push("-wal");
    PathBuf::from(p)
}

/// Rows in the database file alone, ignoring the WAL: a copy of the main file, opened on its
/// own, holds exactly what has been checkpointed.
fn rows_in_main_file(db: &Path) -> i64 {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("copy.db");
    std::fs::copy(db, &copy).unwrap();
    let conn = Connection::open_with_flags(&copy, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
    conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))
        .unwrap_or(0)
}

fn autocheckpoint(audit: &SqliteAudit) -> i64 {
    audit
        .with_connection(|c| Ok(c.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))?))
        .unwrap()
}

fn wait_for(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn concurrent_appends_with_verify_running_and_background_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let audit = Arc::new(
        SqliteAudit::open_with(&path, Durability::Normal)
            .unwrap()
            .with_wal_checkpoints(Duration::from_millis(30))
            .unwrap(),
    );
    assert_eq!(
        autocheckpoint(&audit),
        WAL_WRITER_BACKSTOP_FRAMES,
        "the writer checkpoints only as a backstop, far above what the background thread allows"
    );

    const THREADS: usize = 8;
    const PER_THREAD: usize = 300;
    let stop = Arc::new(AtomicBool::new(false));
    let verifier = {
        let audit = Arc::clone(&audit);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut runs = 0;
            let mut last = 0;
            while !stop.load(Ordering::Acquire) {
                let report = audit.verify_chain().unwrap();
                assert!(report.ok, "{report:?}");
                assert!(report.entries >= last, "entries never go backwards");
                last = report.entries;
                runs += 1;
                // The scan holds the store lock; leave room for the writers (std mutexes are
                // not fair, so a tight loop could starve them).
                std::thread::sleep(Duration::from_millis(5));
            }
            runs
        })
    };
    let writers: Vec<_> = (0..THREADS)
        .map(|t| {
            let audit = Arc::clone(&audit);
            std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    audit.append(record(t * PER_THREAD + i)).unwrap();
                }
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }
    stop.store(true, Ordering::Release);
    assert!(verifier.join().unwrap() > 0);

    let total = (THREADS * PER_THREAD) as u64;
    let report = audit.verify_chain().unwrap();
    assert!(report.ok);
    assert_eq!(report.entries, total);
    assert_eq!(audit.len().unwrap(), total);
    assert_eq!(audit.range(1, usize::MAX >> 1).unwrap().len() as u64, total);

    // With the writer idle, the background thread copies everything into the database file
    // (and truncates the WAL) without being asked.
    wait_for("the idle checkpoint", Duration::from_secs(10), || {
        rows_in_main_file(&path) == total as i64
    });
    wait_for("the WAL truncation", Duration::from_secs(10), || {
        std::fs::metadata(wal_path(&path))
            .map(|m| m.len())
            .unwrap_or(0)
            == 0
    });
}

#[test]
fn a_burst_triggers_a_checkpoint_before_the_interval() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let audit = SqliteAudit::open_with(&path, Durability::Normal)
        .unwrap()
        .with_wal_checkpoints(Duration::from_secs(3600))
        .unwrap();
    // One thread, so every append is its own commit.
    let n = WAL_CHECKPOINT_COMMITS as usize + 64;
    for i in 0..n {
        audit.append(record(i)).unwrap();
    }
    // The interval is an hour; only the commit count can have started a checkpoint. Keep a
    // trickle of appends going while waiting, as a live server would: a passive checkpoint
    // that found the writer in the way copies nothing, and the next commit must re-arm it
    // (seen on a slow macOS runner, where the first round raced the tail of the burst).
    let mut i = n;
    wait_for(
        "the count-triggered checkpoint",
        Duration::from_secs(30),
        || {
            audit.append(record(i)).unwrap();
            i += 1;
            rows_in_main_file(&path) >= WAL_CHECKPOINT_COMMITS as i64
        },
    );
    assert!(audit.verify_chain().unwrap().ok);
}

/// Under continuous load a passive checkpoint never finds every frame copied, and SQLite only
/// starts the WAL over when it does; the checkpointer's short catch-up pass is what keeps the
/// WAL from growing for as long as the load lasts (without it this run leaves a WAL of
/// hundreds of megabytes). On a host where that thread cannot keep up (CI runners with two
/// cores and a slow disk reached 184 and 301 MB), the writer's own 128 MB backstop holds the
/// bound instead.
#[test]
fn the_wal_stays_bounded_under_continuous_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let audit = Arc::new(
        SqliteAudit::open_with(&path, Durability::Normal)
            .unwrap()
            .with_wal_checkpoints(Duration::from_secs(3600))
            .unwrap(),
    );
    const THREADS: usize = 8;
    const PER_THREAD: usize = 3000;
    let done = Arc::new(AtomicBool::new(false));
    let sampler = {
        let done = Arc::clone(&done);
        let wal = wal_path(&path);
        std::thread::spawn(move || {
            let mut largest = 0;
            while !done.load(Ordering::Acquire) {
                largest = largest.max(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0));
                std::thread::sleep(Duration::from_millis(5));
            }
            largest
        })
    };
    let writers: Vec<_> = (0..THREADS)
        .map(|t| {
            let audit = Arc::clone(&audit);
            std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    audit.append(record(t * PER_THREAD + i)).unwrap();
                }
            })
        })
        .collect();
    for w in writers {
        w.join().unwrap();
    }
    done.store(true, Ordering::Release);
    let largest = sampler.join().unwrap();
    eprintln!("largest WAL: {} KiB", largest >> 10);
    // The backstop (128 MB at the 4 KiB page) plus what one locked pass has in flight.
    let bound = WAL_WRITER_BACKSTOP_FRAMES as u64 * 4096 + (32 << 20);
    assert!(largest < bound, "the WAL reached {} MB", largest >> 20);
    let report = audit.verify_chain().unwrap();
    assert!(report.ok);
    assert_eq!(report.entries, (THREADS * PER_THREAD) as u64);
}

#[test]
fn dropping_the_store_checkpoints_and_truncates_the_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    // The lease store shares the file and stays open, as in the server.
    let leases = SqliteLeaseStore::open_with(&path, Durability::Normal)
        .unwrap()
        .without_wal_autocheckpoint()
        .unwrap();
    let audit = SqliteAudit::open_with(&path, Durability::Normal)
        .unwrap()
        .with_wal_checkpoints(Duration::from_secs(3600))
        .unwrap();
    for i in 0..200 {
        audit.append(record(i)).unwrap();
    }
    assert!(
        rows_in_main_file(&path) < 200,
        "nothing has checkpointed yet (the interval is an hour)"
    );

    // An explicit checkpoint, as the server runs after draining.
    let done = audit.checkpoint_wal().unwrap().expect("a file in WAL mode");
    assert!(done.complete(), "{done:?}");
    assert_eq!(rows_in_main_file(&path), 200);

    for i in 200..300 {
        audit.append(record(i)).unwrap();
    }
    drop(audit);
    assert_eq!(
        rows_in_main_file(&path),
        300,
        "the final checkpoint ran on drop"
    );
    assert_eq!(
        std::fs::metadata(wal_path(&path))
            .map(|m| m.len())
            .unwrap_or(0),
        0,
        "and truncated the WAL"
    );
    drop(leases);

    let reopened = SqliteAudit::open(&path).unwrap();
    let report = reopened.verify_chain().unwrap();
    assert!(report.ok);
    assert_eq!(report.entries, 300);
}

#[test]
fn in_memory_stores_and_a_zero_interval_are_left_alone() {
    let memory = SqliteAudit::open_in_memory()
        .unwrap()
        .with_wal_checkpoints(Duration::from_secs(5))
        .unwrap();
    assert!(format!("{memory:?}").contains("wal_checkpointer: false"));
    assert_eq!(memory.checkpoint_wal().unwrap(), None);
    memory.append(record(0)).unwrap();
    assert!(memory.verify_chain().unwrap().ok);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let off = SqliteAudit::open(&path)
        .unwrap()
        .with_wal_checkpoints(Duration::ZERO)
        .unwrap();
    assert!(format!("{off:?}").contains("wal_checkpointer: false"));
    assert_eq!(
        autocheckpoint(&off),
        1000,
        "SQLite's own checkpoints stay on"
    );
    off.append(record(0)).unwrap();
    assert!(off.checkpoint_wal().unwrap().unwrap().complete());
}
