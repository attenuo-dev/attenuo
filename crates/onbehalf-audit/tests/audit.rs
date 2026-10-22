//! Audit chain: append, verify, tamper detection, concurrency, queries, persistence.

mod common;

use std::sync::Arc;

use common::{chain, record, record_for};
use onbehalf_audit::{
    compute_entry_hash, AuditSink, MemoryAudit, SqliteAudit, VerifyReport, GENESIS_HASH,
};
use onbehalf_core::{Decision, LeaseId};
use rusqlite::params;

fn sinks() -> Vec<(&'static str, Box<dyn AuditSink>)> {
    vec![
        ("memory", Box::new(MemoryAudit::new())),
        ("sqlite", Box::new(SqliteAudit::open_in_memory().unwrap())),
    ]
}

fn fill(sink: &dyn AuditSink, n: usize) {
    for i in 0..n {
        sink.append(record(i)).unwrap();
    }
}

#[test]
fn empty_log_verifies_and_checkpoints_at_genesis() {
    for (name, sink) in sinks() {
        assert_eq!(sink.head().unwrap(), None, "{name}");
        assert_eq!(sink.checkpoint().unwrap(), (0, GENESIS_HASH.to_string()));
        assert_eq!(
            sink.verify_chain().unwrap(),
            VerifyReport {
                entries: 0,
                ok: true,
                first_bad_seq: None
            }
        );
    }
}

#[test]
fn append_links_entries_and_verifies() {
    for (name, sink) in sinks() {
        let e1 = sink.append(record(0)).unwrap();
        assert_eq!(e1.seq, 1, "{name}");
        assert_eq!(e1.prev_hash, GENESIS_HASH);
        assert_eq!(
            e1.entry_hash,
            compute_entry_hash(1, GENESIS_HASH, &e1.record)
        );
        let e2 = sink.append(record(1)).unwrap();
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev_hash, e1.entry_hash);
        assert_ne!(e2.entry_hash, e1.entry_hash);

        let report = sink.verify_chain().unwrap();
        assert!(report.ok, "{name}: {report:?}");
        assert_eq!(report.entries, 2);
        assert_eq!(report.first_bad_seq, None);
        assert_eq!(sink.checkpoint().unwrap(), (2, e2.entry_hash.clone()));
    }
}

#[test]
fn head_and_range() {
    for (name, sink) in sinks() {
        fill(sink.as_ref(), 10);
        let head = sink.head().unwrap().unwrap();
        assert_eq!(head.seq, 10, "{name}");

        let r = sink.range(4, 3).unwrap();
        assert_eq!(r.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![4, 5, 6]);
        let r = sink.range(9, 100).unwrap();
        assert_eq!(r.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![9, 10]);
        assert!(sink.range(11, 5).unwrap().is_empty());
        assert!(sink.range(1, 0).unwrap().is_empty());
        let all = sink.range(1, usize::MAX).unwrap();
        assert_eq!(all.len(), 10);
        for w in all.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].entry_hash);
            assert_eq!(w[1].seq, w[0].seq + 1);
        }
    }
}

#[test]
fn concurrent_appends_keep_a_contiguous_valid_chain() {
    let threads = 8;
    let per_thread = 25;
    let sqlite = Arc::new(SqliteAudit::open_in_memory().unwrap());
    let memory = Arc::new(MemoryAudit::new());
    let targets: Vec<Arc<dyn AuditSink>> = vec![sqlite.clone(), memory.clone()];
    for sink in targets {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || {
                    for i in 0..per_thread {
                        sink.append(record(t * per_thread + i)).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let report = sink.verify_chain().unwrap();
        assert!(report.ok, "{report:?}");
        assert_eq!(report.entries, (threads * per_thread) as u64);
        let all = sink.range(1, usize::MAX).unwrap();
        let seqs: Vec<u64> = all.iter().map(|e| e.seq).collect();
        assert_eq!(
            seqs,
            (1..=(threads * per_thread) as u64).collect::<Vec<_>>()
        );
        let mut hashes: Vec<&str> = all.iter().map(|e| e.entry_hash.as_str()).collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), all.len(), "no two entries share a hash");
    }
}

// ---- tamper detection (SQLite rows edited directly) ----

fn sqlite_with(n: usize) -> SqliteAudit {
    let s = SqliteAudit::open_in_memory().unwrap();
    fill(&s, n);
    assert!(s.verify_chain().unwrap().ok);
    s
}

fn exec(s: &SqliteAudit, sql: &str, p: &[&dyn rusqlite::ToSql]) {
    s.with_connection(|c| {
        c.execute(sql, p)?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn tamper_record_json_is_detected() {
    let s = sqlite_with(6);
    let original: String = s
        .with_connection(|c| {
            Ok(
                c.query_row("SELECT record_json FROM audit WHERE seq = 4", [], |r| {
                    r.get(0)
                })?,
            )
        })
        .unwrap();
    assert!(original.contains("\"tool\":\"create_issue\""));
    let edited = original.replace("\"tool\":\"create_issue\"", "\"tool\":\"delete_repo\"");
    exec(
        &s,
        "UPDATE audit SET record_json = ?1, tool = 'delete_repo' WHERE seq = 4",
        &[&edited],
    );
    let report = s.verify_chain().unwrap();
    assert_eq!(
        report,
        VerifyReport {
            entries: 4,
            ok: false,
            first_bad_seq: Some(4)
        }
    );
}

#[test]
fn tamper_every_byte_of_record_json_is_detected() {
    // A tiny property-style sweep: flip each character of one row's JSON (keeping it parseable
    // or not) and confirm the chain breaks at exactly that seq every time.
    let s = sqlite_with(3);
    let original: String = s
        .with_connection(|c| {
            Ok(
                c.query_row("SELECT record_json FROM audit WHERE seq = 2", [], |r| {
                    r.get(0)
                })?,
            )
        })
        .unwrap();
    let bytes = original.as_bytes();
    for i in 0..bytes.len() {
        let mut mutated = bytes.to_vec();
        mutated[i] = if mutated[i] == b'x' { b'y' } else { b'x' };
        let Ok(mutated) = String::from_utf8(mutated) else {
            continue;
        };
        exec(
            &s,
            "UPDATE audit SET record_json = ?1 WHERE seq = 2",
            &[&mutated],
        );
        let report = s.verify_chain().unwrap();
        assert!(!report.ok, "byte {i}");
        assert_eq!(report.first_bad_seq, Some(2), "byte {i}");
    }
    exec(
        &s,
        "UPDATE audit SET record_json = ?1 WHERE seq = 2",
        &[&original],
    );
    assert!(s.verify_chain().unwrap().ok);
}

#[test]
fn tamper_decision_column_is_detected() {
    let s = sqlite_with(5);
    // seq 3 is record(2): an allow. Flip the indexed column only; JSON and hash are untouched.
    exec(&s, "UPDATE audit SET decision = 'deny' WHERE seq = 3", &[]);
    let report = s.verify_chain().unwrap();
    assert!(!report.ok);
    assert_eq!(report.first_bad_seq, Some(3));
    // Readers get an error for that row rather than the forged value.
    let err = s.range(3, 1).unwrap_err();
    assert!(
        matches!(err, onbehalf_audit::AuditError::Corrupt { seq: 3, .. }),
        "{err}"
    );
}

#[test]
fn tamper_prev_hash_is_detected() {
    let s = sqlite_with(5);
    exec(
        &s,
        "UPDATE audit SET prev_hash = ?1 WHERE seq = 3",
        &[&"f".repeat(64)],
    );
    let report = s.verify_chain().unwrap();
    assert_eq!(report.first_bad_seq, Some(3));
    assert_eq!(report.entries, 3);
}

#[test]
fn tamper_entry_hash_is_detected() {
    let s = sqlite_with(5);
    exec(
        &s,
        "UPDATE audit SET entry_hash = ?1 WHERE seq = 2",
        &[&"a".repeat(64)],
    );
    assert_eq!(s.verify_chain().unwrap().first_bad_seq, Some(2));
}

#[test]
fn delete_middle_row_is_detected() {
    let s = sqlite_with(7);
    exec(&s, "DELETE FROM audit WHERE seq = 4", &[]);
    let report = s.verify_chain().unwrap();
    assert!(!report.ok);
    assert_eq!(report.first_bad_seq, Some(5), "the row after the gap");
    assert_eq!(report.entries, 4, "three good rows plus the bad one");
}

#[test]
fn delete_head_row_is_detected_by_checkpoint_mismatch() {
    // Truncating the tail cannot be seen by verify_chain alone (the remaining prefix is
    // valid); that is what checkpoint() countersigning is for.
    let s = sqlite_with(5);
    let (seq, hash) = s.checkpoint().unwrap();
    exec(&s, "DELETE FROM audit WHERE seq = 5", &[]);
    assert!(s.verify_chain().unwrap().ok);
    assert_ne!(s.checkpoint().unwrap(), (seq, hash));
}

#[test]
fn reordered_rows_are_detected() {
    let s = sqlite_with(4);
    // Swap seq 2 and 3 by renumbering through a temporary value.
    exec(&s, "UPDATE audit SET seq = 99 WHERE seq = 2", &[]);
    exec(&s, "UPDATE audit SET seq = 2 WHERE seq = 3", &[]);
    exec(&s, "UPDATE audit SET seq = 3 WHERE seq = 99", &[]);
    assert_eq!(s.verify_chain().unwrap().first_bad_seq, Some(2));
}

#[test]
fn memory_sink_detects_tamper_too() {
    // MemoryAudit has no external tamper surface, but verify_entries is shared: feed it a
    // forged sequence to pin the behaviour.
    let m = MemoryAudit::new();
    fill(&m, 4);
    let mut entries = m.snapshot().unwrap();
    entries[2].record.decision = Decision::Allow;
    entries[2].record.reason = "forged".into();
    let report = onbehalf_audit::verify_entries(entries.into_iter().map(Ok)).unwrap();
    assert_eq!(report.first_bad_seq, Some(3));
}

// ---- queries ----

#[test]
fn queries_by_subject_chain_and_lease() {
    let s = SqliteAudit::open_in_memory().unwrap();
    let a = chain("user:alice", ("la-1", "la-2"));
    let b = chain("user:bob", ("lb-1", "lb-2"));
    let b2 = chain("user:bob", ("lb-1", "lb-20"));
    for i in 0..5 {
        s.append(record_for(&a, i, Decision::Allow)).unwrap();
    }
    for i in 0..3 {
        s.append(record_for(&b, i, Decision::Deny)).unwrap();
    }
    s.append(record_for(&b2, 9, Decision::Allow)).unwrap();

    let alice = s.by_subject("user:alice", 10).unwrap();
    assert_eq!(alice.len(), 5);
    assert!(alice
        .iter()
        .all(|e| e.record.originating_subject == "user:alice"));
    assert_eq!(alice[0].seq, 5, "newest first");
    assert_eq!(s.by_subject("user:alice", 2).unwrap().len(), 2);
    assert!(s.by_subject("user:nobody", 10).unwrap().is_empty());

    let by_chain = s.by_chain(&b.digest()).unwrap();
    assert_eq!(
        by_chain.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![6, 7, 8]
    );
    assert_eq!(s.by_chain(&b2.digest()).unwrap().len(), 1);

    assert_eq!(s.by_lease(&LeaseId::new("lb-1")).unwrap().len(), 4);
    assert_eq!(
        s.by_lease(&LeaseId::new("lb-2")).unwrap().len(),
        3,
        "lb-2 must not match lb-20"
    );
    assert_eq!(s.by_lease(&LeaseId::new("lb-20")).unwrap().len(), 1);
    assert_eq!(s.by_lease(&LeaseId::new("la-2")).unwrap().len(), 5);
    assert!(s.by_lease(&LeaseId::new("l")).unwrap().is_empty());
    assert!(s.by_lease(&LeaseId::new("%")).unwrap().is_empty());
}

// ---- persistence ----

#[test]
fn sqlite_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let head_hash = {
        let s = SqliteAudit::open(&path).unwrap();
        fill(&s, 6);
        s.checkpoint().unwrap().1
    };
    let s = SqliteAudit::open(&path).unwrap();
    assert_eq!(s.len().unwrap(), 6);
    assert_eq!(s.checkpoint().unwrap(), (6, head_hash.clone()));
    let report = s.verify_chain().unwrap();
    assert!(report.ok, "{report:?}");
    // Appending after reopen continues the chain from the persisted head.
    let e7 = s.append(record(6)).unwrap();
    assert_eq!(e7.seq, 7);
    assert_eq!(e7.prev_hash, head_hash);
    assert!(s.verify_chain().unwrap().ok);

    // Tampering through a second, independent connection to the same file is caught.
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE audit SET reason = ?1 WHERE seq = 2",
        params!["policy_allow_forged"],
    )
    .unwrap();
    drop(raw);
    assert_eq!(s.verify_chain().unwrap().first_bad_seq, Some(2));
}
