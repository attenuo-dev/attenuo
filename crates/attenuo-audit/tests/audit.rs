//! Audit chain: append, verify, tamper detection, concurrency, queries, persistence.

mod common;

use std::sync::Arc;

use attenuo_audit::{
    compute_entry_hash, AuditSink, MemoryAudit, SqliteAudit, VerifyReport, GENESIS_HASH,
};
use attenuo_audit::{ExportHeader, RecordFilter};
use attenuo_core::{Decision, LeaseId, RecordKind};
use common::{chain, record, record_for};
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
    // A file-backed log too: appends go through the group-commit writer and real WAL commits.
    // (Checkpoints under concurrency: tests/checkpoints.rs.)
    let dir = tempfile::tempdir().unwrap();
    let file = Arc::new(SqliteAudit::open(dir.path().join("audit.db")).unwrap());
    let targets: Vec<Arc<dyn AuditSink>> = vec![sqlite.clone(), memory.clone(), file];
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
        matches!(err, attenuo_audit::AuditError::Corrupt { seq: 3, .. }),
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
    let report = attenuo_audit::verify_entries(entries.into_iter().map(Ok)).unwrap();
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

/// The SQLite sink hashes the record text it stores instead of serializing the record twice.
/// That must be byte-for-byte the canonical hash, or `verify_chain` would reject the log.
#[test]
fn entry_hash_from_stored_json_equals_the_canonical_hash() {
    use attenuo_audit::{canonical_record_json, entry_hash_from_json, ENTRY_HASH_VERSION};
    use attenuo_core::digest::sha256_bytes;
    use attenuo_core::jcs;
    for i in 0..20 {
        let r = record(i);
        let json = canonical_record_json(&r);
        for (seq, prev) in [(1, GENESIS_HASH), (u64::MAX, "ab\"c\\d\n"), (42, "")] {
            let expected = compute_entry_hash(seq, prev, &r);
            assert_eq!(entry_hash_from_json(seq, prev, &json), expected);
            // SR-20: the hash is SHA-256 over the RFC 8785 form of the tagged array.
            let canonical = jcs::to_vec(&(ENTRY_HASH_VERSION, seq, prev, &r)).unwrap();
            assert_eq!(sha256_bytes(&canonical), expected);
        }
    }
}

/// SR-20: the stored record text is RFC 8785 canonical (sorted members), so its hash does not
/// depend on the declaration order of `DecisionRecord`'s fields or on `preserve_order`.
#[test]
fn stored_record_json_is_canonical_sr20() {
    let s = SqliteAudit::open_in_memory().unwrap();
    s.append(record(3)).unwrap();
    let stored: String = s
        .with_connection(|c| {
            Ok(
                c.query_row("SELECT record_json FROM audit WHERE seq = 1", [], |r| {
                    r.get(0)
                })?,
            )
        })
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&stored).unwrap();
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "{stored}");
    assert_eq!(attenuo_core::jcs::to_string(&v).unwrap(), stored);
}

fn kinded(sink: &SqliteAudit) {
    let c1 = chain("user:mudit", ("l1", "l2"));
    let c2 = chain("user:other", ("m1", "m2"));
    let kinds = [
        (&c1, RecordKind::Exchange),
        (&c1, RecordKind::Decision),
        (&c2, RecordKind::Exchange),
        (&c2, RecordKind::Decision),
        (&c1, RecordKind::LeaseRenew),
        (&c2, RecordKind::Decision),
    ];
    for (i, (c, k)) in kinds.into_iter().enumerate() {
        sink.append(record_for(c, i, Decision::Allow).with_kind(k))
            .unwrap();
    }
}

#[test]
fn records_carry_kind_and_chain_id_at_the_top_level_of_the_hashed_json() {
    let s = SqliteAudit::open_in_memory().unwrap();
    kinded(&s);
    let e = s.range(1, 10).unwrap();
    assert_eq!(e[0].record.kind, RecordKind::Exchange);
    assert_eq!(e[0].record.chain_id.as_deref(), Some("l1"));
    assert_eq!(e[2].record.chain_id.as_deref(), Some("m1"));
    let json = attenuo_audit::canonical_record_json(&e[4].record);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["kind"], "lease_renew");
    assert_eq!(v["chain_id"], "l1");
    // The fields are part of the hash: changing either changes it.
    let mut r = e[4].record.clone();
    let h = compute_entry_hash(5, &e[4].prev_hash, &r);
    assert_eq!(h, e[4].entry_hash);
    r.kind = RecordKind::Decision;
    assert_ne!(compute_entry_hash(5, &e[4].prev_hash, &r), h);
    r.kind = RecordKind::LeaseRenew;
    r.chain_id = None;
    assert_ne!(compute_entry_hash(5, &e[4].prev_hash, &r), h);
    assert!(s.verify_chain().unwrap().ok);
}

#[test]
fn range_filtered_matches_kind_and_chain_id_within_the_range() {
    let s = SqliteAudit::open_in_memory().unwrap();
    kinded(&s);
    let seqs = |f: RecordFilter, from, to| -> Vec<u64> {
        s.range_filtered(from, to, &f, 100)
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect()
    };
    let kind = |k| RecordFilter {
        kind: Some(k),
        chain_id: None,
    };
    let chain = |c: &str| RecordFilter {
        kind: None,
        chain_id: Some(c.into()),
    };
    assert_eq!(seqs(RecordFilter::default(), 1, 6), [1, 2, 3, 4, 5, 6]);
    assert_eq!(seqs(kind(RecordKind::Decision), 1, 6), [2, 4, 6]);
    assert_eq!(seqs(kind(RecordKind::Decision), 3, 5), [4]);
    assert_eq!(seqs(kind(RecordKind::Admin), 1, 6), Vec::<u64>::new());
    assert_eq!(seqs(chain("l1"), 1, 6), [1, 2, 5]);
    assert_eq!(seqs(chain("m1"), 1, 6), [3, 4, 6]);
    assert_eq!(seqs(chain("nope"), 1, 6), Vec::<u64>::new());
    let both = RecordFilter {
        kind: Some(RecordKind::Exchange),
        chain_id: Some("m1".into()),
    };
    assert_eq!(seqs(both, 1, 6), [3]);
    // The limit applies to matches.
    let f = kind(RecordKind::Decision);
    assert_eq!(s.range_filtered(1, 6, &f, 2).unwrap().len(), 2);
}

#[test]
fn tamper_kind_or_chain_id_column_is_detected() {
    for sql in [
        "UPDATE audit SET kind = 'admin' WHERE seq = 2",
        "UPDATE audit SET chain_id = 'x' WHERE seq = 2",
        "UPDATE audit SET chain_id = NULL WHERE seq = 2",
    ] {
        let s = SqliteAudit::open_in_memory().unwrap();
        kinded(&s);
        exec(&s, sql, &[]);
        let report = s.verify_chain().unwrap();
        assert_eq!(report.first_bad_seq, Some(2), "{sql}");
    }
}

#[test]
fn a_filtered_export_is_marked_and_refused_by_verification() {
    let h = ExportHeader::new(1, 6, "2026-10-23T00:00:00Z".into());
    assert!(h.filter.is_none());
    assert!(!attenuo_audit::header_line(&h).contains("filter"));
    let same = h.clone().with_filter(RecordFilter::default());
    assert_eq!(same, h);
    let f = RecordFilter {
        kind: Some(RecordKind::LeaseRevoke),
        chain_id: None,
    };
    let line = attenuo_audit::header_line(&h.clone().with_filter(f.clone()));
    assert!(
        line.contains(r#""filter":{"kind":"lease_revoke"}"#),
        "{line}"
    );

    let s = SqliteAudit::open_in_memory().unwrap();
    kinded(&s);
    let mut text = line;
    for e in s
        .range(1, 10)
        .unwrap()
        .iter()
        .filter(|e| f.matches(&e.record))
    {
        text.push_str(&attenuo_audit::entry_line(e));
    }
    let export = attenuo_audit::parse_export(&text).unwrap();
    assert_eq!(export.header.unwrap().filter, Some(f));
    let keys = attenuo_audit::CheckpointKeys::from_jwks(&serde_json::json!({"keys": []})).unwrap();
    let export = attenuo_audit::parse_export(&text).unwrap();
    let err = attenuo_audit::verify_export(&export, &keys).unwrap_err();
    assert!(err.to_string().contains("filtered"), "{err}");
}

/// The SDKs (Python `tests/test_audit.py`, TypeScript `test/audit.test.ts`) assert the same
/// record and hash: it pins the construction across implementations.
#[test]
fn entry_hash_golden_vector() {
    let record: attenuo_core::DecisionRecord = serde_json::from_value(serde_json::json!({
        "agents": ["agent:planner"], "arguments_digest": "ab".repeat(32), "chain_depth": 1,
        "chain_digest": "cd".repeat(32), "chain_id": "l1", "decision": "allow",
        "id": "00000000-0000-4000-8000-000000000001", "kind": "decision", "leases": ["l1"],
        "originating_subject": "user:mudit", "reason": "policy_allow", "server": "github",
        "tool": "read_file", "at": "2026-10-23T12:00:00Z"
    }))
    .unwrap();
    assert_eq!(
        compute_entry_hash(7, &"11".repeat(32), &record),
        "e8ababad86538918f6eee2d5edb7e6aa4bfa8f8f6ea032f2b5fde00dfe52d693"
    );
}

/// Fuzzing F4: an entry whose `seq` is `u64::MAX`, with a correct hash, used to overflow
/// `seq + 1` in the chain walk (a panic with overflow checks on). It is now a bad entry.
#[test]
fn an_entry_at_u64_max_fails_verification_cleanly_f4() {
    use attenuo_audit::{verify_with_checkpoints, AuditEntry, CheckpointKeys, Start};
    let first = AuditEntry::next(None, record(0));
    let mut last = AuditEntry::next(Some(&first), record(1));
    last.seq = u64::MAX;
    last.entry_hash = compute_entry_hash(last.seq, &last.prev_hash, &last.record);
    assert!(last.hash_matches());
    // As the only entry of a window (the first entry sets the expected seq).
    let r = verify_with_checkpoints(
        [Ok(last.clone())],
        &[],
        &CheckpointKeys::default(),
        Start::Window,
    )
    .unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(u64::MAX));
    // After a good entry, anchored.
    let r = attenuo_audit::verify_entries([Ok(first), Ok(last)]).unwrap();
    assert_eq!(
        r,
        VerifyReport {
            entries: 2,
            ok: false,
            first_bad_seq: Some(u64::MAX)
        }
    );
}

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

// ---- durability settings ----

fn pragma(s: &SqliteAudit, name: &str) -> String {
    s.with_connection(|c| {
        Ok(c.query_row(&format!("PRAGMA {name}"), [], |r| {
            r.get::<_, rusqlite::types::Value>(0)
        })?)
    })
    .map(|v| match v {
        rusqlite::types::Value::Integer(i) => i.to_string(),
        rusqlite::types::Value::Text(t) => t,
        other => format!("{other:?}"),
    })
    .unwrap()
}

#[test]
fn file_log_runs_in_wal_mode_at_the_requested_durability() {
    use attenuo_audit::Durability;
    let dir = tempfile::tempdir().unwrap();
    for (durability, synchronous) in [(Durability::Normal, "1"), (Durability::Full, "2")] {
        let path = dir.path().join(format!("{durability}.db"));
        let s = SqliteAudit::open_with(&path, durability).unwrap();
        assert_eq!(pragma(&s, "journal_mode"), "wal", "{durability}");
        assert_eq!(pragma(&s, "synchronous"), synchronous, "{durability}");
        assert_eq!(pragma(&s, "busy_timeout"), "5000", "{durability}");
        fill(&s, 5);
        drop(s);
        // WAL mode is persistent; the data survives a reopen at the other setting.
        let s = SqliteAudit::open_with(&path, Durability::Normal).unwrap();
        assert_eq!(pragma(&s, "journal_mode"), "wal");
        let report = s.verify_chain().unwrap();
        assert!(report.ok && report.entries == 5, "{report:?}");
    }
    // `open` is `normal`, and so is the default.
    assert_eq!(Durability::default(), Durability::Normal);
    let s = SqliteAudit::open(dir.path().join("default.db")).unwrap();
    assert_eq!(pragma(&s, "synchronous"), "1");
}

#[test]
fn durability_parses_from_config_strings() {
    use attenuo_audit::Durability;
    #[derive(serde::Deserialize)]
    struct T {
        d: Durability,
    }
    let t: T = serde_json::from_str(r#"{"d":"full"}"#).unwrap();
    assert_eq!(t.d, Durability::Full);
    let t: T = serde_json::from_str(r#"{"d":"normal"}"#).unwrap();
    assert_eq!(t.d, Durability::Normal);
    assert!(serde_json::from_str::<T>(r#"{"d":"off"}"#).is_err());
}

/// An append that finds the store idle commits on the caller's thread: sequential appends
/// never start the writer thread, and the chain is the same as through the writer.
#[test]
fn idle_appends_commit_inline_without_the_writer_thread() {
    let s = SqliteAudit::open_in_memory().unwrap();
    for i in 0..20 {
        assert_eq!(s.append(record(i)).unwrap().seq, i as u64 + 1);
    }
    assert!(format!("{s:?}").contains("writer_started: false"), "{s:?}");
    assert!(s.verify_chain().unwrap().ok);

    // Contended appends go through the writer; mixed with inline ones the chain stays linear.
    let s = Arc::new(s);
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                for i in 0..100 {
                    s.append(record(1000 + t * 100 + i)).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let report = s.verify_chain().unwrap();
    assert!(report.ok);
    assert_eq!(report.entries, 820);
}
