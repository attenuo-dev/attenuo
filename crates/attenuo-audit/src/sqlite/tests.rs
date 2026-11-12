use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use attenuo_core::{Charge, DecisionRecord, LeaseId, LimitKind};
use rusqlite::Connection;

use crate::budget::ChargeOutcome;
use crate::checkpoint::Checkpoint;
use crate::error::AuditError;
use crate::export::RecordFilter;
use crate::lease::LeaseStore;
use crate::log::{AuditSink, ENTRY_HASH_VERSION};
use crate::query::{EntryFilter, Order};

use super::connection::{
    open_connection, with_full_sync, Durability, Ticket, WriteGate, SYNC_FULL, SYNC_NORMAL,
};
use super::leases::SqliteLeaseStore;
use super::log::{SqliteAudit, ENTRY_COLUMNS};
use super::schema::RECORD_ID_EXPR;
use super::wal::{nears_checkpoint, WAL_WRITER_BACKSTOP_FRAMES};
use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, OriginatingUser, RecordKind,
    ToolCall,
};
use time::macros::datetime;

fn record(i: i64) -> DecisionRecord {
    let at = datetime!(2026-10-23 12:00 UTC);
    let chain = DelegationChain::root(
        OriginatingUser {
            subject: "user:mudit".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: at,
            attributes: Default::default(),
        },
        AgentId::new("agent:planner"),
        CapabilitySet::from_iter([Capability::new("github", "*")]),
        at,
        time::Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap();
    let call = ToolCall::new("github", "read_file", serde_json::json!({ "i": i }));
    DecisionRecord::new(
        at + time::Duration::seconds(i),
        Decision::Allow,
        "policy_allow",
        &chain,
        &call,
        vec![],
    )
}

fn issuer() -> attenuo_token::Issuer {
    attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    })
}

fn synchronous(log: &SqliteAudit) -> i64 {
    log.with_connection(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
        .unwrap()
}

/// SR-50: at `durability = "normal"`, the commit that writes a signed checkpoint runs at
/// `synchronous=FULL` (2), the hook sees the checkpoint only after that commit, and the
/// connection is back at `NORMAL` (1) afterwards. Appends here run one at a time on the
/// caller's thread, so the log's order is deterministic.
#[test]
fn checkpoint_commits_are_synced_before_the_hook_sr50() {
    let dir = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let log = SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Normal)
        .unwrap()
        .with_checkpointing(issuer().detached_signer(), 3)
        .with_checkpoint_hook(move |cp| seen.lock().unwrap().push(format!("hook {}", cp.seq)))
        .with_probe(Arc::clone(&events));
    assert_eq!(synchronous(&log), SYNC_NORMAL);
    for i in 0..4 {
        log.append(record(i)).unwrap();
    }
    log.checkpoint_signed(datetime!(2026-10-23 13:00 UTC))
        .unwrap();
    // Asking again returns the stored checkpoint: no commit, no hook.
    log.checkpoint_signed(datetime!(2026-10-23 13:00 UTC))
        .unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        [
            "commit 1 synchronous=1",
            "commit 2 synchronous=1",
            "commit 3 synchronous=2",
            "hook 3",
            "commit 4 synchronous=1",
            "checkpoint 4 synchronous=2",
            "hook 4",
        ]
    );
    assert_eq!(synchronous(&log), SYNC_NORMAL);
    assert!(log.verify_chain().unwrap().ok);
}

/// SR-50, batched: a group commit that crosses a checkpoint is retried as a whole at
/// `FULL`, and every record of it still gets its entry.
#[test]
fn a_batch_crossing_a_checkpoint_is_committed_synced_sr50() {
    let dir = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let log = SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Normal)
        .unwrap()
        .with_checkpointing(issuer().detached_signer(), 4)
        .with_checkpoint_hook(move |cp| seen.lock().unwrap().push(format!("hook {}", cp.seq)))
        .with_probe(Arc::clone(&events));
    let entries = {
        let mut conn = log.inner.conn.lock().unwrap();
        log.inner
            .append_locked(&mut conn, (0..6).map(record).collect(), false)
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        *events.lock().unwrap(),
        ["commit 6 synchronous=2", "hook 4"]
    );
    assert_eq!(synchronous(&log), SYNC_NORMAL);
    assert_eq!(log.len().unwrap(), 6);
}

/// Charges against lease `l1`: `calls` (max 100), and with `sum` a `sum` on `n`
/// (max `sum_max`) adding `amount`.
fn charges(sum: Option<(u64, u64)>) -> Vec<Charge> {
    let mut out = vec![Charge {
        hop: 0,
        cap: 0,
        lease: LeaseId::new("l1"),
        kind: LimitKind::Calls,
        arg: None,
        value: None,
        amount: 1,
        max: 100,
        usage: false,
    }];
    if let Some((amount, max)) = sum {
        out.push(Charge {
            hop: 0,
            cap: 0,
            lease: LeaseId::new("l1"),
            kind: LimitKind::Sum,
            arg: Some("n".into()),
            value: None,
            amount,
            max,
            usage: false,
        });
    }
    out
}

/// A log and a lease store on one file at `durability`, both writing to `events`.
fn shared_file(
    dir: &tempfile::TempDir,
    durability: Durability,
    events: &Arc<Mutex<Vec<String>>>,
) -> (SqliteAudit, SqliteLeaseStore) {
    let path = dir.path().join("audit.db");
    let log = SqliteAudit::open_with(&path, durability)
        .unwrap()
        .with_probe(Arc::clone(events));
    let leases = SqliteLeaseStore::open_with(&path, durability)
        .unwrap()
        .with_probe(Arc::clone(events));
    (log, leases)
}

fn lease_synchronous(leases: &SqliteLeaseStore) -> i64 {
    leases
        .with_connection(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
        .unwrap()
}

/// Design 3.4 at `durability = "normal"`: a `sum` charge is synced before the call goes
/// on. `charge` syncs its own commit; `charge_sync_deferred` commits at `NORMAL` and says
/// so, and the decision's `append_synced` on the same file then commits at `FULL`, which
/// syncs the WAL holding both. A `calls`-only charge and a plain append are unchanged.
#[test]
fn a_deferred_sum_charge_is_synced_by_the_decision_append() {
    let dir = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (log, leases) = shared_file(&dir, Durability::Normal, &events);
    assert!(leases.sync_file().is_some());
    assert_eq!(leases.sync_file(), log.sync_file());
    let at = datetime!(2026-10-24 12:00 UTC);
    leases
        .register(&LeaseId::new("l1"), None, at + time::Duration::hours(1))
        .unwrap();
    let sum = charges(Some((1, 1000)));

    assert!(matches!(
        leases.charge("d1", &sum, at).unwrap(),
        ChargeOutcome::Charged { .. }
    ));
    let (outcome, owed) = leases.charge_sync_deferred("d2", &sum, at).unwrap();
    assert!(matches!(outcome, ChargeOutcome::Charged { .. }) && owed);
    log.append_synced(record(1)).unwrap();
    let (_, owed) = leases
        .charge_sync_deferred("d3", &charges(None), at)
        .unwrap();
    assert!(!owed, "a calls-only charge owes no sync");
    log.append(record(2)).unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        [
            "charge synchronous=2",
            "charge synchronous=1",
            "commit 1 synchronous=2",
            "charge synchronous=1",
            "commit 2 synchronous=1",
        ]
    );
    // Both connections are back at the store's level.
    assert_eq!(synchronous(&log), SYNC_NORMAL);
    assert_eq!(lease_synchronous(&leases), SYNC_NORMAL);
}

/// The deferred charge keeps the exhaustion check of `charge`: the re-check and the
/// writes stay in one transaction, a charge that would go over writes nothing and owes
/// no sync, and concurrent deferred charges never spend more than `max`.
#[test]
fn a_deferred_sum_charge_is_still_checked_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (_log, leases) = shared_file(&dir, Durability::Normal, &events);
    let at = datetime!(2026-10-24 12:00 UTC);
    leases
        .register(&LeaseId::new("l1"), None, at + time::Duration::hours(1))
        .unwrap();
    let leases = Arc::new(leases);
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let leases = Arc::clone(&leases);
            std::thread::spawn(move || {
                (0..5)
                    .filter(|i| {
                        let id = format!("d{t}-{i}");
                        let (outcome, owed) = leases
                            .charge_sync_deferred(&id, &charges(Some((3, 30))), at)
                            .unwrap();
                        let charged = matches!(outcome, ChargeOutcome::Charged { .. });
                        assert_eq!(charged, owed, "{outcome:?}");
                        charged
                    })
                    .count()
            })
        })
        .collect();
    let charged: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
    assert_eq!(charged, 10, "30 / 3: exactly ten charges fit");
    assert_eq!(
        leases.budget_used(&charges(Some((0, 30)))).unwrap(),
        [10, 30]
    );
    // Only the charges that went through committed anything.
    assert_eq!(events.lock().unwrap().len(), 10);
}

/// Nothing is deferred where `charge` has no sync to skip: a store at `full` syncs every
/// commit, and an in-memory store has no file.
#[test]
fn full_and_in_memory_stores_never_defer_a_charge() {
    let dir = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (log, leases) = shared_file(&dir, Durability::Full, &events);
    let memory = SqliteLeaseStore::open_in_memory().unwrap();
    assert_eq!(memory.sync_file(), None);
    let at = datetime!(2026-10-24 12:00 UTC);
    for store in [&leases, &memory] {
        let (outcome, owed) = store
            .charge_sync_deferred("d1", &charges(Some((1, 10))), at)
            .unwrap();
        assert!(matches!(outcome, ChargeOutcome::Charged { .. }) && !owed);
    }
    log.append_synced(record(1)).unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["charge synchronous=2", "commit 1 synchronous=2"]
    );
}

/// Group commit: one record appended with `append_synced` makes its whole batch commit at
/// `FULL`, so one sync covers every record in it.
#[test]
fn a_batch_with_a_synced_record_commits_at_full() {
    let dir = tempfile::tempdir().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Normal)
        .unwrap()
        .with_probe(Arc::clone(&events));
    for sync in [false, true] {
        let results = log.inner.append_batch((0..3).map(record).collect(), sync);
        assert!(results.iter().all(Result::is_ok));
    }
    assert_eq!(
        *events.lock().unwrap(),
        ["commit 3 synchronous=1", "commit 6 synchronous=2"]
    );
    assert_eq!(synchronous(&log), SYNC_NORMAL);
}

/// A store opened at `full` (or in memory) needs no extra step.
#[test]
fn full_and_in_memory_stores_commit_checkpoints_once_sr50() {
    let dir = tempfile::tempdir().unwrap();
    for log in [
        SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Full).unwrap(),
        SqliteAudit::open_in_memory().unwrap(),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let log = log
            .with_checkpointing(issuer().detached_signer(), 2)
            .with_probe(Arc::clone(&events));
        for i in 0..2 {
            log.append(record(i)).unwrap();
        }
        assert_eq!(
            events.lock().unwrap().len(),
            2,
            "{:?}",
            events.lock().unwrap()
        );
    }
}

/// SR-51: the synced operation's result comes back even when lowering `synchronous`
/// afterwards fails (here because the operation left a transaction open, inside which
/// SQLite refuses to change it).
#[test]
fn a_failed_restore_does_not_replace_the_result_sr51() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = open_connection(&dir.path().join("x.db"), Durability::Normal).unwrap();
    let out = with_full_sync(&mut conn, Some(SYNC_NORMAL), |c| {
        c.execute_batch("BEGIN")?;
        Ok::<_, AuditError>(7)
    });
    assert_eq!(out.unwrap().unwrap(), 7);
    // The restore did fail: the connection is still at FULL.
    let level: i64 = conn
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .unwrap();
    assert_eq!(level, SYNC_FULL);
    // And a failure of the operation itself is returned as such.
    conn.execute_batch("ROLLBACK").unwrap();
    let out = with_full_sync(&mut conn, Some(SYNC_NORMAL), |_| {
        Err::<u64, _>(AuditError::UnknownLease("x".into()))
    });
    assert!(matches!(out, Ok(Err(AuditError::UnknownLease(_)))));
}

/// SR-51: `revoke` at `normal` answers with the revocation's result, commits at `FULL` and
/// goes back to `NORMAL`.
#[test]
fn revoke_returns_the_revocation_result_sr51() {
    let dir = tempfile::tempdir().unwrap();
    let store =
        SqliteLeaseStore::open_with(dir.path().join("leases.db"), Durability::Normal).unwrap();
    let now = datetime!(2026-10-23 12:00 UTC);
    let (a, b) = (LeaseId::new("a"), LeaseId::new("b"));
    store
        .register(&a, None, now + time::Duration::hours(1))
        .unwrap();
    store
        .register(&b, Some(&a), now + time::Duration::hours(1))
        .unwrap();
    assert_eq!(store.revoke(&a, "test", now).unwrap(), 2);
    assert!(matches!(
        store.revoke(&LeaseId::new("nope"), "test", now),
        Err(AuditError::UnknownLease(_))
    ));
    let level: i64 = store
        .with_connection(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(level, SYNC_NORMAL);
}

/// SR-20: a log written with the v1 entry hash (no `audit_meta` row, entries present) is
/// refused with a clear error; a new log records the construction.
#[test]
fn a_log_from_before_kind_and_chain_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE audit (seq INTEGER PRIMARY KEY, record_json TEXT NOT NULL)",
        )
        .unwrap();
    }
    let err = SqliteAudit::open(&path).unwrap_err().to_string();
    assert!(err.contains("`kind` and `chain_id`"), "{err}");
}

#[test]
fn a_log_with_v1_hashes_is_refused_sr20() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    {
        let log = SqliteAudit::open(&path).unwrap();
        log.append(record(0)).unwrap();
        log.with_connection(|c| Ok(c.execute("DROP TABLE audit_meta", [])?))
            .unwrap();
    }
    let err = SqliteAudit::open(&path).unwrap_err().to_string();
    assert!(err.contains("earlier attenuo"), "{err}");
    assert!(err.contains(ENTRY_HASH_VERSION), "{err}");
    let other = dir.path().join("other.db");
    {
        let log = SqliteAudit::open(&other).unwrap();
        log.with_connection(|c| {
            Ok(c.execute("UPDATE audit_meta SET value = 'attenuo-audit-entry-v9'", [])?)
        })
        .unwrap();
    }
    let err = SqliteAudit::open(&other).unwrap_err().to_string();
    assert!(err.contains("attenuo-audit-entry-v9"), "{err}");
    // Reopening a current log works, empty or not.
    let fresh = dir.path().join("fresh.db");
    SqliteAudit::open(&fresh).unwrap();
    let log = SqliteAudit::open(&fresh).unwrap();
    log.append(record(1)).unwrap();
    drop(log);
    assert_eq!(SqliteAudit::open(&fresh).unwrap().len().unwrap(), 1);
}

/// The writer's backstop on its own: with the background checkpointer stuck (the test
/// holds its connection, so every round blocks before its first checkpoint), appends keep
/// the WAL under `WAL_WRITER_BACKSTOP_FRAMES` plus one batch, because the writer
/// checkpoints and truncates it itself once a commit leaves that many frames.
#[test]
fn the_writer_checkpoints_itself_when_the_background_thread_cannot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let audit = SqliteAudit::open_with(&path, Durability::Normal)
        .unwrap()
        .with_wal_checkpoints(Duration::from_millis(1))
        .unwrap();
    let wal_path = {
        let mut p = path.as_os_str().to_owned();
        p.push("-wal");
        PathBuf::from(p)
    };
    let wal_size = || std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    let page_size: i64 = audit
        .with_connection(|c| Ok(c.query_row("PRAGMA page_size", [], |r| r.get(0))?))
        .unwrap();
    let backstop = u64::try_from(WAL_WRITER_BACKSTOP_FRAMES * page_size).unwrap();

    // Park the background thread: it locks its own connection first thing in a round.
    let checkpointer = audit.wal.as_ref().unwrap();
    let parked = checkpointer.conn.lock().unwrap();

    let mut largest = 0;
    let mut truncations = 0;
    let mut i = 0;
    // Single-threaded appends: one commit each, so the WAL grows a few frames at a time
    // and the backstop fires with the WAL just past the threshold.
    while truncations < 2 {
        audit.append(record(i)).unwrap();
        i += 1;
        let size = wal_size();
        if size < largest / 2 {
            truncations += 1;
        }
        largest = largest.max(size);
        assert!(
            size < backstop + (16 << 20),
            "the WAL reached {} MB after {i} appends with the checkpointer parked",
            size >> 20
        );
        assert!(
            i < 100_000,
            "the backstop never fired ({} MB)",
            largest >> 20
        );
    }
    assert!(
        largest >= backstop,
        "the WAL was truncated before the backstop ({} MB)",
        largest >> 20
    );
    drop(parked);
    let report = audit.verify_chain().unwrap();
    assert!(report.ok);
    assert_eq!(report.entries, u64::try_from(i).unwrap());
}

// -----------------------------------------------------------------------------------------
// Queries for the admin API: `entries_matching`, lookups, checkpoint listing, the
// record-id index.
// -----------------------------------------------------------------------------------------

/// A record with the given fields, at `2026-10-23 12:00 UTC + i seconds`.
fn shaped(
    i: i64,
    kind: RecordKind,
    decision: Decision,
    agent: &str,
    lease: &str,
    tool: &str,
) -> DecisionRecord {
    let mut r = record(i);
    r.reason = match decision {
        Decision::Allow => "policy_allow".into(),
        Decision::Deny => "policy_deny".into(),
    };
    r.kind = kind;
    r.decision = decision;
    r.agents = vec![AgentId::new(agent)];
    r.leases = vec![LeaseId::new(lease)];
    r.chain_id = Some(lease.to_string());
    r.tool = tool.into();
    r
}

/// Twelve entries: seqs 1 to 12, at 12:00:01 to 12:00:12. Agents `l1` and `l10`, leases
/// `a_1` and `ab1` (an unescaped `_` would match both), tools `50%` and `50x`.
fn query_log() -> SqliteAudit {
    use Decision as D;
    use RecordKind as K;
    let log = SqliteAudit::open_in_memory().unwrap();
    let rows = [
        (K::Decision, D::Allow, "l1", "a_1", "50%"),
        (K::Decision, D::Deny, "l10", "ab1", "50x"),
        (K::Exchange, D::Allow, "l1", "a_1", "read_file"),
        (K::Decision, D::Deny, "l1", "a_1", "50%"),
        (K::LeaseRenew, D::Allow, "l10", "ab1", "read_file"),
        (K::Decision, D::Allow, "l10", "ab1", "50x"),
        (K::Admin, D::Allow, "l1", "a_1", "read_file"),
        (K::Decision, D::Deny, "l1", "ab1", "read_file"),
        (K::Decision, D::Allow, "l10", "a_1", "50%"),
        (K::Exchange, D::Allow, "l1", "ab1", "50x"),
        (K::Decision, D::Deny, "l10", "a_1", "read_file"),
        (K::Decision, D::Allow, "l1", "ab1", "50%"),
    ];
    for (i, (kind, decision, agent, lease, tool)) in rows.into_iter().enumerate() {
        log.append(shaped(
            i64::try_from(i).unwrap() + 1,
            kind,
            decision,
            agent,
            lease,
            tool,
        ))
        .unwrap();
    }
    log
}

fn seqs(log: &SqliteAudit, filter: &EntryFilter) -> Vec<u64> {
    log.entries_matching(1, u64::MAX, filter, Order::Ascending, 1000)
        .unwrap()
        .iter()
        .map(|e| e.seq)
        .collect()
}

#[test]
fn each_filter_returns_exactly_the_matching_entries() {
    let log = query_log();
    let all = log.range(1, 1000).unwrap();
    let filters = [
        EntryFilter {
            kinds: vec![RecordKind::Exchange, RecordKind::LeaseRenew],
            ..Default::default()
        },
        EntryFilter {
            decision: Some(Decision::Deny),
            ..Default::default()
        },
        EntryFilter {
            reason: Some("policy_allow".into()),
            ..Default::default()
        },
        EntryFilter {
            subject: Some("user:mudit".into()),
            ..Default::default()
        },
        EntryFilter {
            agent: Some(AgentId::new("l1")),
            ..Default::default()
        },
        EntryFilter {
            lease: Some(LeaseId::new("a_1")),
            ..Default::default()
        },
        EntryFilter {
            server: Some("github".into()),
            ..Default::default()
        },
        EntryFilter {
            tool: Some("50%".into()),
            ..Default::default()
        },
        EntryFilter {
            chain_id: Some("ab1".into()),
            ..Default::default()
        },
        EntryFilter {
            since: Some(datetime!(2026-10-23 12:00:04 UTC)),
            until: Some(datetime!(2026-10-23 12:00:09 UTC)),
            ..Default::default()
        },
        EntryFilter {
            kinds: vec![RecordKind::Decision],
            decision: Some(Decision::Allow),
            agent: Some(AgentId::new("l10")),
            ..Default::default()
        },
    ];
    for f in filters {
        let want: Vec<u64> = all
            .iter()
            .filter(|e| f.matches(&e.record))
            .map(|e| e.seq)
            .collect();
        assert!(!want.is_empty(), "{f:?} matches nothing in the fixture");
        assert_eq!(seqs(&log, &f), want, "{f:?}");
    }
    // Spot checks against the fixture table rather than against `matches`.
    let agent = |a: &str| EntryFilter {
        agent: Some(AgentId::new(a)),
        ..Default::default()
    };
    assert_eq!(seqs(&log, &agent("l1")), [1, 3, 4, 7, 8, 10, 12]);
    assert_eq!(seqs(&log, &agent("l10")), [2, 5, 6, 9, 11]);
    assert_eq!(seqs(&log, &agent("l")), Vec::<u64>::new());
    // `LIKE` ignores ASCII case; the exact check does not.
    assert_eq!(seqs(&log, &agent("L1")), Vec::<u64>::new());
    let window = EntryFilter {
        since: Some(datetime!(2026-10-23 12:00:04 UTC)),
        until: Some(datetime!(2026-10-23 12:00:09 UTC)),
        ..Default::default()
    };
    assert_eq!(seqs(&log, &window), [4, 5, 6, 7, 8]);
    let multi = EntryFilter {
        kinds: vec![RecordKind::Exchange, RecordKind::Admin],
        ..Default::default()
    };
    assert_eq!(seqs(&log, &multi), [3, 7, 10]);
    assert_eq!(seqs(&log, &EntryFilter::default()).len(), 12);
}

#[test]
fn percent_and_underscore_match_literally() {
    let log = query_log();
    let lease = |l: &str| EntryFilter {
        lease: Some(LeaseId::new(l)),
        ..Default::default()
    };
    assert_eq!(seqs(&log, &lease("a_1")), [1, 3, 4, 7, 9, 11]);
    assert_eq!(seqs(&log, &lease("ab1")), [2, 5, 6, 8, 10, 12]);
    assert_eq!(seqs(&log, &lease("a%")), Vec::<u64>::new());
    let tool = |t: &str| EntryFilter {
        tool: Some(t.into()),
        ..Default::default()
    };
    assert_eq!(seqs(&log, &tool("50%")), [1, 4, 9, 12]);
    assert_eq!(seqs(&log, &tool("50_")), Vec::<u64>::new());
    let agent = |a: &str| EntryFilter {
        agent: Some(AgentId::new(a)),
        ..Default::default()
    };
    assert_eq!(seqs(&log, &agent("l_")), Vec::<u64>::new());
    assert_eq!(seqs(&log, &agent("%")), Vec::<u64>::new());
}

#[test]
fn pages_cover_the_window_in_both_directions_without_gaps_or_repeats() {
    let log = query_log();
    let l1 = EntryFilter {
        agent: Some(AgentId::new("l1")),
        ..Default::default()
    };
    let want = seqs(&log, &l1);
    for limit in 1..=4 {
        // Ascending: each page starts after the last entry of the previous one.
        let (mut got, mut from) = (Vec::new(), 1);
        loop {
            let page = log
                .entries_matching(from, u64::MAX, &l1, Order::Ascending, limit)
                .unwrap();
            got.extend(page.iter().map(|e| e.seq));
            if page.len() < limit {
                break;
            }
            from = page.last().unwrap().seq + 1;
        }
        assert_eq!(got, want, "ascending, limit {limit}");
        // Descending: each page ends before the last (oldest) entry of the previous one.
        let (mut got, mut hi) = (Vec::new(), 12);
        loop {
            let page = log
                .entries_matching(1, hi, &l1, Order::Descending, limit)
                .unwrap();
            got.extend(page.iter().map(|e| e.seq));
            if page.len() < limit {
                break;
            }
            hi = page.last().unwrap().seq - 1;
        }
        got.reverse();
        assert_eq!(got, want, "descending, limit {limit}");
    }
    // The window bounds the scan.
    let some = log
        .entries_matching(5, 9, &EntryFilter::default(), Order::Descending, 100)
        .unwrap();
    assert_eq!(
        some.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [9, 8, 7, 6, 5]
    );
}

#[test]
fn range_filtered_keeps_its_meaning() {
    let log = query_log();
    let f = RecordFilter {
        kind: Some(RecordKind::Exchange),
        chain_id: None,
        ..Default::default()
    };
    let got: Vec<u64> = log
        .range_filtered(1, 12, &f, 100)
        .unwrap()
        .iter()
        .map(|e| e.seq)
        .collect();
    assert_eq!(got, [3, 10]);
    let unfiltered = log
        .range_filtered(1, 5, &RecordFilter::default(), 100)
        .unwrap();
    assert_eq!(unfiltered.len(), 5);
}

#[test]
fn lookups_by_seq_and_record_id() {
    let log = query_log();
    let e = log.entry_at(7).unwrap().unwrap();
    assert_eq!(e.seq, 7);
    assert!(log.entry_at(13).unwrap().is_none());
    assert!(log.entry_at(0).unwrap().is_none());
    assert!(log.entry_at(u64::MAX).unwrap().is_none());
    let id = e.record.id.to_string();
    assert_eq!(log.entry_by_record_id(&id).unwrap().unwrap().seq, 7);
    assert!(log
        .entry_by_record_id("00000000-0000-0000-0000-000000000000")
        .unwrap()
        .is_none());
    let plan: Vec<String> = log
        .with_connection(|c| {
            let sql =
                format!("EXPLAIN QUERY PLAN SELECT seq FROM audit WHERE {RECORD_ID_EXPR} = ?1");
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map([&id], |r| r.get::<_, String>(3))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert!(
        plan.iter().any(|p| p.contains("audit_record_id_idx")),
        "{plan:?}"
    );
}

#[test]
fn checkpoints_are_listed_newest_first_without_signing() {
    let log = SqliteAudit::open_in_memory()
        .unwrap()
        .with_checkpointing(issuer().detached_signer(), 3);
    for i in 0..10 {
        log.append(record(i)).unwrap();
    }
    let count = || -> i64 {
        log.with_connection(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM checkpoints", [], |r| r.get(0))?)
        })
        .unwrap()
    };
    assert_eq!(count(), 3);
    let seqs = |v: Vec<Checkpoint>| v.iter().map(|c| c.seq).collect::<Vec<_>>();
    assert_eq!(
        seqs(log.checkpoints_before(u64::MAX, 10).unwrap()),
        [9, 6, 3]
    );
    assert_eq!(seqs(log.checkpoints_before(9, 1).unwrap()), [6]);
    assert!(log.checkpoints_before(3, 10).unwrap().is_empty());
    assert_eq!(log.checkpoint_covering(4).unwrap().unwrap().seq, 6);
    assert_eq!(log.checkpoint_covering(6).unwrap().unwrap().seq, 6);
    assert!(log.checkpoint_covering(10).unwrap().is_none());
    assert_eq!(count(), 3, "listing must not sign");
}

#[test]
fn first_entry_after_finds_the_next_one_of_a_kind() {
    let log = query_log();
    let next = |after| {
        log.first_entry_after(after, RecordKind::Exchange, "50x", &Decision::Allow)
            .unwrap()
            .map(|e| e.seq)
    };
    assert_eq!(next(0), Some(10));
    assert_eq!(next(10), None);
    let deny = log
        .first_entry_after(0, RecordKind::Exchange, "50x", &Decision::Deny)
        .unwrap();
    assert!(deny.is_none());
}

/// The record-id index is created when a log written without it is opened. It changes no
/// row (so no hash) and the log still verifies. A row with damaged JSON does not stop the
/// open; `verify` reports it as before.
#[test]
fn the_record_id_index_is_added_to_an_existing_log_without_touching_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("before-index.db");
    let dump = |log: &SqliteAudit| -> Vec<String> {
        log.with_connection(|c| {
            let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit ORDER BY seq");
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map([], |r| {
                let mut cols = Vec::new();
                for i in 0..18 {
                    cols.push(format!("{:?}", r.get_ref(i)?));
                }
                Ok(cols.join("|"))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .unwrap()
    };
    let index_exists = |log: &SqliteAudit| -> bool {
        log.with_connection(|c| {
            Ok(c.query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master \
                 WHERE type = 'index' AND name = 'audit_record_id_idx')",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap()
    };
    let (before, id) = {
        let log = SqliteAudit::open(&path).unwrap();
        for i in 0..5 {
            log.append(record(i)).unwrap();
        }
        // Make the file look like one written before the index existed.
        log.with_connection(|c| Ok(c.execute_batch("DROP INDEX audit_record_id_idx")?))
            .unwrap();
        assert!(!index_exists(&log));
        let id = log.entry_at(4).unwrap().unwrap().record.id.to_string();
        (dump(&log), id)
    };
    let log = SqliteAudit::open(&path).unwrap();
    assert!(index_exists(&log));
    assert_eq!(dump(&log), before, "opening must not change any row");
    assert!(log.verify_chain().unwrap().ok);
    assert_eq!(log.entry_by_record_id(&id).unwrap().unwrap().seq, 4);
    // A row whose JSON was damaged while the index did not exist.
    log.with_connection(|c| {
        c.execute_batch(
            "DROP INDEX audit_record_id_idx; \
             UPDATE audit SET record_json = '{not json' WHERE seq = 2;",
        )?;
        Ok(())
    })
    .unwrap();
    drop(log);
    let log = SqliteAudit::open(&path).expect("a damaged row must not stop the open");
    assert!(index_exists(&log));
    assert_eq!(log.verify_chain().unwrap().first_bad_seq, Some(2));
}

fn gate_of(g: &WriteGate) -> Arc<Ticket> {
    g.0.clone().expect("a file-backed store has a write gate")
}

/// One gate per canonical file: the audit log and the lease store on one file share it
/// (also through another spelling of the path), stores on other files do not, and an
/// in-memory store has none.
#[test]
fn write_gate_is_shared_per_file_and_absent_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.db");
    let audit = SqliteAudit::open(&a).unwrap();
    let leases = SqliteLeaseStore::open(&a).unwrap();
    let spelled = SqliteLeaseStore::open(dir.path().join(".").join("a.db")).unwrap();
    let other = SqliteLeaseStore::open(dir.path().join("b.db")).unwrap();
    let shared = gate_of(&audit.inner.gate);
    assert!(Arc::ptr_eq(&shared, &gate_of(&leases.gate)));
    assert!(Arc::ptr_eq(&shared, &gate_of(&spelled.gate)));
    assert!(!Arc::ptr_eq(&shared, &gate_of(&other.gate)));
    assert!(SqliteLeaseStore::open_in_memory().unwrap().gate.0.is_none());
    assert!(SqliteAudit::open_in_memory()
        .unwrap()
        .inner
        .gate
        .0
        .is_none());
    assert!(SqliteAudit::open(":memory:")
        .unwrap()
        .inner
        .gate
        .0
        .is_none());
    // Once every store on a file is gone its gate goes too, and a new store gets a new one.
    let weak = Arc::downgrade(&shared);
    drop((shared, audit, leases, spelled));
    assert!(weak.upgrade().is_none());
    let again = SqliteLeaseStore::open(&a).unwrap();
    assert!(again.gate.0.is_some());
}

/// Writes on either connection wait for the gate; reads do not.
#[test]
fn writes_wait_for_the_gate_and_reads_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.db");
    let audit = Arc::new(SqliteAudit::open(&path).unwrap());
    let leases = Arc::new(SqliteLeaseStore::open(&path).unwrap());
    let at = datetime!(2026-10-23 12:00 UTC);
    leases.register(&LeaseId::new("l1"), None, at).unwrap();
    audit.append(record(1)).unwrap();

    let held = leases.gate.hold();
    let (done_tx, done) = mpsc::channel();
    let writers = [
        {
            let (leases, done_tx) = (leases.clone(), done_tx.clone());
            std::thread::spawn(move || {
                leases.renew(&LeaseId::new("l1"), at, at).unwrap();
                done_tx.send("renew").unwrap();
            })
        },
        {
            let (audit, done_tx) = (audit.clone(), done_tx.clone());
            std::thread::spawn(move || {
                audit.append(record(2)).unwrap();
                done_tx.send("append").unwrap();
            })
        },
    ];
    // Lease-store reads go through while the gate is held, even with a lease write
    // waiting for it (the lease store takes the gate before its connection).
    std::thread::sleep(Duration::from_millis(50));
    assert!(leases.get(&LeaseId::new("l1")).unwrap().is_some());
    assert!(leases.labels(&LeaseId::new("l1")).unwrap().is_empty());
    assert!(
        done.recv_timeout(Duration::from_millis(200)).is_err(),
        "a write went through while the gate was held"
    );
    drop(held);
    let mut finished: Vec<_> = (0..2)
        .map(|_| done.recv_timeout(Duration::from_secs(10)).unwrap())
        .collect();
    finished.sort_unstable();
    assert_eq!(finished, ["append", "renew"]);
    writers.into_iter().for_each(|w| w.join().unwrap());
    assert_eq!(audit.head().unwrap().unwrap().seq, 2);
}

/// The WAL sync ahead of a signed checkpoint is asked for once per checkpoint, by the
/// commit that brings the head within the lead of it, and never by the commit that writes
/// the checkpoint itself.
#[test]
fn nears_checkpoint_fires_once_per_checkpoint() {
    // One entry per commit, every 1,000, lead 32: only the commit of entry 968.
    let fired: Vec<u64> = (1..=3000)
        .filter(|&seq| nears_checkpoint(seq, seq, 1000, 32))
        .collect();
    assert_eq!(fired, [968, 1968, 2968]);
    // A batch that steps over the point fires; one that goes past the checkpoint does
    // not (it writes the checkpoint and syncs at FULL anyway).
    assert!(nears_checkpoint(960, 975, 1000, 32));
    assert!(!nears_checkpoint(960, 1000, 1000, 32));
    assert!(!nears_checkpoint(969, 990, 1000, 32));
    // The lead is capped at half the interval; off when the lead or `every` is 0.
    let fired: Vec<u64> = (1..=20)
        .filter(|&seq| nears_checkpoint(seq, seq, 10, 32))
        .collect();
    assert_eq!(fired, [5, 15]);
    assert!(!nears_checkpoint(968, 968, 1000, 0));
    assert!(!nears_checkpoint(968, 968, 0, 32));
}

/// The writer stuck (here: the test holds the connection, as a write stuck on a hung disk
/// would): every append fails within the append timeout instead of blocking, the ones the
/// writer had not taken are never written, and once the writer is free the chain goes on
/// from what it did commit, unforked.
#[test]
fn a_stuck_writer_times_appends_out_and_never_writes_withdrawn_ones() {
    let log = Arc::new(
        SqliteAudit::open_in_memory()
            .unwrap()
            .with_append_limits(64, Duration::from_millis(200)),
    );
    let held = log.inner.conn.lock().unwrap();
    let started = std::time::Instant::now();
    let appenders: Vec<_> = (1..=8)
        .map(|i| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || (i, log.append(record(i))))
        })
        .collect();
    let results: Vec<_> = appenders.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "appends waited {:?}",
        started.elapsed()
    );
    let mut taken = Vec::new();
    for (i, r) in &results {
        match r {
            Err(AuditError::Overloaded(why)) if why.contains("did not take") => {}
            Err(AuditError::Overloaded(why)) if why.contains("did not commit") => taken.push(*i),
            other => panic!("append {i}: expected a timeout, got {other:?}"),
        }
    }
    assert_eq!(log.append_stats().timeouts, 8);
    assert_eq!(log.append_stats().queue_full, 0);
    drop(held);
    // The writer commits the batch it had taken (before or after this append, which may
    // commit inline) and drops the withdrawn jobs.
    let last = log.append(record(100)).unwrap();
    let want = taken.len() as u64 + 1;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while log.head().unwrap().map_or(0, |h| h.seq) < want {
        assert!(
            std::time::Instant::now() < deadline,
            "the writer never caught up"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let entries = log.range(1, 100).unwrap();
    let mut written: Vec<i64> = entries
        .iter()
        .map(|e| e.record.at.unix_timestamp() - datetime!(2026-10-23 12:00 UTC).unix_timestamp())
        .collect();
    written.sort_unstable();
    taken.push(100);
    taken.sort_unstable();
    assert_eq!(
        written, taken,
        "only the records the writer had taken, and the new one"
    );
    assert!(last.seq <= want);
    assert!(log.verify_chain().unwrap().ok);
}

/// A writer that does not drain fills its bounded queue, and further appends fail at once
/// (`queue_full`) rather than waiting.
#[test]
fn a_full_writer_queue_sheds_appends_at_once() {
    let log = Arc::new(
        SqliteAudit::open_in_memory()
            .unwrap()
            .with_append_limits(1, Duration::from_millis(300)),
    );
    let held = log.inner.conn.lock().unwrap();
    let appenders: Vec<_> = (1..=32)
        .map(|i| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || log.append(record(i)))
        })
        .collect();
    for t in appenders {
        assert!(matches!(t.join().unwrap(), Err(AuditError::Overloaded(_))));
    }
    let stats = log.append_stats();
    assert_eq!(stats.queue_full + stats.timeouts, 32);
    // At most the batch the writer took and one queued job can wait; the rest are refused.
    assert!(stats.queue_full >= 1, "{stats:?}");
    drop(held);
    // Withdrawn jobs hold their queue slots until the writer drains them, which it does as
    // soon as it is free: appends succeed again shortly after.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match log.append(record(100)) {
            Ok(_) => break,
            Err(AuditError::Overloaded(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("the writer did not recover: {e}"),
        }
    }
    assert!(log.verify_chain().unwrap().ok);
}

/// Under the default limits a busy writer still group-commits every append, in order.
#[test]
fn bounded_queue_keeps_group_commit_and_order() {
    let log = Arc::new(SqliteAudit::open_in_memory().unwrap());
    let appenders: Vec<_> = (0..16)
        .map(|t| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                (0..50)
                    .map(|i| log.append(record(t * 1000 + i)).unwrap().seq)
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    for t in appenders {
        let seqs = t.join().unwrap();
        // One thread's appends get increasing sequence numbers.
        assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    }
    assert_eq!(log.head().unwrap().unwrap().seq, 800);
    assert_eq!(log.append_stats(), super::log::AppendStats::default());
    assert!(log.verify_chain().unwrap().ok);
}

/// A-1: on a file in WAL mode, queries run on their own read-only connection, so a long read
/// (here simulated by holding the reader's lock, as a verify walking a page does) never holds
/// up an append, and an append is visible to the next read.
#[test]
fn a_read_in_progress_does_not_hold_up_appends() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(SqliteAudit::open(dir.path().join("audit.db")).unwrap());
    log.append(record(0)).unwrap();
    let reading = log
        .reader
        .as_ref()
        .expect("a file in WAL mode has a reader")
        .lock();
    let (done, appended) = mpsc::channel();
    let writer = {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for i in 1..=20 {
                log.append(record(i)).unwrap();
            }
            done.send(()).unwrap();
        })
    };
    appended
        .recv_timeout(Duration::from_secs(10))
        .expect("appends commit while a read holds the reader connection");
    // Queries wait for the reader, not for the writer.
    let (asked, answered) = mpsc::channel();
    let counting = {
        let log = Arc::clone(&log);
        std::thread::spawn(move || asked.send(log.len().unwrap()).unwrap())
    };
    assert!(answered.recv_timeout(Duration::from_millis(100)).is_err());
    drop(reading);
    assert_eq!(answered.recv_timeout(Duration::from_secs(10)).unwrap(), 21);
    writer.join().unwrap();
    counting.join().unwrap();
    assert!(log.verify_chain().unwrap().ok);
    // The reader cannot write.
    let refused = log
        .reader
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .execute("DELETE FROM audit", []);
    assert!(refused.is_err(), "the reader connection is read-only");
    assert_eq!(log.len().unwrap(), 21);
}

/// An in-memory store has no second connection: its reads share the writer's.
#[test]
fn an_in_memory_store_reads_on_the_writer_connection() {
    let log = SqliteAudit::open_in_memory().unwrap();
    assert!(log.reader.is_none());
    log.append(record(0)).unwrap();
    assert_eq!(log.len().unwrap(), 1);
    assert!(log.verify_chain().unwrap().ok);
}

/// A verify walks the log as it was when it began, page by page: entries appended after its
/// snapshot are not walked, whatever page the walk is on when they land.
#[test]
fn a_paged_verify_stops_at_its_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let log = SqliteAudit::open(dir.path().join("audit.db")).unwrap();
    // More than two pages.
    let n = 2500;
    std::thread::scope(|s| {
        for t in 0..4 {
            let log = &log;
            s.spawn(move || {
                for i in (t..n).step_by(4) {
                    log.append(record(i)).unwrap();
                }
            });
        }
    });
    let (upper, _) = log.verify_snapshot().unwrap();
    assert_eq!(upper, n);
    let mut walk = log.entries_through(upper);
    let first = walk.next().unwrap().unwrap();
    assert_eq!(first.seq, 1);
    // Appends land while the walk is in its first page.
    for i in 0..50 {
        log.append(record(n + i)).unwrap();
    }
    let seqs: Vec<u64> = std::iter::once(Ok(first))
        .chain(walk)
        .map(|e| e.unwrap().seq)
        .collect();
    assert_eq!(seqs, (1..=2500).collect::<Vec<u64>>());
    let report = log.verify_chain().unwrap();
    assert!(report.ok);
    assert_eq!(report.entries, 2550);
}

/// A row that does not decode is reported at its seq by the paged walk too, and the walk
/// goes on past it.
#[test]
fn a_paged_verify_reports_a_corrupt_row_at_its_seq() {
    let dir = tempfile::tempdir().unwrap();
    let log = SqliteAudit::open(dir.path().join("audit.db")).unwrap();
    for i in 0..1500 {
        log.append(record(i)).unwrap();
    }
    log.with_connection(|c| {
        c.execute("UPDATE audit SET decision = 'deny' WHERE seq = 1200", [])?;
        Ok(())
    })
    .unwrap();
    let report = log.verify_chain().unwrap();
    assert!(!report.ok);
    assert_eq!(report.first_bad_seq, Some(1200));
}
