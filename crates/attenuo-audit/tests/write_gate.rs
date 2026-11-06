//! The in-process write gate between a lease store and an audit log on one SQLite file: many
//! threads charging, labelling and appending through both connections (with the audit writer
//! thread and the WAL checkpointer running) finish without a deadlock and without SQLite's
//! busy handler, the counters and the chain come out exact, and a budget is never overspent.
//! The same workload on two files, and on the in-memory stores, behaves as before.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use attenuo_audit::{
    AuditSink, ChargeOutcome, Durability, LeaseStore, MemoryAudit, MemoryLeaseStore, RunLabel,
    SqliteAudit, SqliteLeaseStore, DEFAULT_WAL_CHECKPOINT_INTERVAL,
};
use attenuo_core::{Charge, Decision, LeaseId, LimitKind};
use common::{chain, record_for, t0};

const THREADS: usize = 8;
const CALLS: usize = 60;

/// Busy-handler invocations on the connections a test installed [`counting`] on.
static BUSY: AtomicU64 = AtomicU64::new(0);

fn counting(_: i32) -> bool {
    BUSY.fetch_add(1, Ordering::Relaxed);
    // A busy handler's backoff (it must not spin), part of the workload: not a wait.
    std::thread::sleep(Duration::from_millis(1));
    true
}

fn charges(sum: bool) -> Vec<Charge> {
    let mut v = Vec::new();
    for (hop, lease) in ["l1", "l2"].iter().enumerate() {
        v.push(Charge {
            hop,
            cap: 0,
            lease: LeaseId::new(*lease),
            kind: if sum {
                LimitKind::Sum
            } else {
                LimitKind::Calls
            },
            arg: sum.then(|| "n".to_string()),
            value: None,
            amount: 1,
            max: u64::MAX >> 2,
            usage: false,
        });
    }
    v
}

/// Run `f` on another thread and fail the test if it does not finish in time.
fn within<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(out) => {
            handle.join().unwrap();
            out
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // The closure panicked: surface its panic.
            handle.join().unwrap();
            unreachable!("{what}: the worker ended without an answer")
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("{what}: deadlocked (no answer in 120 s)"),
    }
}

/// The pipeline's writes for a limited call, from [`THREADS`] threads: a charge (a deferred
/// `sum` charge on odd threads, a plain `calls` charge on even ones), the decision append
/// (synced after a deferred charge), and a run label on every third call; plus a lease
/// renewal now and then and the lease check in between.
fn hammer(audit: Arc<dyn AuditSink>, leases: Arc<dyn LeaseStore>) {
    let at = t0() + time::Duration::hours(1);
    leases.register(&LeaseId::new("l1"), None, at).unwrap();
    leases
        .register(&LeaseId::new("l2"), Some(&LeaseId::new("l1")), at)
        .unwrap();
    let chain = Arc::new(chain("user:gate", ("l1", "l2")));
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let (audit, leases, chain, barrier) = (
                audit.clone(),
                leases.clone(),
                chain.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                let sum = t % 2 == 1;
                let c = charges(sum);
                barrier.wait();
                for i in 0..CALLS {
                    let id = format!("d{t}-{i}");
                    let (l1, l2) = (LeaseId::new("l1"), LeaseId::new("l2"));
                    assert!(leases.check_all(&[&l1, &l2], t0()).unwrap().active);
                    let (outcome, owed) = leases.charge_sync_deferred(&id, &c, t0()).unwrap();
                    assert!(matches!(outcome, ChargeOutcome::Charged { .. }));
                    let record = record_for(&chain, t * CALLS + i, Decision::Allow);
                    let entry = if owed {
                        audit.append_synced(record).unwrap()
                    } else {
                        audit.append(record).unwrap()
                    };
                    if i % 3 == 0 {
                        let label = RunLabel {
                            source: format!("gate/t{t}"),
                            decision_id: id,
                            seq: entry.seq,
                            at: t0(),
                        };
                        leases.add_label(&LeaseId::new("l1"), &label).unwrap();
                    }
                    if i % 20 == 0 {
                        leases.renew(&LeaseId::new("l2"), at, t0()).unwrap();
                    }
                }
            })
        })
        .collect();
    handles.into_iter().for_each(|h| h.join().unwrap());

    // Every charge counted exactly once, on both hops.
    let per_kind = (THREADS / 2 * CALLS) as u64;
    assert_eq!(leases.budget_used(&charges(false)).unwrap(), [per_kind; 2]);
    assert_eq!(leases.budget_used(&charges(true)).unwrap(), [per_kind; 2]);
    // One label per source (the first one), every thread's source present.
    assert_eq!(leases.labels(&LeaseId::new("l1")).unwrap().len(), THREADS);
    // Every append chained, in one unbroken chain.
    let report = audit.verify_chain().unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.entries, (THREADS * CALLS) as u64);
}

fn open_pair(audit_path: &Path, lease_path: &Path) -> (SqliteAudit, SqliteLeaseStore) {
    let audit = SqliteAudit::open_with(audit_path, Durability::Normal)
        .unwrap()
        .with_wal_checkpoints(DEFAULT_WAL_CHECKPOINT_INTERVAL)
        .unwrap();
    let leases = SqliteLeaseStore::open_with(lease_path, Durability::Normal).unwrap();
    (audit, leases)
}

/// The server's layout: one file, two connections, the writer thread and the checkpointer.
#[test]
fn shared_file_writes_from_both_stores_neither_deadlock_nor_lose_anything() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.db");
    let (audit, leases) = open_pair(&path, &path);
    let leases = leases.without_wal_autocheckpoint().unwrap();
    within("shared file", move || {
        hammer(Arc::new(audit), Arc::new(leases))
    });
}

/// With the two connections on one file queuing on the gate, SQLite's busy handler never runs
/// in this process. (No background WAL checkpointer here: its idle-time `TRUNCATE` takes the
/// write lock outside the gate, which is allowed to make a writer wait briefly.)
#[test]
fn shared_file_writers_never_reach_the_busy_handler() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.db");
    let audit = SqliteAudit::open_with(&path, Durability::Normal).unwrap();
    let leases = SqliteLeaseStore::open_with(&path, Durability::Normal).unwrap();
    audit
        .with_connection(|c| Ok(c.busy_handler(Some(counting))?))
        .unwrap();
    leases
        .with_connection(|c| Ok(c.busy_handler(Some(counting))?))
        .unwrap();
    BUSY.store(0, Ordering::Relaxed);
    within("busy handler", move || {
        hammer(Arc::new(audit), Arc::new(leases))
    });
    assert_eq!(BUSY.load(Ordering::Relaxed), 0, "busy handler invocations");
}

/// A lease store and an audit log in different files share no gate; the same workload runs.
#[test]
fn separate_files_are_unaffected() {
    let dir = tempfile::tempdir().unwrap();
    let (audit, leases) = open_pair(&dir.path().join("audit.db"), &dir.path().join("leases.db"));
    within("separate files", move || {
        hammer(Arc::new(audit), Arc::new(leases))
    });
}

/// The in-memory stores (no file, no gate) run the same workload.
#[test]
fn memory_stores_are_unaffected() {
    within("memory stores", || {
        hammer(
            Arc::new(MemoryAudit::new()),
            Arc::new(MemoryLeaseStore::new()),
        )
    });
    within("in-memory sqlite", || {
        hammer(
            Arc::new(SqliteAudit::open_in_memory().unwrap()),
            Arc::new(SqliteLeaseStore::open_in_memory().unwrap()),
        )
    });
}

/// Siblings race for a parent budget of `BUDGET` calls through the shared file's lease store,
/// each appending its decision right after its charge: exactly `BUDGET` charges win, and the
/// log holds one entry per call.
#[test]
fn concurrent_siblings_cannot_overspend_parent_with_appends_on_the_same_file() {
    const BUDGET: u64 = 5;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.db");
    let (audit, leases) = open_pair(&path, &path);
    let (audit, leases) = (Arc::new(audit), Arc::new(leases));
    let chain = Arc::new(chain("user:gate", ("root", "child")));
    let wins = within("siblings", {
        let (audit, leases) = (audit.clone(), leases.clone());
        move || {
            let barrier = Arc::new(Barrier::new(THREADS * 2));
            let handles: Vec<_> = (0..THREADS * 2)
                .map(|i| {
                    let (audit, leases, chain, barrier) = (
                        audit.clone(),
                        leases.clone(),
                        chain.clone(),
                        barrier.clone(),
                    );
                    std::thread::spawn(move || {
                        let call = [
                            Charge {
                                hop: 0,
                                cap: 0,
                                lease: LeaseId::new("root"),
                                kind: LimitKind::Calls,
                                arg: None,
                                value: None,
                                amount: 1,
                                max: BUDGET,
                                usage: false,
                            },
                            Charge {
                                hop: 1,
                                cap: 0,
                                lease: LeaseId::new(format!("child{i}")),
                                kind: LimitKind::Sum,
                                arg: Some("n".into()),
                                value: None,
                                amount: 1,
                                max: 1,
                                usage: false,
                            },
                        ];
                        barrier.wait();
                        let (outcome, owed) = leases
                            .charge_sync_deferred(&format!("d{i}"), &call, t0())
                            .unwrap();
                        let charged = matches!(outcome, ChargeOutcome::Charged { .. });
                        let decision = if charged {
                            Decision::Allow
                        } else {
                            Decision::Deny
                        };
                        let record = record_for(&chain, i, decision);
                        if owed {
                            audit.append_synced(record).unwrap();
                        } else {
                            audit.append(record).unwrap();
                        }
                        charged
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|&c| c)
                .count()
        }
    });
    assert_eq!(wins as u64, BUDGET);
    let root = [Charge {
        hop: 0,
        cap: 0,
        lease: LeaseId::new("root"),
        kind: LimitKind::Calls,
        arg: None,
        value: None,
        amount: 1,
        max: BUDGET,
        usage: false,
    }];
    assert_eq!(leases.budget_used(&root).unwrap(), [BUDGET]);
    let report = audit.verify_chain().unwrap();
    assert!(
        report.ok && report.entries == (THREADS * 2) as u64,
        "{report:?}"
    );
}
