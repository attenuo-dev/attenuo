//! Run-limit counters in the lease store (ADR-0010): all-or-nothing charges across hops,
//! concurrent charges against a budget of one, refunds at most once, and counters that stay
//! readable after a revocation; and run-usage counters (run-limits design section 3.5), which
//! never refuse, are refunded with their decision and end with their run. Every behaviour test
//! runs against both stores.

mod common;

use std::sync::{Arc, Barrier};

use attenuo_audit::{AuditError, ChargeOutcome, LeaseStore, MemoryLeaseStore, SqliteLeaseStore};
use attenuo_core::limits::{usage_charges, MAX_LIMIT};
use attenuo_core::{Charge, LeaseId, LimitKind, ToolCall};
use common::t0;
use serde_json::json;
use time::Duration;

fn stores() -> Vec<(&'static str, Box<dyn LeaseStore>)> {
    vec![
        ("memory", Box::new(MemoryLeaseStore::new())),
        (
            "sqlite",
            Box::new(SqliteLeaseStore::open_in_memory().unwrap()),
        ),
    ]
}

fn charge(hop: usize, lease: &str, kind: LimitKind, amount: u64, max: u64) -> Charge {
    Charge {
        hop,
        cap: 0,
        lease: LeaseId::new(lease),
        kind,
        arg: (kind != LimitKind::Calls).then(|| "amount".to_string()),
        value: None,
        amount,
        max,
        usage: false,
    }
}

fn per(lease: &str, value: &str, max: u64) -> Charge {
    Charge {
        hop: 0,
        cap: 1,
        lease: LeaseId::new(lease),
        kind: LimitKind::CallsPer,
        arg: Some("recipient".into()),
        value: Some(format!("\"{value}\"").into_bytes()),
        amount: 1,
        max,
        usage: false,
    }
}

fn charged(outcome: ChargeOutcome) -> Vec<u64> {
    match outcome {
        ChargeOutcome::Charged { used_after } => used_after,
        other => panic!("expected a charge, got {other:?}"),
    }
}

#[test]
fn call_is_charged_to_every_ancestor_hop_all_or_nothing() {
    for (name, store) in stores() {
        // Root: 2 calls; sub-agent: 1 call, sum 40.
        let call = vec![
            charge(0, "root", LimitKind::Calls, 1, 2),
            charge(1, "helper", LimitKind::Calls, 1, 1),
            charge(1, "helper", LimitKind::Sum, 40, 40),
        ];
        assert_eq!(store.budget_used(&call).unwrap(), vec![0, 0, 0], "{name}");
        assert_eq!(
            charged(store.charge("d1", &call, t0()).unwrap()),
            vec![1, 1, 40],
            "{name}"
        );
        // The second identical call would take the sub-agent past both its limits: nothing
        // is charged, not even the root's counter, which still has room.
        assert_eq!(
            store.charge("d2", &call, t0()).unwrap(),
            ChargeOutcome::Exhausted { index: 1, used: 1 },
            "{name}"
        );
        assert_eq!(store.budget_used(&call).unwrap(), vec![1, 1, 40], "{name}");
        // A sibling under the same root (another lease) spends the root's second call ...
        let sibling = vec![
            charge(0, "root", LimitKind::Calls, 1, 2),
            charge(1, "sibling", LimitKind::Calls, 1, 5),
        ];
        assert_eq!(
            charged(store.charge("d3", &sibling, t0()).unwrap()),
            vec![2, 1]
        );
        // ... and then the root's counter refuses the sibling's next one.
        assert_eq!(
            store.charge("d4", &sibling, t0()).unwrap(),
            ChargeOutcome::Exhausted { index: 0, used: 2 },
            "{name}"
        );
    }
}

#[test]
fn calls_per_counts_each_value_separately_and_a_call_cannot_double_count() {
    for (name, store) in stores() {
        assert_eq!(
            charged(store.charge("d1", &[per("root", "emma", 1)], t0()).unwrap()),
            vec![1]
        );
        assert_eq!(
            charged(store.charge("d2", &[per("root", "bob", 1)], t0()).unwrap()),
            vec![1],
            "{name}: another payee has its own counter"
        );
        assert_eq!(
            store.charge("d3", &[per("root", "emma", 1)], t0()).unwrap(),
            ChargeOutcome::Exhausted { index: 0, used: 1 },
            "{name}"
        );
        // Two charges of one counter in one call add up.
        let twice = [per("root", "carol", 2), per("root", "carol", 2)];
        assert_eq!(
            charged(store.charge("d4", &twice, t0()).unwrap()),
            vec![1, 2]
        );
        let thrice = [
            per("root", "dave", 2),
            per("root", "dave", 2),
            per("root", "dave", 2),
        ];
        assert_eq!(
            store.charge("d5", &thrice, t0()).unwrap(),
            ChargeOutcome::Exhausted { index: 2, used: 2 },
            "{name}"
        );
        assert_eq!(
            store.budget_used(&[per("root", "dave", 2)]).unwrap(),
            vec![0]
        );
    }
}

#[test]
fn refund_restores_what_one_decision_charged_once() {
    for (name, store) in stores() {
        let call = vec![
            charge(0, "root", LimitKind::Sum, 30, 100),
            charge(0, "root", LimitKind::Calls, 1, 5),
        ];
        charged(store.charge("d1", &call, t0()).unwrap());
        charged(store.charge("d2", &call, t0()).unwrap());
        assert_eq!(store.budget_used(&call).unwrap(), vec![60, 2], "{name}");
        assert_eq!(store.refund("d1", t0()).unwrap(), 2, "{name}");
        assert_eq!(store.budget_used(&call).unwrap(), vec![30, 1], "{name}");
        assert!(
            matches!(store.refund("d1", t0()), Err(AuditError::ChargeRefunded(_))),
            "{name}"
        );
        assert!(
            matches!(
                store.refund("nope", t0()),
                Err(AuditError::UnknownCharge(_))
            ),
            "{name}"
        );
        // A decision is charged once.
        assert!(store.charge("d2", &call, t0()).is_err(), "{name}");
        // An empty charge writes nothing (and leaves nothing to refund).
        assert_eq!(
            charged(store.charge("d9", &[], t0()).unwrap()),
            Vec::<u64>::new()
        );
        assert!(matches!(
            store.refund("d9", t0()),
            Err(AuditError::UnknownCharge(_))
        ));
    }
}

#[test]
fn revoking_a_lease_does_not_break_reading_counters() {
    for (name, store) in stores() {
        let exp = t0() + Duration::hours(1);
        store.register(&LeaseId::new("root"), None, exp).unwrap();
        store
            .register(&LeaseId::new("helper"), Some(&LeaseId::new("root")), exp)
            .unwrap();
        let call = vec![
            charge(0, "root", LimitKind::Calls, 1, 3),
            charge(1, "helper", LimitKind::Calls, 1, 3),
        ];
        charged(store.charge("d1", &call, t0()).unwrap());
        store.revoke(&LeaseId::new("root"), "test", t0()).unwrap();
        assert_eq!(store.budget_used(&call).unwrap(), vec![1, 1], "{name}");
        // An operator refund still works on a revoked run.
        assert_eq!(store.refund("d1", t0()).unwrap(), 2, "{name}");
    }
}

/// Two calls race for a budget of one, through two connections to one SQLite file (as two
/// server processes would): the `IMMEDIATE` transaction lets exactly one through.
#[test]
fn concurrent_siblings_cannot_overspend_parent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    for round in 0..10 {
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let (barrier, path) = (barrier.clone(), path.clone());
                std::thread::spawn(move || {
                    let store = SqliteLeaseStore::open(&path).unwrap();
                    let call = vec![
                        charge(0, &format!("root{round}"), LimitKind::Calls, 1, 1),
                        charge(1, &format!("child{round}-{i}"), LimitKind::Calls, 1, 1),
                    ];
                    barrier.wait();
                    store.charge(&format!("d{round}-{i}"), &call, t0()).unwrap()
                })
            })
            .collect();
        let outcomes: Vec<ChargeOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let wins = outcomes
            .iter()
            .filter(|o| matches!(o, ChargeOutcome::Charged { .. }))
            .count();
        assert_eq!(wins, 1, "round {round}: {outcomes:?}");
    }
    // The same through one store shared by threads (the server's case).
    for (name, store) in stores() {
        let store: Arc<dyn LeaseStore> = Arc::from(store);
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let (store, barrier) = (store.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .charge(
                            &format!("d{i}"),
                            &[charge(0, "root", LimitKind::Calls, 1, 1)],
                            t0(),
                        )
                        .unwrap()
                })
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|o| matches!(o, ChargeOutcome::Charged { .. }))
            .count();
        assert_eq!(wins, 1, "{name}");
    }
}

/// Counters, charges and the value key survive reopening the file; `calls_per` values are
/// stored as hashes, not in clear.
#[test]
fn sqlite_counters_survive_reopen_and_hold_no_values_in_clear() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    {
        let store = SqliteLeaseStore::open(&path).unwrap();
        charged(
            store
                .charge(
                    "d1",
                    &[
                        per("root", "FR00EMMA", 1),
                        charge(0, "root", LimitKind::Sum, 7, 9),
                    ],
                    t0(),
                )
                .unwrap(),
        );
    }
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(
        store
            .charge("d2", &[per("root", "FR00EMMA", 1)], t0())
            .unwrap(),
        ChargeOutcome::Exhausted { index: 0, used: 1 }
    );
    let dump: Vec<String> = store
        .with_connection(|c| {
            let mut stmt = c.prepare(
                "SELECT lease || kind || arg || value FROM budget_counters \
                 UNION ALL SELECT lease || kind || arg || value FROM budget_charges",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert!(!dump.is_empty());
    assert!(dump.iter().all(|r| !r.contains("EMMA")), "{dump:?}");
}

/// Run usage shares the counters' transaction and refund but not their rules: it never
/// refuses (it saturates), it is keyed apart from any token limit on the same lease, a refund
/// returns it without counting it, and revoking the run's root lease deletes it while limit
/// counters stay readable.
#[test]
fn run_usage_saturates_is_refunded_and_ends_with_the_run() {
    for (name, store) in stores() {
        let exp = t0() + Duration::hours(1);
        let root = LeaseId::new("root");
        store.register(&root, None, exp).unwrap();
        let call = ToolCall::new(
            "bank",
            "send_money",
            json!({"recipient": "FR00EMMA", "amount": 40}),
        );
        let usage = usage_charges(&root, &call, Some("amount"), Some("recipient"));
        let limit = charge(0, "root", LimitKind::Calls, 1, 5);
        let mut both = vec![limit.clone()];
        both.extend(usage.clone());
        assert_eq!(
            charged(store.charge("d1", &both, t0()).unwrap()),
            vec![1, 1, 40, 1],
            "{name}: the usage `calls` counter is not the limit's, though both are on `root`"
        );
        assert_eq!(
            charged(store.charge("d2", &usage, t0()).unwrap()),
            vec![2, 80, 2],
            "{name}"
        );
        // A refund returns the usage too, but counts only token-limit counters.
        assert_eq!(store.refund("d2", t0()).unwrap(), 0, "{name}");
        assert_eq!(store.refund("d1", t0()).unwrap(), 1, "{name}");
        assert_eq!(
            store.budget_used(&both).unwrap(),
            vec![0, 0, 0, 0],
            "{name}"
        );

        // Saturates instead of refusing.
        let mut huge = usage.clone();
        huge[1].amount = MAX_LIMIT;
        charged(store.charge("d3", &huge, t0()).unwrap());
        assert_eq!(
            charged(store.charge("d4", &huge, t0()).unwrap())[1],
            MAX_LIMIT,
            "{name}"
        );

        charged(store.charge("d5", &both, t0()).unwrap());
        store.revoke(&root, "test", t0()).unwrap();
        assert_eq!(
            store.budget_used(&both).unwrap(),
            vec![1, 0, 0, 0],
            "{name}: usage ends with the run, the limit counter stays"
        );
    }
}

fn distinct(lease: &str, value: &str, max: u64) -> Charge {
    Charge {
        hop: 0,
        cap: 2,
        lease: LeaseId::new(lease),
        kind: LimitKind::Distinct,
        arg: Some("url#host".into()),
        value: Some(format!("\"{value}\"").into_bytes()),
        amount: 1,
        max,
        usage: false,
    }
}

/// The count of a `distinct` limit, as the pipeline reads it: a probe with no value.
fn distinct_count(lease: &str, max: u64) -> Charge {
    Charge {
        value: None,
        ..distinct(lease, "", max)
    }
}

/// `distinct` (run-limits phase 2): a new value adds one to the limit's count, a value already
/// seen costs nothing, a value past `max` is refused with the count as `used`, values new in
/// one call add up, and a refund takes the decision's values back so they count as new again.
#[test]
fn distinct_counts_new_values_once_and_refunds_them() {
    for (name, store) in stores() {
        let count = |s: &dyn LeaseStore| s.budget_used(&[distinct_count("root", 2)]).unwrap()[0];
        assert_eq!(
            charged(
                store
                    .charge("d1", &[distinct("root", "a.example", 2)], t0())
                    .unwrap()
            ),
            vec![1],
            "{name}"
        );
        // The same host again: allowed, nothing added.
        assert_eq!(
            charged(
                store
                    .charge("d2", &[distinct("root", "a.example", 2)], t0())
                    .unwrap()
            ),
            vec![1],
            "{name}"
        );
        assert_eq!(
            store
                .budget_used(&[distinct("root", "a.example", 2)])
                .unwrap(),
            vec![1],
            "{name}: the value's own row says it was seen"
        );
        // Two new hosts in one call would take the count to 3: nothing is charged.
        assert_eq!(
            store
                .charge(
                    "d3",
                    &[
                        distinct("root", "b.example", 2),
                        distinct("root", "c.example", 2)
                    ],
                    t0()
                )
                .unwrap(),
            ChargeOutcome::Exhausted { index: 1, used: 2 },
            "{name}"
        );
        assert_eq!(count(store.as_ref()), 1, "{name}");
        assert_eq!(
            charged(
                store
                    .charge("d4", &[distinct("root", "b.example", 2)], t0())
                    .unwrap()
            ),
            vec![2],
            "{name}"
        );
        // A third host is refused; a seen one still passes.
        assert_eq!(
            store
                .charge("d5", &[distinct("root", "c.example", 2)], t0())
                .unwrap(),
            ChargeOutcome::Exhausted { index: 0, used: 2 },
            "{name}"
        );
        assert_eq!(
            charged(
                store
                    .charge("d6", &[distinct("root", "a.example", 2)], t0())
                    .unwrap()
            ),
            vec![2],
            "{name}"
        );
        // A refund of d4 returns b.example: the count drops and c.example fits. The value
        // row is not a token-limit counter of its own, so `refunded` counts 1.
        assert_eq!(store.refund("d4", t0()).unwrap(), 1, "{name}");
        assert_eq!(count(store.as_ref()), 1, "{name}");
        assert_eq!(
            charged(
                store
                    .charge("d7", &[distinct("root", "c.example", 2)], t0())
                    .unwrap()
            ),
            vec![2],
            "{name}"
        );
        // A decision whose values were all seen charged nothing to refund.
        assert!(
            matches!(store.refund("d6", t0()), Err(AuditError::UnknownCharge(_))),
            "{name}"
        );
    }
}

/// Concurrent calls with new values never take a `distinct` count past `max`.
#[test]
fn concurrent_new_values_cannot_overspend_distinct() {
    for (name, store) in stores() {
        let store: Arc<dyn LeaseStore> = Arc::from(store);
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let (store, barrier) = (store.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let host = format!("h{i}.example");
                    store
                        .charge(&format!("d{i}"), &[distinct("root", &host, 3)], t0())
                        .unwrap()
                })
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|o| matches!(o, ChargeOutcome::Charged { .. }))
            .count();
        assert_eq!(wins, 3, "{name}");
        assert_eq!(
            store.budget_used(&[distinct_count("root", 3)]).unwrap(),
            vec![3],
            "{name}"
        );
    }
}

/// What the console reads: the limits a hop was issued with, and its counters grouped, with
/// no value hashes.
#[test]
fn hop_limits_and_counter_summaries_for_the_console() {
    use attenuo_audit::{CounterSummary, HopLimit};
    use attenuo_core::Limits;
    for (name, store) in stores() {
        let lease = LeaseId::new("root");
        assert_eq!(store.hop_limits(&lease).unwrap(), None, "{name}");
        assert!(store.budget_summary(&lease).unwrap().is_empty(), "{name}");
        let hop = vec![HopLimit {
            cap: 0,
            server: "banking".into(),
            tool: "send_money".into(),
            limits: Limits::default()
                .with_calls(3)
                .with_distinct("recipient", 2),
        }];
        store.record_hop_limits(&lease, &hop).unwrap();
        assert_eq!(store.hop_limits(&lease).unwrap(), Some(hop), "{name}");
        charged(
            store
                .charge(
                    "d1",
                    &[
                        charge(0, "root", LimitKind::Calls, 1, 3),
                        per("root", "A", 5),
                        distinct("root", "a.example", 2),
                    ],
                    t0(),
                )
                .unwrap(),
        );
        charged(
            store
                .charge("d2", &[per("root", "A", 5), per("root", "B", 5)], t0())
                .unwrap(),
        );
        let row = |cap, kind: &str, arg: &str, used, values| CounterSummary {
            cap,
            kind: kind.into(),
            arg: arg.into(),
            used,
            values,
        };
        assert_eq!(
            store.budget_summary(&lease).unwrap(),
            vec![
                row(0, "calls", "", 1, 0),
                row(1, "calls_per", "recipient", 2, 2),
                row(2, "distinct", "url#host", 1, 0),
            ],
            "{name}"
        );
        assert!(store
            .budget_summary(&LeaseId::new("other"))
            .unwrap()
            .is_empty());
    }
}
