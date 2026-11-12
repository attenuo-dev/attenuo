//! Per-user windows in the lease store (run limits phase 3, design note section 3): charged in
//! the same transaction as limits and run usage, shared by every run of one user (issuer and
//! subject), never refusing, refunded once with their decision, untouched by revocation, kept
//! in the SQLite file only under a keyed digest of the user, and pruned by the window's end.
//! Every behaviour test runs against both stores and compares them.

mod common;

use attenuo_audit::{
    window_prunable, AuditError, ChargeOutcome, LeaseStore, MemoryLeaseStore, SqliteLeaseStore,
};
use attenuo_core::limits::{usage_charges, MAX_LIMIT};
use attenuo_core::windows::window_charges;
use attenuo_core::{Charge, LeaseId, LimitKind, ToolCall, WindowCharge, WindowKind};
use common::{t0, user};
use serde_json::json;
use time::{Duration, OffsetDateTime};

fn stores() -> Vec<(&'static str, Box<dyn LeaseStore>)> {
    vec![
        ("memory", Box::new(MemoryLeaseStore::new())),
        (
            "sqlite",
            Box::new(SqliteLeaseStore::open_in_memory().unwrap()),
        ),
    ]
}

fn pay(amount: u64) -> ToolCall {
    ToolCall::new("bank", "send_money", json!({"amount": amount}))
}

/// The day and hour windows of `subject` for one payment, at `at`.
fn windows(subject: &str, amount: u64, at: OffsetDateTime) -> Vec<WindowCharge> {
    window_charges(
        &user(subject),
        &pay(amount),
        Some("amount"),
        &WindowKind::ALL,
        at,
    )
}

fn usage(run: &str, amount: u64) -> Vec<Charge> {
    usage_charges(&LeaseId::new(run), &pay(amount), Some("amount"), None)
}

fn charge(
    store: &dyn LeaseStore,
    decision: &str,
    charges: &[Charge],
    windows: &[WindowCharge],
) -> ChargeOutcome {
    store
        .charge_windowed(decision, charges, windows, t0(), false)
        .unwrap()
        .0
}

#[test]
fn every_run_of_one_user_shares_the_window_and_other_users_do_not() {
    let mut seen = Vec::new();
    for (name, store) in stores() {
        let store = store.as_ref();
        // Two runs of alice, one of bob, and alice under another issuer.
        charge(
            store,
            "d1",
            &usage("run-a", 300),
            &windows("alice", 300, t0()),
        );
        charge(
            store,
            "d2",
            &usage("run-b", 200),
            &windows("alice", 200, t0()),
        );
        charge(store, "d3", &usage("run-c", 50), &windows("bob", 50, t0()));
        let mut other = windows("alice", 7, t0());
        for w in &mut other {
            w.issuer = "https://other-idp.example".into();
        }
        charge(store, "d4", &usage("run-d", 7), &other);
        let alice = store.window_used(&windows("alice", 0, t0())).unwrap();
        assert_eq!(
            alice,
            vec![2, 500, 2, 500],
            "{name}: hour calls/amount, day calls/amount"
        );
        assert_eq!(
            store.window_used(&windows("bob", 0, t0())).unwrap(),
            vec![1, 50, 1, 50],
            "{name}"
        );
        assert_eq!(
            store.window_used(&other).unwrap(),
            vec![1, 7, 1, 7],
            "{name}"
        );
        // The next hour is a new hour window, the same day window.
        let later = t0() + Duration::hours(1);
        assert_eq!(
            store.window_used(&windows("alice", 0, later)).unwrap(),
            vec![0, 0, 2, 500],
            "{name}"
        );
        // And the next UTC day a new day window.
        let tomorrow = t0() + Duration::days(1);
        assert_eq!(
            store.window_used(&windows("alice", 0, tomorrow)).unwrap(),
            vec![0, 0, 0, 0],
            "{name}"
        );
        seen.push(alice);
    }
    assert_eq!(seen[0], seen[1], "the stores agree");
}

#[test]
fn an_exhausted_limit_charges_no_window_and_a_window_never_refuses() {
    for (name, store) in stores() {
        let store = store.as_ref();
        let limit = Charge {
            hop: 0,
            cap: 0,
            lease: LeaseId::new("root"),
            kind: LimitKind::Calls,
            arg: None,
            value: None,
            amount: 1,
            max: 1,
            usage: false,
        };
        let mut charges = vec![limit];
        charges.extend(usage("root", 10));
        charge(store, "d1", &charges, &windows("alice", 10, t0()));
        assert_eq!(
            charge(store, "d2", &charges, &windows("alice", 10, t0())),
            ChargeOutcome::Exhausted { index: 0, used: 1 },
            "{name}"
        );
        assert_eq!(
            store.window_used(&windows("alice", 0, t0())).unwrap(),
            vec![1, 10, 1, 10],
            "{name}: the refused call charged no window"
        );
        // Saturates at MAX_LIMIT instead of refusing.
        charge(store, "d3", &[], &windows("alice", MAX_LIMIT, t0()));
        assert_eq!(
            store.window_used(&windows("alice", 0, t0())).unwrap(),
            vec![2, MAX_LIMIT, 2, MAX_LIMIT],
            "{name}"
        );
        // A decision is charged once, whatever it charged.
        let again = store.charge_windowed("d3", &[], &windows("alice", 1, t0()), t0(), false);
        assert!(
            matches!(again, Err(AuditError::Storage(_))),
            "{name}: {again:?}"
        );
        let again = store.charge_windowed("d1", &[], &windows("alice", 1, t0()), t0(), false);
        assert!(
            matches!(again, Err(AuditError::Storage(_))),
            "{name}: {again:?}"
        );
    }
}

#[test]
fn a_refund_returns_window_charges_once_to_their_window() {
    for (name, store) in stores() {
        let store = store.as_ref();
        charge(
            store,
            "d1",
            &usage("run-a", 300),
            &windows("alice", 300, t0()),
        );
        charge(
            store,
            "d2",
            &usage("run-b", MAX_LIMIT),
            &windows("alice", MAX_LIMIT, t0()),
        );
        // Window charges only (the run's usage was ended by a revocation, say).
        charge(store, "d3", &[], &windows("alice", 5, t0()));
        assert_eq!(
            store.refund("d2", t0()).unwrap(),
            0,
            "{name}: windows are not counted"
        );
        assert_eq!(
            store.window_used(&windows("alice", 0, t0())).unwrap(),
            vec![2, 305, 2, 305],
            "{name}: recomputed from the charges left, not MAX - MAX"
        );
        assert!(matches!(
            store.refund("d2", t0()),
            Err(AuditError::ChargeRefunded(_))
        ));
        assert_eq!(store.refund("d3", t0()).unwrap(), 0, "{name}");
        assert!(matches!(
            store.refund("d3", t0()),
            Err(AuditError::ChargeRefunded(_))
        ));
        assert_eq!(
            store.window_used(&windows("alice", 0, t0())).unwrap(),
            vec![1, 300, 1, 300],
            "{name}"
        );
        assert!(matches!(
            store.refund("nothing", t0()),
            Err(AuditError::UnknownCharge(_))
        ));
    }
}

#[test]
fn revoking_a_run_does_not_reset_the_window() {
    for (name, store) in stores() {
        let store = store.as_ref();
        let root = LeaseId::new("run-a");
        store
            .register(&root, None, t0() + Duration::hours(1))
            .unwrap();
        charge(
            store,
            "d1",
            &usage("run-a", 900),
            &windows("alice", 900, t0()),
        );
        store.revoke(&root, "test", t0()).unwrap();
        assert_eq!(
            store.budget_used(&usage("run-a", 0)).unwrap(),
            vec![0, 0],
            "{name}: the run's usage ends with it"
        );
        assert_eq!(
            store.window_used(&windows("alice", 0, t0())).unwrap(),
            vec![1, 900, 1, 900],
            "{name}: the user's window does not"
        );
        // The decision's window part can still be refunded.
        assert_eq!(store.refund("d1", t0()).unwrap(), 0, "{name}");
        assert_eq!(
            store.window_used(&windows("alice", 0, t0())).unwrap(),
            vec![0, 0, 0, 0],
            "{name}"
        );
    }
}

#[test]
fn windows_are_pruned_by_their_end_never_while_open() {
    let retention = Duration::days(35);
    for (name, store) in stores() {
        let store = store.as_ref();
        let old = t0() - Duration::days(40);
        store
            .charge_windowed("old", &[], &windows("alice", 1, old), old, false)
            .unwrap();
        charge(store, "new", &[], &windows("alice", 2, t0()));
        // With a zero retention, only ended windows go: the hour ended, the day did not.
        let p = store
            .prune_user_windows(t0() + Duration::minutes(61), Duration::ZERO, 1000)
            .unwrap();
        assert_eq!(
            p.pruned_windows, 6,
            "{name}: both old windows and the new hour"
        );
        assert_eq!(p.pruned_charges, 6, "{name}");
        assert!(p.wrapped, "{name}");
        assert_eq!(
            store.window_used(&windows("alice", 0, t0())).unwrap(),
            vec![0, 0, 1, 2],
            "{name}: the open day is kept"
        );
        // Under the real retention, the open day is kept for 35 days after it ends.
        let p = store
            .prune_user_windows(t0() + Duration::days(30), retention, 1000)
            .unwrap();
        assert_eq!(p.pruned_windows, 0, "{name}");
        let p = store
            .prune_user_windows(t0() + Duration::days(37), retention, 1)
            .unwrap();
        assert_eq!(
            (p.pruned_windows, p.wrapped),
            (1, false),
            "{name}: a bounded pass"
        );
        let p = store
            .prune_user_windows(t0() + Duration::days(37), retention, 1)
            .unwrap();
        assert_eq!(p.pruned_windows, 1, "{name}");
        assert!(matches!(
            store.refund("new", t0()),
            Err(AuditError::UnknownCharge(_))
        ));
    }
    assert!(!window_prunable(
        100,
        OffsetDateTime::from_unix_timestamp(150).unwrap(),
        Duration::seconds(50)
    ));
    assert!(window_prunable(
        100,
        OffsetDateTime::from_unix_timestamp(151).unwrap(),
        Duration::seconds(50)
    ));
}

#[test]
fn sqlite_windows_survive_reopen_and_hold_no_subject_in_clear() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    {
        let store = SqliteLeaseStore::open(&path).unwrap();
        charge(
            &store,
            "d1",
            &usage("run-a", 40),
            &windows("alice-SECRET", 40, t0()),
        );
    }
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(
        store
            .window_used(&windows("alice-SECRET", 0, t0()))
            .unwrap(),
        vec![1, 40, 1, 40]
    );
    let dump: Vec<String> = store
        .with_connection(|c| {
            let mut stmt = c.prepare(
                "SELECT user || window_kind || tool FROM user_windows \
                 UNION ALL SELECT user || window_kind || tool FROM user_window_charges",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .unwrap();
    assert_eq!(dump.len(), 8);
    assert!(
        dump.iter()
            .all(|r| !r.contains("SECRET") && !r.contains("idp")),
        "{dump:?}"
    );
}
