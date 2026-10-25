//! Run-state retention (`LeaseStore::prune_run_state`): run-limit counters, the charge log and
//! approvals of a run are deleted only once the run's leases are gone from the registry and
//! the state is older than the retention. Every test runs against both stores.

mod common;

use attenuo_audit::{
    Approval, ApprovalMethod, ApprovalState, Approver, AuditError, LeaseStore, MemoryLeaseStore,
    RunStatePrune, SqliteLeaseStore,
};
use attenuo_core::{Charge, LeaseId, LimitKind};
use common::{chain, t0};
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

/// The run-state retention under test (the server default).
const RETAIN: Duration = Duration::days(30);
/// The lease retention the registry is pruned with first.
const LEASE_RETAIN: Duration = Duration::weeks(1);

fn id(s: &str) -> LeaseId {
    LeaseId::new(s)
}

fn calls(lease: &str) -> Charge {
    Charge {
        hop: 0,
        cap: 0,
        lease: id(lease),
        kind: LimitKind::Calls,
        arg: None,
        value: None,
        amount: 1,
        max: 100,
        usage: false,
    }
}

fn sum(lease: &str, amount: u64) -> Charge {
    Charge {
        hop: 1,
        cap: 0,
        lease: id(lease),
        kind: LimitKind::Sum,
        arg: Some("amount".into()),
        value: None,
        amount,
        max: 1000,
        usage: false,
    }
}

fn approval(n: u32, chain_id: &str, lease: &str) -> Approval {
    Approval {
        id: format!("00000000-0000-4000-8000-{n:012}"),
        chain_id: id(chain_id),
        lease: id(lease),
        call_hash: format!("h{n}"),
        server: "github".into(),
        tool: "delete_repo".into(),
        arguments: json!({"repo": "alice/site"}),
        labels: Vec::new(),
        untrusted_args: Vec::new(),
        decision_id: format!("d-gated-{n}"),
        chain: chain("alice", (chain_id, lease)),
        created_at: t0(),
        expires_at: t0() + Duration::minutes(2),
        state: ApprovalState::Pending,
        approver: None,
        decided_at: None,
        consumed_by: None,
        jkt: None,
    }
}

fn operator() -> Approver {
    Approver {
        subject: "ops".into(),
        method: ApprovalMethod::AdminToken,
    }
}

/// Run passes of `batch` until one wraps; what they deleted in total.
fn prune_all(s: &dyn LeaseStore, now: OffsetDateTime, batch: usize) -> RunStatePrune {
    let mut total = RunStatePrune::default();
    for _ in 0..10_000 {
        let p = s.prune_run_state(now, RETAIN, batch).unwrap();
        assert!(p.examined <= batch as u64, "{p:?}");
        total.examined += p.examined;
        total.pruned_counters += p.pruned_counters;
        total.pruned_charges += p.pruned_charges;
        total.pruned_approvals += p.pruned_approvals;
        if p.wrapped {
            total.wrapped = true;
            return total;
        }
    }
    panic!("no pass wrapped");
}

/// (counters, charges, approvals) deleted by a full sweep.
fn sweep(s: &dyn LeaseStore, now: OffsetDateTime) -> (u64, u64, u64) {
    let p = prune_all(s, now, 1000);
    (p.pruned_counters, p.pruned_charges, p.pruned_approvals)
}

/// alice's run `r` -> `c` (expiring an hour after t0): two charged decisions, `d1` at t0 on
/// both hops and `d2` ten minutes later on `c`; three approvals made by `c`, granted then
/// consumed, declined, and granted but never used.
fn alice_run(s: &dyn LeaseStore) {
    let exp = t0() + Duration::hours(1);
    s.register(&id("r"), None, exp).unwrap();
    s.register(&id("c"), Some(&id("r")), exp).unwrap();
    s.charge("d1", &[calls("r"), calls("c")], t0()).unwrap();
    s.charge("d2", &[sum("c", 5)], t0() + Duration::minutes(10))
        .unwrap();
    let decided = t0() + Duration::seconds(5);
    for (n, grant) in [(1, true), (2, false), (3, true)] {
        let (a, _) = s.create_approval(&approval(n, "r", "c")).unwrap();
        s.decide_approval(&a.id, grant, &operator(), decided)
            .unwrap();
    }
    let used = s
        .take_approval(
            &id("r"),
            &id("c"),
            "h1",
            "d-retry",
            t0() + Duration::seconds(10),
        )
        .unwrap();
    assert!(used.is_some());
}

fn approval_ids(s: &dyn LeaseStore, ns: &[u32]) -> Vec<u32> {
    ns.iter()
        .copied()
        .filter(|n| {
            s.approval(&format!("00000000-0000-4000-8000-{n:012}"))
                .unwrap()
                .is_some()
        })
        .collect()
}

/// Nothing of a run whose leases are still in the registry is deleted, however old it is:
/// live, revoked or long expired, its counters, charge log and approvals stay, and its
/// charges can still be refunded.
#[test]
fn state_of_a_run_still_in_the_registry_is_kept_whatever_its_age() {
    for (name, s) in stores() {
        let s = s.as_ref();
        alice_run(s);
        // Live (as of t0), then revoked, then far past everything: never touched.
        assert_eq!(sweep(s, t0()), (0, 0, 0), "{name}");
        s.revoke(&id("r"), "done", t0() + Duration::minutes(20))
            .unwrap();
        assert_eq!(sweep(s, t0() + Duration::weeks(1000)), (0, 0, 0), "{name}");
        assert_eq!(approval_ids(s, &[1, 2, 3]), [1, 2, 3], "{name}");
        assert_eq!(
            s.budget_used(&[calls("r"), calls("c"), sum("c", 0)])
                .unwrap(),
            [1, 1, 5],
            "{name}"
        );
        assert_eq!(
            s.refund("d2", t0() + Duration::weeks(1000)).unwrap(),
            1,
            "{name}"
        );
    }
}

/// Once a run's leases are pruned, its state is kept for the retention past its newest event
/// and deleted after: a charge-log entry once its charge and refund are older, a counter once
/// no charge under its lease is left, an approval once its creation, decision and expiry are
/// older. A refund of a pruned charge is refused as unknown. Another user's live run, charged
/// at the same time, is untouched; a charge under a lease the registry never knew follows
/// the rule as a gone run's would.
#[test]
fn state_of_a_pruned_run_is_kept_within_the_retention_and_deleted_past_it() {
    for (name, s) in stores() {
        let s = s.as_ref();
        alice_run(s);
        let far = t0() + Duration::weeks(10_000);
        s.register(&id("br"), None, far).unwrap();
        s.register(&id("bc"), Some(&id("br")), far).unwrap();
        s.charge("dbob", &[calls("br")], t0()).unwrap();
        let (b, _) = s.create_approval(&approval(9, "br", "bc")).unwrap();
        s.decide_approval(&b.id, true, &operator(), t0()).unwrap();
        s.charge("dghost", &[calls("ghost")], t0()).unwrap();

        // The unknown lease's state goes once it is old enough; nothing else is touched.
        assert_eq!(
            sweep(s, t0() + RETAIN),
            (0, 0, 0),
            "{name}: at exactly the retention"
        );
        assert_eq!(
            sweep(s, t0() + RETAIN + Duration::seconds(1)),
            (1, 1, 0),
            "{name}: the ghost's charge, then its counter"
        );

        // alice's run ends (revoked; `d2` refunded two days later) and its leases are pruned.
        let revoked = t0() + Duration::minutes(20);
        s.revoke(&id("r"), "done", revoked).unwrap();
        s.refund("d2", t0() + Duration::days(2)).unwrap();
        let pruned = s
            .prune_leases(
                revoked + LEASE_RETAIN + Duration::seconds(1),
                LEASE_RETAIN,
                100,
            )
            .unwrap();
        assert_eq!(pruned.pruned, 2, "{name}");

        // At exactly the retention after `d1` (t0): kept.
        assert_eq!(sweep(s, t0() + RETAIN), (0, 0, 0), "{name}");
        assert_eq!(approval_ids(s, &[1, 2, 3]), [1, 2, 3], "{name}");

        // Past it for `d1`, not for `d2` (refunded on day 2): `d1` goes, and with it the
        // root's counter (nothing under `r` is left in the log); `c`'s two counters stay with
        // `d2`. The approvals' newest event is their expiry, two minutes after t0: kept.
        let now = t0() + RETAIN + Duration::seconds(1);
        assert_eq!(sweep(s, now), (1, 1, 0), "{name}");
        assert_eq!(approval_ids(s, &[1, 2, 3]), [1, 2, 3], "{name}");
        assert!(
            matches!(s.refund("d1", now), Err(AuditError::UnknownCharge(_))),
            "{name}: a pruned charge is unknown"
        );
        assert_eq!(s.budget_used(&[calls("r")]).unwrap(), [0], "{name}");
        assert_eq!(s.budget_used(&[calls("c")]).unwrap(), [1], "{name}");

        // Past the approvals' expiry: consumed, declined and granted-but-unused alike go,
        // since none of them can be used once the run's leases are gone.
        let now = t0() + RETAIN + Duration::minutes(2) + Duration::seconds(1);
        assert_eq!(sweep(s, now), (0, 0, 3), "{name}");
        assert!(approval_ids(s, &[1, 2, 3]).is_empty(), "{name}");

        // Past `d2`'s refund too: the rest goes, and refunding it again is unknown rather
        // than already refunded.
        let later = t0() + Duration::days(2) + RETAIN + Duration::seconds(1);
        assert_eq!(sweep(s, later), (2, 1, 0), "{name}");
        assert!(
            matches!(s.refund("d2", later), Err(AuditError::UnknownCharge(_))),
            "{name}"
        );
        assert_eq!(
            s.budget_used(&[calls("c"), sum("c", 0)]).unwrap(),
            [0, 0],
            "{name}"
        );

        // bob's live run keeps everything, and nothing is left to prune.
        assert_eq!(s.budget_used(&[calls("br")]).unwrap(), [1], "{name}");
        assert_eq!(approval_ids(s, &[9]), [9], "{name}");
        assert_eq!(
            s.approval(&b.id).unwrap().unwrap().state,
            ApprovalState::Granted
        );
        assert_eq!(sweep(s, later + Duration::weeks(1000)), (0, 0, 0), "{name}");
        assert_eq!(s.refund("dbob", later).unwrap(), 1, "{name}");
    }
}

/// A granted approval that has not been used yet, of a run whose leases are live, survives
/// every pass (even with a retention far shorter than its age) and can still be consumed.
#[test]
fn a_granted_unconsumed_approval_of_a_live_run_is_kept() {
    for (name, s) in stores() {
        let s = s.as_ref();
        let exp = t0() + Duration::hours(1);
        s.register(&id("r"), None, exp).unwrap();
        s.register(&id("c"), Some(&id("r")), exp).unwrap();
        let (a, _) = s.create_approval(&approval(1, "r", "c")).unwrap();
        s.decide_approval(&a.id, true, &operator(), t0() + Duration::seconds(5))
            .unwrap();
        for now in [t0() + Duration::seconds(30), t0() + Duration::weeks(1000)] {
            let p = s.prune_run_state(now, Duration::seconds(1), 100).unwrap();
            assert_eq!(p.pruned_approvals, 0, "{name}");
            assert!(p.wrapped, "{name}");
        }
        let taken = s
            .take_approval(&id("r"), &id("c"), "h1", "d1", t0() + Duration::seconds(40))
            .unwrap();
        assert_eq!(
            taken.map(|a| a.state),
            Some(ApprovalState::Consumed),
            "{name}"
        );
    }
}

/// A refund of a charge whose log entry was pruned is refused with the documented error,
/// `UnknownCharge` (the operator route answers 404 `not_found`), and changes nothing.
#[test]
fn a_refund_of_a_pruned_charge_is_refused_as_unknown() {
    for (name, s) in stores() {
        let s = s.as_ref();
        s.charge("d1", &[calls("gone"), sum("gone", 7)], t0())
            .unwrap();
        let p = s
            .prune_run_state(t0() + RETAIN + Duration::seconds(1), RETAIN, 100)
            .unwrap();
        assert_eq!((p.pruned_charges, p.pruned_counters), (1, 2), "{name}");
        for _ in 0..2 {
            assert!(
                matches!(
                    s.refund("d1", t0() + RETAIN + Duration::days(1)),
                    Err(AuditError::UnknownCharge(ref d)) if d == "d1"
                ),
                "{name}"
            );
        }
        assert_eq!(
            s.budget_used(&[calls("gone"), sum("gone", 0)]).unwrap(),
            [0, 0],
            "{name}"
        );
    }
}

/// Passes look at no more than their batch, resume where the previous one stopped, walk the
/// charge log, the counters and the approvals in turn, and report `wrapped` only after the
/// approvals; a full sweep reaches every row.
#[test]
fn run_state_passes_are_bounded_and_resume() {
    for (name, s) in stores() {
        let s = s.as_ref();
        for i in 0..40 {
            s.charge(&format!("d{i:02}"), &[calls(&format!("g{i:02}"))], t0())
                .unwrap();
        }
        let now = t0() + RETAIN + Duration::seconds(1);
        let mut passes = 0;
        let mut total = RunStatePrune::default();
        loop {
            let p = s.prune_run_state(now, RETAIN, 7).unwrap();
            passes += 1;
            assert!(p.examined <= 7, "{name}: {p:?}");
            total.examined += p.examined;
            total.pruned_charges += p.pruned_charges;
            total.pruned_counters += p.pruned_counters;
            if p.wrapped {
                break;
            }
            assert_eq!(p.examined, 7, "{name}: only the last pass is short");
        }
        // 40 log entries and 40 counters: eleven full passes and a short twelfth.
        assert_eq!(passes, 12, "{name}");
        assert_eq!(total.examined, 80, "{name}");
        assert_eq!(
            (total.pruned_charges, total.pruned_counters),
            (40, 40),
            "{name}"
        );
        let next = s.prune_run_state(now, RETAIN, 7).unwrap();
        assert_eq!(
            next,
            RunStatePrune {
                wrapped: true,
                ..Default::default()
            },
            "{name}"
        );
    }
}
