//! Pending approvals in the lease store (ADR-0009): created bound to a lease and a call hash,
//! granted or declined once, consumed once, and unusable once the lease is revoked or the
//! approval has expired. Every test runs against both stores.

mod common;

use attenuo_audit::{
    Approval, ApprovalLabel, ApprovalMethod, ApprovalState, ApprovalStore, Approver, AuditError,
    LeaseStore, MemoryLeaseStore, SqliteLeaseStore, MAX_PENDING_APPROVALS_PER_RUN,
};
use attenuo_core::{LeaseId, UntrustedArg, UntrustedKind};
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

fn id(s: &str) -> LeaseId {
    LeaseId::new(s)
}

/// `l1` (root) and `l2` (the calling hop), both live for an hour after t0.
fn leases(store: &dyn LeaseStore) {
    let exp = t0() + Duration::hours(1);
    store.register(&id("l1"), None, exp).unwrap();
    store.register(&id("l2"), Some(&id("l1")), exp).unwrap();
}

fn pending(n: u32, call_hash: &str, ttl: Duration) -> Approval {
    Approval {
        id: format!("00000000-0000-4000-8000-{n:012}"),
        chain_id: id("l1"),
        lease: id("l2"),
        call_hash: call_hash.into(),
        server: "github".into(),
        tool: "delete_repo".into(),
        arguments: json!({"repo": "alice/site"}),
        labels: vec![ApprovalLabel {
            source: "github/read_web".into(),
            seq: 3,
        }],
        untrusted_args: vec![UntrustedArg {
            arg: "repo".into(),
            seq: Some(3),
            kind: UntrustedKind::Leaf,
        }],
        decision_id: "d-gated".into(),
        chain: chain("alice", ("l1", "l2")),
        created_at: t0(),
        expires_at: t0() + ttl,
        state: ApprovalState::Pending,
        approver: None,
        decided_at: None,
        consumed_by: None,
        jkt: None,
    }
}

fn user() -> Approver {
    Approver {
        subject: "alice".into(),
        method: ApprovalMethod::IdToken,
    }
}

fn take(
    store: &dyn LeaseStore,
    hash: &str,
    decision: &str,
    now: OffsetDateTime,
) -> Option<Approval> {
    store
        .take_approval(&id("l1"), &id("l2"), hash, decision, now)
        .unwrap()
}

#[test]
fn approval_is_granted_then_consumed_once() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        let (a, created) = store
            .create_approval(&pending(1, "h1", Duration::seconds(120)))
            .unwrap();
        assert!(created, "{name}");
        assert_eq!(a.state, ApprovalState::Pending);
        assert_eq!(
            store.approval(&a.id).unwrap().unwrap(),
            a,
            "{name}: round trip"
        );

        // Nothing to use while pending.
        assert!(take(store, "h1", "d1", t0()).is_none(), "{name}");
        let now = t0() + Duration::seconds(5);
        let granted = store.decide_approval(&a.id, true, &user(), now).unwrap();
        assert_eq!(granted.state, ApprovalState::Granted);
        assert_eq!(granted.approver, Some(user()));
        assert_eq!(granted.decided_at, Some(now));

        // A different call hash or another hop's lease does not find it.
        assert!(take(store, "h2", "d1", now).is_none(), "{name}");
        assert!(store
            .take_approval(&id("l1"), &id("l1"), "h1", "d1", now)
            .unwrap()
            .is_none());

        let used = take(store, "h1", "d1", now).unwrap();
        assert_eq!(used.state, ApprovalState::Consumed, "{name}");
        assert_eq!(used.consumed_by.as_deref(), Some("d1"));
        assert!(take(store, "h1", "d2", now).is_none(), "{name}: single use");

        // A decision that did not go through gives it back; only its own consumer can.
        store.restore_approval(&a.id, "other").unwrap();
        assert!(take(store, "h1", "d2", now).is_none(), "{name}");
        store.restore_approval(&a.id, "d1").unwrap();
        assert_eq!(
            store.approval(&a.id).unwrap().unwrap().state,
            ApprovalState::Granted
        );
        assert!(take(store, "h1", "d2", now).is_some(), "{name}");

        // Granting again is refused.
        assert!(matches!(
            store.decide_approval(&a.id, true, &user(), now),
            Err(AuditError::ApprovalNotPending { .. })
        ));
    }
}

#[test]
fn declined_approval_cannot_be_used_or_granted() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        let (a, _) = store
            .create_approval(&pending(1, "h1", Duration::seconds(120)))
            .unwrap();
        let d = store.decide_approval(&a.id, false, &user(), t0()).unwrap();
        assert_eq!(d.state, ApprovalState::Declined, "{name}");
        assert!(take(store, "h1", "d1", t0()).is_none(), "{name}");
        assert!(matches!(
            store.decide_approval(&a.id, true, &user(), t0()),
            Err(AuditError::ApprovalNotPending { .. })
        ));
        // The same call gated again gets a new approval.
        let (b, created) = store
            .create_approval(&pending(2, "h1", Duration::seconds(120)))
            .unwrap();
        assert!(created, "{name}");
        assert_ne!(a.id, b.id);
    }
}

#[test]
fn a_repeated_gated_call_reuses_the_pending_approval() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        let (a, _) = store
            .create_approval(&pending(1, "h1", Duration::seconds(120)))
            .unwrap();
        let (b, created) = store
            .create_approval(&pending(2, "h1", Duration::seconds(120)))
            .unwrap();
        assert!(!created, "{name}");
        assert_eq!(a, b);
        let (c, created) = store
            .create_approval(&pending(3, "h2", Duration::seconds(120)))
            .unwrap();
        assert!(created, "{name}: another call hash is another approval");
        assert_eq!(store.approvals(None, None, None, 10).unwrap().len(), 2);
        assert_eq!(
            store.approvals(Some(&id("l1")), None, None, 10).unwrap()[0].1,
            c
        );
        assert!(store
            .approvals(Some(&id("other")), None, None, 10)
            .unwrap()
            .is_empty());
        assert_eq!(store.approvals(None, None, None, 1).unwrap().len(), 1);
    }
}

#[test]
fn expiry_is_capped_by_the_lease_and_ends_use() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        // A TTL past the lease's expiry is cut to it.
        let (a, _) = store
            .create_approval(&pending(1, "h1", Duration::hours(5)))
            .unwrap();
        assert_eq!(a.expires_at, t0() + Duration::hours(1), "{name}");

        let (b, _) = store
            .create_approval(&pending(2, "h2", Duration::seconds(120)))
            .unwrap();
        let late = t0() + Duration::seconds(121);
        assert!(matches!(
            store.decide_approval(&b.id, true, &user(), late),
            Err(AuditError::ApprovalExpired(_))
        ));
        store
            .decide_approval(&b.id, true, &user(), t0() + Duration::seconds(10))
            .unwrap();
        assert!(take(store, "h2", "d1", late).is_none(), "{name}: expired");
        assert!(take(store, "h2", "d1", t0() + Duration::seconds(119)).is_some());
    }
}

/// ADR-0009: revoking the lease kills pending and granted approvals.
#[test]
fn revoked_lease_kills_pending_and_granted_approvals() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        let (granted, _) = store
            .create_approval(&pending(1, "h1", Duration::seconds(120)))
            .unwrap();
        store
            .decide_approval(&granted.id, true, &user(), t0())
            .unwrap();
        let (waiting, _) = store
            .create_approval(&pending(2, "h2", Duration::seconds(120)))
            .unwrap();
        // Revoking the root revokes the calling hop's lease with it.
        store.revoke(&id("l1"), "test", t0()).unwrap();
        assert!(take(store, "h1", "d1", t0()).is_none(), "{name}");
        assert!(matches!(
            store.decide_approval(&waiting.id, true, &user(), t0()),
            Err(AuditError::LeaseRevoked(_))
        ));
        assert!(matches!(
            store.create_approval(&pending(3, "h3", Duration::seconds(120))),
            Err(AuditError::LeaseRevoked(_))
        ));
    }
}

#[test]
fn unknown_approvals_and_leases_are_errors() {
    for (name, store) in stores() {
        let store = store.as_ref();
        assert!(
            matches!(
                store.create_approval(&pending(1, "h1", Duration::seconds(120))),
                Err(AuditError::UnknownLease(_))
            ),
            "{name}"
        );
        assert!(store.approval("nope").unwrap().is_none());
        assert!(matches!(
            store.decide_approval("nope", true, &user(), t0()),
            Err(AuditError::UnknownApproval(_))
        ));
        leases(store);
        let (a, _) = store
            .create_approval(&pending(1, "h1", Duration::seconds(120)))
            .unwrap();
        store.remove_approval(&a.id).unwrap();
        assert!(store.approval(&a.id).unwrap().is_none(), "{name}");
    }
}

#[test]
fn approvals_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    let a = {
        let store = SqliteLeaseStore::open(&path).unwrap();
        leases(&store);
        let (a, _) = store
            .create_approval(&pending(1, "h1", Duration::seconds(120)))
            .unwrap();
        store
            .decide_approval(
                &a.id,
                true,
                &Approver {
                    subject: "urn:attenuo:admin".into(),
                    method: ApprovalMethod::AdminToken,
                },
                t0(),
            )
            .unwrap()
    };
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.approval(&a.id).unwrap().unwrap(), a);
    assert_eq!(a.approver.unwrap().method.by(), "operator");
}

/// A presented approval token names its approval by id (`jti`): taking it by id checks the
/// same things as the identical-retry lookup, and is single use too.
#[test]
fn approval_taken_by_id_checks_run_hop_call_and_state() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        let mut wanted = pending(1, "h1", Duration::seconds(120));
        wanted.jkt = Some("jkt-1".into());
        let (a, _) = store.create_approval(&wanted).unwrap();
        assert_eq!(a.jkt.as_deref(), Some("jkt-1"), "{name}");
        assert_eq!(
            store.approval(&a.id).unwrap().unwrap().jkt.as_deref(),
            Some("jkt-1"),
            "{name}: jkt round trip"
        );
        let by_id = |id_: &str, chain: &str, lease: &str, hash: &str, d: &str, now| {
            store
                .take_approval_by_id(id_, &id(chain), &id(lease), hash, d, now)
                .unwrap()
        };
        let now = t0() + Duration::seconds(5);
        assert!(
            by_id(&a.id, "l1", "l2", "h1", "d1", now).is_none(),
            "{name}: pending"
        );
        store.decide_approval(&a.id, true, &user(), now).unwrap();
        assert!(
            by_id("nope", "l1", "l2", "h1", "d1", now).is_none(),
            "{name}"
        );
        assert!(
            by_id(&a.id, "l9", "l2", "h1", "d1", now).is_none(),
            "{name}: run"
        );
        assert!(
            by_id(&a.id, "l1", "l1", "h1", "d1", now).is_none(),
            "{name}: hop"
        );
        assert!(
            by_id(&a.id, "l1", "l2", "h2", "d1", now).is_none(),
            "{name}: call"
        );
        let late = t0() + Duration::seconds(121);
        assert!(
            by_id(&a.id, "l1", "l2", "h1", "d1", late).is_none(),
            "{name}: expired"
        );
        let used = by_id(&a.id, "l1", "l2", "h1", "d1", now).unwrap();
        assert_eq!(used.state, ApprovalState::Consumed, "{name}");
        assert!(
            by_id(&a.id, "l1", "l2", "h1", "d2", now).is_none(),
            "{name}: single use"
        );
        store.restore_approval(&a.id, "d1").unwrap();
        // Revoking the hop's lease kills it.
        store.revoke(&id("l2"), "test", now).unwrap();
        assert!(
            by_id(&a.id, "l1", "l2", "h1", "d3", now).is_none(),
            "{name}: revoked"
        );
    }
}

/// SR-92: a run has at most `MAX_PENDING_APPROVALS_PER_RUN` pending, unexpired approvals. The
/// next distinct gated call is refused; a repeat of a waiting call still gets its approval and
/// does not count again; another run is not affected; a decided or expired approval frees
/// its place.
#[test]
fn a_run_has_at_most_max_pending_approvals_sr92() {
    assert_eq!(MAX_PENDING_APPROVALS_PER_RUN, 32);
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        let ttl = Duration::seconds(120);
        let hash = |n: u32| format!("h{n}");
        let mut first = Vec::new();
        for n in 0..MAX_PENDING_APPROVALS_PER_RUN as u32 {
            let (a, created) = store.create_approval(&pending(n, &hash(n), ttl)).unwrap();
            assert!(created, "{name}: approval {n}");
            first.push(a);
        }
        let over = pending(100, &hash(100), ttl);
        match store.create_approval(&over) {
            Err(AuditError::TooManyPendingApprovals { chain_id, max }) => {
                assert_eq!((chain_id.as_str(), max), ("l1", 32), "{name}");
            }
            other => panic!("{name}: the 33rd distinct approval was not refused: {other:?}"),
        }
        assert!(
            store.approval(&over.id).unwrap().is_none(),
            "{name}: not stored"
        );
        assert_eq!(
            store
                .approvals(Some(&id("l1")), None, None, 100)
                .unwrap()
                .len(),
            32,
            "{name}"
        );

        // The same call again reuses its approval, at the cap and as often as it is repeated.
        for _ in 0..3 {
            let (again, created) = store.create_approval(&pending(101, &hash(5), ttl)).unwrap();
            assert!(!created, "{name}");
            assert_eq!(again, first[5], "{name}");
        }

        // Another run (root `l3`, calling hop `l4`) still gets one.
        let exp = t0() + Duration::hours(1);
        store.register(&id("l3"), None, exp).unwrap();
        store.register(&id("l4"), Some(&id("l3")), exp).unwrap();
        let mut other = pending(200, &hash(100), ttl);
        other.chain_id = id("l3");
        other.lease = id("l4");
        other.chain = chain("bob", ("l3", "l4"));
        assert!(
            store.create_approval(&other).unwrap().1,
            "{name}: other run"
        );

        // A declined approval no longer counts: one more fits, then the cap holds again.
        store
            .decide_approval(&first[0].id, false, &user(), t0())
            .unwrap();
        assert!(store.create_approval(&over).unwrap().1, "{name}");
        assert!(matches!(
            store.create_approval(&pending(102, &hash(102), ttl)),
            Err(AuditError::TooManyPendingApprovals { .. })
        ));

        // Once they have expired, pending approvals no longer count either.
        let mut later = pending(103, &hash(103), ttl);
        later.created_at = t0() + Duration::seconds(121);
        later.expires_at = later.created_at + ttl;
        assert!(
            store.create_approval(&later).unwrap().1,
            "{name}: after expiry"
        );
    }
}

/// SR-97: approvals of a revoked hop do not hold the run's places. Hops `l1` (root), `l2`
/// and `l3` (child of `l2`): while `l3` is live its 32 approvals fill the run and `l2` is
/// refused; once `l3` is revoked `l2` gets one at once, and the cap then counts only the
/// live hops' approvals.
#[test]
fn a_revoked_child_frees_the_runs_pending_places_sr97() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        let exp = t0() + Duration::hours(1);
        store.register(&id("l3"), Some(&id("l2")), exp).unwrap();
        let ttl = Duration::seconds(120);
        let of_child = |n: u32| {
            let mut a = pending(n, &format!("c{n}"), ttl);
            a.lease = id("l3");
            a.chain = chain("alice", ("l1", "l3"));
            a
        };
        for n in 0..MAX_PENDING_APPROVALS_PER_RUN as u32 {
            assert!(
                store.create_approval(&of_child(n)).unwrap().1,
                "{name}: {n}"
            );
        }

        // The child is live: the cap holds for its parent.
        let mut parent = pending(100, "p100", ttl);
        parent.created_at = t0() + Duration::seconds(1);
        match store.create_approval(&parent) {
            Err(AuditError::TooManyPendingApprovals { chain_id, max }) => {
                assert_eq!((chain_id.as_str(), max), ("l1", 32), "{name}");
            }
            other => panic!("{name}: the parent's approval was not refused: {other:?}"),
        }

        // Revoking the child frees its places at once.
        store
            .revoke(&id("l3"), "misbehaving", t0() + Duration::seconds(1))
            .unwrap();
        assert!(
            store.create_approval(&parent).unwrap().1,
            "{name}: parent after revocation"
        );

        // The cap still holds over the live hops: 31 more fit, the next is refused.
        for n in 101..132u32 {
            let mut a = pending(n, &format!("p{n}"), ttl);
            a.created_at = parent.created_at;
            assert!(store.create_approval(&a).unwrap().1, "{name}: {n}");
        }
        let mut over = pending(200, "p200", ttl);
        over.created_at = parent.created_at;
        assert!(
            matches!(
                store.create_approval(&over),
                Err(AuditError::TooManyPendingApprovals { .. })
            ),
            "{name}: cap over live hops"
        );
    }
}

/// Every page of `approvals(chain, state, before, limit)` from the top, following the position
/// of each page's last approval, as the ids in the order listed.
fn page_all(
    store: &dyn LeaseStore,
    chain: Option<&LeaseId>,
    state: Option<ApprovalState>,
    limit: usize,
    mut between: impl FnMut(usize),
) -> Vec<String> {
    let mut out = Vec::new();
    let mut before = None;
    for page_no in 0.. {
        let page = store.approvals(chain, state, before, limit).unwrap();
        assert!(page.len() <= limit);
        assert!(
            page.windows(2).all(|w| w[0].0 > w[1].0),
            "positions strictly decrease within a page"
        );
        if let (Some(b), Some((first, _))) = (before, page.first()) {
            assert!(*first < b, "a page starts below its bound");
        }
        out.extend(page.iter().map(|(_, a)| a.id.clone()));
        match page.last() {
            Some((pos, _)) if page.len() == limit => before = Some(*pos),
            _ => break,
        }
        between(page_no);
    }
    out
}

#[test]
fn approvals_page_by_position_each_exactly_once() {
    for (name, store) in stores() {
        let store = store.as_ref();
        leases(store);
        // More than the pending cap allows at once: decide every other one so the run stays
        // below it, which also gives the state filter something to keep and drop.
        let n = 250u32;
        for i in 0..n {
            let (a, created) = store
                .create_approval(&pending(i, &format!("h{i}"), Duration::seconds(600)))
                .unwrap();
            assert!(created, "{name}");
            store
                .decide_approval(&a.id, i.is_multiple_of(2), &user(), t0())
                .unwrap();
        }
        let ids = |r: std::ops::Range<u32>| -> Vec<String> {
            r.rev()
                .map(|i| format!("00000000-0000-4000-8000-{i:012}"))
                .collect()
        };

        // Newest first, every approval once, for page sizes that do and do not divide n.
        for limit in [1usize, 7, 50, 250, 1000] {
            let got = page_all(store, None, None, limit, |_| {});
            assert_eq!(got, ids(0..n), "{name}: limit {limit}");
        }

        // Approvals created while paging sort above the first page: the pre-existing ones are
        // each listed once, none skipped, and the new ones are not mixed in below.
        let mut extra = n;
        let got = page_all(store, None, None, 40, |_| {
            let (a, _) = store
                .create_approval(&pending(
                    extra,
                    &format!("h{extra}"),
                    Duration::seconds(600),
                ))
                .unwrap();
            store.decide_approval(&a.id, false, &user(), t0()).unwrap();
            extra += 1;
        });
        assert_eq!(got, ids(0..n), "{name}: inserts during paging");

        // The state filter applies before the limit, and pages like the unfiltered list.
        let granted = page_all(store, None, Some(ApprovalState::Granted), 9, |_| {});
        let want: Vec<String> = ids(0..n)
            .into_iter()
            .enumerate()
            .filter(|(k, _)| (n as usize - 1 - k).is_multiple_of(2))
            .map(|(_, id)| id)
            .collect();
        assert_eq!(granted, want, "{name}: state filter");
        let chain_only = page_all(
            store,
            Some(&id("l1")),
            Some(ApprovalState::Declined),
            13,
            |_| {},
        );
        assert_eq!(
            chain_only.len(),
            (n as usize) / 2 + (extra - n) as usize,
            "{name}: chain and state"
        );
        assert!(page_all(store, Some(&id("other")), None, 10, |_| {}).is_empty());

        // An approval removed at the page boundary does not lose the position.
        let first = store.approvals(None, None, None, 10).unwrap();
        let (pos, last) = first.last().unwrap().clone();
        store.remove_approval(&last.id).unwrap();
        let next = store.approvals(None, None, Some(pos), 1).unwrap();
        assert!(next[0].0 < pos, "{name}");
        assert_ne!(next[0].1.id, last.id);
    }
}
