//! `take_approval` on a SQLite file reads before it writes (audit finding A-4): a call with no
//! usable granted approval takes no write lock and runs no write transaction, and a granted
//! approval is still consumed exactly once. The read may only conclude "nothing to consume":
//! a grant that lands after it is left for the next call, an approval consumed by another
//! call after it is not taken twice, and a lease revoked after it still refuses the approval.

mod common;

use std::sync::{Arc, Barrier};

use attenuo_audit::{
    Approval, ApprovalMethod, ApprovalState, Approver, Durability, LeaseStore, SqliteLeaseStore,
};
use attenuo_core::LeaseId;
use common::{chain, t0};
use serde_json::json;
use time::{Duration, OffsetDateTime};

/// Rounds of each race. Every round is a new approval, so a lost or doubled consume in any
/// round fails the test.
const ROUNDS: usize = 200;

fn id(s: &str) -> LeaseId {
    LeaseId::new(s)
}

/// Two stores (two connections) on one new file, `l1` -> `l2` registered, live for an hour.
fn pair() -> (
    tempfile::TempDir,
    Arc<SqliteLeaseStore>,
    Arc<SqliteLeaseStore>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let a = SqliteLeaseStore::open_with(&path, Durability::Normal).unwrap();
    let b = SqliteLeaseStore::open_with(&path, Durability::Normal).unwrap();
    let exp = t0() + Duration::hours(1);
    a.register(&id("l1"), None, exp).unwrap();
    a.register(&id("l2"), Some(&id("l1")), exp).unwrap();
    (dir, Arc::new(a), Arc::new(b))
}

fn pending(n: usize, call_hash: &str, ttl: Duration) -> Approval {
    Approval {
        id: format!("00000000-0000-4000-8000-{n:012}"),
        chain_id: id("l1"),
        lease: id("l2"),
        call_hash: call_hash.into(),
        server: "github".into(),
        tool: "delete_repo".into(),
        arguments: json!({"repo": "alice/site"}),
        labels: Vec::new(),
        untrusted_args: Vec::new(),
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

fn approver() -> Approver {
    Approver {
        subject: "alice".into(),
        method: ApprovalMethod::IdToken,
    }
}

/// A granted approval `n` for `call_hash`, usable for two minutes after t0.
fn granted(store: &dyn LeaseStore, n: usize, call_hash: &str) -> Approval {
    let (a, created) = store
        .create_approval(&pending(n, call_hash, Duration::seconds(120)))
        .unwrap();
    assert!(created);
    store
        .decide_approval(&a.id, true, &approver(), t0() + Duration::seconds(1))
        .unwrap()
}

fn take(store: &dyn LeaseStore, hash: &str, decision: &str, now: OffsetDateTime) -> bool {
    store
        .take_approval(&id("l1"), &id("l2"), hash, decision, now)
        .unwrap()
        .is_some()
}

fn now() -> OffsetDateTime {
    t0() + Duration::seconds(5)
}

#[test]
fn a_call_with_nothing_to_consume_takes_no_write() {
    let (_dir, store, _) = pair();
    let store = store.as_ref();
    // A pending approval, a granted one for another call, and an expired granted one: none
    // is usable by `h1` at `now()`, so none needs the write lock.
    store
        .create_approval(&pending(1, "h1", Duration::seconds(120)))
        .unwrap();
    granted(store, 2, "h2");
    let (short, _) = store
        .create_approval(&pending(3, "h3", Duration::seconds(3)))
        .unwrap();
    store
        .decide_approval(&short.id, true, &approver(), t0() + Duration::seconds(1))
        .unwrap();

    let before = store.write_turns();
    for i in 0..50 {
        assert!(!take(store, "h1", &format!("d{i}"), now()));
        assert!(!take(store, "h3", &format!("e{i}"), now()), "expired");
        assert!(!take(store, "nothing", &format!("f{i}"), now()));
    }
    assert_eq!(
        store.write_turns(),
        before,
        "no write without a usable approval"
    );

    // A usable one is consumed in one write.
    assert!(take(store, "h2", "d-took", now()));
    assert_eq!(store.write_turns(), before + 1);
    assert!(!take(store, "h2", "d-again", now()), "consumed once");
    assert_eq!(store.write_turns(), before + 1);
}

#[test]
fn a_grant_after_the_read_is_left_for_the_next_call() {
    let (_dir, a, b) = pair();
    let (pend, _) = a
        .create_approval(&pending(1, "h1", Duration::seconds(120)))
        .unwrap();
    // The grant commits (on the other connection) between this call's read, which saw
    // nothing usable, and its return.
    let id = pend.id.clone();
    let other = b.clone();
    a.after_next_approval_read(move || {
        other
            .decide_approval(&id, true, &approver(), t0() + Duration::seconds(1))
            .unwrap();
    });
    assert!(!take(a.as_ref(), "h1", "d1", now()));
    assert_eq!(
        a.approval(&pend.id).unwrap().unwrap().state,
        ApprovalState::Granted,
        "not consumed by the call that missed it"
    );
    assert!(
        take(a.as_ref(), "h1", "d2", now()),
        "the next call takes it"
    );
    let stored = a.approval(&pend.id).unwrap().unwrap();
    assert_eq!(stored.state, ApprovalState::Consumed);
    assert_eq!(stored.consumed_by.as_deref(), Some("d2"));
}

#[test]
fn a_revocation_after_the_read_still_refuses_the_approval() {
    let (_dir, a, b) = pair();
    let g = granted(a.as_ref(), 1, "h1");
    // The read sees a usable approval; the lease is revoked before the write transaction.
    let other = b.clone();
    a.after_next_approval_read(move || {
        other.revoke(&LeaseId::new("l2"), "test", now()).unwrap();
    });
    assert!(!take(a.as_ref(), "h1", "d1", now()));
    assert_eq!(
        a.approval(&g.id).unwrap().unwrap().state,
        ApprovalState::Granted,
        "left unconsumed"
    );
    assert!(!take(a.as_ref(), "h1", "d2", now()), "refused from then on");
}

#[test]
fn a_revoked_lease_or_an_expired_approval_is_refused() {
    let (_dir, a, _) = pair();
    granted(a.as_ref(), 1, "h1");
    assert!(
        !take(a.as_ref(), "h1", "d1", t0() + Duration::seconds(121)),
        "expired"
    );
    a.revoke(&id("l2"), "test", now()).unwrap();
    assert!(!take(a.as_ref(), "h1", "d2", now()), "lease revoked");
}

#[test]
fn a_consume_by_another_call_after_the_read_is_not_doubled() {
    let (_dir, a, b) = pair();
    let g = granted(a.as_ref(), 1, "h1");
    // Both reads have seen the approval; the other call consumes it first.
    let other = b.clone();
    a.after_next_approval_read(move || {
        assert!(take(other.as_ref(), "h1", "d-other", now()));
    });
    assert!(!take(a.as_ref(), "h1", "d1", now()));
    assert_eq!(
        a.approval(&g.id).unwrap().unwrap().consumed_by.as_deref(),
        Some("d-other")
    );
}

/// Two calls race for one granted approval, `ROUNDS` times: exactly one takes it. `forced`
/// (two stores only) holds both calls between their read and their write until both have
/// read, so every round is the interleaving the read-first path adds.
fn race(same_store: bool, forced: bool) {
    assert!(!(same_store && forced), "one hook per store");
    let (_dir, a, b) = pair();
    let b = if same_store { a.clone() } else { b };
    for round in 0..ROUNDS {
        let hash = format!("h{round}");
        let g = granted(a.as_ref(), round, &hash);
        if forced {
            // Two stores, one hook each: both calls wait after their read until both have
            // read, then race for the write.
            let both_read = Arc::new(Barrier::new(2));
            let (ga, gb) = (both_read.clone(), both_read);
            a.after_next_approval_read(move || {
                ga.wait();
            });
            b.after_next_approval_read(move || {
                gb.wait();
            });
            let racers: Vec<_> = [(a.clone(), "da"), (b.clone(), "db")]
                .into_iter()
                .map(|(store, d)| {
                    let hash = hash.clone();
                    std::thread::spawn(move || take(store.as_ref(), &hash, d, now()))
                })
                .collect();
            let won: usize = racers
                .into_iter()
                .map(|r| usize::from(r.join().unwrap()))
                .sum();
            assert_eq!(won, 1, "round {round}: exactly one call takes it");
        } else {
            let start = Arc::new(Barrier::new(2));
            let racers: Vec<_> = [(a.clone(), "da"), (b.clone(), "db")]
                .into_iter()
                .map(|(store, d)| {
                    let (hash, start) = (hash.clone(), start.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        take(store.as_ref(), &hash, d, now())
                    })
                })
                .collect();
            let won: usize = racers
                .into_iter()
                .map(|r| usize::from(r.join().unwrap()))
                .sum();
            assert_eq!(won, 1, "round {round}: exactly one call takes it");
        }
        let stored = a.approval(&g.id).unwrap().unwrap();
        assert_eq!(stored.state, ApprovalState::Consumed, "round {round}");
        assert!(matches!(stored.consumed_by.as_deref(), Some("da" | "db")));
    }
}

#[test]
fn racing_calls_on_two_connections_consume_one_approval_once() {
    race(false, false);
}

#[test]
fn racing_calls_on_one_store_consume_one_approval_once() {
    race(true, false);
}

#[test]
fn calls_that_both_read_before_either_writes_consume_once() {
    race(false, true);
}
