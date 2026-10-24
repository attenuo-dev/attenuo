//! Lease registry: register, revoke with cascade, revoke by user, chain or session, expiry,
//! unknown-fails-closed, persistence.

mod common;

use attenuo_audit::{
    AuditError, AuditSink, LeaseNode, LeaseSelector, LeaseStatus, LeaseStore, LeaseSubtree,
    MemoryLeaseStore, SessionBinding, SqliteAudit, SqliteLeaseStore,
};
use attenuo_core::LeaseId;
use attenuo_core::{Decision, DelegationChain, RecordKind};
use common::t0;
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

fn id(s: &str) -> LeaseId {
    LeaseId::new(s)
}

/// root -> a -> (a1, a2 -> a2x); root -> b. All expire an hour after t0.
fn tree(store: &dyn LeaseStore) {
    let exp = t0() + Duration::hours(1);
    store.register(&id("root"), None, exp).unwrap();
    store.register(&id("a"), Some(&id("root")), exp).unwrap();
    store.register(&id("a1"), Some(&id("a")), exp).unwrap();
    store.register(&id("a2"), Some(&id("a")), exp).unwrap();
    store.register(&id("a2x"), Some(&id("a2")), exp).unwrap();
    store.register(&id("b"), Some(&id("root")), exp).unwrap();
}

/// SR-08 defence in depth: bindings are write-once and only for known leases.
#[test]
fn bindings_are_write_once() {
    for (name, store) in stores() {
        tree(store.as_ref());
        assert_eq!(store.binding(&id("a")).unwrap(), None, "{name}");
        store.bind(&id("a"), "d1").unwrap();
        store.bind(&id("a"), "d1").unwrap();
        assert_eq!(store.binding(&id("a")).unwrap().as_deref(), Some("d1"));
        assert!(
            matches!(
                store.bind(&id("a"), "d2"),
                Err(AuditError::BindingConflict(_))
            ),
            "{name}"
        );
        assert_eq!(store.binding(&id("a")).unwrap().as_deref(), Some("d1"));
        assert!(matches!(
            store.bind(&id("nope"), "d1"),
            Err(AuditError::UnknownLease(_))
        ));
        // Revocation does not touch the binding.
        store.revoke(&id("root"), "x", t0()).unwrap();
        assert_eq!(store.binding(&id("a")).unwrap().as_deref(), Some("d1"));
    }
}

#[test]
fn register_then_active() {
    for (name, store) in stores() {
        tree(store.as_ref());
        for l in ["root", "a", "a1", "a2", "a2x", "b"] {
            assert!(store.is_active(&id(l), t0()).unwrap(), "{name}: {l}");
        }
        let status = store
            .check_all(&[&id("root"), &id("a"), &id("a2x")], t0())
            .unwrap();
        assert_eq!(
            status,
            LeaseStatus {
                active: true,
                ..Default::default()
            }
        );
    }
}

#[test]
fn revoke_cascades_to_descendants_only() {
    for (name, store) in stores() {
        tree(store.as_ref());
        let now = t0() + Duration::minutes(1);
        let n = store.revoke(&id("a"), "operator_kill", now).unwrap();
        assert_eq!(n, 4, "{name}: a, a1, a2, a2x");
        for l in ["a", "a1", "a2", "a2x"] {
            assert!(!store.is_active(&id(l), now).unwrap(), "{name}: {l}");
        }
        for l in ["root", "b"] {
            assert!(store.is_active(&id(l), now).unwrap(), "{name}: {l}");
        }
        // Revoking again is idempotent: nothing new changes.
        assert_eq!(store.revoke(&id("a"), "again", now).unwrap(), 0);
        // Revoking an ancestor counts only what was still live.
        assert_eq!(store.revoke(&id("root"), "all", now).unwrap(), 2);
        assert!(!store.is_active(&id("b"), now).unwrap());
    }
}

#[test]
fn revoke_leaf_does_not_touch_parent() {
    for (name, store) in stores() {
        tree(store.as_ref());
        assert_eq!(store.revoke(&id("a2x"), "leaf", t0()).unwrap(), 1, "{name}");
        assert!(store.is_active(&id("a2"), t0()).unwrap());
        assert!(store.is_active(&id("a"), t0()).unwrap());
    }
}

#[test]
fn revoke_unknown_is_an_error() {
    for (name, store) in stores() {
        let err = store.revoke(&id("ghost"), "x", t0()).unwrap_err();
        assert!(
            matches!(err, AuditError::UnknownLease(ref l) if l == "ghost"),
            "{name}: {err}"
        );
    }
}

#[test]
fn expired_lease_is_inactive() {
    for (name, store) in stores() {
        let exp = t0() + Duration::minutes(10);
        store.register(&id("short"), None, exp).unwrap();
        assert!(store.is_active(&id("short"), t0()).unwrap(), "{name}");
        assert!(store
            .is_active(&id("short"), exp - Duration::seconds(1))
            .unwrap());
        assert!(
            !store.is_active(&id("short"), exp).unwrap(),
            "{name}: boundary is exclusive"
        );
        assert!(!store
            .is_active(&id("short"), exp + Duration::days(1))
            .unwrap());
    }
}

#[test]
fn unknown_lease_is_inactive() {
    for (name, store) in stores() {
        assert!(
            !store.is_active(&id("never-registered"), t0()).unwrap(),
            "{name}"
        );
        let status = store.check_all(&[&id("never-registered")], t0()).unwrap();
        assert!(!status.active);
        assert_eq!(status.unknown, vec![id("never-registered")]);
    }
}

#[test]
fn check_all_reports_mixed_statuses() {
    for (name, store) in stores() {
        let exp = t0() + Duration::hours(1);
        store.register(&id("ok"), None, exp).unwrap();
        store.register(&id("gone"), None, exp).unwrap();
        store
            .register(&id("stale"), None, t0() - Duration::seconds(1))
            .unwrap();
        store
            .register(&id("gone-and-stale"), None, t0() - Duration::seconds(1))
            .unwrap();
        store.revoke(&id("gone"), "r", t0()).unwrap();
        store.revoke(&id("gone-and-stale"), "r", t0()).unwrap();

        let leases = [
            id("ok"),
            id("gone"),
            id("stale"),
            id("missing"),
            id("gone-and-stale"),
        ];
        let refs: Vec<&LeaseId> = leases.iter().collect();
        let status = store.check_all(&refs, t0()).unwrap();
        assert_eq!(
            status,
            LeaseStatus {
                active: false,
                revoked: vec![id("gone"), id("gone-and-stale")],
                expired: vec![id("stale")],
                unknown: vec![id("missing")],
            },
            "{name}"
        );

        let status = store.check_all(&[&id("ok")], t0()).unwrap();
        assert!(status.active, "{name}");
        let status = store.check_all(&[], t0()).unwrap();
        assert!(status.active, "{name}: vacuously active with no leases");
    }
}

/// The SQLite store reads every lease of a chain in one `IN (...)` query (in chunks for very
/// long lists). Order, duplicates and unknown ids must come out as with one lookup per lease.
#[test]
fn check_all_batches_agree_with_per_lease_lookups() {
    let exp = t0() + Duration::hours(1);
    let leases: Vec<LeaseId> = (0..1100)
        .map(|i| id(&format!("l{i}")))
        .chain([id("l7"), id("unknown-1"), id("l3")])
        .collect();
    let refs: Vec<&LeaseId> = leases.iter().collect();
    let mut results = Vec::new();
    for (name, store) in stores() {
        for (i, l) in leases.iter().take(1100).enumerate() {
            let at = if i % 97 == 5 {
                t0() - Duration::seconds(1)
            } else {
                exp
            };
            store.register(l, None, at).unwrap();
        }
        store.revoke(&id("l3"), "r", t0()).unwrap();
        store.revoke(&id("l1050"), "r", t0()).unwrap();
        let status = store.check_all(&refs, t0()).unwrap();
        assert!(!status.active, "{name}");
        assert_eq!(
            status.revoked,
            vec![id("l3"), id("l1050"), id("l3")],
            "{name}"
        );
        assert_eq!(status.unknown, vec![id("unknown-1")], "{name}");
        results.push(status);
    }
    assert_eq!(results[0], results[1], "memory and sqlite agree");
}

#[test]
fn reregister_keeps_revocation() {
    for (name, store) in stores() {
        let exp = t0() + Duration::hours(1);
        store.register(&id("x"), None, exp).unwrap();
        store.revoke(&id("x"), "r", t0()).unwrap();
        store
            .register(&id("x"), None, exp + Duration::hours(1))
            .unwrap();
        assert!(!store.is_active(&id("x"), t0()).unwrap(), "{name}");
    }
}

#[test]
fn sqlite_leases_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    {
        let s = SqliteLeaseStore::open(&path).unwrap();
        tree(&s);
        assert_eq!(s.revoke(&id("a2"), "r", t0()).unwrap(), 2);
    }
    let s = SqliteLeaseStore::open(&path).unwrap();
    assert!(s.is_active(&id("root"), t0()).unwrap());
    assert!(s.is_active(&id("a1"), t0()).unwrap());
    assert!(!s.is_active(&id("a2"), t0()).unwrap());
    assert!(!s.is_active(&id("a2x"), t0()).unwrap());
    let row = s.get(&id("a2x")).unwrap().unwrap();
    assert_eq!(row.parent, Some(id("a2")));
    assert_eq!(row.revoked_at, Some(t0()));
    assert_eq!(row.revoke_reason.as_deref(), Some("r"));
    // Cascade still works on the reopened tree.
    assert_eq!(s.revoke(&id("root"), "r2", t0()).unwrap(), 4);
}

#[test]
fn renew_extends_and_revives_an_expired_lease() {
    for (name, store) in stores() {
        let exp = t0() + Duration::minutes(5);
        store.register(&id("r"), None, exp).unwrap();
        let later = t0() + Duration::minutes(10);
        assert!(!store.is_active(&id("r"), later).unwrap(), "{name}");
        store
            .renew(&id("r"), later + Duration::minutes(5), later)
            .unwrap();
        assert!(store.is_active(&id("r"), later).unwrap(), "{name}");
        assert!(!store
            .is_active(&id("r"), later + Duration::minutes(5))
            .unwrap());
    }
}

#[test]
fn renew_rejects_unknown_and_revoked() {
    for (name, store) in stores() {
        let exp = t0() + Duration::minutes(5);
        let err = store.renew(&id("ghost"), exp, t0()).unwrap_err();
        assert!(matches!(err, AuditError::UnknownLease(_)), "{name}: {err}");

        store.register(&id("p"), None, exp).unwrap();
        store.register(&id("c"), Some(&id("p")), exp).unwrap();
        store.revoke(&id("p"), "r", t0()).unwrap();
        for l in ["p", "c"] {
            let err = store
                .renew(&id(l), exp + Duration::hours(1), t0())
                .unwrap_err();
            assert!(matches!(err, AuditError::LeaseRevoked(_)), "{name}: {l}");
            assert!(!store.is_active(&id(l), t0()).unwrap(), "{name}: {l}");
        }
    }
}

#[test]
fn file_store_revokes_with_full_sync_and_returns_to_its_setting() {
    use attenuo_audit::Durability;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    let store = SqliteLeaseStore::open_with(&path, Durability::Normal).unwrap();
    let query = |s: &SqliteLeaseStore, sql: &str| -> String {
        s.with_connection(|c| Ok(c.query_row(sql, [], |r| r.get::<_, rusqlite::types::Value>(0))?))
            .map(|v| match v {
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Text(t) => t,
                other => format!("{other:?}"),
            })
            .unwrap()
    };
    assert_eq!(query(&store, "PRAGMA journal_mode"), "wal");
    assert_eq!(query(&store, "PRAGMA synchronous"), "1", "normal");
    tree(&store);
    assert_eq!(store.revoke(&id("a"), "test", t0()).unwrap(), 4);
    assert_eq!(query(&store, "PRAGMA synchronous"), "1", "back to normal");
    // A failed revocation restores the setting too.
    assert!(store.revoke(&id("nope"), "test", t0()).is_err());
    assert_eq!(query(&store, "PRAGMA synchronous"), "1");
    drop(store);
    let store = SqliteLeaseStore::open_with(&path, Durability::Full).unwrap();
    assert_eq!(query(&store, "PRAGMA synchronous"), "2", "full");
    let status = store.check_all(&[&id("root"), &id("a2x")], t0()).unwrap();
    assert_eq!(status.revoked, vec![id("a2x")], "the revocation persisted");
}

/// `subtree` is inherent on each store (the server holds a concrete `SqliteLeaseStore`), so
/// the parity tests below run it on both through this pair.
struct Both {
    memory: MemoryLeaseStore,
    sqlite: SqliteLeaseStore,
}

impl Both {
    fn new() -> Self {
        Self {
            memory: MemoryLeaseStore::new(),
            sqlite: SqliteLeaseStore::open_in_memory().unwrap(),
        }
    }

    fn each(&self) -> [(&'static str, &dyn LeaseStore); 2] {
        [("memory", &self.memory), ("sqlite", &self.sqlite)]
    }

    /// Both stores' answer, after checking that they agree.
    fn subtree(&self, lease: &str, max_nodes: usize) -> Option<LeaseSubtree> {
        let m = self.memory.subtree(&id(lease), max_nodes).unwrap();
        let s = self.sqlite.subtree(&id(lease), max_nodes).unwrap();
        assert_eq!(m, s, "memory and sqlite disagree on the subtree of {lease}");
        s
    }
}

fn ids(nodes: &[LeaseNode]) -> Vec<&str> {
    nodes.iter().map(|n| n.id.0.as_str()).collect()
}

#[test]
fn subtree_lists_the_lease_its_descendants_and_its_ancestors() {
    let both = Both::new();
    for (_, s) in both.each() {
        tree(s);
    }
    let t = both.subtree("a", 1000).unwrap();
    assert_eq!(ids(&t.nodes), ["a", "a1", "a2", "a2x"]);
    assert_eq!(ids(&t.ancestors), ["root"]);
    assert_eq!(t.root(), &id("root"));
    assert_eq!(t.would_revoke, 4);
    assert!(!t.truncated);

    let t = both.subtree("a2x", 1000).unwrap();
    assert_eq!(ids(&t.nodes), ["a2x"]);
    assert_eq!(ids(&t.ancestors), ["a2", "a", "root"], "nearest first");

    let t = both.subtree("root", 1000).unwrap();
    assert_eq!(ids(&t.nodes), ["root", "a", "b", "a1", "a2", "a2x"]);
    assert!(t.ancestors.is_empty());
    assert_eq!(t.root(), &id("root"));

    assert_eq!(both.subtree("ghost", 1000), None);
}

/// The preview is a dry run: `would_revoke` is what `revoke` then reports, whether the
/// subtree is fresh, partly revoked or fully revoked, and reading it changes nothing.
#[test]
fn would_revoke_matches_the_following_revocation() {
    let both = Both::new();
    for (_, s) in both.each() {
        tree(s);
    }
    let now = t0() + Duration::minutes(1);
    let before = both.subtree("root", 1000).unwrap();
    assert_eq!(both.subtree("root", 1000).unwrap(), before, "read-only");
    // Fresh: a2 and a2x.
    let predicted = both.subtree("a2", 1000).unwrap().would_revoke;
    assert_eq!(predicted, 2);
    for (name, s) in both.each() {
        assert_eq!(s.revoke(&id("a2"), "x", now).unwrap(), predicted, "{name}");
    }
    // Partly revoked: only a and a1 are still live.
    let predicted = both.subtree("a", 1000).unwrap().would_revoke;
    assert_eq!(predicted, 2);
    for (name, s) in both.each() {
        assert_eq!(s.revoke(&id("a"), "x", now).unwrap(), predicted, "{name}");
    }
    // Fully revoked.
    assert_eq!(both.subtree("a", 1000).unwrap().would_revoke, 0);
    for (name, s) in both.each() {
        assert_eq!(s.revoke(&id("a"), "x", now).unwrap(), 0, "{name}");
    }
    // The rows show the revocation the preview did not make.
    let t = both.subtree("a", 1000).unwrap();
    assert!(t.nodes.iter().all(|n| n.row.revoked_at == Some(now)));
}

#[test]
fn max_nodes_truncates_breadth_first_but_would_revoke_counts_everything() {
    let both = Both::new();
    for (_, s) in both.each() {
        tree(s);
    }
    let t = both.subtree("root", 3).unwrap();
    assert_eq!(ids(&t.nodes), ["root", "a", "b"]);
    assert!(t.truncated);
    assert_eq!(t.would_revoke, 6);
    // Exactly the subtree's size is not truncated; zero is raised to one.
    assert!(!both.subtree("root", 6).unwrap().truncated);
    let t = both.subtree("root", 0).unwrap();
    assert_eq!(ids(&t.nodes), ["root"]);
    assert!(t.truncated);
}

/// A parent cycle cannot come from the issuer, but a store edited by hand could hold one.
/// Neither the descendant query nor the ancestor walk may loop on it.
#[test]
fn a_parent_cycle_terminates() {
    let both = Both::new();
    let exp = t0() + Duration::hours(1);
    for (_, s) in both.each() {
        // x -> y -> z -> x, plus a child w of z outside the cycle.
        s.register(&id("x"), Some(&id("z")), exp).unwrap();
        s.register(&id("y"), Some(&id("x")), exp).unwrap();
        s.register(&id("z"), Some(&id("y")), exp).unwrap();
        s.register(&id("w"), Some(&id("z")), exp).unwrap();
    }
    let t = both.subtree("x", 1000).unwrap();
    assert_eq!(ids(&t.nodes), ["x", "y", "z", "w"]);
    assert_eq!(
        ids(&t.ancestors),
        ["z", "y"],
        "stops before coming back to x"
    );
    assert_eq!(t.root(), &id("y"));
    assert_eq!(t.would_revoke, 4);
    for (name, s) in both.each() {
        assert_eq!(s.revoke(&id("x"), "x", t0()).unwrap(), 4, "{name}");
    }

    // A lease that is its own parent.
    let both = Both::new();
    for (_, s) in both.each() {
        s.register(&id("self"), Some(&id("self")), exp).unwrap();
    }
    let t = both.subtree("self", 1000).unwrap();
    assert_eq!(ids(&t.nodes), ["self"]);
    assert!(t.ancestors.is_empty());
    assert_eq!(t.root(), &id("self"));
}

/// The SQLite subtree reads the parent column directly, so a cycle written with plain SQL
/// (bypassing `register`) is covered too.
#[test]
fn sqlite_subtree_survives_a_cycle_written_with_sql() {
    let store = SqliteLeaseStore::open_in_memory().unwrap();
    store
        .with_connection(|c| {
            c.execute_batch(
                "INSERT INTO leases (id, parent, expires_at) VALUES \
                 ('p', 'q', '2026-10-23T00:00:00Z'), ('q', 'p', '2026-10-23T00:00:00Z');",
            )?;
            Ok(())
        })
        .unwrap();
    let t = store.subtree(&id("p"), 1000).unwrap().unwrap();
    assert_eq!(ids(&t.nodes), ["p", "q"]);
    assert_eq!(ids(&t.ancestors), ["q"]);
    assert_eq!(t.would_revoke, 2);
}

/// `issuance_records` finds the record that issued each lease (the one whose last lease it
/// is), only among the `root_token` and `exchange` records of the chain.
#[test]
fn issuance_records_pick_the_record_that_issued_each_lease() {
    let audit = SqliteAudit::open_in_memory().unwrap();
    let two = common::chain("user:mudit", ("l1", "l2"));
    let one = DelegationChain {
        hops: two.hops[..1].to_vec(),
        ..two.clone()
    };
    // A decision on the two-hop chain is not an issuance.
    audit
        .append(common::record_for(&two, 0, Decision::Allow))
        .unwrap();
    audit
        .append(common::record_for(&one, 1, Decision::Allow).with_kind(RecordKind::RootToken))
        .unwrap();
    audit
        .append(common::record_for(&two, 2, Decision::Allow).with_kind(RecordKind::Exchange))
        .unwrap();
    let got = audit
        .issuance_records("l1", &[&id("l1"), &id("l2"), &id("l3")])
        .unwrap();
    let by: Vec<_> = got
        .iter()
        .map(|e| {
            (
                e.record.leases.last().unwrap().0.as_str(),
                e.record.agents.last().unwrap().0.as_str(),
                e.seq,
            )
        })
        .collect();
    assert_eq!(by, [("l1", "agent:planner", 2), ("l2", "agent:coder", 3)]);
    assert!(audit
        .issuance_records("nope", &[&id("l1")])
        .unwrap()
        .is_empty());
}

// -- Revocation by selector (`LeaseStore::revoke_selected`, `POST /admin/leases/revoke`) --

fn ids_of(leases: &[LeaseId]) -> Vec<&str> {
    leases.iter().map(|l| l.0.as_str()).collect()
}

fn user(s: &str) -> LeaseSelector {
    LeaseSelector::Subject(s.into())
}

fn chain(s: &str) -> LeaseSelector {
    LeaseSelector::Chain(id(s))
}

/// [`tree`] for alice, every lease but `b` with its subject recorded (`b` stands for a lease
/// registered before subjects were kept); bob's chain `broot -> bchild`; and `legacy`, a root
/// with no subject.
fn two_users(store: &dyn LeaseStore) {
    tree(store);
    for l in ["root", "a", "a1", "a2", "a2x"] {
        store.record_subject(&id(l), "alice").unwrap();
    }
    let exp = t0() + Duration::hours(1);
    store.register(&id("broot"), None, exp).unwrap();
    store
        .register(&id("bchild"), Some(&id("broot")), exp)
        .unwrap();
    store.record_subject(&id("broot"), "bob").unwrap();
    store.record_subject(&id("bchild"), "bob").unwrap();
    store.register(&id("legacy"), None, exp).unwrap();
}

#[test]
fn subjects_are_write_once_and_only_for_known_leases() {
    for (name, store) in stores() {
        tree(store.as_ref());
        assert_eq!(store.subject(&id("a")).unwrap(), None, "{name}");
        store.record_subject(&id("a"), "alice").unwrap();
        store.record_subject(&id("a"), "alice").unwrap();
        assert_eq!(store.subject(&id("a")).unwrap().as_deref(), Some("alice"));
        assert!(
            matches!(
                store.record_subject(&id("a"), "mallory"),
                Err(AuditError::BindingConflict(_))
            ),
            "{name}"
        );
        assert_eq!(store.subject(&id("a")).unwrap().as_deref(), Some("alice"));
        assert!(matches!(
            store.record_subject(&id("ghost"), "alice"),
            Err(AuditError::UnknownLease(_))
        ));
    }
}

/// `subjects` answers in one call what `subject` answers per lease: leases with no recorded
/// subject (here `b`, standing for a lease from before subjects were kept, `legacy`, and an
/// unknown id) are absent.
#[test]
fn subjects_in_one_call_agree_with_subject_per_lease() {
    for (name, store) in stores() {
        two_users(store.as_ref());
        let all = [
            "root", "a", "a1", "a2", "a2x", "b", "broot", "bchild", "legacy", "ghost",
        ];
        let leases: Vec<LeaseId> = all.iter().map(|l| id(l)).collect();
        let refs: Vec<&LeaseId> = leases.iter().collect();
        let got = store.subjects(&refs).unwrap();
        for l in &leases {
            assert_eq!(
                got.get(l).cloned(),
                store.subject(l).unwrap(),
                "{name}: {}",
                l.0
            );
        }
        assert_eq!(got.len(), 7, "{name}");
        assert!(store.subjects(&[]).unwrap().is_empty(), "{name}");
    }
}

/// More leases than one `IN (...)` query takes are answered in chunks.
#[test]
fn subjects_of_a_long_list_are_read_in_chunks() {
    for (name, store) in stores() {
        let exp = t0() + Duration::hours(1);
        let leases: Vec<LeaseId> = (0..150).map(|i| id(&format!("l{i:03}"))).collect();
        for (i, l) in leases.iter().enumerate() {
            store.register(l, None, exp).unwrap();
            if i % 3 != 0 {
                store.record_subject(l, &format!("user{}", i % 5)).unwrap();
            }
        }
        let refs: Vec<&LeaseId> = leases.iter().collect();
        let got = store.subjects(&refs).unwrap();
        assert_eq!(got.len(), 100, "{name}");
        assert_eq!(got[&id("l001")], "user1", "{name}");
        assert!(!got.contains_key(&id("l147")), "{name}");
        assert_eq!(got[&id("l149")], "user4", "{name}");
    }
}

/// A user's leases are revoked with their descendants; another user's chain and a lease with
/// no recorded subject are not touched. The preview names exactly what the revocation then
/// changes.
#[test]
fn revoke_by_user_revokes_the_users_leases_with_the_cascade() {
    for (name, store) in stores() {
        two_users(store.as_ref());
        let now = t0() + Duration::minutes(1);
        let preview = store.preview_selected(&user("alice")).unwrap();
        assert_eq!(
            ids_of(&preview.matched),
            ["a", "a1", "a2", "a2x", "root"],
            "{name}"
        );
        // `b` has no subject, but it descends from `root`: the cascade takes it.
        assert_eq!(
            ids_of(&preview.revoked),
            ["a", "a1", "a2", "a2x", "root", "b"],
            "{name}"
        );
        let all = [
            "root", "a", "a1", "a2", "a2x", "b", "broot", "bchild", "legacy",
        ];
        assert!(
            all.iter().all(|l| store.is_active(&id(l), now).unwrap()),
            "{name}: the preview wrote nothing"
        );

        let out = store
            .revoke_selected(&user("alice"), "incident-42", now)
            .unwrap();
        assert_eq!(out, preview, "{name}");
        for l in ["root", "a", "a1", "a2", "a2x", "b"] {
            assert!(!store.is_active(&id(l), now).unwrap(), "{name}: {l}");
        }
        for l in ["broot", "bchild", "legacy"] {
            assert!(store.is_active(&id(l), now).unwrap(), "{name}: {l}");
        }
        // Nothing left to match: a second call is an empty answer, not an error.
        let again = store.revoke_selected(&user("alice"), "x", now).unwrap();
        assert!(
            again.matched.is_empty() && again.revoked.is_empty(),
            "{name}"
        );
        // A subject nobody has matches nothing.
        let none = store.revoke_selected(&user("nobody"), "x", now).unwrap();
        assert_eq!(none, Default::default(), "{name}");
        // Subjects are matched exactly, not as a prefix or case-insensitively.
        assert!(store
            .preview_selected(&user("bo"))
            .unwrap()
            .matched
            .is_empty());
        assert!(store
            .preview_selected(&user("BOB"))
            .unwrap()
            .matched
            .is_empty());
    }
}

/// Leases already revoked are neither matched nor counted again, and a lease reached both as
/// a match and through another match's cascade is listed once.
#[test]
fn revoke_by_user_skips_revoked_leases_and_lists_each_lease_once() {
    for (name, store) in stores() {
        two_users(store.as_ref());
        store.record_subject(&id("b"), "alice").unwrap();
        assert_eq!(store.revoke(&id("a"), "earlier", t0()).unwrap(), 4);
        let out = store.revoke_selected(&user("alice"), "now", t0()).unwrap();
        assert_eq!(ids_of(&out.matched), ["b", "root"], "{name}");
        assert_eq!(ids_of(&out.revoked), ["b", "root"], "{name}");
        let status = store.check_all(&[&id("a2x")], t0()).unwrap();
        assert_eq!(status.revoked, [id("a2x")], "{name}");
    }
}

/// An expired, unrevoked lease is matched: `POST /token/renew` could bring it back.
#[test]
fn expired_unrevoked_leases_are_matched() {
    for (name, store) in stores() {
        two_users(store.as_ref());
        let later = t0() + Duration::hours(2);
        assert!(!store.is_active(&id("broot"), later).unwrap());
        let out = store.revoke_selected(&user("bob"), "late", later).unwrap();
        assert_eq!(ids_of(&out.revoked), ["bchild", "broot"], "{name}");
        assert!(matches!(
            store.renew(&id("broot"), later + Duration::hours(1), later),
            Err(AuditError::LeaseRevoked(_))
        ));
    }
}

/// A chain id names the chain's first-hop lease: the whole tree under it goes, whether or not
/// subjects were recorded. A lease that has a parent is not a chain id, and an unknown id
/// matches nothing.
#[test]
fn revoke_by_chain_revokes_the_whole_chain_only() {
    for (name, store) in stores() {
        two_users(store.as_ref());
        assert_eq!(
            store.preview_selected(&chain("a")).unwrap(),
            Default::default(),
            "{name}: `a` has a parent"
        );
        assert_eq!(
            store.preview_selected(&chain("ghost")).unwrap(),
            Default::default(),
            "{name}"
        );
        let out = store
            .revoke_selected(&chain("root"), "chain", t0())
            .unwrap();
        assert_eq!(
            ids_of(&out.matched),
            ["a", "a1", "a2", "a2x", "b", "root"],
            "{name}"
        );
        assert_eq!(out.revoked, out.matched, "{name}");
        for l in ["broot", "bchild", "legacy"] {
            assert!(store.is_active(&id(l), t0()).unwrap(), "{name}: {l}");
        }
        // A lease without a subject is found by its chain.
        let legacy = store.revoke_selected(&chain("legacy"), "x", t0()).unwrap();
        assert_eq!(ids_of(&legacy.revoked), ["legacy"], "{name}");
    }
}

/// Part of a chain revoked earlier: the chain revocation takes the rest. A chain whose root
/// is revoked but which still has an unrevoked lease under it gets that lease.
#[test]
fn revoke_by_chain_after_a_partial_revocation() {
    for (name, store) in stores() {
        tree(store.as_ref());
        assert_eq!(store.revoke(&id("a2"), "earlier", t0()).unwrap(), 2);
        let out = store.revoke_selected(&chain("root"), "rest", t0()).unwrap();
        assert_eq!(ids_of(&out.revoked), ["a", "a1", "b", "root"], "{name}");
        store
            .register(&id("late"), Some(&id("b")), t0() + Duration::hours(1))
            .unwrap();
        let out = store.revoke_selected(&chain("root"), "late", t0()).unwrap();
        assert_eq!(ids_of(&out.revoked), ["late"], "{name}");
    }
}

/// A file store opened by an older server has no `lease_subjects` table: it is created at
/// open, and the leases registered before have no subject, so only a chain selector finds
/// them.
#[test]
fn sqlite_store_from_before_subjects_gains_the_table_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    {
        let s = SqliteLeaseStore::open(&path).unwrap();
        tree(&s);
        s.with_connection(|c| {
            c.execute_batch("DROP TABLE lease_subjects;")?;
            Ok(())
        })
        .unwrap();
    }
    let s = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(s.subject(&id("root")).unwrap(), None);
    assert!(s
        .preview_selected(&user("alice"))
        .unwrap()
        .matched
        .is_empty());
    s.register(&id("new"), None, t0() + Duration::hours(1))
        .unwrap();
    s.record_subject(&id("new"), "alice").unwrap();
    let out = s.revoke_selected(&user("alice"), "x", t0()).unwrap();
    assert_eq!(ids_of(&out.revoked), ["new"]);
    let out = s.revoke_selected(&chain("root"), "x", t0()).unwrap();
    assert_eq!(out.revoked.len(), 6);
}

/// A selector revocation persists, and the subjects survive a reopen.
#[test]
fn sqlite_selector_revocation_persists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    {
        let s = SqliteLeaseStore::open(&path).unwrap();
        two_users(&s);
    }
    let s = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(s.subject(&id("broot")).unwrap().as_deref(), Some("bob"));
    s.revoke_selected(&user("bob"), "persist", t0()).unwrap();
    drop(s);
    let s = SqliteLeaseStore::open(&path).unwrap();
    let row = s.get(&id("bchild")).unwrap().unwrap();
    assert_eq!(row.revoked_at, Some(t0()));
    assert_eq!(row.revoke_reason.as_deref(), Some("persist"));
    assert!(s.is_active(&id("root"), t0()).unwrap());
}

fn session(s: &str) -> LeaseSelector {
    LeaseSelector::Session(s.into())
}

/// A session digest stand-in (the stores take any string; the proxy passes SHA-256 hex).
const S1: &str = "5e55101100000000000000000000000000000000000000000000000000000001";
const S2: &str = "5e55101100000000000000000000000000000000000000000000000000000002";

/// A session binds once per `(session, server)`: the first chain is kept, a second bind (same
/// or another chain) changes nothing, an unknown chain is refused, and a session opened with
/// two upstreams resolves to both.
#[test]
fn session_bindings_are_write_once_per_server() {
    for (name, s) in stores() {
        two_users(s.as_ref());
        assert_eq!(s.sessions(S1).unwrap(), Vec::new(), "{name}");
        assert!(
            s.record_session(S1, "github", &id("root"), t0()).unwrap(),
            "{name}"
        );
        assert!(
            !s.record_session(S1, "github", &id("root"), t0()).unwrap(),
            "{name}"
        );
        let later = t0() + Duration::minutes(1);
        assert!(
            !s.record_session(S1, "github", &id("broot"), later).unwrap(),
            "{name}"
        );
        assert_eq!(
            s.sessions(S1).unwrap(),
            vec![SessionBinding {
                server: "github".into(),
                chain_id: id("root"),
                bound_at: t0(),
            }],
            "{name}"
        );
        assert!(matches!(
            s.record_session(S2, "github", &id("nope"), t0()),
            Err(AuditError::UnknownLease(_))
        ));
        assert_eq!(s.sessions(S2).unwrap(), Vec::new(), "{name}");

        // The same session id from another upstream is another binding.
        assert!(
            s.record_session(S1, "fs", &id("broot"), later).unwrap(),
            "{name}"
        );
        let servers: Vec<(String, String)> = s
            .sessions(S1)
            .unwrap()
            .into_iter()
            .map(|b| (b.server, b.chain_id.0))
            .collect();
        assert_eq!(
            servers,
            [
                ("fs".to_string(), "broot".to_string()),
                ("github".to_string(), "root".to_string())
            ],
            "{name}"
        );
    }
}

/// A session selector revokes the chain that opened the session, exactly as the chain id
/// would, and nothing else; an unknown session matches nothing; the preview agrees.
#[test]
fn revoke_by_session_revokes_the_chain_that_opened_it() {
    for (name, s) in stores() {
        two_users(s.as_ref());
        s.record_session(S1, "github", &id("root"), t0()).unwrap();
        assert!(
            s.preview_selected(&session(S2)).unwrap().matched.is_empty(),
            "{name}"
        );
        let preview = s.preview_selected(&session(S1)).unwrap();
        assert_eq!(
            preview,
            s.preview_selected(&chain("root")).unwrap(),
            "{name}"
        );
        assert_eq!(preview.revoked.len(), 6, "{name}");
        assert!(s.is_active(&id("a2x"), t0()).unwrap(), "{name}");

        let out = s.revoke_selected(&session(S1), "stolen", t0()).unwrap();
        assert_eq!(out, preview, "{name}");
        for l in ["root", "a", "a1", "a2", "a2x", "b"] {
            assert!(!s.is_active(&id(l), t0()).unwrap(), "{name} {l}");
        }
        for l in ["broot", "bchild", "legacy"] {
            assert!(s.is_active(&id(l), t0()).unwrap(), "{name} {l}");
        }
        let out = s.revoke_selected(&session(S1), "again", t0()).unwrap();
        assert!(out.revoked.is_empty(), "{name}");
        let out = s.revoke_selected(&session(S2), "x", t0()).unwrap();
        assert!(out.matched.is_empty(), "{name}");
    }
}

/// A session bound to two chains (through two upstreams) revokes both; one bound to a lease
/// with a parent matches nothing, as a chain selector would.
#[test]
fn a_session_bound_to_two_chains_revokes_both() {
    for (name, s) in stores() {
        two_users(s.as_ref());
        s.record_session(S1, "github", &id("root"), t0()).unwrap();
        s.record_session(S1, "fs", &id("broot"), t0()).unwrap();
        s.record_session(S2, "github", &id("a"), t0()).unwrap();
        assert!(
            s.preview_selected(&session(S2)).unwrap().matched.is_empty(),
            "{name}"
        );
        let out = s.revoke_selected(&session(S1), "x", t0()).unwrap();
        assert_eq!(out.revoked.len(), 8, "{name}");
        assert!(s.is_active(&id("legacy"), t0()).unwrap(), "{name}");
    }
}

/// A file store written before `lease_sessions` existed gains the table at open: nothing
/// matches a session until one is recorded, and then it does; bindings survive a reopen.
#[test]
fn sqlite_store_from_before_sessions_gains_the_table_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leases.db");
    {
        let s = SqliteLeaseStore::open(&path).unwrap();
        two_users(&s);
        s.with_connection(|c| {
            c.execute_batch("DROP TABLE lease_sessions;")?;
            Ok(())
        })
        .unwrap();
    }
    {
        let s = SqliteLeaseStore::open(&path).unwrap();
        assert_eq!(s.sessions(S1).unwrap(), Vec::new());
        assert!(s.preview_selected(&session(S1)).unwrap().matched.is_empty());
        assert!(s.record_session(S1, "github", &id("broot"), t0()).unwrap());
    }
    let s = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(s.sessions(S1).unwrap()[0].chain_id, id("broot"));
    assert!(!s.record_session(S1, "github", &id("root"), t0()).unwrap());
    let out = s.revoke_selected(&session(S1), "x", t0()).unwrap();
    assert_eq!(ids_of(&out.revoked), ["bchild", "broot"]);
}

/// The default `[leases] session_retention_seconds`: a day.
const GRACE: Duration = Duration::hours(24);

/// Run `prune_sessions` passes of `batch` until one wraps; the total pruned.
fn prune_all(s: &dyn LeaseStore, now: time::OffsetDateTime, batch: usize) -> u64 {
    let mut pruned = 0;
    for _ in 0..10_000 {
        let pass = s.prune_sessions(now, GRACE, batch).unwrap();
        assert!(pass.examined <= batch as u64 && pass.pruned <= pass.examined);
        pruned += pass.pruned;
        if pass.wrapped {
            return pruned;
        }
    }
    panic!("no pass wrapped");
}

/// Retention keeps a binding while its chain may be used: a live chain's binding stays; a
/// revoked chain's goes at the next pass; an expired chain's goes only once it has been
/// expired for longer than the grace period, measured from the root lease's expiry as
/// renewals leave it. A pruned session resolves to no chain, exactly like a session that was
/// never recorded.
#[test]
fn session_bindings_are_pruned_only_once_their_chain_is_over() {
    for (name, s) in stores() {
        two_users(s.as_ref());
        // root: live. broot: revoked. legacy: live now, expires at t0 + 1 h.
        s.record_session(S1, "github", &id("root"), t0()).unwrap();
        s.record_session(S2, "github", &id("broot"), t0()).unwrap();
        s.record_session(S2, "fs", &id("legacy"), t0()).unwrap();
        s.revoke(&id("broot"), "stolen", t0()).unwrap();

        assert_eq!(prune_all(s.as_ref(), t0(), 100), 1, "{name}");
        assert_eq!(s.sessions(S1).unwrap().len(), 1, "{name}: live chain kept");
        let left: Vec<String> = s
            .sessions(S2)
            .unwrap()
            .into_iter()
            .map(|b| b.server)
            .collect();
        assert_eq!(left, ["fs"], "{name}: revoked chain pruned, live one kept");

        // Expired, but not for longer than the grace period: kept.
        let expired = t0() + Duration::hours(1);
        let at_grace = expired + GRACE;
        assert_eq!(prune_all(s.as_ref(), at_grace, 100), 0, "{name}");
        assert_eq!(s.sessions(S2).unwrap().len(), 1, "{name}");
        // Renewed in time: the grace period runs from the new expiry.
        let renewed = expired + Duration::hours(2);
        s.renew(&id("legacy"), renewed, at_grace).unwrap();
        s.renew(&id("root"), renewed, at_grace).unwrap();
        let after = at_grace + Duration::minutes(30);
        assert_eq!(prune_all(s.as_ref(), after, 100), 0, "{name}: renewed");
        // Expired for longer than the grace period: pruned, unless renewed even then.
        let past = renewed + GRACE + Duration::seconds(1);
        s.renew(&id("root"), past + Duration::hours(1), past)
            .unwrap();
        assert_eq!(prune_all(s.as_ref(), past, 100), 1, "{name}");
        assert_eq!(s.sessions(S2).unwrap(), Vec::new(), "{name}");
        assert_eq!(
            s.sessions(S1).unwrap().len(),
            1,
            "{name}: renewed root kept"
        );

        // A pruned session matches nothing, as an unknown one does.
        assert_eq!(
            s.preview_selected(&session(S2)).unwrap(),
            Default::default(),
            "{name}"
        );
        assert_eq!(
            s.revoke_selected(&session(S2), "x", past).unwrap(),
            Default::default(),
            "{name}"
        );
    }
}

/// One pass looks at no more than its batch of bindings and continues where the previous one
/// stopped, so a large table is pruned in bounded steps and every binding is reached.
#[test]
fn session_prune_passes_are_bounded_and_resume() {
    for (name, s) in stores() {
        two_users(s.as_ref());
        s.revoke(&id("broot"), "done", t0()).unwrap();
        // 25 bindings of the revoked chain between 25 of the live one.
        for n in 0..50 {
            let chain = if n % 2 == 0 { "root" } else { "broot" };
            s.record_session(&format!("{n:064}"), "github", &id(chain), t0())
                .unwrap();
        }
        let mut passes = Vec::new();
        loop {
            let pass = s.prune_sessions(t0(), GRACE, 7).unwrap();
            assert!(pass.examined <= 7, "{name}: {pass:?}");
            passes.push(pass);
            if pass.wrapped {
                break;
            }
        }
        let examined: u64 = passes.iter().map(|p| p.examined).sum();
        let pruned: u64 = passes.iter().map(|p| p.pruned).sum();
        assert_eq!((examined, pruned), (50, 25), "{name}: {passes:?}");
        assert_eq!(passes.len(), 8, "{name}: 7 full passes, then 1 binding");
        for n in 0..50 {
            let left = s.sessions(&format!("{n:064}")).unwrap().len();
            assert_eq!(left, usize::from(n % 2 == 0), "{name} {n}");
        }
        // The next sweep starts from the first binding again and finds nothing more.
        assert_eq!(prune_all(s.as_ref(), t0(), 7), 0, "{name}");
    }
}

/// A binding whose chain's root lease the store does not know (a store that lost the row) is
/// pruned: an unknown lease is inactive.
#[test]
fn a_session_of_an_unknown_chain_is_pruned() {
    let s = SqliteLeaseStore::open_in_memory().unwrap();
    two_users(&s);
    s.record_session(S1, "github", &id("legacy"), t0()).unwrap();
    s.with_connection(|c| {
        c.execute("DELETE FROM leases WHERE id = 'legacy'", [])?;
        Ok(())
    })
    .unwrap();
    assert_eq!(prune_all(&s, t0(), 10), 1);
    assert_eq!(s.sessions(S1).unwrap(), Vec::new());
}

/// The default `[leases] retention_seconds`: a week.
const RETAIN: Duration = Duration::weeks(1);

/// Run `prune_leases` passes of `batch` until one wraps; the total pruned.
fn prune_leases_all(s: &dyn LeaseStore, now: time::OffsetDateTime, batch: usize) -> u64 {
    let mut pruned = 0;
    for _ in 0..10_000 {
        let pass = s.prune_leases(now, RETAIN, batch).unwrap();
        assert!(pass.examined <= batch as u64, "{pass:?}");
        pruned += pass.pruned;
        if pass.wrapped {
            return pruned;
        }
    }
    panic!("no pass wrapped");
}

/// Which of `leases` the store still knows.
fn known(s: &dyn LeaseStore, leases: &[&str]) -> Vec<String> {
    let ids: Vec<LeaseId> = leases.iter().map(|l| id(l)).collect();
    let refs: Vec<&LeaseId> = ids.iter().collect();
    let status = s.check_all(&refs, t0()).unwrap();
    leases
        .iter()
        .filter(|l| !status.unknown.contains(&id(l)))
        .map(|l| l.to_string())
        .collect()
}

const ALICE: &[&str] = &["root", "a", "a1", "a2", "a2x", "b"];

/// Retention of the lease registry, chain by chain (a chain being a root lease and everything
/// delegated from it): a live chain is kept; a revoked chain is kept for the retention after
/// its revocation and pruned past it; an expired chain likewise from its expiry, and a renewal
/// inside the grace period moves the start of the grace period; a chain with one descendant
/// still live is kept whole, root included. A pruned chain goes with its subjects, bindings,
/// session bindings and hop limits, and reads as unknown everywhere.
#[test]
fn lease_trees_are_pruned_only_once_every_lease_ended() {
    for (name, s) in stores() {
        let s = s.as_ref();
        two_users(s);
        s.bind(&id("bchild"), "digest").unwrap();
        s.record_session(S1, "github", &id("broot"), t0()).unwrap();
        s.record_hop_limits(&id("bchild"), &[]).unwrap();
        assert_eq!(s.hop_limits(&id("bchild")).unwrap(), Some(vec![]), "{name}");
        let exp = t0() + Duration::hours(1);

        // Everything live: nothing to prune.
        assert_eq!(prune_leases_all(s, t0(), 100), 0, "{name}");

        // bob's chain revoked at t0: kept for the retention, pruned past it.
        s.revoke(&id("broot"), "done", t0()).unwrap();
        // alice's `a` subtree revoked, `b` renewed far ahead; the root will expire at `exp`.
        s.revoke(&id("a"), "done", t0()).unwrap();
        s.renew(&id("b"), exp + Duration::weeks(10), t0()).unwrap();
        assert_eq!(prune_leases_all(s, t0() + RETAIN, 100), 0, "{name}");
        assert_eq!(known(s, &["broot", "bchild"]).len(), 2, "{name}");

        let past = exp + RETAIN + Duration::seconds(1);
        // legacy expired at `exp`: renewed inside its grace period, so kept.
        s.renew(&id("legacy"), exp + Duration::hours(2), exp + RETAIN)
            .unwrap();
        assert_eq!(prune_leases_all(s, past, 100), 2, "{name}: bob's chain");
        assert!(known(s, &["broot", "bchild"]).is_empty(), "{name}");
        assert_eq!(known(s, &["legacy"]), ["legacy"], "{name}: renewed in time");
        // alice's root expired past the grace period and `a` is revoked, but `b` is live:
        // the whole tree stays, so `b` never loses its parent.
        assert_eq!(known(s, ALICE), ALICE, "{name}: one live descendant");
        assert_eq!(s.subject(&id("root")).unwrap().as_deref(), Some("alice"));

        // bob's chain went with everything keyed by it.
        assert_eq!(s.subject(&id("broot")).unwrap(), None, "{name}");
        assert_eq!(s.binding(&id("bchild")).unwrap(), None, "{name}");
        assert_eq!(s.sessions(S1).unwrap(), Vec::new(), "{name}");
        assert_eq!(s.hop_limits(&id("bchild")).unwrap(), None, "{name}");
        let status = s.check_all(&[&id("broot"), &id("bchild")], past).unwrap();
        assert_eq!(status.unknown, [id("broot"), id("bchild")], "{name}");
        assert!(!status.active);
        assert!(matches!(
            s.renew(&id("broot"), past + Duration::hours(1), past),
            Err(AuditError::UnknownLease(_))
        ));
        assert_eq!(
            s.preview_selected(&LeaseSelector::Subject("bob".into()))
                .unwrap(),
            Default::default(),
            "{name}: revoke-by-user no longer lists it"
        );
        assert_eq!(
            s.preview_selected(&chain("broot")).unwrap(),
            Default::default(),
            "{name}"
        );

        // Once `b` has been expired for longer than the grace period too, alice's tree goes
        // whole; legacy, expired at `exp + 2 h`, goes once its own grace period is over.
        let later = exp + Duration::weeks(10) + RETAIN + Duration::seconds(1);
        assert_eq!(prune_leases_all(s, later, 100), 7, "{name}");
        assert!(known(s, ALICE).is_empty(), "{name}");
        assert!(known(s, &["legacy"]).is_empty(), "{name}");
        assert_eq!(
            s.preview_selected(&LeaseSelector::Subject("alice".into()))
                .unwrap(),
            Default::default(),
            "{name}"
        );
        assert_eq!(prune_leases_all(s, later, 100), 0, "{name}");
    }
}

/// The grace period of a revoked lease runs from its revocation, not from its expiry: an
/// expired lease that a user-wide revocation reaches later was renewable until then.
#[test]
fn a_late_revocation_restarts_the_grace_period() {
    for (name, s) in stores() {
        let s = s.as_ref();
        let exp = t0() + Duration::hours(1);
        s.register(&id("r"), None, exp).unwrap();
        s.record_subject(&id("r"), "carol").unwrap();
        let revoked_at = exp + RETAIN - Duration::hours(1);
        let out = s
            .revoke_selected(&LeaseSelector::Subject("carol".into()), "x", revoked_at)
            .unwrap();
        assert_eq!(ids_of(&out.revoked), ["r"], "{name}");
        assert_eq!(
            prune_leases_all(s, exp + RETAIN + Duration::seconds(1), 10),
            0,
            "{name}"
        );
        assert_eq!(
            prune_leases_all(s, revoked_at + RETAIN + Duration::seconds(1), 10),
            1,
            "{name}"
        );
    }
}

/// One pass looks at no more than its batch of leases and continues where the previous one
/// stopped; every ended chain is reached, children with their root, and the next sweep finds
/// nothing more.
#[test]
fn lease_prune_passes_are_bounded_and_resume() {
    for (name, s) in stores() {
        let s = s.as_ref();
        let exp = t0() + Duration::hours(1);
        for n in 0..30 {
            let root = format!("r{n:02}");
            s.register(&id(&root), None, exp).unwrap();
            s.register(&id(&format!("{root}c")), Some(&id(&root)), exp)
                .unwrap();
            if n % 2 == 1 {
                s.revoke(&id(&root), "done", t0()).unwrap();
            }
        }
        let now = t0() + RETAIN + Duration::seconds(1);
        let mut passes = Vec::new();
        loop {
            let pass = s.prune_leases(now, RETAIN, 7).unwrap();
            assert!(pass.examined <= 7, "{name}: {pass:?}");
            passes.push(pass);
            if pass.wrapped {
                break;
            }
        }
        let pruned: u64 = passes.iter().map(|p| p.pruned).sum();
        assert_eq!(pruned, 30, "{name}: 15 revoked chains of 2: {passes:?}");
        assert!(passes.len() >= 5, "{name}: {passes:?}");
        for n in 0..30 {
            let root = format!("r{n:02}");
            let child = format!("{root}c");
            let left = known(s, &[&root, &child]).len();
            assert_eq!(left, if n % 2 == 0 { 2 } else { 0 }, "{name} {n}");
        }
        assert_eq!(prune_leases_all(s, now, 7), 0, "{name}");
    }
}

/// A lease whose parent row is gone (a store that lost rows) is the top of its own tree: it
/// is pruned once it and its descendants ended, and kept while any is live. Its token was
/// refused all along, since the chain names the missing parent.
#[test]
fn a_lease_whose_parent_is_gone_is_pruned_as_its_own_tree() {
    let s = SqliteLeaseStore::open_in_memory().unwrap();
    tree(&s);
    s.with_connection(|c| {
        c.execute("DELETE FROM leases WHERE id = 'a'", [])?;
        Ok(())
    })
    .unwrap();
    let past = t0() + Duration::hours(1) + RETAIN + Duration::seconds(1);
    s.renew(&id("a2x"), past + Duration::hours(1), t0())
        .unwrap();
    // root and b form one tree, a1 one, a2 > a2x another (a2x live).
    assert_eq!(prune_leases_all(&s, past, 100), 3);
    assert_eq!(known(&s, &["root", "b", "a1", "a2", "a2x"]), ["a2", "a2x"]);
    assert_eq!(
        prune_leases_all(
            &s,
            past + Duration::hours(1) + RETAIN + Duration::seconds(1),
            100
        ),
        2
    );
}
