//! Lease registry: register, revoke with cascade, expiry, unknown-fails-closed, persistence.

mod common;

use attenuo_audit::{
    AuditError, AuditSink, LeaseNode, LeaseStatus, LeaseStore, LeaseSubtree, MemoryLeaseStore,
    SqliteAudit, SqliteLeaseStore,
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
