//! Lease registry: register, revoke with cascade, expiry, unknown-fails-closed, persistence.

mod common;

use common::t0;
use onbehalf_audit::{AuditError, LeaseStatus, LeaseStore, MemoryLeaseStore, SqliteLeaseStore};
use onbehalf_core::LeaseId;
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
    use onbehalf_audit::Durability;
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
