//! The `used_credentials` table: [`ReplayStore`] for [`SqliteLeaseStore`] (schema version 3).

use rusqlite::{params, TransactionBehavior};
use sha2::{Digest, Sha256};

use super::leases::SqliteLeaseStore;
use super::usize_to_i64;
use crate::error::AuditError;
use crate::replay::{has_duplicate, prune_batch, ReplayOutcome, ReplayStore};

/// The table and its expiry index, created by migration 3.
pub(super) const REPLAY_SCHEMA: &str = "CREATE TABLE used_credentials (
    key        BLOB    PRIMARY KEY,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX used_credentials_expiry_idx ON used_credentials(expires_at);";

/// Insert the marker, or overwrite an expired one; a live marker is left alone and the
/// statement changes no row, which is the refusal.
const USE: &str = "INSERT INTO used_credentials (key, expires_at) VALUES (?1, ?2) \
    ON CONFLICT (key) DO UPDATE SET expires_at = excluded.expires_at \
    WHERE used_credentials.expires_at <= ?3";

/// Delete up to `?2` markers that expired at or before `?1`, oldest first, through the index.
const PRUNE: &str = "DELETE FROM used_credentials WHERE key IN \
    (SELECT key FROM used_credentials WHERE expires_at <= ?1 ORDER BY expires_at LIMIT ?2)";

/// The stored form of a key: its SHA-256.
fn digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

impl ReplayStore for SqliteLeaseStore {
    /// One `BEGIN IMMEDIATE` transaction under the file's write gate: each key's `INSERT` (or
    /// overwrite of an expired marker) is the decision, a bounded delete of expired markers
    /// follows, then a count against `capacity`. A replay or a full table rolls everything
    /// back. The commit runs at the store's [`Durability`](super::Durability); a credential is
    /// acted on (a token registered, an approval decided) only in a later commit to the same
    /// file, which a crash or power loss cannot keep while losing this one.
    fn use_all_once(
        &self,
        keys: &[(&str, i64)],
        now: i64,
        capacity: usize,
    ) -> Result<ReplayOutcome, AuditError> {
        if has_duplicate(keys) {
            return Ok(ReplayOutcome::Replayed);
        }
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut insert = tx.prepare_cached(USE)?;
            for (key, expires_at) in keys {
                if insert.execute(params![digest(key).as_slice(), expires_at, now])? == 0 {
                    // Dropping `tx` rolls back the keys inserted before this one.
                    return Ok(ReplayOutcome::Replayed);
                }
            }
            tx.prepare_cached(PRUNE)?
                .execute(params![now, usize_to_i64(prune_batch(keys.len()))])?;
            let stored: i64 =
                tx.query_row("SELECT COUNT(*) FROM used_credentials", [], |r| r.get(0))?;
            if stored > usize_to_i64(capacity.max(1)) {
                return Ok(ReplayOutcome::Full);
            }
        }
        tx.commit()?;
        Ok(ReplayOutcome::Recorded)
    }

    fn replay_markers(&self) -> Result<usize, AuditError> {
        let conn = self.conn.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM used_credentials", [], |r| r.get(0))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::MemoryLeaseStore;

    fn stores() -> Vec<(&'static str, Box<dyn ReplayStore>)> {
        vec![
            ("sqlite", Box::new(SqliteLeaseStore::open_in_memory().unwrap())),
            ("memory", Box::new(MemoryLeaseStore::new())),
        ]
    }

    #[test]
    fn second_use_is_refused_until_expiry() {
        for (name, s) in stores() {
            assert_eq!(
                s.use_all_once(&[("a", 1_100)], 1_000, 10).unwrap(),
                ReplayOutcome::Recorded,
                "{name}"
            );
            assert_eq!(
                s.use_all_once(&[("a", 1_100)], 1_099, 10).unwrap(),
                ReplayOutcome::Replayed,
                "{name}"
            );
            assert_eq!(
                s.use_all_once(&[("b", 1_100)], 1_000, 10).unwrap(),
                ReplayOutcome::Recorded,
                "{name}"
            );
            // Expired: the credential cannot be accepted any more, so the key is free.
            assert_eq!(
                s.use_all_once(&[("a", 1_200)], 1_100, 10).unwrap(),
                ReplayOutcome::Recorded,
                "{name}"
            );
            assert_eq!(
                s.use_all_once(&[("a", 1_200)], 1_150, 10).unwrap(),
                ReplayOutcome::Replayed,
                "{name}: the overwritten marker has the new expiry"
            );
        }
    }

    #[test]
    fn several_keys_are_recorded_together_or_not_at_all() {
        for (name, s) in stores() {
            s.use_all_once(&[("used", 1_100)], 1_000, 3).unwrap();
            assert_eq!(
                s.use_all_once(&[("fresh", 1_100), ("used", 1_100)], 1_000, 3)
                    .unwrap(),
                ReplayOutcome::Replayed,
                "{name}"
            );
            assert_eq!(s.replay_markers().unwrap(), 1, "{name}: `fresh` rolled back");
            assert_eq!(
                s.use_all_once(&[("dup", 1_100), ("dup", 1_100)], 1_000, 3)
                    .unwrap(),
                ReplayOutcome::Replayed,
                "{name}: the same key twice"
            );
            s.use_all_once(&[("b", 1_100)], 1_000, 3).unwrap();
            assert_eq!(
                s.use_all_once(&[("x", 1_100), ("y", 1_100)], 1_000, 3)
                    .unwrap(),
                ReplayOutcome::Full,
                "{name}"
            );
            assert_eq!(s.replay_markers().unwrap(), 2, "{name}");
            s.use_all_once(&[("x", 1_100)], 1_000, 3).unwrap();
            assert_eq!(s.replay_markers().unwrap(), 3, "{name}");
            // `fresh` was never recorded.
            assert_eq!(
                s.use_all_once(&[("fresh", 1_100)], 1_000, 3).unwrap(),
                ReplayOutcome::Full,
                "{name}"
            );
        }
    }

    #[test]
    fn a_full_store_drops_expired_markers_then_fails_closed() {
        for (name, s) in stores() {
            s.use_all_once(&[("a", 1_010)], 1_000, 2).unwrap();
            s.use_all_once(&[("b", 1_100)], 1_000, 2).unwrap();
            assert_eq!(
                s.use_all_once(&[("c", 1_100)], 1_000, 2).unwrap(),
                ReplayOutcome::Full,
                "{name}"
            );
            // `a` expires; its slot is reused.
            assert_eq!(
                s.use_all_once(&[("c", 1_100)], 1_050, 2).unwrap(),
                ReplayOutcome::Recorded,
                "{name}"
            );
            assert_eq!(s.replay_markers().unwrap(), 2, "{name}");
            assert_eq!(
                s.use_all_once(&[("b", 1_100)], 1_050, 2).unwrap(),
                ReplayOutcome::Replayed,
                "{name}"
            );
        }
    }

    /// Expired markers are deleted a bounded batch per call, oldest first, and live ones are
    /// never deleted.
    #[test]
    fn expired_markers_are_pruned_a_batch_per_call() {
        let s = SqliteLeaseStore::open_in_memory().unwrap();
        let n = crate::REPLAY_PRUNE_BATCH * 2 + 10;
        for i in 0..n {
            let key = format!("old-{i}");
            s.use_all_once(&[(&key, 1_000 + i as i64)], 900, n + 10)
                .unwrap();
        }
        s.use_all_once(&[("live", 10_000)], 900, n + 10).unwrap();
        assert_eq!(s.replay_markers().unwrap(), n + 1);
        // Every `old-*` has expired at 5 000: each call deletes one batch.
        s.use_all_once(&[("k1", 10_000)], 5_000, n + 10).unwrap();
        assert_eq!(
            s.replay_markers().unwrap(),
            n + 2 - crate::REPLAY_PRUNE_BATCH
        );
        s.use_all_once(&[("k2", 10_000)], 5_000, n + 10).unwrap();
        s.use_all_once(&[("k3", 10_000)], 5_000, n + 10).unwrap();
        // All expired ones are gone; `live`, `k1`..`k3` remain.
        assert_eq!(s.replay_markers().unwrap(), 4);
        for k in ["live", "k1", "k2", "k3"] {
            assert_eq!(
                s.use_all_once(&[(k, 10_000)], 5_000, n + 10).unwrap(),
                ReplayOutcome::Replayed
            );
        }
    }

    /// A store at capacity with more expired markers than one batch: the batch makes room,
    /// so a call is refused only when the markers left are live.
    #[test]
    fn a_full_table_of_expired_markers_takes_new_ones() {
        let s = SqliteLeaseStore::open_in_memory().unwrap();
        let cap = crate::REPLAY_PRUNE_BATCH * 3;
        for i in 0..cap {
            let key = format!("old-{i}");
            s.use_all_once(&[(&key, 1_000)], 900, cap).unwrap();
        }
        assert_eq!(
            s.use_all_once(&[("new", 2_000)], 900, cap).unwrap(),
            ReplayOutcome::Full
        );
        for i in 0..cap {
            let key = format!("new-{i}");
            assert_eq!(
                s.use_all_once(&[(&key, 2_000)], 1_000, cap).unwrap(),
                ReplayOutcome::Recorded,
                "{key}"
            );
        }
        assert_eq!(s.replay_markers().unwrap(), cap);
        assert_eq!(
            s.use_all_once(&[("one-more", 2_000)], 1_000, cap).unwrap(),
            ReplayOutcome::Full
        );
    }

    /// The table holds digests, never the key text.
    #[test]
    fn keys_are_stored_as_digests() {
        let s = SqliteLeaseStore::open_in_memory().unwrap();
        s.use_all_once(&[("https://idp.example\njti-1", 1_100)], 1_000, 10)
            .unwrap();
        let stored: Vec<u8> = s
            .with_connection(|c| {
                Ok(c.query_row("SELECT key FROM used_credentials", [], |r| r.get(0))?)
            })
            .unwrap();
        assert_eq!(stored, digest("https://idp.example\njti-1").to_vec());
    }

    /// Two threads redeeming one key at once, on two stores sharing one file (as two requests
    /// share one store, but without the store's own lock in the way): exactly one wins.
    #[test]
    fn concurrent_uses_of_one_key_record_it_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.sqlite");
        let stores: Vec<Arc<SqliteLeaseStore>> = (0..4)
            .map(|_| Arc::new(SqliteLeaseStore::open(&path).unwrap()))
            .collect();
        for round in 0..20 {
            let key = format!("k{round}");
            let barrier = Arc::new(Barrier::new(stores.len()));
            let handles: Vec<_> = stores
                .iter()
                .map(|s| {
                    let (s, b, key) = (Arc::clone(s), Arc::clone(&barrier), key.clone());
                    std::thread::spawn(move || {
                        b.wait();
                        s.use_all_once(&[(&key, 2_000)], 1_000, 1_000).unwrap()
                    })
                })
                .collect();
            let outcomes: Vec<ReplayOutcome> =
                handles.into_iter().map(|h| h.join().unwrap()).collect();
            let won = outcomes
                .iter()
                .filter(|o| **o == ReplayOutcome::Recorded)
                .count();
            assert_eq!(won, 1, "round {round}: {outcomes:?}");
        }
    }

    /// A store fault records nothing and is an error, not a pass.
    #[test]
    fn a_store_fault_is_an_error() {
        let s = SqliteLeaseStore::open_in_memory().unwrap();
        s.with_connection(|c| Ok(c.execute_batch("DROP TABLE used_credentials")?))
            .unwrap();
        assert!(s.use_all_once(&[("a", 1_100)], 1_000, 10).is_err());
    }
}
