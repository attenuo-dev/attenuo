//! The server's liveness marker: one `audit_meta` row, `dpop_max_iat`, for
//! [`SqliteLeaseStore`].
//!
//! A running server keeps the row a little ahead of its clock: it is the largest DPoP proof
//! `iat` the server may accept before it moves the row further. The next server on the same
//! file reads the row before it writes its own, and so knows which proofs the previous process
//! could have accepted. The DPoP checker of `attenuo-server` refuses those (its module docs,
//! "Restart fence").
//!
//! The row lives in `audit_meta`, the key and value table every file has had since schema
//! version 1, so it needs no migration and a build from before it opens the file as before (it
//! ignores the row). The value is a decimal Unix second and only ever grows: a write of an
//! earlier second keeps the stored one. Every write commits with `synchronous=FULL`, so a
//! marker the server acts on survives a power failure.

use rusqlite::{params, OptionalExtension};

use super::connection::{relaxed_sync_of, with_full_sync};
use super::leases::SqliteLeaseStore;
use crate::error::AuditError;

/// The `audit_meta` key of the marker.
const KEY: &str = "dpop_max_iat";

/// Store `?2` under key `?1` unless the stored value is the same or later.
const EXTEND: &str = "INSERT INTO audit_meta (key, value) VALUES (?1, ?2) \
    ON CONFLICT (key) DO UPDATE SET value = excluded.value \
    WHERE CAST(audit_meta.value AS INTEGER) < CAST(excluded.value AS INTEGER)";

impl SqliteLeaseStore {
    /// The stored `dpop_max_iat` second, or `None` when no server has written one (a new
    /// file, a file written by a build from before the marker, or an in-memory store).
    ///
    /// # Errors
    ///
    /// [`AuditError::Sqlite`] when the row cannot be read, and [`AuditError::Storage`] when it
    /// is not a decimal integer (the file was changed outside attenuo).
    pub fn dpop_max_iat(&self) -> Result<Option<i64>, AuditError> {
        let conn = self.conn.lock()?;
        read(&conn)
    }

    /// Move `dpop_max_iat` to `until`, or keep the stored value when it is later, and
    /// return the value now stored. One small `IMMEDIATE` transaction under the file's write
    /// gate, committed with `synchronous=FULL`: when this returns `Ok`, the returned value is
    /// on disk.
    ///
    /// # Errors
    ///
    /// As [`dpop_max_iat`](Self::dpop_max_iat), and [`AuditError::Sqlite`] when the
    /// write or the commit fails (nothing is changed then).
    pub fn extend_dpop_max_iat(&self, until: i64) -> Result<i64, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let relaxed = relaxed_sync_of(&conn)?;
        with_full_sync(&mut conn, relaxed, |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(EXTEND, params![KEY, until.to_string()])?;
            let stored = read(&tx)?.unwrap_or(until);
            tx.commit()?;
            Ok(stored)
        })?
    }
}

fn read(conn: &rusqlite::Connection) -> Result<Option<i64>, AuditError> {
    let value: Option<String> = conn
        .query_row("SELECT value FROM audit_meta WHERE key = ?1", [KEY], |r| {
            r.get(0)
        })
        .optional()?;
    value
        .map(|v| {
            v.parse::<i64>().map_err(|_| {
                AuditError::Storage(format!(
                    "audit_meta `{KEY}` is `{v}`, not a Unix second; the file was changed \
                     outside attenuo"
                ))
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No row on a new file; a write stores the value; an earlier value never lowers it; the
    /// next store on the same file (the next server) reads it.
    #[test]
    fn marker_only_grows_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.sqlite");
        let store = SqliteLeaseStore::open(&path).unwrap();
        assert_eq!(store.dpop_max_iat().unwrap(), None);
        assert_eq!(store.extend_dpop_max_iat(1_000).unwrap(), 1_000);
        assert_eq!(store.extend_dpop_max_iat(1_010).unwrap(), 1_010);
        assert_eq!(store.extend_dpop_max_iat(990).unwrap(), 1_010);
        assert_eq!(store.dpop_max_iat().unwrap(), Some(1_010));
        drop(store);
        let next = SqliteLeaseStore::open(&path).unwrap();
        assert_eq!(next.dpop_max_iat().unwrap(), Some(1_010));
    }

    #[test]
    fn a_value_that_is_not_a_number_is_refused() {
        let store = SqliteLeaseStore::open_in_memory().unwrap();
        store
            .with_connection(|c| {
                Ok(c.execute(
                    "INSERT INTO audit_meta (key, value) VALUES ('dpop_max_iat', 'soon')",
                    [],
                )?)
            })
            .unwrap();
        assert!(matches!(store.dpop_max_iat(), Err(AuditError::Storage(_))));
    }
}
