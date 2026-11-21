//! The notice outbox (`[approvals.notify]`, `[leases.notify]`): one row per notice one of the
//! server's notifiers is to deliver, kept in the lease store's database so that a restart
//! neither loses a notice still queued nor forgets an approval still waiting for its expiry.
//!
//! A notifier (in `attenuo-server`) writes a row right after the change it describes was
//! stored and recorded, delivers from its in-memory queue, and marks the row delivered or given
//! up. On start it delivers the rows still open, in insertion order, reading them in batches no
//! larger than half its queue ([`SqliteLeaseStore::outbox_open_between_of`]). `event_id` is
//! unique: it is derived from what the notice is about and its type, so a second notice of one
//! type for one approval (an `approval.expired` found again after a restart) is refused here
//! instead of being sent twice.
//!
//! **Two notifiers, one table.** The rows of the two notifiers are told apart by the namespace
//! of their `kind`: `approval.*` for the approval notifier, `lease.*` for the revocation
//! notifier. Each notifier reads, counts and prunes only the rows of its own namespace (the
//! `_of` methods take the prefix, `approval.` or `lease.`), so that each keeps its own backlog,
//! gauge and retention, and a notifier that is not configured leaves the other's rows alone.
//! The table needed no change for this: rows written before it are all `approval.*`. The
//! column `approval_id` holds what the notice is about: an approval id, or for `lease.revoked`
//! the first lease the revocation named. The methods without a prefix see every row.
//!
//! Times are Unix milliseconds (`INTEGER`), so that the pruning cutoff is a plain comparison.

use rusqlite::{params, OptionalExtension};
use time::OffsetDateTime;

use super::{approval_from_row, SqliteLeaseStore, APPROVAL_COLUMNS};
use crate::approval::Approval;
use crate::error::AuditError;

/// Part of schema version 1 (migration 1, see `migrations.rs`).
pub(super) const OUTBOX_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS notice_outbox (
    id              INTEGER PRIMARY KEY,
    event_id        TEXT    NOT NULL UNIQUE,
    kind            TEXT    NOT NULL,
    approval_id     TEXT    NOT NULL,
    body            BLOB    NOT NULL,
    created_at      INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NULL,
    delivered_at    INTEGER NULL,
    given_up_at     INTEGER NULL
);
CREATE INDEX IF NOT EXISTS notice_outbox_open_idx ON notice_outbox(id)
    WHERE delivered_at IS NULL AND given_up_at IS NULL;
"#;

/// A notice not yet delivered nor given up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxNotice {
    /// The row id: insertion order.
    pub id: i64,
    /// Stable across retries and restarts; receivers deduplicate by it.
    pub event_id: String,
    /// `approval.pending`, `approval.decided`, `approval.expired` or `lease.revoked`.
    pub kind: String,
    /// What the notice is about: the approval, or for `lease.revoked` the first lease the
    /// revocation named.
    pub approval_id: String,
    /// The JSON document exactly as sent and signed.
    pub body: Vec<u8>,
    /// Failed attempts so far.
    pub attempts: u32,
}

/// What [`SqliteLeaseStore::outbox_insert`] stores.
#[derive(Debug, Clone, Copy)]
pub struct NewNotice<'a> {
    /// The notice's stable id, as [`OutboxNotice::event_id`].
    pub event_id: &'a str,
    /// The event kind, as [`OutboxNotice::kind`].
    pub kind: &'a str,
    /// What the notice is about, as [`OutboxNotice::approval_id`].
    pub approval_id: &'a str,
    /// The signed JSON document to send.
    pub body: &'a [u8],
}

fn ms(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

/// One row of `SELECT id, event_id, kind, approval_id, body, attempts`.
fn outbox_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxNotice> {
    Ok(OutboxNotice {
        id: r.get(0)?,
        event_id: r.get(1)?,
        kind: r.get(2)?,
        approval_id: r.get(3)?,
        body: r.get(4)?,
        attempts: u32::try_from(r.get::<_, i64>(5)?).unwrap_or(u32::MAX),
    })
}

const OPEN: &str = "delivered_at IS NULL AND given_up_at IS NULL";

/// Rows whose `kind` starts with the bound parameter `?N` (an empty prefix matches every row).
/// A plain comparison of the leading characters, so no character of the prefix is a wildcard.
fn of_kind(n: u8) -> String {
    format!("substr(kind, 1, length(?{n})) = ?{n}")
}

/// Every row: the prefix the methods without `_of` pass.
const ALL_KINDS: &str = "";

impl SqliteLeaseStore {
    /// Store a notice to deliver. `Ok(None)` when a notice with this `event_id` is already
    /// stored (open, delivered or given up): it is not stored again.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the insert fails. A duplicate `event_id` is `Ok(None)`, not an
    /// error.
    pub fn outbox_insert(
        &self,
        n: NewNotice<'_>,
        now: OffsetDateTime,
    ) -> Result<Option<i64>, AuditError> {
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        let added = conn.execute(
            "INSERT OR IGNORE INTO notice_outbox (event_id, kind, approval_id, body, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![n.event_id, n.kind, n.approval_id, n.body, ms(now)],
        )?;
        Ok((added == 1).then(|| conn.last_insert_rowid()))
    }

    /// The open notices, oldest first, at most `limit`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails or a row has the wrong shape.
    pub fn outbox_open(&self, limit: usize) -> Result<Vec<OutboxNotice>, AuditError> {
        let conn = self.conn.lock()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT id, event_id, kind, approval_id, body, attempts FROM notice_outbox \
             WHERE {OPEN} ORDER BY id LIMIT ?1"
        ))?;
        let rows = stmt.query_map([limit], outbox_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The open notices with a row id in `(after, through]`, oldest first, at most `limit`.
    /// The notifier reads the rows left open by the last process in batches of this, so that
    /// none is dropped for lack of room in its queue, and never past the last row that was
    /// open at start (`through`, [`Self::outbox_last_open_id`]), so that a notice stored
    /// since, and queued directly, is not read a second time.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails or a row has the wrong shape.
    pub fn outbox_open_between(
        &self,
        after: i64,
        through: i64,
        limit: usize,
    ) -> Result<Vec<OutboxNotice>, AuditError> {
        self.outbox_open_between_of(ALL_KINDS, after, through, limit)
    }

    /// [`outbox_open_between`](Self::outbox_open_between) for the rows whose `kind` starts
    /// with `prefix` only (one notifier's rows, see the module docs).
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails or a row has the wrong shape.
    pub fn outbox_open_between_of(
        &self,
        prefix: &str,
        after: i64,
        through: i64,
        limit: usize,
    ) -> Result<Vec<OutboxNotice>, AuditError> {
        let conn = self.conn.lock()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT id, event_id, kind, approval_id, body, attempts FROM notice_outbox \
             WHERE {OPEN} AND id > ?1 AND id <= ?2 AND {} ORDER BY id LIMIT ?3",
            of_kind(4)
        ))?;
        let rows = stmt.query_map(params![after, through, limit, prefix], outbox_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The row id of the newest open notice, or `None` when none is open. An open row is
    /// never pruned, and SQLite gives a new row an id above every id in the table, so a
    /// notice stored after this was read has a higher id.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails.
    pub fn outbox_last_open_id(&self) -> Result<Option<i64>, AuditError> {
        self.outbox_last_open_id_of(ALL_KINDS)
    }

    /// [`outbox_last_open_id`](Self::outbox_last_open_id) among the rows whose `kind` starts
    /// with `prefix`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails.
    pub fn outbox_last_open_id_of(&self, prefix: &str) -> Result<Option<i64>, AuditError> {
        let conn = self.conn.lock()?;
        Ok(conn.query_row(
            &format!(
                "SELECT max(id) FROM notice_outbox WHERE {OPEN} AND {}",
                of_kind(1)
            ),
            [prefix],
            |r| r.get(0),
        )?)
    }

    /// How many notices are open.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails.
    pub fn outbox_open_count(&self) -> Result<u64, AuditError> {
        self.outbox_open_count_of(ALL_KINDS)
    }

    /// How many notices whose `kind` starts with `prefix` are open.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails.
    pub fn outbox_open_count_of(&self, prefix: &str) -> Result<u64, AuditError> {
        let conn = self.conn.lock()?;
        let n: i64 = conn.query_row(
            &format!(
                "SELECT count(*) FROM notice_outbox WHERE {OPEN} AND {}",
                of_kind(1)
            ),
            [prefix],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Mark notice `id` delivered. `false` when it was not open (already settled, or pruned).
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the update fails. A notice that is not open is `Ok(false)`.
    pub fn outbox_delivered(&self, id: i64, now: OffsetDateTime) -> Result<bool, AuditError> {
        self.outbox_settle(id, "delivered_at", None, now)
    }

    /// Mark notice `id` given up after `attempts` failed attempts. `false` when it was not
    /// open.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the update fails. A notice that is not open is `Ok(false)`.
    pub fn outbox_given_up(
        &self,
        id: i64,
        attempts: u32,
        now: OffsetDateTime,
    ) -> Result<bool, AuditError> {
        self.outbox_settle(id, "given_up_at", Some(attempts), now)
    }

    fn outbox_settle(
        &self,
        id: i64,
        column: &str,
        attempts: Option<u32>,
        now: OffsetDateTime,
    ) -> Result<bool, AuditError> {
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        let changed = conn.execute(
            &format!(
                "UPDATE notice_outbox SET {column} = ?2, next_attempt_at = NULL, \
                 attempts = coalesce(?3, attempts) WHERE id = ?1 AND {OPEN}"
            ),
            params![id, ms(now), attempts],
        )?;
        Ok(changed == 1)
    }

    /// Record a failed attempt of notice `id`: `attempts` so far, the next try at `next`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the update fails. A notice that is not open is left alone and is
    /// `Ok(())`.
    pub fn outbox_retry(
        &self,
        id: i64,
        attempts: u32,
        next: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        conn.execute(
            &format!(
                "UPDATE notice_outbox SET attempts = ?2, next_attempt_at = ?3 \
                 WHERE id = ?1 AND {OPEN}"
            ),
            params![id, attempts, ms(next)],
        )?;
        Ok(())
    }

    /// Delete the notices delivered or given up before `before`. Returns how many.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the delete fails.
    pub fn outbox_prune(&self, before: OffsetDateTime) -> Result<u64, AuditError> {
        self.outbox_prune_of(ALL_KINDS, before)
    }

    /// [`outbox_prune`](Self::outbox_prune) for the rows whose `kind` starts with `prefix`,
    /// so that each notifier applies its own `outbox_retention_seconds` to its own rows.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the delete fails.
    pub fn outbox_prune_of(&self, prefix: &str, before: OffsetDateTime) -> Result<u64, AuditError> {
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        let n = conn.execute(
            &format!(
                "DELETE FROM notice_outbox WHERE coalesce(delivered_at, given_up_at) < ?1 AND {}",
                of_kind(2)
            ),
            params![ms(before), prefix],
        )?;
        Ok(n as u64)
    }

    /// The `id` of the open notice with `event_id`, if any (tests and tooling).
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock, or
    /// [`AuditError::Sqlite`] when the query fails. No open notice with that `event_id` is
    /// `Ok(None)`.
    pub fn outbox_open_id(&self, event_id: &str) -> Result<Option<i64>, AuditError> {
        let conn = self.conn.lock()?;
        Ok(conn
            .query_row(
                &format!("SELECT id FROM notice_outbox WHERE event_id = ?1 AND {OPEN}"),
                [event_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Approvals still in state `pending` (expired or not), oldest first, at most `limit`.
    /// The notifier reads them at start to watch for their expiry again.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the store's lock,
    /// [`AuditError::Sqlite`] when the query fails, or a row that cannot be read back as an
    /// approval ([`AuditError::Storage`] for an unknown state or method, [`AuditError::TimeParse`]
    /// for a bad timestamp).
    pub fn pending_approvals(&self, limit: usize) -> Result<Vec<Approval>, AuditError> {
        let conn = self.conn.lock()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {APPROVAL_COLUMNS} FROM approvals WHERE state = 'pending' \
             ORDER BY rowid LIMIT ?1"
        ))?;
        let mut rows = stmt.query([limit])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(approval_from_row(r)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice<'a>(event_id: &'a str, body: &'a [u8]) -> NewNotice<'a> {
        NewNotice {
            event_id,
            kind: "approval.pending",
            approval_id: "a1",
            body,
        }
    }

    /// SR-93: the rows open at start are read in batches up to the newest one open then;
    /// a row stored later is outside the range.
    #[test]
    fn open_rows_are_read_in_batches_up_to_the_last_open_at_start() {
        let s = SqliteLeaseStore::open_in_memory().unwrap();
        let t = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        assert_eq!(s.outbox_last_open_id().unwrap(), None);
        let ids: Vec<i64> = (0..5)
            .map(|n| {
                let e = format!("e{n}");
                s.outbox_insert(notice(&e, b"{}"), t).unwrap().unwrap()
            })
            .collect();
        assert!(s.outbox_delivered(ids[1], t).unwrap());
        let through = s.outbox_last_open_id().unwrap().unwrap();
        assert_eq!(through, ids[4]);
        let later = s.outbox_insert(notice("late", b"{}"), t).unwrap().unwrap();
        assert!(later > through);
        let batch = |after| {
            s.outbox_open_between(after, through, 2)
                .unwrap()
                .into_iter()
                .map(|r| r.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            batch(0),
            vec![ids[0], ids[2]],
            "the delivered row is skipped"
        );
        assert_eq!(batch(ids[2]), vec![ids[3], ids[4]]);
        assert_eq!(
            batch(ids[4]),
            Vec::<i64>::new(),
            "the later row is not read"
        );
    }

    #[test]
    fn insert_is_once_per_event_and_settling_closes_a_row_once() {
        let s = SqliteLeaseStore::open_in_memory().unwrap();
        let t = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let a = s.outbox_insert(notice("e1", b"{}"), t).unwrap().unwrap();
        assert_eq!(s.outbox_insert(notice("e1", b"{}"), t).unwrap(), None);
        let b = s.outbox_insert(notice("e2", b"[]"), t).unwrap().unwrap();
        assert!(a < b);
        s.outbox_retry(a, 2, t + time::Duration::seconds(1))
            .unwrap();
        let open = s.outbox_open(10).unwrap();
        assert_eq!(open.len(), 2);
        assert_eq!((open[0].id, open[0].attempts), (a, 2));
        assert_eq!(open[1].body, b"[]");
        assert_eq!(s.outbox_open_count().unwrap(), 2);

        assert!(s.outbox_delivered(a, t).unwrap());
        assert!(!s.outbox_given_up(a, 5, t).unwrap(), "already delivered");
        assert!(s.outbox_given_up(b, 5, t).unwrap());
        assert_eq!(s.outbox_open_count().unwrap(), 0);
        assert_eq!(s.outbox_open_id("e1").unwrap(), None);
        // Settled rows still refuse their event id until pruned.
        assert_eq!(s.outbox_insert(notice("e2", b"[]"), t).unwrap(), None);

        assert_eq!(s.outbox_prune(t).unwrap(), 0, "not before the cutoff");
        assert_eq!(
            s.outbox_prune(t + time::Duration::milliseconds(1)).unwrap(),
            2
        );
        let open = s.outbox_insert(notice("e3", b"{}"), t).unwrap().unwrap();
        assert_eq!(
            s.outbox_prune(t + time::Duration::days(30)).unwrap(),
            0,
            "open rows are never pruned"
        );
        assert_eq!(s.outbox_open_id("e3").unwrap(), Some(open));
    }

    /// The `_of` methods see the rows of one kind namespace only; the others see every row.
    #[test]
    fn each_notifier_sees_only_its_own_rows() {
        let s = SqliteLeaseStore::open_in_memory().unwrap();
        let t = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let row = |event: &str, kind: &str| {
            s.outbox_insert(
                NewNotice {
                    event_id: event,
                    kind,
                    approval_id: "x",
                    body: b"{}",
                },
                t,
            )
            .unwrap()
            .unwrap()
        };
        let a1 = row("a1", "approval.pending");
        let l1 = row("l1", "lease.revoked");
        let a2 = row("a2", "approval.decided");
        let l2 = row("l2", "lease.revoked");
        // A kind that only looks like the prefix: `_` and `%` are not wildcards here.
        row("odd", "lease_revoked");
        let ids = |rows: Vec<OutboxNotice>| rows.into_iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(
            ids(s
                .outbox_open_between_of("approval.", 0, i64::MAX, 10)
                .unwrap()),
            vec![a1, a2]
        );
        assert_eq!(
            ids(s.outbox_open_between_of("lease.", 0, i64::MAX, 10).unwrap()),
            vec![l1, l2]
        );
        assert_eq!(s.outbox_last_open_id_of("approval.").unwrap(), Some(a2));
        assert_eq!(s.outbox_last_open_id_of("lease.").unwrap(), Some(l2));
        assert_eq!(s.outbox_last_open_id_of("none.").unwrap(), None);
        assert_eq!(s.outbox_open_count_of("lease.").unwrap(), 2);
        assert_eq!(s.outbox_open_count().unwrap(), 5);
        for id in [a1, l1] {
            assert!(s.outbox_delivered(id, t).unwrap());
        }
        let later = t + time::Duration::seconds(1);
        assert_eq!(s.outbox_prune_of("lease.", later).unwrap(), 1);
        assert_eq!(s.outbox_prune_of("lease.", later).unwrap(), 0);
        assert_eq!(s.outbox_prune_of("approval.", later).unwrap(), 1);
        assert_eq!(s.outbox_open_count().unwrap(), 3);
    }
}
