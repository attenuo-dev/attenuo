//! The approval notice outbox (`[approvals.notify]`): one row per notice the server's notifier
//! is to deliver, kept in the lease store's database so that a restart neither loses a notice
//! still queued nor forgets an approval still waiting for its expiry.
//!
//! The notifier (in `attenuo-server`) writes a row right after the approval change it
//! describes was stored and recorded, delivers from its in-memory queue, and marks the row
//! delivered or given up. On start it loads the rows still open and delivers them first, in
//! insertion order. `event_id` is unique: it is derived from the approval id and the notice
//! type, so a second notice of one type for one approval (an `approval.expired` found again
//! after a restart) is refused here instead of being sent twice.
//!
//! Times are Unix milliseconds (`INTEGER`), so that the pruning cutoff is a plain comparison.

use rusqlite::{params, OptionalExtension};
use time::OffsetDateTime;

use super::{approval_from_row, SqliteLeaseStore, APPROVAL_COLUMNS};
use crate::approval::Approval;
use crate::error::AuditError;

/// Created at open, on new stores and on stores that predate it.
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
    /// `approval.pending`, `approval.decided` or `approval.expired`.
    pub kind: String,
    pub approval_id: String,
    /// The JSON document exactly as sent and signed.
    pub body: Vec<u8>,
    /// Failed attempts so far.
    pub attempts: u32,
}

/// What [`SqliteLeaseStore::outbox_insert`] stores.
#[derive(Debug, Clone, Copy)]
pub struct NewNotice<'a> {
    pub event_id: &'a str,
    pub kind: &'a str,
    pub approval_id: &'a str,
    pub body: &'a [u8],
}

fn ms(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

const OPEN: &str = "delivered_at IS NULL AND given_up_at IS NULL";

impl SqliteLeaseStore {
    /// Store a notice to deliver. `Ok(None)` when a notice with this `event_id` is already
    /// stored (open, delivered or given up): it is not stored again.
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
    pub fn outbox_open(&self, limit: usize) -> Result<Vec<OutboxNotice>, AuditError> {
        let conn = self.conn.lock()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT id, event_id, kind, approval_id, body, attempts FROM notice_outbox \
             WHERE {OPEN} ORDER BY id LIMIT ?1"
        ))?;
        let rows = stmt.query_map([limit], |r| {
            Ok(OutboxNotice {
                id: r.get(0)?,
                event_id: r.get(1)?,
                kind: r.get(2)?,
                approval_id: r.get(3)?,
                body: r.get(4)?,
                attempts: u32::try_from(r.get::<_, i64>(5)?).unwrap_or(u32::MAX),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// How many notices are open.
    pub fn outbox_open_count(&self) -> Result<u64, AuditError> {
        let conn = self.conn.lock()?;
        let n: i64 = conn.query_row(
            &format!("SELECT count(*) FROM notice_outbox WHERE {OPEN}"),
            [],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Mark notice `id` delivered. `false` when it was not open (already settled, or pruned).
    pub fn outbox_delivered(&self, id: i64, now: OffsetDateTime) -> Result<bool, AuditError> {
        self.outbox_settle(id, "delivered_at", None, now)
    }

    /// Mark notice `id` given up after `attempts` failed attempts. `false` when it was not
    /// open.
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
    pub fn outbox_prune(&self, before: OffsetDateTime) -> Result<u64, AuditError> {
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        let n = conn.execute(
            "DELETE FROM notice_outbox WHERE coalesce(delivered_at, given_up_at) < ?1",
            [ms(before)],
        )?;
        Ok(n as u64)
    }

    /// The `id` of the open notice with `event_id`, if any (tests and tooling).
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
}
