//! SQLite-backed audit sink and lease store.
//!
//! Both wrap a single `rusqlite::Connection` behind a `Mutex`. Appends run inside a transaction
//! that reads the current head and inserts the next row, so two writers can never produce two
//! entries with the same `prev_hash`. The lock, not SQLite's locking, is what keeps the chain
//! linear within a process; across processes SQLite's write lock plus the `UNIQUE` constraint on
//! `entry_hash` and the primary key on `seq` make a fork fail rather than succeed.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use onbehalf_core::{DecisionRecord, LeaseId};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::AuditError;
use crate::lease::{classify, LeaseRow, LeaseStatus, LeaseStore};
use crate::log::{verify_entries, AuditEntry, AuditSink, VerifyReport, GENESIS_HASH};

const AUDIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit (
    seq                 INTEGER PRIMARY KEY,
    prev_hash           TEXT    NOT NULL,
    entry_hash          TEXT    NOT NULL UNIQUE,
    at                  TEXT    NOT NULL,
    decision            TEXT    NOT NULL,
    reason              TEXT    NOT NULL,
    originating_subject TEXT    NOT NULL,
    agents              TEXT    NOT NULL,
    chain_depth         INTEGER NOT NULL,
    chain_digest        TEXT    NOT NULL,
    leases              TEXT    NOT NULL,
    server              TEXT    NOT NULL,
    tool                TEXT    NOT NULL,
    arguments_digest    TEXT    NOT NULL,
    session_id          TEXT    NULL,
    policy_ids          TEXT    NOT NULL,
    record_json         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_subject_idx ON audit(originating_subject);
CREATE INDEX IF NOT EXISTS audit_chain_idx   ON audit(chain_digest);
CREATE INDEX IF NOT EXISTS audit_at_idx      ON audit(at);
"#;

const LEASE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS leases (
    id            TEXT PRIMARY KEY,
    parent        TEXT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT NULL,
    revoke_reason TEXT NULL
);
CREATE INDEX IF NOT EXISTS leases_parent_idx ON leases(parent);
"#;

/// Columns read back for an entry, in the order `entry_from_row` expects.
const ENTRY_COLUMNS: &str = "seq, prev_hash, entry_hash, decision, reason, originating_subject, \
     agents, chain_depth, chain_digest, leases, server, tool, arguments_digest, session_id, \
     policy_ids, record_json";

fn open_connection(path: &Path) -> Result<Connection, AuditError> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

fn fmt_time(t: OffsetDateTime) -> Result<String, AuditError> {
    Ok(t.format(&Rfc3339)?)
}

fn parse_time(s: &str) -> Result<OffsetDateTime, AuditError> {
    Ok(OffsetDateTime::parse(s, &Rfc3339)?)
}

/// Rebuild an entry from a row and cross-check the indexed columns against `record_json`.
///
/// The hash covers `record_json`; the denormalized columns exist for queries. If someone edits a
/// column (say, flips `decision` from `deny` to `allow`) without touching the JSON, the hash would
/// still verify, so the mismatch is surfaced as a corrupt entry instead.
fn entry_from_row(row: &Row<'_>) -> Result<AuditEntry, AuditError> {
    let seq: i64 = row.get(0)?;
    let seq = u64::try_from(seq).map_err(|_| AuditError::Corrupt {
        seq: 0,
        detail: format!("negative seq {seq}"),
    })?;
    let prev_hash: String = row.get(1)?;
    let entry_hash: String = row.get(2)?;
    let decision: String = row.get(3)?;
    let reason: String = row.get(4)?;
    let subject: String = row.get(5)?;
    let agents: String = row.get(6)?;
    let chain_depth: i64 = row.get(7)?;
    let chain_digest: String = row.get(8)?;
    let leases: String = row.get(9)?;
    let server: String = row.get(10)?;
    let tool: String = row.get(11)?;
    let arguments_digest: String = row.get(12)?;
    let session_id: Option<String> = row.get(13)?;
    let policy_ids: String = row.get(14)?;
    let record_json: String = row.get(15)?;

    let corrupt = |detail: String| AuditError::Corrupt { seq, detail };
    let record: DecisionRecord =
        serde_json::from_str(&record_json).map_err(|e| corrupt(format!("record_json: {e}")))?;
    // The hash covers the *decoded* record, and some decoders are lenient (RFC 3339 accepts any
    // date/time separator, for instance), so a byte-level edit could decode to the same value.
    // Rows are written in canonical form; anything that no longer round-trips was edited.
    if serde_json::to_string(&record)? != record_json {
        return Err(corrupt(
            "record_json is not the canonical encoding of its record".into(),
        ));
    }

    let expect = |name: &str, stored: &str, actual: &str| -> Result<(), AuditError> {
        if stored == actual {
            Ok(())
        } else {
            Err(corrupt(format!(
                "column `{name}` ({stored}) disagrees with record_json ({actual})"
            )))
        }
    };
    expect("decision", &decision, decision_str(&record.decision))?;
    expect("reason", &reason, &record.reason)?;
    expect("originating_subject", &subject, &record.originating_subject)?;
    expect("agents", &agents, &serde_json::to_string(&record.agents)?)?;
    expect("chain_digest", &chain_digest, &record.chain_digest)?;
    expect("leases", &leases, &serde_json::to_string(&record.leases)?)?;
    expect("server", &server, &record.server)?;
    expect("tool", &tool, &record.tool)?;
    expect(
        "arguments_digest",
        &arguments_digest,
        &record.arguments_digest,
    )?;
    expect(
        "policy_ids",
        &policy_ids,
        &serde_json::to_string(&record.policy_ids)?,
    )?;
    if session_id != record.session_id {
        return Err(corrupt(format!(
            "column `session_id` ({session_id:?}) disagrees with record_json ({:?})",
            record.session_id
        )));
    }
    if u64::try_from(chain_depth).ok() != Some(record.chain_depth as u64) {
        return Err(corrupt(format!(
            "column `chain_depth` ({chain_depth}) disagrees with record_json ({})",
            record.chain_depth
        )));
    }

    Ok(AuditEntry {
        seq,
        prev_hash,
        record,
        entry_hash,
    })
}

fn decision_str(d: &onbehalf_core::Decision) -> &'static str {
    match d {
        onbehalf_core::Decision::Allow => "allow",
        onbehalf_core::Decision::Deny => "deny",
    }
}

fn head_in(tx: &Transaction<'_>) -> Result<Option<AuditEntry>, AuditError> {
    let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit ORDER BY seq DESC LIMIT 1");
    let mut stmt = tx.prepare_cached(&sql)?;
    stmt.query_row([], |row| Ok(entry_from_row(row)))
        .optional()?
        .transpose()
}

fn query_entries(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<AuditEntry>, AuditError> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(params, |row| Ok(entry_from_row(row)))?;
    rows.map(|r| r?).collect()
}

/// Hash-chained audit log in SQLite.
#[derive(Debug)]
pub struct SqliteAudit {
    conn: Mutex<Connection>,
}

impl SqliteAudit {
    /// Open (or create) the log at `path`. Pass `":memory:"` for a private in-memory log.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::from_connection(open_connection(path.as_ref())?)
    }

    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// Wrap an existing connection, creating the schema if needed.
    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        conn.execute_batch(AUDIT_SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Run `f` against the underlying connection while holding the write lock.
    ///
    /// Meant for operational tooling and tests (export, vacuum, deliberate tampering in a test).
    /// Anything written through here bypasses the chain, which `verify_chain` will report.
    pub fn with_connection<R>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let conn = self.conn.lock()?;
        f(&conn)
    }

    /// Entries for one originating subject, newest first, at most `limit`.
    pub fn by_subject(&self, subject: &str, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE originating_subject = ?1 \
             ORDER BY seq DESC LIMIT ?2"
        );
        let conn = self.conn.lock()?;
        query_entries(&conn, &sql, &[&subject, &(limit as i64)])
    }

    /// Every entry bound to one delegation chain, in order.
    pub fn by_chain(&self, chain_digest: &str) -> Result<Vec<AuditEntry>, AuditError> {
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE chain_digest = ?1 ORDER BY seq");
        let conn = self.conn.lock()?;
        query_entries(&conn, &sql, &[&chain_digest])
    }

    /// Every entry whose chain held `lease`, in order.
    ///
    /// v0 note: `leases` is stored as a JSON array of strings and this is a `LIKE` on that text
    /// (the id is matched as a quoted JSON string so `l1` does not match `l10`). It is a full scan;
    /// a join table is the upgrade path when volume demands an index.
    pub fn by_lease(&self, lease: &LeaseId) -> Result<Vec<AuditEntry>, AuditError> {
        let needle = serde_json::to_string(&lease.0)?;
        let pattern = format!(
            "%{}%",
            needle
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE leases LIKE ?1 ESCAPE '\\' ORDER BY seq"
        );
        let conn = self.conn.lock()?;
        let candidates = query_entries(&conn, &sql, &[&pattern])?;
        // Confirm against the decoded record; LIKE is only a prefilter.
        Ok(candidates
            .into_iter()
            .filter(|e| e.record.leases.contains(lease))
            .collect())
    }

    /// Number of entries.
    pub fn len(&self) -> Result<u64, AuditError> {
        let conn = self.conn.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn is_empty(&self) -> Result<bool, AuditError> {
        Ok(self.len()? == 0)
    }
}

impl AuditSink for SqliteAudit {
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let head = head_in(&tx)?;
        let entry = AuditEntry::next(head.as_ref(), record);
        let r = &entry.record;
        tx.execute(
            "INSERT INTO audit (seq, prev_hash, entry_hash, at, decision, reason, \
             originating_subject, agents, chain_depth, chain_digest, leases, server, tool, \
             arguments_digest, session_id, policy_ids, record_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                entry.seq as i64,
                entry.prev_hash,
                entry.entry_hash,
                fmt_time(r.at)?,
                decision_str(&r.decision),
                r.reason,
                r.originating_subject,
                serde_json::to_string(&r.agents)?,
                r.chain_depth as i64,
                r.chain_digest,
                serde_json::to_string(&r.leases)?,
                r.server,
                r.tool,
                r.arguments_digest,
                r.session_id,
                serde_json::to_string(&r.policy_ids)?,
                serde_json::to_string(r)?,
            ],
        )?;
        tx.commit()?;
        Ok(entry)
    }

    fn head(&self) -> Result<Option<AuditEntry>, AuditError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        head_in(&tx)
    }

    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let sql =
            format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE seq >= ?1 ORDER BY seq LIMIT ?2");
        let conn = self.conn.lock()?;
        query_entries(&conn, &sql, &[&(from_seq as i64), &(limit as i64)])
    }

    fn verify_chain(&self) -> Result<VerifyReport, AuditError> {
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit ORDER BY seq");
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(entry_from_row(row)))?;
        // A row that cannot be decoded (corrupt JSON, column/JSON disagreement) surfaces as
        // `AuditError::Corrupt`, which `verify_entries` reports as a break at that seq.
        verify_entries(rows.map(|r| r?))
    }

    fn checkpoint(&self) -> Result<(u64, String), AuditError> {
        Ok(match self.head()? {
            Some(h) => (h.seq, h.entry_hash),
            None => (0, GENESIS_HASH.to_string()),
        })
    }
}

/// Lease registry in SQLite.
#[derive(Debug)]
pub struct SqliteLeaseStore {
    conn: Mutex<Connection>,
}

impl SqliteLeaseStore {
    /// Open (or create) the registry at `path`. May be the same file as a [`SqliteAudit`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::from_connection(open_connection(path.as_ref())?)
    }

    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        conn.execute_batch(LEASE_SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// One lease's row, if known.
    pub fn get(&self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
        let conn = self.conn.lock()?;
        get_in(&conn, lease)
    }
}

fn get_in(conn: &Connection, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
    let mut stmt = conn.prepare_cached(
        "SELECT parent, expires_at, revoked_at, revoke_reason FROM leases WHERE id = ?1",
    )?;
    let row = stmt
        .query_row([&lease.0], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .optional()?;
    match row {
        None => Ok(None),
        Some((parent, expires_at, revoked_at, revoke_reason)) => Ok(Some(LeaseRow {
            parent: parent.map(LeaseId),
            expires_at: parse_time(&expires_at)?,
            revoked_at: revoked_at.as_deref().map(parse_time).transpose()?,
            revoke_reason,
        })),
    }
}

impl LeaseStore for SqliteLeaseStore {
    fn register(
        &self,
        lease: &LeaseId,
        parent: Option<&LeaseId>,
        expires_at: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let conn = self.conn.lock()?;
        conn.execute(
            "INSERT INTO leases (id, parent, expires_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET parent = excluded.parent, \
             expires_at = excluded.expires_at",
            params![lease.0, parent.map(|p| p.0.as_str()), fmt_time(expires_at)?],
        )?;
        Ok(())
    }

    fn revoke(
        &self,
        lease: &LeaseId,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<u64, AuditError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if get_in(&tx, lease)?.is_none() {
            return Err(AuditError::UnknownLease(lease.0.clone()));
        }
        // UNION (not UNION ALL) so an accidental cycle terminates.
        let changed = tx.execute(
            "UPDATE leases SET revoked_at = ?2, revoke_reason = ?3 \
             WHERE revoked_at IS NULL AND id IN ( \
                 WITH RECURSIVE sub(id) AS ( \
                     SELECT id FROM leases WHERE id = ?1 \
                     UNION \
                     SELECT l.id FROM leases l JOIN sub ON l.parent = sub.id \
                 ) SELECT id FROM sub)",
            params![lease.0, fmt_time(now)?, reason],
        )?;
        tx.commit()?;
        Ok(changed as u64)
    }

    fn is_active(&self, lease: &LeaseId, now: OffsetDateTime) -> Result<bool, AuditError> {
        let conn = self.conn.lock()?;
        Ok(get_in(&conn, lease)?.is_some_and(|r| r.is_active(now)))
    }

    fn check_all(
        &self,
        leases: &[&LeaseId],
        now: OffsetDateTime,
    ) -> Result<LeaseStatus, AuditError> {
        let conn = self.conn.lock()?;
        classify(leases, now, |id| get_in(&conn, id))
    }
}
