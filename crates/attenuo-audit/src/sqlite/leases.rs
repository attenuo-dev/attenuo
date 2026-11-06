//! [`SqliteLeaseStore`]: the lease registry, revocation, sessions, subjects, pruning and the
//! [`LeaseStore`] implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

use attenuo_core::fingerprint::Fingerprint;
use attenuo_core::{Charge, LeaseId};
use rusqlite::{params, Connection, OptionalExtension, Row};
use time::OffsetDateTime;

use super::approvals::{
    add_approval_columns, approval_from_row, approval_in, approvals_for_call, pending_of_run,
    APPROVAL_COLUMNS,
};
use super::budgets::{counter_in, refund_in};
use super::connection::{
    file_of, open_connection, open_memory_connection, with_full_sync, Durability, WriteGate,
};
use super::outbox;
use super::schema::LEASE_SCHEMA;
use super::{fmt_time, parse_time};
use crate::approval::{rules, Approval, ApprovalState, Approver};
use crate::budget::{
    kind_static, summarize, ChargeOutcome, CounterKey, CounterSummary, HopLimit, ValueKey,
    USAGE_KINDS,
};
use crate::error::AuditError;
use crate::lease::{
    ancestors_of, breadth_first, classify, prune_pass, run_state_prunable, session_prunable,
    LeasePrune, LeasePruneState, LeaseRow, LeaseSelector, LeaseStatus, LeaseStore, LeaseSubtree,
    PruneOps, RunLabel, RunStatePrune, SelectorRevocation, SessionBinding, SessionPrune,
};
use crate::spans::{
    distinct_hashes, evictions, SpanHit, SpanKey, MAX_SEQS_PER_PROBE, MAX_SPANS_PER_RUN,
};

/// Lease registry in SQLite.
///
/// A file-backed store runs at the [`Durability`] it was opened with, except that
/// [`revoke`](LeaseStore::revoke) always commits with `synchronous=FULL`: losing a revocation
/// to a power failure would bring a revoked lease back, and revocations are rare enough that
/// their `fsync` does not matter. A [`charge`](LeaseStore::charge) that charges a `sum` limit
/// commits with `synchronous=FULL` too, unless it is made with
/// [`charge_sync_deferred`](LeaseStore::charge_sync_deferred), which commits it at the
/// store's level and leaves the sync to the caller's
/// [`append_synced`](crate::AuditSink::append_synced) on a [`SqliteAudit`](super::SqliteAudit) in the same file.
#[derive(Debug)]
pub struct SqliteLeaseStore {
    pub(super) conn: Mutex<Connection>,
    /// `None` for a connection this crate did not open (or an in-memory one): its pragmas are
    /// left alone.
    pub(super) durability: Option<Durability>,
    /// The database file (canonical path) of a store this crate opened on a file: the file a
    /// deferred `sum` charge's sync must cover. `None` otherwise, and then nothing is deferred.
    pub(super) file: Option<PathBuf>,
    /// Held across every write (see [`WriteGate`]); shared with a [`SqliteAudit`](super::SqliteAudit) on the same
    /// file.
    pub(super) gate: WriteGate,
    /// The key `calls_per` values are hashed under (`budget_meta`, ADR-0010).
    pub(super) value_key: ValueKey,
    /// The key span-index fingerprints are hashed under (`budget_meta`, ADR-0009 phase 2).
    span_key: SpanKey,
    /// The `rowid` of the last `lease_sessions` row a `prune_sessions` pass looked at; 0 to
    /// start from the first.
    session_cursor: Mutex<i64>,
    /// Where the next `prune_leases` pass starts (the `rowid` of the last `leases` row a pass
    /// looked at), and the run it is pruning, if any. Taken under `conn`.
    lease_prune: Mutex<LeasePruneState<i64>>,
    /// Where the next `prune_run_state` pass starts: the table (0 `budget_charges`, 1
    /// `budget_counters`, 2 `approvals`) and the `rowid` of the last row a pass looked at in
    /// it, 0 to start from the first.
    run_state_cursor: Mutex<(u8, i64)>,
    /// Tests: every charge commit and the `synchronous` level it ran at.
    #[cfg(test)]
    pub(super) probe: Option<Arc<Mutex<Vec<String>>>>,
}

impl SqliteLeaseStore {
    /// Open (or create) the registry at `path` with [`Durability::Normal`]. May be the same file
    /// as a [`SqliteAudit`](super::SqliteAudit).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::open_with(path, Durability::default())
    }

    /// Open (or create) the registry at `path` in WAL mode with the given durability.
    /// Revocations commit with `synchronous=FULL` whatever `durability` says.
    pub fn open_with(path: impl AsRef<Path>, durability: Durability) -> Result<Self, AuditError> {
        let conn = open_connection(path.as_ref(), durability)?;
        let file = file_of(&conn);
        let mut store = Self::from_connection(conn)?;
        store.durability = Some(durability);
        store.file = file;
        Ok(store)
    }

    /// A registry in a private in-memory database, gone when the value is dropped.
    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_connection(open_memory_connection()?)
    }

    /// Wrap an existing connection, creating or upgrading the lease, approval and outbox
    /// tables as needed.
    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        conn.execute_batch(LEASE_SCHEMA)?;
        add_approval_columns(&conn)?;
        conn.execute_batch(outbox::OUTBOX_SCHEMA)?;
        let key: String = conn.query_row(
            "SELECT value FROM budget_meta WHERE key = 'value_key'",
            [],
            |r| r.get(0),
        )?;
        let key = hex::decode(&key)
            .map_err(|e| AuditError::Storage(format!("budget value key is not hex: {e}")))?;
        let span_key: String = conn.query_row(
            "SELECT value FROM budget_meta WHERE key = 'span_key'",
            [],
            |r| r.get(0),
        )?;
        let span_key = hex::decode(&span_key)
            .map_err(|e| AuditError::Storage(format!("span key is not hex: {e}")))?;
        let gate = WriteGate::for_file(file_of(&conn).as_deref());
        Ok(Self {
            conn: Mutex::new(conn),
            durability: None,
            file: None,
            gate,
            value_key: ValueKey::new(&key),
            span_key: SpanKey::new(&span_key),
            session_cursor: Mutex::new(0),
            lease_prune: Mutex::default(),
            run_state_cursor: Mutex::new((0, 0)),
            #[cfg(test)]
            probe: None,
        })
    }

    /// Run `f` against the underlying connection while holding the store's lock. For tests
    /// and operational tooling.
    pub fn with_connection<R>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let conn = self.conn.lock()?;
        f(&conn)
    }

    /// Stop this connection from checkpointing the WAL when it commits
    /// (`wal_autocheckpoint=0`). Only for a store that shares its file with a
    /// [`SqliteAudit`](super::SqliteAudit) whose [`with_wal_checkpoints`](super::SqliteAudit::with_wal_checkpoints) is on:
    /// that checkpointer covers the whole file, and without this a token exchange that
    /// registers a lease would still run a checkpoint inline now and then. Nothing to do for
    /// an in-memory store.
    pub fn without_wal_autocheckpoint(self) -> Result<Self, AuditError> {
        self.conn
            .lock()?
            .pragma_update(None, "wal_autocheckpoint", 0)?;
        Ok(self)
    }

    /// One lease's row, if known.
    pub fn get(&self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
        let conn = self.conn.lock()?;
        get_in(&conn, lease)
    }

    /// What revoking `lease` would touch, without changing anything; `None` for an unknown
    /// lease. A dry run of [`revoke`](LeaseStore::revoke): it reads the subtree through the
    /// same recursive query over `leases_parent_idx`, so `would_revoke` is the count a
    /// revocation run now would return. `nodes` holds at most `max_nodes` leases (at least 1),
    /// found breadth-first; `would_revoke` counts the whole subtree regardless of the cap.
    pub fn subtree(
        &self,
        lease: &LeaseId,
        max_nodes: usize,
    ) -> Result<Option<LeaseSubtree>, AuditError> {
        let mut conn = self.conn.lock()?;
        subtree_in(&mut conn, lease, max_nodes)
    }
}

/// `SELECT id FROM sub`, where `sub` is lease `?1` and every lease descended from it, found
/// through `leases_parent_idx`. UNION (not UNION ALL) so an accidental cycle terminates.
/// `$limit` goes on the recursive select: `""` for the whole subtree, or a `LIMIT` that stops
/// the recursion early. Revocation and its preview ([`SqliteLeaseStore::subtree`]) both use
/// this, so the preview counts exactly the rows a revocation would change.
macro_rules! subtree_ids {
    ($limit:literal) => {
        concat!(
            "WITH RECURSIVE sub(id) AS ( \
                 SELECT id FROM leases WHERE id = ?1 \
                 UNION \
                 SELECT l.id FROM leases l JOIN sub ON l.parent = sub.id ",
            $limit,
            ") SELECT id FROM sub"
        )
    };
}

/// The SQLite store's side of [`prune_pass`], inside the pass's transaction.
struct SqlitePrune<'a> {
    tx: &'a rusqlite::Transaction<'a>,
}

/// A lease row as `prune_pass` reads it.
fn prune_row(
    parent: Option<String>,
    expires_at: &str,
    revoked_at: Option<&str>,
) -> Result<LeaseRow, AuditError> {
    Ok(LeaseRow {
        parent: parent.map(LeaseId),
        expires_at: parse_time(expires_at)?,
        revoked_at: revoked_at.map(parse_time).transpose()?,
        revoke_reason: None,
    })
}

impl PruneOps for SqlitePrune<'_> {
    type Pos = i64;

    fn window(
        &mut self,
        after: Option<&i64>,
        limit: usize,
    ) -> Result<Vec<(i64, LeaseId, bool, LeaseRow)>, AuditError> {
        // A top is a lease with no parent, or whose parent row is gone (a store that lost
        // rows): its run is decided there, its descendants are skipped.
        type Seen = (i64, String, bool, Option<String>, String, Option<String>);
        let seen: Vec<Seen> = self
            .tx
            .prepare_cached(
                "SELECT l.rowid, l.id, (l.parent IS NULL OR NOT EXISTS \
                 (SELECT 1 FROM leases p WHERE p.id = l.parent)), l.parent, l.expires_at, \
                 l.revoked_at FROM leases l WHERE l.rowid > ?1 ORDER BY l.rowid LIMIT ?2",
            )?
            .query_map(
                params![
                    after.copied().unwrap_or(0),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?
            .collect::<Result<_, _>>()?;
        seen.into_iter()
            .map(|(rowid, id, top, parent, expires_at, revoked_at)| {
                let row = prune_row(parent, &expires_at, revoked_at.as_deref())?;
                Ok((rowid, LeaseId(id), top, row))
            })
            .collect()
    }

    fn children(
        &mut self,
        parent: &LeaseId,
        after: Option<&LeaseId>,
        limit: usize,
    ) -> Result<Vec<(LeaseId, LeaseRow, bool)>, AuditError> {
        // `leases_parent_idx` holds `(parent, rowid)`, so this is one index range, and the
        // `EXISTS` one probe of it per child.
        type Kid = (String, String, Option<String>, bool);
        let kids: Vec<Kid> = self
            .tx
            .prepare_cached(
                "SELECT l.id, l.expires_at, l.revoked_at, \
                 EXISTS (SELECT 1 FROM leases c WHERE c.parent = l.id) \
                 FROM leases l INDEXED BY leases_parent_idx WHERE l.parent = ?1 \
                 AND l.rowid > coalesce((SELECT rowid FROM leases WHERE id = ?2), 0) \
                 ORDER BY l.rowid LIMIT ?3",
            )?
            .query_map(
                params![
                    parent.0,
                    after.map(|a| a.0.as_str()),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?
            .collect::<Result<_, _>>()?;
        kids.into_iter()
            .map(|(id, expires_at, revoked_at, has_kids)| {
                let row = prune_row(Some(parent.0.clone()), &expires_at, revoked_at.as_deref())?;
                Ok((LeaseId(id), row, has_kids))
            })
            .collect()
    }

    fn row(&mut self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
        get_in(self.tx, lease)
    }

    fn delete(&mut self, lease: &LeaseId) -> Result<bool, AuditError> {
        // Everything keyed by the lease first, the lease row last.
        for (table, column) in [
            ("lease_subjects", "id"),
            ("lease_bindings", "id"),
            ("lease_sessions", "chain_id"),
            ("hop_limits", "lease"),
            ("run_labels", "chain_id"),
            ("run_spans", "chain_id"),
        ] {
            self.tx
                .prepare_cached(&format!("DELETE FROM {table} WHERE {column} = ?1"))?
                .execute([&lease.0])?;
        }
        let n = self
            .tx
            .prepare_cached("DELETE FROM leases WHERE id = ?1")?
            .execute([&lease.0])?;
        Ok(n > 0)
    }
}

fn revoke_in(
    conn: &mut Connection,
    lease: &LeaseId,
    reason: &str,
    now: OffsetDateTime,
) -> Result<u64, AuditError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if get_in(&tx, lease)?.is_none() {
        return Err(AuditError::UnknownLease(lease.0.clone()));
    }
    let changed = revoke_subtree(&tx, lease, reason, now)?;
    tx.commit()?;
    Ok(changed as u64)
}

/// The unrevoked leases in the subtree of `lease` (itself included).
fn unrevoked_subtree(conn: &Connection, lease: &LeaseId) -> Result<Vec<LeaseId>, AuditError> {
    let ids = conn
        .prepare_cached(concat!(
            "SELECT id FROM leases WHERE revoked_at IS NULL AND id IN (",
            subtree_ids!(""),
            ")"
        ))?
        .query_map([&lease.0], |r| r.get::<_, String>(0))?
        .map(|r| r.map(LeaseId))
        .collect::<Result<_, _>>()?;
    Ok(ids)
}

/// [`LeaseStore::preview_selected`] and [`LeaseStore::revoke_selected`] in one transaction
/// (`IMMEDIATE` when writing): `write` carries the reason and time of a real revocation,
/// `None` for a preview. The selector's value is always a bound parameter.
fn selected_in(
    conn: &mut Connection,
    selector: &LeaseSelector,
    write: Option<(&str, OffsetDateTime)>,
) -> Result<SelectorRevocation, AuditError> {
    let tx = if write.is_some() {
        conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?
    } else {
        conn.transaction()?
    };
    let matched: Vec<LeaseId> = match selector {
        LeaseSelector::Subject(subject) => tx
            .prepare_cached(
                "SELECT l.id FROM lease_subjects s JOIN leases l ON l.id = s.id \
                 WHERE s.subject = ?1 AND l.revoked_at IS NULL ORDER BY l.id",
            )?
            .query_map([subject], |r| r.get::<_, String>(0))?
            .map(|r| r.map(LeaseId))
            .collect::<Result<_, _>>()?,
        LeaseSelector::Chain(root) => chain_matches_in(&tx, root)?,
        LeaseSelector::Session(session) => {
            let mut matched = Vec::new();
            for b in sessions_in(&tx, session)? {
                matched.extend(chain_matches_in(&tx, &b.chain_id)?);
            }
            matched
        }
    };
    let mut cascade = Vec::new();
    for m in &matched {
        cascade.extend(unrevoked_subtree(&tx, m)?);
    }
    let out = SelectorRevocation::from_parts(matched, cascade);
    if let Some((reason, now)) = write {
        // Revoke the matches one by one, each with the same cascade as `revoke_in`. A match
        // already revoked by an earlier match's cascade changes nothing the second time.
        for m in &out.matched {
            revoke_subtree(&tx, m, reason, now)?;
        }
    }
    tx.commit()?;
    Ok(out)
}

/// The writes of a revocation of `lease` inside `tx`: mark its unrevoked subtree revoked and
/// end the runs' span indexes and usage. Returns how many leases changed.
fn revoke_subtree(
    tx: &rusqlite::Transaction<'_>,
    lease: &LeaseId,
    reason: &str,
    now: OffsetDateTime,
) -> Result<usize, AuditError> {
    let changed = tx.execute(
        concat!(
            "UPDATE leases SET revoked_at = ?2, revoke_reason = ?3 \
             WHERE revoked_at IS NULL AND id IN (",
            subtree_ids!(""),
            ")"
        ),
        params![lease.0, fmt_time(now)?, reason],
    )?;
    // A revoked run's span index ends with it (`crate::spans`): chain ids are root leases.
    tx.execute(
        concat!(
            "DELETE FROM run_spans WHERE chain_id IN (",
            subtree_ids!(""),
            ")"
        ),
        params![lease.0],
    )?;
    // So does its run usage (`crate::budget`): the counters, and the hashed destinations that
    // the charge log holds for a refund. Token-limit counters stay readable.
    for table in ["budget_counters", "budget_charges"] {
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE kind IN (?2, ?3, ?4) AND lease IN ({})",
                subtree_ids!("")
            ),
            params![lease.0, USAGE_KINDS[0], USAGE_KINDS[1], USAGE_KINDS[2]],
        )?;
    }
    Ok(changed)
}

/// [`SqliteLeaseStore::subtree`] inside one read transaction, so the nodes, the count and the
/// ancestors describe the same moment.
fn subtree_in(
    conn: &mut Connection,
    lease: &LeaseId,
    max_nodes: usize,
) -> Result<Option<LeaseSubtree>, AuditError> {
    let tx = conn.transaction()?;
    let Some(row) = get_in(&tx, lease)? else {
        return Ok(None);
    };
    // The same predicate as the UPDATE in `revoke_in`, counted instead of written.
    let would_revoke: i64 = tx
        .prepare_cached(concat!(
            "SELECT COUNT(*) FROM leases WHERE revoked_at IS NULL AND id IN (",
            subtree_ids!(""),
            ")"
        ))?
        .query_row([&lease.0], |r| r.get(0))?;
    // One row past the cap tells a full answer from a truncated one.
    let max_nodes = max_nodes.max(1);
    let fetch = i64::try_from(max_nodes.saturating_add(1)).unwrap_or(i64::MAX);
    let mut found = Vec::new();
    {
        let mut stmt = tx.prepare_cached(concat!(
            "SELECT id, parent, expires_at, revoked_at, revoke_reason FROM leases WHERE id IN (",
            subtree_ids!("LIMIT ?2"),
            ")"
        ))?;
        let mut rows = stmt.query(params![lease.0, fetch])?;
        while let Some(r) = rows.next()? {
            let (id, row) = lease_row_from(r)?;
            found.push((LeaseId(id), row));
        }
    }
    let truncated = found.len() > max_nodes;
    let mut nodes = breadth_first(lease, found);
    nodes.truncate(max_nodes);
    let ancestors = ancestors_of(lease, &row, |id| get_in(&tx, id))?;
    tx.commit()?;
    Ok(Some(LeaseSubtree {
        nodes,
        ancestors,
        would_revoke: u64::try_from(would_revoke).unwrap_or(0),
        truncated,
    }))
}

/// What [`LeaseSelector::Chain`] matches: the unrevoked leases of the subtree of `root`, or
/// nothing when `root` is unknown or has a parent.
fn chain_matches_in(conn: &Connection, root: &LeaseId) -> Result<Vec<LeaseId>, AuditError> {
    match get_in(conn, root)? {
        Some(row) if row.parent.is_none() => unrevoked_subtree(conn, root),
        _ => Ok(Vec::new()),
    }
}

fn sessions_in(conn: &Connection, session: &str) -> Result<Vec<SessionBinding>, AuditError> {
    let rows: Vec<(String, String, String)> = conn
        .prepare_cached(
            "SELECT server, chain_id, bound_at FROM lease_sessions WHERE session = ?1 \
             ORDER BY server",
        )?
        .query_map([session], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|(server, chain_id, at)| {
            Ok(SessionBinding {
                server,
                chain_id: LeaseId(chain_id),
                bound_at: parse_time(&at)?,
            })
        })
        .collect()
}

fn subject_in(conn: &Connection, lease: &LeaseId) -> Result<Option<String>, AuditError> {
    Ok(conn
        .prepare_cached("SELECT subject FROM lease_subjects WHERE id = ?1")?
        .query_row([&lease.0], |row| row.get::<_, String>(0))
        .optional()?)
}

/// The recorded subject of every lease in `leases` that has one, with one `IN (...)` query per
/// [`LEASES_PER_QUERY`] leases.
fn subjects_in(
    conn: &Connection,
    leases: &[&LeaseId],
) -> Result<BTreeMap<LeaseId, String>, AuditError> {
    let mut out = BTreeMap::new();
    for chunk in leases.chunks(LEASES_PER_QUERY) {
        // One cached statement per chunk length.
        let sql = format!(
            "SELECT id, subject FROM lease_subjects WHERE id IN ({})",
            vec!["?"; chunk.len()].join(",")
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(
            chunk.iter().map(|l| l.0.as_str()),
        ))?;
        while let Some(row) = rows.next()? {
            out.insert(LeaseId(row.get::<_, String>(0)?), row.get::<_, String>(1)?);
        }
    }
    Ok(out)
}

fn binding_in(conn: &Connection, lease: &LeaseId) -> Result<Option<String>, AuditError> {
    Ok(conn
        .prepare_cached("SELECT binding FROM lease_bindings WHERE id = ?1")?
        .query_row([&lease.0], |row| row.get::<_, String>(0))
        .optional()?)
}

/// Leases read per `IN (...)` query. SQLite allows 32766 parameters; chains are capped far
/// below this, but a longer list still works, in chunks.
const LEASES_PER_QUERY: usize = 64;

/// `SELECT ... WHERE id IN (?,...,?)` with `n` placeholders, built once per `n`.
fn leases_in_sql(n: usize) -> &'static str {
    static SQL: OnceLock<Vec<String>> = OnceLock::new();
    &SQL.get_or_init(|| {
        (0..=LEASES_PER_QUERY)
            .map(|n| {
                format!(
                    "SELECT id, parent, expires_at, revoked_at, revoke_reason FROM leases \
                     WHERE id IN ({})",
                    vec!["?"; n].join(",")
                )
            })
            .collect()
    })[n]
}

/// The rows of every lease in `leases`, with one query (`WHERE id IN (...)`) instead of one
/// per hop. Unknown ids are absent from the result; order is unspecified.
fn rows_in(conn: &Connection, leases: &[&LeaseId]) -> Result<Vec<(String, LeaseRow)>, AuditError> {
    let mut out = Vec::with_capacity(leases.len());
    for chunk in leases.chunks(LEASES_PER_QUERY) {
        // One cached statement per chain length.
        let mut stmt = conn.prepare_cached(leases_in_sql(chunk.len()))?;
        let mut rows = stmt.query(rusqlite::params_from_iter(
            chunk.iter().map(|l| l.0.as_str()),
        ))?;
        while let Some(row) = rows.next()? {
            out.push(lease_row_from(row)?);
        }
    }
    Ok(out)
}

/// Decode `id, parent, expires_at, revoked_at, revoke_reason` (in that order).
fn lease_row_from(row: &Row<'_>) -> Result<(String, LeaseRow), AuditError> {
    let expires_at: String = row.get(2)?;
    let revoked_at: Option<String> = row.get(3)?;
    Ok((
        row.get::<_, String>(0)?,
        LeaseRow {
            parent: row.get::<_, Option<String>>(1)?.map(LeaseId),
            expires_at: parse_time(&expires_at)?,
            revoked_at: revoked_at.as_deref().map(parse_time).transpose()?,
            revoke_reason: row.get(4)?,
        },
    ))
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
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        {
            let mut prune = self.lease_prune.lock()?;
            prune.before_revival(lease)?;
            if let Some(p) = parent {
                prune.after_write(p);
            }
        }
        conn.prepare_cached(
            "INSERT INTO leases (id, parent, expires_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET parent = excluded.parent, \
             expires_at = excluded.expires_at",
        )?
        .execute(params![
            lease.0,
            parent.map(|p| p.0.as_str()),
            fmt_time(expires_at)?
        ])?;
        Ok(())
    }

    fn revoke(
        &self,
        lease: &LeaseId,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<u64, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        // A revocation must survive a power failure even when the store runs at `normal`. The
        // answer is the revocation's: a failure to lower `synchronous` again afterwards is
        // logged, not returned, because the revocation has committed (SR-51).
        let relaxed = self
            .durability
            .filter(|d| *d != Durability::Full)
            .map(Durability::level);
        self.lease_prune.lock()?.after_write(lease);
        with_full_sync(&mut conn, relaxed, |conn| {
            revoke_in(conn, lease, reason, now)
        })?
    }

    fn renew(
        &self,
        lease: &LeaseId,
        new_expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        self.lease_prune.lock()?.before_revival(lease)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        match get_in(&tx, lease)? {
            None => return Err(AuditError::UnknownLease(lease.0.clone())),
            Some(row) if row.revoked_at.is_some() => {
                return Err(AuditError::LeaseRevoked(lease.0.clone()))
            }
            Some(_) => {}
        }
        tx.execute(
            "UPDATE leases SET expires_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![lease.0, fmt_time(new_expires_at)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn is_active(&self, lease: &LeaseId, now: OffsetDateTime) -> Result<bool, AuditError> {
        let conn = self.conn.lock()?;
        Ok(get_in(&conn, lease)?.is_some_and(|r| r.is_active(now)))
    }

    fn bind(&self, lease: &LeaseId, binding: &str) -> Result<(), AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if get_in(&tx, lease)?.is_none() {
            return Err(AuditError::UnknownLease(lease.0.clone()));
        }
        match binding_in(&tx, lease)? {
            Some(b) if b == binding => {}
            Some(_) => return Err(AuditError::BindingConflict(lease.0.clone())),
            None => {
                tx.execute(
                    "INSERT INTO lease_bindings (id, binding) VALUES (?1, ?2)",
                    params![lease.0, binding],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn binding(&self, lease: &LeaseId) -> Result<Option<String>, AuditError> {
        let conn = self.conn.lock()?;
        binding_in(&conn, lease)
    }

    fn record_subject(&self, lease: &LeaseId, subject: &str) -> Result<(), AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if get_in(&tx, lease)?.is_none() {
            return Err(AuditError::UnknownLease(lease.0.clone()));
        }
        match subject_in(&tx, lease)? {
            Some(s) if s == subject => {}
            Some(_) => return Err(AuditError::BindingConflict(lease.0.clone())),
            None => {
                tx.prepare_cached("INSERT INTO lease_subjects (id, subject) VALUES (?1, ?2)")?
                    .execute(params![lease.0, subject])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn subject(&self, lease: &LeaseId) -> Result<Option<String>, AuditError> {
        let conn = self.conn.lock()?;
        subject_in(&conn, lease)
    }

    fn subjects(&self, leases: &[&LeaseId]) -> Result<BTreeMap<LeaseId, String>, AuditError> {
        let conn = self.conn.lock()?;
        subjects_in(&conn, leases)
    }

    fn record_session(
        &self,
        session: &str,
        server: &str,
        chain_id: &LeaseId,
        now: OffsetDateTime,
    ) -> Result<bool, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if get_in(&tx, chain_id)?.is_none() {
            return Err(AuditError::UnknownLease(chain_id.0.clone()));
        }
        let inserted = tx
            .prepare_cached(
                "INSERT OR IGNORE INTO lease_sessions (session, server, chain_id, bound_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![session, server, chain_id.0, fmt_time(now)?])?;
        tx.commit()?;
        Ok(inserted == 1)
    }

    fn sessions(&self, session: &str) -> Result<Vec<SessionBinding>, AuditError> {
        let conn = self.conn.lock()?;
        sessions_in(&conn, session)
    }

    fn prune_sessions(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<SessionPrune, AuditError> {
        let max_rows = max_rows.max(1);
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let mut cursor = self.session_cursor.lock()?;
        // One write transaction from the read on: a renewal cannot revive a chain between the
        // classification and the delete.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        type Seen = (i64, Option<String>, Option<String>);
        let seen: Vec<Seen> = tx
            .prepare_cached(
                "SELECT s.rowid, l.expires_at, l.revoked_at FROM lease_sessions s \
                 LEFT JOIN leases l ON l.id = s.chain_id \
                 WHERE s.rowid > ?1 ORDER BY s.rowid LIMIT ?2",
            )?
            .query_map(
                params![*cursor, i64::try_from(max_rows).unwrap_or(i64::MAX)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?
            .collect::<Result<_, _>>()?;
        let mut pruned = 0;
        {
            let mut delete = tx.prepare_cached("DELETE FROM lease_sessions WHERE rowid = ?1")?;
            for (rowid, expires_at, revoked_at) in &seen {
                let root = match expires_at {
                    None => None,
                    Some(at) => Some(LeaseRow {
                        parent: None,
                        expires_at: parse_time(at)?,
                        revoked_at: revoked_at.as_deref().map(parse_time).transpose()?,
                        revoke_reason: None,
                    }),
                };
                if session_prunable(root.as_ref(), now, retention) {
                    pruned += delete.execute([rowid])? as u64;
                }
            }
        }
        tx.commit()?;
        let wrapped = seen.len() < max_rows;
        *cursor = match seen.last() {
            Some((rowid, _, _)) if !wrapped => *rowid,
            _ => 0,
        };
        Ok(SessionPrune {
            examined: seen.len() as u64,
            pruned,
            wrapped,
        })
    }

    fn prune_leases(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<LeasePrune, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let mut state = self.lease_prune.lock()?;
        // One write transaction from the read on: a renewal cannot revive a run between the
        // check and the delete, and an exchange cannot register a child under a top being
        // deleted (it would need the top live, and then the top is kept). A run carried over
        // to the next pass is guarded by `state` (`before_revival`, `after_write`).
        let pass = (|| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let pass = prune_pass(
                &mut SqlitePrune { tx: &tx },
                &mut state,
                now,
                retention,
                max_rows,
            )?;
            tx.commit()?;
            Ok(pass)
        })();
        if pass.is_err() {
            state.abandon_sweep();
        }
        pass
    }

    fn prune_run_state(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<RunStatePrune, AuditError> {
        let max_rows = max_rows.max(1);
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let mut cursor = self.run_state_cursor.lock()?;
        // One write transaction from the read on: an exchange or a charge cannot slip in
        // between the check that a lease is gone and the delete.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut out = RunStatePrune::default();
        let mut budget = max_rows;
        let (mut phase, mut from) = *cursor;
        while budget > 0 {
            let limit = i64::try_from(budget).unwrap_or(i64::MAX);
            let seen: Vec<i64> = match phase {
                0 => {
                    // The charge log, decided per decision: its rows share one run.
                    let window: Vec<(i64, String)> = tx
                        .prepare_cached(
                            "SELECT rowid, decision_id FROM budget_charges \
                             WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
                        )?
                        .query_map(params![from, limit], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<Result<_, _>>()?;
                    let decisions: BTreeSet<&str> =
                        window.iter().map(|(_, d)| d.as_str()).collect();
                    for decision in decisions {
                        type Logged = (String, Option<String>, bool);
                        let rows: Vec<Logged> = tx
                            .prepare_cached(
                                "SELECT c.at, c.refunded_at, \
                                 EXISTS (SELECT 1 FROM leases l WHERE l.id = c.lease) \
                                 FROM budget_charges c WHERE c.decision_id = ?1",
                            )?
                            .query_map([decision], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                            .collect::<Result<_, _>>()?;
                        let mut lease_known = false;
                        let mut last: Option<OffsetDateTime> = None;
                        for (at, refunded_at, known) in &rows {
                            lease_known |= *known;
                            for t in std::iter::once(at).chain(refunded_at) {
                                let t = parse_time(t)?;
                                last = Some(last.map_or(t, |l| l.max(t)));
                            }
                        }
                        // Rows deleted earlier in this pass (another window row of it).
                        let Some(last) = last else { continue };
                        if run_state_prunable(lease_known, last, now, retention) {
                            tx.prepare_cached("DELETE FROM budget_charges WHERE decision_id = ?1")?
                                .execute([decision])?;
                            out.pruned_charges += 1;
                        }
                    }
                    window.into_iter().map(|(rowid, _)| rowid).collect()
                }
                1 => {
                    // A counter goes once its lease is gone and no charge under it is left.
                    let window: Vec<(i64, bool)> = tx
                        .prepare_cached(
                            "SELECT b.rowid, \
                             EXISTS (SELECT 1 FROM leases l WHERE l.id = b.lease) \
                             OR EXISTS (SELECT 1 FROM budget_charges c WHERE c.lease = b.lease) \
                             FROM budget_counters b WHERE b.rowid > ?1 ORDER BY b.rowid LIMIT ?2",
                        )?
                        .query_map(params![from, limit], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<Result<_, _>>()?;
                    let mut delete =
                        tx.prepare_cached("DELETE FROM budget_counters WHERE rowid = ?1")?;
                    for (rowid, kept) in &window {
                        if !kept {
                            out.pruned_counters += delete.execute([rowid])? as u64;
                        }
                    }
                    window.into_iter().map(|(rowid, _)| rowid).collect()
                }
                _ => {
                    type Seen = (i64, String, Option<String>, String, bool);
                    let window: Vec<Seen> = tx
                        .prepare_cached(
                            "SELECT a.rowid, a.created_at, a.decided_at, a.expires_at, \
                             EXISTS (SELECT 1 FROM leases l WHERE l.id = a.lease \
                                     OR l.id = a.chain_id) \
                             FROM approvals a WHERE a.rowid > ?1 ORDER BY a.rowid LIMIT ?2",
                        )?
                        .query_map(params![from, limit], |r| {
                            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                        })?
                        .collect::<Result<_, _>>()?;
                    let mut delete = tx.prepare_cached("DELETE FROM approvals WHERE rowid = ?1")?;
                    for (rowid, created_at, decided_at, expires_at, known) in &window {
                        let mut last = parse_time(created_at)?.max(parse_time(expires_at)?);
                        if let Some(d) = decided_at {
                            last = last.max(parse_time(d)?);
                        }
                        if run_state_prunable(*known, last, now, retention) {
                            out.pruned_approvals += delete.execute([rowid])? as u64;
                        }
                    }
                    window.into_iter().map(|(rowid, ..)| rowid).collect()
                }
            };
            out.examined += seen.len() as u64;
            if seen.len() < budget {
                // The end of this table: on to the next one, or back to the first.
                if phase >= 2 {
                    (phase, from) = (0, 0);
                    out.wrapped = true;
                    break;
                }
                (phase, from) = (phase + 1, 0);
            } else {
                from = *seen.last().expect("a full window");
            }
            budget -= seen.len();
        }
        tx.commit()?;
        *cursor = (phase, from);
        Ok(out)
    }

    fn preview_selected(&self, selector: &LeaseSelector) -> Result<SelectorRevocation, AuditError> {
        let mut conn = self.conn.lock()?;
        selected_in(&mut conn, selector, None)
    }

    fn revoke_selected(
        &self,
        selector: &LeaseSelector,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<SelectorRevocation, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        // Synced like a single revocation (SR-51).
        let relaxed = self
            .durability
            .filter(|d| *d != Durability::Full)
            .map(Durability::level);
        let out = with_full_sync(&mut conn, relaxed, |conn| {
            selected_in(conn, selector, Some((reason, now)))
        })??;
        let mut prune = self.lease_prune.lock()?;
        for id in &out.revoked {
            prune.after_write(id);
        }
        Ok(out)
    }

    fn check_all(
        &self,
        leases: &[&LeaseId],
        now: OffsetDateTime,
    ) -> Result<LeaseStatus, AuditError> {
        let rows = {
            let conn = self.conn.lock()?;
            rows_in(&conn, leases)?
        };
        // A chain has a handful of leases: a linear scan beats hashing them.
        classify(leases, now, |id| {
            Ok(rows
                .iter()
                .find(|(r, _)| *r == id.0)
                .map(|(_, row)| row.clone()))
        })
    }

    fn add_label(&self, chain_id: &LeaseId, label: &RunLabel) -> Result<(), AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if get_in(&tx, chain_id)?.is_none() {
            return Err(AuditError::UnknownLease(chain_id.0.clone()));
        }
        let seq = i64::try_from(label.seq)
            .map_err(|_| AuditError::Storage(format!("label seq {} out of range", label.seq)))?;
        tx.prepare_cached(
            // One row per source: the label with the smallest seq wins.
            "INSERT INTO run_labels (chain_id, source, decision_id, seq, at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (chain_id, source) DO UPDATE SET \
               decision_id = excluded.decision_id, seq = excluded.seq, at = excluded.at \
             WHERE excluded.seq < run_labels.seq",
        )?
        .execute(params![
            chain_id.0,
            label.source,
            label.decision_id,
            seq,
            fmt_time(label.at)?
        ])?;
        tx.commit()?;
        Ok(())
    }

    fn labels(&self, chain_id: &LeaseId) -> Result<Vec<RunLabel>, AuditError> {
        let conn = self.conn.lock()?;
        // One row per source, already the first (see `add_label`).
        let mut stmt = conn.prepare_cached(
            "SELECT source, decision_id, seq, at FROM run_labels WHERE chain_id = ?1 \
             ORDER BY seq",
        )?;
        let rows = stmt.query_map(params![chain_id.0], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (source, decision_id, seq, at) = row?;
            let seq = u64::try_from(seq)
                .map_err(|_| AuditError::Storage(format!("label seq {seq} out of range")))?;
            out.push(RunLabel {
                source,
                decision_id,
                seq,
                at: parse_time(&at)?,
            });
        }
        Ok(out)
    }

    fn add_spans(
        &self,
        chain_id: &LeaseId,
        seq: u64,
        spans: &[Fingerprint],
    ) -> Result<(), AuditError> {
        let seq = i64::try_from(seq)
            .map_err(|_| AuditError::Storage(format!("span seq {seq} out of range")))?;
        let mut hashes = distinct_hashes(&self.span_key, spans);
        hashes.truncate(MAX_SPANS_PER_RUN);
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if get_in(&tx, chain_id)?.is_none() {
            return Err(AuditError::UnknownLease(chain_id.0.clone()));
        }
        if hashes.is_empty() {
            return Ok(());
        }
        let stored: Vec<(u64, usize)> = tx
            .prepare_cached(
                "SELECT seq, COUNT(*) FROM run_spans WHERE chain_id = ?1 GROUP BY seq ORDER BY seq",
            )?
            .query_map(params![chain_id.0], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })?
            .map(|row| {
                let (s, n) = row?;
                Ok((
                    u64::try_from(s).unwrap_or_default(),
                    usize::try_from(n).unwrap_or_default(),
                ))
            })
            .collect::<Result<_, AuditError>>()?;
        {
            let mut delete =
                tx.prepare_cached("DELETE FROM run_spans WHERE chain_id = ?1 AND seq = ?2")?;
            for old in evictions(&stored, hashes.len()) {
                delete.execute(params![chain_id.0, i64::try_from(old).unwrap_or(i64::MAX)])?;
            }
            delete.execute(params![chain_id.0, seq])?;
            let mut insert = tx.prepare_cached(
                "INSERT OR IGNORE INTO run_spans (chain_id, hash, seq) VALUES (?1, ?2, ?3)",
            )?;
            for h in &hashes {
                insert.execute(params![chain_id.0, &h[..], seq])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn find_spans(
        &self,
        chain_id: &LeaseId,
        probes: &[Fingerprint],
    ) -> Result<Vec<SpanHit>, AuditError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        let mut hits = Vec::new();
        {
            let mut stmt = tx.prepare_cached(
                "SELECT seq FROM run_spans WHERE chain_id = ?1 AND hash = ?2 ORDER BY seq LIMIT ?3",
            )?;
            let limit = i64::try_from(MAX_SEQS_PER_PROBE).unwrap_or(i64::MAX);
            for (probe, f) in probes.iter().enumerate() {
                let h = self.span_key.hash(f);
                let seqs =
                    stmt.query_map(params![chain_id.0, &h[..], limit], |r| r.get::<_, i64>(0))?;
                for seq in seqs {
                    let seq = seq?;
                    let seq = u64::try_from(seq)
                        .map_err(|_| AuditError::Storage(format!("span seq {seq} out of range")))?;
                    hits.push(SpanHit { probe, seq });
                }
            }
        }
        tx.commit()?;
        Ok(hits)
    }

    fn create_approval(&self, approval: &Approval) -> Result<(Approval, bool), AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = approval.created_at;
        let lease_expiry =
            rules::live_lease(&approval.lease, get_in(&tx, &approval.lease)?.as_ref(), now)?;
        if let Some(existing) = approvals_for_call(
            &tx,
            &approval.chain_id,
            &approval.call_hash,
            ApprovalState::Pending,
        )?
        .into_iter()
        .find(|a| rules::reusable(a, approval, now))
        {
            return Ok((existing, false));
        }
        let pending = pending_of_run(&tx, &approval.chain_id, now)?;
        rules::below_pending_cap(&approval.chain_id, pending)?;
        let mut stored = approval.clone();
        stored.state = ApprovalState::Pending;
        stored.approver = None;
        stored.decided_at = None;
        stored.consumed_by = None;
        stored.expires_at = stored.expires_at.min(lease_expiry);
        tx.prepare_cached(
            "INSERT INTO approvals (id, chain_id, lease, call_hash, server, tool, arguments, \
             labels, decision_id, chain, created_at, expires_at, state, jkt, untrusted_args) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        )?
        .execute(params![
            stored.id,
            stored.chain_id.0,
            stored.lease.0,
            stored.call_hash,
            stored.server,
            stored.tool,
            serde_json::to_string(&stored.arguments)?,
            serde_json::to_string(&stored.labels)?,
            stored.decision_id,
            serde_json::to_string(&stored.chain)?,
            fmt_time(stored.created_at)?,
            fmt_time(stored.expires_at)?,
            stored.state.as_str(),
            stored.jkt,
            (!stored.untrusted_args.is_empty())
                .then(|| serde_json::to_string(&stored.untrusted_args))
                .transpose()?,
        ])?;
        tx.commit()?;
        Ok((stored, true))
    }

    fn approval(&self, id: &str) -> Result<Option<Approval>, AuditError> {
        let conn = self.conn.lock()?;
        approval_in(&conn, id)
    }

    fn approvals(
        &self,
        chain_id: Option<&LeaseId>,
        limit: usize,
    ) -> Result<Vec<Approval>, AuditError> {
        let conn = self.conn.lock()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        // `rowid` follows insertion order, which is creation order.
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {APPROVAL_COLUMNS} FROM approvals \
             WHERE ?1 IS NULL OR chain_id = ?1 ORDER BY rowid DESC LIMIT ?2"
        ))?;
        let mut rows = stmt.query(params![chain_id.map(|c| c.0.as_str()), limit])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(approval_from_row(r)?);
        }
        Ok(out)
    }

    fn decide_approval(
        &self,
        id: &str,
        grant: bool,
        approver: &Approver,
        now: OffsetDateTime,
    ) -> Result<Approval, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut a =
            approval_in(&tx, id)?.ok_or_else(|| AuditError::UnknownApproval(id.to_owned()))?;
        rules::decidable(&a, now)?;
        rules::live_lease(&a.lease, get_in(&tx, &a.lease)?.as_ref(), now)?;
        a.state = if grant {
            ApprovalState::Granted
        } else {
            ApprovalState::Declined
        };
        a.approver = Some(approver.clone());
        a.decided_at = Some(now);
        tx.execute(
            "UPDATE approvals SET state = ?2, approver_subject = ?3, approver_method = ?4, \
             decided_at = ?5 WHERE id = ?1 AND state = 'pending'",
            params![
                id,
                a.state.as_str(),
                approver.subject,
                approver.method.as_str(),
                fmt_time(now)?
            ],
        )?;
        tx.commit()?;
        Ok(a)
    }

    fn take_approval(
        &self,
        chain_id: &LeaseId,
        lease: &LeaseId,
        call_hash: &str,
        decision_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Approval>, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if rules::live_lease(lease, get_in(&tx, lease)?.as_ref(), now).is_err() {
            return Ok(None);
        }
        let Some(mut a) = approvals_for_call(&tx, chain_id, call_hash, ApprovalState::Granted)?
            .into_iter()
            .filter(|a| rules::usable(a, chain_id, lease, call_hash, now))
            .min_by(|a, b| a.created_at.cmp(&b.created_at))
        else {
            return Ok(None);
        };
        let changed = tx.execute(
            "UPDATE approvals SET state = 'consumed', consumed_by = ?2 \
             WHERE id = ?1 AND state = 'granted'",
            params![a.id, decision_id],
        )?;
        if changed != 1 {
            return Ok(None);
        }
        tx.commit()?;
        a.state = ApprovalState::Consumed;
        a.consumed_by = Some(decision_id.to_owned());
        Ok(Some(a))
    }

    fn take_approval_by_id(
        &self,
        id: &str,
        chain_id: &LeaseId,
        lease: &LeaseId,
        call_hash: &str,
        decision_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Approval>, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if rules::live_lease(lease, get_in(&tx, lease)?.as_ref(), now).is_err() {
            return Ok(None);
        }
        let Some(mut a) =
            approval_in(&tx, id)?.filter(|a| rules::usable(a, chain_id, lease, call_hash, now))
        else {
            return Ok(None);
        };
        let changed = tx.execute(
            "UPDATE approvals SET state = 'consumed', consumed_by = ?2 \
             WHERE id = ?1 AND state = 'granted'",
            params![a.id, decision_id],
        )?;
        if changed != 1 {
            return Ok(None);
        }
        tx.commit()?;
        a.state = ApprovalState::Consumed;
        a.consumed_by = Some(decision_id.to_owned());
        Ok(Some(a))
    }

    fn restore_approval(&self, id: &str, decision_id: &str) -> Result<(), AuditError> {
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        conn.execute(
            "UPDATE approvals SET state = 'granted', consumed_by = NULL \
             WHERE id = ?1 AND state = 'consumed' AND consumed_by = ?2",
            params![id, decision_id],
        )?;
        Ok(())
    }

    fn remove_approval(&self, id: &str) -> Result<(), AuditError> {
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        conn.execute("DELETE FROM approvals WHERE id = ?1", params![id])?;
        Ok(())
    }

    fn budget_used(&self, charges: &[Charge]) -> Result<Vec<u64>, AuditError> {
        let keys = charges
            .iter()
            .map(|c| self.value_key.counter(c))
            .collect::<Result<Vec<_>, _>>()?;
        let mut conn = self.conn.lock()?;
        // One read transaction, so every counter is read at the same moment.
        let tx = conn.transaction()?;
        keys.iter().map(|k| counter_in(&tx, k)).collect()
    }

    fn charge(
        &self,
        decision_id: &str,
        charges: &[Charge],
        at: OffsetDateTime,
    ) -> Result<ChargeOutcome, AuditError> {
        self.charge_with(decision_id, charges, at, false)
            .map(|(outcome, _)| outcome)
    }

    /// Defers the sync of a `sum` charge on a file store below `durability = "full"`; any
    /// other charge commits exactly as [`charge`](LeaseStore::charge) does.
    fn charge_sync_deferred(
        &self,
        decision_id: &str,
        charges: &[Charge],
        at: OffsetDateTime,
    ) -> Result<(ChargeOutcome, bool), AuditError> {
        self.charge_with(decision_id, charges, at, true)
    }

    fn sync_file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    fn refund(&self, decision_id: &str, at: OffsetDateTime) -> Result<u64, AuditError> {
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        refund_in(&mut conn, decision_id, at)
    }

    fn record_hop_limits(&self, lease: &LeaseId, limits: &[HopLimit]) -> Result<(), AuditError> {
        let json = serde_json::to_string(limits)
            .map_err(|e| AuditError::Storage(format!("hop limits do not serialize: {e}")))?;
        let _gate = self.gate.hold();
        let conn = self.conn.lock()?;
        conn.prepare_cached(
            "INSERT INTO hop_limits (lease, limits) VALUES (?1, ?2) \
             ON CONFLICT (lease) DO UPDATE SET limits = excluded.limits",
        )?
        .execute(params![lease.0, json])?;
        Ok(())
    }

    fn hop_limits(&self, lease: &LeaseId) -> Result<Option<Vec<HopLimit>>, AuditError> {
        let conn = self.conn.lock()?;
        let json: Option<String> = conn
            .prepare_cached("SELECT limits FROM hop_limits WHERE lease = ?1")?
            .query_row([&lease.0], |r| r.get(0))
            .optional()?;
        json.map(|j| {
            serde_json::from_str(&j)
                .map_err(|e| AuditError::Storage(format!("hop limits of `{}`: {e}", lease.0)))
        })
        .transpose()
    }

    fn budget_summary(&self, lease: &LeaseId) -> Result<Vec<CounterSummary>, AuditError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT cap, kind, arg, value, used FROM budget_counters WHERE lease = ?1",
        )?;
        let rows = stmt
            .query_map([&lease.0], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut keyed = Vec::with_capacity(rows.len());
        for (cap, kind, arg, value, used) in rows {
            // A kind this version does not know is skipped rather than failing the read.
            let Some(kind) = kind_static(&kind) else {
                continue;
            };
            let key = CounterKey {
                lease: lease.0.clone(),
                cap,
                kind,
                arg,
                value,
            };
            keyed.push((key, u64::try_from(used).unwrap_or(0)));
        }
        Ok(summarize(keyed.iter().map(|(k, v)| (k, *v))))
    }
}

#[cfg(test)]
impl SqliteLeaseStore {
    /// Log every charge that commits (with its `synchronous` level) into `log`.
    pub(super) fn with_probe(mut self, log: Arc<Mutex<Vec<String>>>) -> Self {
        self.probe = Some(log);
        self
    }
}
