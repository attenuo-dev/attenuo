//! Audit retention (ADR-0015): pruning a prefix of the log at a signed checkpoint, behind a
//! signed [`Anchor`], and verifying a pruned log.
//!
//! A prune through `B` is one short transaction on the writer connection, under the write
//! gate, committed with `synchronous=FULL` ([`SqliteAudit::prune_through`]): the guards are
//! checked again, a checkpoint of the head `H` is signed if it has none (the "before"
//! checkpoint), the prune record is appended at `P = H + 1`, the anchor is signed over `B`,
//! the hash at `B`, `P` and `P`'s hash, a checkpoint at `P` is signed (the "after" checkpoint),
//! and the anchor row is inserted with `state = 'deleting'`. Only then are the rows at or
//! below `B` deleted, in batches of their own ([`SqliteAudit::prune_step`]), each a short
//! transaction under the gate; the last one deletes the checkpoints below `B` and sets the
//! anchor `done`. The batches run on the server's maintenance ticker, so a restart resumes them.
//!
//! From the commit on, every read clamps its lower bound to the newest anchor
//! ([`RETAINED`](super::log::RETAINED)), and verification reads the anchors in the same
//! snapshot as the head and the checkpoints. A prune therefore has two states only, before and
//! after, however the deletes are interrupted.

use attenuo_core::DecisionRecord;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::connection::with_full_sync;
use super::log::{checkpoint_at, checkpoint_from_row, head_link, insert_checkpoint, insert_entry};
use super::{parse_time, seq_to_i64, usize_to_i64, SqliteAudit};
use crate::checkpoint::{
    verify_with_checkpoints, Anchor, BadAnchor, Checkpoint, CheckpointKeys, SignedVerifyReport,
    Start,
};
use crate::error::AuditError;
use crate::log::{canonical_record_json, entry_hash_from_json, AuditEntry};

/// Where a prune's batched deletes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorState {
    /// The prune is committed (every read starts after `through_seq`) and the rows at or
    /// below `through_seq` are being deleted in batches.
    Deleting,
    /// Every row at or below `through_seq`, and every checkpoint below it, is deleted.
    Done,
}

impl AnchorState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deleting => "deleting",
            Self::Done => "done",
        }
    }
}

/// An anchor as stored, with the state of its deletes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAnchor {
    /// The signed anchor.
    #[serde(flatten)]
    pub anchor: Anchor,
    /// Where its batched deletes are.
    pub state: AnchorState,
    /// When `[audit.sink]` delivered the anchor (RFC 3339); `None` until then. The server
    /// queues an undelivered anchor again at start-up, and refuses the next prune with
    /// `sink_behind` until it is delivered.
    pub shipped_at: Option<String>,
}

/// Which guard refused a prune ([`AuditError::PruneRefused`]). Each has its own HTTP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneGuard {
    /// No signed checkpoint at the boundary, or one whose hash is not the entry's there.
    NotAtCheckpoint,
    /// The entry at the boundary is younger than the minimum age.
    TooRecent,
    /// A delegation chain whose root lease is still in the registry has a record at or below
    /// the boundary.
    LiveRun,
    /// The checkpoint sink is degraded or has not delivered a checkpoint at or after the
    /// boundary.
    SinkBehind,
    /// An earlier prune is still deleting its rows.
    InProgress,
    /// A prune through this boundary was already made with another archive digest.
    Conflict,
    /// The archive the request describes ([`PruneExpect`]) is not the prefix the prune
    /// removes: it does not start at the first retained seq, or its last entry is not the
    /// entry at the boundary. For a repeat, it does not match the stored anchor.
    ArchiveMismatch,
    /// The boundary is at or below the log's first retained seq already.
    AlreadyPruned,
}

impl PruneGuard {
    /// The stable code the server answers with.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotAtCheckpoint => "prune_not_at_checkpoint",
            Self::TooRecent => "prune_too_recent",
            Self::LiveRun => "prune_live_run",
            Self::SinkBehind => "sink_behind",
            Self::InProgress => "prune_in_progress",
            Self::Conflict => "prune_conflict",
            Self::ArchiveMismatch => "prune_archive_mismatch",
            Self::AlreadyPruned => "audit_pruned",
        }
    }
}

impl std::fmt::Display for PruneGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// How far the checkpoint sink has got, for the "sink caught up" guard. `None` in
/// [`PruneLimits::sink`] means there is no sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkProgress {
    /// The sink reports itself degraded (queue full, or lagging past its limit).
    pub degraded: bool,
    /// The highest checkpoint seq it has delivered, if any.
    pub delivered_through: Option<u64>,
}

/// The guards that do not come from the file itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneLimits {
    /// The entry at the boundary must be at least this old (`[audit.retention]
    /// min_age_seconds`).
    pub min_age: time::Duration,
    /// The checkpoint sink, when one is configured.
    pub sink: Option<SinkProgress>,
    /// The time the guards are checked at, and the prune record's and signatures' time.
    pub now: OffsetDateTime,
}

/// What the request says about the archive it kept, checked inside the prune's transaction
/// (both optional, for clients that send only `through` and `archive_sha256`). Without them
/// nothing ties the digest to the entries the prune removes: an archive of `1001..=2000`
/// would let a prune through 2000 remove `1..=1000` archived nowhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneExpect {
    /// The archive's first seq: must be the log's first retained seq (1, or the previous
    /// boundary + 1).
    pub from: Option<u64>,
    /// The archive's last entry hash: must be the entry hash at `through`.
    pub through_hash: Option<String>,
}

/// A committed prune: the anchor, the two checkpoints around the prune record, and whether
/// this call made it or found it made already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneOutcome {
    /// The anchor and its state.
    pub anchor: StoredAnchor,
    /// The checkpoint of the head before the prune record (`prune_seq - 1`).
    pub checkpoint_before: Option<Checkpoint>,
    /// The checkpoint at the prune record (`prune_seq`).
    pub checkpoint_after: Option<Checkpoint>,
    /// The same request was made before; nothing was written now.
    pub already: bool,
}

/// One batch of a prune's deletes ([`SqliteAudit::prune_step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PruneStep {
    /// The boundary of the prune whose rows were deleted; `None` when no prune is deleting.
    pub through_seq: Option<u64>,
    /// Entries deleted by this batch.
    pub deleted: u64,
    /// The prune is done: every row at or below its boundary is gone.
    pub done: bool,
}

/// What `GET /admin/audit/prune/plan` answers: the largest boundary the guards allow at or
/// below the one asked for, and which guard limited it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrunePlan {
    /// The first retained seq now (1 for a log never pruned): the archive starts here.
    pub from: u64,
    /// The boundary the guards allow, if any.
    pub through: Option<u64>,
    /// Entries a prune through `through` removes.
    pub entries: u64,
    /// The checkpoint at `through`.
    pub checkpoint: Option<Checkpoint>,
    /// The time of the entry at `through`.
    pub at: Option<String>,
    /// The bounds each guard sets, and the one that limited `through` below the request.
    pub guards: PlanGuards,
    /// The newest anchor, if the log was pruned before.
    pub anchor: Option<StoredAnchor>,
}

/// The bound each guard of a [`PrunePlan`] sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanGuards {
    /// The boundary asked for (the head when none was given).
    pub requested: u64,
    /// With `before`: entries at or after this time are kept.
    pub before: Option<String>,
    /// Entries newer than this time are too recent to prune (`min_age_seconds`).
    pub min_age_cutoff: String,
    /// The first record of a chain whose root lease is still in the registry; the boundary
    /// must be below it.
    pub live_run_seq: Option<u64>,
    /// The highest checkpoint seq the sink has delivered (`None` without a sink).
    pub sink_delivered_through: Option<u64>,
    /// The sink is degraded: nothing can be pruned until it recovers.
    pub sink_degraded: bool,
    /// A prune is still deleting: nothing can be pruned until it is done.
    pub in_progress: bool,
    /// With a sink: the anchor of the newest prune is not delivered yet, so nothing can be
    /// pruned until it is (`sink_behind`). False for a log never pruned or without a sink.
    pub anchor_undelivered: bool,
    /// What set `through` below `requested`: the refusal code of a guard, or `"before"` when
    /// it was the `before` time asked for; `None` when `through` is the request.
    pub limited_by: Option<&'static str>,
}

/// The boundary a plan is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanBound {
    /// Up to this seq.
    Through(u64),
    /// Entries older than this time.
    Before(OffsetDateTime),
}

/// `(page_count * page_size, freelist_count * page_size)` of the file `conn` reads.
fn db_size_of(conn: &Connection) -> Result<(u64, u64), AuditError> {
    let pragma = |name: &str| -> Result<u64, AuditError> {
        let v: i64 = conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?;
        Ok(u64_of(v))
    };
    let page = pragma("page_size")?;
    Ok((
        pragma("page_count")?.saturating_mul(page),
        pragma("freelist_count")?.saturating_mul(page),
    ))
}

const ANCHOR_COLUMNS: &str = "through_seq, through_hash, prune_seq, prune_entry_hash, \
                              previous_through_seq, archive_sha256, at, kid, signature, state, \
                              shipped_at";

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn anchor_from_row(row: &Row<'_>) -> rusqlite::Result<StoredAnchor> {
    let state: String = row.get(9)?;
    Ok(StoredAnchor {
        anchor: Anchor {
            through_seq: u64_of(row.get(0)?),
            through_hash: row.get(1)?,
            prune_seq: u64_of(row.get(2)?),
            prune_entry_hash: row.get(3)?,
            previous_through_seq: row.get::<_, Option<i64>>(4)?.map(u64_of),
            archive_sha256: row.get(5)?,
            at: row.get(6)?,
            kid: row.get(7)?,
            signature: row.get(8)?,
        },
        state: if state == "done" {
            AnchorState::Done
        } else {
            AnchorState::Deleting
        },
        shipped_at: row.get(10)?,
    })
}

/// Every stored anchor, oldest first.
pub(super) fn all_anchors(conn: &Connection) -> Result<Vec<StoredAnchor>, AuditError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {ANCHOR_COLUMNS} FROM audit_anchors ORDER BY through_seq"
    ))?;
    let rows = stmt.query_map([], anchor_from_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn newest_anchor(conn: &Connection) -> Result<Option<StoredAnchor>, AuditError> {
    Ok(conn
        .prepare_cached(&format!(
            "SELECT {ANCHOR_COLUMNS} FROM audit_anchors ORDER BY through_seq DESC LIMIT 1"
        ))?
        .query_row([], anchor_from_row)
        .optional()?)
}

fn anchor_at(conn: &Connection, through: u64) -> Result<Option<StoredAnchor>, AuditError> {
    let Ok(through) = i64::try_from(through) else {
        return Ok(None);
    };
    Ok(conn
        .prepare_cached(&format!(
            "SELECT {ANCHOR_COLUMNS} FROM audit_anchors WHERE through_seq = ?1"
        ))?
        .query_row([through], anchor_from_row)
        .optional()?)
}

fn deleting_anchor(conn: &Connection) -> Result<Option<StoredAnchor>, AuditError> {
    Ok(conn
        .prepare_cached(&format!(
            "SELECT {ANCHOR_COLUMNS} FROM audit_anchors WHERE state = 'deleting' \
             ORDER BY through_seq LIMIT 1"
        ))?
        .query_row([], anchor_from_row)
        .optional()?)
}

fn insert_anchor(conn: &Connection, a: &Anchor, state: AnchorState) -> Result<(), AuditError> {
    conn.execute(
        &format!(
            "INSERT INTO audit_anchors ({ANCHOR_COLUMNS}) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)"
        ),
        params![
            seq_to_i64(a.through_seq)?,
            a.through_hash,
            seq_to_i64(a.prune_seq)?,
            a.prune_entry_hash,
            a.previous_through_seq.map(seq_to_i64).transpose()?,
            a.archive_sha256,
            a.at,
            a.kid,
            a.signature,
            state.as_str(),
        ],
    )?;
    Ok(())
}

/// `(entry_hash, at)` of the entry at `seq`, read without decoding the record.
fn entry_link(conn: &Connection, seq: u64) -> Result<Option<(String, String)>, AuditError> {
    let Ok(seq) = i64::try_from(seq) else {
        return Ok(None);
    };
    Ok(conn
        .prepare_cached("SELECT entry_hash, at FROM audit WHERE seq = ?1")?
        .query_row([seq], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?)
}

/// The first record of any delegation chain whose root lease is still in the registry (the
/// `leases` table of the same file). One lookup per root lease, each the first entry of
/// `audit_chain_id_idx` for that chain (the index is ordered by `(chain_id, seq)`), so the cost
/// grows with the number of roots in the registry and not with the records of their chains.
/// It runs under the write gate in a prune. Its plan is pinned by a test.
pub(super) const LIVE_RUN_SQL: &str = "SELECT MIN((SELECT a.seq FROM audit a \
     WHERE a.chain_id = l.id ORDER BY a.seq LIMIT 1)) \
     FROM leases l WHERE l.parent IS NULL";

fn live_run_seq(conn: &Connection) -> Result<Option<u64>, AuditError> {
    let min: Option<i64> = conn
        .prepare_cached(LIVE_RUN_SQL)?
        .query_row([], |r| r.get(0))?;
    Ok(min.map(u64_of))
}

/// `now - min_age`, or the earliest time there is when that does not fit (a `min_age` of
/// centuries), so that nothing is old enough rather than a panic under the writer's lock.
fn age_cutoff(limits: &PruneLimits) -> OffsetDateTime {
    limits
        .now
        .checked_sub(limits.min_age)
        .unwrap_or(time::PrimitiveDateTime::MIN.assume_utc())
}

fn refused(guard: PruneGuard, detail: impl Into<String>) -> AuditError {
    AuditError::PruneRefused {
        guard,
        detail: detail.into(),
    }
}

fn fmt_utc(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(t)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Check every guard on `through` that the file decides, plus the sink, inside the caller's
/// transaction. `Ok` carries the checkpoint at `through`.
/// Refuse with [`PruneGuard::ArchiveMismatch`] when `expect` names another first seq than
/// `first` or another hash at `through` than `hash`; `what` names what was compared.
fn check_expect(
    expect: &PruneExpect,
    first: u64,
    through: u64,
    hash: &str,
    what: &str,
) -> Result<(), AuditError> {
    if let Some(from) = expect.from.filter(|f| *f != first) {
        return Err(refused(
            PruneGuard::ArchiveMismatch,
            format!(
                "the archive starts at seq {from}, but {what} starts at seq {first}: the \
                 entries before seq {from} would be pruned without being archived"
            ),
        ));
    }
    if let Some(h) = expect.through_hash.as_deref().filter(|h| *h != hash) {
        return Err(refused(
            PruneGuard::ArchiveMismatch,
            format!(
                "the archive's last entry hash {h} is not the entry hash at seq {through} in \
                 {what} ({hash})"
            ),
        ));
    }
    Ok(())
}

fn check_guards(
    conn: &Connection,
    through: u64,
    floor: u64,
    limits: &PruneLimits,
) -> Result<Checkpoint, AuditError> {
    // Below the boundary is gone whatever else holds, so it is answered first.
    if through <= floor {
        return Err(refused(
            PruneGuard::AlreadyPruned,
            format!(
                "the log is already pruned through seq {floor}; its first retained seq is {}",
                floor + 1
            ),
        ));
    }
    if let Some(a) = deleting_anchor(conn)? {
        return Err(refused(
            PruneGuard::InProgress,
            format!(
                "the prune through seq {} is still deleting its rows; try again once it is done",
                a.anchor.through_seq
            ),
        ));
    }
    let cp = checkpoint_at(conn, through)?;
    let link = entry_link(conn, through)?;
    let (cp, at) = match (cp, link) {
        (Some(cp), Some((hash, at))) if cp.head_hash == hash => (cp, at),
        _ => {
            return Err(refused(
                PruneGuard::NotAtCheckpoint,
                format!(
                    "seq {through} has no signed checkpoint that matches its entry; ask \
                     GET /admin/audit/prune/plan for a boundary at a checkpoint"
                ),
            ))
        }
    };
    let at = parse_time(&at)?;
    if at > age_cutoff(limits) {
        return Err(refused(
            PruneGuard::TooRecent,
            format!(
                "the entry at seq {through} was written at {}, less than [audit.retention] \
                 min_age_seconds ({}) ago",
                fmt_utc(at),
                limits.min_age.whole_seconds()
            ),
        ));
    }
    if let Some(live) = live_run_seq(conn)?.filter(|&l| l <= through) {
        return Err(refused(
            PruneGuard::LiveRun,
            format!(
                "seq {live} belongs to a delegation chain whose root lease is still in the \
                 registry; prune below it"
            ),
        ));
    }
    if let Some(sink) = limits.sink {
        // The anchor of the prune before must be off the host before another prune: it is
        // the only record of where the log starts that is not in this file.
        if let Some(prev) = newest_anchor(conn)?.filter(|a| a.shipped_at.is_none()) {
            return Err(refused(
                PruneGuard::SinkBehind,
                format!(
                    "[audit.sink] has not delivered the anchor of the prune through seq {} yet; \
                     try again once it has",
                    prev.anchor.through_seq
                ),
            ));
        }
        if sink.degraded || sink.delivered_through.is_none_or(|d| d < through) {
            return Err(refused(
                PruneGuard::SinkBehind,
                format!(
                    "[audit.sink] has not delivered a checkpoint at or after seq {through} \
                     (delivered through {}{}); try again once it has",
                    sink.delivered_through
                        .map_or_else(|| "none".to_string(), |d| d.to_string()),
                    if sink.degraded { ", degraded" } else { "" }
                ),
            ));
        }
    }
    Ok(cp)
}

impl SqliteAudit {
    /// The last seq pruned (the newest anchor's `through_seq`), or `None` for a log never
    /// pruned.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the query fails.
    pub fn pruned_through(&self) -> Result<Option<u64>, AuditError> {
        let conn = self.read_conn()?;
        Ok(newest_anchor(&conn)?.map(|a| a.anchor.through_seq))
    }

    /// The first seq every read starts at: one above [`pruned_through`](Self::pruned_through),
    /// 1 for a log never pruned.
    ///
    /// # Errors
    ///
    /// As [`pruned_through`](Self::pruned_through).
    pub fn first_retained_seq(&self) -> Result<u64, AuditError> {
        Ok(self.pruned_through()?.map_or(1, |b| b.saturating_add(1)))
    }

    /// The newest anchor and its state, if the log was ever pruned.
    ///
    /// # Errors
    ///
    /// As [`pruned_through`](Self::pruned_through).
    pub fn newest_anchor(&self) -> Result<Option<StoredAnchor>, AuditError> {
        let conn = self.read_conn()?;
        newest_anchor(&conn)
    }

    /// Up to `limit` anchors with `through_seq < before`, newest first.
    ///
    /// # Errors
    ///
    /// As [`pruned_through`](Self::pruned_through).
    pub fn anchors_before(
        &self,
        before: u64,
        limit: usize,
    ) -> Result<Vec<StoredAnchor>, AuditError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {ANCHOR_COLUMNS} FROM audit_anchors WHERE through_seq < ?1 \
             ORDER BY through_seq DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(
            params![
                i64::try_from(before).unwrap_or(i64::MAX),
                usize_to_i64(limit)
            ],
            anchor_from_row,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The anchors `[audit.sink]` has not delivered yet (`shipped_at` null), oldest first: the
    /// server queues them again at start-up.
    ///
    /// # Errors
    ///
    /// As [`pruned_through`](Self::pruned_through).
    pub fn unshipped_anchors(&self) -> Result<Vec<StoredAnchor>, AuditError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {ANCHOR_COLUMNS} FROM audit_anchors WHERE shipped_at IS NULL \
             ORDER BY through_seq"
        ))?;
        let rows = stmt.query_map([], anchor_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Record that `[audit.sink]` delivered the anchor through `through_seq` at `at`. Only the
    /// first delivery is kept; an unknown anchor changes nothing. `shipped_at` is not signed:
    /// it only drives the re-queueing and the `sink_behind` guard.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the update fails.
    pub fn mark_anchor_shipped(
        &self,
        through_seq: u64,
        at: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let conn = self.inner.conn.lock()?;
        let _gate = self.inner.gate.hold();
        conn.execute(
            "UPDATE audit_anchors SET shipped_at = ?2 \
             WHERE through_seq = ?1 AND shipped_at IS NULL",
            params![seq_to_i64(through_seq)?, fmt_utc(at)],
        )?;
        Ok(())
    }

    /// The size of the database file as SQLite sees it, `(page_count * page_size,
    /// freelist_count * page_size)` in bytes: the second is the part a `DELETE` freed, which
    /// new rows reuse; the file does not shrink without `VACUUM`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when a pragma cannot be read.
    pub fn db_size(&self) -> Result<(u64, u64), AuditError> {
        let conn = self.read_conn()?;
        db_size_of(&conn)
    }

    /// [`db_size`](Self::db_size) when the connection it reads is free now; `Ok(None)` when
    /// a read (a whole-log verify, an export page) or, for an in-memory store, a write holds
    /// it. Never waits, so a metrics scrape cannot queue behind a long read or an append.
    ///
    /// # Errors
    ///
    /// As [`db_size`](Self::db_size).
    pub fn try_db_size(&self) -> Result<Option<(u64, u64)>, AuditError> {
        let lock = match &self.reader {
            Some(r) => r.try_lock(),
            None => self.inner.conn.try_lock(),
        };
        match lock {
            Ok(conn) => db_size_of(&conn).map(Some),
            Err(std::sync::TryLockError::WouldBlock) => Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => Err(AuditError::Poisoned),
        }
    }

    /// The largest boundary the guards allow at or below `bound` (see [`PrunePlan`]). Reads
    /// only. A log with nothing to prune answers `through: None`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when a query fails, and [`AuditError::TimeParse`] when a stored
    /// time does not parse.
    pub fn prune_plan(
        &self,
        bound: PlanBound,
        limits: &PruneLimits,
    ) -> Result<PrunePlan, AuditError> {
        self.plan_with_scan(bound, limits, PLAN_SCAN)
    }

    /// Tests: [`prune_plan`](Self::prune_plan) looking at most `scan` checkpoints.
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn prune_plan_with_scan(
        &self,
        bound: PlanBound,
        limits: &PruneLimits,
        scan: i64,
    ) -> Result<PrunePlan, AuditError> {
        self.plan_with_scan(bound, limits, scan)
    }

    fn plan_with_scan(
        &self,
        bound: PlanBound,
        limits: &PruneLimits,
        scan: i64,
    ) -> Result<PrunePlan, AuditError> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let anchor = newest_anchor(&tx)?;
        let floor = anchor.as_ref().map_or(0, |a| a.anchor.through_seq);
        let head = head_link(&tx)?.0;
        let (requested, before) = match bound {
            PlanBound::Through(b) => (b.min(head), None),
            PlanBound::Before(t) => (head, Some(t)),
        };
        let cutoff = age_cutoff(limits);
        let live = live_run_seq(&tx)?;
        let in_progress = deleting_anchor(&tx)?.is_some();
        let sink = limits.sink;
        let anchor_undelivered =
            sink.is_some() && anchor.as_ref().is_some_and(|a| a.shipped_at.is_none());
        let mut guards = PlanGuards {
            requested,
            before: before.map(fmt_utc),
            min_age_cutoff: fmt_utc(cutoff),
            live_run_seq: live,
            sink_delivered_through: sink.and_then(|s| s.delivered_through),
            sink_degraded: sink.is_some_and(|s| s.degraded),
            in_progress,
            anchor_undelivered,
            limited_by: None,
        };
        // The bounds that do not depend on the entry's time, tightest first.
        let mut upper = requested;
        let mut limit = |bound: u64, code: &'static str, upper: &mut u64| {
            if bound < *upper {
                *upper = bound;
                guards.limited_by = Some(code);
            }
        };
        if in_progress {
            limit(0, PruneGuard::InProgress.code(), &mut upper);
        }
        if let Some(s) = sink {
            let delivered = if s.degraded || anchor_undelivered {
                0
            } else {
                s.delivered_through.unwrap_or(0)
            };
            limit(delivered, PruneGuard::SinkBehind.code(), &mut upper);
        }
        if let Some(l) = live {
            limit(l.saturating_sub(1), PruneGuard::LiveRun.code(), &mut upper);
        }
        // The newest entry that is old enough (and older than `before`), found by a binary
        // search on seq, so that the checkpoint scan below starts near it and not at the head
        // of a busy log. Entry times are in seq order but for clock steps; the scan checks
        // each checkpoint's own entry again, so a step can only make the plan smaller.
        if upper > floor {
            let old_enough = |seq: u64| -> Result<Option<&'static str>, AuditError> {
                let Some((_, at)) = entry_link(&tx, seq)? else {
                    return Ok(Some(PruneGuard::NotAtCheckpoint.code()));
                };
                let t = parse_time(&at)?;
                Ok(if t > cutoff {
                    Some(PruneGuard::TooRecent.code())
                } else if before.is_some_and(|b| t >= b) {
                    Some("before")
                } else {
                    None
                })
            };
            if let Some(code) = old_enough(upper)? {
                let (mut lo, mut hi) = (floor, upper - 1);
                // The largest seq in (floor, upper) that is old enough, or `floor`.
                while lo < hi {
                    let mid = lo + (hi - lo).div_ceil(2);
                    if old_enough(mid)?.is_none() {
                        lo = mid;
                    } else {
                        hi = mid - 1;
                    }
                }
                limit(lo, code, &mut upper);
            }
        }
        // The newest checkpoint at or below `upper` that matches its entry and is old
        // enough (and older than `before`). Why the first one looked at was passed over says
        // which guard limited the plan, unless a bound above did already.
        let mut found: Option<(Checkpoint, String)> = None;
        let mut passed_over: Option<&'static str> = None;
        if upper > floor {
            let mut stmt = tx.prepare_cached(
                "SELECT c.seq, c.head_hash, c.at, c.kid, c.signature, a.entry_hash, a.at \
                 FROM checkpoints c JOIN audit a ON a.seq = c.seq \
                 WHERE c.seq <= ?1 AND c.seq > ?2 ORDER BY c.seq DESC LIMIT ?3",
            )?;
            let mut rows = stmt.query(params![
                i64::try_from(upper).unwrap_or(i64::MAX),
                i64::try_from(floor).unwrap_or(i64::MAX),
                scan
            ])?;
            while let Some(row) = rows.next()? {
                let cp = checkpoint_from_row(row)?;
                let hash: String = row.get(5)?;
                let at: String = row.get(6)?;
                let t = parse_time(&at)?;
                let why = if hash != cp.head_hash {
                    Some(PruneGuard::NotAtCheckpoint.code())
                } else if t > cutoff {
                    Some(PruneGuard::TooRecent.code())
                } else if before.is_some_and(|b| t >= b) {
                    Some("before")
                } else {
                    None
                };
                match why {
                    None => {
                        if cp.seq < upper {
                            passed_over.get_or_insert(PruneGuard::NotAtCheckpoint.code());
                        }
                        found = Some((cp, at));
                        break;
                    }
                    Some(code) => {
                        passed_over.get_or_insert(code);
                    }
                }
            }
        }
        if guards.limited_by.is_none() {
            guards.limited_by = passed_over.or_else(|| {
                found.is_none().then_some(if upper <= floor {
                    PruneGuard::AlreadyPruned.code()
                } else {
                    PruneGuard::NotAtCheckpoint.code()
                })
            });
        }
        let through = found.as_ref().map(|(cp, _)| cp.seq);
        if through == Some(requested) {
            guards.limited_by = None;
        }
        drop(tx);
        Ok(PrunePlan {
            from: floor + 1,
            entries: through.map_or(0, |t| t - floor),
            through,
            at: found.as_ref().map(|(_, at)| at.clone()),
            checkpoint: found.map(|(cp, _)| cp),
            guards,
            anchor,
        })
    }

    /// Prune the log through `through` (see the module docs): check the guards, sign the
    /// "before" checkpoint if the head has none, append the prune record that `record` builds
    /// from the prune's arguments (its `seq` is the head plus one; [`Anchor::prune_arguments`]
    /// gives the arguments it must hold the digest of), sign the anchor and the "after"
    /// checkpoint, and store the anchor as `deleting`, in one transaction committed with
    /// `synchronous=FULL`. The checkpoint hook then sees both checkpoints and the anchor hook
    /// the anchor. The rows are deleted later, by [`prune_step`](Self::prune_step).
    ///
    /// Repeating a request that succeeded (the same `through` and `archive_sha256`) answers
    /// with the stored anchor and `already: true`, and writes nothing.
    ///
    /// # Errors
    ///
    /// [`AuditError::PruneRefused`] naming the guard that refused it (nothing is written);
    /// [`AuditError::NoCheckpointSigner`] without [`with_checkpointing`](Self::with_checkpointing);
    /// [`AuditError::Corrupt`] when a stored checkpoint at the head disagrees with the log;
    /// [`AuditError::Poisoned`], [`AuditError::Sqlite`], [`AuditError::TimeFormat`] or
    /// [`AuditError::TimeParse`] when the store fails (the transaction rolls back).
    pub fn prune_through(
        &self,
        through: u64,
        archive_sha256: Option<String>,
        limits: &PruneLimits,
        record: impl FnOnce(&Value) -> DecisionRecord,
    ) -> Result<PruneOutcome, AuditError> {
        self.prune_through_expecting(
            through,
            archive_sha256,
            &PruneExpect::default(),
            limits,
            record,
        )
    }

    /// [`Self::prune_through`], refusing with [`PruneGuard::ArchiveMismatch`] unless the
    /// archive `expect` describes is the prefix the prune removes: `expect.from` is the first
    /// retained seq and `expect.through_hash` the entry hash at `through`, both checked inside
    /// the transaction. A repeat of a request that succeeded compares them with the stored
    /// anchor (`previous_through_seq + 1`, or 1, and `through_hash`).
    ///
    /// # Errors
    ///
    /// As [`Self::prune_through`], and [`AuditError::PruneRefused`] with
    /// [`PruneGuard::ArchiveMismatch`].
    pub fn prune_through_expecting(
        &self,
        through: u64,
        archive_sha256: Option<String>,
        expect: &PruneExpect,
        limits: &PruneLimits,
        record: impl FnOnce(&Value) -> DecisionRecord,
    ) -> Result<PruneOutcome, AuditError> {
        #[cfg(any(test, feature = "testing"))]
        self.run_prune_hook();
        let c = self
            .inner
            .checkpointing
            .as_ref()
            .ok_or(AuditError::NoCheckpointSigner)?;
        let mut conn = self.inner.conn.lock()?;
        let gate = self.inner.gate.hold();
        // One key for the prune's two checkpoints and its anchor, even if the key is swapped
        // meanwhile ([`SqliteAudit::set_checkpoint_signer`]).
        let signer = c.signer();
        let now = limits.now;
        let done = with_full_sync(&mut conn, self.inner.relaxed_sync, |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // A repeat of a request that succeeded.
            if let Some(existing) = anchor_at(&tx, through)? {
                let a = &existing.anchor;
                check_expect(
                    expect,
                    a.previous_through_seq.map_or(1, |p| p + 1),
                    through,
                    &a.through_hash,
                    "the stored prune through this seq",
                )?;
                if existing.anchor.archive_sha256 == archive_sha256 {
                    let p = existing.anchor.prune_seq;
                    let out = PruneOutcome {
                        checkpoint_before: checkpoint_at(&tx, p.saturating_sub(1))?,
                        checkpoint_after: checkpoint_at(&tx, p)?,
                        anchor: existing,
                        already: true,
                    };
                    return Ok::<_, AuditError>((out, None, None));
                }
                return Err(refused(
                    PruneGuard::Conflict,
                    format!(
                        "the log was already pruned through seq {through} with another \
                         archive_sha256"
                    ),
                ));
            }
            // 1. The guards, again, inside the transaction.
            let previous = newest_anchor(&tx)?.map(|a| a.anchor.through_seq);
            let cp_b = check_guards(&tx, through, previous.unwrap_or(0), limits)?;
            check_expect(
                expect,
                previous.map_or(1, |p| p + 1),
                through,
                &cp_b.head_hash,
                "the log",
            )?;
            self.fail_prune_at(1)?;
            // 2. The "before" checkpoint of the head, if it has none.
            let (head, head_hash) = head_link(&tx)?;
            let before = match checkpoint_at(&tx, head)? {
                Some(cp) if cp.head_hash == head_hash => (cp, false),
                Some(_) => {
                    return Err(AuditError::Corrupt {
                        seq: head,
                        detail: "a stored checkpoint disagrees with the log at its seq".into(),
                    })
                }
                None => {
                    let cp = Checkpoint::sign(&signer, head, &head_hash, now)?;
                    insert_checkpoint(&tx, &cp)?;
                    (cp, true)
                }
            };
            self.fail_prune_at(2)?;
            // 3. The prune record at P = H + 1.
            let arguments = Anchor::prune_arguments(
                through,
                &cp_b.head_hash,
                previous,
                archive_sha256.as_deref(),
            );
            let record = record(&arguments);
            let json = canonical_record_json(&record);
            let prune_seq = head + 1;
            let entry = AuditEntry {
                seq: prune_seq,
                entry_hash: entry_hash_from_json(prune_seq, &head_hash, &json),
                prev_hash: head_hash,
                record,
            };
            insert_entry(&tx, &entry, &json)?;
            self.fail_prune_at(3)?;
            // 4. The anchor, naming P and its hash.
            let anchor = Anchor::sign(
                &signer,
                through,
                &cp_b.head_hash,
                prune_seq,
                &entry.entry_hash,
                previous,
                archive_sha256.clone(),
                now,
            )?;
            if anchor.check_prune_record(&entry).is_err() {
                return Err(AuditError::Storage(
                    "the prune record does not carry the digest of the prune's arguments".into(),
                ));
            }
            self.fail_prune_at(4)?;
            // 5. The "after" checkpoint at P.
            let after = Checkpoint::sign(&signer, prune_seq, &entry.entry_hash, now)?;
            insert_checkpoint(&tx, &after)?;
            self.fail_prune_at(5)?;
            // 6. The anchor row, deleting.
            insert_anchor(&tx, &anchor, AnchorState::Deleting)?;
            self.fail_prune_at(6)?;
            tx.commit()?;
            let created_before = before.1.then(|| before.0.clone());
            let out = PruneOutcome {
                anchor: StoredAnchor {
                    anchor: anchor.clone(),
                    state: AnchorState::Deleting,
                    shipped_at: None,
                },
                checkpoint_before: Some(before.0),
                checkpoint_after: Some(after.clone()),
                already: false,
            };
            Ok((out, created_before, Some((anchor, after))))
        })?;
        drop(gate);
        drop(conn);
        let (out, created_before, created) = done?;
        // After the synced commit, outside the gate: the sink only queues.
        if let Some(cp) = &created_before {
            if let Some(hook) = &c.on_created {
                hook(cp);
            }
        }
        if let Some((anchor, after)) = &created {
            if let Some(hook) = &c.on_anchor {
                hook(anchor);
            }
            if let Some(hook) = &c.on_created {
                hook(after);
            }
        }
        Ok(out)
    }

    /// Verify the part of the log a prune through `through` removes, before an automatic
    /// prune makes it (`[audit.retention] prune = "auto"`), as
    /// [`verify_chain_signed`](Self::verify_chain_signed) does for the whole log but
    /// stopping at `through`: from the newest anchor (or genesis) the chain, every stored
    /// checkpoint up to there, and the anchors. When the newest anchor's prune record lies
    /// above `through`, the walk goes on to it, so that the anchor is checked whole. Reads only,
    /// on the reader, so appends are not held up.
    ///
    /// The prefix is safe to prune when the report is `ok`, its `last_signed_seq` is at least
    /// `through` (a checkpoint at or past it verified) and its `pruned_through` is the log's
    /// boundary.
    ///
    /// # Errors
    ///
    /// As [`verify_chain_signed`](Self::verify_chain_signed).
    pub fn verify_retained_through(
        &self,
        through: u64,
        keys: &CheckpointKeys,
    ) -> Result<SignedVerifyReport, AuditError> {
        let (head, checkpoints, anchors) = self.verify_snapshot()?;
        let newest_prune = anchors.last().map_or(0, |a| a.anchor.prune_seq);
        let upper = i64::try_from(through.max(newest_prune))
            .unwrap_or(i64::MAX)
            .min(head);
        let checkpoints: Vec<Checkpoint> = checkpoints
            .into_iter()
            .filter(|c| i64::try_from(c.seq).is_ok_and(|s| s <= upper))
            .collect();
        self.verify_signed_from(upper, &checkpoints, &anchors, keys)
    }

    /// Write the export of `from..=through` to `out`, a page of entries at a time, in the
    /// format of `GET /admin/audit/export` (the same [`header_line`](crate::header_line),
    /// [`entry_line`](crate::entry_line) and [`checkpoint_line`](crate::checkpoint_line)):
    /// the header (with the newest anchor when `from` is the first retained seq), the
    /// entries, then the checkpoints inside the range. `exported_at` goes in the header as
    /// given, so two writes of the same range with the same `exported_at` give the same
    /// bytes. Answers the number of entries written.
    ///
    /// # Errors
    ///
    /// [`AuditError::Export`] when `from` is 0, `through` is below `from` or above the head,
    /// `from` is at or below a prune's boundary, or a prune commits while the export is
    /// written (the rows it covers would be missing); [`AuditError::Storage`] when `out`
    /// fails; and the errors of the reads.
    pub fn write_export(
        &self,
        from: u64,
        through: u64,
        exported_at: String,
        out: &mut impl std::io::Write,
    ) -> Result<u64, AuditError> {
        const PAGE: usize = 1_000;
        let io = |e: std::io::Error| AuditError::Storage(format!("writing the export: {e}"));
        let head = crate::log::AuditSink::head(self)?.map_or(0, |h| h.seq);
        if from == 0 || through < from || through > head {
            return Err(AuditError::Export(format!(
                "cannot export seq {from}..={through} of a log whose head is {head}"
            )));
        }
        let anchor = self.newest_anchor()?.map(|a| a.anchor);
        let floor = anchor.as_ref().map(|a| a.through_seq);
        if floor.is_some_and(|f| from <= f) {
            return Err(AuditError::Export(format!(
                "seq {from} is pruned: the log starts after seq {}",
                floor.unwrap_or(0)
            )));
        }
        let header_anchor = anchor.filter(|a| from == a.through_seq + 1);
        let header =
            crate::ExportHeader::new(from, through, exported_at).with_anchor(header_anchor);
        out.write_all(crate::header_line(&header).as_bytes())
            .map_err(io)?;
        let all = crate::RecordFilter::default();
        let mut next = from;
        let mut written = 0u64;
        #[cfg(any(test, feature = "testing"))]
        self.run_export_page_hook();
        while next <= through {
            let want = usize::try_from(through - next + 1)
                .unwrap_or(PAGE)
                .min(PAGE);
            let page = self.range_filtered(next, through, &all, want)?;
            if self.pruned_through()? != floor {
                return Err(AuditError::Export(
                    "the log was pruned while the export was written".to_string(),
                ));
            }
            let Some(last) = page.last().map(|e| e.seq) else {
                break;
            };
            let mut text = String::new();
            for e in page.iter().filter(|e| e.seq <= through) {
                text.push_str(&crate::entry_line(e));
                written += 1;
            }
            out.write_all(text.as_bytes()).map_err(io)?;
            next = last + 1;
        }
        let mut text = String::new();
        for c in self.checkpoints_between(from, through)? {
            text.push_str(&crate::checkpoint_line(&c));
        }
        out.write_all(text.as_bytes()).map_err(io)?;
        Ok(written)
    }

    /// One batch of the deletes of the prune that is `deleting`, if any: at most
    /// `batch_rows` entries at or below its boundary, in one short transaction under the
    /// write gate. The batch that finds no more rows also deletes the checkpoints below the
    /// boundary (the one at it stays) and sets the anchor `done`. Safe to call at any time
    /// and after a restart: the state is in the file.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the transaction fails (it rolls back; the next call
    /// retries).
    pub fn prune_step(&self, batch_rows: usize) -> Result<PruneStep, AuditError> {
        // Most ticks find nothing to delete: say so from the reader, without a write
        // transaction. A prune that commits meanwhile is found by the next tick.
        if self.reader.is_some() && deleting_anchor(&*self.read_conn()?)?.is_none() {
            return Ok(PruneStep::default());
        }
        let mut conn = self.inner.conn.lock()?;
        let _gate = self.inner.gate.hold();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(a) = deleting_anchor(&tx)? else {
            return Ok(PruneStep::default());
        };
        let b = seq_to_i64(a.anchor.through_seq)?;
        let n = usize_to_i64(batch_rows.max(1));
        let deleted = tx
            .prepare_cached(
                "DELETE FROM audit WHERE seq IN \
                 (SELECT seq FROM audit WHERE seq <= ?1 ORDER BY seq LIMIT ?2)",
            )?
            .execute(params![b, n])?;
        let deleted = deleted as u64;
        let done = deleted < u64_of(n);
        if done {
            tx.execute("DELETE FROM checkpoints WHERE seq < ?1", [b])?;
            tx.execute(
                "UPDATE audit_anchors SET state = 'done' WHERE through_seq = ?1",
                [b],
            )?;
        }
        tx.commit()?;
        Ok(PruneStep {
            through_seq: Some(a.anchor.through_seq),
            deleted,
            done,
        })
    }

    /// Tests: make step `step` (1 to 6) of the next prune transactions fail, so that it rolls
    /// back there; 0 turns it off.
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn fail_prune_at_step(&self, step: u8) {
        use std::sync::atomic::Ordering;
        self.inner.prune_fail_at.store(step, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "testing"))]
    fn fail_prune_at(&self, step: u8) -> Result<(), AuditError> {
        use std::sync::atomic::Ordering;
        if self.inner.prune_fail_at.load(Ordering::Relaxed) == step {
            return Err(AuditError::Storage(format!(
                "prune step {step} failed on purpose"
            )));
        }
        Ok(())
    }

    #[cfg(not(any(test, feature = "testing")))]
    #[allow(clippy::unused_self)]
    fn fail_prune_at(&self, _step: u8) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Most checkpoints a plan looks at below the tightest bound before it gives up.
const PLAN_SCAN: i64 = 100_000;

/// `verify_chain_signed` of a log with anchors (`anchors` oldest first, read in the same
/// snapshot as `upper` and `checkpoints`).
///
/// The newest anchor decides where the log starts. When its signature verifies and the stored
/// checkpoint at its `through_seq` verifies and names its `through_hash`, the retained entries
/// are walked from `through_seq + 1` ([`Start::Anchored`]), and the entry at its `prune_seq`
/// must be its prune record ([`Anchor::check_prune_record`]). Otherwise the anchor is reported
/// in `bad_anchors` and every row is walked from genesis, as for a log never pruned: a prefix
/// cut without a valid anchor is a broken chain at its first row. Older anchors are checked for
/// their signature and that each names the one before it (`previous_through_seq`); their
/// checkpoints and prune records may be pruned by a later prune.
pub(super) fn verify_pruned(
    log: &SqliteAudit,
    upper: i64,
    checkpoints: &[Checkpoint],
    anchors: &[StoredAnchor],
    keys: &CheckpointKeys,
) -> Result<SignedVerifyReport, AuditError> {
    let mut bad: Vec<BadAnchor> = Vec::new();
    let fail = |bad: &mut Vec<BadAnchor>, a: &Anchor, reason: String| {
        bad.push(BadAnchor {
            through_seq: a.through_seq,
            reason,
        })
    };
    let mut previous: Option<u64> = None;
    for s in anchors {
        let a = &s.anchor;
        if let Err(reason) = keys.verify_anchor(a) {
            fail(&mut bad, a, reason);
        } else if a.previous_through_seq != previous {
            fail(
                &mut bad,
                a,
                format!(
                    "previous_through_seq is {:?}, but the anchor before it is through {:?}",
                    a.previous_through_seq, previous
                ),
            );
        }
        previous = Some(a.through_seq);
    }
    let newest = &anchors[anchors.len() - 1].anchor;
    let newest_ok = !bad.iter().any(|b| b.through_seq == newest.through_seq)
        && match checkpoints.iter().find(|c| c.seq == newest.through_seq) {
            None => {
                fail(
                    &mut bad,
                    newest,
                    "no stored checkpoint at through_seq (it is never pruned)".into(),
                );
                false
            }
            Some(cp) if keys.verify(cp).is_err() || cp.head_hash != newest.through_hash => {
                fail(
                    &mut bad,
                    newest,
                    "the checkpoint at through_seq does not verify or names another hash".into(),
                );
                false
            }
            Some(_) => true,
        };
    let mut report = if newest_ok {
        let b = newest.through_seq;
        let mut prune_record: Option<Result<(), String>> = None;
        let entries = log.entries_through(Some(b), upper).inspect(|item| {
            if let Ok(e) = item {
                if e.seq == newest.prune_seq {
                    prune_record = Some(newest.check_prune_record(e));
                }
            }
        });
        let retained: Vec<Checkpoint> =
            checkpoints.iter().filter(|c| c.seq >= b).cloned().collect();
        let report = verify_with_checkpoints(
            entries,
            &retained,
            keys,
            Start::Anchored {
                seq: b,
                hash: newest.through_hash.clone(),
            },
        )?;
        match prune_record {
            Some(Ok(())) => {}
            Some(Err(reason)) => fail(&mut bad, newest, reason),
            None => fail(&mut bad, newest, "no entry at prune_seq".into()),
        }
        report
    } else {
        verify_with_checkpoints(
            log.entries_through(None, upper),
            checkpoints,
            keys,
            Start::Genesis,
        )?
    };
    report.anchors = anchors.len() as u64;
    if !bad.is_empty() {
        report.ok = false;
    }
    report.bad_anchors = bad;
    Ok(report)
}

/// Entries with `seq <= through` that are still in the table (deleted or not yet): for tests.
#[cfg(any(test, feature = "testing"))]
impl SqliteAudit {
    #[doc(hidden)]
    pub fn rows_at_or_below(&self, through: u64) -> Result<u64, AuditError> {
        let conn = self.inner.conn.lock()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM audit WHERE seq <= ?1",
            [seq_to_i64(through)?],
            |r| r.get(0),
        )?;
        Ok(u64_of(n))
    }

    #[doc(hidden)]
    pub fn raw_entry(&self, seq: u64) -> Result<Option<AuditEntry>, AuditError> {
        let conn = self.inner.conn.lock()?;
        let sql = format!(
            "SELECT {} FROM audit WHERE seq = ?1",
            super::log::ENTRY_COLUMNS
        );
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([seq_to_i64(seq)?])?;
        match rows.next()? {
            Some(row) => super::log::entry_from_row(row).map(Some),
            None => Ok(None),
        }
    }
}
