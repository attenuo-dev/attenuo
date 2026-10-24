//! SQLite-backed audit sink and lease store.
//!
//! Both wrap a single `rusqlite::Connection` behind a `Mutex`. Audit appends go through one
//! writer thread (group commit, see [`SqliteAudit`]): it takes the lock, reads the current head
//! and inserts the next rows in one transaction, so two entries can never share a `prev_hash`.
//! The lock and the single writer, not SQLite's locking, keep the chain linear within a
//! process; across processes SQLite's write lock plus the `UNIQUE` constraint on `entry_hash`
//! and the primary key on `seq` make a fork fail rather than succeed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock, PoisonError, TryLockError, Weak};
use std::time::Duration;

use attenuo_core::fingerprint::Fingerprint;
use attenuo_core::limits::MAX_LIMIT;
use attenuo_core::{Charge, DecisionRecord, LeaseId, LimitKind};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::approval::{rules, Approval, ApprovalMethod, ApprovalState, Approver};
use crate::budget::{
    kind_static, plan, summarize, ChargeOutcome, CounterKey, CounterSummary, HopLimit, ValueKey,
    DISTINCT_VALUE_KIND, USAGE_KINDS,
};
use crate::checkpoint::{
    verify_with_checkpoints, Checkpoint, CheckpointKeys, SignedVerifyReport, Start,
};
use crate::error::AuditError;
use crate::export::RecordFilter;
use crate::lease::{
    ancestors_of, breadth_first, classify, session_prunable, LeaseRow, LeaseSelector, LeaseStatus,
    LeaseStore, LeaseSubtree, RunLabel, SelectorRevocation, SessionBinding, SessionPrune,
};
use crate::log::{
    canonical_record_json, entry_hash_from_json, verify_entries, AuditEntry, AuditSink,
    VerifyReport, ENTRY_HASH_VERSION, GENESIS_HASH,
};
use crate::query::{like_contains, EntryFilter, Order};
use crate::spans::{distinct_hashes, evictions, SpanHit, SpanKey, MAX_SPANS_PER_RUN};

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
    record_json         TEXT    NOT NULL,
    kind                TEXT    NOT NULL,
    chain_id            TEXT    NULL
);
CREATE INDEX IF NOT EXISTS audit_subject_idx ON audit(originating_subject);
CREATE INDEX IF NOT EXISTS audit_chain_idx   ON audit(chain_digest);
CREATE INDEX IF NOT EXISTS audit_at_idx      ON audit(at);
CREATE INDEX IF NOT EXISTS audit_kind_idx    ON audit(kind);
CREATE INDEX IF NOT EXISTS audit_chain_id_idx ON audit(chain_id);
"#;

const CHECKPOINT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS checkpoints (
    seq       INTEGER PRIMARY KEY,
    head_hash TEXT NOT NULL,
    at        TEXT NOT NULL,
    kid       TEXT NOT NULL,
    signature TEXT NOT NULL
);
"#;

/// Which entry hash construction the `audit` table was written with (key `entry_hash`).
const META_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
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
CREATE TABLE IF NOT EXISTS lease_bindings (
    id      TEXT PRIMARY KEY,
    binding TEXT NOT NULL
);
-- The originating user's subject of each lease (`LeaseStore::record_subject`), for revoking
-- every lease of one user. Created at open on stores that predate it; a lease registered
-- before then has no row and is not matched by a subject.
CREATE TABLE IF NOT EXISTS lease_subjects (
    id      TEXT PRIMARY KEY,
    subject TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS lease_subjects_subject_idx ON lease_subjects(subject);
-- MCP sessions opened through the proxy and the chain that opened each
-- (`LeaseStore::record_session`), for revoking by session. `session` is the SHA-256 of the
-- `Mcp-Session-Id` in hex, never the id. Write-once per (session, server). Created at open on
-- stores that predate it; a session opened before then has no row and matches nothing.
CREATE TABLE IF NOT EXISTS lease_sessions (
    session  TEXT NOT NULL,
    server   TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    bound_at TEXT NOT NULL,
    PRIMARY KEY (session, server)
);
CREATE TABLE IF NOT EXISTS run_labels (
    chain_id    TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    decision_id TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    PRIMARY KEY (chain_id, source)
);
CREATE TABLE IF NOT EXISTS approvals (
    id               TEXT PRIMARY KEY,
    chain_id         TEXT NOT NULL,
    lease            TEXT NOT NULL,
    call_hash        TEXT NOT NULL,
    server           TEXT NOT NULL,
    tool             TEXT NOT NULL,
    arguments        TEXT NOT NULL,
    labels           TEXT NOT NULL,
    decision_id      TEXT NOT NULL,
    chain            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    state            TEXT NOT NULL,
    approver_subject TEXT NULL,
    approver_method  TEXT NULL,
    decided_at       TEXT NULL,
    consumed_by      TEXT NULL,
    jkt              TEXT NULL,
    untrusted_args   TEXT NULL
);
CREATE INDEX IF NOT EXISTS approvals_call_idx ON approvals(chain_id, call_hash, state);
-- Run limits (ADR-0010). One row per counter; `value` is the hex HMAC of a `calls_per`
-- value, or '' for `calls` and `sum`. Keyed by lease id, never joined with `leases`.
CREATE TABLE IF NOT EXISTS budget_counters (
    lease TEXT    NOT NULL,
    cap   INTEGER NOT NULL,
    kind  TEXT    NOT NULL,
    arg   TEXT    NOT NULL,
    value TEXT    NOT NULL,
    used  INTEGER NOT NULL,
    PRIMARY KEY (lease, cap, kind, arg, value)
);
-- What each decision charged, so that it can be refunded exactly and at most once.
CREATE TABLE IF NOT EXISTS budget_charges (
    decision_id TEXT    NOT NULL,
    lease       TEXT    NOT NULL,
    cap         INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    arg         TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    amount      INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    refunded_at TEXT    NULL
);
CREATE INDEX IF NOT EXISTS budget_charges_decision_idx ON budget_charges(decision_id);
-- A refund looks up the other decisions that used a `distinct` value (SR-62).
CREATE INDEX IF NOT EXISTS budget_charges_counter_idx
    ON budget_charges(lease, cap, kind, arg, value);
-- The key `calls_per` values are hashed under, generated once per store.
CREATE TABLE IF NOT EXISTS budget_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO budget_meta (key, value) VALUES ('value_key', lower(hex(randomblob(32))));
-- The limited capabilities of each hop as issued (JSON list of `HopLimit`), for the admin
-- console only: enforcement reads limits from the token. Created at open on older stores.
CREATE TABLE IF NOT EXISTS hop_limits (
    lease  TEXT PRIMARY KEY,
    limits TEXT NOT NULL
);
-- Output labelling phase 2 (ADR-0009): the span index of each run. `hash` is the HMAC-SHA-256
-- of a result fingerprint under `span_key` (no content); `seq` is the audit seq of the result's
-- `tool_result` record. Created at open on stores that predate it.
CREATE TABLE IF NOT EXISTS run_spans (
    chain_id TEXT    NOT NULL,
    hash     BLOB    NOT NULL,
    seq      INTEGER NOT NULL,
    PRIMARY KEY (chain_id, hash, seq)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS run_spans_seq_idx ON run_spans(chain_id, seq);
INSERT OR IGNORE INTO budget_meta (key, value) VALUES ('span_key', lower(hex(randomblob(32))));
"#;

/// The record id (`DecisionRecord::id`) of a row, as SQL. `record_json` is the hashed text
/// and is only read here. `json_valid` keeps a row whose JSON was damaged from failing the
/// index build (and so the open): such a row indexes as NULL and `verify` reports it.
/// The index and [`SqliteAudit::entry_by_record_id`] both use this one expression, which is
/// what lets SQLite answer the lookup from the index.
const RECORD_ID_EXPR: &str =
    "CASE WHEN json_valid(record_json) THEN json_extract(record_json, '$.id') END";

/// Create the index for looking an entry up by its record id (`GET /admin/audit/records/{id}`).
///
/// Added after the table was first released, so it is created at open on databases that
/// lack it. An expression index stores derived values in a separate b-tree; it never writes
/// to the `audit` rows, so no hashed data changes. Once built it costs one b-tree insert per
/// append; building it on a large existing log reads every row once.
fn create_record_id_index(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS audit_record_id_idx ON audit({RECORD_ID_EXPR})"
    ))?;
    Ok(())
}

/// Columns read back for an entry, in the order `entry_from_row` expects.
const ENTRY_COLUMNS: &str = "seq, prev_hash, entry_hash, decision, reason, originating_subject, \
     agents, chain_depth, chain_digest, leases, server, tool, arguments_digest, session_id, \
     policy_ids, record_json, kind, chain_id";

/// How long a connection waits for another connection's write lock before giving up with
/// `SQLITE_BUSY`. Within one process the stores' [`WriteGate`] serializes writers on one file,
/// including the audit and lease connections of one server; this covers a second process.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Prepared statements kept per connection (`prepare_cached`). The stores use about a dozen.
const STATEMENT_CACHE: usize = 32;

/// How hard a file-backed store pushes a commit to stable storage. In-memory stores ignore it.
///
/// Both settings run SQLite in write-ahead-log mode (`journal_mode=WAL`): a commit appends to
/// the `-wal` file and readers do not block the writer. They differ in when SQLite calls
/// `fsync`:
///
/// - [`Normal`](Self::Normal) (`synchronous=NORMAL`, the default): not on commit, only when
///   the WAL is checkpointed into the database file. A committed transaction survives the
///   process crashing or being killed (it is in the OS page cache), but the most recent
///   commits can be lost if the machine loses power or the OS crashes before the next sync.
///   What survives is always a prefix of the log: a transaction is never torn, the database is
///   never corrupt, and the hash chain still verifies, ending at an earlier head. Two kinds of
///   commit are the exception and always run with `synchronous=FULL`: lease revocations (see
///   [`SqliteLeaseStore`]), so a revoked lease cannot come back after a power failure, and
///   every commit that writes a signed checkpoint (see [`SqliteAudit`]), so a checkpoint
///   handed to the `on_created` hook, and shipped off the host from there, never names
///   entries that a power failure could still take back (SR-50).
/// - [`Full`](Self::Full) (`synchronous=FULL`): every commit is synced before it returns, so a
///   decision that was answered is on disk. One `fsync` per commit bounds throughput by the
///   storage's sync latency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    #[default]
    Normal,
    Full,
}

impl Durability {
    fn pragma(self) -> &'static str {
        match self {
            Durability::Normal => "NORMAL",
            Durability::Full => "FULL",
        }
    }

    /// The numeric `PRAGMA synchronous` level.
    fn level(self) -> i64 {
        match self {
            Durability::Normal => SYNC_NORMAL,
            Durability::Full => SYNC_FULL,
        }
    }
}

/// `PRAGMA synchronous` levels (`OFF` is 0, `EXTRA` 3).
const SYNC_NORMAL: i64 = 1;
const SYNC_FULL: i64 = 2;

/// Put `conn` back to `synchronous` level `level` after a commit that ran at `FULL`. A failure
/// is logged, not returned: the commit before it succeeded and its caller must learn that, and
/// the connection merely stays at the safer setting (SR-51).
fn restore_sync(conn: &Connection, level: i64) {
    if let Err(e) = conn.pragma_update(None, "synchronous", level) {
        eprintln!(
            "attenuo-audit: could not set synchronous back to {level} after a synced commit \
             (the connection stays at FULL): {e}"
        );
    }
}

/// Run `f` with `synchronous=FULL`, then go back to `relaxed`, the connection's own level,
/// when it is set (`None`: the connection already syncs every commit, or has nothing to sync).
/// Raising the level must succeed before `f` runs; lowering it again cannot fail the call (see
/// [`restore_sync`]), so `f`'s result always comes back.
fn with_full_sync<T>(
    conn: &mut Connection,
    relaxed: Option<i64>,
    f: impl FnOnce(&mut Connection) -> T,
) -> Result<T, AuditError> {
    let Some(level) = relaxed else {
        return Ok(f(conn));
    };
    conn.pragma_update(None, "synchronous", SYNC_FULL)?;
    let out = f(conn);
    restore_sync(conn, level);
    Ok(out)
}

/// The canonical path of `conn`'s database file; `None` for an in-memory database.
fn file_of(conn: &Connection) -> Option<PathBuf> {
    conn.path()
        .filter(|p| !p.is_empty())
        .and_then(|p| std::fs::canonicalize(p).ok())
}

/// In-process lock on one database file's writes, shared by every store of this process
/// opened on that file (keyed by canonical path).
///
/// The server opens the audit log and the lease store as two connections on one file, and
/// SQLite lets only one of them write at a time. Without this gate the connection that loses
/// the race for `BEGIN IMMEDIATE` gets `SQLITE_BUSY` and SQLite's busy handler sleeps (1, 2,
/// 5 ms and so on) instead of being woken when the lock frees; under four to eight concurrent
/// calls that happened about once per call. Holding the gate across every write transaction
/// makes writers queue instead, and the next one is woken as soon as the commit is done. The
/// gate is a ticket lock, so writers get the file in arrival order: a plain mutex let the
/// audit writer take it back for its next batch while a charge waited, which measured
/// higher p99 latency (see `docs/design/performance.md`, "Write-lock contention between the
/// lease and audit connections").
///
/// Lock order: [`SqliteLeaseStore`] takes the gate before its connection lock, so its reads
/// (the lease check on every call) are not held up by a lease write waiting for the gate.
/// [`SqliteAudit`] takes it after its connection lock, which its writer thread holds for a
/// whole batch, and releases it before the checkpoint hook or any other call out. While
/// holding the gate a thread waits at most for its own store's connection (held only by
/// readers, or by the audit writer that already holds the gate) or for the WAL checkpoint
/// gate (held only around a checkpoint that does not wait for the gate), so no cycle can
/// form. Reads never take the gate. An in-memory store has no gate, stores on
/// different files have different gates, and another process is still kept out by SQLite's
/// lock and [`BUSY_TIMEOUT`].
#[derive(Debug, Clone, Default)]
struct WriteGate(Option<Arc<Ticket>>);

/// A FIFO lock: each writer draws the next ticket and waits until it is served.
#[derive(Debug, Default)]
struct Ticket {
    /// (next ticket to hand out, ticket now served).
    state: Mutex<(u64, u64)>,
    turn: Condvar,
}

/// Holds a [`Ticket`] until dropped (also when unwinding), which serves the next ticket.
struct TicketGuard<'a>(&'a Ticket);

impl Drop for TicketGuard<'_> {
    fn drop(&mut self) {
        let mut s = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.1 += 1;
        self.0.turn.notify_all();
    }
}

/// Live gates by canonical database path. Entries whose stores are all gone are pruned when
/// the next store opens.
static WRITE_GATES: OnceLock<Mutex<HashMap<PathBuf, Weak<Ticket>>>> = OnceLock::new();

impl WriteGate {
    /// The gate of `file` (a canonical path, see [`file_of`]); none for `None`.
    fn for_file(file: Option<&Path>) -> Self {
        let Some(file) = file else {
            return Self(None);
        };
        let mut gates = WRITE_GATES
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        gates.retain(|_, g| g.strong_count() > 0);
        if let Some(gate) = gates.get(file).and_then(Weak::upgrade) {
            return Self(Some(gate));
        }
        let gate = Arc::new(Ticket::default());
        gates.insert(file.to_path_buf(), Arc::downgrade(&gate));
        Self(Some(gate))
    }

    /// Wait for this caller's turn and hold the gate until the guard drops. The gate guards
    /// no data, so a panic while it was held leaves nothing inconsistent: poisoning is
    /// ignored.
    fn hold(&self) -> Option<TicketGuard<'_>> {
        self.0.as_ref().map(|t| {
            let mut s = t.state.lock().unwrap_or_else(PoisonError::into_inner);
            let mine = s.0;
            s.0 += 1;
            while s.1 != mine {
                s = t.turn.wait(s).unwrap_or_else(PoisonError::into_inner);
            }
            TicketGuard(t)
        })
    }
}

/// The `synchronous` level of `conn` if it is below `FULL` and there is a file to sync.
fn relaxed_sync_of(conn: &Connection) -> Result<Option<i64>, AuditError> {
    let file_backed = conn.path().is_some_and(|p| !p.is_empty());
    let level: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    Ok((file_backed && level < SYNC_FULL).then_some(level))
}

/// Refuse a log created before records had `kind` and `chain_id` (this morning's v2 shape,
/// never released): its rows lack the columns and its hashes do not cover the fields.
fn check_record_fields(conn: &Connection) -> Result<(), AuditError> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('audit')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if !cols.is_empty() && !cols.iter().any(|c| c == "kind") {
        return Err(AuditError::Storage(
            "this audit log was written before records had `kind` and `chain_id` (a pre-release \
             build) and cannot be read by this version; move the file aside and start a new log"
                .into(),
        ));
    }
    Ok(())
}

/// Refuse a log whose entries were hashed with another construction than
/// [`ENTRY_HASH_VERSION`], and record the construction of a new one.
fn check_hash_version(conn: &Connection) -> Result<(), AuditError> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM audit_meta WHERE key = 'entry_hash'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match stored {
        Some(v) if v == ENTRY_HASH_VERSION => Ok(()),
        Some(v) => Err(AuditError::Storage(format!(
            "this audit log was written with entry hash `{v}`; this version reads only \
             `{ENTRY_HASH_VERSION}`"
        ))),
        None => {
            let has_entries: bool =
                conn.query_row("SELECT EXISTS (SELECT 1 FROM audit)", [], |r| r.get(0))?;
            if has_entries {
                return Err(AuditError::Storage(format!(
                    "this audit log was written by an earlier attenuo (entry hash v1, before \
                     RFC 8785 canonical JSON) and cannot be verified or extended by this \
                     version, which hashes `{ENTRY_HASH_VERSION}`; move the file aside and \
                     start a new log"
                )));
            }
            conn.execute(
                "INSERT OR IGNORE INTO audit_meta (key, value) VALUES ('entry_hash', ?1)",
                [ENTRY_HASH_VERSION],
            )?;
            // Another process may have created the log meanwhile; whoever won must agree.
            let v: String = conn.query_row(
                "SELECT value FROM audit_meta WHERE key = 'entry_hash'",
                [],
                |r| r.get(0),
            )?;
            if v == ENTRY_HASH_VERSION {
                Ok(())
            } else {
                Err(AuditError::Storage(format!(
                    "this audit log uses entry hash `{v}`; this version reads only \
                     `{ENTRY_HASH_VERSION}`"
                )))
            }
        }
    }
}

impl std::fmt::Display for Durability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Durability::Normal => "normal",
            Durability::Full => "full",
        })
    }
}

fn open_connection(path: &Path, durability: Durability) -> Result<Connection, AuditError> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
    // `journal_mode` answers with the mode in force. A `:memory:` path keeps `memory`, which
    // is fine: there is nothing to sync.
    let mode = switch_to_wal(&conn)?;
    if !mode.eq_ignore_ascii_case("wal") && !mode.eq_ignore_ascii_case("memory") {
        return Err(AuditError::Storage(format!(
            "could not switch {} to WAL mode (journal_mode is `{mode}`)",
            path.display()
        )));
    }
    conn.pragma_update(None, "synchronous", durability.pragma())?;
    Ok(conn)
}

/// `PRAGMA journal_mode=WAL`, answering the mode in force. SQLite does not call the busy
/// handler for a journal-mode change, so a second process opening the same file at the same
/// moment can get `SQLITE_BUSY` here at once; retry for up to [`BUSY_TIMEOUT`], as the busy
/// handler would.
fn switch_to_wal(conn: &Connection) -> Result<String, AuditError> {
    let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
    loop {
        match conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0)) {
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            other => return Ok(other?),
        }
    }
}

fn open_memory_connection() -> Result<Connection, AuditError> {
    let conn = Connection::open_in_memory()?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
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
    let kind: String = row.get(16)?;
    let chain_id: Option<String> = row.get(17)?;

    let corrupt = |detail: String| AuditError::Corrupt { seq, detail };
    let record: DecisionRecord =
        serde_json::from_str(&record_json).map_err(|e| corrupt(format!("record_json: {e}")))?;
    // The hash covers the *decoded* record, and some decoders are lenient (RFC 3339 accepts any
    // date/time separator, for instance), so a byte-level edit could decode to the same value.
    // Rows are written in canonical (RFC 8785) form; anything that no longer round-trips was
    // edited.
    if canonical_record_json(&record) != record_json {
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
    expect("kind", &kind, record.kind.as_str())?;
    if chain_id != record.chain_id {
        return Err(corrupt(format!(
            "column `chain_id` ({chain_id:?}) disagrees with record_json ({:?})",
            record.chain_id
        )));
    }
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

fn decision_str(d: &attenuo_core::Decision) -> &'static str {
    match d {
        attenuo_core::Decision::Allow => "allow",
        attenuo_core::Decision::Deny => "deny",
    }
}

fn head_in(tx: &Transaction<'_>) -> Result<Option<AuditEntry>, AuditError> {
    let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit ORDER BY seq DESC LIMIT 1");
    let mut stmt = tx.prepare_cached(&sql)?;
    stmt.query_row([], |row| Ok(entry_from_row(row)))
        .optional()?
        .transpose()
}

/// `(seq, entry_hash)` of the newest row, for chaining the next append. Unlike [`head_in`] it
/// does not decode and cross-check the row: checking stored entries is `verify_chain`'s job
/// (and the signed checkpoints'), and decoding the head on every append cost more than the
/// insert itself.
fn head_link(tx: &Transaction<'_>) -> Result<(u64, String), AuditError> {
    let link = tx
        .prepare_cached("SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1")?
        .query_row([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .optional()?;
    match link {
        None => Ok((0, GENESIS_HASH.to_string())),
        Some((seq, hash)) => match u64::try_from(seq) {
            Ok(seq) => Ok((seq, hash)),
            Err(_) => Err(AuditError::Corrupt {
                seq: 0,
                detail: format!("negative seq {seq}"),
            }),
        },
    }
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

fn checkpoint_from_row(row: &Row<'_>) -> rusqlite::Result<Checkpoint> {
    let seq: i64 = row.get(0)?;
    Ok(Checkpoint {
        seq: seq.max(0) as u64,
        head_hash: row.get(1)?,
        at: row.get(2)?,
        kid: row.get(3)?,
        signature: row.get(4)?,
    })
}

fn insert_checkpoint(conn: &Connection, cp: &Checkpoint) -> Result<(), AuditError> {
    conn.execute(
        "INSERT INTO checkpoints (seq, head_hash, at, kid, signature) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![cp.seq as i64, cp.head_hash, cp.at, cp.kid, cp.signature],
    )?;
    Ok(())
}

fn checkpoint_at(conn: &Connection, seq: u64) -> Result<Option<Checkpoint>, AuditError> {
    Ok(conn
        .prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints WHERE seq = ?1",
        )?
        .query_row([seq as i64], checkpoint_from_row)
        .optional()?)
}

/// Default for [`SqliteAudit::with_wal_checkpoints`] (`[audit] wal_checkpoint_seconds`).
pub const DEFAULT_WAL_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);

/// Commits (transactions) after which the background checkpointer runs without waiting for
/// its interval. A one-record commit adds about 15 pages to the WAL (the row and three
/// indexes), so this is about 4,000 pages, 16 MB at the default 4 KiB page.
pub const WAL_CHECKPOINT_COMMITS: u64 = 256;

/// WAL size (in frames, one page each) above which a checkpoint round ends with a short
/// catch-up pass that holds the store's lock (see [`WalCheckpointer`]), so that the next
/// commit starts the WAL over. 64 MB at the default 4 KiB page: each such round pauses
/// appends briefly (two syncs), so it is kept rare; with 4,096 pages the pauses set the p99
/// at 32 clients in the end-to-end bench.
const WAL_RESTART_FRAMES: i64 = 16384;

/// Unlocked catch-up passes before the locked one, at most.
const WAL_CATCH_UP_PASSES: usize = 4;

/// Frames committed during a catch-up pass small enough to copy with appends paused.
const WAL_LOCKED_RESIDUE: i64 = 256;

/// The writer's own backstop. When a commit leaves this many frames in the WAL (128 MB at the
/// default page size; twice the size at which the background checkpointer starts its catch-up
/// passes), the writer runs a `TRUNCATE` checkpoint itself, on its own connection, before it
/// takes the next batch. This is the one case where an append pays for a whole checkpoint,
/// and it only arises when the background thread cannot keep up with the writer (a small
/// box under sustained load): the WAL is then bounded by this many frames plus one batch,
/// where before it grew for as long as the load lasted.
pub const WAL_WRITER_BACKSTOP_FRAMES: i64 = 2 * WAL_RESTART_FRAMES;

thread_local! {
    /// Frames in the WAL after the last commit on this thread, as reported by the WAL hook
    /// (see [`note_wal_pages`]); read by the writer right after its commit.
    static WAL_PAGES: std::cell::Cell<std::ffi::c_int> = const { std::cell::Cell::new(0) };
}

/// The writer connection's WAL hook: SQLite calls it after every commit in WAL mode with the
/// number of frames the WAL now holds. It replaces SQLite's own hook (the one behind
/// `wal_autocheckpoint`, which would run a `PASSIVE` checkpoint here that, with the
/// background checkpointer holding SQLite's checkpoint lock most of the time under load,
/// would nearly always return busy and copy nothing).
fn note_wal_pages(_: &rusqlite::hooks::Wal, pages: std::ffi::c_int) -> rusqlite::Result<()> {
    WAL_PAGES.with(|p| p.set(pages));
    Ok(())
}

/// What one `PRAGMA wal_checkpoint` reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalCheckpoint {
    /// SQLite could not finish (another connection held a lock it needed).
    pub busy: bool,
    /// Frames in the WAL when the checkpoint ran.
    pub wal_frames: i64,
    /// Of those, frames now copied into the database file.
    pub checkpointed_frames: i64,
}

impl WalCheckpoint {
    /// Everything in the WAL is in the database file.
    pub fn complete(&self) -> bool {
        !self.busy && self.wal_frames == self.checkpointed_frames
    }
}

/// What the background WAL checkpointer has done since the store was opened, as returned by
/// [`SqliteAudit::wal_stats`]. For metrics: every field is read without a lock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalStats {
    /// Rounds that left every WAL frame copied into the database file.
    pub rounds_complete: u64,
    /// Rounds that left frames behind (a reader or the writer was in the way); the next
    /// commit starts another round.
    pub rounds_incomplete: u64,
    /// Rounds that failed with an error.
    pub round_errors: u64,
    /// Catch-up passes run while holding the store's lock, each pausing appends briefly.
    pub locked_passes: u64,
    /// Checkpoints the writer ran itself because the WAL outgrew
    /// [`WAL_WRITER_BACKSTOP_FRAMES`].
    pub backstops: u64,
    /// WAL file syncs run ahead of a signed audit checkpoint (see
    /// [`CHECKPOINT_PRESYNC_LEAD`]).
    pub wal_presyncs: u64,
    /// Database file syncs run before a locked pass.
    pub db_presyncs: u64,
    /// Unix time (seconds) the last complete round finished; 0 before the first one.
    pub last_complete_unix: u64,
    /// Frames in the WAL at the last pass of the last round.
    pub wal_frames: u64,
}

/// The always-on counters behind [`WalStats`].
#[derive(Default)]
struct WalCounters {
    rounds_complete: AtomicU64,
    rounds_incomplete: AtomicU64,
    round_errors: AtomicU64,
    locked_passes: AtomicU64,
    backstops: AtomicU64,
    wal_presyncs: AtomicU64,
    db_presyncs: AtomicU64,
    last_complete_unix: AtomicU64,
    wal_frames: AtomicU64,
}

impl WalCounters {
    fn snapshot(&self) -> WalStats {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        WalStats {
            rounds_complete: get(&self.rounds_complete),
            rounds_incomplete: get(&self.rounds_incomplete),
            round_errors: get(&self.round_errors),
            locked_passes: get(&self.locked_passes),
            backstops: get(&self.backstops),
            wal_presyncs: get(&self.wal_presyncs),
            db_presyncs: get(&self.db_presyncs),
            last_complete_unix: get(&self.last_complete_unix),
            wal_frames: get(&self.wal_frames),
        }
    }

    fn bump(a: &AtomicU64) {
        a.fetch_add(1, Ordering::Relaxed);
    }
}

/// Unix time in whole seconds, at least 1 (0 means "never" in [`WalStats`]).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().max(1))
}

fn wal_checkpoint(conn: &Connection, mode: &str) -> Result<WalCheckpoint, AuditError> {
    Ok(
        conn.query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |r| {
            Ok(WalCheckpoint {
                busy: r.get::<_, i64>(0)? != 0,
                wal_frames: r.get(1)?,
                checkpointed_frames: r.get(2)?,
            })
        })?,
    )
}

enum WalMsg {
    /// Enough commits since the last checkpoint: run one now.
    Kick,
    /// A signed audit checkpoint is near: sync the WAL file now, so that the commit writing
    /// it, which syncs at `FULL`, finds little left to write (see [`CHECKPOINT_PRESYNC_LEAD`]).
    SyncWal,
    /// The store is closing: run the final checkpoint and exit.
    Stop,
}

/// The background WAL checkpointer of a file-backed [`SqliteAudit`]: a thread with its own
/// connection to the same file.
///
/// The writer connection runs with `wal_autocheckpoint=0`, so a commit never copies the WAL
/// into the database file (and, at `durability = "normal"`, never pays the `fsync` that comes
/// with it); before this, every thousandth page made one append wait for a whole checkpoint.
/// Instead this thread runs a round every interval, or sooner after
/// [`WAL_CHECKPOINT_COMMITS`] commits:
///
/// 1. `PRAGMA wal_checkpoint(PASSIVE)` without any lock of the store's. `PASSIVE` takes no
///    SQLite lock the writer needs and never waits, so appends continue while it copies and
///    syncs; this is where nearly all of the work happens.
/// 2. If the WAL has grown past [`WAL_RESTART_FRAMES`], more unlocked passes, each copying
///    what was committed during the one before, until few frames arrive during a pass (at
///    most [`WAL_CATCH_UP_PASSES`]), then an `fsync` of the database file from a descriptor of
///    this thread's own (the unlocked passes, not having finished, copied pages they did not
///    sync), then one more `PASSIVE` while holding the store's connection lock, which pauses
///    appends in this process for as long as it takes to copy that remainder and sync.
///    SQLite only starts a WAL over from its
///    beginning when a write finds every frame already copied, which under continuous load
///    step 1 alone never achieves (it copies up to where the WAL ended when it started), so
///    without this the WAL file would grow for as long as the load lasts.
/// 3. If no append is queued or in progress and everything was copied, `TRUNCATE` (busy
///    timeout zero, so it never makes an append wait), which shrinks the WAL file to zero.
///
/// Stopping runs a final `TRUNCATE`.
///
/// Every checkpoint, this thread's and the writer's backstop (see
/// [`WAL_WRITER_BACKSTOP_FRAMES`]), runs under [`Activity::checkpoint_gate`]: SQLite lets
/// only one connection checkpoint at a time and turns a second one away at once (its busy
/// handler is not consulted for that lock), so without the gate the writer's checkpoint
/// would fail exactly when it is needed, while this thread is busy copying.
struct WalCheckpointer {
    msgs: mpsc::SyncSender<WalMsg>,
    conn: Arc<Mutex<Connection>>,
    activity: Arc<Activity>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// What the checkpointer thread works with.
struct WalShared {
    /// Its own connection.
    conn: Arc<Mutex<Connection>>,
    /// The store's connection: holding its lock pauses every append and read in this process.
    store: Arc<Mutex<Connection>>,
    activity: Arc<Activity>,
    interval: Duration,
    /// The database file.
    path: PathBuf,
    /// A descriptor of the database file, opened once and kept for as long as the thread
    /// runs, to sync the file before a locked pass ([`wal_round`]). Never open and close one
    /// per sync: closing any descriptor of a file releases every POSIX lock the process holds
    /// on it, including the SHARED lock SQLite keeps on the database file in WAL mode, and
    /// SQLite does not take it again. Another process could then take the WAL for unused,
    /// checkpoint it and delete it under the live store (SR-58). Dropped last, when the thread
    /// ends after its final checkpoint. `None` when the file could not be opened (the sync is
    /// skipped). The WAL file carries no such lock, so it is opened per sync.
    db_file: Option<std::fs::File>,
}

impl WalCheckpointer {
    fn start(
        conn: Connection,
        store: Arc<Mutex<Connection>>,
        interval: Duration,
        activity: Arc<Activity>,
        channel: (mpsc::SyncSender<WalMsg>, mpsc::Receiver<WalMsg>),
        path: PathBuf,
    ) -> Result<Self, AuditError> {
        let (msgs, rx) = channel;
        let conn = Arc::new(Mutex::new(conn));
        let db_file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("attenuo-audit: cannot open the database file to sync it: {e}");
                None
            }
        };
        let shared = WalShared {
            conn: Arc::clone(&conn),
            store,
            activity: Arc::clone(&activity),
            interval,
            path,
            db_file,
        };
        let thread = std::thread::Builder::new()
            .name("attenuo-audit-wal".into())
            .spawn(move || wal_loop(&shared, &rx))
            .map_err(|e| AuditError::Storage(format!("cannot start the WAL checkpointer: {e}")))?;
        Ok(Self {
            msgs,
            conn,
            activity,
            thread: Some(thread),
        })
    }

    /// `TRUNCATE` now, waiting up to the busy timeout for the locks it needs.
    fn truncate(&self) -> Result<WalCheckpoint, AuditError> {
        let conn = self.conn.lock()?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let result = gated_checkpoint(&self.activity, &conn, "TRUNCATE");
        conn.busy_timeout(Duration::ZERO)?;
        result
    }
}

impl Drop for WalCheckpointer {
    fn drop(&mut self) {
        let _ = self.msgs.send(WalMsg::Stop);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn wal_loop(shared: &WalShared, msgs: &mpsc::Receiver<WalMsg>) {
    loop {
        match msgs.recv_timeout(shared.interval) {
            Ok(WalMsg::Kick) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(WalMsg::SyncWal) => {
                let mut wal = shared.path.clone().into_os_string();
                wal.push("-wal");
                // Best effort: an extra sync, which no commit relies on.
                let synced = sync_file_data(Path::new(&wal));
                if synced.is_ok() {
                    WalCounters::bump(&shared.activity.wal_stats.wal_presyncs);
                }
                #[cfg(any(test, feature = "testing"))]
                if synced.is_ok() {
                    if let Ok(mut t) = shared.activity.timings.lock() {
                        t.wal_presyncs += 1;
                    }
                }
                continue;
            }
            Ok(WalMsg::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Final checkpoint. The writer thread has stopped (`SqliteAudit`'s drop joins
                // it first), so waiting for the write lock is fine.
                let Ok(conn) = shared.conn.lock() else { return };
                let _ = conn.busy_timeout(BUSY_TIMEOUT);
                if let Err(e) = gated_checkpoint(&shared.activity, &conn, "TRUNCATE") {
                    eprintln!("attenuo-audit: final WAL checkpoint failed: {e}");
                }
                return;
            }
        }
        if let Err(e) = wal_round(shared) {
            WalCounters::bump(&shared.activity.wal_stats.round_errors);
            eprintln!("attenuo-audit: WAL checkpoint failed: {e}");
        }
    }
}

/// `fsync` the file at `path` (the WAL) from a descriptor of our own: it writes out every
/// dirty page of that file, whichever connection wrote it. Used before a signed audit
/// checkpoint (see [`CHECKPOINT_PRESYNC_LEAD`]). Never for the database file itself, whose
/// descriptor must not be closed while the store is open (see `WalShared::db_file`, SR-58).
fn sync_file_data(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_data()
}

/// [`CHECKPOINT_PRESYNC_LEAD`], or what a test or measurement set instead (see
/// `SqliteAudit::set_checkpoint_presync_lead`; 0 turns the WAL sync off).
fn presync_lead(activity: &Activity) -> u64 {
    #[cfg(any(test, feature = "testing"))]
    {
        match activity.presync_lead.load(Ordering::Relaxed) {
            0 => CHECKPOINT_PRESYNC_LEAD,
            set => set - 1,
        }
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        let _ = activity;
        CHECKPOINT_PRESYNC_LEAD
    }
}

/// Whether [`wal_round`] syncs the database file before its locked pass: always, except in
/// tests and measurements that turn it off (see `SqliteAudit::set_wal_presync`).
fn presync_enabled(activity: &Activity) -> bool {
    #[cfg(any(test, feature = "testing"))]
    {
        !activity.no_presync.load(Ordering::Relaxed)
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        let _ = activity;
        true
    }
}

/// One `PRAGMA wal_checkpoint` under the store's checkpoint gate (see [`WalCheckpointer`]).
fn gated_checkpoint(
    activity: &Activity,
    conn: &Connection,
    mode: &str,
) -> Result<WalCheckpoint, AuditError> {
    let _gate = activity.checkpoint_gate.lock()?;
    wal_checkpoint(conn, mode)
}

/// One round: see [`WalCheckpointer`].
fn wal_round(shared: &WalShared) -> Result<(), AuditError> {
    let conn = shared.conn.lock()?;
    #[cfg(any(test, feature = "testing"))]
    let round_started = std::time::Instant::now();
    let activity = &shared.activity;
    activity.since_wal_checkpoint.store(0, Ordering::Release);
    let committed_before = activity.committed.load(Ordering::Acquire);
    let mut done = gated_checkpoint(activity, &conn, "PASSIVE")?;
    #[cfg(any(test, feature = "testing"))]
    let first = done;
    #[cfg(any(test, feature = "testing"))]
    let mut locked = None;
    #[cfg(any(test, feature = "testing"))]
    let mut presynced = false;
    if done.wal_frames >= WAL_RESTART_FRAMES {
        // Catch up without the lock first: each pass copies what was committed during the
        // previous one, so the frames left for the locked pass (and the pause) stay small.
        for _ in 0..WAL_CATCH_UP_PASSES {
            let again = gated_checkpoint(activity, &conn, "PASSIVE")?;
            let arrived = again.wal_frames - done.wal_frames;
            done = again;
            if arrived <= WAL_LOCKED_RESIDUE {
                break;
            }
        }
    }
    if done.wal_frames >= WAL_RESTART_FRAMES {
        // The unlocked passes copied nearly everything into the database file, but a
        // `PASSIVE` that does not finish leaves those pages unsynced, and the locked pass,
        // which does finish, would sync them all with appends paused (10 to 23 ms at the
        // median on the dev VM for one client). Sync them here first, so the locked pass syncs only what it
        // copies itself. An extra sync: no commit becomes less durable.
        if presync_enabled(activity) {
            // The kept descriptor, never a new one (SR-58).
            let synced = match &shared.db_file {
                Some(f) => f.sync_data(),
                None => Err(std::io::Error::other("the database file is not open")),
            };
            match &synced {
                Ok(()) => WalCounters::bump(&activity.wal_stats.db_presyncs),
                Err(e) => eprintln!("attenuo-audit: syncing the database file failed: {e}"),
            }
            #[cfg(any(test, feature = "testing"))]
            {
                presynced = synced.is_ok();
            }
        }
        let _store = shared.store.lock()?;
        #[cfg(any(test, feature = "testing"))]
        let started = std::time::Instant::now();
        done = gated_checkpoint(activity, &conn, "PASSIVE")?;
        WalCounters::bump(&activity.wal_stats.locked_passes);
        #[cfg(any(test, feature = "testing"))]
        {
            activity
                .timings
                .lock()?
                .locked_passes
                .push((started.elapsed(), done.wal_frames));
            locked = Some((started, started.elapsed()));
        }
    }
    let idle = activity.pending.load(Ordering::Acquire) == 0
        && activity.committed.load(Ordering::Acquire) == committed_before;
    #[cfg_attr(not(any(test, feature = "testing")), allow(unused_variables))]
    let truncated = if done.complete() && done.wal_frames > 0 && idle {
        // Busy timeout zero: if an append starts meanwhile, give up rather than make it
        // wait; the next round tries again.
        gated_checkpoint(activity, &conn, "TRUNCATE").is_ok_and(|t| t.complete())
    } else {
        false
    };
    #[cfg(any(test, feature = "testing"))]
    activity.timings.lock()?.rounds.push(WalRound {
        started: round_started,
        took: round_started.elapsed(),
        first,
        last: done,
        truncated,
        locked,
        presynced,
    });
    let stats = &activity.wal_stats;
    stats.wal_frames.store(
        u64::try_from(done.wal_frames).unwrap_or(0),
        Ordering::Relaxed,
    );
    if done.complete() {
        WalCounters::bump(&stats.rounds_complete);
        stats
            .last_complete_unix
            .store(unix_now(), Ordering::Relaxed);
    } else {
        WalCounters::bump(&stats.rounds_incomplete);
    }
    if !done.complete() {
        // Frames were left behind (a reader or the writer was in the way). Do not wait a
        // whole interval, or another WAL_CHECKPOINT_COMMITS commits, to try again: the very
        // next commit kicks a new round.
        activity
            .since_wal_checkpoint
            .store(WAL_CHECKPOINT_COMMITS - 1, Ordering::Release);
    }
    Ok(())
}

/// How many entries before a signed audit checkpoint the writer asks the background WAL
/// checkpointer to sync the WAL file. The commit that writes the checkpoint syncs at `FULL`
/// (SR-50), and at `durability = "normal"` that sync writes out every WAL page committed
/// since the WAL was last synced, up to [`WAL_CHECKPOINT_COMMITS`] commits of them (about
/// 14 ms for one client on the dev VM). Syncing the WAL off the request path a little
/// earlier leaves that commit only the pages of the last few entries. Nothing commits at a
/// different level: this is one more sync, on another thread.
pub const CHECKPOINT_PRESYNC_LEAD: u64 = 32;

/// Whether the batch of entries `first..=last` brings the head to [`CHECKPOINT_PRESYNC_LEAD`]
/// entries (or fewer) before the next multiple of `every`, having been further from it
/// before. Never for a batch that writes the checkpoint itself.
fn nears_checkpoint(first: u64, last: u64, every: u64, lead: u64) -> bool {
    if every == 0 || lead == 0 || first == 0 || first > last {
        return false;
    }
    let before = first - 1;
    let next = (before / every + 1) * every;
    let point = next.saturating_sub(lead.min(every / 2));
    before < point && point <= last && last < next
}

type CheckpointHook = Arc<dyn Fn(&Checkpoint) + Send + Sync>;

/// Automatic checkpointing: sign the head every `every` entries, inside the append's
/// transaction, so a checkpoint can never refer to a head that was not committed. That
/// transaction commits with `synchronous=FULL` whatever the store's durability, before the
/// `on_created` hook sees the checkpoint (SR-50).
struct Checkpointing {
    signer: attenuo_token::DetachedSigner,
    every: u64,
    on_created: Option<CheckpointHook>,
}

/// Most appends committed in one transaction by the writer thread.
pub const MAX_BATCH: usize = 256;

/// Hash-chained audit log in SQLite.
///
/// **Group commit.** [`append`](AuditSink::append) hands the record to a single writer thread
/// over a channel and blocks until that thread answers with the entry (or the error). The
/// writer takes the first waiting record, adds every other record already queued (up to
/// [`MAX_BATCH`]) and commits them in one transaction, so under load one commit (and, at
/// `durability = "full"`, one `fsync`) covers many appends, while a lone caller pays no extra
/// wait: records that arrive while a batch is being committed form the next batch. Records get
/// sequence numbers in the order they reached the channel. If a batch fails, its records are
/// retried one transaction each, so one bad record fails only its own append; every append
/// either gets its committed entry back or an error, never a guess.
///
/// **Inline commit.** When no append is waiting for the writer and the connection is free, an
/// append commits on the caller's thread instead, the same one-record transaction the writer
/// would run, without the hand-off between threads. The connection lock keeps the chain
/// linear whichever thread commits.
///
/// **WAL checkpoints.** [`with_wal_checkpoints`](Self::with_wal_checkpoints) moves SQLite's
/// checkpoints off the commit path to a background thread.
///
/// **Signed checkpoints are synced.** A commit that writes a signed checkpoint (an automatic
/// one in an append batch, or [`checkpoint_signed`](Self::checkpoint_signed)) runs with
/// `synchronous=FULL` even at `durability = "normal"`, and only then is the checkpoint handed
/// to the [`with_checkpoint_hook`](Self::with_checkpoint_hook) hook. The sync covers every
/// earlier commit too, so whatever the hook ships off the host is on disk here. A batch finds
/// out that it crosses a checkpoint after it has read the head inside its transaction, and
/// SQLite cannot change `synchronous` inside a transaction, so such a batch rolls back
/// (nothing was written yet) and runs again at `FULL`: one extra transaction per checkpoint.
/// With the background checkpointer running, the WAL is also synced off the request path
/// [`CHECKPOINT_PRESYNC_LEAD`] entries before each checkpoint, so that commit's sync has
/// only the last few entries' pages to write.
///
/// Reads, checkpoints and [`with_connection`](Self::with_connection) take the same lock and
/// see only committed batches.
pub struct SqliteAudit {
    inner: Arc<Inner>,
    /// Started by the first append that finds the store busy, after the builders have run.
    writer: OnceLock<Writer>,
    /// The background WAL checkpointer, if [`with_wal_checkpoints`](Self::with_wal_checkpoints)
    /// started one.
    wal: Option<WalCheckpointer>,
}

/// What the writer thread and the readers share.
struct Inner {
    /// Shared with the WAL checkpointer, which holds it briefly to pause appends.
    conn: Arc<Mutex<Connection>>,
    checkpointing: Option<Checkpointing>,
    activity: Arc<Activity>,
    /// The connection's `synchronous` level when it is below `FULL` on a file: commits that
    /// write a signed checkpoint raise it to `FULL` for themselves (SR-50).
    relaxed_sync: Option<i64>,
    /// The database file, if there is one (canonical path): what a synced commit covers.
    file: Option<PathBuf>,
    /// Held across every write transaction (see [`WriteGate`]).
    gate: WriteGate,
    /// Tests: every commit and the `synchronous` level it ran at, in one log with the hook.
    #[cfg(test)]
    probe: Option<Arc<Mutex<Vec<String>>>>,
}

/// Why [`Inner::commit_tx`] wrote nothing. Either way the records come back.
enum CommitFailure {
    Error(AuditError, Vec<DecisionRecord>),
    /// The batch writes a signed checkpoint and must run again with `synchronous=FULL`.
    NeedsSync(Vec<DecisionRecord>),
}

/// Counters the WAL checkpointer reads to know whether the writer is busy.
#[derive(Default)]
struct Activity {
    /// Appends handed to the writer thread and not answered yet.
    pending: AtomicUsize,
    /// Entries committed since the store was opened.
    committed: AtomicU64,
    /// Commits since the last background checkpoint started.
    since_wal_checkpoint: AtomicU64,
    /// Wakes the checkpointer early (see [`WAL_CHECKPOINT_COMMITS`]).
    wal_kick: OnceLock<mpsc::SyncSender<WalMsg>>,
    /// Held for the duration of every `PRAGMA wal_checkpoint` in this process, by the
    /// background thread and by the writer's backstop (see [`WalCheckpointer`]).
    checkpoint_gate: Mutex<()>,
    /// What the background checkpointer has done, for [`SqliteAudit::wal_stats`].
    wal_stats: WalCounters,
    /// Tests and measurements: how long each pause the checkpointers impose lasted.
    #[cfg(any(test, feature = "testing"))]
    timings: Mutex<WalTimings>,
    /// Tests and measurements: skip the database-file sync before the locked pass.
    #[cfg(any(test, feature = "testing"))]
    no_presync: std::sync::atomic::AtomicBool,
    /// Tests and measurements: 0 for [`CHECKPOINT_PRESYNC_LEAD`], else the lead plus one.
    #[cfg(any(test, feature = "testing"))]
    presync_lead: AtomicU64,
}

/// Tests and measurements: the pauses the WAL checkpointers imposed on appends, as returned
/// by [`SqliteAudit::wal_timings`].
#[cfg(any(test, feature = "testing"))]
#[doc(hidden)]
#[derive(Debug, Default, Clone)]
pub struct WalTimings {
    /// How long each writer backstop (`TRUNCATE` on the writer's connection) ran.
    pub backstops: Vec<Duration>,
    /// Each locked pass of the background checkpointer: how long it held the store lock and
    /// the WAL frames its `PASSIVE` reported.
    pub locked_passes: Vec<(Duration, i64)>,
    /// Each round of the background checkpointer.
    pub rounds: Vec<WalRound>,
    /// WAL syncs the checkpointer ran ahead of a signed audit checkpoint.
    pub wal_presyncs: usize,
}

/// Tests and measurements: one round of the background WAL checkpointer.
#[cfg(any(test, feature = "testing"))]
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct WalRound {
    /// When the round started.
    pub started: std::time::Instant,
    /// How long it ran.
    pub took: Duration,
    /// What its first `PASSIVE` reported.
    pub first: WalCheckpoint,
    /// What its last `PASSIVE` reported.
    pub last: WalCheckpoint,
    /// It ran the idle `TRUNCATE`, and that succeeded.
    pub truncated: bool,
    /// When its locked pass started (store lock taken) and how long it held the lock.
    pub locked: Option<(std::time::Instant, Duration)>,
    /// It synced the database file before its locked pass.
    pub presynced: bool,
}

impl Drop for SqliteAudit {
    fn drop(&mut self) {
        // Stop the writer first (it finishes the batch in hand), then the checkpointer, whose
        // last act is a `TRUNCATE` checkpoint with nothing left to write.
        drop(self.writer.take());
        drop(self.wal.take());
    }
}

impl std::fmt::Debug for SqliteAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteAudit")
            .field("checkpointing", &self.inner.checkpointing.is_some())
            .field("writer_started", &self.writer.get().is_some())
            .field("wal_checkpointer", &self.wal.is_some())
            .finish_non_exhaustive()
    }
}

/// One append waiting for the writer.
struct Job {
    record: DecisionRecord,
    /// [`AuditSink::append_synced`]: the batch that carries this record commits at `FULL`.
    sync: bool,
    reply: mpsc::SyncSender<Result<AuditEntry, AuditError>>,
}

/// Handle on the writer thread. Dropping it closes the channel; the thread finishes the batch
/// in hand and exits, and the drop waits for it.
struct Writer {
    jobs: Option<mpsc::Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Writer {
    fn start(inner: Arc<Inner>) -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        match std::thread::Builder::new()
            .name("attenuo-audit-writer".into())
            .spawn(move || writer_loop(&inner, &rx))
        {
            Ok(thread) => Self {
                jobs: Some(tx),
                thread: Some(thread),
            },
            // Without a writer every append fails, and so every decision is denied.
            Err(e) => {
                eprintln!("attenuo-audit: cannot start the audit writer thread: {e}");
                Self {
                    jobs: None,
                    thread: None,
                }
            }
        }
    }

    fn append(&self, record: DecisionRecord, sync: bool) -> Result<AuditEntry, AuditError> {
        let stopped = || AuditError::Storage("the audit writer is not running".into());
        let jobs = self.jobs.as_ref().ok_or_else(stopped)?;
        let (reply, answer) = mpsc::sync_channel(1);
        jobs.send(Job {
            record,
            reply,
            sync,
        })
        .map_err(|_| stopped())?;
        // A writer that panicked drops the reply sender: the append fails, it is not assumed.
        answer.recv().map_err(|_| stopped())?
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn writer_loop(inner: &Inner, jobs: &mpsc::Receiver<Job>) {
    while let Ok(first) = jobs.recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match jobs.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }
        // One record that must be synced makes the whole batch commit at `FULL`: one sync
        // covers them all.
        let sync = batch.iter().any(|j| j.sync);
        let (records, replies): (Vec<_>, Vec<_>) =
            batch.into_iter().map(|j| (j.record, j.reply)).unzip();
        for (reply, result) in replies.into_iter().zip(inner.append_batch(records, sync)) {
            // The caller always waits for its answer; a send can only fail if it panicked.
            let _ = reply.send(result);
        }
    }
}

impl Inner {
    /// Commit `records` in order, as one transaction when possible. One result per record.
    /// With `sync`, every commit runs at `synchronous=FULL`.
    fn append_batch(
        &self,
        records: Vec<DecisionRecord>,
        sync: bool,
    ) -> Vec<Result<AuditEntry, AuditError>> {
        let n = records.len();
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return (0..n).map(|_| Err(AuditError::Poisoned)).collect(),
        };
        self.append_locked(&mut conn, records, sync)
    }

    /// [`append_batch`](Self::append_batch) with the connection already locked.
    fn append_locked(
        &self,
        conn: &mut Connection,
        records: Vec<DecisionRecord>,
        sync: bool,
    ) -> Vec<Result<AuditEntry, AuditError>> {
        let n = records.len();
        match self.commit(conn, records, sync) {
            Ok(entries) => entries.into_iter().map(Ok).collect(),
            Err((e, _)) if n == 1 => vec![Err(e)],
            // Something in the batch failed and the transaction rolled back. Find out which
            // record it was by committing them one at a time, in the same order.
            Err((_, records)) => records
                .into_iter()
                .map(|r| match self.commit(conn, vec![r], sync) {
                    Ok(mut one) => Ok(one.pop().expect("one record, one entry")),
                    Err((e, _)) => Err(e),
                })
                .collect(),
        }
    }

    /// One transaction: read the head, chain and insert every record, sign the checkpoints
    /// that fall in the batch, commit. On failure nothing is written and the records come back.
    /// A batch that writes a signed checkpoint commits with `synchronous=FULL` (SR-50), and so
    /// does every batch with `sync` (it holds a record appended with
    /// [`append_synced`](AuditSink::append_synced)).
    fn commit(
        &self,
        conn: &mut Connection,
        records: Vec<DecisionRecord>,
        sync: bool,
    ) -> Result<Vec<AuditEntry>, (AuditError, Vec<DecisionRecord>)> {
        // Without `relaxed_sync` every commit is synced already, or there is no file to sync.
        let records = if sync && self.relaxed_sync.is_some() {
            records
        } else {
            match self.commit_tx(conn, records, false) {
                Ok(entries) => return Ok(entries),
                Err(CommitFailure::Error(e, records)) => return Err((e, records)),
                Err(CommitFailure::NeedsSync(records)) => records,
            }
        };
        // Only reached when `relaxed_sync` is set.
        let level = self.relaxed_sync.unwrap_or(SYNC_NORMAL);
        if let Err(e) = conn.pragma_update(None, "synchronous", SYNC_FULL) {
            return Err((e.into(), records));
        }
        let out = self.commit_tx(conn, records, true);
        restore_sync(conn, level);
        out.map_err(|f| match f {
            CommitFailure::Error(e, records) => (e, records),
            CommitFailure::NeedsSync(records) => (
                AuditError::Storage("a synced commit asked for a sync".into()),
                records,
            ),
        })
    }

    /// [`commit`](Self::commit)'s transaction. With `synced` false, a batch that would write a
    /// signed checkpoint on a relaxed connection is rolled back before anything is inserted
    /// and comes back as [`CommitFailure::NeedsSync`].
    fn commit_tx(
        &self,
        conn: &mut Connection,
        records: Vec<DecisionRecord>,
        synced: bool,
    ) -> Result<Vec<AuditEntry>, CommitFailure> {
        // Declared before the transaction, so an early return rolls back before releasing it.
        let gate = self.gate.hold();
        let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(e) => return Err(CommitFailure::Error(e.into(), records)),
        };
        let (mut seq, mut prev_hash) = match head_link(&tx) {
            Ok(h) => h,
            Err(e) => return Err(CommitFailure::Error(e, records)),
        };
        // Serialize each record once, canonically: the same text is hashed and stored as
        // `record_json`.
        let jsons: Vec<String> = records.iter().map(canonical_record_json).collect();
        let mut entries: Vec<AuditEntry> = Vec::with_capacity(records.len());
        for (record, json) in records.into_iter().zip(&jsons) {
            seq += 1;
            let entry_hash = entry_hash_from_json(seq, &prev_hash, json);
            let entry = AuditEntry {
                seq,
                prev_hash: std::mem::replace(&mut prev_hash, entry_hash.clone()),
                record,
                entry_hash,
            };
            entries.push(entry);
        }
        let every = self.checkpointing.as_ref().map_or(0, |c| c.every).max(1);
        let signs = self.checkpointing.as_ref().is_some_and(|c| c.every > 0)
            && entries.iter().any(|e| e.seq.is_multiple_of(every));
        if signs && !synced && self.relaxed_sync.is_some() {
            // `synchronous` cannot change inside a transaction: roll back (nothing is written
            // yet) and let `commit` run the batch again at `FULL`.
            drop(tx);
            return Err(CommitFailure::NeedsSync(
                entries.into_iter().map(|e| e.record).collect(),
            ));
        }
        let mut created = Vec::new();
        let written = entries
            .iter()
            .zip(&jsons)
            .try_for_each(|(entry, json)| {
                insert_entry(&tx, entry, json)?;
                if let Some(c) = self.checkpointing.as_ref().filter(|c| c.every > 0) {
                    if entry.seq.is_multiple_of(c.every) {
                        let cp = Checkpoint::sign(
                            &c.signer,
                            entry.seq,
                            &entry.entry_hash,
                            entry.record.at,
                        )?;
                        insert_checkpoint(&tx, &cp)?;
                        created.push(cp);
                    }
                }
                Ok::<(), AuditError>(())
            })
            .and_then(|()| {
                #[cfg(test)]
                self.probe_commit(&tx, format!("commit {}", seq));
                Ok(tx.commit()?)
            });
        // Before the backstop and the hook: neither may run under the gate.
        drop(gate);
        if let Err(e) = written {
            return Err(CommitFailure::Error(
                e,
                entries.into_iter().map(|e| e.record).collect(),
            ));
        }
        let n = entries.len() as u64;
        let activity = &self.activity;
        activity.committed.fetch_add(n, Ordering::AcqRel);
        if let (Some(kick), Some(c), Some(first), true) = (
            activity.wal_kick.get(),
            self.checkpointing.as_ref(),
            entries.first(),
            self.relaxed_sync.is_some(),
        ) {
            if nears_checkpoint(first.seq, seq, c.every, presync_lead(activity)) {
                // Full means a round or a sync is already waiting; a round syncs the WAL too.
                let _ = kick.try_send(WalMsg::SyncWal);
            }
        }
        if let Some(kick) = activity.wal_kick.get() {
            if i64::from(WAL_PAGES.replace(0)) >= WAL_WRITER_BACKSTOP_FRAMES {
                self.wal_backstop(conn);
            } else if activity.since_wal_checkpoint.fetch_add(1, Ordering::AcqRel) + 1
                >= WAL_CHECKPOINT_COMMITS
            {
                // Full means a kick is already waiting.
                let _ = kick.try_send(WalMsg::Kick);
            }
        }
        if let Some(hook) = self
            .checkpointing
            .as_ref()
            .and_then(|c| c.on_created.as_ref())
        {
            created.iter().for_each(|cp| hook(cp));
        }
        Ok(entries)
    }

    /// The writer's backstop (see [`WAL_WRITER_BACKSTOP_FRAMES`]): the WAL has outgrown
    /// what the background checkpointer manages, so checkpoint and truncate it here, on the
    /// writer's connection, with the batch's entries already committed. The connection waits
    /// up to its busy timeout for readers on other connections (the lease store's); its own
    /// has none, the writer holds it. Whatever the outcome the append has succeeded: a busy
    /// or failed checkpoint is reported and the next commit, finding the WAL still large,
    /// tries again.
    fn wal_backstop(&self, conn: &Connection) {
        #[cfg(any(test, feature = "testing"))]
        let started = std::time::Instant::now();
        // `TRUNCATE` takes the write lock: queue behind the lease store's writes rather than
        // sleep in the busy handler.
        let result = {
            let _gate = self.gate.hold();
            gated_checkpoint(&self.activity, conn, "TRUNCATE")
        };
        WalCounters::bump(&self.activity.wal_stats.backstops);
        #[cfg(any(test, feature = "testing"))]
        if let (Ok(_), Ok(mut t)) = (&result, self.activity.timings.lock()) {
            t.backstops.push(started.elapsed());
        }
        match result {
            Ok(done) if done.complete() => {
                self.activity
                    .since_wal_checkpoint
                    .store(0, Ordering::Release);
            }
            Ok(done) => eprintln!(
                "attenuo-audit: writer WAL checkpoint left {} of {} frames (busy: {})",
                done.wal_frames - done.checkpointed_frames,
                done.wal_frames,
                done.busy
            ),
            Err(e) => eprintln!("attenuo-audit: writer WAL checkpoint failed: {e}"),
        }
    }

    /// Tests: note `what` and the `synchronous` level `conn` runs at.
    #[cfg(test)]
    fn probe_commit(&self, conn: &Connection, what: String) {
        if let Some(log) = &self.probe {
            let level: i64 = conn
                .query_row("PRAGMA synchronous", [], |r| r.get(0))
                .unwrap_or(-1);
            log.lock()
                .unwrap()
                .push(format!("{what} synchronous={level}"));
        }
    }
}

/// Insert `entry`, whose record serializes to `record_json`.
fn insert_entry(
    tx: &Transaction<'_>,
    entry: &AuditEntry,
    record_json: &str,
) -> Result<(), AuditError> {
    let r = &entry.record;
    tx.prepare_cached(
        "INSERT INTO audit (seq, prev_hash, entry_hash, at, decision, reason, \
         originating_subject, agents, chain_depth, chain_digest, leases, server, tool, \
         arguments_digest, session_id, policy_ids, record_json, kind, chain_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
         ?18, ?19)",
    )?
    .execute(params![
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
        record_json,
        r.kind.as_str(),
        r.chain_id,
    ])?;
    Ok(())
}

impl SqliteAudit {
    /// Open (or create) the log at `path` with [`Durability::Normal`]. Pass `":memory:"` for a
    /// private in-memory log.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::open_with(path, Durability::default())
    }

    /// Open (or create) the log at `path` in WAL mode with the given durability.
    pub fn open_with(path: impl AsRef<Path>, durability: Durability) -> Result<Self, AuditError> {
        Self::from_connection(open_connection(path.as_ref(), durability)?)
    }

    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_connection(open_memory_connection()?)
    }

    /// Wrap an existing connection, creating the schema if needed.
    ///
    /// Fails for a log written with another entry hash construction than
    /// [`ENTRY_HASH_VERSION`], such as one written before RFC 8785
    /// canonical JSON (SR-20): there is no migration, start a new file.
    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        check_record_fields(&conn)?;
        conn.execute_batch(AUDIT_SCHEMA)?;
        conn.execute_batch(CHECKPOINT_SCHEMA)?;
        conn.execute_batch(META_SCHEMA)?;
        check_hash_version(&conn)?;
        // After the version check, so a log this version refuses is not changed by it.
        create_record_id_index(&conn)?;
        let relaxed_sync = relaxed_sync_of(&conn)?;
        let file = file_of(&conn);
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Arc::new(Mutex::new(conn)),
                checkpointing: None,
                activity: Arc::new(Activity::default()),
                relaxed_sync,
                gate: WriteGate::for_file(file.as_deref()),
                file,
                #[cfg(test)]
                probe: None,
            }),
            writer: OnceLock::new(),
            wal: None,
        })
    }

    /// Move WAL checkpoints off the writer: the writer connection stops checkpointing on
    /// commit (`wal_autocheckpoint=0`) and a background thread with its own connection runs
    /// `PRAGMA wal_checkpoint(PASSIVE)` every `interval`, or sooner after
    /// [`WAL_CHECKPOINT_COMMITS`] commits, plus `TRUNCATE` when the writer is idle and once
    /// more when the store is dropped. Under continuous load a round that finds the WAL past
    /// 64 MB pauses appends for a short catch-up pass so the WAL starts over instead of
    /// growing, and should the background thread still fall behind, the writer checkpoints
    /// itself once the WAL holds [`WAL_WRITER_BACKSTOP_FRAMES`] frames, so the WAL is
    /// bounded whatever the load. See `[audit] wal_checkpoint_seconds`.
    ///
    /// A zero `interval` changes nothing (SQLite checkpoints on the writer, every 1,000
    /// pages), and so does a store that is not a file in WAL mode, such as an in-memory one.
    /// Readers are unaffected: every read goes through the store's own connection, which sees
    /// every committed row whether or not it has been copied into the database file yet.
    pub fn with_wal_checkpoints(mut self, interval: Duration) -> Result<Self, AuditError> {
        if interval.is_zero() || self.wal.is_some() {
            return Ok(self);
        }
        let (path, synchronous) = {
            let conn = self.inner.conn.lock()?;
            let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            let path = conn
                .path()
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .filter(|_| mode.eq_ignore_ascii_case("wal"));
            let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
            (path, synchronous)
        };
        let Some(path) = path else {
            return Ok(self);
        };
        let conn = Connection::open(&path)?;
        let file = self.inner.file.clone().unwrap_or_else(|| path.clone());
        // Checkpoints sync the WAL and the database file as this setting says.
        conn.pragma_update(None, "synchronous", synchronous)?;
        conn.busy_timeout(Duration::ZERO)?;
        let (kick, msgs) = mpsc::sync_channel(1);
        let activity = Arc::clone(&self.inner.activity);
        let _ = activity.wal_kick.set(kick.clone());
        {
            let writer = self.inner.conn.lock()?;
            writer.pragma_update(None, "wal_autocheckpoint", 0)?;
            // After the pragma: setting `wal_autocheckpoint` installs SQLite's own hook.
            writer.wal_hook(Some(note_wal_pages));
        }
        self.wal = Some(WalCheckpointer::start(
            conn,
            Arc::clone(&self.inner.conn),
            interval,
            activity,
            (kick, msgs),
            file,
        )?);
        Ok(self)
    }

    /// What the background WAL checkpointer has done since the store was opened (for
    /// metrics). `None` when [`with_wal_checkpoints`](Self::with_wal_checkpoints) started no
    /// checkpointer (a zero interval, or a store that is not a file in WAL mode).
    pub fn wal_stats(&self) -> Option<WalStats> {
        self.wal
            .as_ref()
            .map(|_| self.inner.activity.wal_stats.snapshot())
    }

    /// Checkpoint the WAL into the database file now and truncate it (`TRUNCATE`), waiting
    /// up to the busy timeout for the locks that takes. `None` for a store that is not a
    /// file in WAL mode. The server calls it once more after draining at shutdown; dropping
    /// the store does it too.
    pub fn checkpoint_wal(&self) -> Result<Option<WalCheckpoint>, AuditError> {
        if let Some(wal) = &self.wal {
            return wal.truncate().map(Some);
        }
        let conn = self.inner.conn.lock()?;
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Ok(None);
        }
        wal_checkpoint(&conn, "TRUNCATE").map(Some)
    }

    /// The shared state, for the builders. They run before the first append starts the writer
    /// thread (which holds the other reference), so the `Arc` is still unique.
    fn inner_mut(&mut self) -> &mut Inner {
        Arc::get_mut(&mut self.inner).expect("SqliteAudit builders must run before any append")
    }

    /// Sign checkpoints with `signer`: one every `every` appended entries (0 turns the
    /// automatic ones off), plus whatever [`checkpoint_signed`](Self::checkpoint_signed) and
    /// [`checkpoint_if_new`](Self::checkpoint_if_new) are asked for.
    pub fn with_checkpointing(mut self, signer: attenuo_token::DetachedSigner, every: u64) -> Self {
        self.inner_mut().checkpointing = Some(Checkpointing {
            signer,
            every,
            on_created: None,
        });
        self
    }

    /// Call `hook` once for every checkpoint this log creates (not for repeat requests that
    /// return an existing one), after the commit that wrote it, which ran with
    /// `synchronous=FULL`: the checkpoint and every entry it covers are on disk (SR-50). For
    /// metrics, or to ship checkpoints off the host. No effect before
    /// [`with_checkpointing`](Self::with_checkpointing).
    pub fn with_checkpoint_hook(
        mut self,
        hook: impl Fn(&Checkpoint) + Send + Sync + 'static,
    ) -> Self {
        if let Some(c) = self.inner_mut().checkpointing.as_mut() {
            c.on_created = Some(Arc::new(hook));
        }
        self
    }

    /// The signed checkpoint of the current head, creating it if the head has none yet. Asking
    /// twice without an append in between returns the same checkpoint.
    pub fn checkpoint_signed(&self, now: OffsetDateTime) -> Result<Checkpoint, AuditError> {
        let c = self
            .inner
            .checkpointing
            .as_ref()
            .ok_or(AuditError::NoCheckpointSigner)?;
        let mut conn = self.inner.conn.lock()?;
        let gate = self.inner.gate.hold();
        // Synced like an append batch that writes a checkpoint (SR-50).
        let (cp, created) = with_full_sync(&mut conn, self.inner.relaxed_sync, |conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (seq, hash) = match head_in(&tx)? {
                Some(h) => (h.seq, h.entry_hash),
                None => (0, GENESIS_HASH.to_string()),
            };
            if let Some(existing) = checkpoint_at(&tx, seq)? {
                if existing.head_hash == hash {
                    return Ok((existing, false));
                }
                // Never sign over a conflict: the log and an earlier checkpoint disagree.
                return Err(AuditError::Corrupt {
                    seq,
                    detail: "a stored checkpoint disagrees with the log at its seq".into(),
                });
            }
            let cp = Checkpoint::sign(&c.signer, seq, &hash, now)?;
            insert_checkpoint(&tx, &cp)?;
            #[cfg(test)]
            self.inner.probe_commit(&tx, format!("checkpoint {seq}"));
            tx.commit()?;
            Ok::<_, AuditError>((cp, true))
        })??;
        drop(gate);
        if created {
            if let Some(hook) = &c.on_created {
                hook(&cp);
            }
        }
        Ok(cp)
    }

    /// Checkpoint the head only if it has advanced past the newest checkpoint; `None` when
    /// there is nothing new to sign (or the log is empty). The timer behind
    /// `[audit] checkpoint_interval_seconds` calls this.
    pub fn checkpoint_if_new(&self, now: OffsetDateTime) -> Result<Option<Checkpoint>, AuditError> {
        let (head, last) = {
            let conn = self.inner.conn.lock()?;
            let head: i64 =
                conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |r| r.get(0))?;
            let last: i64 =
                conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM checkpoints", [], |r| {
                    r.get(0)
                })?;
            (head, last)
        };
        if head == 0 || head <= last {
            return Ok(None);
        }
        self.checkpoint_signed(now).map(Some)
    }

    /// The newest checkpoint, if any.
    pub fn last_checkpoint(&self) -> Result<Option<Checkpoint>, AuditError> {
        let conn = self.inner.conn.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints \
             ORDER BY seq DESC LIMIT 1",
        )?;
        let cp = stmt.query_row([], checkpoint_from_row).optional()?;
        Ok(cp)
    }

    /// Checkpoints with `from <= seq <= to`, ascending.
    pub fn checkpoints_between(&self, from: u64, to: u64) -> Result<Vec<Checkpoint>, AuditError> {
        let conn = self.inner.conn.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints \
             WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq",
        )?;
        let rows = stmt.query_map(
            [
                from.min(i64::MAX as u64) as i64,
                to.min(i64::MAX as u64) as i64,
            ],
            checkpoint_from_row,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Walk the chain and verify every stored checkpoint against `keys`.
    pub fn verify_chain_signed(
        &self,
        keys: &CheckpointKeys,
    ) -> Result<SignedVerifyReport, AuditError> {
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit ORDER BY seq");
        let conn = self.inner.conn.lock()?;
        let checkpoints: Vec<Checkpoint> = {
            let mut stmt = conn.prepare(
                "SELECT seq, head_hash, at, kid, signature FROM checkpoints ORDER BY seq",
            )?;
            let rows = stmt.query_map([], checkpoint_from_row)?;
            rows.collect::<Result<_, _>>()?
        };
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(entry_from_row(row)))?;
        verify_with_checkpoints(rows.map(|r| r?), &checkpoints, keys, Start::Genesis)
    }

    /// Run `f` against the underlying connection while holding the write lock.
    ///
    /// Meant for operational tooling and tests (export, vacuum, deliberate tampering in a test).
    /// Anything written through here bypasses the chain, which `verify_chain` will report.
    pub fn with_connection<R>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let conn = self.inner.conn.lock()?;
        f(&conn)
    }

    /// Entries for one originating subject, newest first, at most `limit`.
    pub fn by_subject(&self, subject: &str, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE originating_subject = ?1 \
             ORDER BY seq DESC LIMIT ?2"
        );
        let conn = self.inner.conn.lock()?;
        query_entries(&conn, &sql, &[&subject, &(limit as i64)])
    }

    /// Up to `limit` entries with `from_seq <= seq <= to_seq` that match `filter`, in order.
    /// An empty filter is the same as [`AuditSink::range`] bounded by `to_seq`.
    pub fn range_filtered(
        &self,
        from_seq: u64,
        to_seq: u64,
        filter: &RecordFilter,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        self.entries_matching(
            from_seq,
            to_seq,
            &EntryFilter::from(filter),
            Order::Ascending,
            limit,
        )
    }

    /// Up to `limit` entries with `lo <= seq <= hi` that match `filter`, in `order`.
    ///
    /// Fewer than `limit` entries means the whole window was read. A full page stops at its
    /// last entry, so the next page in the same direction starts just past that entry's seq.
    ///
    /// The SQL narrows rows by the `seq` range (the primary key) and by the denormalized
    /// columns, compared with `=`, never as patterns. `agent` and `lease` live in JSON array
    /// columns and are found with a `LIKE` on the element as a quoted JSON string, with its
    /// `%`, `_` and `\` escaped, so `l1` does not match `l10`. The time window is compared
    /// with `julianday` and a one-second margin. Both are only a first cut: every row the SQL
    /// returns is decoded (and cross-checked against `record_json`) and must also pass
    /// [`EntryFilter::matches`].
    ///
    /// Rows are read in batches of `limit` and the store's lock is released between batches,
    /// so a long scan does not hold up appends. The cost grows with the window, not the page:
    /// callers bound the window.
    pub fn entries_matching(
        &self,
        lo: u64,
        hi: u64,
        filter: &EntryFilter,
        order: Order,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let mut out = Vec::new();
        if limit == 0 {
            return Ok(out);
        }
        let direction = match order {
            Order::Ascending => "ASC",
            Order::Descending => "DESC",
        };
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE seq >= ?1 AND seq <= ?2 \
             AND (?3 IS NULL OR kind IN (SELECT value FROM json_each(?3))) \
             AND (?4 IS NULL OR decision = ?4) \
             AND (?5 IS NULL OR reason = ?5) \
             AND (?6 IS NULL OR originating_subject = ?6) \
             AND (?7 IS NULL OR agents LIKE ?7 ESCAPE '\\') \
             AND (?8 IS NULL OR leases LIKE ?8 ESCAPE '\\') \
             AND (?9 IS NULL OR server = ?9) \
             AND (?10 IS NULL OR tool = ?10) \
             AND (?11 IS NULL OR chain_id = ?11) \
             AND (?12 IS NULL OR julianday(at) >= julianday(?12) - 1.0 / 86400) \
             AND (?13 IS NULL OR julianday(at) <= julianday(?13) + 1.0 / 86400) \
             ORDER BY seq {direction} LIMIT ?14"
        );
        let kinds = if filter.kinds.is_empty() {
            None
        } else {
            let names: Vec<&str> = filter.kinds.iter().map(|k| k.as_str()).collect();
            Some(serde_json::to_string(&names)?)
        };
        let decision = filter.decision.as_ref().map(decision_str);
        // The columns hold JSON arrays of strings: look for the element as a quoted string.
        let agent = match &filter.agent {
            Some(a) => Some(like_contains(&serde_json::to_string(&a.0)?)),
            None => None,
        };
        let lease = match &filter.lease {
            Some(l) => Some(like_contains(&serde_json::to_string(&l.0)?)),
            None => None,
        };
        let since = filter.since.map(fmt_time).transpose()?;
        let until = filter.until.map(fmt_time).transpose()?;
        let batch = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut lo = i64::try_from(lo).unwrap_or(i64::MAX);
        let mut hi = i64::try_from(hi).unwrap_or(i64::MAX);
        while lo <= hi {
            let rows = {
                let conn = self.inner.conn.lock()?;
                query_entries(
                    &conn,
                    &sql,
                    &[
                        &lo,
                        &hi,
                        &kinds,
                        &decision,
                        &filter.reason,
                        &filter.subject,
                        &agent,
                        &lease,
                        &filter.server,
                        &filter.tool,
                        &filter.chain_id,
                        &since,
                        &until,
                        &batch,
                    ],
                )?
            };
            let read_all = rows.len() < limit;
            for entry in rows {
                // A seq read from an INTEGER column fits in i64.
                let seq = entry.seq as i64;
                match order {
                    Order::Ascending => lo = seq + 1,
                    Order::Descending => hi = seq - 1,
                }
                if filter.matches(&entry.record) {
                    out.push(entry);
                    if out.len() == limit {
                        return Ok(out);
                    }
                }
            }
            if read_all {
                break;
            }
        }
        Ok(out)
    }

    /// The entry at `seq`, if there is one.
    pub fn entry_at(&self, seq: u64) -> Result<Option<AuditEntry>, AuditError> {
        let Ok(seq) = i64::try_from(seq) else {
            return Ok(None);
        };
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE seq = ?1");
        let conn = self.inner.conn.lock()?;
        Ok(query_entries(&conn, &sql, &[&seq])?.pop())
    }

    /// The entry whose record has id `id` (the hyphenated lower-case UUID that proxy denials
    /// and AuthZEN answers return as `decision_id`), if there is one. Uses the
    /// `audit_record_id_idx` expression index.
    pub fn entry_by_record_id(&self, id: &str) -> Result<Option<AuditEntry>, AuditError> {
        let sql =
            format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE {RECORD_ID_EXPR} = ?1 ORDER BY seq");
        let conn = self.inner.conn.lock()?;
        let found = query_entries(&conn, &sql, &[&id])?;
        // Record ids are random UUIDs, so one row at most is expected; take the first whose
        // decoded record really has that id.
        Ok(found.into_iter().find(|e| e.record.id.to_string() == id))
    }

    /// Up to `limit` stored checkpoints with `seq < before`, newest first. It only reads:
    /// unlike [`checkpoint_signed`](Self::checkpoint_signed) it never signs one.
    pub fn checkpoints_before(
        &self,
        before: u64,
        limit: usize,
    ) -> Result<Vec<Checkpoint>, AuditError> {
        let conn = self.inner.conn.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints \
             WHERE seq < ?1 ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            [
                i64::try_from(before).unwrap_or(i64::MAX),
                i64::try_from(limit).unwrap_or(i64::MAX),
            ],
            checkpoint_from_row,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The oldest stored checkpoint at or after `seq`: the first one whose signature covers
    /// the entry at `seq` through the hash chain. It is read as stored, not verified;
    /// [`verify_chain_signed`](Self::verify_chain_signed) checks signatures.
    pub fn checkpoint_covering(&self, seq: u64) -> Result<Option<Checkpoint>, AuditError> {
        let Ok(seq) = i64::try_from(seq) else {
            return Ok(None);
        };
        let conn = self.inner.conn.lock()?;
        let mut stmt = conn.prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints \
             WHERE seq >= ?1 ORDER BY seq LIMIT 1",
        )?;
        Ok(stmt.query_row([seq], checkpoint_from_row).optional()?)
    }

    /// The first entry after `after` (`seq > after`) of `kind` with this `tool` and
    /// `decision`, if any. For questions such as "was the policy reloaded after this
    /// decision?" (kind `admin`, tool `admin.policies.reload`, `allow`). It reads through the
    /// `kind` index, so it stays cheap on a long log as long as that kind is rare.
    pub fn first_entry_after(
        &self,
        after: u64,
        kind: attenuo_core::RecordKind,
        tool: &str,
        decision: &attenuo_core::Decision,
    ) -> Result<Option<AuditEntry>, AuditError> {
        let Ok(after) = i64::try_from(after) else {
            return Ok(None);
        };
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit \
             WHERE kind = ?1 AND tool = ?2 AND decision = ?3 AND seq > ?4 \
             ORDER BY seq LIMIT 1"
        );
        let conn = self.inner.conn.lock()?;
        Ok(query_entries(
            &conn,
            &sql,
            &[&kind.as_str(), &tool, &decision_str(decision), &after],
        )?
        .pop())
    }

    /// The issuance record (kind `root_token` or `exchange`) of each lease in `leases`, all of
    /// which belong to the chain `chain_id`. The issuance of a hop is the record whose last
    /// lease is that hop's, so its last agent is the agent the lease was issued to. Leases
    /// with no such record are absent from the result; if a lease has several, the earliest
    /// wins.
    ///
    /// Reads through the `chain_id` index and decodes only that chain's issuance records, so
    /// the cost grows with the chain, not the log.
    pub fn issuance_records(
        &self,
        chain_id: &str,
        leases: &[&LeaseId],
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let wanted: BTreeSet<&LeaseId> = leases.iter().copied().collect();
        let mut found: BTreeMap<LeaseId, AuditEntry> = BTreeMap::new();
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE chain_id = ?1 \
             AND kind IN ('root_token', 'exchange') ORDER BY seq"
        );
        let conn = self.inner.conn.lock()?;
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query([chain_id])?;
        while let Some(row) = rows.next()? {
            let entry = entry_from_row(row)?;
            let Some(last) = entry.record.leases.last() else {
                continue;
            };
            if wanted.contains(last) && !found.contains_key(last) {
                found.insert(last.clone(), entry);
            }
        }
        Ok(found.into_values().collect())
    }

    /// Every entry bound to one delegation chain, in order.
    pub fn by_chain(&self, chain_digest: &str) -> Result<Vec<AuditEntry>, AuditError> {
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE chain_digest = ?1 ORDER BY seq");
        let conn = self.inner.conn.lock()?;
        query_entries(&conn, &sql, &[&chain_digest])
    }

    /// Every entry whose chain held `lease`, in order.
    ///
    /// v0 note: `leases` is stored as a JSON array of strings and this is a `LIKE` on that text
    /// (the id is matched as a quoted JSON string so `l1` does not match `l10`). It is a full scan;
    /// a join table is the upgrade path when volume demands an index.
    pub fn by_lease(&self, lease: &LeaseId) -> Result<Vec<AuditEntry>, AuditError> {
        let pattern = like_contains(&serde_json::to_string(&lease.0)?);
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE leases LIKE ?1 ESCAPE '\\' ORDER BY seq"
        );
        let conn = self.inner.conn.lock()?;
        let candidates = query_entries(&conn, &sql, &[&pattern])?;
        // Confirm against the decoded record; LIKE is only a prefilter.
        Ok(candidates
            .into_iter()
            .filter(|e| e.record.leases.contains(lease))
            .collect())
    }

    /// Number of entries.
    pub fn len(&self) -> Result<u64, AuditError> {
        let conn = self.inner.conn.lock()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn is_empty(&self) -> Result<bool, AuditError> {
        Ok(self.len()? == 0)
    }
}

impl SqliteAudit {
    /// [`AuditSink::append`] and [`AuditSink::append_synced`].
    fn append_with(&self, record: DecisionRecord, sync: bool) -> Result<AuditEntry, AuditError> {
        let activity = &self.inner.activity;
        // Nothing queued for the writer and the connection free: commit on this thread and
        // skip the hand-off. Anything else (a batch in progress, appends waiting, a reader
        // holding the lock) goes to the writer, so group commit works as before under load.
        if activity.pending.load(Ordering::Acquire) == 0 {
            match self.inner.conn.try_lock() {
                Ok(mut conn) => {
                    let mut out = self.inner.append_locked(&mut conn, vec![record], sync);
                    return out.pop().expect("one record, one result");
                }
                Err(TryLockError::Poisoned(_)) => return Err(AuditError::Poisoned),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        activity.pending.fetch_add(1, Ordering::AcqRel);
        let result = self
            .writer
            .get_or_init(|| Writer::start(Arc::clone(&self.inner)))
            .append(record, sync);
        activity.pending.fetch_sub(1, Ordering::AcqRel);
        result
    }
}

impl AuditSink for SqliteAudit {
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        self.append_with(record, false)
    }

    /// The record's batch commits with `synchronous=FULL` (at `durability = "full"` every
    /// batch does). Under load, the records appended meanwhile share that commit and its
    /// `fsync`, as at `full` (group commit).
    fn append_synced(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        self.append_with(record, true)
    }

    fn sync_file(&self) -> Option<&Path> {
        self.inner.file.as_deref()
    }

    fn head(&self) -> Result<Option<AuditEntry>, AuditError> {
        let mut conn = self.inner.conn.lock()?;
        let tx = conn.transaction()?;
        head_in(&tx)
    }

    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let sql =
            format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE seq >= ?1 ORDER BY seq LIMIT ?2");
        let conn = self.inner.conn.lock()?;
        query_entries(&conn, &sql, &[&(from_seq as i64), &(limit as i64)])
    }

    fn verify_chain(&self) -> Result<VerifyReport, AuditError> {
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit ORDER BY seq");
        let conn = self.inner.conn.lock()?;
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
///
/// A file-backed store runs at the [`Durability`] it was opened with, except that
/// [`revoke`](LeaseStore::revoke) always commits with `synchronous=FULL`: losing a revocation
/// to a power failure would bring a revoked lease back, and revocations are rare enough that
/// their `fsync` does not matter. A [`charge`](LeaseStore::charge) that charges a `sum` limit
/// commits with `synchronous=FULL` too, unless it is made with
/// [`charge_sync_deferred`](LeaseStore::charge_sync_deferred), which commits it at the
/// store's level and leaves the sync to the caller's
/// [`append_synced`](crate::AuditSink::append_synced) on a [`SqliteAudit`] in the same file.
#[derive(Debug)]
pub struct SqliteLeaseStore {
    conn: Mutex<Connection>,
    /// `None` for a connection this crate did not open (or an in-memory one): its pragmas are
    /// left alone.
    durability: Option<Durability>,
    /// The database file (canonical path) of a store this crate opened on a file: the file a
    /// deferred `sum` charge's sync must cover. `None` otherwise, and then nothing is deferred.
    file: Option<PathBuf>,
    /// Held across every write (see [`WriteGate`]); shared with a [`SqliteAudit`] on the same
    /// file.
    gate: WriteGate,
    /// The key `calls_per` values are hashed under (`budget_meta`, ADR-0010).
    value_key: ValueKey,
    /// The key span-index fingerprints are hashed under (`budget_meta`, ADR-0009 phase 2).
    span_key: SpanKey,
    /// The `rowid` of the last `lease_sessions` row a `prune_sessions` pass looked at; 0 to
    /// start from the first.
    session_cursor: Mutex<i64>,
    /// Tests: every charge commit and the `synchronous` level it ran at.
    #[cfg(test)]
    probe: Option<Arc<Mutex<Vec<String>>>>,
}

impl SqliteLeaseStore {
    /// Open (or create) the registry at `path` with [`Durability::Normal`]. May be the same file
    /// as a [`SqliteAudit`].
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

    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_connection(open_memory_connection()?)
    }

    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        conn.execute_batch(LEASE_SCHEMA)?;
        add_approval_columns(&conn)?;
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
    /// [`SqliteAudit`] whose [`with_wal_checkpoints`](SqliteAudit::with_wal_checkpoints) is on:
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

/// What counter `key` holds (0 when it has never been charged).
fn counter_in(conn: &Connection, key: &CounterKey) -> Result<u64, AuditError> {
    let used: Option<i64> = conn
        .prepare_cached(
            "SELECT used FROM budget_counters \
             WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5",
        )?
        .query_row(
            params![key.lease, key.cap, key.kind, key.arg, key.value],
            |r| r.get(0),
        )
        .optional()?;
    let used = used.unwrap_or(0);
    u64::try_from(used)
        .map_err(|_| AuditError::Storage(format!("budget counter {used} is negative")))
}

/// [`LeaseStore::charge`] in one `IMMEDIATE` transaction: the re-check and the writes see the
/// same counters, and a concurrent charge waits for this one to commit.
fn charge_in(
    conn: &mut Connection,
    keys: &[CounterKey],
    decision_id: &str,
    charges: &[Charge],
    at: OffsetDateTime,
) -> Result<ChargeOutcome, AuditError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let already: bool = tx
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM budget_charges WHERE decision_id = ?1)")?
        .query_row([decision_id], |r| r.get(0))?;
    if already {
        return Err(AuditError::Storage(format!(
            "decision `{decision_id}` is already charged"
        )));
    }
    let planned = match plan(keys, charges, |k| counter_in(&tx, k))? {
        Ok(planned) => planned,
        Err(exhausted) => return Ok(exhausted),
    };
    let at = fmt_time(at)?;
    for w in &planned.writes {
        let (key, after, amount) = (&w.key, to_i64(w.after)?, to_i64(w.amount)?);
        tx.prepare_cached(
            "INSERT INTO budget_counters (lease, cap, kind, arg, value, used) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (lease, cap, kind, arg, value) DO UPDATE SET used = excluded.used",
        )?
        .execute(params![
            key.lease, key.cap, key.kind, key.arg, key.value, after
        ])?;
        tx.prepare_cached(
            "INSERT INTO budget_charges (decision_id, lease, cap, kind, arg, value, amount, at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?
        .execute(params![
            decision_id,
            key.lease,
            key.cap,
            key.kind,
            key.arg,
            key.value,
            amount,
            at
        ])?;
    }
    tx.commit()?;
    Ok(ChargeOutcome::Charged {
        used_after: planned.used_after,
    })
}

/// [`LeaseStore::refund`] in one `IMMEDIATE` transaction. The value rows of a `distinct` limit
/// are freed only when no other unrefunded decision logged them (SR-62); every other counter
/// gets back what the decision logged.
fn refund_in(
    conn: &mut Connection,
    decision_id: &str,
    at: OffsetDateTime,
) -> Result<u64, AuditError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let distinct = LimitKind::Distinct.as_str();
    let (rows, refunded, limits): (i64, i64, i64) = tx
        .prepare_cached(
            "SELECT COUNT(*), COUNT(refunded_at), \
                    COUNT(*) FILTER (WHERE kind NOT IN (?2, ?3, ?4, ?5, ?6)) \
             FROM budget_charges WHERE decision_id = ?1",
        )?
        .query_row(
            params![
                decision_id,
                USAGE_KINDS[0],
                USAGE_KINDS[1],
                USAGE_KINDS[2],
                DISTINCT_VALUE_KIND,
                distinct
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
    if rows == 0 {
        return Err(AuditError::UnknownCharge(decision_id.to_owned()));
    }
    if refunded > 0 {
        return Err(AuditError::ChargeRefunded(decision_id.to_owned()));
    }
    // The values this decision used, and whether another unrefunded decision used each too.
    let values: Vec<(String, i64, String, String, bool)> = tx
        .prepare_cached(
            "SELECT DISTINCT c.lease, c.cap, c.arg, c.value, EXISTS ( \
                 SELECT 1 FROM budget_charges o WHERE o.lease = c.lease AND o.cap = c.cap \
                   AND o.kind = c.kind AND o.arg = c.arg AND o.value = c.value \
                   AND o.decision_id <> c.decision_id AND o.refunded_at IS NULL) \
             FROM budget_charges c WHERE c.decision_id = ?1 AND c.kind = ?2",
        )?
        .query_map(params![decision_id, DISTINCT_VALUE_KIND], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<Result<_, _>>()?;
    let mut freed: u64 = 0;
    for (lease, cap, arg, value, shared) in values {
        if shared {
            continue;
        }
        let cleared = tx
            .prepare_cached(
                "UPDATE budget_counters SET used = 0 \
                 WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5 \
                   AND used > 0",
            )?
            .execute(params![lease, cap, DISTINCT_VALUE_KIND, arg, value])?;
        if cleared > 0 {
            tx.prepare_cached(
                "UPDATE budget_counters SET used = MAX(0, used - 1) \
                 WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ''",
            )?
            .execute(params![lease, cap, distinct, arg])?;
            freed += 1;
        }
    }
    // Every other counter: what the decision logged, row by row, saturating at 0. One
    // `UPDATE` per logged row rather than a `SUM` of them: two rows of one decision on one
    // counter (run usage of up to `MAX_LIMIT` each) would overflow SQLite's integer `SUM`
    // and fail the refund, where the memory store succeeds (fuzzing round 2, FZ2-3). A
    // `distinct` limit's count moves with its values, above, not with the amounts logged.
    let rows: Vec<(String, i64, String, String, String, i64)> = tx
        .prepare_cached(
            "SELECT lease, cap, kind, arg, value, amount FROM budget_charges \
             WHERE decision_id = ?1 AND kind NOT IN (?2, ?3)",
        )?
        .query_map(params![decision_id, DISTINCT_VALUE_KIND, distinct], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    let mut usage = Vec::new();
    for (lease, cap, kind, arg, value, amount) in rows {
        if USAGE_KINDS.contains(&kind.as_str()) {
            usage.push((lease, cap, kind, arg, value));
            continue;
        }
        tx.prepare_cached(
            "UPDATE budget_counters SET used = MAX(0, used - ?6) \
             WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5",
        )?
        .execute(params![lease, cap, kind, arg, value, amount])?;
    }
    tx.prepare_cached("UPDATE budget_charges SET refunded_at = ?2 WHERE decision_id = ?1")?
        .execute(params![decision_id, fmt_time(at)?])?;
    // A run-usage counter saturates at `MAX_LIMIT`, so what one decision logged is not what it
    // added once the counter was full: recompute it from the unrefunded rows left (FZ2-4).
    for (lease, cap, kind, arg, value) in usage {
        let amounts: Vec<i64> = tx
            .prepare_cached(
                "SELECT amount FROM budget_charges WHERE lease = ?1 AND cap = ?2 AND kind = ?3 \
                 AND arg = ?4 AND value = ?5 AND refunded_at IS NULL",
            )?
            .query_map(params![lease, cap, kind, arg, value], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let total = amounts
            .into_iter()
            .fold(0u64, |t, a| t.saturating_add(u64::try_from(a).unwrap_or(0)))
            .min(MAX_LIMIT);
        tx.prepare_cached(
            "UPDATE budget_counters SET used = ?6 \
             WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5",
        )?
        .execute(params![lease, cap, kind, arg, value, to_i64(total)?])?;
    }
    tx.commit()?;
    // Token-limit counters only (see `LeaseStore::refund`).
    Ok(limits as u64 + freed)
}

fn to_i64(v: u64) -> Result<i64, AuditError> {
    i64::try_from(v).map_err(|_| AuditError::Storage(format!("budget figure {v} out of range")))
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

/// Columns of an approval row, in the order [`approval_from_row`] reads them.
const APPROVAL_COLUMNS: &str = "id, chain_id, lease, call_hash, server, tool, arguments, labels, \
     decision_id, chain, created_at, expires_at, state, approver_subject, approver_method, \
     decided_at, consumed_by, jkt, untrusted_args";

fn approval_from_row(r: &Row<'_>) -> Result<Approval, AuditError> {
    let text = |i: usize| -> Result<String, AuditError> { Ok(r.get::<_, String>(i)?) };
    let opt =
        |i: usize| -> Result<Option<String>, AuditError> { Ok(r.get::<_, Option<String>>(i)?) };
    let approver = match (opt(13)?, opt(14)?) {
        (Some(subject), Some(method)) => Some(Approver {
            subject,
            method: ApprovalMethod::parse(&method)?,
        }),
        _ => None,
    };
    Ok(Approval {
        id: text(0)?,
        chain_id: LeaseId(text(1)?),
        lease: LeaseId(text(2)?),
        call_hash: text(3)?,
        server: text(4)?,
        tool: text(5)?,
        arguments: serde_json::from_str(&text(6)?)?,
        labels: serde_json::from_str(&text(7)?)?,
        decision_id: text(8)?,
        chain: serde_json::from_str(&text(9)?)?,
        created_at: parse_time(&text(10)?)?,
        expires_at: parse_time(&text(11)?)?,
        state: ApprovalState::parse(&text(12)?)?,
        approver,
        decided_at: opt(15)?.as_deref().map(parse_time).transpose()?,
        consumed_by: opt(16)?,
        jkt: opt(17)?,
        untrusted_args: match opt(18)? {
            Some(json) => serde_json::from_str(&json)?,
            None => Vec::new(),
        },
    })
}

fn approval_in(conn: &Connection, id: &str) -> Result<Option<Approval>, AuditError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {APPROVAL_COLUMNS} FROM approvals WHERE id = ?1"
    ))?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(r) => Ok(Some(approval_from_row(r)?)),
        None => Ok(None),
    }
}

/// Add the `approvals` columns that came after the table: `jkt` (approval tokens) and
/// `untrusted_args` (output labelling phase 2), each in the same release cycle as the table
/// and never shipped without it, but cheap to carry. A missing value reads as `NULL`: an
/// approval with no key binding, or with no matched arguments.
fn add_approval_columns(conn: &Connection) -> Result<(), AuditError> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('approvals')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for column in ["jkt", "untrusted_args"] {
        if !cols.iter().any(|c| c == column) {
            conn.execute_batch(&format!(
                "ALTER TABLE approvals ADD COLUMN {column} TEXT NULL"
            ))?;
        }
    }
    Ok(())
}

/// Approvals of one run for one call hash in one state. Expiry is compared in Rust: the
/// stored times are RFC 3339 text, which does not sort as time across offsets.
fn approvals_for_call(
    conn: &Connection,
    chain_id: &LeaseId,
    call_hash: &str,
    state: ApprovalState,
) -> Result<Vec<Approval>, AuditError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {APPROVAL_COLUMNS} FROM approvals \
         WHERE chain_id = ?1 AND call_hash = ?2 AND state = ?3"
    ))?;
    let mut rows = stmt.query(params![chain_id.0, call_hash, state.as_str()])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(approval_from_row(r)?);
    }
    Ok(out)
}

impl SqliteLeaseStore {
    /// [`LeaseStore::charge`], or with `defer` [`LeaseStore::charge_sync_deferred`].
    fn charge_with(
        &self,
        decision_id: &str,
        charges: &[Charge],
        at: OffsetDateTime,
        defer: bool,
    ) -> Result<(ChargeOutcome, bool), AuditError> {
        if charges.is_empty() {
            let none = ChargeOutcome::Charged {
                used_after: Vec::new(),
            };
            return Ok((none, false));
        }
        let keys = charges
            .iter()
            .map(|c| self.value_key.counter(c))
            .collect::<Result<Vec<_>, _>>()?;
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        // A lost `sum` charge could be spent again after a power failure, so a transaction
        // that charges one commits with `synchronous=FULL`, as revocations do (design 3.4).
        // Run usage is not a limit: it never adds the sync (design section 3.5).
        let relaxed = if charges.iter().any(|c| c.kind == LimitKind::Sum && !c.usage) {
            self.durability
                .filter(|d| *d != Durability::Full)
                .map(Durability::level)
        } else {
            None
        };
        if defer && relaxed.is_some() && self.file.is_some() {
            // Committed at the store's own level. The caller's synced append on the same
            // file syncs the WAL, which holds this commit, before the call goes anywhere.
            let outcome = charge_in(&mut conn, &keys, decision_id, charges, at)?;
            self.probe_charge(&conn, &outcome);
            let owed = matches!(outcome, ChargeOutcome::Charged { .. });
            return Ok((outcome, owed));
        }
        let outcome = with_full_sync(&mut conn, relaxed, |conn| {
            let outcome = charge_in(conn, &keys, decision_id, charges, at);
            if let Ok(o) = &outcome {
                self.probe_charge(conn, o);
            }
            outcome
        })??;
        Ok((outcome, false))
    }

    /// Tests: note a charge that committed and the `synchronous` level it committed at.
    #[cfg(not(test))]
    fn probe_charge(&self, _: &Connection, _: &ChargeOutcome) {}

    /// Tests: note a charge that committed and the `synchronous` level it committed at.
    #[cfg(test)]
    fn probe_charge(&self, conn: &Connection, outcome: &ChargeOutcome) {
        if let (Some(log), ChargeOutcome::Charged { .. }) = (&self.probe, outcome) {
            let level: i64 = conn
                .query_row("PRAGMA synchronous", [], |r| r.get(0))
                .unwrap_or(-1);
            log.lock()
                .unwrap()
                .push(format!("charge synchronous={level}"));
        }
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
        with_full_sync(&mut conn, relaxed, |conn| {
            selected_in(conn, selector, Some((reason, now)))
        })?
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
                "SELECT seq FROM run_spans WHERE chain_id = ?1 AND hash = ?2 ORDER BY seq",
            )?;
            for (probe, f) in probes.iter().enumerate() {
                let h = self.span_key.hash(f);
                let seqs = stmt.query_map(params![chain_id.0, &h[..]], |r| r.get::<_, i64>(0))?;
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

#[cfg(any(test, feature = "testing"))]
impl SqliteAudit {
    /// Tests and measurements: park the background WAL checkpointer for as long as the guard
    /// lives (it locks its own connection first thing in a round, so every round blocks).
    /// `None` without [`with_wal_checkpoints`](Self::with_wal_checkpoints).
    #[doc(hidden)]
    pub fn park_wal_checkpointer(&self) -> Option<std::sync::MutexGuard<'_, Connection>> {
        self.wal.as_ref().map(|w| w.conn.lock().unwrap())
    }

    /// Tests and measurements: the pauses the WAL checkpointers have imposed so far.
    #[doc(hidden)]
    pub fn wal_timings(&self) -> WalTimings {
        self.inner.activity.timings.lock().unwrap().clone()
    }

    /// Tests and measurements: whether the background checkpointer syncs the database file
    /// before its locked pass (on by default), for an A/B on one build.
    #[doc(hidden)]
    pub fn set_wal_presync(&self, on: bool) {
        self.inner.activity.no_presync.store(!on, Ordering::Relaxed);
    }

    /// Tests and measurements: how many entries before a signed checkpoint the WAL is synced
    /// off the request path ([`CHECKPOINT_PRESYNC_LEAD`] by default; 0 turns it off).
    #[doc(hidden)]
    pub fn set_checkpoint_presync_lead(&self, lead: u64) {
        self.inner
            .activity
            .presync_lead
            .store(lead.saturating_add(1), Ordering::Relaxed);
    }
}

#[cfg(test)]
impl SqliteAudit {
    /// Log every commit (with its `synchronous` level) into `log`, the log a test's
    /// checkpoint hook writes to as well.
    fn with_probe(mut self, log: Arc<Mutex<Vec<String>>>) -> Self {
        self.inner_mut().probe = Some(log);
        self
    }
}

#[cfg(test)]
impl SqliteLeaseStore {
    /// Log every charge that commits (with its `synchronous` level) into `log`.
    fn with_probe(mut self, log: Arc<Mutex<Vec<String>>>) -> Self {
        self.probe = Some(log);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_core::{
        AgentId, Capability, CapabilitySet, Decision, DelegationChain, OriginatingUser, RecordKind,
        ToolCall,
    };
    use time::macros::datetime;

    fn record(i: i64) -> DecisionRecord {
        let at = datetime!(2026-10-23 12:00 UTC);
        let chain = DelegationChain::root(
            OriginatingUser {
                subject: "user:mudit".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: at,
                attributes: Default::default(),
            },
            AgentId::new("agent:planner"),
            CapabilitySet::from_iter([Capability::new("github", "*")]),
            at,
            time::Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        let call = ToolCall::new("github", "read_file", serde_json::json!({ "i": i }));
        DecisionRecord::new(
            at + time::Duration::seconds(i),
            Decision::Allow,
            "policy_allow",
            &chain,
            &call,
            vec![],
        )
    }

    fn issuer() -> attenuo_token::Issuer {
        attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: time::Duration::minutes(5),
        })
    }

    fn synchronous(log: &SqliteAudit) -> i64 {
        log.with_connection(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
            .unwrap()
    }

    /// SR-50: at `durability = "normal"`, the commit that writes a signed checkpoint runs at
    /// `synchronous=FULL` (2), the hook sees the checkpoint only after that commit, and the
    /// connection is back at `NORMAL` (1) afterwards. Appends here run one at a time on the
    /// caller's thread, so the log's order is deterministic.
    #[test]
    fn checkpoint_commits_are_synced_before_the_hook_sr50() {
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&events);
        let log = SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Normal)
            .unwrap()
            .with_checkpointing(issuer().detached_signer(), 3)
            .with_checkpoint_hook(move |cp| seen.lock().unwrap().push(format!("hook {}", cp.seq)))
            .with_probe(Arc::clone(&events));
        assert_eq!(synchronous(&log), SYNC_NORMAL);
        for i in 0..4 {
            log.append(record(i)).unwrap();
        }
        log.checkpoint_signed(datetime!(2026-10-23 13:00 UTC))
            .unwrap();
        // Asking again returns the stored checkpoint: no commit, no hook.
        log.checkpoint_signed(datetime!(2026-10-23 13:00 UTC))
            .unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                "commit 1 synchronous=1",
                "commit 2 synchronous=1",
                "commit 3 synchronous=2",
                "hook 3",
                "commit 4 synchronous=1",
                "checkpoint 4 synchronous=2",
                "hook 4",
            ]
        );
        assert_eq!(synchronous(&log), SYNC_NORMAL);
        assert!(log.verify_chain().unwrap().ok);
    }

    /// SR-50, batched: a group commit that crosses a checkpoint is retried as a whole at
    /// `FULL`, and every record of it still gets its entry.
    #[test]
    fn a_batch_crossing_a_checkpoint_is_committed_synced_sr50() {
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&events);
        let log = SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Normal)
            .unwrap()
            .with_checkpointing(issuer().detached_signer(), 4)
            .with_checkpoint_hook(move |cp| seen.lock().unwrap().push(format!("hook {}", cp.seq)))
            .with_probe(Arc::clone(&events));
        let entries = {
            let mut conn = log.inner.conn.lock().unwrap();
            log.inner
                .append_locked(&mut conn, (0..6).map(record).collect(), false)
                .into_iter()
                .map(Result::unwrap)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            *events.lock().unwrap(),
            ["commit 6 synchronous=2", "hook 4"]
        );
        assert_eq!(synchronous(&log), SYNC_NORMAL);
        assert_eq!(log.len().unwrap(), 6);
    }

    /// Charges against lease `l1`: `calls` (max 100), and with `sum` a `sum` on `n`
    /// (max `sum_max`) adding `amount`.
    fn charges(sum: Option<(u64, u64)>) -> Vec<Charge> {
        let mut out = vec![Charge {
            hop: 0,
            cap: 0,
            lease: LeaseId::new("l1"),
            kind: LimitKind::Calls,
            arg: None,
            value: None,
            amount: 1,
            max: 100,
            usage: false,
        }];
        if let Some((amount, max)) = sum {
            out.push(Charge {
                hop: 0,
                cap: 0,
                lease: LeaseId::new("l1"),
                kind: LimitKind::Sum,
                arg: Some("n".into()),
                value: None,
                amount,
                max,
                usage: false,
            });
        }
        out
    }

    /// A log and a lease store on one file at `durability`, both writing to `events`.
    fn shared_file(
        dir: &tempfile::TempDir,
        durability: Durability,
        events: &Arc<Mutex<Vec<String>>>,
    ) -> (SqliteAudit, SqliteLeaseStore) {
        let path = dir.path().join("audit.db");
        let log = SqliteAudit::open_with(&path, durability)
            .unwrap()
            .with_probe(Arc::clone(events));
        let leases = SqliteLeaseStore::open_with(&path, durability)
            .unwrap()
            .with_probe(Arc::clone(events));
        (log, leases)
    }

    fn lease_synchronous(leases: &SqliteLeaseStore) -> i64 {
        leases
            .with_connection(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
            .unwrap()
    }

    /// Design 3.4 at `durability = "normal"`: a `sum` charge is synced before the call goes
    /// on. `charge` syncs its own commit; `charge_sync_deferred` commits at `NORMAL` and says
    /// so, and the decision's `append_synced` on the same file then commits at `FULL`, which
    /// syncs the WAL holding both. A `calls`-only charge and a plain append are unchanged.
    #[test]
    fn a_deferred_sum_charge_is_synced_by_the_decision_append() {
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let (log, leases) = shared_file(&dir, Durability::Normal, &events);
        assert!(leases.sync_file().is_some());
        assert_eq!(leases.sync_file(), log.sync_file());
        let at = datetime!(2026-10-24 12:00 UTC);
        leases
            .register(&LeaseId::new("l1"), None, at + time::Duration::hours(1))
            .unwrap();
        let sum = charges(Some((1, 1000)));

        assert!(matches!(
            leases.charge("d1", &sum, at).unwrap(),
            ChargeOutcome::Charged { .. }
        ));
        let (outcome, owed) = leases.charge_sync_deferred("d2", &sum, at).unwrap();
        assert!(matches!(outcome, ChargeOutcome::Charged { .. }) && owed);
        log.append_synced(record(1)).unwrap();
        let (_, owed) = leases
            .charge_sync_deferred("d3", &charges(None), at)
            .unwrap();
        assert!(!owed, "a calls-only charge owes no sync");
        log.append(record(2)).unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                "charge synchronous=2",
                "charge synchronous=1",
                "commit 1 synchronous=2",
                "charge synchronous=1",
                "commit 2 synchronous=1",
            ]
        );
        // Both connections are back at the store's level.
        assert_eq!(synchronous(&log), SYNC_NORMAL);
        assert_eq!(lease_synchronous(&leases), SYNC_NORMAL);
    }

    /// The deferred charge keeps the exhaustion check of `charge`: the re-check and the
    /// writes stay in one transaction, a charge that would go over writes nothing and owes
    /// no sync, and concurrent deferred charges never spend more than `max`.
    #[test]
    fn a_deferred_sum_charge_is_still_checked_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let (_log, leases) = shared_file(&dir, Durability::Normal, &events);
        let at = datetime!(2026-10-24 12:00 UTC);
        leases
            .register(&LeaseId::new("l1"), None, at + time::Duration::hours(1))
            .unwrap();
        let leases = Arc::new(leases);
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let leases = Arc::clone(&leases);
                std::thread::spawn(move || {
                    (0..5)
                        .filter(|i| {
                            let id = format!("d{t}-{i}");
                            let (outcome, owed) = leases
                                .charge_sync_deferred(&id, &charges(Some((3, 30))), at)
                                .unwrap();
                            let charged = matches!(outcome, ChargeOutcome::Charged { .. });
                            assert_eq!(charged, owed, "{outcome:?}");
                            charged
                        })
                        .count()
                })
            })
            .collect();
        let charged: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(charged, 10, "30 / 3: exactly ten charges fit");
        assert_eq!(
            leases.budget_used(&charges(Some((0, 30)))).unwrap(),
            [10, 30]
        );
        // Only the charges that went through committed anything.
        assert_eq!(events.lock().unwrap().len(), 10);
    }

    /// Nothing is deferred where `charge` has no sync to skip: a store at `full` syncs every
    /// commit, and an in-memory store has no file.
    #[test]
    fn full_and_in_memory_stores_never_defer_a_charge() {
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let (log, leases) = shared_file(&dir, Durability::Full, &events);
        let memory = SqliteLeaseStore::open_in_memory().unwrap();
        assert_eq!(memory.sync_file(), None);
        let at = datetime!(2026-10-24 12:00 UTC);
        for store in [&leases, &memory] {
            let (outcome, owed) = store
                .charge_sync_deferred("d1", &charges(Some((1, 10))), at)
                .unwrap();
            assert!(matches!(outcome, ChargeOutcome::Charged { .. }) && !owed);
        }
        log.append_synced(record(1)).unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            ["charge synchronous=2", "commit 1 synchronous=2"]
        );
    }

    /// Group commit: one record appended with `append_synced` makes its whole batch commit at
    /// `FULL`, so one sync covers every record in it.
    #[test]
    fn a_batch_with_a_synced_record_commits_at_full() {
        let dir = tempfile::tempdir().unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let log = SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Normal)
            .unwrap()
            .with_probe(Arc::clone(&events));
        for sync in [false, true] {
            let results = log.inner.append_batch((0..3).map(record).collect(), sync);
            assert!(results.iter().all(Result::is_ok));
        }
        assert_eq!(
            *events.lock().unwrap(),
            ["commit 3 synchronous=1", "commit 6 synchronous=2"]
        );
        assert_eq!(synchronous(&log), SYNC_NORMAL);
    }

    /// A store opened at `full` (or in memory) needs no extra step.
    #[test]
    fn full_and_in_memory_stores_commit_checkpoints_once_sr50() {
        let dir = tempfile::tempdir().unwrap();
        for log in [
            SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Full).unwrap(),
            SqliteAudit::open_in_memory().unwrap(),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let log = log
                .with_checkpointing(issuer().detached_signer(), 2)
                .with_probe(Arc::clone(&events));
            for i in 0..2 {
                log.append(record(i)).unwrap();
            }
            assert_eq!(
                events.lock().unwrap().len(),
                2,
                "{:?}",
                events.lock().unwrap()
            );
        }
    }

    /// SR-51: the synced operation's result comes back even when lowering `synchronous`
    /// afterwards fails (here because the operation left a transaction open, inside which
    /// SQLite refuses to change it).
    #[test]
    fn a_failed_restore_does_not_replace_the_result_sr51() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open_connection(&dir.path().join("x.db"), Durability::Normal).unwrap();
        let out = with_full_sync(&mut conn, Some(SYNC_NORMAL), |c| {
            c.execute_batch("BEGIN")?;
            Ok::<_, AuditError>(7)
        });
        assert_eq!(out.unwrap().unwrap(), 7);
        // The restore did fail: the connection is still at FULL.
        let level: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(level, SYNC_FULL);
        // And a failure of the operation itself is returned as such.
        conn.execute_batch("ROLLBACK").unwrap();
        let out = with_full_sync(&mut conn, Some(SYNC_NORMAL), |_| {
            Err::<u64, _>(AuditError::UnknownLease("x".into()))
        });
        assert!(matches!(out, Ok(Err(AuditError::UnknownLease(_)))));
    }

    /// SR-51: `revoke` at `normal` answers with the revocation's result, commits at `FULL` and
    /// goes back to `NORMAL`.
    #[test]
    fn revoke_returns_the_revocation_result_sr51() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            SqliteLeaseStore::open_with(dir.path().join("leases.db"), Durability::Normal).unwrap();
        let now = datetime!(2026-10-23 12:00 UTC);
        let (a, b) = (LeaseId::new("a"), LeaseId::new("b"));
        store
            .register(&a, None, now + time::Duration::hours(1))
            .unwrap();
        store
            .register(&b, Some(&a), now + time::Duration::hours(1))
            .unwrap();
        assert_eq!(store.revoke(&a, "test", now).unwrap(), 2);
        assert!(matches!(
            store.revoke(&LeaseId::new("nope"), "test", now),
            Err(AuditError::UnknownLease(_))
        ));
        let level: i64 = store
            .with_connection(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(level, SYNC_NORMAL);
    }

    /// SR-20: a log written with the v1 entry hash (no `audit_meta` row, entries present) is
    /// refused with a clear error; a new log records the construction.
    #[test]
    fn a_log_from_before_kind_and_chain_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit (seq INTEGER PRIMARY KEY, record_json TEXT NOT NULL)",
            )
            .unwrap();
        }
        let err = SqliteAudit::open(&path).unwrap_err().to_string();
        assert!(err.contains("`kind` and `chain_id`"), "{err}");
    }

    #[test]
    fn a_log_with_v1_hashes_is_refused_sr20() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        {
            let log = SqliteAudit::open(&path).unwrap();
            log.append(record(0)).unwrap();
            log.with_connection(|c| Ok(c.execute("DROP TABLE audit_meta", [])?))
                .unwrap();
        }
        let err = SqliteAudit::open(&path).unwrap_err().to_string();
        assert!(err.contains("earlier attenuo"), "{err}");
        assert!(err.contains(ENTRY_HASH_VERSION), "{err}");
        let other = dir.path().join("other.db");
        {
            let log = SqliteAudit::open(&other).unwrap();
            log.with_connection(|c| {
                Ok(c.execute("UPDATE audit_meta SET value = 'attenuo-audit-entry-v9'", [])?)
            })
            .unwrap();
        }
        let err = SqliteAudit::open(&other).unwrap_err().to_string();
        assert!(err.contains("attenuo-audit-entry-v9"), "{err}");
        // Reopening a current log works, empty or not.
        let fresh = dir.path().join("fresh.db");
        SqliteAudit::open(&fresh).unwrap();
        let log = SqliteAudit::open(&fresh).unwrap();
        log.append(record(1)).unwrap();
        drop(log);
        assert_eq!(SqliteAudit::open(&fresh).unwrap().len().unwrap(), 1);
    }

    /// The writer's backstop on its own: with the background checkpointer stuck (the test
    /// holds its connection, so every round blocks before its first checkpoint), appends keep
    /// the WAL under `WAL_WRITER_BACKSTOP_FRAMES` plus one batch, because the writer
    /// checkpoints and truncates it itself once a commit leaves that many frames.
    #[test]
    fn the_writer_checkpoints_itself_when_the_background_thread_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let audit = SqliteAudit::open_with(&path, Durability::Normal)
            .unwrap()
            .with_wal_checkpoints(Duration::from_millis(1))
            .unwrap();
        let wal_path = {
            let mut p = path.as_os_str().to_owned();
            p.push("-wal");
            PathBuf::from(p)
        };
        let wal_size = || std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
        let page_size: i64 = audit
            .with_connection(|c| Ok(c.query_row("PRAGMA page_size", [], |r| r.get(0))?))
            .unwrap();
        let backstop = (WAL_WRITER_BACKSTOP_FRAMES * page_size) as u64;

        // Park the background thread: it locks its own connection first thing in a round.
        let checkpointer = audit.wal.as_ref().unwrap();
        let parked = checkpointer.conn.lock().unwrap();

        let mut largest = 0;
        let mut truncations = 0;
        let mut i = 0;
        // Single-threaded appends: one commit each, so the WAL grows a few frames at a time
        // and the backstop fires with the WAL just past the threshold.
        while truncations < 2 {
            audit.append(record(i)).unwrap();
            i += 1;
            let size = wal_size();
            if size < largest / 2 {
                truncations += 1;
            }
            largest = largest.max(size);
            assert!(
                size < backstop + (16 << 20),
                "the WAL reached {} MB after {i} appends with the checkpointer parked",
                size >> 20
            );
            assert!(
                i < 100_000,
                "the backstop never fired ({} MB)",
                largest >> 20
            );
        }
        assert!(
            largest >= backstop,
            "the WAL was truncated before the backstop ({} MB)",
            largest >> 20
        );
        drop(parked);
        let report = audit.verify_chain().unwrap();
        assert!(report.ok);
        assert_eq!(report.entries, i as u64);
    }

    // -----------------------------------------------------------------------------------------
    // Queries for the admin API: `entries_matching`, lookups, checkpoint listing, the
    // record-id index.
    // -----------------------------------------------------------------------------------------

    /// A record with the given fields, at `2026-10-23 12:00 UTC + i seconds`.
    fn shaped(
        i: i64,
        kind: RecordKind,
        decision: Decision,
        agent: &str,
        lease: &str,
        tool: &str,
    ) -> DecisionRecord {
        let mut r = record(i);
        r.reason = match decision {
            Decision::Allow => "policy_allow".into(),
            Decision::Deny => "policy_deny".into(),
        };
        r.kind = kind;
        r.decision = decision;
        r.agents = vec![AgentId::new(agent)];
        r.leases = vec![LeaseId::new(lease)];
        r.chain_id = Some(lease.to_string());
        r.tool = tool.into();
        r
    }

    /// Twelve entries: seqs 1 to 12, at 12:00:01 to 12:00:12. Agents `l1` and `l10`, leases
    /// `a_1` and `ab1` (an unescaped `_` would match both), tools `50%` and `50x`.
    fn query_log() -> SqliteAudit {
        use Decision as D;
        use RecordKind as K;
        let log = SqliteAudit::open_in_memory().unwrap();
        let rows = [
            (K::Decision, D::Allow, "l1", "a_1", "50%"),
            (K::Decision, D::Deny, "l10", "ab1", "50x"),
            (K::Exchange, D::Allow, "l1", "a_1", "read_file"),
            (K::Decision, D::Deny, "l1", "a_1", "50%"),
            (K::LeaseRenew, D::Allow, "l10", "ab1", "read_file"),
            (K::Decision, D::Allow, "l10", "ab1", "50x"),
            (K::Admin, D::Allow, "l1", "a_1", "read_file"),
            (K::Decision, D::Deny, "l1", "ab1", "read_file"),
            (K::Decision, D::Allow, "l10", "a_1", "50%"),
            (K::Exchange, D::Allow, "l1", "ab1", "50x"),
            (K::Decision, D::Deny, "l10", "a_1", "read_file"),
            (K::Decision, D::Allow, "l1", "ab1", "50%"),
        ];
        for (i, (kind, decision, agent, lease, tool)) in rows.into_iter().enumerate() {
            log.append(shaped(i as i64 + 1, kind, decision, agent, lease, tool))
                .unwrap();
        }
        log
    }

    fn seqs(log: &SqliteAudit, filter: &EntryFilter) -> Vec<u64> {
        log.entries_matching(1, u64::MAX, filter, Order::Ascending, 1000)
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect()
    }

    #[test]
    fn each_filter_returns_exactly_the_matching_entries() {
        let log = query_log();
        let all = log.range(1, 1000).unwrap();
        let filters = [
            EntryFilter {
                kinds: vec![RecordKind::Exchange, RecordKind::LeaseRenew],
                ..Default::default()
            },
            EntryFilter {
                decision: Some(Decision::Deny),
                ..Default::default()
            },
            EntryFilter {
                reason: Some("policy_allow".into()),
                ..Default::default()
            },
            EntryFilter {
                subject: Some("user:mudit".into()),
                ..Default::default()
            },
            EntryFilter {
                agent: Some(AgentId::new("l1")),
                ..Default::default()
            },
            EntryFilter {
                lease: Some(LeaseId::new("a_1")),
                ..Default::default()
            },
            EntryFilter {
                server: Some("github".into()),
                ..Default::default()
            },
            EntryFilter {
                tool: Some("50%".into()),
                ..Default::default()
            },
            EntryFilter {
                chain_id: Some("ab1".into()),
                ..Default::default()
            },
            EntryFilter {
                since: Some(datetime!(2026-10-23 12:00:04 UTC)),
                until: Some(datetime!(2026-10-23 12:00:09 UTC)),
                ..Default::default()
            },
            EntryFilter {
                kinds: vec![RecordKind::Decision],
                decision: Some(Decision::Allow),
                agent: Some(AgentId::new("l10")),
                ..Default::default()
            },
        ];
        for f in filters {
            let want: Vec<u64> = all
                .iter()
                .filter(|e| f.matches(&e.record))
                .map(|e| e.seq)
                .collect();
            assert!(!want.is_empty(), "{f:?} matches nothing in the fixture");
            assert_eq!(seqs(&log, &f), want, "{f:?}");
        }
        // Spot checks against the fixture table rather than against `matches`.
        let agent = |a: &str| EntryFilter {
            agent: Some(AgentId::new(a)),
            ..Default::default()
        };
        assert_eq!(seqs(&log, &agent("l1")), [1, 3, 4, 7, 8, 10, 12]);
        assert_eq!(seqs(&log, &agent("l10")), [2, 5, 6, 9, 11]);
        assert_eq!(seqs(&log, &agent("l")), Vec::<u64>::new());
        // `LIKE` ignores ASCII case; the exact check does not.
        assert_eq!(seqs(&log, &agent("L1")), Vec::<u64>::new());
        let window = EntryFilter {
            since: Some(datetime!(2026-10-23 12:00:04 UTC)),
            until: Some(datetime!(2026-10-23 12:00:09 UTC)),
            ..Default::default()
        };
        assert_eq!(seqs(&log, &window), [4, 5, 6, 7, 8]);
        let multi = EntryFilter {
            kinds: vec![RecordKind::Exchange, RecordKind::Admin],
            ..Default::default()
        };
        assert_eq!(seqs(&log, &multi), [3, 7, 10]);
        assert_eq!(seqs(&log, &EntryFilter::default()).len(), 12);
    }

    #[test]
    fn percent_and_underscore_match_literally() {
        let log = query_log();
        let lease = |l: &str| EntryFilter {
            lease: Some(LeaseId::new(l)),
            ..Default::default()
        };
        assert_eq!(seqs(&log, &lease("a_1")), [1, 3, 4, 7, 9, 11]);
        assert_eq!(seqs(&log, &lease("ab1")), [2, 5, 6, 8, 10, 12]);
        assert_eq!(seqs(&log, &lease("a%")), Vec::<u64>::new());
        let tool = |t: &str| EntryFilter {
            tool: Some(t.into()),
            ..Default::default()
        };
        assert_eq!(seqs(&log, &tool("50%")), [1, 4, 9, 12]);
        assert_eq!(seqs(&log, &tool("50_")), Vec::<u64>::new());
        let agent = |a: &str| EntryFilter {
            agent: Some(AgentId::new(a)),
            ..Default::default()
        };
        assert_eq!(seqs(&log, &agent("l_")), Vec::<u64>::new());
        assert_eq!(seqs(&log, &agent("%")), Vec::<u64>::new());
    }

    #[test]
    fn pages_cover_the_window_in_both_directions_without_gaps_or_repeats() {
        let log = query_log();
        let l1 = EntryFilter {
            agent: Some(AgentId::new("l1")),
            ..Default::default()
        };
        let want = seqs(&log, &l1);
        for limit in 1..=4 {
            // Ascending: each page starts after the last entry of the previous one.
            let (mut got, mut from) = (Vec::new(), 1);
            loop {
                let page = log
                    .entries_matching(from, u64::MAX, &l1, Order::Ascending, limit)
                    .unwrap();
                got.extend(page.iter().map(|e| e.seq));
                if page.len() < limit {
                    break;
                }
                from = page.last().unwrap().seq + 1;
            }
            assert_eq!(got, want, "ascending, limit {limit}");
            // Descending: each page ends before the last (oldest) entry of the previous one.
            let (mut got, mut hi) = (Vec::new(), 12);
            loop {
                let page = log
                    .entries_matching(1, hi, &l1, Order::Descending, limit)
                    .unwrap();
                got.extend(page.iter().map(|e| e.seq));
                if page.len() < limit {
                    break;
                }
                hi = page.last().unwrap().seq - 1;
            }
            got.reverse();
            assert_eq!(got, want, "descending, limit {limit}");
        }
        // The window bounds the scan.
        let some = log
            .entries_matching(5, 9, &EntryFilter::default(), Order::Descending, 100)
            .unwrap();
        assert_eq!(
            some.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [9, 8, 7, 6, 5]
        );
    }

    #[test]
    fn range_filtered_keeps_its_meaning() {
        let log = query_log();
        let f = RecordFilter {
            kind: Some(RecordKind::Exchange),
            chain_id: None,
            ..Default::default()
        };
        let got: Vec<u64> = log
            .range_filtered(1, 12, &f, 100)
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect();
        assert_eq!(got, [3, 10]);
        let unfiltered = log
            .range_filtered(1, 5, &RecordFilter::default(), 100)
            .unwrap();
        assert_eq!(unfiltered.len(), 5);
    }

    #[test]
    fn lookups_by_seq_and_record_id() {
        let log = query_log();
        let e = log.entry_at(7).unwrap().unwrap();
        assert_eq!(e.seq, 7);
        assert!(log.entry_at(13).unwrap().is_none());
        assert!(log.entry_at(0).unwrap().is_none());
        assert!(log.entry_at(u64::MAX).unwrap().is_none());
        let id = e.record.id.to_string();
        assert_eq!(log.entry_by_record_id(&id).unwrap().unwrap().seq, 7);
        assert!(log
            .entry_by_record_id("00000000-0000-0000-0000-000000000000")
            .unwrap()
            .is_none());
        let plan: Vec<String> = log
            .with_connection(|c| {
                let sql =
                    format!("EXPLAIN QUERY PLAN SELECT seq FROM audit WHERE {RECORD_ID_EXPR} = ?1");
                let mut stmt = c.prepare(&sql)?;
                let rows = stmt.query_map([&id], |r| r.get::<_, String>(3))?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .unwrap();
        assert!(
            plan.iter().any(|p| p.contains("audit_record_id_idx")),
            "{plan:?}"
        );
    }

    #[test]
    fn checkpoints_are_listed_newest_first_without_signing() {
        let log = SqliteAudit::open_in_memory()
            .unwrap()
            .with_checkpointing(issuer().detached_signer(), 3);
        for i in 0..10 {
            log.append(record(i)).unwrap();
        }
        let count = || -> i64 {
            log.with_connection(|c| {
                Ok(c.query_row("SELECT COUNT(*) FROM checkpoints", [], |r| r.get(0))?)
            })
            .unwrap()
        };
        assert_eq!(count(), 3);
        let seqs = |v: Vec<Checkpoint>| v.iter().map(|c| c.seq).collect::<Vec<_>>();
        assert_eq!(
            seqs(log.checkpoints_before(u64::MAX, 10).unwrap()),
            [9, 6, 3]
        );
        assert_eq!(seqs(log.checkpoints_before(9, 1).unwrap()), [6]);
        assert!(log.checkpoints_before(3, 10).unwrap().is_empty());
        assert_eq!(log.checkpoint_covering(4).unwrap().unwrap().seq, 6);
        assert_eq!(log.checkpoint_covering(6).unwrap().unwrap().seq, 6);
        assert!(log.checkpoint_covering(10).unwrap().is_none());
        assert_eq!(count(), 3, "listing must not sign");
    }

    #[test]
    fn first_entry_after_finds_the_next_one_of_a_kind() {
        let log = query_log();
        let next = |after| {
            log.first_entry_after(after, RecordKind::Exchange, "50x", &Decision::Allow)
                .unwrap()
                .map(|e| e.seq)
        };
        assert_eq!(next(0), Some(10));
        assert_eq!(next(10), None);
        let deny = log
            .first_entry_after(0, RecordKind::Exchange, "50x", &Decision::Deny)
            .unwrap();
        assert!(deny.is_none());
    }

    /// The record-id index is created when a log written without it is opened. It changes no
    /// row (so no hash) and the log still verifies. A row with damaged JSON does not stop the
    /// open; `verify` reports it as before.
    #[test]
    fn the_record_id_index_is_added_to_an_existing_log_without_touching_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("before-index.db");
        let dump = |log: &SqliteAudit| -> Vec<String> {
            log.with_connection(|c| {
                let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit ORDER BY seq");
                let mut stmt = c.prepare(&sql)?;
                let rows = stmt.query_map([], |r| {
                    let mut cols = Vec::new();
                    for i in 0..18 {
                        cols.push(format!("{:?}", r.get_ref(i)?));
                    }
                    Ok(cols.join("|"))
                })?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .unwrap()
        };
        let index_exists = |log: &SqliteAudit| -> bool {
            log.with_connection(|c| {
                Ok(c.query_row(
                    "SELECT EXISTS (SELECT 1 FROM sqlite_master \
                     WHERE type = 'index' AND name = 'audit_record_id_idx')",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
        };
        let (before, id) = {
            let log = SqliteAudit::open(&path).unwrap();
            for i in 0..5 {
                log.append(record(i)).unwrap();
            }
            // Make the file look like one written before the index existed.
            log.with_connection(|c| Ok(c.execute_batch("DROP INDEX audit_record_id_idx")?))
                .unwrap();
            assert!(!index_exists(&log));
            let id = log.entry_at(4).unwrap().unwrap().record.id.to_string();
            (dump(&log), id)
        };
        let log = SqliteAudit::open(&path).unwrap();
        assert!(index_exists(&log));
        assert_eq!(dump(&log), before, "opening must not change any row");
        assert!(log.verify_chain().unwrap().ok);
        assert_eq!(log.entry_by_record_id(&id).unwrap().unwrap().seq, 4);
        // A row whose JSON was damaged while the index did not exist.
        log.with_connection(|c| {
            c.execute_batch(
                "DROP INDEX audit_record_id_idx; \
                 UPDATE audit SET record_json = '{not json' WHERE seq = 2;",
            )?;
            Ok(())
        })
        .unwrap();
        drop(log);
        let log = SqliteAudit::open(&path).expect("a damaged row must not stop the open");
        assert!(index_exists(&log));
        assert_eq!(log.verify_chain().unwrap().first_bad_seq, Some(2));
    }

    fn gate_of(g: &WriteGate) -> Arc<Ticket> {
        g.0.clone().expect("a file-backed store has a write gate")
    }

    /// One gate per canonical file: the audit log and the lease store on one file share it
    /// (also through another spelling of the path), stores on other files do not, and an
    /// in-memory store has none.
    #[test]
    fn write_gate_is_shared_per_file_and_absent_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.db");
        let audit = SqliteAudit::open(&a).unwrap();
        let leases = SqliteLeaseStore::open(&a).unwrap();
        let spelled = SqliteLeaseStore::open(dir.path().join(".").join("a.db")).unwrap();
        let other = SqliteLeaseStore::open(dir.path().join("b.db")).unwrap();
        let shared = gate_of(&audit.inner.gate);
        assert!(Arc::ptr_eq(&shared, &gate_of(&leases.gate)));
        assert!(Arc::ptr_eq(&shared, &gate_of(&spelled.gate)));
        assert!(!Arc::ptr_eq(&shared, &gate_of(&other.gate)));
        assert!(SqliteLeaseStore::open_in_memory().unwrap().gate.0.is_none());
        assert!(SqliteAudit::open_in_memory()
            .unwrap()
            .inner
            .gate
            .0
            .is_none());
        assert!(SqliteAudit::open(":memory:")
            .unwrap()
            .inner
            .gate
            .0
            .is_none());
        // Once every store on a file is gone its gate goes too, and a new store gets a new one.
        let weak = Arc::downgrade(&shared);
        drop((shared, audit, leases, spelled));
        assert!(weak.upgrade().is_none());
        let again = SqliteLeaseStore::open(&a).unwrap();
        assert!(again.gate.0.is_some());
    }

    /// Writes on either connection wait for the gate; reads do not.
    #[test]
    fn writes_wait_for_the_gate_and_reads_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let audit = Arc::new(SqliteAudit::open(&path).unwrap());
        let leases = Arc::new(SqliteLeaseStore::open(&path).unwrap());
        let at = datetime!(2026-10-23 12:00 UTC);
        leases.register(&LeaseId::new("l1"), None, at).unwrap();
        audit.append(record(1)).unwrap();

        let held = leases.gate.hold();
        let (done_tx, done) = mpsc::channel();
        let writers = [
            {
                let (leases, done_tx) = (leases.clone(), done_tx.clone());
                std::thread::spawn(move || {
                    leases.renew(&LeaseId::new("l1"), at, at).unwrap();
                    done_tx.send("renew").unwrap();
                })
            },
            {
                let (audit, done_tx) = (audit.clone(), done_tx.clone());
                std::thread::spawn(move || {
                    audit.append(record(2)).unwrap();
                    done_tx.send("append").unwrap();
                })
            },
        ];
        // Lease-store reads go through while the gate is held, even with a lease write
        // waiting for it (the lease store takes the gate before its connection).
        std::thread::sleep(Duration::from_millis(50));
        assert!(leases.get(&LeaseId::new("l1")).unwrap().is_some());
        assert!(leases.labels(&LeaseId::new("l1")).unwrap().is_empty());
        assert!(
            done.recv_timeout(Duration::from_millis(200)).is_err(),
            "a write went through while the gate was held"
        );
        drop(held);
        let mut finished: Vec<_> = (0..2)
            .map(|_| done.recv_timeout(Duration::from_secs(10)).unwrap())
            .collect();
        finished.sort_unstable();
        assert_eq!(finished, ["append", "renew"]);
        writers.into_iter().for_each(|w| w.join().unwrap());
        assert_eq!(audit.head().unwrap().unwrap().seq, 2);
    }

    /// The WAL sync ahead of a signed checkpoint is asked for once per checkpoint, by the
    /// commit that brings the head within the lead of it, and never by the commit that writes
    /// the checkpoint itself.
    #[test]
    fn nears_checkpoint_fires_once_per_checkpoint() {
        // One entry per commit, every 1,000, lead 32: only the commit of entry 968.
        let fired: Vec<u64> = (1..=3000)
            .filter(|&seq| nears_checkpoint(seq, seq, 1000, 32))
            .collect();
        assert_eq!(fired, [968, 1968, 2968]);
        // A batch that steps over the point fires; one that goes past the checkpoint does
        // not (it writes the checkpoint and syncs at FULL anyway).
        assert!(nears_checkpoint(960, 975, 1000, 32));
        assert!(!nears_checkpoint(960, 1000, 1000, 32));
        assert!(!nears_checkpoint(969, 990, 1000, 32));
        // The lead is capped at half the interval; off when the lead or `every` is 0.
        let fired: Vec<u64> = (1..=20)
            .filter(|&seq| nears_checkpoint(seq, seq, 10, 32))
            .collect();
        assert_eq!(fired, [5, 15]);
        assert!(!nears_checkpoint(968, 968, 1000, 0));
        assert!(!nears_checkpoint(968, 968, 0, 32));
    }
}
