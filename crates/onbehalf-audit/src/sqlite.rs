//! SQLite-backed audit sink and lease store.
//!
//! Both wrap a single `rusqlite::Connection` behind a `Mutex`. Audit appends go through one
//! writer thread (group commit, see [`SqliteAudit`]): it takes the lock, reads the current head
//! and inserts the next rows in one transaction, so two entries can never share a `prev_hash`.
//! The lock and the single writer, not SQLite's locking, keep the chain linear within a
//! process; across processes SQLite's write lock plus the `UNIQUE` constraint on `entry_hash`
//! and the primary key on `seq` make a fork fail rather than succeed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, TryLockError};
use std::time::Duration;

use onbehalf_core::{DecisionRecord, LeaseId};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::checkpoint::{
    verify_with_checkpoints, Checkpoint, CheckpointKeys, SignedVerifyReport, Start,
};
use crate::error::AuditError;
use crate::lease::{classify, LeaseRow, LeaseStatus, LeaseStore};
use crate::log::{
    canonical_record_json, entry_hash_from_json, verify_entries, AuditEntry, AuditSink,
    VerifyReport, ENTRY_HASH_VERSION, GENESIS_HASH,
};

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
"#;

/// Columns read back for an entry, in the order `entry_from_row` expects.
const ENTRY_COLUMNS: &str = "seq, prev_hash, entry_hash, decision, reason, originating_subject, \
     agents, chain_depth, chain_digest, leases, server, tool, arguments_digest, session_id, \
     policy_ids, record_json";

/// How long a connection waits for another connection's write lock before giving up with
/// `SQLITE_BUSY`. Within one process the store's own lock serializes writers; this covers a
/// second process (and the audit and lease connections of one server, which share a file).
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
            "onbehalf-audit: could not set synchronous back to {level} after a synced commit \
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

/// The `synchronous` level of `conn` if it is below `FULL` and there is a file to sync.
fn relaxed_sync_of(conn: &Connection) -> Result<Option<i64>, AuditError> {
    let file_backed = conn.path().is_some_and(|p| !p.is_empty());
    let level: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    Ok((file_backed && level < SYNC_FULL).then_some(level))
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
                    "this audit log was written by an earlier onbehalf (entry hash v1, before \
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
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") && !mode.eq_ignore_ascii_case("memory") {
        return Err(AuditError::Storage(format!(
            "could not switch {} to WAL mode (journal_mode is `{mode}`)",
            path.display()
        )));
    }
    conn.pragma_update(None, "synchronous", durability.pragma())?;
    Ok(conn)
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
///    most [`WAL_CATCH_UP_PASSES`]), then one more `PASSIVE` while holding the store's
///    connection lock, which pauses appends in this process for as long as it takes to copy
///    that remainder and sync. SQLite only starts a WAL over from its
///    beginning when a write finds every frame already copied, which under continuous load
///    step 1 alone never achieves (it copies up to where the WAL ended when it started), so
///    without this the WAL file would grow for as long as the load lasts.
/// 3. If no append is queued or in progress and everything was copied, `TRUNCATE` (busy
///    timeout zero, so it never makes an append wait), which shrinks the WAL file to zero.
///
/// Stopping runs a final `TRUNCATE`.
struct WalCheckpointer {
    msgs: mpsc::SyncSender<WalMsg>,
    conn: Arc<Mutex<Connection>>,
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
}

impl WalCheckpointer {
    fn start(
        conn: Connection,
        store: Arc<Mutex<Connection>>,
        interval: Duration,
        activity: Arc<Activity>,
        msgs: mpsc::SyncSender<WalMsg>,
        rx: mpsc::Receiver<WalMsg>,
    ) -> Result<Self, AuditError> {
        let conn = Arc::new(Mutex::new(conn));
        let shared = WalShared {
            conn: Arc::clone(&conn),
            store,
            activity,
            interval,
        };
        let thread = std::thread::Builder::new()
            .name("onbehalf-audit-wal".into())
            .spawn(move || wal_loop(&shared, &rx))
            .map_err(|e| AuditError::Storage(format!("cannot start the WAL checkpointer: {e}")))?;
        Ok(Self {
            msgs,
            conn,
            thread: Some(thread),
        })
    }

    /// `TRUNCATE` now, waiting up to the busy timeout for the locks it needs.
    fn truncate(&self) -> Result<WalCheckpoint, AuditError> {
        let conn = self.conn.lock()?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let result = wal_checkpoint(&conn, "TRUNCATE");
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
            Ok(WalMsg::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Final checkpoint. The writer thread has stopped (`SqliteAudit`'s drop joins
                // it first), so waiting for the write lock is fine.
                let Ok(conn) = shared.conn.lock() else { return };
                let _ = conn.busy_timeout(BUSY_TIMEOUT);
                if let Err(e) = wal_checkpoint(&conn, "TRUNCATE") {
                    eprintln!("onbehalf-audit: final WAL checkpoint failed: {e}");
                }
                return;
            }
        }
        if let Err(e) = wal_round(shared) {
            eprintln!("onbehalf-audit: WAL checkpoint failed: {e}");
        }
    }
}

/// One round: see [`WalCheckpointer`].
fn wal_round(shared: &WalShared) -> Result<(), AuditError> {
    let conn = shared.conn.lock()?;
    let activity = &shared.activity;
    activity.since_wal_checkpoint.store(0, Ordering::Release);
    let committed_before = activity.committed.load(Ordering::Acquire);
    let mut done = wal_checkpoint(&conn, "PASSIVE")?;
    if done.wal_frames >= WAL_RESTART_FRAMES {
        // Catch up without the lock first: each pass copies what was committed during the
        // previous one, so the frames left for the locked pass (and the pause) stay small.
        for _ in 0..WAL_CATCH_UP_PASSES {
            let again = wal_checkpoint(&conn, "PASSIVE")?;
            let arrived = again.wal_frames - done.wal_frames;
            done = again;
            if arrived <= WAL_LOCKED_RESIDUE {
                break;
            }
        }
    }
    if done.wal_frames >= WAL_RESTART_FRAMES {
        let _store = shared.store.lock()?;
        done = wal_checkpoint(&conn, "PASSIVE")?;
    }
    let idle = activity.pending.load(Ordering::Acquire) == 0
        && activity.committed.load(Ordering::Acquire) == committed_before;
    if done.complete() && done.wal_frames > 0 && idle {
        // Busy timeout zero: if an append starts meanwhile, give up rather than make it
        // wait; the next round tries again.
        let _ = wal_checkpoint(&conn, "TRUNCATE");
    }
    Ok(())
}

type CheckpointHook = Arc<dyn Fn(&Checkpoint) + Send + Sync>;

/// Automatic checkpointing: sign the head every `every` entries, inside the append's
/// transaction, so a checkpoint can never refer to a head that was not committed. That
/// transaction commits with `synchronous=FULL` whatever the store's durability, before the
/// `on_created` hook sees the checkpoint (SR-50).
struct Checkpointing {
    signer: onbehalf_token::DetachedSigner,
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
            .name("onbehalf-audit-writer".into())
            .spawn(move || writer_loop(&inner, &rx))
        {
            Ok(thread) => Self {
                jobs: Some(tx),
                thread: Some(thread),
            },
            // Without a writer every append fails, and so every decision is denied.
            Err(e) => {
                eprintln!("onbehalf-audit: cannot start the audit writer thread: {e}");
                Self {
                    jobs: None,
                    thread: None,
                }
            }
        }
    }

    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        let stopped = || AuditError::Storage("the audit writer is not running".into());
        let jobs = self.jobs.as_ref().ok_or_else(stopped)?;
        let (reply, answer) = mpsc::sync_channel(1);
        jobs.send(Job { record, reply }).map_err(|_| stopped())?;
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
        let (records, replies): (Vec<_>, Vec<_>) =
            batch.into_iter().map(|j| (j.record, j.reply)).unzip();
        for (reply, result) in replies.into_iter().zip(inner.append_batch(records)) {
            // The caller always waits for its answer; a send can only fail if it panicked.
            let _ = reply.send(result);
        }
    }
}

impl Inner {
    /// Commit `records` in order, as one transaction when possible. One result per record.
    fn append_batch(&self, records: Vec<DecisionRecord>) -> Vec<Result<AuditEntry, AuditError>> {
        let n = records.len();
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return (0..n).map(|_| Err(AuditError::Poisoned)).collect(),
        };
        self.append_locked(&mut conn, records)
    }

    /// [`append_batch`](Self::append_batch) with the connection already locked.
    fn append_locked(
        &self,
        conn: &mut Connection,
        records: Vec<DecisionRecord>,
    ) -> Vec<Result<AuditEntry, AuditError>> {
        let n = records.len();
        match self.commit(conn, records) {
            Ok(entries) => entries.into_iter().map(Ok).collect(),
            Err((e, _)) if n == 1 => vec![Err(e)],
            // Something in the batch failed and the transaction rolled back. Find out which
            // record it was by committing them one at a time, in the same order.
            Err((_, records)) => records
                .into_iter()
                .map(|r| match self.commit(conn, vec![r]) {
                    Ok(mut one) => Ok(one.pop().expect("one record, one entry")),
                    Err((e, _)) => Err(e),
                })
                .collect(),
        }
    }

    /// One transaction: read the head, chain and insert every record, sign the checkpoints
    /// that fall in the batch, commit. On failure nothing is written and the records come back.
    /// A batch that writes a signed checkpoint commits with `synchronous=FULL` (SR-50).
    fn commit(
        &self,
        conn: &mut Connection,
        records: Vec<DecisionRecord>,
    ) -> Result<Vec<AuditEntry>, (AuditError, Vec<DecisionRecord>)> {
        let records = match self.commit_tx(conn, records, false) {
            Ok(entries) => return Ok(entries),
            Err(CommitFailure::Error(e, records)) => return Err((e, records)),
            Err(CommitFailure::NeedsSync(records)) => records,
        };
        // `commit_tx` asks for a sync only when `relaxed_sync` is set.
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
        if let Err(e) = written {
            return Err(CommitFailure::Error(
                e,
                entries.into_iter().map(|e| e.record).collect(),
            ));
        }
        let n = entries.len() as u64;
        let activity = &self.activity;
        activity.committed.fetch_add(n, Ordering::AcqRel);
        if let Some(kick) = activity.wal_kick.get() {
            if activity.since_wal_checkpoint.fetch_add(1, Ordering::AcqRel) + 1
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
         arguments_digest, session_id, policy_ids, record_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
    /// [`ENTRY_HASH_VERSION`](crate::ENTRY_HASH_VERSION), such as one written before RFC 8785
    /// canonical JSON (SR-20): there is no migration, start a new file.
    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        conn.execute_batch(AUDIT_SCHEMA)?;
        conn.execute_batch(CHECKPOINT_SCHEMA)?;
        conn.execute_batch(META_SCHEMA)?;
        check_hash_version(&conn)?;
        let relaxed_sync = relaxed_sync_of(&conn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Arc::new(Mutex::new(conn)),
                checkpointing: None,
                activity: Arc::new(Activity::default()),
                relaxed_sync,
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
    /// growing. See `[audit] wal_checkpoint_seconds`.
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
        // Checkpoints sync the WAL and the database file as this setting says.
        conn.pragma_update(None, "synchronous", synchronous)?;
        conn.busy_timeout(Duration::ZERO)?;
        let (kick, msgs) = mpsc::sync_channel(1);
        let activity = Arc::clone(&self.inner.activity);
        let _ = activity.wal_kick.set(kick.clone());
        self.inner
            .conn
            .lock()?
            .pragma_update(None, "wal_autocheckpoint", 0)?;
        self.wal = Some(WalCheckpointer::start(
            conn,
            Arc::clone(&self.inner.conn),
            interval,
            activity,
            kick,
            msgs,
        )?);
        Ok(self)
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
    pub fn with_checkpointing(
        mut self,
        signer: onbehalf_token::DetachedSigner,
        every: u64,
    ) -> Self {
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

impl AuditSink for SqliteAudit {
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        let activity = &self.inner.activity;
        // Nothing queued for the writer and the connection free: commit on this thread and
        // skip the hand-off. Anything else (a batch in progress, appends waiting, a reader
        // holding the lock) goes to the writer, so group commit works as before under load.
        if activity.pending.load(Ordering::Acquire) == 0 {
            match self.inner.conn.try_lock() {
                Ok(mut conn) => {
                    let mut out = self.inner.append_locked(&mut conn, vec![record]);
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
            .append(record);
        activity.pending.fetch_sub(1, Ordering::AcqRel);
        result
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
/// their `fsync` does not matter.
#[derive(Debug)]
pub struct SqliteLeaseStore {
    conn: Mutex<Connection>,
    /// `None` for a connection this crate did not open (or an in-memory one): its pragmas are
    /// left alone.
    durability: Option<Durability>,
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
        let mut store = Self::from_connection(open_connection(path.as_ref(), durability)?)?;
        store.durability = Some(durability);
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_connection(open_memory_connection()?)
    }

    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        conn.execute_batch(LEASE_SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
            durability: None,
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
            let expires_at: String = row.get(2)?;
            let revoked_at: Option<String> = row.get(3)?;
            out.push((
                row.get::<_, String>(0)?,
                LeaseRow {
                    parent: row.get::<_, Option<String>>(1)?.map(LeaseId),
                    expires_at: parse_time(&expires_at)?,
                    revoked_at: revoked_at.as_deref().map(parse_time).transpose()?,
                    revoke_reason: row.get(4)?,
                },
            ));
        }
    }
    Ok(out)
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
mod tests {
    use super::*;
    use onbehalf_core::{
        AgentId, Capability, CapabilitySet, Decision, DelegationChain, OriginatingUser, ToolCall,
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

    fn issuer() -> onbehalf_token::Issuer {
        onbehalf_token::Issuer::generate(onbehalf_token::IssuerConfig {
            issuer: "https://onbehalf.test".into(),
            audience: "onbehalf".into(),
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
                .append_locked(&mut conn, (0..6).map(record).collect())
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
        assert!(err.contains("earlier onbehalf"), "{err}");
        assert!(err.contains(ENTRY_HASH_VERSION), "{err}");
        let other = dir.path().join("other.db");
        {
            let log = SqliteAudit::open(&other).unwrap();
            log.with_connection(|c| {
                Ok(c.execute(
                    "UPDATE audit_meta SET value = 'onbehalf-audit-entry-v9'",
                    [],
                )?)
            })
            .unwrap();
        }
        let err = SqliteAudit::open(&other).unwrap_err().to_string();
        assert!(err.contains("onbehalf-audit-entry-v9"), "{err}");
        // Reopening a current log works, empty or not.
        let fresh = dir.path().join("fresh.db");
        SqliteAudit::open(&fresh).unwrap();
        let log = SqliteAudit::open(&fresh).unwrap();
        log.append(record(1)).unwrap();
        drop(log);
        assert_eq!(SqliteAudit::open(&fresh).unwrap().len().unwrap(), 1);
    }
}
