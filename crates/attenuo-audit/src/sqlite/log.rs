//! [`SqliteAudit`]: the hash-chained audit log, its writer thread, queries and signed
//! checkpoints.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, TryLockError};
use std::time::Duration;

use attenuo_core::{DecisionRecord, LeaseId};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use time::OffsetDateTime;

use super::connection::{
    file_of, open_connection, open_memory_connection, relaxed_sync_of, restore_sync,
    with_full_sync, Durability, WriteGate, BUSY_TIMEOUT, SYNC_FULL, SYNC_NORMAL,
};
use super::migrations::{check_entry_hash, migrate, SchemaState};
use super::schema::RECORD_ID_EXPR;
#[cfg(any(test, feature = "testing"))]
use super::wal::WalTimings;
use super::wal::{
    gated_checkpoint, nears_checkpoint, note_wal_pages, presync_lead, wal_checkpoint, Activity,
    WalCheckpoint, WalCheckpointer, WalCounters, WalMsg, WalStats, WAL_CHECKPOINT_COMMITS,
    WAL_PAGES, WAL_WRITER_BACKSTOP_FRAMES,
};
use super::{fmt_time, seq_to_i64, usize_to_i64};
use crate::checkpoint::{
    verify_with_checkpoints, Checkpoint, CheckpointKeys, SignedVerifyReport, Start,
};
use crate::error::AuditError;
use crate::export::RecordFilter;
use crate::log::{
    canonical_record_json, entry_hash_from_json, verify_entries, AuditEntry, AuditSink,
    VerifyReport, GENESIS_HASH,
};
use crate::query::{like_contains, EntryFilter, Order};

/// Columns read back for an entry, in the order `entry_from_row` expects.
pub(super) const ENTRY_COLUMNS: &str =
    "seq, prev_hash, entry_hash, decision, reason, originating_subject, \
     agents, chain_depth, chain_digest, leases, server, tool, arguments_digest, session_id, \
     policy_ids, record_json, kind, chain_id";

/// A commit of one record handed back no entry. `commit` returns one entry per record, so this
/// does not happen; if it ever did, the caller gets a storage error instead of a panic on the
/// request path.
fn no_entry_for_record() -> AuditError {
    AuditError::Storage("an append of one record returned no entry".into())
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
    expect("decision", &decision, record.decision.as_str())?;
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
        seq: u64::try_from(seq.max(0)).unwrap_or(0),
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
        params![
            seq_to_i64(cp.seq)?,
            cp.head_hash,
            cp.at,
            cp.kid,
            cp.signature
        ],
    )?;
    Ok(())
}

fn checkpoint_at(conn: &Connection, seq: u64) -> Result<Option<Checkpoint>, AuditError> {
    // A seq above `i64::MAX` is never stored, so there is no such checkpoint.
    let Ok(seq) = i64::try_from(seq) else {
        return Ok(None);
    };
    Ok(conn
        .prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints WHERE seq = ?1",
        )?
        .query_row([seq], checkpoint_from_row)
        .optional()?)
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

/// Default of [`SqliteAudit::with_append_limits`]'s queue: appends that may wait for the
/// writer at once. Above the tokio blocking pool's default of 512 threads, so a server under
/// load waits for the writer as before and only a writer that stopped draining sheds.
pub const DEFAULT_APPEND_QUEUE: usize = 1024;

/// Default of [`SqliteAudit::with_append_limits`]'s timeout: how long an append waits for the
/// writer before it fails.
pub const DEFAULT_APPEND_TIMEOUT: Duration = Duration::from_secs(10);

/// How many appends this log has shed rather than waited for ([`SqliteAudit::append_stats`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppendStats {
    /// Appends refused at once because the writer's queue was full.
    pub queue_full: u64,
    /// Appends that waited the whole append timeout without an answer.
    pub timeouts: u64,
}

/// The counters behind [`AppendStats`].
#[derive(Debug, Default)]
struct ShedCounters {
    queue_full: AtomicU64,
    timeouts: AtomicU64,
}

/// [`Job::claim`] states. A job moves from `WAITING` to `TAKEN` (the writer will commit it) or
/// to `ABANDONED` (its caller gave up; the writer drops it unwritten), never both.
const WAITING: u8 = 0;
const TAKEN: u8 = 1;
const ABANDONED: u8 = 2;

/// Rows a whole-log read (verify) takes per read transaction on the reader connection.
const VERIFY_PAGE: i64 = 1000;

/// The read-only connection a store on a file in WAL mode reads through (see "Reads" on
/// [`SqliteAudit`]); `None` for an in-memory database or a file in another journal mode,
/// where a second connection would block the writer or see another database.
fn open_reader(writer: &Connection) -> Result<Option<Connection>, AuditError> {
    let Some(path) = writer.path().filter(|p| !p.is_empty()).map(PathBuf::from) else {
        return Ok(None);
    };
    let mode: String = writer.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Ok(None);
    }
    let reader = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // A reader waits for a lock only while the WAL index is being rebuilt or reset; give it
    // the same patience as the writer.
    reader.busy_timeout(BUSY_TIMEOUT)?;
    reader.set_prepared_statement_cache_capacity(READER_STATEMENT_CACHE);
    Ok(Some(reader))
}

/// Prepared statements kept on the reader connection: one per query above.
const READER_STATEMENT_CACHE: usize = 32;

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
/// **Bounded waits.** The writer's queue holds at most [`DEFAULT_APPEND_QUEUE`] appends and
/// each waits at most [`DEFAULT_APPEND_TIMEOUT`] for the writer to take it
/// ([`with_append_limits`](Self::with_append_limits)); past either the append fails with
/// [`AuditError::Overloaded`] and is never written, so a hung disk denies decisions instead
/// of blocking threads without end. The writer takes a batch only once it holds the
/// connection, and the callers of a taken batch (at most [`MAX_BATCH`]) wait for its commit
/// however long it takes, so an append that fails was not committed (SR-102).
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
/// [`CHECKPOINT_PRESYNC_LEAD`](super::CHECKPOINT_PRESYNC_LEAD) entries before each checkpoint, so that commit's sync has
/// only the last few entries' pages to write.
///
/// **Reads.** On a file in WAL mode, every query (verify, export, search, lookups, `head`)
/// runs on a separate read-only connection with its own lock, so a long read never holds the
/// connection an append needs: WAL lets one writer and readers proceed together, and a reader
/// sees the last transaction committed before its own read began. A whole-log read (verify)
/// is paged: it fixes the newest seq and reads the checkpoints in one read transaction at the
/// start, then reads the entries up to that seq a page at a time, each page in its own short
/// read transaction, so it neither sees an append that started after it nor pins one WAL
/// snapshot for the whole walk (which would keep the WAL from being checkpointed). An
/// in-memory store, or one whose file is not in WAL mode, reads on the writer's connection
/// as before. Signed checkpoints and [`with_connection`](Self::with_connection) use the
/// writer's connection and lock.
pub struct SqliteAudit {
    pub(super) inner: Arc<Inner>,
    /// Started by the first append that finds the store busy, after the builders have run.
    writer: OnceLock<Writer>,
    /// The background WAL checkpointer, if [`with_wal_checkpoints`](Self::with_wal_checkpoints)
    /// started one.
    pub(super) wal: Option<WalCheckpointer>,
    /// A second, read-only connection on the same file for every query (see
    /// [`read_conn`](Self::read_conn)); `None` for a store that is not a file in WAL mode,
    /// whose reads share the writer's connection.
    pub(super) reader: Option<Mutex<Connection>>,
    /// The file's schema version and what this open did to it.
    schema: SchemaState,
}

/// What the writer thread and the readers share.
pub(super) struct Inner {
    /// Shared with the WAL checkpointer, which holds it briefly to pause appends.
    pub(super) conn: Arc<Mutex<Connection>>,
    checkpointing: Option<Checkpointing>,
    activity: Arc<Activity>,
    /// The connection's `synchronous` level when it is below `FULL` on a file: commits that
    /// write a signed checkpoint raise it to `FULL` for themselves (SR-50).
    relaxed_sync: Option<i64>,
    /// The database file, if there is one (canonical path): what a synced commit covers.
    file: Option<PathBuf>,
    /// Held across every write transaction (see [`WriteGate`]).
    pub(super) gate: WriteGate,
    /// The writer's queue capacity, at least 1 ([`SqliteAudit::with_append_limits`]).
    append_queue: usize,
    /// How long an append waits for the writer ([`SqliteAudit::with_append_limits`]).
    append_timeout: Duration,
    /// Appends shed so far.
    shed: ShedCounters,
    /// Tests: every commit and the `synchronous` level it ran at, in one log with the hook.
    #[cfg(test)]
    probe: Option<Arc<Mutex<Vec<String>>>>,
    /// Tests: the writer stops here once it has taken a batch, before committing it.
    #[cfg(test)]
    pub(super) take_gate: Option<Arc<TakeGate>>,
}

/// Tests: holds the writer between taking a batch and committing it, so a test can make an
/// append's wait run out at exactly that point.
#[cfg(test)]
#[derive(Default)]
pub(super) struct TakeGate {
    state: Mutex<(bool, bool)>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
impl TakeGate {
    /// The writer: note that a batch is taken and wait until the test lets it commit.
    fn hold(&self) {
        let mut s = self.state.lock().unwrap();
        s.0 = true;
        self.changed.notify_all();
        while !s.1 {
            s = self.changed.wait(s).unwrap();
        }
    }

    /// Wait until the writer has taken a batch.
    pub(super) fn wait_taken(&self) {
        let mut s = self.state.lock().unwrap();
        while !s.0 {
            s = self.changed.wait(s).unwrap();
        }
    }

    /// Let the writer commit.
    pub(super) fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

/// Why [`Inner::commit_tx`] wrote nothing. Either way the records come back.
enum CommitFailure {
    Error(AuditError, Vec<DecisionRecord>),
    /// The batch writes a signed checkpoint and must run again with `synchronous=FULL`.
    NeedsSync(Vec<DecisionRecord>),
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
    /// [`WAITING`], [`TAKEN`] or [`ABANDONED`]: decides, once, whether the writer commits
    /// the record or its caller has given up on it.
    claim: Arc<AtomicU8>,
}

impl Job {
    /// The writer's side of [`Job::claim`]: `Some` when the caller still waits, and from now
    /// on the record is the writer's to commit; `None` when the caller gave up, and the
    /// record is dropped unwritten.
    fn take(self) -> Option<Self> {
        self.claim
            .compare_exchange(WAITING, TAKEN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(self)
    }
}

/// Handle on the writer thread. Dropping it closes the channel; the thread finishes the batch
/// in hand and exits, and the drop waits for it.
struct Writer {
    /// Bounded ([`Inner::append_queue`]): a writer that stopped draining (a hung disk) fills
    /// it, and further appends fail at once instead of piling up.
    jobs: Option<mpsc::SyncSender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Writer {
    fn start(inner: Arc<Inner>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Job>(inner.append_queue.max(1));
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

    /// Queue `record` for the writer and wait for its entry.
    ///
    /// A full queue fails at once. A job the writer has not taken within
    /// `inner.append_timeout` is withdrawn, never written, and the caller gets
    /// [`AuditError::Overloaded`], so its decision fails closed. The writer takes a job only
    /// once it holds the connection, right before the commit; a caller whose job was taken
    /// waits for the commit's outcome however long it takes, as an inline commit does. So an
    /// error always means the record is not in the log and never will be, and the caller may
    /// undo what it charged (SR-102). Which records are committed, and in what order, is
    /// decided by the writer alone, so the chain stays linear whatever the callers do.
    fn append(
        &self,
        inner: &Inner,
        record: DecisionRecord,
        sync: bool,
    ) -> Result<AuditEntry, AuditError> {
        let stopped = || AuditError::Storage("the audit writer is not running".into());
        let jobs = self.jobs.as_ref().ok_or_else(stopped)?;
        let (reply, answer) = mpsc::sync_channel(1);
        let claim = Arc::new(AtomicU8::new(WAITING));
        match jobs.try_send(Job {
            record,
            reply,
            sync,
            claim: Arc::clone(&claim),
        }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                inner.shed.queue_full.fetch_add(1, Ordering::Relaxed);
                return Err(AuditError::Overloaded("the audit writer's queue is full"));
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return Err(stopped()),
        }
        // Tests: start the wait only once the writer holds the batch, so it runs out there.
        #[cfg(test)]
        if let Some(gate) = &inner.take_gate {
            gate.wait_taken();
        }
        match answer.recv_timeout(inner.append_timeout) {
            Ok(result) => result,
            // A writer that panicked drops the reply sender: the append fails, it is not
            // assumed.
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(stopped()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if claim
                    .compare_exchange(WAITING, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    inner.shed.timeouts.fetch_add(1, Ordering::Relaxed);
                    return Err(AuditError::Overloaded(
                        "the audit writer did not take the record within the append timeout",
                    ));
                }
                // Taken: the writer holds the connection and is committing the record. Wait
                // for the outcome, as an inline commit does, so that an error always means
                // the record was not written and the caller may roll back what it charged
                // (SR-102). Only the one batch in hand can wait here: the writer takes no
                // other while it commits.
                answer.recv().unwrap_or_else(|_| Err(stopped()))
            }
        }
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
        let mut batch: Vec<Job> = vec![first];
        while batch.len() < MAX_BATCH {
            match jobs.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }
        // Claim the jobs only once the connection is held, right before the commit: a job
        // whose caller gave up meanwhile (the connection was busy) is dropped unwritten, and
        // a claimed job is committed or fails without further waits on anything but the
        // commit itself, whose outcome its caller waits for (SR-102).
        let mut conn = match inner.conn.lock() {
            Ok(c) => c,
            Err(_) => {
                for job in batch.into_iter().filter_map(Job::take) {
                    let _ = job.reply.send(Err(AuditError::Poisoned));
                }
                continue;
            }
        };
        // Jobs whose callers gave up are dropped here, before anything is written; the rest
        // keep the order in which they reached the queue.
        let batch: Vec<Job> = batch.into_iter().filter_map(Job::take).collect();
        if batch.is_empty() {
            continue;
        }
        #[cfg(test)]
        if let Some(gate) = &inner.take_gate {
            gate.hold();
        }
        // One record that must be synced makes the whole batch commit at `FULL`: one sync
        // covers them all.
        let sync = batch.iter().any(|j| j.sync);
        let (records, replies): (Vec<_>, Vec<_>) =
            batch.into_iter().map(|j| (j.record, j.reply)).unzip();
        let results = inner.append_locked(&mut conn, records, sync);
        drop(conn);
        for (reply, result) in replies.into_iter().zip(results) {
            // The caller always waits for its answer; a send can only fail if it panicked.
            let _ = reply.send(result);
        }
    }
}

impl Inner {
    /// Commit `records` in order, as one transaction when possible. One result per record.
    /// With `sync`, every commit runs at `synchronous=FULL`. Tests only: the writer locks the
    /// connection itself and calls [`append_locked`](Self::append_locked).
    #[cfg(test)]
    pub(super) fn append_batch(
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
    pub(super) fn append_locked(
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
                    Ok(mut one) => one.pop().ok_or_else(no_entry_for_record),
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
        seq_to_i64(entry.seq)?,
        entry.prev_hash,
        entry.entry_hash,
        fmt_time(r.at)?,
        r.decision.as_str(),
        r.reason,
        r.originating_subject,
        serde_json::to_string(&r.agents)?,
        usize_to_i64(r.chain_depth),
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
    ///
    /// # Errors
    ///
    /// As [`open_with`](Self::open_with).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::open_with(path, Durability::default())
    }

    /// Open (or create) the log at `path` in WAL mode with the given durability.
    ///
    /// # Errors
    ///
    /// [`AuditError::Sqlite`] when the file cannot be opened or the schema cannot be created, and
    /// [`AuditError::Storage`] when the file cannot be switched to WAL mode or holds a log this
    /// version refuses (see [`from_connection`](Self::from_connection)).
    pub fn open_with(path: impl AsRef<Path>, durability: Durability) -> Result<Self, AuditError> {
        Self::from_connection(open_connection(path.as_ref(), durability)?)
    }

    /// A log in a private in-memory database, gone when the value is dropped.
    ///
    /// # Errors
    ///
    /// As [`from_connection`](Self::from_connection); a fresh in-memory database should not fail.
    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_connection(open_memory_connection()?)
    }

    /// Wrap an existing connection, bringing its file to
    /// [`SCHEMA_VERSION`](crate::SCHEMA_VERSION) first (see [`schema`](Self::schema)).
    ///
    /// The migration runs on this connection, before the read-only reader connection is
    /// opened, so the reader never sees a file mid-migration and never migrates. On a file
    /// that is already current (a [`SqliteLeaseStore`](super::SqliteLeaseStore) on the same
    /// file migrated it) it only reads `user_version`.
    ///
    /// # Errors
    ///
    /// [`AuditError::SchemaTooNew`] when a newer attenuo wrote the file. [`AuditError::Storage`]
    /// when the log predates records with `kind` and `chain_id`, or was written with another
    /// entry hash construction than [`ENTRY_HASH_VERSION`](crate::log::ENTRY_HASH_VERSION),
    /// such as one written before RFC 8785 canonical JSON (SR-20): there is no migration for
    /// those, start a new file; or when a migration fails (the file stays at the version
    /// before it). [`AuditError::Sqlite`] when the schema cannot be read or written (a
    /// read-only or foreign database, for example).
    pub fn from_connection(mut conn: Connection) -> Result<Self, AuditError> {
        let schema = migrate(&mut conn)?;
        check_entry_hash(&conn, false)?;
        let relaxed_sync = relaxed_sync_of(&conn)?;
        let file = file_of(&conn);
        // After the migration: the reader only ever sees a current file.
        let reader = open_reader(&conn)?.map(Mutex::new);
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Arc::new(Mutex::new(conn)),
                checkpointing: None,
                activity: Arc::new(Activity::default()),
                relaxed_sync,
                gate: WriteGate::for_file(file.as_deref()),
                file,
                append_queue: DEFAULT_APPEND_QUEUE,
                append_timeout: DEFAULT_APPEND_TIMEOUT,
                shed: ShedCounters::default(),
                #[cfg(test)]
                probe: None,
                #[cfg(test)]
                take_gate: None,
            }),
            writer: OnceLock::new(),
            wal: None,
            reader,
            schema,
        })
    }

    /// The file's schema version and whether this open migrated it (for the start-up log).
    pub fn schema(&self) -> SchemaState {
        self.schema
    }

    /// The connection queries run on: the read-only reader when there is one, else the
    /// writer's connection. Only reads go through here.
    fn read_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, AuditError> {
        match &self.reader {
            Some(r) => Ok(r.lock()?),
            None => Ok(self.inner.conn.lock()?),
        }
    }

    /// The newest seq and every stored checkpoint, read in one read transaction: the snapshot
    /// a whole-log verify walks. A checkpoint is written in the same transaction as the entry
    /// it names or after it, so in one snapshot a checkpoint past the newest seq means the log
    /// was truncated, never that an append was half seen.
    pub(super) fn verify_snapshot(&self) -> Result<(i64, Vec<Checkpoint>), AuditError> {
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        let upper: i64 =
            tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |r| r.get(0))?;
        let checkpoints: Vec<Checkpoint> = {
            let mut stmt = tx.prepare_cached(
                "SELECT seq, head_hash, at, kid, signature FROM checkpoints ORDER BY seq",
            )?;
            let rows = stmt.query_map([], checkpoint_from_row)?;
            rows.collect::<Result<_, _>>()?
        };
        tx.commit()?;
        Ok((upper, checkpoints))
    }

    /// Every entry with `seq <= upper`, in order, read [`VERIFY_PAGE`] rows at a time, each
    /// page under the read lock for just that page. A row that cannot be decoded comes back
    /// as its error ([`AuditError::Corrupt`]) in its place; a failed query ends the walk
    /// with that error.
    pub(super) fn entries_through(
        &self,
        upper: i64,
    ) -> impl Iterator<Item = Result<AuditEntry, AuditError>> + '_ {
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq \
             LIMIT ?3"
        );
        let mut next: i64 = i64::MIN;
        let mut page: std::collections::VecDeque<Result<AuditEntry, AuditError>> =
            std::collections::VecDeque::new();
        let mut done = false;
        std::iter::from_fn(move || loop {
            if let Some(item) = page.pop_front() {
                return Some(item);
            }
            if done {
                return None;
            }
            let read = (|| -> Result<(), AuditError> {
                let conn = self.read_conn()?;
                let mut stmt = conn.prepare_cached(&sql)?;
                let mut rows = stmt.query(params![next, upper, VERIFY_PAGE])?;
                let mut n = 0;
                while let Some(row) = rows.next()? {
                    n += 1;
                    // The raw seq pages on even when the row does not decode.
                    let seq: i64 = row.get(0)?;
                    next = seq.saturating_add(1);
                    page.push_back(entry_from_row(row));
                }
                if n < VERIFY_PAGE || next > upper {
                    done = true;
                }
                Ok(())
            })();
            if let Err(e) = read {
                done = true;
                page.push_back(Err(e));
            }
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
    /// Readers are unaffected: every read goes through the store's own connections, which see
    /// every committed row whether or not it has been copied into the database file yet.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the pragmas cannot be read or set or the checkpointer's own
    /// connection cannot be opened, and [`AuditError::Storage`] when its thread cannot be started.
    /// A zero interval or a store that is not a WAL file is `Ok`, unchanged.
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
            let mut writer = self.inner.conn.lock()?;
            writer.pragma_update(None, "wal_autocheckpoint", 0)?;
            // After the pragma: setting `wal_autocheckpoint` installs SQLite's own hook.
            writer.wal_hook(Some(note_wal_pages))?;
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the checkpoint fails, including when its locks are not free
    /// within the busy timeout. A store that is not a WAL file is `Ok(None)`.
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

    /// Bound the appends that wait for the writer thread: at most `queue` (at least 1) wait at
    /// once, and each waits at most `timeout` for the writer to take it. A full queue, or a
    /// wait that runs out, fails the append with [`AuditError::Overloaded`] (counted in
    /// [`append_stats`](Self::append_stats)) and the record is never written, so a writer
    /// stuck on a hung disk turns into failed appends, and denied decisions, instead of an
    /// ever-growing number of blocked threads. The appends of the one batch the writer has
    /// taken wait for its commit without a deadline, so their outcome is never a guess
    /// (SR-102). Group commit is unchanged: what reaches the writer is batched and committed in
    /// queue order. An append committed inline, on the caller's thread (when nothing waits
    /// and the connection is free), has no deadline: a thread cannot be taken out of a stuck
    /// write, and it holds the connection, so every later append goes to the queue and is
    /// bounded there. Defaults: [`DEFAULT_APPEND_QUEUE`], [`DEFAULT_APPEND_TIMEOUT`]. Call it
    /// before the first append.
    pub fn with_append_limits(mut self, queue: usize, timeout: Duration) -> Self {
        let inner = self.inner_mut();
        inner.append_queue = queue.max(1);
        inner.append_timeout = timeout;
        self
    }

    /// How many appends were shed so far ([`with_append_limits`](Self::with_append_limits)).
    pub fn append_stats(&self) -> AppendStats {
        AppendStats {
            queue_full: self.inner.shed.queue_full.load(Ordering::Relaxed),
            timeouts: self.inner.shed.timeouts.load(Ordering::Relaxed),
        }
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
    ///
    /// # Errors
    ///
    /// [`AuditError::NoCheckpointSigner`] when [`with_checkpointing`](Self::with_checkpointing) was
    /// not called, [`AuditError::Corrupt`] when a stored checkpoint at the head's seq disagrees
    /// with the log (nothing is signed over a conflict), [`AuditError::TimeFormat`] when `now`
    /// cannot be written as RFC 3339, or [`AuditError::Poisoned`] when a writer panicked holding
    /// the log's lock, [`AuditError::Sqlite`] when the transaction or its synced commit fails.
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
    ///
    /// # Errors
    ///
    /// As [`checkpoint_signed`](Self::checkpoint_signed), plus [`AuditError::Sqlite`] when the head
    /// or newest checkpoint cannot be read. Nothing new to sign is `Ok(None)`.
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the query fails or a row has the wrong shape.
    pub fn last_checkpoint(&self) -> Result<Option<Checkpoint>, AuditError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints \
             ORDER BY seq DESC LIMIT 1",
        )?;
        let cp = stmt.query_row([], checkpoint_from_row).optional()?;
        Ok(cp)
    }

    /// Checkpoints with `from <= seq <= to`, ascending.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the query fails or a row has the wrong shape.
    pub fn checkpoints_between(&self, from: u64, to: u64) -> Result<Vec<Checkpoint>, AuditError> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT seq, head_hash, at, kid, signature FROM checkpoints \
             WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq",
        )?;
        let rows = stmt.query_map(
            [
                i64::try_from(from).unwrap_or(i64::MAX),
                i64::try_from(to).unwrap_or(i64::MAX),
            ],
            checkpoint_from_row,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Walk the chain and verify every stored checkpoint against `keys`.
    ///
    /// The walk covers the log as it was when the call began (see "Reads" on [`SqliteAudit`]):
    /// appends made meanwhile are neither walked nor waited for, and are not held up.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when a query fails, or a fault decoding an entry other than a corrupt
    /// one. A corrupt entry, a broken chain and a bad checkpoint are reported in the
    /// [`SignedVerifyReport`], not as errors.
    pub fn verify_chain_signed(
        &self,
        keys: &CheckpointKeys,
    ) -> Result<SignedVerifyReport, AuditError> {
        let (upper, checkpoints) = self.verify_snapshot()?;
        verify_with_checkpoints(
            self.entries_through(upper),
            &checkpoints,
            keys,
            Start::Genesis,
        )
    }

    /// Run `f` against the underlying connection while holding the write lock.
    ///
    /// Meant for operational tooling and tests (export, vacuum, deliberate tampering in a test).
    /// Anything written through here bypasses the chain, which `verify_chain` will report.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or whatever `f`
    /// returns.
    pub fn with_connection<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, AuditError>,
    ) -> Result<R, AuditError> {
        let mut conn = self.inner.conn.lock()?;
        f(&mut conn)
    }

    /// Entries for one originating subject, newest first, at most `limit`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the query fails, or [`AuditError::Corrupt`] when a row cannot be
    /// decoded.
    pub fn by_subject(&self, subject: &str, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE originating_subject = ?1 \
             ORDER BY seq DESC LIMIT ?2"
        );
        let conn = self.read_conn()?;
        query_entries(&conn, &sql, &[&subject, &usize_to_i64(limit)])
    }

    /// Up to `limit` entries with `from_seq <= seq <= to_seq` that match `filter`, in order.
    /// An empty filter is the same as [`AuditSink::range`] bounded by `to_seq`.
    ///
    /// # Errors
    ///
    /// As [`entries_matching`](Self::entries_matching).
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
    /// Rows are read on the reader connection (see "Reads" on [`SqliteAudit`]) in batches of
    /// `limit`, and its lock is released between batches, so a long scan holds up neither
    /// appends nor other reads for long. The cost grows with the window, not the page:
    /// callers bound the window.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when a query fails, [`AuditError::Corrupt`] when a row cannot be
    /// decoded or disagrees with its `record_json`, and [`AuditError::Serde`] or
    /// [`AuditError::TimeFormat`] when a filter value cannot be encoded for the query.
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
        let decision = filter.decision.as_ref().map(attenuo_core::Decision::as_str);
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
                let conn = self.read_conn()?;
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
                let seq = seq_to_i64(entry.seq)?;
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the query fails, or [`AuditError::Corrupt`] when the row cannot
    /// be decoded. A seq with no entry, or one past `i64::MAX`, is `Ok(None)`.
    pub fn entry_at(&self, seq: u64) -> Result<Option<AuditEntry>, AuditError> {
        let Ok(seq) = i64::try_from(seq) else {
            return Ok(None);
        };
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE seq = ?1");
        let conn = self.read_conn()?;
        Ok(query_entries(&conn, &sql, &[&seq])?.pop())
    }

    /// The entry whose record has id `id` (the hyphenated lower-case UUID that proxy denials
    /// and AuthZEN answers return as `decision_id`), if there is one. Uses the
    /// `audit_record_id_idx` expression index.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the query fails, or [`AuditError::Corrupt`] when a row cannot be
    /// decoded. An unknown id is `Ok(None)`.
    pub fn entry_by_record_id(&self, id: &str) -> Result<Option<AuditEntry>, AuditError> {
        let sql =
            format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE {RECORD_ID_EXPR} = ?1 ORDER BY seq");
        let conn = self.read_conn()?;
        let found = query_entries(&conn, &sql, &[&id])?;
        // Record ids are random UUIDs, so one row at most is expected; take the first whose
        // decoded record really has that id.
        Ok(found.into_iter().find(|e| e.record.id.to_string() == id))
    }

    /// Up to `limit` stored checkpoints with `seq < before`, newest first. It only reads:
    /// unlike [`checkpoint_signed`](Self::checkpoint_signed) it never signs one.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the query fails or a row has the wrong shape.
    pub fn checkpoints_before(
        &self,
        before: u64,
        limit: usize,
    ) -> Result<Vec<Checkpoint>, AuditError> {
        let conn = self.read_conn()?;
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the query fails or a row has the wrong shape. A seq past
    /// `i64::MAX` or past the newest checkpoint is `Ok(None)`.
    pub fn checkpoint_covering(&self, seq: u64) -> Result<Option<Checkpoint>, AuditError> {
        let Ok(seq) = i64::try_from(seq) else {
            return Ok(None);
        };
        let conn = self.read_conn()?;
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the query fails, or [`AuditError::Corrupt`] when the row cannot
    /// be decoded.
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
        let conn = self.read_conn()?;
        Ok(query_entries(
            &conn,
            &sql,
            &[&kind.as_str(), &tool, &decision.as_str(), &after],
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the query fails, or [`AuditError::Corrupt`] when one of the
    /// chain's issuance rows cannot be decoded.
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
        let conn = self.read_conn()?;
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the query fails, or [`AuditError::Corrupt`] when a row cannot be
    /// decoded.
    pub fn by_chain(&self, chain_digest: &str) -> Result<Vec<AuditEntry>, AuditError> {
        let sql = format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE chain_digest = ?1 ORDER BY seq");
        let conn = self.read_conn()?;
        query_entries(&conn, &sql, &[&chain_digest])
    }

    /// Every entry whose chain held `lease`, in order.
    ///
    /// v0 note: `leases` is stored as a JSON array of strings and this is a `LIKE` on that text
    /// (the id is matched as a quoted JSON string so `l1` does not match `l10`). It is a full scan;
    /// a join table is the upgrade path when volume demands an index.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock,
    /// [`AuditError::Sqlite`] when the query fails, or [`AuditError::Corrupt`] when a candidate row
    /// cannot be decoded.
    pub fn by_lease(&self, lease: &LeaseId) -> Result<Vec<AuditEntry>, AuditError> {
        let pattern = like_contains(&serde_json::to_string(&lease.0)?);
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM audit WHERE leases LIKE ?1 ESCAPE '\\' ORDER BY seq"
        );
        let conn = self.read_conn()?;
        let candidates = query_entries(&conn, &sql, &[&pattern])?;
        // Confirm against the decoded record; LIKE is only a prefilter.
        Ok(candidates
            .into_iter()
            .filter(|e| e.record.leases.contains(lease))
            .collect())
    }

    /// Number of entries.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked holding the log's lock, or
    /// [`AuditError::Sqlite`] when the count query fails.
    pub fn len(&self) -> Result<u64, AuditError> {
        let conn = self.read_conn()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Whether the log has no entries.
    ///
    /// # Errors
    ///
    /// As [`len`](Self::len).
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
                    return out.pop().unwrap_or_else(|| Err(no_entry_for_record()));
                }
                Err(TryLockError::Poisoned(_)) => return Err(AuditError::Poisoned),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        activity.pending.fetch_add(1, Ordering::AcqRel);
        let result = self
            .writer
            .get_or_init(|| Writer::start(Arc::clone(&self.inner)))
            .append(&self.inner, record, sync);
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
        let mut conn = self.read_conn()?;
        let tx = conn.transaction()?;
        head_in(&tx)
    }

    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let sql =
            format!("SELECT {ENTRY_COLUMNS} FROM audit WHERE seq >= ?1 ORDER BY seq LIMIT ?2");
        let conn = self.read_conn()?;
        query_entries(
            &conn,
            &sql,
            &[
                &i64::try_from(from_seq).unwrap_or(i64::MAX),
                &usize_to_i64(limit),
            ],
        )
    }

    fn verify_chain(&self) -> Result<VerifyReport, AuditError> {
        let (upper, _) = self.verify_snapshot()?;
        // A row that cannot be decoded (corrupt JSON, column/JSON disagreement) surfaces as
        // `AuditError::Corrupt`, which `verify_entries` reports as a break at that seq.
        verify_entries(self.entries_through(upper))
    }

    fn checkpoint(&self) -> Result<(u64, String), AuditError> {
        Ok(match self.head()? {
            Some(h) => (h.seq, h.entry_hash),
            None => (0, GENESIS_HASH.to_string()),
        })
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

    /// Tests: wait until the background WAL checkpointer has handled every message sent to it
    /// before this call (the syncs ahead of checkpoints that the appends so far asked for, and
    /// any round they queued). The channel is first in, first out, so what the checkpointer
    /// has done by then is final for those appends: a test can assert that something did
    /// *not* happen without sleeping. Returns at once without
    /// [`with_wal_checkpoints`](Self::with_wal_checkpoints).
    #[doc(hidden)]
    pub fn settle_wal_checkpointer(&self) {
        let Some(w) = self.wal.as_ref() else { return };
        let (done, settled) = mpsc::sync_channel(1);
        w.msgs
            .send(WalMsg::Settle(done))
            .expect("the WAL checkpointer is running");
        settled.recv().expect("the WAL checkpointer answers");
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
    /// off the request path ([`CHECKPOINT_PRESYNC_LEAD`](super::CHECKPOINT_PRESYNC_LEAD) by default; 0 turns it off).
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
    pub(super) fn with_probe(mut self, log: Arc<Mutex<Vec<String>>>) -> Self {
        self.inner_mut().probe = Some(log);
        self
    }

    /// Stop the writer at `gate` after it takes each batch (see [`TakeGate`]).
    pub(super) fn with_take_gate(mut self, gate: Arc<TakeGate>) -> Self {
        self.inner_mut().take_gate = Some(gate);
        self
    }

    /// Send every later append to the writer thread, as if one were already waiting there.
    pub(super) fn never_inline(&self) {
        self.inner.activity.pending.fetch_add(1, Ordering::AcqRel);
    }
}
