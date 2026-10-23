//! SQLite-backed audit sink and lease store.
//!
//! Both wrap a single `rusqlite::Connection` behind a `Mutex`. Audit appends go through one
//! writer thread (group commit, see [`SqliteAudit`]): it takes the lock, reads the current head
//! and inserts the next rows in one transaction, so two entries can never share a `prev_hash`.
//! The lock and the single writer, not SQLite's locking, keep the chain linear within a
//! process; across processes SQLite's write lock plus the `UNIQUE` constraint on `entry_hash`
//! and the primary key on `seq` make a fork fail rather than succeed.

use std::path::Path;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
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

const CHECKPOINT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS checkpoints (
    seq       INTEGER PRIMARY KEY,
    head_hash TEXT NOT NULL,
    at        TEXT NOT NULL,
    kid       TEXT NOT NULL,
    signature TEXT NOT NULL
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
///   never corrupt, and the hash chain still verifies, ending at an earlier head. Lease
///   revocations are the exception: they always commit with `synchronous=FULL` (see
///   [`SqliteLeaseStore`]), so a revoked lease cannot come back after a power failure.
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

type CheckpointHook = Arc<dyn Fn(&Checkpoint) + Send + Sync>;

/// Automatic checkpointing: sign the head every `every` entries, inside the append's
/// transaction, so a checkpoint can never refer to a head that was not committed.
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
/// Reads, checkpoints and [`with_connection`](Self::with_connection) take the same lock and
/// see only committed batches.
pub struct SqliteAudit {
    inner: Arc<Inner>,
    /// Started by the first append, after the builders have run.
    writer: OnceLock<Writer>,
}

/// What the writer thread and the readers share.
struct Inner {
    conn: Mutex<Connection>,
    checkpointing: Option<Checkpointing>,
}

impl std::fmt::Debug for SqliteAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteAudit")
            .field("checkpointing", &self.inner.checkpointing.is_some())
            .field("writer_started", &self.writer.get().is_some())
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
        match self.commit(&mut conn, records) {
            Ok(entries) => entries.into_iter().map(Ok).collect(),
            Err((e, _)) if n == 1 => vec![Err(e)],
            // Something in the batch failed and the transaction rolled back. Find out which
            // record it was by committing them one at a time, in the same order.
            Err((_, records)) => records
                .into_iter()
                .map(|r| match self.commit(&mut conn, vec![r]) {
                    Ok(mut one) => Ok(one.pop().expect("one record, one entry")),
                    Err((e, _)) => Err(e),
                })
                .collect(),
        }
    }

    /// One transaction: read the head, chain and insert every record, sign the checkpoints
    /// that fall in the batch, commit. On failure nothing is written and the records come back.
    fn commit(
        &self,
        conn: &mut Connection,
        records: Vec<DecisionRecord>,
    ) -> Result<Vec<AuditEntry>, (AuditError, Vec<DecisionRecord>)> {
        let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
            Ok(tx) => tx,
            Err(e) => return Err((e.into(), records)),
        };
        let head = match head_in(&tx) {
            Ok(h) => h,
            Err(e) => return Err((e, records)),
        };
        let mut entries: Vec<AuditEntry> = Vec::with_capacity(records.len());
        for record in records {
            let entry = AuditEntry::next(entries.last().or(head.as_ref()), record);
            entries.push(entry);
        }
        let mut created = Vec::new();
        let written = entries
            .iter()
            .try_for_each(|entry| {
                insert_entry(&tx, entry)?;
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
            .and_then(|()| Ok(tx.commit()?));
        if let Err(e) = written {
            return Err((e, entries.into_iter().map(|e| e.record).collect()));
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
}

fn insert_entry(tx: &Transaction<'_>, entry: &AuditEntry) -> Result<(), AuditError> {
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
        serde_json::to_string(r)?,
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
    pub fn from_connection(conn: Connection) -> Result<Self, AuditError> {
        conn.execute_batch(AUDIT_SCHEMA)?;
        conn.execute_batch(CHECKPOINT_SCHEMA)?;
        Ok(Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
                checkpointing: None,
            }),
            writer: OnceLock::new(),
        })
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
    /// return an existing one). For metrics. No effect before
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
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (seq, hash) = match head_in(&tx)? {
            Some(h) => (h.seq, h.entry_hash),
            None => (0, GENESIS_HASH.to_string()),
        };
        if let Some(existing) = checkpoint_at(&tx, seq)? {
            if existing.head_hash == hash {
                return Ok(existing);
            }
            // Never sign over a conflict: the log and an earlier checkpoint disagree.
            return Err(AuditError::Corrupt {
                seq,
                detail: "a stored checkpoint disagrees with the log at its seq".into(),
            });
        }
        let cp = Checkpoint::sign(&c.signer, seq, &hash, now)?;
        insert_checkpoint(&tx, &cp)?;
        tx.commit()?;
        if let Some(hook) = &c.on_created {
            hook(&cp);
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
        self.writer
            .get_or_init(|| Writer::start(Arc::clone(&self.inner)))
            .append(record)
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
        // A revocation must survive a power failure even when the store runs at `normal`.
        let relaxed = self.durability.filter(|d| *d != Durability::Full);
        if relaxed.is_some() {
            conn.pragma_update(None, "synchronous", Durability::Full.pragma())?;
        }
        let out = revoke_in(&mut conn, lease, reason, now);
        if let Some(d) = relaxed {
            conn.pragma_update(None, "synchronous", d.pragma())?;
        }
        out
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
        let conn = self.conn.lock()?;
        classify(leases, now, |id| get_in(&conn, id))
    }
}
