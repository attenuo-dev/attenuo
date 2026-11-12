//! Opening a connection: durability, the switch to WAL mode and the per-file write gate. The
//! schema is brought up to date by `migrations.rs`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use rusqlite::Connection;

use crate::error::AuditError;

/// How long a connection waits for another connection's write lock before giving up with
/// `SQLITE_BUSY`. Within one process the stores' [`WriteGate`] serializes writers on one file,
/// including the audit and lease connections of one server; this covers a second process.
pub(super) const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
///   [`SqliteLeaseStore`](super::SqliteLeaseStore)), so a revoked lease cannot come back after a power failure, and
///   every commit that writes a signed checkpoint (see [`SqliteAudit`](super::SqliteAudit)), so a checkpoint
///   handed to the `on_created` hook, and shipped off the host from there, never names
///   entries that a power failure could still take back (SR-50).
/// - [`Full`](Self::Full) (`synchronous=FULL`): every commit is synced before it returns, so a
///   decision that was answered is on disk. One `fsync` per commit bounds throughput by the
///   storage's sync latency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Durability {
    /// `synchronous=NORMAL`: synced at WAL checkpoints; the default.
    #[default]
    Normal,
    /// `synchronous=FULL`: every commit synced before it returns.
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
    pub(super) fn level(self) -> i64 {
        match self {
            Durability::Normal => SYNC_NORMAL,
            Durability::Full => SYNC_FULL,
        }
    }
}

/// `PRAGMA synchronous` levels (`OFF` is 0, `EXTRA` 3).
pub(super) const SYNC_NORMAL: i64 = 1;
pub(super) const SYNC_FULL: i64 = 2;

/// Put `conn` back to `synchronous` level `level` after a commit that ran at `FULL`. A failure
/// is logged, not returned: the commit before it succeeded and its caller must learn that, and
/// the connection merely stays at the safer setting (SR-51).
pub(super) fn restore_sync(conn: &Connection, level: i64) {
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
pub(super) fn with_full_sync<T>(
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
pub(super) fn file_of(conn: &Connection) -> Option<PathBuf> {
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
/// Lock order: [`SqliteLeaseStore`](super::SqliteLeaseStore) takes the gate before its connection lock, so its reads
/// (the lease check on every call) are not held up by a lease write waiting for the gate.
/// [`SqliteAudit`](super::SqliteAudit) takes it after its connection lock, which its writer thread holds for a
/// whole batch, and releases it before the checkpoint hook or any other call out. While
/// holding the gate a thread waits at most for its own store's connection (held only by
/// readers, or by the audit writer that already holds the gate) or for the WAL checkpoint
/// gate (held only around a checkpoint that does not wait for the gate), so no cycle can
/// form. Reads never take the gate. An in-memory store has no gate, stores on
/// different files have different gates, and another process is still kept out by SQLite's
/// lock and [`BUSY_TIMEOUT`].
#[derive(Debug, Clone, Default)]
pub(super) struct WriteGate(pub(super) Option<Arc<Ticket>>);

/// A FIFO lock: each writer draws the next ticket and waits until it is served.
#[derive(Debug, Default)]
pub(super) struct Ticket {
    /// (next ticket to hand out, ticket now served).
    state: Mutex<(u64, u64)>,
    turn: Condvar,
}

/// Holds a [`Ticket`] until dropped (also when unwinding), which serves the next ticket.
pub(super) struct TicketGuard<'a>(&'a Ticket);

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
    pub(super) fn for_file(file: Option<&Path>) -> Self {
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
    pub(super) fn hold(&self) -> Option<TicketGuard<'_>> {
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
pub(super) fn relaxed_sync_of(conn: &Connection) -> Result<Option<i64>, AuditError> {
    let file_backed = conn.path().is_some_and(|p| !p.is_empty());
    let level: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    Ok((file_backed && level < SYNC_FULL).then_some(level))
}

impl std::fmt::Display for Durability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Durability::Normal => "normal",
            Durability::Full => "full",
        })
    }
}

pub(super) fn open_connection(
    path: &Path,
    durability: Durability,
) -> Result<Connection, AuditError> {
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

pub(super) fn open_memory_connection() -> Result<Connection, AuditError> {
    let conn = Connection::open_in_memory()?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
    Ok(conn)
}
