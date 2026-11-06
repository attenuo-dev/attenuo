//! The background WAL checkpointer that [`SqliteAudit::with_wal_checkpoints`](super::SqliteAudit::with_wal_checkpoints) starts, and
//! the counters it and the writer share.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use rusqlite::Connection;

use super::connection::BUSY_TIMEOUT;
use super::unix_now;
use crate::error::AuditError;

/// Default for [`SqliteAudit::with_wal_checkpoints`](super::SqliteAudit::with_wal_checkpoints) (`[audit] wal_checkpoint_seconds`).
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
    pub(super) static WAL_PAGES: std::cell::Cell<std::ffi::c_int> = const { std::cell::Cell::new(0) };
}

/// The writer connection's WAL hook: SQLite calls it after every commit in WAL mode with the
/// number of frames the WAL now holds. It replaces SQLite's own hook (the one behind
/// `wal_autocheckpoint`, which would run a `PASSIVE` checkpoint here that, with the
/// background checkpointer holding SQLite's checkpoint lock most of the time under load,
/// would nearly always return busy and copy nothing).
pub(super) fn note_wal_pages(
    _: &rusqlite::hooks::Wal,
    pages: std::ffi::c_int,
) -> rusqlite::Result<()> {
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
/// [`SqliteAudit::wal_stats`](super::SqliteAudit::wal_stats). For metrics: every field is read without a lock.
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
pub(super) struct WalCounters {
    rounds_complete: AtomicU64,
    rounds_incomplete: AtomicU64,
    round_errors: AtomicU64,
    locked_passes: AtomicU64,
    pub(super) backstops: AtomicU64,
    wal_presyncs: AtomicU64,
    db_presyncs: AtomicU64,
    last_complete_unix: AtomicU64,
    wal_frames: AtomicU64,
}

impl WalCounters {
    pub(super) fn snapshot(&self) -> WalStats {
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

    pub(super) fn bump(a: &AtomicU64) {
        a.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) fn wal_checkpoint(conn: &Connection, mode: &str) -> Result<WalCheckpoint, AuditError> {
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

pub(super) enum WalMsg {
    /// Enough commits since the last checkpoint: run one now.
    Kick,
    /// A signed audit checkpoint is near: sync the WAL file now, so that the commit writing
    /// it, which syncs at `FULL`, finds little left to write (see [`CHECKPOINT_PRESYNC_LEAD`]).
    SyncWal,
    /// The store is closing: run the final checkpoint and exit.
    Stop,
    /// Tests: answer once every message sent before this one has been handled
    /// (`SqliteAudit::settle_wal_checkpointer`).
    #[cfg(any(test, feature = "testing"))]
    Settle(mpsc::SyncSender<()>),
}

/// The background WAL checkpointer of a file-backed [`SqliteAudit`](super::SqliteAudit): a thread with its own
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
pub(super) struct WalCheckpointer {
    pub(super) msgs: mpsc::SyncSender<WalMsg>,
    pub(super) conn: Arc<Mutex<Connection>>,
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
    pub(super) fn start(
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
    pub(super) fn truncate(&self) -> Result<WalCheckpoint, AuditError> {
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
            #[cfg(any(test, feature = "testing"))]
            Ok(WalMsg::Settle(done)) => {
                let _ = done.send(());
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
pub(super) fn presync_lead(activity: &Activity) -> u64 {
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
pub(super) fn gated_checkpoint(
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
pub(super) fn nears_checkpoint(first: u64, last: u64, every: u64, lead: u64) -> bool {
    if every == 0 || lead == 0 || first == 0 || first > last {
        return false;
    }
    let before = first - 1;
    let next = (before / every + 1) * every;
    let point = next.saturating_sub(lead.min(every / 2));
    before < point && point <= last && last < next
}

/// Counters the WAL checkpointer reads to know whether the writer is busy.
#[derive(Default)]
pub(super) struct Activity {
    /// Appends handed to the writer thread and not answered yet.
    pub(super) pending: AtomicUsize,
    /// Entries committed since the store was opened.
    pub(super) committed: AtomicU64,
    /// Commits since the last background checkpoint started.
    pub(super) since_wal_checkpoint: AtomicU64,
    /// Wakes the checkpointer early (see [`WAL_CHECKPOINT_COMMITS`]).
    pub(super) wal_kick: OnceLock<mpsc::SyncSender<WalMsg>>,
    /// Held for the duration of every `PRAGMA wal_checkpoint` in this process, by the
    /// background thread and by the writer's backstop (see [`WalCheckpointer`]).
    checkpoint_gate: Mutex<()>,
    /// What the background checkpointer has done, for [`SqliteAudit::wal_stats`](super::SqliteAudit::wal_stats).
    pub(super) wal_stats: WalCounters,
    /// Tests and measurements: how long each pause the checkpointers impose lasted.
    #[cfg(any(test, feature = "testing"))]
    pub(super) timings: Mutex<WalTimings>,
    /// Tests and measurements: skip the database-file sync before the locked pass.
    #[cfg(any(test, feature = "testing"))]
    pub(super) no_presync: std::sync::atomic::AtomicBool,
    /// Tests and measurements: 0 for [`CHECKPOINT_PRESYNC_LEAD`], else the lead plus one.
    #[cfg(any(test, feature = "testing"))]
    pub(super) presync_lead: AtomicU64,
}

/// Tests and measurements: the pauses the WAL checkpointers imposed on appends, as returned
/// by [`SqliteAudit::wal_timings`](super::SqliteAudit::wal_timings).
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
