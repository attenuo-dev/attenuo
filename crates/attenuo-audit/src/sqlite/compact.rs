//! Shrinking the database file offline (`attenuo audit compact`): `VACUUM` with the server
//! stopped, between checks that prove nothing but the file's size changed.
//!
//! A prune deletes rows, and SQLite puts the freed pages on its free list for new rows; the
//! file does not get smaller (design note `docs/design/audit-retention.md`, section 7).
//! [`compact`] rewrites the file in place with `VACUUM` and then truncates the write-ahead log,
//! so the space goes back to the filesystem. It changes no row, so it writes no audit entry.
//!
//! The steps, each of which refuses ([`CompactError::Refused`], nothing changed) or fails:
//!
//! 1. Refuse a database on a network filesystem, where neither lock below can be trusted.
//! 2. Take the single-writer fence (`<database>.lock`), which a running attenuo server holds
//!    for as long as it runs, idle or not.
//! 3. Open the file (never create it) with `locking_mode=EXCLUSIVE` and take SQLite's
//!    exclusive lock with a short busy timeout. In WAL mode, the mode the server always leaves
//!    the file in, every connection that has read the file holds a shared lock on it until it
//!    closes, so this fails while any other connection is open and has read it, idle or in a
//!    transaction. A connection that was opened but has not read anything yet holds no lock
//!    and cannot be seen; once this lock is taken it cannot read until it is released. The
//!    lock is held to the end.
//! 4. Record the state before ([`CompactState`]): `PRAGMA integrity_check` (refused unless
//!    `ok`), the schema version (refused unless [`SCHEMA_VERSION`]; nothing is migrated
//!    here), the size and the free pages, the entry count, the chain head, the prune marker
//!    and newest anchor, the hash chain walked from its stored start (refused when it does
//!    not verify: `VACUUM` erases freed pages that may hold what an investigation needs), and
//!    a SHA-256 of every row of every table, rowid included, and of the schema text.
//! 5. Refuse a table whose rowids `VACUUM` may renumber: a rowid table with neither an
//!    `INTEGER PRIMARY KEY` nor any index. None of attenuo's tables is one today.
//! 6. Refuse when the free space is clearly too small: `VACUUM` builds a copy of the live data
//!    in SQLite's temporary directory and writes it again into the WAL next to the file.
//! 7. With [`CompactOptions::dry_run`], stop here.
//! 8. `VACUUM`, then `PRAGMA wal_checkpoint(TRUNCATE)`.
//! 9. Record the state again and compare everything but the size and the free pages. A
//!    difference is [`CompactError::PostCheck`]: the file was rewritten and must not be used;
//!    restore the backup.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::filesystem::{self, Filesystem};
use super::log::{entry_from_row, ENTRY_COLUMNS};
use super::migrations::{check_entry_hash, user_version, SCHEMA_VERSION};
use super::retention::{all_anchors, StoredAnchor};
use super::WriterFence;
use crate::error::AuditError;
use crate::log::VerifyReport;

/// How long [`compact`] waits for SQLite's exclusive lock by default before it refuses.
pub const COMPACT_BUSY_TIMEOUT: Duration = Duration::from_secs(2);

/// Free space asked for on top of the live data, per place `VACUUM` writes: 2% of it plus
/// 16 MiB (the WAL's frame headers, SQLite's own bookkeeping, and room to spare).
fn margin(live: u64) -> u64 {
    live / 50 + 16 * 1024 * 1024
}

/// Answers the bytes an unprivileged process may still write on the filesystem of a
/// directory.
type FreeSpaceProbe = Box<dyn Fn(&Path) -> std::io::Result<u64>>;

/// Runs on the connection right after `VACUUM`, before the checks after it.
#[cfg(any(test, feature = "testing"))]
type AfterVacuum = Box<dyn FnOnce(&Connection) -> rusqlite::Result<()>>;

/// How [`compact`] runs.
pub struct CompactOptions {
    dry_run: bool,
    busy_timeout: Duration,
    free_space: FreeSpaceProbe,
    #[cfg(any(test, feature = "testing"))]
    after_vacuum: Option<AfterVacuum>,
}

impl Default for CompactOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            busy_timeout: COMPACT_BUSY_TIMEOUT,
            free_space: Box::new(available_bytes),
            #[cfg(any(test, feature = "testing"))]
            after_vacuum: None,
        }
    }
}

impl std::fmt::Debug for CompactOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompactOptions")
            .field("dry_run", &self.dry_run)
            .field("busy_timeout", &self.busy_timeout)
            .finish_non_exhaustive()
    }
}

impl CompactOptions {
    /// Run every check before `VACUUM` and stop: the file is not changed.
    #[must_use]
    pub fn dry_run(mut self, on: bool) -> Self {
        self.dry_run = on;
        self
    }

    /// How long to wait for SQLite's exclusive lock (default [`COMPACT_BUSY_TIMEOUT`]).
    #[must_use]
    pub fn busy_timeout(mut self, timeout: Duration) -> Self {
        self.busy_timeout = timeout;
        self
    }

    /// Tests: answer the free space of a directory with `probe` instead of asking the
    /// filesystem.
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    #[must_use]
    pub fn with_free_space_probe(
        mut self,
        probe: impl Fn(&Path) -> std::io::Result<u64> + 'static,
    ) -> Self {
        self.free_space = Box::new(probe);
        self
    }

    /// Tests: run `f` on the connection right after `VACUUM`, to make the checks after it
    /// fail.
    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    #[must_use]
    pub fn after_vacuum(
        mut self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<()> + 'static,
    ) -> Self {
        self.after_vacuum = Some(Box::new(f));
        self
    }
}

/// The SHA-256 of one table's rows, in rowid (or primary key) order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableDigest {
    /// The table.
    pub name: String,
    /// Its rows.
    pub rows: u64,
    /// SHA-256 (hex) of every row with its rowid, each value with its type.
    pub sha256: String,
}

/// What [`compact`] records before and after `VACUUM`. Everything but `file_bytes` and
/// `free_bytes` must come out the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompactState {
    /// `PRAGMA user_version`.
    pub schema_version: u32,
    /// `PRAGMA page_size`.
    pub page_size: u64,
    /// `page_count * page_size`: the database as SQLite sees it, WAL included.
    pub file_bytes: u64,
    /// `freelist_count * page_size`: the pages a `DELETE` freed.
    pub free_bytes: u64,
    /// Rows of the `audit` table, retained or not yet deleted by a prune.
    pub entries: u64,
    /// The newest entry's seq, if any.
    pub head_seq: Option<u64>,
    /// The newest entry's hash, if any.
    pub head_hash: Option<String>,
    /// The newest anchor's `through_seq`: the last seq pruned.
    pub pruned_through: Option<u64>,
    /// The newest anchor as stored, with its state.
    pub newest_anchor: Option<StoredAnchor>,
    /// The hash chain walked from where the newest anchor says the log starts (or from
    /// genesis), without keys: the anchor's signature is not checked here.
    pub chain: VerifyReport,
    /// Every table but `sqlite_master`, by name.
    pub tables: Vec<TableDigest>,
    /// SHA-256 (hex) of the schema text (type, name, table and SQL of every object).
    pub schema_sha256: String,
}

/// The free space check before `VACUUM`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpaceCheck {
    /// One entry per filesystem `VACUUM` writes to.
    pub places: Vec<SpacePlace>,
}

/// One filesystem of a [`SpaceCheck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpacePlace {
    /// What is written there: `"wal"`, `"temp"` or both.
    pub what: Vec<&'static str>,
    /// A directory on it.
    pub dir: PathBuf,
    /// Bytes asked for.
    pub needed: u64,
    /// Bytes available.
    pub available: u64,
}

/// What [`compact`] did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompactReport {
    /// The database file, symbolic links resolved.
    pub path: PathBuf,
    /// Whether this was a dry run (nothing changed).
    pub dry_run: bool,
    /// The database file and its `-wal` on disk before, in bytes.
    pub disk_bytes_before: u64,
    /// The same after (the same as before for a dry run).
    pub disk_bytes_after: u64,
    /// The state before.
    pub before: CompactState,
    /// The state after `VACUUM`; `None` for a dry run.
    pub after: Option<CompactState>,
    /// The free space check.
    pub space: SpaceCheck,
}

impl CompactReport {
    /// Bytes given back to the filesystem (0 for a dry run).
    pub fn bytes_returned(&self) -> u64 {
        self.disk_bytes_before.saturating_sub(self.disk_bytes_after)
    }
}

/// Why [`compact`] stopped.
#[derive(Debug, thiserror::Error)]
pub enum CompactError {
    /// A check before `VACUUM` refused: the file was not changed.
    #[error("{detail}")]
    Refused {
        /// A stable code: `in_use`, `network_filesystem`, `integrity`, `schema_version`,
        /// `not_attenuo`, `rowid_unsafe`, `chain_broken` or `disk_space`.
        code: &'static str,
        /// For people.
        detail: String,
    },
    /// `VACUUM` ran, and the state after it differs from the state before. The file must not
    /// be used: restore the backup.
    #[error(
        "the compacted file does not match the file before: {}. Do not start the server on \
         it; restore the backup taken before compacting",
        mismatches.join("; ")
    )]
    PostCheck {
        /// What differs, one item each.
        mismatches: Vec<String>,
    },
    /// Anything else (the file cannot be opened, a query failed).
    #[error(transparent)]
    Failed(#[from] AuditError),
}

impl From<rusqlite::Error> for CompactError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Failed(AuditError::Sqlite(e))
    }
}

fn refuse(code: &'static str, detail: impl Into<String>) -> CompactError {
    CompactError::Refused {
        code,
        detail: detail.into(),
    }
}

const IN_USE: &str = "the database is in use; stop the server first";

/// Shrink the database file at `path` in place (see the module documentation for the steps).
/// The server must be stopped.
///
/// # Errors
///
/// [`CompactError::Refused`] when a check before `VACUUM` fails (the file is not changed),
/// [`CompactError::PostCheck`] when the state after `VACUUM` differs from the state before,
/// and [`CompactError::Failed`] when the file cannot be opened or read, or `VACUUM` itself
/// fails (SQLite then leaves the file as it was).
pub fn compact(path: &Path, options: CompactOptions) -> Result<CompactReport, CompactError> {
    let path = super::fence::resolve(path);
    match std::fs::metadata(&path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => {
            return Err(
                AuditError::Storage(format!("{} is not a regular file", path.display())).into(),
            )
        }
        Err(e) => {
            return Err(AuditError::Storage(format!("cannot read {}: {e}", path.display())).into())
        }
    }
    if let Ok(Filesystem::Network(kind)) = filesystem::probe(&path) {
        return Err(refuse(
            "network_filesystem",
            format!(
                "{} is on a network filesystem ({kind}), where file locks cannot show that no \
                 other process has it open; copy it to a local disk to compact it",
                path.display()
            ),
        ));
    }
    let _fence = match WriterFence::acquire(&path) {
        Ok(f) => f,
        Err(AuditError::Fenced { lock, .. }) => {
            return Err(refuse(
                "in_use",
                format!(
                    "{IN_USE} ({} is held, by a running attenuo server or another compact)",
                    lock.display()
                ),
            ))
        }
        Err(e) => return Err(e.into()),
    };
    let wal = wal_path(&path);
    let wal_had_frames = file_len(&wal) > 0;
    let disk_bytes_before = file_len(&path) + file_len(&wal);

    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Closing the last connection copies the WAL into the file. Until `VACUUM`, which only a
    // run that passed every check reaches, a WAL with commits in it (a server that was killed)
    // is left as it is, so a dry run or a refusal changes no byte of either file.
    let no_checkpoint_on_close = |on: bool| {
        conn.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            on,
        )
    };
    if wal_had_frames {
        no_checkpoint_on_close(true)?;
    }
    lock_exclusive(&conn, options.busy_timeout)?;
    conn.pragma_update(None, "synchronous", "FULL")?;

    integrity(&conn, "before")?;
    let found = user_version(&conn)?;
    if found != SCHEMA_VERSION {
        return Err(refuse(
            "schema_version",
            if found > SCHEMA_VERSION {
                format!(
                    "the file is at schema version {found}, written by a newer attenuo; this \
                     one reads version {SCHEMA_VERSION}. Compact it with that newer version"
                )
            } else {
                format!(
                    "the file is at schema version {found}; this attenuo reads version \
                     {SCHEMA_VERSION} and does not migrate here. Back it up, start this \
                     version's server on it once (which migrates it), stop it, then compact"
                )
            },
        ));
    }
    check_entry_hash(&conn, false).map_err(|e| refuse("not_attenuo", e.to_string()))?;
    let unsafe_tables = rowid_unsafe_tables(&conn)?;
    if !unsafe_tables.is_empty() {
        return Err(refuse(
            "rowid_unsafe",
            format!(
                "VACUUM may renumber the rowids of {}: a table with no INTEGER PRIMARY KEY \
                 and no index",
                unsafe_tables.join(", ")
            ),
        ));
    }
    let before = state(&conn)?;
    if !before.chain.ok {
        return Err(refuse(
            "chain_broken",
            format!(
                "the hash chain does not verify (first bad seq {}); compacting would erase \
                 freed pages that may matter to an investigation. Run `attenuo audit verify` \
                 against the server and look into it first",
                before
                    .chain
                    .first_bad_seq
                    .map_or_else(|| "unknown".into(), |s| s.to_string())
            ),
        ));
    }
    let space = space_check(&path, &before, &options.free_space)?;

    if options.dry_run {
        drop(conn);
        return Ok(CompactReport {
            disk_bytes_after: file_len(&path) + file_len(&wal),
            path,
            dry_run: true,
            disk_bytes_before,
            before,
            after: None,
            space,
        });
    }

    if wal_had_frames {
        no_checkpoint_on_close(false)?;
    }
    conn.execute_batch("VACUUM")?;
    let journal: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if journal.eq_ignore_ascii_case("wal") {
        let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        if busy != 0 {
            return Err(AuditError::Storage(
                "the WAL could not be checkpointed after VACUUM (busy); the compacted data is \
                 in the WAL and the next start copies it"
                    .into(),
            )
            .into());
        }
    }
    #[cfg(any(test, feature = "testing"))]
    if let Some(f) = options.after_vacuum {
        f(&conn)?;
    }

    let mut mismatches = Vec::new();
    if let Err(e) = integrity(&conn, "after") {
        mismatches.push(e.to_string());
    }
    let after = state(&conn)?;
    mismatches.extend(differences(&before, &after));
    drop(conn);
    if !mismatches.is_empty() {
        return Err(CompactError::PostCheck { mismatches });
    }
    Ok(CompactReport {
        disk_bytes_after: file_len(&path) + file_len(&wal),
        path,
        dry_run: false,
        disk_bytes_before,
        before,
        after: Some(after),
        space,
    })
}

/// `<database>-wal`.
fn wal_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

/// The size of a file, 0 when it does not exist.
fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |m| m.len())
}

/// Take SQLite's exclusive lock on the file and keep it until the connection closes.
fn lock_exclusive(conn: &Connection, timeout: Duration) -> Result<(), CompactError> {
    conn.busy_timeout(timeout)?;
    // Before the first read: in WAL mode the connection then also keeps the WAL index in its
    // own memory, so it never needs the `-shm` file other processes share.
    let mode: String = conn.query_row("PRAGMA locking_mode=EXCLUSIVE", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("exclusive") {
        return Err(AuditError::Storage(format!(
            "could not set locking_mode=EXCLUSIVE (got `{mode}`)"
        ))
        .into());
    }
    match conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;") {
        Ok(()) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            Err(refuse(
                "in_use",
                format!("{IN_USE} (another connection has the file open)"),
            ))
        }
        Err(rusqlite::Error::SqliteFailure(e, msg))
            if e.code == rusqlite::ErrorCode::NotADatabase =>
        {
            Err(refuse(
                "not_attenuo",
                format!(
                    "not a SQLite database: {}",
                    msg.unwrap_or_else(|| e.to_string())
                ),
            ))
        }
        Err(e) => Err(e.into()),
    }
}

/// Refuse unless `PRAGMA integrity_check` answers `ok`.
fn integrity(conn: &Connection, when: &str) -> Result<(), CompactError> {
    let read = || -> rusqlite::Result<Vec<String>> {
        conn.prepare("PRAGMA integrity_check(20)")?
            .query_map([], |r| r.get(0))?
            .collect()
    };
    let lines = match read() {
        Ok(lines) => lines,
        // A file too damaged for the check to run is as much a refusal as one it reports.
        Err(rusqlite::Error::SqliteFailure(e, msg))
            if matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            vec![msg.unwrap_or_else(|| e.to_string())]
        }
        Err(e) => return Err(e.into()),
    };
    if lines.len() == 1 && lines[0] == "ok" {
        return Ok(());
    }
    Err(refuse(
        "integrity",
        format!(
            "PRAGMA integrity_check {when} compacting did not answer ok: {}",
            lines.join(" | ")
        ),
    ))
}

/// The tables `VACUUM` may give new rowids: rowid tables, other than SQLite's own, with no
/// `INTEGER PRIMARY KEY` (which is the rowid) and no index (SQLite copies the rowids of a
/// table with an index, and gives a table with neither new ones in the same order).
fn rowid_unsafe_tables(conn: &Connection) -> Result<Vec<String>, CompactError> {
    let mut out = Vec::new();
    for (name, without_rowid) in tables(conn)? {
        if without_rowid || name.starts_with("sqlite_") {
            continue;
        }
        let pk: Vec<(String, i64)> = conn
            .prepare("SELECT type, pk FROM pragma_table_info(?1) WHERE pk > 0")?
            .query_map([&name], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let integer_pk = pk.len() == 1 && pk[0].0.eq_ignore_ascii_case("INTEGER");
        let indexes: i64 =
            conn.query_row("SELECT count(*) FROM pragma_index_list(?1)", [&name], |r| {
                r.get(0)
            })?;
        if !integer_pk && indexes == 0 {
            out.push(name);
        }
    }
    Ok(out)
}

/// Every table of the main database but the schema table, by name, and whether it is a
/// `WITHOUT ROWID` table.
fn tables(conn: &Connection) -> Result<Vec<(String, bool)>, CompactError> {
    Ok(conn
        .prepare(
            "SELECT name, wr FROM pragma_table_list \
             WHERE schema = 'main' AND type = 'table' \
             AND name NOT IN ('sqlite_schema', 'sqlite_master') ORDER BY name",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)))?
        .collect::<Result<_, _>>()?)
}

fn pragma_u64(conn: &Connection, name: &str) -> Result<u64, CompactError> {
    let v: i64 = conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?;
    Ok(u64::try_from(v).unwrap_or(0))
}

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Record everything [`compact`] compares.
fn state(conn: &Connection) -> Result<CompactState, CompactError> {
    let page_size = pragma_u64(conn, "page_size")?;
    let anchors = all_anchors(conn)?;
    let head: Option<(i64, String)> = conn
        .query_row(
            "SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    let entries: i64 = conn.query_row("SELECT count(*) FROM audit", [], |r| r.get(0))?;
    let mut tables_out = Vec::new();
    for (name, without_rowid) in tables(conn)? {
        tables_out.push(table_digest(conn, &name, without_rowid)?);
    }
    let newest_anchor = anchors.last().cloned();
    Ok(CompactState {
        schema_version: user_version(conn)?,
        page_size,
        file_bytes: pragma_u64(conn, "page_count")?.saturating_mul(page_size),
        free_bytes: pragma_u64(conn, "freelist_count")?.saturating_mul(page_size),
        entries: u64_of(entries),
        head_seq: head.as_ref().map(|h| u64_of(h.0)),
        head_hash: head.map(|h| h.1),
        pruned_through: newest_anchor.as_ref().map(|a| a.anchor.through_seq),
        chain: walk_chain(conn, newest_anchor.as_ref())?,
        newest_anchor,
        tables: tables_out,
        schema_sha256: schema_digest(conn)?,
    })
}

/// The hash chain, walked as `AuditSink::verify_chain` walks it: from genesis, or from right
/// after the newest anchor's boundary with the anchor's hash (its signature is not checked).
fn walk_chain(
    conn: &Connection,
    newest: Option<&StoredAnchor>,
) -> Result<VerifyReport, CompactError> {
    let after = newest.map(|a| a.anchor.through_seq);
    let from = after.map_or(i64::MIN, |a| {
        i64::try_from(a).unwrap_or(i64::MAX).saturating_add(1)
    });
    let mut stmt = conn.prepare(&format!(
        "SELECT {ENTRY_COLUMNS} FROM audit WHERE seq >= ?1 ORDER BY seq"
    ))?;
    // One pass, a row at a time: a row that does not decode is the break at its seq.
    let entries = stmt
        .query_map([from], |row| Ok(entry_from_row(row)))?
        .map(|r| r.map_err(AuditError::from).and_then(|e| e));
    let report = match newest {
        None => crate::log::verify_entries(entries)?,
        Some(a) => {
            let mut r = crate::log::walk_entries(
                entries,
                Some((
                    a.anchor.through_seq.saturating_add(1),
                    a.anchor.through_hash.clone(),
                )),
                |_| {},
            )?;
            r.unauthenticated_start = Some(a.anchor.through_seq);
            r
        }
    };
    Ok(report)
}

/// SQL for a quoted identifier.
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Feed one value, with its type and length, so no two rows hash alike by accident.
fn feed(h: &mut Sha256, v: rusqlite::types::ValueRef<'_>) {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => h.update([0u8]),
        ValueRef::Integer(i) => {
            h.update([1u8]);
            h.update(i.to_be_bytes());
        }
        ValueRef::Real(f) => {
            h.update([2u8]);
            h.update(f.to_bits().to_be_bytes());
        }
        ValueRef::Text(t) => {
            h.update([3u8]);
            h.update((t.len() as u64).to_be_bytes());
            h.update(t);
        }
        ValueRef::Blob(b) => {
            h.update([4u8]);
            h.update((b.len() as u64).to_be_bytes());
            h.update(b);
        }
    }
}

/// The digest of one table. A rowid table is read with its rowid, in rowid order, so a
/// renumbered rowid is a difference; a `WITHOUT ROWID` table and SQLite's own tables
/// (`sqlite_sequence`, whose rowids no one reads) in the order of all their columns.
fn table_digest(
    conn: &Connection,
    name: &str,
    without_rowid: bool,
) -> Result<TableDigest, CompactError> {
    let columns: i64 =
        conn.query_row("SELECT count(*) FROM pragma_table_info(?1)", [name], |r| {
            r.get(0)
        })?;
    let sql = if without_rowid || name.starts_with("sqlite_") {
        let order: Vec<String> = (1..=columns).map(|i| i.to_string()).collect();
        format!(
            "SELECT * FROM {} ORDER BY {}",
            quoted(name),
            order.join(", ")
        )
    } else {
        format!("SELECT _rowid_, * FROM {} ORDER BY _rowid_", quoted(name))
    };
    let mut stmt = conn.prepare(&sql)?;
    let width = stmt.column_count();
    let mut rows = stmt.query([])?;
    let mut h = Sha256::new();
    let mut n = 0u64;
    while let Some(row) = rows.next()? {
        n += 1;
        h.update(b"row");
        for i in 0..width {
            feed(&mut h, row.get_ref(i)?);
        }
    }
    Ok(TableDigest {
        name: name.to_string(),
        rows: n,
        sha256: hex::encode(h.finalize()),
    })
}

/// The digest of the schema text. `rootpage` is left out: `VACUUM` moves tables.
fn schema_digest(conn: &Connection) -> Result<String, CompactError> {
    let mut stmt = conn.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name, tbl_name",
    )?;
    let mut rows = stmt.query([])?;
    let mut h = Sha256::new();
    while let Some(row) = rows.next()? {
        h.update(b"obj");
        for i in 0..4 {
            feed(&mut h, row.get_ref(i)?);
        }
    }
    Ok(hex::encode(h.finalize()))
}

/// Every item of `before` and `after` that differs, except the size and the free pages.
fn differences(before: &CompactState, after: &CompactState) -> Vec<String> {
    let mut out = Vec::new();
    let mut cmp = |what: &str, a: String, b: String| {
        if a != b {
            out.push(format!("{what} was {a}, is {b}"));
        }
    };
    cmp(
        "schema version",
        before.schema_version.to_string(),
        after.schema_version.to_string(),
    );
    cmp(
        "page size",
        before.page_size.to_string(),
        after.page_size.to_string(),
    );
    cmp(
        "entry count",
        before.entries.to_string(),
        after.entries.to_string(),
    );
    cmp(
        "head",
        format!("{:?} {:?}", before.head_seq, before.head_hash),
        format!("{:?} {:?}", after.head_seq, after.head_hash),
    );
    cmp(
        "pruned through",
        format!("{:?}", before.pruned_through),
        format!("{:?}", after.pruned_through),
    );
    cmp(
        "newest anchor",
        format!("{:?}", before.newest_anchor),
        format!("{:?}", after.newest_anchor),
    );
    cmp(
        "chain walk",
        format!("{:?}", before.chain),
        format!("{:?}", after.chain),
    );
    cmp(
        "schema",
        before.schema_sha256.clone(),
        after.schema_sha256.clone(),
    );
    let names = |s: &CompactState| s.tables.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
    cmp("tables", names(before).join(","), names(after).join(","));
    for b in &before.tables {
        if let Some(a) = after.tables.iter().find(|a| a.name == b.name) {
            if a != b {
                out.push(format!(
                    "table {} was {} rows {}, is {} rows {}",
                    b.name, b.rows, b.sha256, a.rows, a.sha256
                ));
            }
        }
    }
    out
}

/// The directory SQLite puts temporary files in, found as its Unix VFS finds it: the first of
/// `SQLITE_TMPDIR`, `TMPDIR`, `/var/tmp`, `/usr/tmp`, `/tmp` and `.` that is a directory this
/// process may write and search.
#[cfg(unix)]
fn sqlite_temp_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = ["SQLITE_TMPDIR", "TMPDIR"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect();
    candidates.extend(["/var/tmp", "/usr/tmp", "/tmp", "."].map(PathBuf::from));
    candidates.into_iter().find(|d| writable_dir(d))
}

#[cfg(not(unix))]
fn sqlite_temp_dir() -> Option<PathBuf> {
    None
}

/// Whether this process may create files in `dir` (`access(W_OK | X_OK)`).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn writable_dir(dir: &Path) -> bool {
    use rustix::fs::Access;
    std::fs::metadata(dir).is_ok_and(|m| m.is_dir())
        && rustix::fs::access(dir, Access::WRITE_OK | Access::EXEC_OK).is_ok()
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))
))]
fn writable_dir(_dir: &Path) -> bool {
    false
}

/// The bytes an unprivileged process may still write on the filesystem of `dir`
/// (`f_bavail * f_frsize` of `statvfs(2)`).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn available_bytes(dir: &Path) -> std::io::Result<u64> {
    let st = rustix::fs::statvfs(dir)?;
    Ok(st.f_bavail.saturating_mul(st.f_frsize))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn available_bytes(_dir: &Path) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "free space is only measured on Linux, Android, macOS and iOS",
    ))
}

/// The device of a directory, to tell whether two directories share a filesystem.
#[cfg(unix)]
fn device(dir: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).ok().map(|m| m.dev())
}

#[cfg(not(unix))]
fn device(_dir: &Path) -> Option<u64> {
    None
}

/// Refuse when the free space is clearly too small for `VACUUM`: the live data (the file less
/// its free pages) once in the WAL next to the file and once in SQLite's temporary directory,
/// each with [`margin`]; both on one filesystem when the two directories share one.
fn space_check(
    path: &Path,
    before: &CompactState,
    probe: &FreeSpaceProbe,
) -> Result<SpaceCheck, CompactError> {
    let live = before.file_bytes.saturating_sub(before.free_bytes);
    let need = live.saturating_add(margin(live));
    let db_dir = filesystem::directory_of(path);
    let mut places = vec![SpacePlace {
        what: vec!["wal"],
        dir: db_dir.clone(),
        needed: need,
        available: 0,
    }];
    match sqlite_temp_dir() {
        Some(tmp) if device(&tmp).is_some() && device(&tmp) == device(&db_dir) => {
            places[0].what.push("temp");
            places[0].needed = need.saturating_mul(2);
        }
        Some(tmp) => places.push(SpacePlace {
            what: vec!["temp"],
            dir: tmp,
            needed: need,
            available: 0,
        }),
        None => {
            return Err(refuse(
                "disk_space",
                "cannot find SQLite's temporary directory (set SQLITE_TMPDIR to a directory \
                 with room for a copy of the database)",
            ))
        }
    }
    for p in &mut places {
        p.available = probe(&p.dir).map_err(|e| {
            refuse(
                "disk_space",
                format!("cannot measure the free space of {}: {e}", p.dir.display()),
            )
        })?;
        if p.available < p.needed {
            return Err(refuse(
                "disk_space",
                format!(
                    "not enough free space for VACUUM in {} ({}): {} bytes needed (the live \
                     data, {live} bytes, plus a margin{}), {} bytes available",
                    p.dir.display(),
                    p.what.join(" and "),
                    p.needed,
                    if p.what.len() == 2 {
                        ", twice: once for the temporary copy and once for the WAL"
                    } else {
                        ""
                    },
                    p.available
                ),
            ));
        }
    }
    Ok(SpaceCheck { places })
}
