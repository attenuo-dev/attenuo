//! The single-writer fence: an exclusive advisory lock on `<database>.lock`, held by the one
//! process that owns a database file.
//!
//! SQLite's own locking keeps two processes from corrupting a file, but the server keeps state
//! next to the file that assumes it is the only writer: the run lock that serialises a run's
//! budgeted decisions, the replay caches that make a credential single use, the outbox
//! recovery and the loaded policy set all live in the process. A second server on the same
//! file (a rolling update with overlap, a failover script that starts the new instance before
//! the old one is dead) breaks those guarantees silently. [`WriterFence::acquire`] makes the
//! second process fail at start-up instead.
//!
//! The lock is an OS advisory lock (`flock(2)` on Unix, `LockFileEx` on Windows) taken through
//! [`std::fs::File::try_lock`]. It is tied to the open file, so it is released when the fence is
//! dropped and, because the OS closes every file of a process that exits, when the process
//! exits or crashes: a stale lock file left on disk does not block the next start. Two opens
//! of the lock file in one process are independent, so a second fence in the same process is
//! refused too.
//!
//! The fence is advisory: only processes that take it are kept out. The stores themselves
//! ([`SqliteAudit`](super::SqliteAudit), [`SqliteLeaseStore`](super::SqliteLeaseStore)) do
//! not take it, because one server opens the same file through several of them; the server
//! takes it once, before it opens them. `flock` is reliable on a local filesystem and on a
//! `ReadWriteOnce` volume; on NFS it is emulated with `fcntl` locks, which many setups do not
//! honour across hosts, and SQLite in WAL mode does not work there anyway.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::AuditError;

/// An exclusive advisory lock on `<database>.lock`, held until dropped.
#[derive(Debug)]
pub struct WriterFence {
    /// Holds the lock; closing it releases the lock.
    file: File,
    path: PathBuf,
}

impl WriterFence {
    /// The lock file of `database`: the same path with `.lock` appended
    /// (`audit.sqlite` → `audit.sqlite.lock`), in the same directory.
    pub fn lock_path(database: &Path) -> PathBuf {
        let mut name = database.as_os_str().to_owned();
        name.push(".lock");
        PathBuf::from(name)
    }

    /// Take the fence of `database`: create `<database>.lock` if needed and lock it
    /// exclusively, without waiting. The process id is written into the file, for the error
    /// another process gets and for an operator who looks. The database itself is not
    /// opened or created.
    ///
    /// The path is resolved first (symbolic links and `..`, through the directory when the
    /// database does not exist yet), so two spellings of one file share one lock.
    ///
    /// # Errors
    ///
    /// [`AuditError::Fenced`] when another holder has the lock (another process, or another
    /// fence of this process), naming the lock file and the process id it records.
    /// [`AuditError::Storage`] when the lock file cannot be created, opened or locked for
    /// another reason (a missing directory, a read-only filesystem, a filesystem without
    /// locks).
    pub fn acquire(database: &Path) -> Result<Self, AuditError> {
        let path = Self::lock_path(&resolve(database));
        let io = |what: &str, e: std::io::Error| {
            AuditError::Storage(format!("{what} {}: {e}", path.display()))
        };
        // No truncation before the lock is held: the file holds the current holder's pid.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| io("cannot open the lock file", e))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let mut text = String::new();
                let holder = file
                    .read_to_string(&mut text)
                    .ok()
                    .and_then(|_| text.trim().parse::<u32>().ok());
                return Err(AuditError::Fenced { lock: path, holder });
            }
            Err(TryLockError::Error(e)) => return Err(io("cannot lock", e)),
        }
        // Best effort: the pid is for people, the lock is what counts.
        let _ = file
            .set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| writeln!(file, "{}", std::process::id()))
            .and_then(|()| file.flush());
        Ok(Self { file, path })
    }

    /// The lock file this fence holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WriterFence {
    fn drop(&mut self) {
        // Closing the file releases the lock as well; unlocking first says so explicitly. The
        // file is left in place: removing it would race a process that just opened it.
        let _ = self.file.unlock();
    }
}

/// `database` with symbolic links and `..` resolved: the file itself when it exists, else its
/// directory joined with its name. Unchanged when neither resolves (the open then reports it).
fn resolve(database: &Path) -> PathBuf {
    if let Ok(p) = std::fs::canonicalize(database) {
        return p;
    }
    let dir = match database.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    match (std::fs::canonicalize(dir), database.file_name()) {
        (Ok(dir), Some(name)) => dir.join(name),
        _ => database.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_appends_lock() {
        assert_eq!(
            WriterFence::lock_path(Path::new("/var/lib/attenuo/audit.sqlite")),
            PathBuf::from("/var/lib/attenuo/audit.sqlite.lock")
        );
    }

    /// A second fence on the same database is refused, naming the lock file and this
    /// process; once the first is dropped, the next one succeeds.
    #[test]
    fn second_fence_is_refused_until_the_first_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.sqlite");
        let first = WriterFence::acquire(&db).unwrap();
        assert!(first.path().ends_with("audit.sqlite.lock"));
        assert!(!db.exists(), "the fence does not create the database");
        match WriterFence::acquire(&db).unwrap_err() {
            AuditError::Fenced { lock, holder } => {
                assert_eq!(lock, first.path());
                assert_eq!(holder, Some(std::process::id()));
            }
            other => panic!("expected Fenced, got {other:?}"),
        }
        drop(first);
        let again = WriterFence::acquire(&db).unwrap();
        drop(again);
    }

    /// Two spellings of one file share one lock.
    #[test]
    fn spellings_of_one_file_share_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let plain = dir.path().join("audit.sqlite");
        let roundabout = dir.path().join("sub/../audit.sqlite");
        let _held = WriterFence::acquire(&plain).unwrap();
        assert!(matches!(
            WriterFence::acquire(&roundabout),
            Err(AuditError::Fenced { .. })
        ));
    }

    /// A lock file left behind by a process that is gone does not block: the lock, not the
    /// file, is the fence.
    #[test]
    fn a_stale_lock_file_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.sqlite");
        std::fs::write(WriterFence::lock_path(&db), "4242\n").unwrap();
        let fence = WriterFence::acquire(&db).unwrap();
        let text = std::fs::read_to_string(fence.path()).unwrap();
        assert_eq!(text.trim(), std::process::id().to_string());
    }

    #[test]
    fn a_missing_directory_is_a_storage_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("no/such/dir/audit.sqlite");
        assert!(matches!(
            WriterFence::acquire(&db),
            Err(AuditError::Storage(_))
        ));
    }
}
