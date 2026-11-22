//! File placement that never replaces an existing file, shared by the CLI's `audit prune` and
//! the server's automatic prune (both write archive files).

use std::io;
use std::path::Path;

/// Rename `from` to `to`, failing with [`io::ErrorKind::AlreadyExists`] if `to` exists, in
/// one step (Linux `renameat2(RENAME_NOREPLACE)`). Elsewhere it fails with
/// [`io::ErrorKind::Unsupported`].
///
/// # Errors
///
/// Whatever the rename fails with.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(io::Error::from)
}

/// Rename `from` to `to` without replacing `to`: not available on this platform.
///
/// # Errors
///
/// Always [`io::ErrorKind::Unsupported`].
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn rename_noreplace(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no rename that refuses to replace on this platform",
    ))
}

/// Whether a failed `hard_link` says the file system has no hard links (rather than that the
/// link is not allowed or the target exists): `EOPNOTSUPP`, or on Unix `EPERM`, which
/// `link(2)` answers on a file system that does not support them.
pub fn links_unsupported(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(1)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Put `tmp` at `target` without ever replacing a file there: a hard link (then `tmp` is
/// removed), or, only where the file system has no hard links ([`links_unsupported`]),
/// [`rename_noreplace`]. A file at `target` is [`io::ErrorKind::AlreadyExists`]; any other
/// failure of the link (`EACCES`, `EROFS`, a full disk) is returned as it is. `tmp` is left
/// in place on failure. The directory is not flushed here.
///
/// # Errors
///
/// As described.
pub fn place_no_replace(tmp: &Path, target: &Path) -> io::Result<()> {
    match std::fs::hard_link(tmp, target) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
            Ok(())
        }
        Err(e) if links_unsupported(&e) => rename_noreplace(tmp, target),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn place_never_replaces_and_reports_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let (tmp, target) = (dir.path().join(".a.tmp"), dir.path().join("a"));
        std::fs::write(&tmp, "new").unwrap();
        place_no_replace(&tmp, &target).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert!(!tmp.exists());
        std::fs::write(&tmp, "newer").unwrap();
        let e = place_no_replace(&tmp, &target).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert!(tmp.exists(), "the temporary file is left on failure");
        // A link that fails for another reason is not retried as a rename.
        let e = place_no_replace(&tmp, &dir.path().join("missing").join("a")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(!links_unsupported(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(links_unsupported(&io::Error::from(
            io::ErrorKind::Unsupported
        )));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn rename_noreplace_refuses_an_existing_name() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, "a").unwrap();
        std::fs::write(&b, "b").unwrap();
        let e = rename_noreplace(&a, &b).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        std::fs::remove_file(&b).unwrap();
        rename_noreplace(&a, &b).unwrap();
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "a");
    }
}
