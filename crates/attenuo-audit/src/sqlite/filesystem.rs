//! The filesystem a database file lives on, so the server can refuse a network filesystem.
//!
//! SQLite in WAL mode needs every process that opens the file on one host, sharing the `-shm`
//! wal-index in memory, and SQLite's documentation says WAL does not work over a network
//! filesystem. Without WAL it relies on POSIX advisory locks, which many NFS setups do not
//! honour across hosts, and the [`WriterFence`](super::WriterFence)'s `flock` is emulated
//! with the same locks there. The failure is not an error but two writers that both believe
//! they hold the lock (multi-replica design note, section 3 (d), step 2).
//!
//! [`probe`] asks the operating system for the type of the filesystem holding a database's
//! directory with `statfs(2)`, through `rustix` (no `unsafe`): on Linux and Android the
//! `f_type` magic number ([`classify_magic`]), on macOS and iOS the `f_fstypename` name
//! ([`classify_name`]). Elsewhere it reports [`std::io::ErrorKind::Unsupported`].
//!
//! What counts as a network filesystem, and why:
//!
//! - Refused ([`Filesystem::Network`]): NFS, SMB, CIFS and SMB2/3 (the Linux `cifs` client),
//!   NCP, Coda, AFS (OpenAFS and the kernel's kAFS), 9p (also how WSL 2 mounts Windows drives
//!   and how several VMs share host folders), CephFS (kernel client) and Lustre; on macOS
//!   `nfs`, `smbfs`, `afpfs`, `webdav` and `cifs`. Each keeps the data on another host, or
//!   lets another host mount it at the same time, and none gives SQLite's WAL index the
//!   shared memory it needs.
//! - Not refused, reported ([`Filesystem::Fuse`]): FUSE. Its magic number is the same for
//!   sshfs, s3fs, GlusterFS's native client and ceph-fuse (remote) and for fuse-overlayfs
//!   (the root filesystem of rootless containers), gocryptfs or bindfs (local). Refusing
//!   it would stop local deployments that work; the server logs a warning instead.
//! - Everything else is [`Filesystem::Other`], taken as local. Cluster filesystems on shared
//!   block storage (GFS2, OCFS2) are not detected.

use std::path::{Path, PathBuf};

/// What [`probe`] found for a database file's directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    /// A network filesystem, by its usual name (`"nfs"`, `"cifs"`, `"smb2"`, `"9p"`, ...).
    Network(&'static str),
    /// FUSE: a user-space filesystem that may be local or remote; `statfs` cannot tell.
    Fuse,
    /// Any other type, taken as local.
    Other,
}

/// Linux `statfs` `f_type` magic numbers of network filesystems (`linux/magic.h` and the
/// filesystems' own headers), with the name the refusal shows.
pub const NETWORK_MAGICS: &[(u32, &str)] = &[
    (0x6969, "nfs"),
    (0x517B, "smb"),
    (0xFF53_4D42, "cifs"),
    (0xFE53_4D42, "smb2"),
    (0x564C, "ncp"),
    (0x7375_7245, "coda"),
    (0x5346_414F, "afs"),
    (0x6B41_4653, "afs"),
    (0x0102_1997, "9p"),
    (0x00C3_6400, "ceph"),
    (0x0BD0_0BD0, "lustre"),
];

/// The Linux `statfs` `f_type` of FUSE (`FUSE_SUPER_MAGIC`), whatever the daemon behind it.
pub const FUSE_MAGIC: u32 = 0x6573_5546;

/// macOS `f_fstypename` values of network filesystems.
pub const NETWORK_NAMES: &[&str] = &["nfs", "smbfs", "afpfs", "webdav", "cifs"];

/// Classify a Linux `statfs` `f_type`. Only the low 32 bits are meaningful: the kernel's
/// magic numbers are 32-bit, and `f_type` is a signed word on some architectures.
pub fn classify_magic(magic: u32) -> Filesystem {
    if magic == FUSE_MAGIC {
        return Filesystem::Fuse;
    }
    NETWORK_MAGICS
        .iter()
        .find(|(m, _)| *m == magic)
        .map_or(Filesystem::Other, |(_, name)| Filesystem::Network(name))
}

/// Classify a macOS `statfs` `f_fstypename` (`"apfs"`, `"nfs"`, `"macfuse"`, ...). Compared
/// without regard to ASCII case.
pub fn classify_name(name: &str) -> Filesystem {
    let lower = name.to_ascii_lowercase();
    if let Some(n) = NETWORK_NAMES.iter().find(|n| **n == lower) {
        return Filesystem::Network(n);
    }
    // macFUSE reports "macfuse" (older releases "osxfuse"), FUSE-T "fuse-t", others "fusefs".
    if lower.contains("fuse") {
        return Filesystem::Fuse;
    }
    Filesystem::Other
}

/// The type of the filesystem that holds `database`'s directory: the directory of the file
/// once symbolic links and `..` are resolved, which is where SQLite puts the `-wal` and
/// `-shm` files and the fence its `.lock`. The directory must exist; the database need not.
///
/// # Errors
///
/// The `statfs` error (a missing directory, a permission error), or
/// [`std::io::ErrorKind::Unsupported`] on a platform other than Linux, Android, macOS and
/// iOS. A caller that only wants to refuse a network filesystem should log the error and
/// carry on: not knowing is not a reason to refuse.
pub fn probe(database: &Path) -> std::io::Result<Filesystem> {
    probe_dir(&directory_of(database))
}

/// The directory [`probe`] looks at: `database`'s directory once symbolic links and `..` are
/// resolved (as far as they resolve), or `.` for a bare file name that does not resolve.
pub fn directory_of(database: &Path) -> PathBuf {
    let resolved = super::fence::resolve(database);
    match resolved.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn probe_dir(dir: &Path) -> std::io::Result<Filesystem> {
    let st = rustix::fs::statfs(dir)?;
    // Truncation intended: the magic numbers are 32-bit, `f_type` is a 32- or 64-bit word,
    // signed on some architectures, and the cast keeps the low 32 bits as they are.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let magic = st.f_type as u32;
    Ok(classify_magic(magic))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn probe_dir(dir: &Path) -> std::io::Result<Filesystem> {
    let st = rustix::fs::statfs(dir)?;
    // A NUL-terminated C string in a fixed array of `c_char`.
    #[allow(clippy::cast_sign_loss)]
    let bytes: Vec<u8> = st
        .f_fstypename
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    Ok(classify_name(&String::from_utf8_lossy(&bytes)))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn probe_dir(_dir: &Path) -> std::io::Result<Filesystem> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the filesystem type is only checked on Linux, Android, macOS and iOS",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_network_magics_are_network() {
        for (magic, name) in [
            (0x6969, "nfs"),
            (0x517B, "smb"),
            (0xFF53_4D42, "cifs"),
            (0xFE53_4D42, "smb2"),
            (0x564C, "ncp"),
            (0x7375_7245, "coda"),
            (0x5346_414F, "afs"),
            (0x6B41_4653, "afs"),
            (0x0102_1997, "9p"),
            (0x00C3_6400, "ceph"),
            (0x0BD0_0BD0, "lustre"),
        ] {
            assert_eq!(
                classify_magic(magic),
                Filesystem::Network(name),
                "{magic:#x}"
            );
        }
    }

    #[test]
    fn linux_fuse_is_reported_not_refused() {
        assert_eq!(classify_magic(0x6573_5546), Filesystem::Fuse);
    }

    #[test]
    fn linux_local_magics_are_other() {
        for magic in [
            0xEF53,      // ext2/3/4
            0x5846_5342, // xfs
            0x9123_683E, // btrfs
            0x0102_1994, // tmpfs
            0x794C_7630, // overlayfs
            0x2FC1_2FC1, // zfs
            0xF2F5_2010, // f2fs
            0x1234_5678, // no filesystem's
            0,
        ] {
            assert_eq!(classify_magic(magic), Filesystem::Other, "{magic:#x}");
        }
    }

    /// A 64-bit signed `f_type` holding CIFS's magic (sign-extended on a 32-bit word) still
    /// classifies by its low 32 bits.
    #[test]
    fn sign_extended_magic_keeps_its_low_bits() {
        let word: i64 = i64::from(0xFF53_4D42_u32 as i32);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let magic = word as u32;
        assert_eq!(classify_magic(magic), Filesystem::Network("cifs"));
    }

    #[test]
    fn macos_names() {
        for (name, fs) in [
            ("nfs", Filesystem::Network("nfs")),
            ("smbfs", Filesystem::Network("smbfs")),
            ("afpfs", Filesystem::Network("afpfs")),
            ("webdav", Filesystem::Network("webdav")),
            ("cifs", Filesystem::Network("cifs")),
            ("NFS", Filesystem::Network("nfs")),
            ("macfuse", Filesystem::Fuse),
            ("osxfuse", Filesystem::Fuse),
            ("fuse-t", Filesystem::Fuse),
            ("apfs", Filesystem::Other),
            ("hfs", Filesystem::Other),
            ("msdos", Filesystem::Other),
            ("exfat", Filesystem::Other),
            ("devfs", Filesystem::Other),
            ("", Filesystem::Other),
        ] {
            assert_eq!(classify_name(name), fs, "{name:?}");
        }
    }

    /// The temp directory of a test machine is local; a database that does not exist yet is
    /// probed through its directory.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    #[test]
    fn a_temp_dir_is_not_a_network_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let fs = probe(&dir.path().join("audit.sqlite")).unwrap();
        assert!(!matches!(fs, Filesystem::Network(_)), "{fs:?}");
    }

    #[test]
    fn directory_of_resolves_links() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let real = std::fs::canonicalize(&real).unwrap();
        assert_eq!(directory_of(&real.join("audit.sqlite")), real);
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(directory_of(&link.join("audit.sqlite")), real);
        }
    }

    /// The refusal's text is stable: operators search for it and the deploy guide quotes it.
    #[test]
    fn the_refusal_text_is_stable() {
        let err = crate::AuditError::NetworkFilesystem {
            dir: PathBuf::from("/mnt/nfs/attenuo"),
            fs: "nfs",
        };
        assert_eq!(
            err.to_string(),
            "/mnt/nfs/attenuo is on a network filesystem (nfs): SQLite in WAL mode needs every process on one host, and file locks there may not keep a second writer out, so the audit log and lease registry could be corrupted. Put sqlite_path on a local disk or a volume one host mounts (a ReadWriteOnce volume), or set `[audit] allow_network_filesystem = true` if only one host ever mounts this filesystem and its locking works."
        );
    }

    #[test]
    fn a_missing_directory_is_an_error_not_a_verdict() {
        let dir = tempfile::tempdir().unwrap();
        assert!(probe(&dir.path().join("missing/audit.sqlite")).is_err());
    }
}
