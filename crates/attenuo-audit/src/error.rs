//! The error type shared by the audit log, the lease store and the export verifier.

use thiserror::Error;

/// Errors from the audit log and lease store.
#[derive(Debug, Error)]
pub enum AuditError {
    /// A SQLite call failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A stored or exported JSON value could not be encoded or decoded.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// A timestamp could not be written as RFC 3339.
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
    /// A stored timestamp could not be read back.
    #[error("timestamp parse error: {0}")]
    TimeParse(#[from] time::error::Parse),
    /// The database could not be set up as required (for example, WAL mode refused).
    #[error("audit storage error: {0}")]
    Storage(String),
    /// A lock protecting the store was poisoned by a panicking writer.
    #[error("audit store lock poisoned")]
    Poisoned,
    /// A stored row could not be read back as an entry (e.g. corrupted JSON).
    #[error("corrupt audit entry at seq {seq}: {detail}")]
    Corrupt {
        /// Sequence number of the unreadable row.
        seq: u64,
        /// What was wrong with it.
        detail: String,
    },
    /// An audit export could not be parsed.
    #[error("invalid audit export: {0}")]
    Export(String),
    /// A checkpoint was requested but no signing key was configured.
    #[error("no checkpoint signer is configured")]
    NoCheckpointSigner,
    /// The JWKS handed to checkpoint verification is malformed.
    #[error("invalid JWKS: {0}")]
    Jwks(String),
    /// A lease operation referred to an id the store has never seen.
    #[error("unknown lease `{0}`")]
    UnknownLease(String),
    /// A lease cannot be renewed because it has been revoked.
    #[error("lease `{0}` is revoked")]
    LeaseRevoked(String),
    /// A lease already carries a different chain binding (bindings are write-once).
    #[error("lease `{0}` is already bound to a different chain")]
    BindingConflict(String),
    /// No approval with this id is stored.
    #[error("unknown approval `{0}`")]
    UnknownApproval(String),
    /// The approval was already granted, declined or consumed.
    #[error("approval `{id}` is {state}, not pending")]
    ApprovalNotPending {
        /// The approval id.
        id: String,
        /// The state it is in instead, as its wire string.
        state: &'static str,
    },
    /// The approval (or the lease it is bound to) has expired.
    #[error("approval or lease `{0}` has expired")]
    ApprovalExpired(String),
    /// No run-limit charge is recorded for this decision id (ADR-0010).
    #[error("no budget charge is recorded for decision `{0}`")]
    UnknownCharge(String),
    /// What this decision charged was already refunded.
    #[error("the budget charge of decision `{0}` was already refunded")]
    ChargeRefunded(String),
    /// The run already has [`crate::MAX_PENDING_APPROVALS_PER_RUN`] pending approvals, so no
    /// new one is stored (SR-92).
    #[error("run `{chain_id}` already has {max} pending approvals")]
    TooManyPendingApprovals {
        /// The run (the lease of its first hop).
        chain_id: String,
        /// The cap, [`crate::MAX_PENDING_APPROVALS_PER_RUN`].
        max: usize,
    },
    /// Another holder has the database's single-writer fence
    /// ([`WriterFence`](crate::WriterFence)): another server process runs on this file.
    #[error(
        "another process holds {} ({}): one server process per database file; stop the other \
         instance first (in Kubernetes, use `strategy: Recreate`)",
        lock.display(),
        holder.map_or_else(|| "pid unknown".to_string(), |p| format!("pid {p}"))
    )]
    Fenced {
        /// The lock file, `<sqlite_path>.lock`.
        lock: std::path::PathBuf,
        /// The process id the lock file records, when it is readable.
        holder: Option<u32>,
    },
    /// An append was shed instead of waiting without bound: the writer's queue was full, or
    /// the writer did not take the record within the append timeout (a hung disk, say). The
    /// record was not written and never will be, so the caller may undo what the decision
    /// charged; the decision fails closed.
    #[error("audit append shed: {0}")]
    Overloaded(&'static str),
    /// The database file's schema version (`PRAGMA user_version`) is newer than this build
    /// knows: a newer attenuo wrote it. Nothing was read or written. Run the newer binary, or
    /// restore the backup taken before the upgrade; there is no downgrade.
    #[error(
        "the database has schema version {found}, written by a newer attenuo; this build reads \
         schema versions up to {supported}. Run the newer binary, or restore the backup taken \
         before upgrading: there is no downgrade"
    )]
    SchemaTooNew {
        /// The file's `user_version`.
        found: u32,
        /// [`SCHEMA_VERSION`](crate::SCHEMA_VERSION), the newest this build knows.
        supported: u32,
    },
}

impl<T> From<std::sync::PoisonError<T>> for AuditError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        AuditError::Poisoned
    }
}
