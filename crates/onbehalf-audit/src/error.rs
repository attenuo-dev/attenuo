use thiserror::Error;

/// Errors from the audit log and lease store.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("timestamp parse error: {0}")]
    TimeParse(#[from] time::error::Parse),
    /// A lock protecting the store was poisoned by a panicking writer.
    #[error("audit store lock poisoned")]
    Poisoned,
    /// A stored row could not be read back as an entry (e.g. corrupted JSON).
    #[error("corrupt audit entry at seq {seq}: {detail}")]
    Corrupt { seq: u64, detail: String },
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
}

impl<T> From<std::sync::PoisonError<T>> for AuditError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        AuditError::Poisoned
    }
}
