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
    /// The database could not be set up as required (for example, WAL mode refused).
    #[error("audit storage error: {0}")]
    Storage(String),
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
    /// No approval with this id is stored.
    #[error("unknown approval `{0}`")]
    UnknownApproval(String),
    /// The approval was already granted, declined or consumed.
    #[error("approval `{id}` is {state}, not pending")]
    ApprovalNotPending { id: String, state: &'static str },
    /// The approval (or the lease it is bound to) has expired.
    #[error("approval or lease `{0}` has expired")]
    ApprovalExpired(String),
    /// No run-limit charge is recorded for this decision id (ADR-0010).
    #[error("no budget charge is recorded for decision `{0}`")]
    UnknownCharge(String),
    /// What this decision charged was already refunded.
    #[error("the budget charge of decision `{0}` was already refunded")]
    ChargeRefunded(String),
}

impl<T> From<std::sync::PoisonError<T>> for AuditError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        AuditError::Poisoned
    }
}
