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
    /// A lease operation referred to an id the store has never seen.
    #[error("unknown lease `{0}`")]
    UnknownLease(String),
}

impl<T> From<std::sync::PoisonError<T>> for AuditError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        AuditError::Poisoned
    }
}
