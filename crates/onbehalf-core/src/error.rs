use thiserror::Error;

/// Why a requested capability set could not be derived from a parent set.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AttenuationError {
    /// The requested set contains a capability that no parent capability covers.
    #[error("requested capability `{requested}` is not covered by the parent capability set")]
    NotCovered { requested: String },
    /// The requested set is empty; a hop with no capabilities is a configuration error.
    #[error("requested capability set is empty")]
    Empty,
}

/// Why a delegation chain is not valid.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChainError {
    #[error("delegation chain has no hops")]
    NoHops,
    #[error("hop {index} expired at {expires_at}")]
    HopExpired { index: usize, expires_at: String },
    #[error("hop {index} expires after its parent hop {parent}")]
    ExpiryNotMonotonic { index: usize, parent: usize },
    #[error("hop {index} widens capabilities relative to hop {parent}: {source}")]
    AttenuationViolated {
        index: usize,
        parent: usize,
        #[source]
        source: AttenuationError,
    },
    #[error("chain depth {depth} exceeds the maximum of {max}")]
    TooDeep { depth: usize, max: usize },
    #[error("originating user subject is empty")]
    EmptySubject,
    /// The requested lifetime does not give a representable expiry time.
    #[error("requested lifetime is out of range")]
    TtlOutOfRange,
}
