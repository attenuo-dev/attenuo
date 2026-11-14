//! Errors of attenuation and chain validation.

use thiserror::Error;

/// Why a requested capability set could not be derived from a parent set.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AttenuationError {
    /// The requested set contains a capability that no parent capability covers.
    #[error("requested capability `{requested}` is not covered by the parent capability set")]
    NotCovered {
        /// The uncovered capability, as [`crate::Capability::display`] writes it.
        requested: String,
    },
    /// The requested set is empty; a hop with no capabilities is a configuration error.
    #[error("requested capability set is empty")]
    Empty,
    /// At hop 0 ([`crate::CapabilitySet::attenuate_root`]): two requested capabilities take
    /// their limits from the same limited capability of the root grant or ceiling, so each
    /// would carry the whole figure (SR-121).
    #[error(
        "requested capabilities `{first}` and `{second}` take their limits from the same \
         limited capability, which bounds one capability of a root token, not several"
    )]
    LimitSplit {
        /// One of them, as [`crate::Capability::display`] writes the request.
        first: String,
        /// The other.
        second: String,
    },
    /// The requested set is larger than [`crate::capability::MAX_CAPABILITIES`] or holds a
    /// `one_of` longer than [`crate::capability::MAX_ONE_OF_VALUES`] (SR-123). Checked before
    /// anything is compared, since attenuation costs the product of both sides' sizes.
    #[error(transparent)]
    TooLarge(#[from] SizeError),
}

/// Why a capability set is too large to be requested or carried by a token (SR-123).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SizeError {
    /// More capabilities than [`crate::capability::MAX_CAPABILITIES`].
    #[error("{count} capabilities requested; one request or token holds at most {max}")]
    TooManyCapabilities {
        /// How many the set holds.
        count: usize,
        /// The bound.
        max: usize,
    },
    /// A `one_of` constraint with more values than [`crate::capability::MAX_ONE_OF_VALUES`].
    #[error("`one_of` on argument {arg:?} of `{capability}` lists {count} values; at most {max} are allowed")]
    OneOfTooLong {
        /// The capability's `server:tool`.
        capability: String,
        /// The constrained argument.
        arg: String,
        /// How many values the list holds.
        count: usize,
        /// The bound.
        max: usize,
    },
}

/// Why a delegation chain is not valid.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The chain has no hops at all.
    #[error("delegation chain has no hops")]
    NoHops,
    /// A hop's expiry is at or before the time the chain is checked at.
    #[error("hop {index} expired at {expires_at}")]
    HopExpired {
        /// Position of the hop (0 is the root).
        index: usize,
        /// The hop's expiry, RFC 3339.
        expires_at: String,
    },
    /// A hop expires later than the hop that delegated to it.
    #[error("hop {index} expires after its parent hop {parent}")]
    ExpiryNotMonotonic {
        /// Position of the hop.
        index: usize,
        /// Position of its parent hop.
        parent: usize,
    },
    /// A hop holds a capability its parent does not cover.
    #[error("hop {index} widens capabilities relative to hop {parent}: {source}")]
    AttenuationViolated {
        /// Position of the hop.
        index: usize,
        /// Position of its parent hop.
        parent: usize,
        /// What was not covered.
        #[source]
        source: AttenuationError,
    },
    /// A hop's capabilities are more than one token may hold ([`SizeError`], SR-123).
    #[error("hop {index}: {source}")]
    TooLarge {
        /// Position of the hop.
        index: usize,
        /// What is too large.
        #[source]
        source: SizeError,
    },
    /// The chain has more hops than allowed.
    #[error("chain depth {depth} exceeds the maximum of {max}")]
    TooDeep {
        /// Number of hops in the chain.
        depth: usize,
        /// The largest number of hops allowed.
        max: usize,
    },
    /// The originating user's subject is empty.
    #[error("originating user subject is empty")]
    EmptySubject,
    /// The requested lifetime does not give a representable expiry time.
    #[error("requested lifetime is out of range")]
    TtlOutOfRange,
    /// A hop's agent id is empty.
    #[error("hop {index} has an empty agent id")]
    EmptyAgentId {
        /// Position of the hop.
        index: usize,
    },
    /// A hop's lease id is empty.
    #[error("hop {index} has an empty lease id")]
    EmptyLeaseId {
        /// Position of the hop.
        index: usize,
    },
    /// A hop was issued at or after its own expiry.
    #[error("hop {index} is issued at or after its expiry")]
    IssuedAfterExpiry {
        /// Position of the hop.
        index: usize,
    },
    /// A hop was issued before the hop that delegated to it.
    #[error("hop {index} is issued before its parent hop {parent}")]
    IssuedBeforeParent {
        /// Position of the hop.
        index: usize,
        /// Position of its parent hop.
        parent: usize,
    },
    /// The same lease id appears on more than one hop.
    #[error("lease `{lease}` of hop {index} is already used by hop {first}")]
    DuplicateLease {
        /// Position of the later hop.
        index: usize,
        /// Position of the first hop with this lease.
        first: usize,
        /// The repeated lease id.
        lease: String,
    },
    /// The same agent id appears on more than one hop (an agent delegating to itself, or a
    /// cycle back to an earlier agent).
    #[error("agent `{agent}` of hop {index} already acts at hop {first} of this chain")]
    DuplicateAgent {
        /// Position of the later hop.
        index: usize,
        /// Position of the first hop with this agent.
        first: usize,
        /// The repeated agent id.
        agent: String,
    },
    /// A capability of the hop names a server or tool that no call can have (see
    /// [`crate::names`]).
    #[error("hop {index} has an invalid capability: {source}")]
    InvalidName {
        /// Position of the hop.
        index: usize,
        /// What is wrong with the name.
        #[source]
        source: crate::names::NameError,
    },
    /// A capability of the hop carries a malformed limit (see [`crate::limits`]).
    #[error("hop {index} has an invalid limit: {source}")]
    InvalidLimit {
        /// Position of the hop.
        index: usize,
        /// What is wrong with the limit.
        #[source]
        source: crate::limits::LimitError,
    },
}
