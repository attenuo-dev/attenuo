//! Named stages of a proxied call, for per-stage timing.
//!
//! The proxy times the stages it runs itself ([`Stage::Upstream`], [`Stage::Response`],
//! [`Stage::Total`]) and reports them through [`crate::Authorizer::observe_stage`]; the
//! authorizer times its own (token verification, lease check, policy, audit append, the hop to
//! a blocking pool). The server turns both into the `attenuo_proxy_stage_seconds` histogram.
//! Each stage costs one `Instant::now()` pair.

/// One timed stage. The label values are fixed, so metric cardinality stays bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Bearer token verification answered from the verified-token cache.
    TokenVerifyHit,
    /// Bearer token verification that ran the verifier (signatures, decoding, checks).
    TokenVerifyMiss,
    /// Lease check of every hop of the chain, inside the decision.
    LeaseCheck,
    /// Capability stage and Cedar evaluation.
    Policy,
    /// Appending the decision record to the audit log.
    AuditAppend,
    /// Getting the decision onto a blocking thread and its result back: the authorizer's wait
    /// for the decision minus the decision itself.
    BlockingPool,
    /// Sending the screened request upstream until its response headers arrive.
    Upstream,
    /// From the upstream's response headers to the response the proxy hands back (filtering,
    /// session binding, headers). A streamed body is relayed after this and is not included.
    Response,
    /// The proxy's `POST` handler from first byte of handling to the response it returns,
    /// for requests that carried at least one decided call.
    Total,
}

impl Stage {
    /// Every stage, in the order a call passes through them.
    pub const ALL: [Stage; 9] = [
        Stage::TokenVerifyHit,
        Stage::TokenVerifyMiss,
        Stage::LeaseCheck,
        Stage::Policy,
        Stage::AuditAppend,
        Stage::BlockingPool,
        Stage::Upstream,
        Stage::Response,
        Stage::Total,
    ];

    /// The `stage` label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::TokenVerifyHit => "token_verify_hit",
            Stage::TokenVerifyMiss => "token_verify_miss",
            Stage::LeaseCheck => "lease_check",
            Stage::Policy => "policy",
            Stage::AuditAppend => "audit_append",
            Stage::BlockingPool => "blocking_pool",
            Stage::Upstream => "upstream",
            Stage::Response => "response",
            Stage::Total => "total",
        }
    }

    /// Position in [`Stage::ALL`].
    pub fn index(self) -> usize {
        self as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_matches_all() {
        for (i, s) in Stage::ALL.iter().enumerate() {
            assert_eq!(s.index(), i, "{}", s.as_str());
        }
    }
}
