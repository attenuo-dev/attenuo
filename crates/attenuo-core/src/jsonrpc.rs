//! JSON-RPC 2.0 error codes the proxy sends and the CLI reads.
//!
//! The proxy answers with these codes; `attenuo-cli` (for example `attenuo call`) tells a
//! denial from an approval request by them. One definition keeps the two in step.

/// Standard JSON-RPC parse error.
pub const CODE_PARSE_ERROR: i64 = -32700;
/// Standard JSON-RPC invalid request.
pub const CODE_INVALID_REQUEST: i64 = -32600;
/// Standard JSON-RPC invalid params.
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// attenuo: missing or invalid bearer token (sent with HTTP 401).
pub const CODE_UNAUTHORIZED: i64 = -32001;
/// attenuo: the call was denied by policy.
pub const CODE_DENIED: i64 = -32003;
/// attenuo: no upstream is configured under this name (sent with HTTP 404).
pub const CODE_UNKNOWN_SERVER: i64 = -32004;
/// attenuo: the upstream could not be reached, or answered with something the proxy will not
/// relay (sent with HTTP 502).
pub const CODE_UPSTREAM: i64 = -32005;
/// attenuo: the proxy is out of a bounded resource, such as session slots (sent with HTTP
/// 503).
pub const CODE_UNAVAILABLE: i64 = -32006;
/// attenuo: this principal holds too many of a bounded resource, such as session slots (sent
/// with HTTP 429 and `Retry-After`; SR-49).
pub const CODE_TOO_MANY: i64 = -32007;
/// attenuo: the policy asks for an approval of this exact call before it may run
/// (`@obligation("approval")`, ADR-0009). Sent inside a `200` JSON-RPC response, like a
/// denial; `data` carries `reason: "approval_required"`, `decision_id`, `call_hash` and,
/// when the approval was stored, `approval_id` and `expires_at` (RFC 3339). The code is not
/// reserved anywhere (design open question 10).
pub const CODE_APPROVAL_REQUIRED: i64 = -32008;

#[cfg(test)]
mod tests {
    use super::*;

    /// The codes are wire values: a change here is a breaking change for every client.
    #[test]
    fn codes_are_stable() {
        assert_eq!(CODE_DENIED, -32003);
        assert_eq!(CODE_APPROVAL_REQUIRED, -32008);
        assert_eq!(CODE_UNAUTHORIZED, -32001);
    }
}
