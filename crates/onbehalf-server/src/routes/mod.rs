//! HTTP handlers, one module per concern.

pub mod admin;
pub mod authzen;
pub mod dev_root;
pub mod ops;
pub mod renew;
pub mod token;
pub mod wellknown;

use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue};
use onbehalf_core::{Decision, DecisionRecord, DelegationChain, ToolCall};
use serde::de::DeserializeOwned;
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::state::AppState;

/// Logical server name used in audit records for events the server itself performs.
pub const AUDIT_SERVER: &str = "onbehalf";
/// Audit `reason` for a successful token issuance (root mint or exchange).
pub const REASON_TOKEN_ISSUED: &str = "token_issued";
/// Audit `reason` for a successful lease renewal.
pub const REASON_LEASE_RENEWED: &str = "lease_renewed";

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// The bearer token from `Authorization`, `Ok(None)` when the header is absent, or an error
/// when it is present but not `Bearer <token>`.
pub(crate) fn bearer_of(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| ApiError::unauthorized("authorization header is not ASCII"))?;
    match raw.split_once(' ') {
        Some((scheme, token))
            if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() =>
        {
            Ok(Some(token.trim()))
        }
        _ => Err(ApiError::unauthorized(
            "expected `Authorization: Bearer <token>`",
        )),
    }
}

/// Parse a JSON body with a JSON error on failure (axum's own rejection is plain text).
pub(crate) fn parse_json<T: DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))
}

/// Mark a response as not cacheable (token responses, per RFC 6749 §5.1).
pub(crate) fn no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// Record a token issuance in the audit log.
///
/// The audit log stores decision records only, so an issuance is written as an `allow` with
/// reason `token_issued`, server `onbehalf` and tool `token.exchange` (or `token.root` for a
/// dev root mint). The chain is the *new* chain, so the record names the new hop's agent and
/// lease; the arguments (actor, requested capabilities) are stored as a digest like any call.
pub(crate) fn audit_issuance(
    state: &AppState,
    tool: &str,
    chain: &DelegationChain,
    arguments: Value,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, ApiError> {
    audit_event(state, REASON_TOKEN_ISSUED, tool, chain, arguments, now)
}

/// Record a server-performed event (issuance, lease renewal) as an `allow` decision record
/// with the given `reason`, server `onbehalf` and `tool` naming the event.
pub(crate) fn audit_event(
    state: &AppState,
    reason: &str,
    tool: &str,
    chain: &DelegationChain,
    arguments: Value,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, ApiError> {
    let call = ToolCall::new(AUDIT_SERVER, tool, arguments);
    let record = DecisionRecord::new(now, Decision::Allow, reason, chain, &call, Vec::new());
    let id = record.id;
    onbehalf_audit::AuditSink::append(state.audit.as_ref(), record)?;
    Ok(id)
}
