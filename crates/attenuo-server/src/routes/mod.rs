//! HTTP handlers, one module per concern.

pub mod admin;
pub mod approvals;
pub mod authzen;
pub mod dev_root;
pub mod extract;
pub mod ops;
pub mod page;
pub mod policies;
pub mod renew;
pub mod token;
pub mod wellknown;

use attenuo_audit::{HopLimit, LeaseRegistry, RunLimits};
use attenuo_core::{Decision, DecisionRecord, DelegationChain, LeaseId, RecordKind, ToolCall};
use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::{ApiError, REASON_INVALID_TOKEN};
use crate::metrics::TokenKind;
use crate::operators::AdminIdentity;
use crate::state::AppState;

/// Logical server name used in audit records for events the server itself performs.
pub const AUDIT_SERVER: &str = "attenuo";
/// Audit `reason` for a successful token issuance (root mint or exchange).
pub const REASON_TOKEN_ISSUED: &str = "token_issued";
/// Audit `reason` for a successful lease renewal.
pub const REASON_LEASE_RENEWED: &str = "lease_renewed";

/// The token from `Authorization: Bearer <token>` (or `DPoP <token>`, RFC 9449 §7.1),
/// `Ok(None)` when the header is absent, or an error when it is present but neither. The
/// parsing is [`attenuo_core::authorization::token_of`], shared with the proxy.
pub(crate) fn bearer_of(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw.to_str().map_err(|_| {
        ApiError::unauthorized(REASON_INVALID_TOKEN, "authorization header is not ASCII")
    })?;
    attenuo_core::authorization::token_of(raw)
        .map(Some)
        .ok_or_else(|| {
            ApiError::unauthorized(
                REASON_INVALID_TOKEN,
                "expected `Authorization: Bearer <token>`",
            )
        })
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

/// Register the lease of a token this server just minted, bind it to the token's chain, and
/// record the chain's originating user (`LeaseRegistry::record_subject`) so the lease can be
/// revoked by user.
///
/// The lease expiry is [`AppState::initial_lease_expiry`]. The binding is the digest of the
/// chain exactly as the signed token carries it (`LeaseRegistry::bind`), so an AuthZEN body chain
/// can later be matched against what was issued (SR-08).
pub(crate) fn register_issued(
    state: &AppState,
    token: &str,
    lease: &LeaseId,
    parent: Option<&LeaseId>,
    token_exp: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    let chain = state
        .verifier
        .verify(token, now)
        .map_err(|e| ApiError::internal(format!("cannot re-verify an issued token: {e}")))?
        .chain;
    state
        .leases
        .register(lease, parent, state.initial_lease_expiry(now, token_exp))?;
    state.leases.bind(lease, &chain.digest())?;
    // So that `POST /admin/leases/revoke` with `{"user": ...}` finds this lease, and the admin
    // lease tree finds the run's per-user windows (keyed by issuer and subject).
    state.leases.record_originating_user(
        lease,
        &chain.originating_user.issuer,
        &chain.originating_user.subject,
    )?;
    // Run limits (ADR-0010): keep the hop's limits as issued (after clamping), for the admin
    // console. Display only, so a failure is logged and the issuance stands.
    if let Some(hop) = chain.hops.last() {
        let limited: Vec<HopLimit> = hop
            .capabilities
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.limits.is_empty())
            .map(|(cap, c)| HopLimit {
                cap,
                server: c.server.clone(),
                tool: c.tool.clone(),
                limits: c.limits.clone(),
            })
            .collect();
        if !limited.is_empty() {
            if let Err(e) = state.leases.record_hop_limits(lease, &limited) {
                tracing::warn!(error = %e, lease = %lease.0, "could not keep the hop's limits for the console");
            }
        }
    }
    Ok(())
}

/// Prefix of subjects reserved for the server's own audit records. No user can have one:
/// IdP intake and the dev root mint refuse a subject that starts with it (SR-34).
pub const RESERVED_SUBJECT_PREFIX: &str = "urn:attenuo:";
/// `originating_subject` of audit records for actions taken with `[admin] token`, and the
/// prefix of the subjects of named operators (`urn:attenuo:admin:<name>`,
/// [`crate::operators::AdminIdentity::subject`]). It starts with [`RESERVED_SUBJECT_PREFIX`],
/// so no IdP user can produce records that look like admin actions (SR-34).
pub const ADMIN_SUBJECT: &str = "urn:attenuo:admin";
/// Audit `reason` of a successful admin action.
pub const REASON_ADMIN_ACTION: &str = "admin_action";

/// Is `subject` reserved for the server's own records ([`RESERVED_SUBJECT_PREFIX`])?
pub fn is_reserved_subject(subject: &str) -> bool {
    subject
        .get(..RESERVED_SUBJECT_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(RESERVED_SUBJECT_PREFIX))
}

/// Record an action taken by an admin credential (lease revocation, policy reload, dev root
/// mint) in the audit log (SR-15).
///
/// There is no delegation chain behind an admin request, so the record names
/// `originating_subject` = the operator's subject ([`AdminIdentity::subject`]:
/// `urn:attenuo:admin` for `[admin] token`, `urn:attenuo:admin:<name>` for a named operator),
/// no agents, depth 0 and
/// the chain digest of nothing (`sha256` of JSON `null`). `leases` holds the leases the action
/// touched, `server` is `attenuo` and `tool` is `admin.<action>`; the arguments are stored as
/// a digest as usual.
#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_admin(
    state: &AppState,
    actor: &AdminIdentity,
    tool: &str,
    decision: Decision,
    reason: &str,
    leases: Vec<LeaseId>,
    arguments: Value,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, ApiError> {
    let call = ToolCall::new(AUDIT_SERVER, tool, arguments);
    let record = DecisionRecord {
        id: uuid::Uuid::new_v4(),
        at: now,
        kind: if tool == "admin.lease.revoke" {
            RecordKind::LeaseRevoke
        } else {
            RecordKind::Admin
        },
        chain_id: None,
        decision,
        reason: reason.to_string(),
        originating_subject: actor.subject(),
        agents: Vec::new(),
        chain_depth: 0,
        chain_digest: attenuo_core::digest::sha256_json(&Value::Null),
        leases,
        server: AUDIT_SERVER.to_string(),
        tool: call.tool.clone(),
        arguments_digest: call.arguments_digest(),
        session_id: None,
        policy_ids: Vec::new(),
        dpop_bound: false,
        decision_id: None,
        result: None,
        labels: None,
        approval: None,
        budget: None,
        usage: None,
        search: None,
        id_jag_ceiling: None,
    };
    let id = record.id;
    state
        .metrics
        .time_audit_append(|| attenuo_audit::AuditSink::append(state.audit.as_ref(), record))?;
    Ok(id)
}

/// Record a token issuance in the audit log.
///
/// The audit log stores decision records only, so an issuance is written as an `allow` with
/// reason `token_issued`, server `attenuo` and tool `token.exchange` (or `token.root` for a
/// dev root mint). The chain is the *new* chain, so the record names the new hop's agent and
/// lease; the arguments (actor, requested capabilities) are stored as a digest like any call.
/// `dpop_bound` records whether the new token is bound to a key (SR-24).
pub(crate) fn audit_issuance(
    state: &AppState,
    tool: &str,
    chain: &DelegationChain,
    arguments: Value,
    dpop_bound: bool,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, ApiError> {
    audit_issuance_with(state, tool, chain, arguments, dpop_bound, None, now)
}

/// [`audit_issuance`], with the record's `id_jag_ceiling` member for a root token minted
/// under `[idps.id_jag_ceiling]` (SR-126). `None` gives exactly the record of
/// [`audit_issuance`].
pub(crate) fn audit_issuance_with(
    state: &AppState,
    tool: &str,
    chain: &DelegationChain,
    arguments: Value,
    dpop_bound: bool,
    ceiling: Option<attenuo_core::CeilingInfo>,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, ApiError> {
    let kind = if tool == "token.root" {
        RecordKind::RootToken
    } else {
        RecordKind::Exchange
    };
    let mut record = event_record(kind, tool, chain, arguments, dpop_bound, now);
    record.id_jag_ceiling = ceiling;
    let id = append_audit(state, record)?;
    state.metrics.token_issued(if tool == "token.root" {
        TokenKind::Root
    } else {
        TokenKind::Exchange
    });
    Ok(id)
}

/// Record a server-performed event (issuance, lease renewal) as an `allow` decision record
/// (reason `token_issued`, or `lease_renewed` for a renewal), server `attenuo` and `tool` naming the event, and the record's
/// `dpop_bound` flag.
pub(crate) fn audit_event(
    state: &AppState,
    kind: RecordKind,
    tool: &str,
    chain: &DelegationChain,
    arguments: Value,
    dpop_bound: bool,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, ApiError> {
    append_audit(
        state,
        event_record(kind, tool, chain, arguments, dpop_bound, now),
    )
}

/// The record [`audit_event`] appends.
fn event_record(
    kind: RecordKind,
    tool: &str,
    chain: &DelegationChain,
    arguments: Value,
    dpop_bound: bool,
    now: OffsetDateTime,
) -> DecisionRecord {
    let reason = match kind {
        RecordKind::LeaseRenew => REASON_LEASE_RENEWED,
        _ => REASON_TOKEN_ISSUED,
    };
    let call = ToolCall::new(AUDIT_SERVER, tool, arguments).with_dpop_bound(dpop_bound);
    DecisionRecord::new(now, Decision::Allow, reason, chain, &call, Vec::new()).with_kind(kind)
}

/// Append `record` to the audit log, timed (`audit_append_seconds`), and count a failure
/// (`audit_append_errors_total`). A failure is the caller's error: the action it records
/// must not happen, or be answered, without its record (fail closed).
pub(crate) fn append_audit(
    state: &AppState,
    record: DecisionRecord,
) -> Result<uuid::Uuid, ApiError> {
    let id = record.id;
    if let Err(e) = state
        .metrics
        .time_audit_append(|| attenuo_audit::AuditSink::append(state.audit.as_ref(), record))
    {
        state.metrics.audit_append_error();
        return Err(e.into());
    }
    Ok(id)
}
