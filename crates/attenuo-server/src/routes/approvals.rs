//! Approvals of calls gated by `@obligation("approval")` (output labelling, ADR-0009).
//!
//! A gated call gets JSON-RPC `-32008` with an `approval_id`. The approval is decided through
//! a channel the agent does not control:
//!
//! | Route | Auth | Purpose |
//! |---|---|---|
//! | `POST /approvals/{id}` | an ID token of the run's originating user, from a trusted `[[idps]]` | grant or decline (`by = "user"`) |
//! | `GET /approvals/{id}` | that user's ID token, or a delegation token of the same run with live leases | the exact call, labels (and matched arguments, `untrusted_args`), state and expiry |
//! | `POST /admin/approvals/{id}` | admin bearer | grant or decline as an operator (`by = "operator"`) |
//! | `GET /admin/approvals/{id}`, `GET /admin/approvals?chain_id=` | admin bearer | one approval; the newest approvals of a run (console, CLI) |
//!
//! The ID token is checked as hop-0 intake checks it (signature, `iss`, `aud`/`azp` bound to
//! the run's root agent's client id or to `[approvals] client_id`, expiry), its `sub` and
//! `iss` must equal the chain's originating user, and it is used once: the replay cache that
//! makes intake credentials single use also refuses an ID token already presented, so the
//! credential an agent redeemed at hop 0 cannot approve that agent's calls. A delegation
//! token is never accepted for `POST`. `GET` with an ID token does not use the token up.
//!
//! **Approval token.** While an approval is granted and unexpired, every answer about it here
//! (the grant itself and both `GET`s) also carries `approval_token`: a JWT with header
//! `typ: attenuo-approval+jwt`, signed with the issuer key that signs delegation tokens (same
//! `kid`, same JWKS), whose claims (`iss`, `aud`, `sub` = the approver, `by`, `chain_id`,
//! `lease`, `ch` = the call hash, `iat` = when it was granted, `exp` = `expires_at`, `jti` =
//! the approval id, and `cnf.jkt` when the calling hop's token is DPoP-bound) all come from
//! the stored approval, so every answer carries the same token
//! ([`attenuo_token::approval`]). The agent may retry with it in
//! `params._meta["dev.attenuo/approval"]` (AuthZEN: `context.approval_token`) instead of
//! relying on the identical-retry lookup; the stored approval still makes it single use.
//!
//! The store change and the audit record go together: a grant or decline is written to the
//! lease store first (which checks the approval is pending and unexpired and its lease live,
//! in one transaction), then an `approval_grant` record is appended. If the append fails, the
//! approval is deleted, so no grant exists that the log does not show; the agent's next retry
//! asks again.

use std::sync::Arc;

use attenuo_audit::{Approval, ApprovalMethod, ApprovalState, Approver, AuditError, LeaseStore};
use attenuo_core::{
    ApprovalInfo, Decision, DecisionRecord, LeaseId, RecordKind, ToolCall,
    REASON_APPROVAL_DECLINED, REASON_APPROVAL_GRANTED,
};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{bearer_of, parse_json, ADMIN_SUBJECT};
use crate::error::{ApiError, REASON_MISSING_TOKEN};
use crate::state::AppState;

/// Most approvals `GET /admin/approvals` returns.
pub const MAX_LIST: usize = 500;

/// Body of a decision: `{"decision": "grant" | "decline"}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideBody {
    /// `grant` or `decline`; anything else is a 400 `invalid_request`.
    pub decision: String,
}

impl DecideBody {
    fn grant(&self) -> Result<bool, ApiError> {
        match self.decision.as_str() {
            "grant" => Ok(true),
            "decline" => Ok(false),
            _ => Err(ApiError::bad_request(
                "invalid_request",
                "decision must be \"grant\" or \"decline\"",
            )),
        }
    }
}

/// Query of `GET /admin/approvals`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Only the approvals of this delegation run.
    pub chain_id: Option<String>,
    /// Only approvals in this state (`pending`, `granted`, `declined`, `consumed`).
    pub state: Option<String>,
    /// At most this many (default and maximum [`MAX_LIST`]).
    pub limit: Option<usize>,
}

fn fmt(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// The JSON form of an approval, as every route here returns it.
pub fn approval_json(a: &Approval, now: OffsetDateTime) -> Value {
    let mut v = json!({
        "approval_id": a.id,
        "state": a.state.as_str(),
        "expired": a.is_expired(now),
        "chain_id": a.chain_id,
        "lease": a.lease,
        "call_hash": a.call_hash,
        "call": { "server": a.server, "tool": a.tool, "arguments": a.arguments },
        "labels": a.labels,
        "decision_id": a.decision_id,
        "subject": a.chain.originating_user.subject,
        "issuer": a.chain.originating_user.issuer,
        "agents": a.chain.hops.iter().map(|h| h.agent.0.as_str()).collect::<Vec<_>>(),
        "created_at": fmt(a.created_at),
        "expires_at": fmt(a.expires_at),
    });
    if let Some(p) = &a.approver {
        v["approver"] = json!({
            "subject": p.subject,
            "method": p.method.as_str(),
            "by": p.method.by(),
        });
    }
    if let Some(t) = a.decided_at {
        v["decided_at"] = json!(fmt(t));
    }
    if let Some(d) = &a.consumed_by {
        v["consumed_by"] = json!(d);
    }
    // The arguments that matched an untrusted result (ADR-0009 phase 2), when any did.
    if !a.untrusted_args.is_empty() {
        v["untrusted_args"] = crate::authz::untrusted_args_json(&a.untrusted_args);
    }
    v
}

/// The approval token for `a` (see the module docs), or `None` unless `a` is granted and
/// unexpired at `now`.
pub fn approval_token(
    issuer: &attenuo_token::Issuer,
    a: &Approval,
    now: OffsetDateTime,
) -> Option<String> {
    if a.state != ApprovalState::Granted || a.is_expired(now) {
        return None;
    }
    let approver = a.approver.as_ref()?;
    let grant = attenuo_token::ApprovalGrant {
        approval_id: &a.id,
        approver: &approver.subject,
        by: approver.method.by(),
        chain_id: &a.chain_id.0,
        lease: &a.lease.0,
        call_hash: &a.call_hash,
        granted_at: a.decided_at.unwrap_or(a.created_at),
        expires_at: a.expires_at,
        jkt: a.jkt.as_deref(),
    };
    match issuer.issue_approval(&grant) {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::error!(error = %e, approval = %a.id, "approval token could not be signed");
            None
        }
    }
}

/// [`approval_json`] plus `approval_token` while the approval is granted and unexpired.
fn approval_body(state: &AppState, a: &Approval, now: OffsetDateTime) -> Value {
    let mut v = approval_json(a, now);
    if let Some(t) = approval_token(&state.issuer, a, now) {
        v["approval_token"] = json!(t);
    }
    v
}

/// The 404 for an approval that is not stored, or that this caller may not learn exists: the
/// same answer as the store's [`AuditError::UnknownApproval`], from the central mapping.
fn unknown_approval(id: &str) -> ApiError {
    AuditError::UnknownApproval(id.to_owned()).into()
}

fn load(state: &AppState, id: &str) -> Result<Approval, ApiError> {
    state
        .leases
        .approval(id)?
        .ok_or_else(|| unknown_approval(id))
}

/// Grant or decline `id` as `approver`, then record it. See the module docs for the order.
fn decide(
    state: &AppState,
    id: &str,
    grant: bool,
    approver: Approver,
    now: OffsetDateTime,
) -> Result<Approval, ApiError> {
    let a = state
        .leases
        .decide_approval(id, grant, &approver, now)
        .map_err(|e| {
            if matches!(e, AuditError::ApprovalExpired(_)) {
                state.metrics.approval_expired();
            }
            ApiError::from(e)
        })?;
    let call = ToolCall::new(a.server.clone(), a.tool.clone(), a.arguments.clone());
    let (decision, reason) = if grant {
        (Decision::Allow, REASON_APPROVAL_GRANTED)
    } else {
        (Decision::Deny, REASON_APPROVAL_DECLINED)
    };
    let mut record = DecisionRecord::new(now, decision, reason, &a.chain, &call, Vec::new())
        .with_kind(RecordKind::ApprovalGrant);
    record.decision_id = uuid::Uuid::parse_str(&a.decision_id).ok();
    let approval_id = uuid::Uuid::parse_str(&a.id).map_err(ApiError::internal)?;
    let mut info = ApprovalInfo::new(approval_id);
    info.by = Some(approver.method.by().to_string());
    info.call_hash = Some(a.call_hash.clone());
    info.expires_at = Some(a.expires_at);
    info.approver = Some(approver.subject.clone());
    info.method = Some(approver.method.as_str().to_string());
    info.outcome = Some(if grant { "grant" } else { "decline" }.to_string());
    record.approval = Some(info);
    if let Err(e) = state
        .metrics
        .time_audit_append(|| attenuo_audit::AuditSink::append(state.audit.as_ref(), record))
    {
        state.metrics.audit_append_error();
        // No grant the log does not show: drop the approval; the agent's retry asks again.
        let _ = state.leases.remove_approval(&a.id);
        return Err(ApiError::internal(format!(
            "approval decision could not be recorded: {e}"
        )));
    }
    state.metrics.approval_decided(grant, approver.method.by());
    if let Some(n) = &state.approval_notifier {
        // Only queues: the answer does not wait for the webhook.
        n.handle().decided(&a);
    }
    // Subject and tool come from the request and the agent: Debug-format them (SR-18).
    tracing::info!(
        approval = %a.id,
        outcome = if grant { "grant" } else { "decline" },
        by = approver.method.by(),
        approver = ?approver.subject,
        tool = ?a.tool,
        "approval decided"
    );
    Ok(a)
}

/// The bearer of a request, required.
fn required_bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    bearer_of(headers)?
        .ok_or_else(|| ApiError::unauthorized(REASON_MISSING_TOKEN, "a bearer token is required"))
}

/// Is `token` one of this server's delegation tokens (by its unverified `iss`)?
fn is_delegation_token(state: &AppState, token: &str) -> bool {
    crate::idp::unverified_issuer(token).as_deref() == Some(state.issuer.config().issuer.as_str())
}

/// Check that `id_token` is an ID token of the originating user of `a`'s run. Returns the
/// verified assertion; does not use the token up.
async fn verify_user(
    state: &AppState,
    a: &Approval,
    id_token: &str,
    now: OffsetDateTime,
) -> Result<crate::idp::VerifiedAssertion, ApiError> {
    let root_agent = a
        .chain
        .hops
        .first()
        .map(|h| h.agent.0.clone())
        .unwrap_or_default();
    let verified = state
        .idps
        .verify_approval(
            id_token,
            state.approvals_client_id.as_deref(),
            &root_agent,
            now,
        )
        .await
        .map_err(|e| {
            // Only the stable sub-code is returned; the verifier's text (an audience, a `kid`)
            // is logged at debug level (SR-17).
            let d = e.description();
            tracing::debug!(reason = d, detail = ?e.to_string(), "approval ID token refused");
            ApiError::new(StatusCode::UNAUTHORIZED, "invalid_token", d).with_description(d)
        })?;
    let user = &a.chain.originating_user;
    if verified.subject != user.subject || verified.issuer != user.issuer {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "wrong_user",
            "the ID token is not the originating user's of this delegation run",
        ));
    }
    Ok(verified)
}

/// `POST /approvals/{id}` with `Authorization: Bearer <ID token>` and
/// `{"decision": "grant" | "decline"}`: the originating user decides.
///
/// # Errors
///
/// 400 `invalid_request` when the body is not JSON or its `decision` is neither `grant` nor
/// `decline`; 401 `unauthorized` when no bearer token is sent, and 401 `invalid_token` when the ID
/// token does not verify; 403 `agent_token_refused` for a delegation token and 403 `wrong_user` for
/// another user's ID token; 400 `invalid_grant` (`replayed`) for an ID token already used, and 503
/// when the replay cache is full; 404 `not_found` for an unknown approval; 409
/// `approval_not_pending`, `approval_expired` or `lease_revoked` when it cannot be decided; 500
/// `server_error` when the store fails or the decision cannot be audited (the decision is then
/// dropped).
pub async fn user_decide(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let body: DecideBody = parse_json(&body)?;
    let grant = body.grant()?;
    let token = required_bearer(&headers)?.to_owned();
    if is_delegation_token(&state, &token) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "agent_token_refused",
            "approvals are not accepted with a delegation token; present the user's ID token",
        ));
    }
    let now = state.now();
    let id2 = id.clone();
    let a = state.blocking(move |s| load(s, &id2)).await?;
    let verified = verify_user(&state, &a, &token, now).await?;
    let replay_key = verified.replay_key(&token);
    let replay_until = verified
        .expires_at
        .saturating_add(i64::try_from(verified.clock_skew_seconds).unwrap_or(i64::MAX));
    let approver = Approver {
        subject: verified.subject.clone(),
        method: ApprovalMethod::IdToken,
    };
    let a = state
        .blocking(move |s| {
            // Used once, like an intake credential: a token the agent saw cannot approve.
            s.replay.use_once(&replay_key, replay_until, now)?;
            decide(s, &id, grant, approver, now)
        })
        .await?;
    Ok(Json(approval_body(&state, &a, now)))
}

/// `GET /approvals/{id}`: the approval, for its originating user (ID token, not used up) or
/// for an agent of the same delegation run (its delegation token, with a DPoP proof when the
/// token is bound). Anyone else gets 404, as for an unknown approval.
///
/// # Errors
///
/// 401 `unauthorized` when no bearer token is sent or a delegation token does not verify
/// (`invalid_token` or `token_expired`), or when an ID token does not verify; 401 with a DPoP code
/// when a bound delegation token comes without a valid proof; 403 `wrong_user` for another user's
/// ID token; 404 `not_found` for an unknown approval and for a delegation token of another run or
/// with a dead lease; 500 `server_error` when the store fails.
pub async fn user_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let token = required_bearer(&headers)?.to_owned();
    let now = state.now();
    let id2 = id.clone();
    let a = state.blocking(move |s| load(s, &id2)).await?;
    if is_delegation_token(&state, &token) {
        let verified = state
            .verifier
            .verify(&token, now)
            .map_err(|e| ApiError::bad_token(&e))?;
        state.dpop.check_presented(
            verified.claims.cnf.as_ref(),
            &token,
            crate::dpop::header_proof(&headers)?,
            "GET",
            &state
                .dpop
                .expected_url_for(&headers, &format!("/approvals/{id}")),
            now,
        )?;
        if attenuo_core::chain_id_of(&verified.chain).as_deref() != Some(a.chain_id.0.as_str()) {
            // Not this run's: do not confirm the approval exists.
            return Err(unknown_approval(&id));
        }
        // A token whose lease (or an ancestor's) was revoked or has expired speaks for no
        // agent any more, though its signature still verifies (SR-60): answer it as one of
        // another run.
        let chain = verified.chain.clone();
        let live = state
            .blocking(move |s| s.leases.check_all(&chain.leases(), now).map(|st| st.active))
            .await?;
        if !live {
            return Err(unknown_approval(&id));
        }
    } else {
        verify_user(&state, &a, &token, now).await?;
    }
    Ok(Json(approval_body(&state, &a, now)))
}

/// `POST /admin/approvals/{id}` with `{"decision": "grant" | "decline"}`: an operator decides
/// (`by = "operator"`, approver `urn:attenuo:admin`).
///
/// # Errors
///
/// 400 `invalid_request` when the body is not JSON or its `decision` is neither `grant` nor
/// `decline`; 404 `not_found` for an unknown approval; 409 `approval_not_pending`,
/// `approval_expired` or `lease_revoked` when it cannot be decided; 500 `server_error` when the
/// store fails or the decision cannot be audited (the decision is then dropped).
pub async fn admin_decide(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let body: DecideBody = parse_json(&body)?;
    let grant = body.grant()?;
    let now = state.now();
    state
        .blocking(move |s| {
            let approver = Approver {
                subject: ADMIN_SUBJECT.to_string(),
                method: ApprovalMethod::AdminToken,
            };
            let a = decide(s, &id, grant, approver, now)?;
            Ok(Json(approval_body(s, &a, now)))
        })
        .await
}

/// `GET /admin/approvals/{id}`.
///
/// # Errors
///
/// 404 `not_found` for an unknown approval, and 500 `server_error` when the store fails.
pub async fn admin_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let now = state.now();
    state
        .blocking(move |s| Ok(Json(approval_body(s, &load(s, &id)?, now))))
        .await
}

/// `GET /admin/approvals?chain_id=&state=&limit=`: the newest approvals, of one run when
/// `chain_id` is given.
///
/// # Errors
///
/// 400 `invalid_request` for an unknown `state`, and 500 `server_error` when the store fails.
pub async fn admin_list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let want = match q.state.as_deref() {
        None | Some("") => None,
        Some(s) => Some(
            attenuo_audit::ApprovalState::parse(s)
                .map_err(|_| ApiError::bad_request("invalid_request", "unknown state"))?,
        ),
    };
    let limit = q.limit.unwrap_or(MAX_LIST).clamp(1, MAX_LIST);
    let now = state.now();
    state
        .blocking(move |s| {
            let chain = q.chain_id.filter(|c| !c.is_empty()).map(LeaseId::new);
            // A state filter is applied after the store's limit; ask for the most it gives.
            let fetch = if want.is_some() { MAX_LIST } else { limit };
            let approvals: Vec<Value> = s
                .leases
                .approvals(chain.as_ref(), fetch)?
                .iter()
                .filter(|a| want.is_none_or(|w| a.state == w))
                .take(limit)
                .map(|a| approval_json(a, now))
                .collect();
            Ok(Json(json!({ "approvals": approvals })))
        })
        .await
}
