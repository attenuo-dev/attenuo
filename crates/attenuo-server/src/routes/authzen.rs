//! `POST /access/v1/evaluation`: OpenID AuthZEN evaluation, served by the same [`Pipeline`]
//! as the proxy.
//!
//! Where the chain comes from:
//!
//! - **Default: the bearer.** The request must carry `Authorization: Bearer <delegation
//!   token>`. The token is verified and its chain is used. If the body also carries
//!   `subject.properties.chain`, it must equal the token's chain. An empty `subject.id` is
//!   filled with the chain's current agent. Without a bearer the answer is 401. A token
//!   bound to a key (`cnf.jkt`) needs a DPoP proof for this request ([`crate::dpop`]), made
//!   once per HTTP request (a batch's entries share it); `Authorization: DPoP <token>` is
//!   accepted as well.
//! - **Opt-in: an unsigned body chain from an authenticated PEP.** Only with
//!   `[authzen] allow_unsigned_chain = true`. The caller must authenticate as a `[[peps]]` entry
//!   (HTTP Basic, or `pep_id` and `pep_secret` in the body; 401 `invalid_client` otherwise), and
//!   `subject.properties.chain` is then checked structurally (`validate_at`) and hop by hop
//!   against what this server issued: each hop's lease must carry a binding equal to the digest
//!   of the chain up to that hop (`LeaseStore::bind`). A chain that does not match (a forged
//!   user, widened attributes, a lease reused on another hop) is refused with 403
//!   `chain_not_issued` *before* any audit record is written, so it cannot put records in a
//!   victim's name. Lease ids alone are not secret (they are in every token), which is why they
//!   are not enough (SR-08).
//!
//! The response is the AuthZEN `{decision, context}` with `context.reason`,
//! `context.policy_ids`, `context.diagnostics` and `context.decision_id` (the audit record).
//! `context.diagnostics` (effective capabilities, lease ids, Cedar errors) is empty unless
//! `[authzen] diagnostics` allows the caller: by default only a caller that authenticated as a
//! `[[peps]]` entry gets it. With a bearer token, a PEP authenticates with `pep_id` and
//! `pep_secret` in the body (SR-17).
//!
//! [`Pipeline`]: crate::authz::Pipeline

use std::sync::Arc;

use attenuo_audit::LeaseStore;
use attenuo_core::DelegationChain;
use attenuo_policy::authzen::{self, EvaluationRequest, EvaluationResponse};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::{now, parse_json};
use crate::clientauth::{self, ClientKind};
use crate::error::{ApiError, REASON_INVALID_TOKEN, REASON_MISSING_TOKEN};
use crate::state::AppState;

/// Error code when a body chain does not match what this server issued.
pub const CHAIN_NOT_ISSUED: &str = "chain_not_issued";

// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
pub async fn evaluation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<EvaluationResponse>, Response> {
    // Token checks, lease lookups and the audit append all touch SQLite; keep them off the
    // async workers.
    state
        .blocking(move |s| evaluate(s, &headers, &body))
        .await
        .map(Json)
        .map_err(|e| with_challenge(e.into_response()))
}

/// `POST /access/v1/evaluations`: the AuthZEN "boxcar" form. Top-level `subject`, `action`,
/// `resource` and `context` are defaults; each entry of `evaluations` may replace any of them.
/// Every entry is decided and audited exactly like a single evaluation, in order.
///
/// At most `[authzen] max_batch` entries (400 `batch_too_large` beyond that, 400
/// `invalid_request` for none). Only the default `execute_all` semantic is supported. An
/// authentication failure refuses the whole request; any other per-entry failure answers
/// `decision: false` with `context.error` for that entry.
// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
pub async fn evaluations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, Response> {
    state
        .blocking(move |s| evaluate_batch(s, &headers, &body))
        .await
        .map(Json)
        .map_err(|e| with_challenge(e.into_response()))
}

/// Error code when a batch carries more evaluations than `[authzen] max_batch`.
pub const BATCH_TOO_LARGE: &str = "batch_too_large";

fn evaluate_batch(state: &AppState, headers: &HeaderMap, body: &Bytes) -> Result<Value, ApiError> {
    let mut raw: Value = parse_json(body)?;
    let Some(obj) = raw.as_object_mut() else {
        return Err(ApiError::bad_request(
            "invalid_request",
            "expected a JSON object",
        ));
    };
    let items = match obj.remove("evaluations") {
        Some(Value::Array(items)) => items,
        _ => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "`evaluations` must be an array",
            ))
        }
    };
    if items.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`evaluations` must not be empty",
        ));
    }
    // Refuse before any evaluation runs, so an oversized batch writes nothing to the audit log.
    if items.len() > state.authzen_max_batch {
        return Err(ApiError::bad_request(
            BATCH_TOO_LARGE,
            format!(
                "{} evaluations exceed [authzen] max_batch = {}",
                items.len(),
                state.authzen_max_batch
            ),
        ));
    }
    if let Some(sem) = obj
        .get("options")
        .and_then(|o| o.get("evaluations_semantic"))
        .and_then(Value::as_str)
    {
        if sem != "execute_all" {
            return Err(ApiError::bad_request(
                "invalid_request",
                format!("evaluations_semantic `{sem}` is not supported; use `execute_all`"),
            ));
        }
    }
    obj.remove("options");
    let bearer = bearer_auth(state, headers, "/access/v1/evaluations")?;

    let mut results = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(item) = item else {
            results.push(item_error(&ApiError::bad_request(
                "invalid_request",
                "each evaluation must be an object",
            )));
            continue;
        };
        let mut merged = obj.clone();
        for (k, v) in item {
            merged.insert(k, v);
        }
        match evaluate_value(state, headers, bearer.as_ref(), Value::Object(merged)) {
            Ok(r) => results.push(serde_json::to_value(r).map_err(ApiError::internal)?),
            Err(e) if matches!(e.status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
                return Err(e)
            }
            Err(e) => results.push(item_error(&e)),
        }
    }
    Ok(json!({ "evaluations": results }))
}

fn item_error(e: &ApiError) -> Value {
    json!({
        "decision": false,
        "context": { "error": { "status": e.status.as_u16(), "code": e.code, "message": e.detail } },
    })
}

fn with_challenge(mut resp: Response) -> Response {
    if resp.status() == StatusCode::UNAUTHORIZED
        && !resp.headers().contains_key(header::WWW_AUTHENTICATE)
    {
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"attenuo\""),
        );
    }
    resp
}

/// The `Authorization` header split into its scheme and value.
fn authorization(headers: &HeaderMap) -> Result<Option<(String, &str)>, ApiError> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw.to_str().map_err(|_| {
        ApiError::unauthorized(REASON_INVALID_TOKEN, "authorization header is not ASCII")
    })?;
    match raw.split_once(' ') {
        Some((scheme, value)) if !value.trim().is_empty() => {
            Ok(Some((scheme.to_ascii_lowercase(), value.trim())))
        }
        _ => Err(ApiError::unauthorized(
            REASON_INVALID_TOKEN,
            "expected `Authorization: Bearer <token>`",
        )),
    }
}

fn evaluate(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<EvaluationResponse, ApiError> {
    let value = parse_json(body)?;
    let bearer = bearer_auth(state, headers, "/access/v1/evaluation")?;
    evaluate_value(state, headers, bearer.as_ref(), value)
}

/// The bearer's chain and DPoP binding, checked once per HTTP request: a batch's entries share
/// it, and a DPoP proof can be used only once.
struct Bearer {
    chain: DelegationChain,
    dpop_bound: bool,
}

/// Verify the `Authorization: Bearer` (or `DPoP`) token and its DPoP proof, if the request has
/// one. `Ok(None)` without a bearer (no header, or HTTP Basic for a PEP).
fn bearer_auth(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<Option<Bearer>, ApiError> {
    let auth = authorization(headers)?;
    let token = match &auth {
        Some((scheme, token)) if scheme == "bearer" || scheme == "dpop" => *token,
        Some((scheme, _)) if scheme == "basic" => return Ok(None),
        Some(_) => {
            return Err(ApiError::unauthorized(
                REASON_INVALID_TOKEN,
                "expected `Authorization: Bearer <token>`",
            ))
        }
        None => return Ok(None),
    };
    let now = now();
    let v = state
        .verifier
        .verify(token, now)
        .map_err(|e| ApiError::bad_token(&e))?;
    let dpop_bound = state.dpop.check_presented(
        v.claims.cnf.as_ref(),
        token,
        crate::dpop::header_proof(headers)?,
        "POST",
        &state.dpop.expected_url_for(headers, path),
        now,
    )?;
    Ok(Some(Bearer {
        chain: v.chain,
        dpop_bound,
    }))
}

fn evaluate_value(
    state: &AppState,
    headers: &HeaderMap,
    bearer: Option<&Bearer>,
    raw: Value,
) -> Result<EvaluationResponse, ApiError> {
    let pep_field = |k: &str| raw.get(k).and_then(Value::as_str).map(str::to_owned);
    let (pep_id, pep_secret) = (pep_field("pep_id"), pep_field("pep_secret"));
    let mut req: EvaluationRequest = serde_json::from_value(raw)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    let now = now();

    // `body_chain_pep`: the PEP whose unsigned body chain is used. `pep_authenticated`: the
    // caller proved it is a `[[peps]]` entry, which decides whether it sees diagnostics.
    let (body_chain_pep, pep_authenticated) = match bearer {
        Some(b) => {
            attach_chain(&mut req, &b.chain)?;
            // A PEP forwarding an agent's token may authenticate itself in the body (the
            // `Authorization` header holds the bearer) to receive diagnostics.
            let pep = match pep_secret.as_deref() {
                Some(secret) => Some(clientauth::authenticate(
                    ClientKind::Pep,
                    &state.peps,
                    headers,
                    pep_id.as_deref(),
                    Some(secret),
                )?),
                None => None,
            };
            (None, pep.is_some())
        }
        None => {
            if !state.authzen_allow_unsigned_chain {
                return Err(ApiError::unauthorized(
                    REASON_MISSING_TOKEN,
                    "a delegation token is required: send `Authorization: Bearer <token>` \
                     ([authzen] allow_unsigned_chain is off)",
                ));
            }
            let id = clientauth::authenticate(
                ClientKind::Pep,
                &state.peps,
                headers,
                pep_id.as_deref(),
                pep_secret.as_deref(),
            )?;
            (Some(id), true)
        }
    };

    let (chain_value, call) = authzen::to_chain_and_call(&req)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    if let Some(pep) = body_chain_pep {
        chain_value
            .validate_at(now, state.verifier.max_depth())
            .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
        check_issued(state, &chain_value).map_err(|detail| {
            tracing::warn!(pep = ?pep, detail = ?detail, "AuthZEN body chain was not issued here");
            ApiError::new(StatusCode::FORBIDDEN, CHAIN_NOT_ISSUED, detail)
        })?;
        tracing::debug!(pep = ?pep, "AuthZEN body chain accepted from an authenticated PEP");
    }
    let call = call.with_dpop_bound(bearer.is_some_and(|b| b.dpop_bound));
    let mut d = state.pipeline.decide(&chain_value, &call, now);
    let allow = d.is_allow();
    // Diagnostics name effective capabilities, lease ids and Cedar errors: reconnaissance for
    // anyone holding a token. Only PEPs get them unless configured otherwise (SR-17).
    let diagnostics = if state.authzen_diagnostics.allows(pep_authenticated) {
        std::mem::take(&mut d.diagnostics)
    } else {
        Vec::new()
    };
    let mut context = json!({
        "reason": d.reason,
        "policy_ids": d.policy_ids,
        "diagnostics": diagnostics,
        "decision_id": d.decision_id,
    });
    if d.reason == attenuo_policy::REASON_APPROVAL_REQUIRED {
        // What an approval is bound to (ADR-0009), as the proxy's `-32008` carries it.
        context["call_hash"] = json!(call.call_hash());
        if let Some(a) = &d.approval {
            context["approval_id"] = json!(a.approval_id);
            context["expires_at"] = json!(a
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default());
        }
    }
    if let Some((id, by)) = &d.consumed_approval {
        context["approval"] = json!({ "id": id, "by": by });
    }
    // Run limits (ADR-0010): an evaluation is charged as a proxied call is. Only when a limit
    // matched, so answers about unlimited calls are unchanged.
    if d.budget.limited {
        context["budget"] = crate::authz::budget_json(&d.budget);
    }
    if let Some(hit) = &d.limit {
        context["limit"] = hit.to_json();
    }
    if let Some(charged) = &d.charged {
        context["charged"] = json!(charged.charged);
    }
    Ok(EvaluationResponse {
        decision: allow,
        context: Some(context),
    })
}

/// Every hop's lease must be bound to the digest of the chain up to that hop.
fn check_issued(state: &AppState, chain: &DelegationChain) -> Result<(), String> {
    for (i, hop) in chain.hops.iter().enumerate() {
        let expected = chain
            .prefix_digest(i)
            .ok_or_else(|| format!("hop {i} is out of range"))?;
        let bound = state
            .leases
            .binding(&hop.lease)
            .map_err(|e| format!("lease registry error: {e}"))?;
        if bound.as_deref() != Some(expected.as_str()) {
            return Err(format!(
                "hop {i} does not match the chain this server issued for its lease"
            ));
        }
    }
    Ok(())
}

/// Put the verified chain into `subject.properties.chain`, or check the one already there.
pub(crate) fn attach_chain(
    req: &mut EvaluationRequest,
    chain: &DelegationChain,
) -> Result<(), ApiError> {
    if req.subject.id.is_empty() {
        req.subject.id = chain
            .current_agent()
            .map(|a| a.0.clone())
            .unwrap_or_default();
    }
    let props = req
        .subject
        .properties
        .get_or_insert_with(|| Value::Object(Default::default()));
    let Some(obj) = props.as_object_mut() else {
        return Err(ApiError::bad_request(
            "invalid_request",
            "subject.properties must be an object",
        ));
    };
    match obj.get("chain") {
        None => {
            let v = serde_json::to_value(chain).map_err(ApiError::internal)?;
            obj.insert("chain".into(), v);
        }
        Some(given) => {
            let given: DelegationChain = serde_json::from_value(given.clone()).map_err(|e| {
                ApiError::bad_request("invalid_request", format!("subject.properties.chain: {e}"))
            })?;
            if &given != chain {
                return Err(ApiError::bad_request(
                    "chain_mismatch",
                    "subject.properties.chain differs from the bearer token's chain",
                ));
            }
        }
    }
    Ok(())
}
