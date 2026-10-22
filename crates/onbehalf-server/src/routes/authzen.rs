//! `POST /access/v1/evaluation`: OpenID AuthZEN evaluation, served by the same [`Pipeline`]
//! as the proxy.
//!
//! Where the chain comes from:
//!
//! - **Default: the bearer.** The request must carry `Authorization: Bearer <delegation
//!   token>`. The token is verified and its chain is used. If the body also carries
//!   `subject.properties.chain`, it must equal the token's chain. An empty `subject.id` is
//!   filled with the chain's current agent. Without a bearer the answer is 401.
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
//!
//! [`Pipeline`]: crate::authz::Pipeline

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::LeaseStore;
use onbehalf_core::DelegationChain;
use onbehalf_policy::authzen::{self, EvaluationRequest, EvaluationResponse};
use serde_json::{json, Value};

use super::{now, parse_json};
use crate::clientauth::{self, ClientKind};
use crate::error::ApiError;
use crate::state::AppState;

/// Error code when a body chain does not match what this server issued.
pub const CHAIN_NOT_ISSUED: &str = "chain_not_issued";

pub async fn evaluation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<EvaluationResponse>, Response> {
    evaluate(&state, &headers, &body)
        .map(Json)
        .map_err(|e| with_challenge(e.into_response()))
}

fn with_challenge(mut resp: Response) -> Response {
    if resp.status() == StatusCode::UNAUTHORIZED
        && !resp.headers().contains_key(header::WWW_AUTHENTICATE)
    {
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"onbehalf\""),
        );
    }
    resp
}

/// The `Authorization` header split into its scheme and value.
fn authorization(headers: &HeaderMap) -> Result<Option<(String, &str)>, ApiError> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw
        .to_str()
        .map_err(|_| ApiError::unauthorized("authorization header is not ASCII"))?;
    match raw.split_once(' ') {
        Some((scheme, value)) if !value.trim().is_empty() => {
            Ok(Some((scheme.to_ascii_lowercase(), value.trim())))
        }
        _ => Err(ApiError::unauthorized(
            "expected `Authorization: Bearer <token>`",
        )),
    }
}

fn evaluate(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<EvaluationResponse, ApiError> {
    let raw: Value = parse_json(body)?;
    let pep_field = |k: &str| raw.get(k).and_then(Value::as_str).map(str::to_owned);
    let (pep_id, pep_secret) = (pep_field("pep_id"), pep_field("pep_secret"));
    let mut req: EvaluationRequest = serde_json::from_value(raw)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    let now = now();

    let auth = authorization(headers)?;
    let bearer = match &auth {
        Some((scheme, token)) if scheme == "bearer" => Some(*token),
        Some((scheme, _)) if scheme == "basic" => None,
        Some(_) => {
            return Err(ApiError::unauthorized(
                "expected `Authorization: Bearer <token>`",
            ))
        }
        None => None,
    };

    let pep = match bearer {
        Some(token) => {
            if pep_secret.is_some() {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    "send either a bearer token or PEP credentials, not both",
                ));
            }
            let v = state
                .verifier
                .verify(token, now)
                .map_err(|e| ApiError::unauthorized(e.to_string()))?;
            attach_chain(&mut req, &v.chain)?;
            None
        }
        None => {
            if !state.authzen_allow_unsigned_chain {
                return Err(ApiError::unauthorized(
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
            Some(id)
        }
    };

    let (chain_value, call) = authzen::to_chain_and_call(&req)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    if let Some(pep) = pep {
        chain_value
            .validate_at(now, state.verifier.max_depth())
            .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
        check_issued(state, &chain_value).map_err(|detail| {
            tracing::warn!(pep = %pep, detail = %detail, "AuthZEN body chain was not issued here");
            ApiError::new(StatusCode::FORBIDDEN, CHAIN_NOT_ISSUED, detail)
        })?;
        tracing::debug!(pep = %pep, "AuthZEN body chain accepted from an authenticated PEP");
    }
    let d = state.pipeline.decide(&chain_value, &call, now);
    Ok(EvaluationResponse {
        decision: d.is_allow(),
        context: Some(json!({
            "reason": d.reason,
            "policy_ids": d.policy_ids,
            "diagnostics": d.diagnostics,
            "decision_id": d.decision_id,
        })),
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
fn attach_chain(req: &mut EvaluationRequest, chain: &DelegationChain) -> Result<(), ApiError> {
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
