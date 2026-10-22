//! `POST /access/v1/evaluation`: OpenID AuthZEN evaluation, served by the same [`Pipeline`]
//! as the proxy.
//!
//! Where the chain comes from:
//!
//! - With `Authorization: Bearer <delegation token>`, the token is verified and its chain is
//!   used. If the body also carries `subject.properties.chain`, it must equal the token's
//!   chain. An empty `subject.id` is filled with the chain's current agent.
//! - Without a bearer, `subject.properties.chain` is required and is taken as asserted by the
//!   calling PEP. It is checked structurally (`validate_at`), and every lease in it must be in
//!   this server's registry and live, so a chain this server never issued is denied with
//!   `lease_unknown`. Its signatures are *not* checked (there are none in the body); deploy the
//!   endpoint where only trusted PEPs can reach it, or have PEPs send the bearer.
//!
//! The response is the AuthZEN `{decision, context}` with `context.reason`,
//! `context.policy_ids`, `context.diagnostics` and `context.decision_id` (the audit record).
//!
//! [`Pipeline`]: crate::authz::Pipeline

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use onbehalf_core::DelegationChain;
use onbehalf_policy::authzen::{self, EvaluationRequest, EvaluationResponse};
use serde_json::{json, Value};

use super::{bearer_of, now, parse_json};
use crate::error::ApiError;
use crate::state::AppState;

pub async fn evaluation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<EvaluationResponse>, ApiError> {
    let mut req: EvaluationRequest = parse_json(&body)?;
    let now = now();
    let verified = match bearer_of(&headers)? {
        Some(token) => {
            let v = state
                .verifier
                .verify(token, now)
                .map_err(|e| ApiError::unauthorized(e.to_string()))?;
            attach_chain(&mut req, &v.chain)?;
            true
        }
        None => false,
    };
    let (chain, call) = authzen::to_chain_and_call(&req)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    if !verified {
        chain
            .validate_at(now, state.verifier.max_depth())
            .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    }
    let d = state.pipeline.decide(&chain, &call, now);
    Ok(Json(EvaluationResponse {
        decision: d.is_allow(),
        context: Some(json!({
            "reason": d.reason,
            "policy_ids": d.policy_ids,
            "diagnostics": d.diagnostics,
            "decision_id": d.decision_id,
        })),
    }))
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
