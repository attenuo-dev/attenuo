//! `POST /token`: RFC 8693 token exchange.
//!
//! Two kinds of request share this endpoint:
//!
//! - **Hop 0 (IdP intake).** `subject_token_type` is `...:token-type:id_token` or
//!   `...:token-type:id-jag` (or `grant_type` is `...:grant-type:jwt-bearer`): the subject token
//!   is a user credential from a trusted IdP, and the agent authenticates with its client
//!   credentials. Handled by [`crate::idp::intake`].
//! - **Hop n to n+1.** `subject_token_type` is `...:token-type:jwt` and the subject token is an
//!   onbehalf token. Described below.
//!
//! Accepts `application/x-www-form-urlencoded` (RFC 8693 §2.1) or `application/json`. Fields:
//!
//! | Field | Notes |
//! |---|---|
//! | `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
//! | `subject_token` | the parent onbehalf token |
//! | `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` |
//! | `actor` | the sub-agent's id (v0: asserted, not authenticated) |
//! | `authorization_details` | RFC 9396 list with one `{"type":"onbehalf_capabilities","capabilities":[...]}`; a JSON string in form encoding |
//! | `scope` | form only, alternative to `authorization_details`: space-separated `server:tool` |
//! | `requested_ttl_seconds` | optional |
//!
//! Besides what `ExchangeRequest::execute` checks (signature, chain validity, attenuation,
//! depth), the parent's leases must all be live: a revoked parent cannot delegate. The new lease
//! is registered as a child of the parent token's last lease, so revoking the parent cascades.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::LeaseStore;
use onbehalf_token::{ExchangeRequest, AUTHORIZATION_DETAILS_TYPE};
use serde_json::{json, Map, Value};

use super::{audit_issuance, no_store, now, parse_json};
use crate::config::{capability_set, CapSpec};
use crate::error::ApiError;
use crate::state::AppState;

pub async fn exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let value = parse_body(&headers, &body)?;
    let now = now();
    if crate::idp::intake::is_intake(&value) {
        return crate::idp::intake::handle(&state, &headers, value, now).await;
    }
    let req = parse_request(value)?;
    if req.requested.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_request",
            format!("authorization_details must contain a `{AUTHORIZATION_DETAILS_TYPE}` entry with at least one capability"),
        ));
    }
    let parent = state.verifier.verify(&req.subject_token, now)?;
    state
        .pipeline
        .check_leases(&parent.chain, now)
        .map_err(|(reason, detail)| {
            ApiError::bad_request(
                "invalid_grant",
                format!(
                    "subject token cannot delegate: {reason} ({})",
                    detail.join("; ")
                ),
            )
        })?;

    let resp = req.execute(&state.issuer, now)?;
    // The response carries no chain; read it back from the token we just minted.
    let issued = state.verifier.verify(&resp.access_token, now)?;
    let hop = issued
        .chain
        .hops
        .last()
        .ok_or_else(|| ApiError::internal("issued token has no hops"))?;
    let parent_lease = parent.chain.hops.last().map(|h| &h.lease);
    state.leases.register(
        &resp.lease,
        parent_lease,
        state.initial_lease_expiry(now, hop.expires_at),
    )?;

    let args = json!({
        "actor": req.actor,
        "requested": req.requested,
        "parent_lease": parent_lease,
    });
    if let Err(e) = audit_issuance(&state, "token.exchange", &issued.chain, args, now) {
        // An issuance we cannot record must not be usable.
        let _ = state.leases.revoke(&resp.lease, "audit_error", now);
        return Err(e);
    }
    tracing::info!(
        subject = %issued.chain.originating_user.subject,
        actor = %req.actor,
        lease = %resp.lease.0,
        depth = issued.chain.depth(),
        "token exchanged"
    );
    let mut out = Json(resp).into_response();
    no_store(out.headers_mut());
    Ok(out)
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false)
}

/// The request body as JSON, from either encoding.
fn parse_body(headers: &HeaderMap, body: &Bytes) -> Result<Value, ApiError> {
    if is_form(headers) {
        form_to_json(body)
    } else {
        parse_json::<Value>(body)
    }
}

fn parse_request(value: Value) -> Result<ExchangeRequest, ApiError> {
    serde_json::from_value(value).map_err(|e| {
        let msg = e.to_string();
        let code = if msg.contains("unsupported grant_type") {
            "unsupported_grant_type"
        } else {
            "invalid_request"
        };
        ApiError::bad_request(code, msg)
    })
}

/// Turn RFC 8693 form fields into the JSON shape `ExchangeRequest` deserializes.
fn form_to_json(body: &Bytes) -> Result<Value, ApiError> {
    let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    let mut obj = Map::new();
    let mut scope: Option<String> = None;
    for (k, v) in pairs {
        if obj.contains_key(&k) {
            // RFC 6749 §3.1: parameters must not be included more than once.
            return Err(ApiError::bad_request(
                "invalid_request",
                format!("parameter `{k}` repeated"),
            ));
        }
        let value = match k.as_str() {
            "authorization_details" => serde_json::from_str(&v).map_err(|e| {
                ApiError::bad_request(
                    "invalid_request",
                    format!("authorization_details is not JSON: {e}"),
                )
            })?,
            "requested_ttl_seconds" => Value::from(v.parse::<u64>().map_err(|e| {
                ApiError::bad_request("invalid_request", format!("requested_ttl_seconds: {e}"))
            })?),
            "scope" => {
                scope = Some(v);
                continue;
            }
            _ => Value::String(v),
        };
        obj.insert(k, value);
    }
    if let Some(scope) = scope {
        if obj.contains_key("authorization_details") {
            return Err(ApiError::bad_request(
                "invalid_request",
                "use either scope or authorization_details, not both",
            ));
        }
        let specs: Vec<CapSpec> = scope
            .split_whitespace()
            .map(|s| CapSpec::Short(s.to_string()))
            .collect();
        let caps = capability_set(&specs).map_err(|e| ApiError::bad_request("invalid_scope", e))?;
        obj.insert(
            "authorization_details".into(),
            json!([{ "type": AUTHORIZATION_DETAILS_TYPE, "capabilities": caps }]),
        );
    }
    Ok(Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_scope_becomes_authorization_details() {
        let body = Bytes::from(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
             &subject_token=a.b.c&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
             &actor=coder&scope=github%3Aread_file+github%3Aread_dir&requested_ttl_seconds=60",
        );
        let v = form_to_json(&body).unwrap();
        let req: ExchangeRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.requested.len(), 2);
        assert_eq!(req.ttl_seconds, Some(60));
        assert_eq!(req.actor.0, "coder");
    }

    #[test]
    fn form_rejects_repeats_and_bad_json() {
        assert!(form_to_json(&Bytes::from("actor=a&actor=b")).is_err());
        assert!(form_to_json(&Bytes::from("authorization_details=%5Bnope")).is_err());
        assert!(form_to_json(&Bytes::from("scope=nocolon")).is_err());
    }
}
