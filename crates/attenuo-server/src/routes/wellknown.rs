//! Health and discovery: `/healthz`, `/.well-known/jwks.json`,
//! `/.well-known/authzen-configuration`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::Json;
use serde_json::{json, Value};

use crate::config::is_loopback_host;
use crate::error::ApiError;
use crate::state::AppState;

/// `GET /healthz`
pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

/// `GET /.well-known/jwks.json`: the issuer's Ed25519 public key, so other verifiers can check
/// attenuo tokens without sharing a PEM out of band.
pub async fn jwks(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.jwks.clone())
}

/// `GET /.well-known/authzen-configuration` (AuthZEN PDP metadata).
pub async fn authzen_configuration(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let base = base_url(&state, &headers)?;
    Ok(Json(json!({
        "policy_decision_point": base,
        "access_evaluation_endpoint": format!("{base}/access/v1/evaluation"),
        "access_evaluations_endpoint": format!("{base}/access/v1/evaluations"),
    })))
}

/// Error code when discovery is asked with a `Host` it will not echo (SR-19).
pub const INVALID_HOST: &str = "invalid_host";

/// `[server] public_url` if set. Otherwise (only possible on a loopback listener, see
/// `ServerSection::check_public_url`) `http://<Host>`, where `Host` must be a loopback name:
/// anything else is refused with 400, so a forged `Host` cannot end up in a discovery document
/// that a shared cache then serves to others (SR-19).
fn base_url(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    if let Some(url) = &state.public_url {
        return Ok(url.trim_end_matches('/').to_string());
    }
    let host = match headers.get(header::HOST) {
        None => "localhost",
        Some(h) => h
            .to_str()
            .ok()
            .filter(|h| is_loopback_host(h))
            .ok_or_else(|| {
                tracing::debug!(host = ?h, "discovery refused: Host is not a loopback name");
                ApiError::bad_request(
                    INVALID_HOST,
                    "Host must be localhost, 127.0.0.1 or [::1] when [server] public_url is unset",
                )
            })?,
    };
    Ok(format!("http://{host}"))
}
