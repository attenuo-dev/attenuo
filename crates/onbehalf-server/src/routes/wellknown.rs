//! Health and discovery: `/healthz`, `/.well-known/jwks.json`,
//! `/.well-known/authzen-configuration`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

/// `GET /healthz`
pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

/// `GET /.well-known/jwks.json`: the issuer's Ed25519 public key, so other verifiers can check
/// onbehalf tokens without sharing a PEM out of band.
pub async fn jwks(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(state.jwks.clone())
}

/// `GET /.well-known/authzen-configuration` (AuthZEN PDP metadata).
pub async fn authzen_configuration(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let base = base_url(&state, &headers);
    Json(json!({
        "policy_decision_point": base,
        "access_evaluation_endpoint": format!("{base}/access/v1/evaluation"),
        "access_evaluations_endpoint": format!("{base}/access/v1/evaluations"),
    }))
}

/// `[server] public_url` if set, else `http://<Host>`.
fn base_url(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(url) = &state.public_url {
        return url.trim_end_matches('/').to_string();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    format!("http://{host}")
}
