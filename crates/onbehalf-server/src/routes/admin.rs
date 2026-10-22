//! `/admin/*`: leases, audit log and policy reload. Every route requires the static admin
//! bearer from `[admin] token` (v0; see [`require_admin`]).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::{AuditEntry, AuditSink, LeaseStore, VerifyReport};
use onbehalf_core::LeaseId;
use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;

use super::{bearer_of, now};
use crate::error::ApiError;
use crate::state::AppState;

/// Largest page `GET /admin/audit` returns.
pub const MAX_AUDIT_PAGE: usize = 1000;
const DEFAULT_AUDIT_PAGE: usize = 100;

/// Middleware: the request must carry `Authorization: Bearer <[admin] token>`.
///
/// When no admin token is configured every admin route answers 403, so a forgotten setting
/// fails closed rather than open.
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.admin_token.as_deref() else {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "admin_disabled",
            "no [admin] token is configured",
        )
        .into_response();
    };
    match bearer_of(req.headers()) {
        Ok(Some(token)) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(req).await
        }
        _ => {
            let mut resp = ApiError::unauthorized("admin bearer token required").into_response();
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"onbehalf-admin\""),
            );
            resp
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /admin/leases/{lease_id}/revoke` with `{ "reason": "..." }`: revoke the lease and
/// every lease delegated from it. Returns how many leases changed state.
pub async fn revoke_lease(
    State(state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let body: RevokeBody = if body.is_empty() {
        RevokeBody::default()
    } else {
        super::parse_json(&body)?
    };
    let reason = body
        .reason
        .unwrap_or_else(|| "revoked by admin".to_string());
    let lease = LeaseId::new(lease_id);
    let revoked = state.leases.revoke(&lease, &reason, now())?;
    tracing::warn!(lease = %lease.0, reason = %reason, revoked, "lease revoked");
    Ok(Json(
        json!({ "lease_id": lease, "revoked": revoked, "reason": reason }),
    ))
}

/// `GET /admin/leases/{lease_id}`: the lease's registry row and whether it is active now.
pub async fn lease_status(
    State(state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let lease = LeaseId::new(lease_id);
    let row = state
        .leases
        .get(&lease)?
        .ok_or_else(|| ApiError::not_found(format!("unknown lease `{}`", lease.0)))?;
    let fmt = |t: time::OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
    // Ask the store rather than the row so this agrees with what the pipeline sees.
    let active = state.leases.is_active(&lease, now())?;
    Ok(Json(json!({
        "lease_id": lease,
        "active": active,
        "parent": row.parent,
        "expires_at": fmt(row.expires_at),
        "revoked_at": row.revoked_at.map(fmt),
        "revoke_reason": row.revoke_reason,
    })))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// First sequence number to return (default 1).
    pub from: Option<u64>,
    /// Page size (default 100, at most [`MAX_AUDIT_PAGE`]).
    pub limit: Option<usize>,
}

/// `GET /admin/audit?from=&limit=`: entries in ascending `seq` order, plus `next` (the `from`
/// for the following page) when the page was full.
pub async fn audit_range(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let from = q.from.unwrap_or(1).max(1);
    let limit = q
        .limit
        .unwrap_or(DEFAULT_AUDIT_PAGE)
        .clamp(1, MAX_AUDIT_PAGE);
    let entries: Vec<AuditEntry> = state.audit.range(from, limit)?;
    let next = (entries.len() == limit)
        .then(|| entries.last().map(|e| e.seq + 1))
        .flatten();
    Ok(Json(json!({ "entries": entries, "next": next })))
}

/// `GET /admin/audit/verify`: walk the whole chain.
pub async fn audit_verify(
    State(state): State<Arc<AppState>>,
) -> Result<Json<VerifyReport>, ApiError> {
    Ok(Json(state.audit.verify_chain()?))
}

/// `GET /admin/audit/checkpoint`: `{seq, hash}` of the head, for external countersigning.
pub async fn audit_checkpoint(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let (seq, hash) = state.audit.checkpoint()?;
    Ok(Json(json!({ "seq": seq, "hash": hash })))
}

/// `POST /admin/policies/reload`: re-read `policy.policies_path` and swap the policy set if it
/// parses and validates. On failure the previous set stays in force and the answer is 422.
pub async fn reload_policies(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let path = state.policies_path.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "reload_unavailable",
            "policy.policies_path is not configured; there is nothing to reload",
        )
    })?;
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::internal(format!("reading {}: {e}", path.display())))?;
    let mut engine = state
        .pipeline
        .policy()
        .write()
        .map_err(|_| ApiError::internal("policy engine lock poisoned"))?;
    engine.reload_policies_str(&text).map_err(|e| {
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy_invalid",
            e.to_string(),
        )
    })?;
    let ids = engine.policy_ids();
    let warnings = engine.validation_warnings().to_vec();
    drop(engine);
    tracing::info!(policies = ?ids, "policies reloaded");
    Ok(Json(json!({ "policy_ids": ids, "warnings": warnings })))
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn ct_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
