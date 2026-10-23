//! `/admin/*`: leases, audit log and policy reload. Every route requires the static admin
//! bearer from `[admin] token` (v0; see [`require_admin`]).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::{AuditEntry, AuditSink, LeaseStore, SignedVerifyReport};
use onbehalf_core::LeaseId;
use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;

use super::{audit_admin, bearer_of, now, REASON_ADMIN_ACTION};
use crate::error::ApiError;
use crate::state::AppState;
use onbehalf_core::Decision;
use sha2::Digest;

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
        other => {
            let reason = match other {
                Ok(None) => crate::error::REASON_MISSING_TOKEN,
                _ => crate::error::REASON_INVALID_TOKEN,
            };
            let mut resp =
                ApiError::unauthorized(reason, "admin bearer token required").into_response();
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"onbehalf-admin\""),
            );
            resp
        }
    }
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
    let now = now();
    state
        .blocking(move |state| {
            let revoked = state.leases.revoke(&lease, &reason, now)?;
            state.metrics.leases_revoked(revoked);
            tracing::warn!(lease = ?lease.0, reason = ?reason, revoked, "lease revoked");
            // The revocation stands even if it cannot be recorded: undoing it would be the
            // unsafe direction. The response says whether it was audited.
            let audit_id = audit_admin(
                state,
                "admin.lease.revoke",
                Decision::Allow,
                REASON_ADMIN_ACTION,
                vec![lease.clone()],
                json!({ "lease": lease, "reason": reason, "revoked": revoked }),
                now,
            )
            .inspect_err(|e| tracing::error!(error = ?e.detail, "admin revoke was not audited"))
            .ok();
            Ok(Json(json!({
                "lease_id": lease,
                "revoked": revoked,
                "reason": reason,
                "audit_id": audit_id,
            })))
        })
        .await
}

/// `GET /admin/leases/{lease_id}`: the lease's registry row and whether it is active now.
pub async fn lease_status(
    State(state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let lease = LeaseId::new(lease_id);
    state
        .blocking(move |state| {
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
        })
        .await
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// First sequence number to return (default 1).
    pub from: Option<u64>,
    /// Page size (default 100, at most [`MAX_AUDIT_PAGE`]).
    pub limit: Option<usize>,
}

/// `GET /admin/audit?from=&limit=`: entries in ascending `seq` order, plus `next` (the `from`
/// for the following page) when the page was full, and `head` (the newest seq, 0 for an empty
/// log; reading it signs nothing, unlike `/admin/audit/checkpoint`).
pub async fn audit_range(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    let from = q.from.unwrap_or(1).max(1);
    let limit = q
        .limit
        .unwrap_or(DEFAULT_AUDIT_PAGE)
        .clamp(1, MAX_AUDIT_PAGE);
    let (entries, head): (Vec<AuditEntry>, u64) = state
        .blocking(move |s| {
            let entries = s.audit.range(from, limit)?;
            let head = s.audit.head()?.map_or(0, |h| h.seq);
            Ok::<_, onbehalf_audit::AuditError>((entries, head))
        })
        .await?;
    let next = (entries.len() == limit)
        .then(|| entries.last().map(|e| e.seq + 1))
        .flatten();
    Ok(Json(
        json!({ "entries": entries, "next": next, "head": head }),
    ))
}

/// `GET /admin/audit/verify`: walk the whole chain and verify every stored checkpoint
/// signature against the JWKS keys. Besides `entries`, `ok` and `first_bad_seq` the report has
/// `checkpoints`, `last_signed_seq`, `unsigned_tail` and `bad_checkpoints`.
pub async fn audit_verify(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SignedVerifyReport>, ApiError> {
    Ok(Json(
        state
            .blocking(|s| s.audit.verify_chain_signed(&s.checkpoint_keys))
            .await?,
    ))
}

/// `GET /admin/audit/checkpoint`: the signed checkpoint of the current head,
/// `{seq, head_hash, at, kid, signature}`. Created now if the head has none yet, so the answer
/// can be kept off-host and checked later with only the JWKS. `hash` repeats `head_hash` for
/// clients written against the unsigned v0 response.
pub async fn audit_checkpoint(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let cp = state.blocking(|s| s.audit.checkpoint_signed(now())).await?;
    let mut v = serde_json::to_value(&cp).map_err(ApiError::internal)?;
    v["hash"] = Value::String(cp.head_hash.clone());
    Ok(Json(v))
}

/// Entries read per blocking-pool hop while streaming an export.
const EXPORT_PAGE: usize = 500;

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// First sequence number (default 1).
    pub from: Option<u64>,
    /// Last sequence number, inclusive (default: the head when the export starts).
    pub to: Option<u64>,
    /// Only records of this kind (`decision`, `exchange`, `root_token`, `lease_renew`,
    /// `lease_revoke`, `admin`).
    pub kind: Option<String>,
    /// Only records of this delegation chain (the `chain_id` field).
    pub chain_id: Option<String>,
}

/// Where a streaming export is.
enum ExportPhase {
    Entries { next: u64 },
    Checkpoints,
    Done,
}

/// `GET /admin/audit/export?from=&to=`: entries `from..=to` and the checkpoints inside that
/// range, as `application/x-ndjson` (one JSON object per line, see
/// `onbehalf_audit::export`), streamed a page at a time so a large range never sits in memory.
/// Verify the result offline with `onbehalf audit verify --file`.
///
/// `kind` and `chain_id` keep only the matching entries. The header then carries a `filter`
/// member and the file cannot be verified (its chain has gaps); verify an unfiltered export.
pub async fn audit_export(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    use futures_util::stream;

    let from = q.from.unwrap_or(1);
    if from == 0 {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`from` must be at least 1",
        ));
    }
    let head = state
        .blocking(|s| s.audit.head())
        .await?
        .map_or(0, |h| h.seq);
    let to = q.to.map_or(head, |t| t.min(head));
    if q.to.is_some_and(|t| t < from) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`to` must not be smaller than `from`",
        ));
    }
    let filter = onbehalf_audit::RecordFilter {
        kind: q
            .kind
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e: String| ApiError::bad_request("invalid_request", e))?,
        chain_id: q.chain_id.clone(),
    };
    if filter.chain_id.as_deref() == Some("") {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`chain_id` must not be empty",
        ));
    }
    let exported_at = now().format(&Rfc3339).map_err(ApiError::internal)?;
    let header = onbehalf_audit::header_line(
        &onbehalf_audit::ExportHeader::new(from, to, exported_at).with_filter(filter.clone()),
    );

    let first = stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(header)) });
    let rest = stream::unfold(
        (state, ExportPhase::Entries { next: from }),
        move |(state, phase)| {
            let filter = filter.clone();
            async move {
                match phase {
                    ExportPhase::Done => None,
                    ExportPhase::Entries { next } if next > to => {
                        Some((Ok(Bytes::new()), (state, ExportPhase::Checkpoints)))
                    }
                    ExportPhase::Entries { next } => {
                        let want = usize::try_from(to - next + 1)
                            .unwrap_or(EXPORT_PAGE)
                            .min(EXPORT_PAGE);
                        let f = filter.clone();
                        let page = state
                            .blocking(move |s| s.audit.range_filtered(next, to, &f, want))
                            .await;
                        match page {
                            Err(e) => Some((
                                Err(std::io::Error::other(e.to_string())),
                                (state, ExportPhase::Done),
                            )),
                            Ok(entries) if entries.is_empty() => {
                                Some((Ok(Bytes::new()), (state, ExportPhase::Checkpoints)))
                            }
                            Ok(entries) => {
                                let last = entries.last().map_or(next, |e| e.seq);
                                let mut out = String::new();
                                for e in entries.iter().filter(|e| e.seq <= to) {
                                    out.push_str(&onbehalf_audit::entry_line(e));
                                }
                                Some((
                                    Ok(Bytes::from(out)),
                                    (state, ExportPhase::Entries { next: last + 1 }),
                                ))
                            }
                        }
                    }
                    ExportPhase::Checkpoints => {
                        let cps = state
                            .blocking(move |s| s.audit.checkpoints_between(from, to))
                            .await;
                        let item = cps
                            .map(|cps| {
                                let out: String =
                                    cps.iter().map(onbehalf_audit::checkpoint_line).collect();
                                Bytes::from(out)
                            })
                            .map_err(|e| std::io::Error::other(e.to_string()));
                        Some((item, (state, ExportPhase::Done)))
                    }
                }
            }
        },
    );
    let body = axum::body::Body::from_stream(futures_util::StreamExt::chain(first, rest));
    let mut resp = Response::new(body);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
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
    let digest = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    let now = now();
    // The write guard is not `Send`, so it lives only inside this block.
    let reloaded = {
        let mut engine = state
            .pipeline
            .policy()
            .write()
            .map_err(|_| ApiError::internal("policy engine lock poisoned"))?;
        match engine.reload_policies_str(&text) {
            Err(e) => Err(e.to_string()),
            Ok(()) => Ok((engine.policy_ids(), engine.validation_warnings().to_vec())),
        }
    };
    let (ids, warnings) = match reloaded {
        Ok(ok) => ok,
        Err(detail) => {
            let (p, d) = (path.clone(), digest.clone());
            let _ = state
                .blocking(move |state| {
                    audit_admin(
                        state,
                        "admin.policies.reload",
                        Decision::Deny,
                        "policy_invalid",
                        Vec::new(),
                        json!({ "path": p, "sha256": d }),
                        now,
                    )
                })
                .await
                .inspect_err(
                    |e| tracing::error!(error = ?e.detail, "failed reload was not audited"),
                );
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "policy_invalid",
                detail,
            ));
        }
    };
    tracing::info!(policies = ?ids, "policies reloaded");
    let (p, d, pids) = (path.clone(), digest.clone(), ids.clone());
    let audit_id = state
        .blocking(move |state| {
            audit_admin(
                state,
                "admin.policies.reload",
                Decision::Allow,
                REASON_ADMIN_ACTION,
                Vec::new(),
                json!({ "path": p, "sha256": d, "policy_ids": pids }),
                now,
            )
        })
        .await
        .inspect_err(|e| tracing::error!(error = ?e.detail, "policy reload was not audited"))
        .ok();
    Ok(Json(json!({
        "policy_ids": ids,
        "warnings": warnings,
        "sha256": digest,
        "audit_id": audit_id,
    })))
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
