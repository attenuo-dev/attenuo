//! Operational endpoints: `/readyz`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use onbehalf_audit::AuditSink;
use onbehalf_core::LeaseId;
use serde_json::{json, Value};

use crate::state::AppState;

/// `GET /readyz`: can the server do its job right now?
///
/// Reads the audit log head and one lease row. The body has a fixed shape,
/// `{"ready":true,"checks":{"audit":"ok","leases":"ok"}}`, with `"error"` for a failing check
/// and 503 when any check fails. The storage error text (SQLite messages, file paths) goes to
/// the server log only: the endpoint needs no credentials (SR-38). `/healthz` stays
/// liveness-only.
pub async fn readyz(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    let (audit, leases) = state
        .blocking(|s| {
            let audit = s.audit.head().map(|_| ()).map_err(|e| e.to_string());
            let leases = s
                .leases
                .get(&LeaseId::new("readyz-probe"))
                .map(|_| ())
                .map_err(|e| e.to_string());
            (audit, leases)
        })
        .await;
    let check = |name: &str, r: &Result<(), String>| match r {
        Ok(()) => "ok",
        Err(e) => {
            tracing::warn!(check = name, error = %e, "readiness check failed");
            "error"
        }
    };
    let (audit_status, leases_status) = (check("audit", &audit), check("leases", &leases));
    let ready = audit.is_ok() && leases.is_ok();
    let body = json!({
        "ready": ready,
        "checks": { "audit": audit_status, "leases": leases_status },
    });
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}
