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
/// Reads the audit log head and one lease row. Answers 200 `{"status":"ready"}` when both
/// work, otherwise 503 with the failing checks named. `/healthz` stays liveness-only.
pub async fn readyz(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    let audit = state.audit.head().map(|_| ()).map_err(|e| e.to_string());
    let leases = state
        .leases
        .get(&LeaseId::new("readyz-probe"))
        .map(|_| ())
        .map_err(|e| e.to_string());
    let check = |r: &Result<(), String>| match r {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e }),
    };
    let ready = audit.is_ok() && leases.is_ok();
    if !ready {
        tracing::warn!(?audit, ?leases, "readiness check failed");
    }
    let body = json!({
        "status": if ready { "ready" } else { "unavailable" },
        "checks": { "audit": check(&audit), "leases": check(&leases) },
    });
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}
