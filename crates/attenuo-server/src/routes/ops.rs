//! Operational endpoints: `/readyz`.

use std::sync::Arc;

use attenuo_audit::AuditSink;
use attenuo_core::LeaseId;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

/// How long a failed audit append keeps `/readyz` failing when no append succeeds after it
/// (see [`readyz`]).
pub const AUDIT_APPEND_FAILURE_HOLD: std::time::Duration = std::time::Duration::from_secs(30);

/// `GET /readyz`: can the server do its job right now?
///
/// Reads the audit log head and one lease row, and looks at how the last audit append
/// ended. The body has a fixed shape,
/// `{"ready":true,"checks":{"audit":"ok","audit_append":"ok","leases":"ok"}}`, with `"error"`
/// for a failing check and 503 when any check fails.
///
/// `checks.audit_append` is `"error"` when the most recent audit append failed (a full disk,
/// a read-only file, a storage fault): every decision is then denied with `audit_error`, so
/// the server is not ready, although reads still work. It goes back to `"ok"` with the next
/// append that succeeds, or [`AUDIT_APPEND_FAILURE_HOLD`] after the failure when no append
/// has been made since (a server out of rotation gets none), so the server is offered
/// traffic again and the next failing append takes it out again. No probe is written:
/// the check reads a flag the appends set. The storage error text (SQLite messages, file paths) goes to
/// the server log only: the endpoint needs no credentials (SR-38). `/healthz` stays
/// liveness-only.
///
/// With `[audit.sink]` configured, the body also has `"degraded"` and
/// `checks.checkpoint_sink` (`"ok"` or `"degraded"`): degraded when the sink queue is full or
/// the oldest undelivered checkpoint is older than `max_lag_seconds` (SR-21). A degraded sink
/// fails readiness only with `fail_readiness = true`.
///
/// With `[approvals.notify]` configured, `checks.approval_notifier` is `"ok"` or
/// `"degraded"` on the same rule (queue full, or the oldest undelivered notification or the
/// current run of failures older than its `max_lag_seconds`), and `"degraded"` is true when
/// either is. A degraded notifier never fails readiness: notifications are best effort. With
/// `[leases.notify]` configured, `checks.lease_notifier` follows the same rule.
///
/// Right after a quick restart, while the DPoP restart fence refuses every proof made now
/// (`crate::dpop`, "Restart fence"; at most about 21 seconds with the defaults), the answer is
/// 503 with `checks.dpop_restart_fence` = `"fenced"`, so a rolling deploy sends no DPoP traffic
/// to the new server yet. The member is absent otherwise. `/healthz` is not affected.
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
    let appends_failing = state
        .metrics
        .audit_append_failing(AUDIT_APPEND_FAILURE_HOLD);
    if appends_failing {
        tracing::warn!(
            check = "audit_append",
            "readiness check failed: the last audit append failed"
        );
    }
    let fenced = state.dpop_fenced_until();
    let mut ready = audit.is_ok() && leases.is_ok() && !appends_failing && fenced.is_none();
    let mut body = json!({
        "ready": ready,
        "checks": {
            "audit": audit_status,
            "audit_append": if appends_failing { "error" } else { "ok" },
            "leases": leases_status,
        },
    });
    if fenced.is_some() {
        // Moments after a restart, every DPoP proof made now is refused: keep traffic away.
        body["checks"]["dpop_restart_fence"] = json!("fenced");
    }
    if let Some(sink) = &state.checkpoint_sink {
        let status = sink.status();
        if status.degraded {
            tracing::warn!(
                queued = status.queued,
                capacity = status.capacity,
                lag_seconds = status.lag.as_secs(),
                last_error = status.last_error.as_deref().unwrap_or(""),
                "readiness: [audit.sink] is degraded"
            );
            if state.sink_fails_readiness {
                ready = false;
            }
        }
        body["ready"] = json!(ready);
        body["degraded"] = json!(status.degraded);
        body["checks"]["checkpoint_sink"] = json!(if status.degraded { "degraded" } else { "ok" });
    }
    let notifiers = [
        (
            "approval_notifier",
            "[approvals.notify]",
            state.approval_notifier.as_ref().map(|n| n.status()),
        ),
        (
            "lease_notifier",
            "[leases.notify]",
            state.lease_notifier.as_ref().map(|n| n.status()),
        ),
    ];
    for (check, section, status) in notifiers {
        let Some(status) = status else { continue };
        if status.degraded {
            tracing::warn!(
                queued = status.queued,
                capacity = status.capacity,
                lag_seconds = status.lag.as_secs(),
                last_error = status.last_error.as_deref().unwrap_or(""),
                "readiness: {section} is degraded"
            );
        }
        let degraded = status.degraded || body["degraded"].as_bool().unwrap_or(false);
        body["degraded"] = json!(degraded);
        body["checks"][check] = json!(if status.degraded { "degraded" } else { "ok" });
    }
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}
