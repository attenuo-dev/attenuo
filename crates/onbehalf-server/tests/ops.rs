//! Operational endpoints: readiness, metrics, key rotation.

use std::sync::Arc;

use onbehalf_proxy::testing::{spawn_router, Spawned};
use onbehalf_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::Value;

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.admin.token = Some("admin".into());
        cfg.dev.allow_root_mint = true;
        let (router, state) = onbehalf_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            state,
            _dir: dir,
        }
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        reqwest::get(self.server.url(path)).await.unwrap()
    }
}

#[tokio::test]
async fn readyz_ok_when_stores_answer() {
    let h = Harness::start().await;
    let r = h.get("/readyz").await;
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(body["checks"]["audit"]["ok"], true);
    assert_eq!(body["checks"]["leases"]["ok"], true);
}

#[tokio::test]
async fn readyz_503_when_audit_store_fails_but_healthz_stays_ok() {
    let h = Harness::start().await;
    h.state
        .audit
        .with_connection(|c| {
            c.execute_batch("DROP TABLE audit")?;
            Ok(())
        })
        .unwrap();
    let r = h.get("/readyz").await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["status"], "unavailable");
    assert_eq!(body["checks"]["audit"]["ok"], false);
    assert!(body["checks"]["audit"]["error"].is_string());
    assert_eq!(body["checks"]["leases"]["ok"], true);
    assert_eq!(h.get("/healthz").await.status(), StatusCode::OK);
}

#[tokio::test]
async fn readyz_503_when_lease_store_fails() {
    let h = Harness::start().await;
    h.state
        .audit
        .with_connection(|c| {
            c.execute_batch("DROP TABLE leases")?;
            Ok(())
        })
        .unwrap();
    let r = h.get("/readyz").await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["checks"]["leases"]["ok"], false);
    assert_eq!(body["checks"]["audit"]["ok"], true);
}

// ---------------------------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------------------------

use onbehalf_core::ToolCall;
use serde_json::json;

impl Harness {
    async fn admin_post(&self, path: &str, body: Value) -> Value {
        let r = reqwest::Client::new()
            .post(self.server.url(path))
            .bearer_auth("admin")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        r.json().await.unwrap()
    }
}

fn line_value(text: &str, prefix: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix} in:\n{text}"))
        .trim()
        .parse()
        .unwrap()
}

/// Sum of every `onbehalf_decisions_total` sample.
fn decisions_total(text: &str) -> u64 {
    text.lines()
        .filter(|l| l.starts_with("onbehalf_decisions_total{"))
        .map(|l| l.rsplit(' ').next().unwrap().parse::<u64>().unwrap())
        .sum()
}

#[tokio::test]
async fn metrics_endpoint_reports_pipeline_and_token_activity() {
    let h = Harness::start().await;
    let metrics = spawn_router(onbehalf_server::metrics::router(h.state.metrics.clone()))
        .await
        .unwrap();

    let root = h
        .admin_post(
            "/admin/root-token",
            json!({"subject": "alice", "issuer": "https://idp.example", "agent": "planner",
                   "capabilities": ["github:*"]}),
        )
        .await;
    let token = root["access_token"].as_str().unwrap().to_string();
    let child = reqwest::Client::new()
        .post(h.server.url("/token"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": "coder",
            "authorization_details": [{"type": "onbehalf_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(child.status(), StatusCode::OK);

    // Two decisions through the shared pipeline (no policies are loaded, so both deny).
    let now = time::OffsetDateTime::now_utc();
    let chain = h.state.verifier.verify(&token, now).unwrap().chain;
    let call = ToolCall::new("github", "read_file", json!({}));
    h.state.pipeline.decide(&chain, &call, now);
    h.state.pipeline.decide(&chain, &call, now);

    let lease = root["lease"].as_str().unwrap();
    let revoked = h
        .admin_post(&format!("/admin/leases/{lease}/revoke"), json!({}))
        .await;
    assert_eq!(revoked["revoked"], 2); // the root and its child

    // A failing audit store is counted, and the call is denied with audit_error.
    h.state
        .audit
        .with_connection(|c| {
            c.execute_batch("DROP TABLE audit")?;
            Ok(())
        })
        .unwrap();
    let d = h.state.pipeline.decide(&chain, &call, now);
    assert_eq!(d.reason, "audit_error");

    let r = reqwest::get(metrics.url("/metrics")).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let ct = r.headers()["content-type"].to_str().unwrap().to_string();
    assert!(ct.starts_with("text/plain; version=0.0.4"), "{ct}");
    let text = r.text().await.unwrap();

    assert!(text.contains("# TYPE onbehalf_decisions_total counter"));
    assert_eq!(decisions_total(&text), 3);
    assert_eq!(
        line_value(
            &text,
            "onbehalf_decisions_total{decision=\"deny\",reason=\"audit_error\"} "
        ),
        1
    );
    assert_eq!(
        line_value(&text, "onbehalf_tokens_issued_total{kind=\"root\"} "),
        1
    );
    assert_eq!(
        line_value(&text, "onbehalf_tokens_issued_total{kind=\"exchange\"} "),
        1
    );
    assert_eq!(line_value(&text, "onbehalf_leases_revoked_total "), 2);
    assert_eq!(line_value(&text, "onbehalf_audit_append_errors_total "), 1);
    assert_eq!(
        line_value(
            &text,
            "onbehalf_http_requests_total{route=\"/token\",status=\"200\"} "
        ),
        1
    );
    assert_eq!(
        line_value(
            &text,
            "onbehalf_http_requests_total{route=\"/admin/leases/{lease_id}/revoke\",status=\"200\"} "
        ),
        1
    );
    assert_eq!(
        line_value(&text, "onbehalf_authorize_duration_seconds_count "),
        3
    );
    assert_eq!(
        line_value(
            &text,
            "onbehalf_authorize_duration_seconds_bucket{le=\"+Inf\"} "
        ),
        3
    );
}

#[tokio::test]
async fn metrics_are_not_served_on_the_api_port() {
    let h = Harness::start().await;
    assert_eq!(h.get("/metrics").await.status(), StatusCode::NOT_FOUND);
}
