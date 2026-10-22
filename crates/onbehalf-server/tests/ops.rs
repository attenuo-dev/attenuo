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
