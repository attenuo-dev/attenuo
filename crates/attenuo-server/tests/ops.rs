//! Operational endpoints: readiness, metrics, key rotation.

use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::Value;

use sha2::Digest;

const CODER_SECRET: &str = "coder-secret";

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
        // Exchanges authenticate as their actor (SR-10).
        cfg.agents
            .push(attenuo_server::config::AgentConfig::with_secret_sha256(
                "coder",
                hex::encode(sha2::Sha256::digest(CODER_SECRET.as_bytes())),
            ));
        let (router, state) = attenuo_server::build(&cfg).unwrap();
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
    assert_eq!(
        body,
        json!({"ready": true, "checks": {"audit": "ok", "audit_append": "ok", "leases": "ok"}})
    );
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
    // Stable shape, and none of the SQLite error text (SR-38).
    assert_eq!(
        body,
        json!({"ready": false, "checks": {"audit": "error", "audit_append": "ok", "leases": "ok"}})
    );
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
    assert_eq!(
        body,
        json!({"ready": false, "checks": {"audit": "ok", "audit_append": "ok", "leases": "error"}})
    );
}

/// A-12: a full disk fails appends while reads go on working. Readiness follows the
/// appends: not ready after a failed one, ready again after the next one that succeeds.
#[tokio::test]
async fn readyz_503_while_audit_appends_fail_and_ok_after_the_next_success() {
    let h = Harness::start().await;
    // Every insert into the log fails, as on a full disk; the log still reads.
    h.state
        .audit
        .with_connection(|c| {
            c.execute_batch(
                "CREATE TRIGGER full_disk BEFORE INSERT ON audit \
                 BEGIN SELECT RAISE(FAIL, 'database or disk is full'); END;",
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        h.get("/readyz").await.status(),
        StatusCode::OK,
        "no append yet"
    );
    let minted = reqwest::Client::new()
        .post(h.server.url("/admin/root-token"))
        .bearer_auth("admin")
        .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                      "agent": "planner", "capabilities": ["github:*"]}))
        .send()
        .await
        .unwrap();
    assert!(
        !minted.status().is_success(),
        "an unrecorded token is refused"
    );
    let r = h.get("/readyz").await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = r.json().await.unwrap();
    assert_eq!(
        body,
        json!({"ready": false, "checks": {"audit": "ok", "audit_append": "error", "leases": "ok"}})
    );
    // Space is freed: the next append succeeds and readiness comes back with it.
    h.state
        .audit
        .with_connection(|c| {
            c.execute_batch("DROP TRIGGER full_disk")?;
            Ok(())
        })
        .unwrap();
    mint_root(&h.server).await;
    let r = h.get("/readyz").await;
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["checks"]["audit_append"], "ok");
}

// ---------------------------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------------------------

use attenuo_core::ToolCall;
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

/// Sum of every `attenuo_decisions_total` sample.
fn decisions_total(text: &str) -> u64 {
    text.lines()
        .filter(|l| l.starts_with("attenuo_decisions_total{"))
        .map(|l| l.rsplit(' ').next().unwrap().parse::<u64>().unwrap())
        .sum()
}

#[tokio::test]
async fn metrics_endpoint_reports_pipeline_and_token_activity() {
    let h = Harness::start().await;
    let metrics = spawn_router(attenuo_server::metrics::router(h.state.metrics.clone()))
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
        .basic_auth("coder", Some(CODER_SECRET))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": "coder",
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(child.status(), StatusCode::OK);

    // Two decisions through the shared pipeline (no policies are loaded, so both deny).
    let now = time::OffsetDateTime::now_utc();
    let chain = h.state.keys().verifier.verify(&token, now).unwrap().chain;
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

    attenuo_server::metrics::check_text_format(&text).unwrap();
    assert!(text.contains("# TYPE attenuo_decisions_total counter"));
    assert_eq!(decisions_total(&text), 3);
    assert_eq!(
        line_value(
            &text,
            "attenuo_decisions_total{decision=\"deny\",reason=\"audit_error\"} "
        ),
        1
    );
    assert_eq!(
        line_value(&text, "attenuo_tokens_issued_total{kind=\"root\"} "),
        1
    );
    assert_eq!(
        line_value(&text, "attenuo_tokens_issued_total{kind=\"exchange\"} "),
        1
    );
    assert_eq!(line_value(&text, "attenuo_leases_revoked_total "), 2);
    assert_eq!(line_value(&text, "attenuo_audit_append_errors_total "), 1);
    assert_eq!(
        line_value(
            &text,
            "attenuo_http_requests_total{route=\"/token\",status=\"200\"} "
        ),
        1
    );
    assert_eq!(
        line_value(
            &text,
            "attenuo_http_requests_total{route=\"/admin/leases/{lease_id}/revoke\",status=\"200\"} "
        ),
        1
    );
    assert_eq!(
        line_value(&text, "attenuo_authorize_duration_seconds_count "),
        3
    );
    assert_eq!(
        line_value(
            &text,
            "attenuo_authorize_duration_seconds_bucket{le=\"+Inf\"} "
        ),
        3
    );
}

/// The WAL checkpointer and the signed-checkpoint presync are exported: rounds by result,
/// the WAL sync ahead of a signed checkpoint, the time of the last complete round and of the
/// newest signed checkpoint. A file-backed store with a one-second checkpointer.
#[tokio::test]
async fn metrics_report_the_wal_checkpointer_and_presync() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.path().join("a.sqlite").to_string_lossy().into_owned();
    cfg.audit.wal_checkpoint_seconds = 1;
    // A presync is asked for `min(32, every / 2)` entries before each checkpoint: at 20 here.
    cfg.audit.checkpoint_every = 40;
    cfg.admin.token = Some("admin".into());
    cfg.dev.allow_root_mint = true;
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let h = Harness {
        server,
        state,
        _dir: dir,
    };
    let text = h.state.metrics.render();
    attenuo_server::metrics::check_text_format(&text).unwrap();
    assert!(text.contains("# TYPE attenuo_audit_wal_checkpoints_total counter\n"));
    assert!(text.contains("attenuo_audit_checkpoint_last_timestamp_seconds 0\n"));

    let root = h
        .admin_post(
            "/admin/root-token",
            json!({"subject": "alice", "issuer": "https://idp.example", "agent": "planner",
                   "capabilities": ["github:*"]}),
        )
        .await;
    let token = root["access_token"].as_str().unwrap().to_string();
    let now = time::OffsetDateTime::now_utc();
    let chain = h.state.keys().verifier.verify(&token, now).unwrap().chain;
    let call = ToolCall::new("github", "read_file", json!({}));
    // Past seq 40: one presync on the way, then a signed checkpoint.
    for _ in 0..40 {
        h.state.pipeline.decide(&chain, &call, now);
    }
    let mut text = String::new();
    for _ in 0..50 {
        text = h.state.metrics.render();
        let complete = line_value(
            &text,
            "attenuo_audit_wal_checkpoints_total{result=\"complete\"} ",
        );
        let presyncs = line_value(&text, "attenuo_audit_wal_presyncs_total{file=\"wal\"} ");
        if complete > 0 && presyncs > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    attenuo_server::metrics::check_text_format(&text).unwrap();
    assert!(
        line_value(
            &text,
            "attenuo_audit_wal_checkpoints_total{result=\"complete\"} "
        ) > 0,
        "{text}"
    );
    assert_eq!(
        line_value(&text, "attenuo_audit_wal_presyncs_total{file=\"wal\"} "),
        1,
        "{text}"
    );
    assert_eq!(
        line_value(
            &text,
            "attenuo_audit_wal_checkpoints_total{result=\"error\"} "
        ),
        0
    );
    let unix = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let last = line_value(&text, "attenuo_audit_wal_last_complete_timestamp_seconds ");
    assert!(last > 0 && last <= unix, "{last}");
    assert_eq!(line_value(&text, "attenuo_audit_checkpoints_total "), 1);
    let cp = line_value(&text, "attenuo_audit_checkpoint_last_timestamp_seconds ");
    assert!(cp > 0 && cp <= unix, "{cp}");
}

#[tokio::test]
async fn metrics_are_not_served_on_the_api_port() {
    let h = Harness::start().await;
    assert_eq!(h.get("/metrics").await.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------------------------

fn server_with_keys(
    dir: &std::path::Path,
    key: &str,
    previous: &[&str],
) -> (axum::Router, Arc<AppState>) {
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(dir.join(key));
    cfg.issuer.previous_key_paths = previous.iter().map(|p| dir.join(p)).collect();
    cfg.admin.token = Some("admin".into());
    cfg.dev.allow_root_mint = true;
    attenuo_server::build(&cfg).unwrap()
}

async fn mint_root(server: &Spawned) -> String {
    let r: Value = reqwest::Client::new()
        .post(server.url("/admin/root-token"))
        .bearer_auth("admin")
        .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                      "agent": "planner", "capabilities": ["github:*"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    r["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn rotation_keeps_old_tokens_valid_and_publishes_both_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (old_router, old_state) = server_with_keys(dir.path(), "old.pem", &[]);
    let old_server = spawn_router(old_router).await.unwrap();
    let old_token = mint_root(&old_server).await;
    let old_kid = old_state.keys().issuer.key_id();

    // Rotate: a new signing key, the old one verify-only.
    let (new_router, new_state) = server_with_keys(dir.path(), "new.pem", &["old.pem"]);
    let new_server = spawn_router(new_router).await.unwrap();
    assert_ne!(new_state.keys().issuer.key_id(), old_kid);

    // Same issuer/audience defaults, so the new server verifies the old token.
    let now = time::OffsetDateTime::now_utc();
    assert!(new_state.keys().verifier.verify(&old_token, now).is_ok());

    // And it can be exchanged for a child, which is signed with the new key.
    let child: Value = reqwest::Client::new()
        .post(new_server.url("/token"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": old_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": "coder",
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // The old token's lease is unknown to the new server's (empty) store, but the token
    // itself was accepted: the failure, if any, is about the lease, not the signature.
    let err = child["error_description"].as_str().unwrap_or_default();
    assert!(
        !err.contains("signature") && !err.contains("key id"),
        "{child}"
    );

    // The JWKS lists the new key first, then the old one.
    let jwks: Value = reqwest::get(new_server.url("/.well-known/jwks.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kids: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids, [new_state.keys().issuer.key_id(), old_kid.clone()]);

    // Without previous_key_paths the old token is rejected by kid.
    let (_r, solo) = server_with_keys(dir.path(), "new.pem", &[]);
    let err = solo.keys().verifier.verify(&old_token, now).unwrap_err();
    assert!(
        matches!(err, attenuo_token::TokenError::UnknownKeyId(ref k) if *k == old_kid),
        "{err}"
    );
}

#[tokio::test]
async fn previous_key_path_errors_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.issuer.previous_key_paths = vec![dir.path().join("missing.pem")];
    assert!(attenuo_server::build(&cfg).is_err());
    std::fs::write(dir.path().join("bad.pem"), "not a pem").unwrap();
    cfg.issuer.previous_key_paths = vec![dir.path().join("bad.pem")];
    assert!(attenuo_server::build(&cfg).is_err());
}

// ---------------------------------------------------------------------------------------------
// SR-38: the metrics listener must not be public by accident.
// ---------------------------------------------------------------------------------------------

#[test]
fn metrics_listener_off_loopback_needs_allow_public() {
    use attenuo_server::config::MetricsSection;
    let at = |addr: &str, enabled: bool, allow_public: bool| MetricsSection {
        enabled,
        listen: addr.parse().unwrap(),
        allow_public,
    };
    for ok in [
        at("127.0.0.1:9100", true, false),
        at("[::1]:9100", true, false),
        at("0.0.0.0:9100", false, false),
        at("0.0.0.0:9100", true, true),
        at("10.0.0.5:9100", true, true),
    ] {
        ok.check_listen().unwrap();
    }
    for bad in ["0.0.0.0:9100", "10.0.0.5:9100", "[::]:9100"] {
        let err = at(bad, true, false).check_listen().unwrap_err().to_string();
        assert!(err.contains("allow_public"), "{err}");
    }
}

#[tokio::test]
async fn server_refuses_to_start_with_a_public_metrics_listener() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.path().join("a.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some("admin".into());
    cfg.metrics.enabled = true;
    cfg.metrics.listen = "0.0.0.0:9100".parse().unwrap();
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("[metrics] listen"), "{err}");
    cfg.metrics.allow_public = true;
    let _ = attenuo_server::build(&cfg).unwrap();
}
