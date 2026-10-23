//! Regression tests for the Low findings closed together: SR-17 (error responses reveal
//! internals), SR-18 (log injection), SR-19 (Host-header poisoning of discovery) from
//! `docs/research/security-review-2026-10-22.md`, and SR-34 (reserved names and the admin
//! audit subject) from `docs/research/security-review-2026-10-23.md`.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::sync::{Arc, Mutex};

use onbehalf_audit::CheckpointKeys;
use onbehalf_core::{Capability, ToolCall};
use onbehalf_proxy::testing::{spawn_router, test_chain, Spawned};
use onbehalf_proxy::UpstreamConfig;
use onbehalf_server::config::{AgentConfig, AuthzenDiagnostics, CapSpec, RootGrant};
use onbehalf_server::Config;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ADMIN: &str = "0123456789abcdef0123456789abcdef-admin";
const PEP_SECRET: &str = "pep-secret-for-the-low-findings";

/// A config with the dev root mint, the admin token, a PEP and one upstream nobody listens on
/// (port 9), whose path stands in for an internal address.
fn base_config() -> Config {
    let mut cfg = Config::default();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.upstreams = vec![UpstreamConfig::new(
        "github",
        "http://127.0.0.1:9/internal-only-path",
    )];
    cfg.peps = vec![AgentConfig {
        id: "gateway".into(),
        secret_sha256: hex::encode(Sha256::digest(PEP_SECRET.as_bytes())),
    }];
    cfg
}

async fn start(cfg: &Config) -> Spawned {
    let (router, _state) = onbehalf_server::build(cfg).unwrap();
    spawn_router(router).await.unwrap()
}

async fn mint_root(server: &Spawned, subject: &str, agent: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(server.url("/admin/root-token"))
        .bearer_auth(ADMIN)
        .json(&json!({
            "subject": subject,
            "issuer": "https://idp.example",
            "agent": agent,
            "capabilities": ["github:read_file"],
        }))
        .send()
        .await
        .unwrap()
}

async fn root_token(server: &Spawned) -> (String, String) {
    let resp = mint_root(server, "alice", "planner").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    (
        v["access_token"].as_str().unwrap().to_string(),
        v["lease"].as_str().unwrap().to_string(),
    )
}

// ---------------------------------------------------------------------------------------------
// SR-17: reason codes only.
// ---------------------------------------------------------------------------------------------

/// SR-17: 401 bodies carried the verifier's reason (wrong key, malformed, expired ...). They
/// now carry a stable code, as `detail` and `error_description`, and nothing else.
#[tokio::test]
async fn unauthorized_bodies_carry_only_a_reason_code() {
    let server = start(&base_config()).await;
    // A well-formed token from another issuer: the verifier's complaint would name the key.
    let other = start(&base_config()).await;
    let (foreign, _) = root_token(&other).await;
    let client = reqwest::Client::new();

    let check = |resp: reqwest::Response, reason: &'static str| async move {
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let text = resp.text().await.unwrap();
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["error"], "unauthorized", "{text}");
        assert_eq!(body["detail"], reason, "{text}");
        assert_eq!(body["error_description"], reason, "{text}");
        for leak in ["kid", "signature", "audience", "issuer", "malformed"] {
            assert!(!text.contains(leak), "{leak}: {text}");
        }
    };

    let renew = |bearer: Option<&str>| {
        let mut req = client.post(server.url("/token/renew"));
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        req.send()
    };
    check(renew(None).await.unwrap(), "missing_token").await;
    check(renew(Some("not.a.jwt")).await.unwrap(), "invalid_token").await;
    check(renew(Some(&foreign)).await.unwrap(), "invalid_token").await;

    let eval = client
        .post(server.url("/access/v1/evaluation"))
        .bearer_auth(&foreign)
        .json(&json!({
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "read_file"},
            "resource": {"type": "tool", "id": "github/read_file",
                         "properties": {"server": "github"}},
        }))
        .send()
        .await
        .unwrap();
    check(eval, "invalid_token").await;

    let admin = client
        .get(server.url("/admin/audit"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    check(admin, "invalid_token").await;

    // The proxy answers in JSON-RPC, with the code in `data.reason`.
    let resp = client
        .post(server.url("/mcp/github"))
        .bearer_auth(&foreign)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let text = resp.text().await.unwrap();
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"]["data"]["reason"], "invalid_token", "{text}");
    assert!(!text.contains("kid"), "{text}");
}

/// SR-17: a failed upstream request answered `502` with the `reqwest` error, naming the
/// internal upstream URL.
#[tokio::test]
async fn upstream_failure_names_no_internal_url() {
    let server = start(&base_config()).await;
    let (token, _) = root_token(&server).await;
    let resp = reqwest::Client::new()
        .post(server.url("/mcp/github"))
        .bearer_auth(&token)
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let text = resp.text().await.unwrap();
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        body["error"]["data"]["reason"], "upstream_unreachable",
        "{text}"
    );
    assert!(
        !text.contains("127.0.0.1:9") && !text.contains("internal-only-path"),
        "{text}"
    );
}

async fn evaluate(server: &Spawned, token: &str, pep_secret: Option<&str>) -> reqwest::Response {
    let mut body = json!({
        "subject": {"type": "agent", "id": ""},
        "action": {"name": "delete_repo"},
        "resource": {"type": "tool", "id": "github/delete_repo",
                     "properties": {"server": "github"}},
        "context": {"input": {"repo": "acme/api"}},
    });
    if let Some(secret) = pep_secret {
        body["pep_id"] = json!("gateway");
        body["pep_secret"] = json!(secret);
    }
    reqwest::Client::new()
        .post(server.url("/access/v1/evaluation"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn diagnostics_of(resp: reqwest::Response) -> Vec<Value> {
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["decision"], false, "{v}");
    assert_eq!(v["context"]["reason"], "capability_denied", "{v}");
    v["context"]["diagnostics"].as_array().unwrap().clone()
}

/// SR-17: AuthZEN `diagnostics` (the effective capabilities, lease ids, Cedar errors) went to
/// every caller. By default only an authenticated `[[peps]]` caller gets them now;
/// `[authzen] diagnostics` can say `always` or `never`.
#[tokio::test]
async fn authzen_diagnostics_go_only_to_authenticated_peps() {
    let server = start(&base_config()).await;
    let (token, _) = root_token(&server).await;

    // A token holder alone: the reason code, no diagnostics.
    assert!(diagnostics_of(evaluate(&server, &token, None).await)
        .await
        .is_empty());
    // The same request from an authenticated PEP: the diagnostics name the capabilities.
    let d = diagnostics_of(evaluate(&server, &token, Some(PEP_SECRET)).await).await;
    assert!(d[0].as_str().unwrap().contains("github:read_file"), "{d:?}");
    // A wrong PEP secret is refused, not downgraded.
    let resp = evaluate(&server, &token, Some("wrong")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"], "invalid_client", "{v}");

    for (mode, anonymous, pep) in [
        (AuthzenDiagnostics::Always, true, true),
        (AuthzenDiagnostics::Never, false, false),
    ] {
        let mut cfg = base_config();
        cfg.authzen.diagnostics = mode;
        let server = start(&cfg).await;
        let (token, _) = root_token(&server).await;
        let a = diagnostics_of(evaluate(&server, &token, None).await).await;
        assert_eq!(!a.is_empty(), anonymous, "{mode:?}");
        let p = diagnostics_of(evaluate(&server, &token, Some(PEP_SECRET)).await).await;
        assert_eq!(!p.is_empty(), pep, "{mode:?}");
    }
    assert_eq!(
        Config::from_toml("[authzen]\ndiagnostics = \"never\"\n")
            .unwrap()
            .authzen
            .diagnostics,
        AuthzenDiagnostics::Never
    );
    assert_eq!(
        Config::default().authzen.diagnostics,
        AuthzenDiagnostics::Peps
    );
}

// ---------------------------------------------------------------------------------------------
// SR-18: log injection.
// ---------------------------------------------------------------------------------------------

/// A `MakeWriter` that appends every log line to a shared buffer.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// SR-18: the decision log line formatted subject, agent, server and tool with `Display`, so a
/// newline in any of them forged a second line. Each is Debug-formatted now.
#[test]
fn a_newline_in_a_tool_name_stays_on_one_log_line() {
    let logs = LogBuf::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let (_router, state) = onbehalf_server::build(&base_config()).unwrap();
    let chain = test_chain(
        "alice\nFORGED subject",
        "planner\nFORGED agent",
        [Capability::new("github", "*")],
    );
    let call = ToolCall::new("github", "read_file\nFORGED level=INFO decision", json!({}));
    tracing::subscriber::with_default(subscriber, || {
        // The lease is unknown, so this is a deny; it is logged either way.
        let d = state
            .pipeline
            .decide(&chain, &call, time::OffsetDateTime::now_utc());
        assert!(!d.is_allow());
    });
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains(r#"tool="read_file\nFORGED"#), "{text}");
    assert!(text.contains(r#"subject="alice\nFORGED"#), "{text}");
}

// ---------------------------------------------------------------------------------------------
// SR-19: discovery URLs.
// ---------------------------------------------------------------------------------------------

/// SR-19: off loopback, the server refuses to start without `[server] public_url`, since the
/// discovery document would otherwise be built from the request's `Host` header.
#[test]
fn public_url_is_required_off_loopback() {
    let mut cfg = base_config();
    cfg.server.listen = "0.0.0.0:8080".parse().unwrap();
    let err = onbehalf_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("public_url"), "{err}");
    cfg.server.public_url = Some("https://onbehalf.example.com".into());
    let _ = onbehalf_server::build(&cfg).unwrap();
    for bad in [
        "onbehalf.example.com",
        "https://",
        "https://a.example/?x=1",
        "https://a.example/#f",
        "https://a.example /",
    ] {
        cfg.server.public_url = Some(bad.into());
        assert!(onbehalf_server::build(&cfg).is_err(), "{bad}");
    }
}

async fn discovery(server: &Spawned, host: Option<&str>) -> reqwest::Response {
    let mut req = reqwest::Client::new().get(server.url("/.well-known/authzen-configuration"));
    if let Some(h) = host {
        req = req.header("host", h);
    }
    req.send().await.unwrap()
}

/// SR-19: with `public_url` set, discovery uses it whatever `Host` says.
#[tokio::test]
async fn discovery_uses_public_url_and_ignores_host() {
    let mut cfg = base_config();
    cfg.server.public_url = Some("https://onbehalf.example.com/".into());
    let server = start(&cfg).await;
    let resp = discovery(&server, Some("attacker.example")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["policy_decision_point"], "https://onbehalf.example.com");
    assert_eq!(
        v["access_evaluation_endpoint"],
        "https://onbehalf.example.com/access/v1/evaluation"
    );
}

/// SR-19: on loopback without `public_url`, only a loopback `Host` is echoed; anything else
/// is 400 `invalid_host`.
#[tokio::test]
async fn discovery_without_public_url_accepts_only_loopback_hosts() {
    let server = start(&base_config()).await;
    for host in [
        "localhost",
        "localhost:8080",
        "127.0.0.1:1234",
        "[::1]:80",
        "[::1]",
    ] {
        let resp = discovery(&server, Some(host)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{host}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["policy_decision_point"], format!("http://{host}"));
    }
    for host in [
        "attacker.example",
        "localhost.attacker.example",
        "127.0.0.1.nip.io",
        "localhost:80:80",
        "localhost:x",
        "[::1]evil",
    ] {
        let resp = discovery(&server, Some(host)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{host}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"], "invalid_host", "{host}");
    }
}

// ---------------------------------------------------------------------------------------------
// SR-34: reserved names and the admin subject.
// ---------------------------------------------------------------------------------------------

/// SR-34: the server name `onbehalf` was already reserved for upstreams; agents, PEPs and
/// root grants may not use it as an agent id either.
#[test]
fn the_agent_id_onbehalf_is_reserved() {
    let agent = |id: &str| AgentConfig {
        id: id.into(),
        secret_sha256: hex::encode(Sha256::digest(b"s")),
    };
    let mut cfg = Config::default();
    cfg.agents = vec![agent("onbehalf")];
    assert!(cfg
        .check_server_names()
        .unwrap_err()
        .to_string()
        .contains("reserved"));
    let mut cfg = Config::default();
    cfg.peps = vec![agent("onbehalf")];
    assert!(cfg.check_server_names().is_err());
    let mut cfg = Config::default();
    cfg.root_grants = vec![RootGrant {
        subject: None,
        issuer: "https://idp.example".into(),
        agent: "onbehalf".into(),
        capabilities: vec![CapSpec::Short("github:*".into())],
        attributes: Default::default(),
        may_act: None,
    }];
    assert!(cfg.check_server_names().is_err());
    // A root-grant capability or catalog entry on the server `onbehalf` is refused too.
    let mut cfg = Config::default();
    cfg.root_grants = vec![RootGrant {
        subject: None,
        issuer: "https://idp.example".into(),
        agent: "planner".into(),
        capabilities: vec![CapSpec::Short("onbehalf:admin.lease.revoke".into())],
        attributes: Default::default(),
        may_act: None,
    }];
    assert!(cfg.check_server_names().is_err());
    let cfg = Config::from_toml("[policy.catalog.onbehalf.\"token.exchange\"]\n").unwrap();
    let err = cfg.check_server_names().unwrap_err().to_string();
    assert!(err.contains("reserved"), "{err}");
}

/// SR-34: admin actions were audited with `originating_subject = "admin"`, which a real user
/// can have. They now use `urn:onbehalf:admin`, and no user can get a subject under the
/// `urn:onbehalf:` prefix. The log with those records still exports and verifies.
#[tokio::test]
async fn admin_records_use_a_subject_no_user_can_have() {
    let server = start(&base_config()).await;
    let client = reqwest::Client::new();

    for subject in ["urn:onbehalf:admin", "URN:OnBehalf:anything"] {
        let resp = mint_root(&server, subject, "planner").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{subject}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error_description"], "reserved_subject", "{v}");
    }
    let resp = mint_root(&server, "alice", "onbehalf").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // A user called `admin` is an ordinary user.
    assert_eq!(
        mint_root(&server, "admin", "planner").await.status(),
        StatusCode::OK
    );

    let (_, lease) = root_token(&server).await;
    let resp = client
        .post(server.url(&format!("/admin/leases/{lease}/revoke")))
        .bearer_auth(ADMIN)
        .json(&json!({"reason": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let export = client
        .get(server.url("/admin/audit/export"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let parsed = onbehalf_audit::export::parse_export(&export).unwrap();
    let admin: Vec<(&str, &str)> = parsed
        .entries
        .iter()
        .filter(|e| e.record.server == "onbehalf" && e.record.tool.starts_with("admin."))
        .map(|e| {
            (
                e.record.originating_subject.as_str(),
                e.record.tool.as_str(),
            )
        })
        .collect();
    assert_eq!(
        admin,
        vec![
            ("urn:onbehalf:admin", "admin.root_token"),
            ("urn:onbehalf:admin", "admin.root_token"),
            ("urn:onbehalf:admin", "admin.lease.revoke"),
        ]
    );
    // The user `admin`'s own issuance record is not an admin record.
    assert!(parsed
        .entries
        .iter()
        .any(|e| e.record.originating_subject == "admin" && e.record.tool == "token.root"));

    let jwks: Value = client
        .get(server.url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys = CheckpointKeys::from_jwks(&jwks).unwrap();
    // No checkpoint was asked for, so every entry is in the unsigned tail.
    let allow = onbehalf_audit::VerifyOptions {
        allow_unsigned_tail: true,
    };
    let report = onbehalf_audit::export::verify_export_with(&parsed, &keys, allow).unwrap();
    assert!(report.report.ok, "{report:?}");
    let online: Value = client
        .get(server.url("/admin/audit/verify"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(online["ok"], true, "{online}");
}
