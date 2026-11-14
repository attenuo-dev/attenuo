//! Hardening of the server's error bodies, logs, discovery and reserved names: regression tests
//! for the Low findings closed together, SR-17 (error responses reveal internals), SR-18 (log
//! injection) and SR-19 (Host-header poisoning of discovery) from
//! `docs/research/security-review-2026-10-22.md`, and SR-30 (release workflow actions pinned
//! to commits) and SR-34 (reserved names and the admin audit subject) from
//! `docs/research/security-review-2026-10-23.md`, and SR-90 (request spans record the route
//! template, not the URI) from `docs/research/security-review-2026-11-05-pass8.md`. Formerly
//! `security_low.rs`; the SR-30 test and the SR-34 server-name test came from
//! `security_pass3.rs`.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use attenuo_audit::CheckpointKeys;
use attenuo_core::{Capability, ToolCall};
use attenuo_proxy::testing::{spawn_router, test_chain, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::{AgentConfig, AuthzenDiagnostics, CapSpec, RootGrant};
use attenuo_server::Config;
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
    cfg.peps = vec![AgentConfig::with_secret_sha256(
        "gateway",
        hex::encode(Sha256::digest(PEP_SECRET.as_bytes())),
    )];
    cfg
}

async fn start(cfg: &Config) -> Spawned {
    let (router, _state) = attenuo_server::build(cfg).unwrap();
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

thread_local! {
    /// The capture buffer of the test running on this thread, if any.
    static CAPTURE: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// Lines written on threads without a capture buffer of their own (the blocking pool a route
/// handler runs on), while a test that needs them has turned this on. Tests running at the same
/// time may write here too, so a test filters what it reads by a marker of its own.
static SHARED_CAPTURE: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

/// Writes to the calling thread's capture buffer, else to [`SHARED_CAPTURE`] when that is on,
/// and discards output otherwise.
struct ThreadCapture;

impl std::io::Write for ThreadCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mine = CAPTURE.with(|c| match c.borrow_mut().as_mut() {
            Some(v) => {
                v.extend_from_slice(buf);
                true
            }
            None => false,
        });
        if !mine {
            if let Some(v) = SHARED_CAPTURE
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_mut()
            {
                v.extend_from_slice(buf);
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs, once per process, a global subscriber that writes to [`CAPTURE`].
///
/// A scoped `with_default` subscriber is not enough here: `tracing` caches each callsite's
/// "interest" process-wide, and a callsite first hit by another test thread (with no subscriber
/// active) can be cached as disabled, so the capturing test then saw no output at all (observed
/// as `0 != 1` lines under load). A global subscriber keeps every callsite enabled, and the
/// per-thread buffer keeps tests from seeing each other's lines.
fn install_capture() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // `tower_http=debug` for the SR-90 request span; everything else at the default `info`.
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| ThreadCapture)
            .with_env_filter(tracing_subscriber::EnvFilter::new("info,tower_http=debug"))
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other test in this binary may install a global subscriber");
    });
}

/// SR-18: the decision log line formatted subject, agent, server and tool with `Display`, so a
/// newline in any of them forged a second line. Each is Debug-formatted now.
#[test]
fn a_newline_in_a_tool_name_stays_on_one_log_line() {
    install_capture();
    let (_router, state) = attenuo_server::build(&base_config()).unwrap();
    let chain = test_chain(
        "alice\nFORGED subject",
        "planner\nFORGED agent",
        [Capability::new("github", "*")],
    );
    let call = ToolCall::new("github", "read_file\nFORGED level=INFO decision", json!({}));
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    // The lease is unknown, so this is a deny; it is logged either way.
    let d = state
        .pipeline
        .decide(&chain, &call, time::OffsetDateTime::now_utc());
    let captured = CAPTURE.with(|c| c.borrow_mut().take()).unwrap();
    assert!(!d.is_allow());
    let text = String::from_utf8(captured).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains(r#"tool="read_file\nFORGED"#), "{text}");
    assert!(text.contains(r#"subject="alice\nFORGED"#), "{text}");
}

/// SR-115: the `AuthZEN action search` log line wrote the request's `server` with `Display`,
/// so a newline in `resource.properties.server` forged a second log line, as SR-18 did for the
/// decision line. It is Debug-formatted now.
#[tokio::test]
async fn a_newline_in_an_action_search_server_stays_on_one_log_line_sr115() {
    install_capture();
    let server = start(&base_config()).await;
    let (token, _) = root_token(&server).await;
    *SHARED_CAPTURE.lock().unwrap() = Some(Vec::new());
    let resp = reqwest::Client::new()
        .post(server.url("/access/v1/search/action"))
        .bearer_auth(&token)
        .json(&json!({
            "subject": {"type": "agent", "id": ""},
            "resource": {"type": "mcp_server", "id": "x",
                         "properties": {"server": "gh\nFORGED-SR115 level=INFO decision"}},
        }))
        .send()
        .await
        .unwrap();
    let captured = SHARED_CAPTURE.lock().unwrap().take().unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = String::from_utf8(captured).unwrap();
    let marked: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("FORGED-SR115"))
        .collect();
    assert_eq!(marked.len(), 1, "{text}");
    assert!(marked[0].contains("AuthZEN action search"), "{text}");
    assert!(marked[0].contains(r#"server="gh\nFORGED-SR115"#), "{text}");
}

/// SR-90: tower-http's default request span recorded the full URI, query string included, so
/// `RUST_LOG=tower_http=debug` wrote `GET /admin/audit?subject=...` to the log. The span on the
/// API router, the proxy router and the console listener now records the route template only.
#[tokio::test]
async fn request_spans_carry_the_route_template_not_the_uri() {
    install_capture();
    let mut cfg = base_config();
    cfg.admin_ui.enabled = true;
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let main = spawn_router(router).await.unwrap();
    let console = spawn_router(attenuo_server::admin_ui::router(state, &cfg))
        .await
        .unwrap();
    let client = reqwest::Client::new();
    // The `current_thread` test runtime serves these on this thread, so the capture sees them.
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let audit = client
        .get(main.url("/admin/audit?subject=secret-marker"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(audit.status(), StatusCode::OK);
    let mcp = client
        .post(main.url("/mcp/github?subject=secret-marker"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(mcp.status(), StatusCode::UNAUTHORIZED);
    let ui = client
        .get(console.url("/admin/audit?subject=secret-marker"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(ui.status(), StatusCode::OK);
    let unmatched = client
        .get(console.url("/secret-marker?subject=secret-marker"))
        .send()
        .await
        .unwrap();
    assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);
    let text = String::from_utf8(CAPTURE.with(|c| c.borrow_mut().take()).unwrap()).unwrap();
    let spans = |route: &str| {
        text.lines()
            .filter(|l| l.contains(&format!("request{{method=GET route={route} ")))
            .count()
    };
    assert!(spans("/admin/audit") >= 2, "{text}");
    assert!(spans("unmatched") >= 1, "{text}");
    assert!(
        text.lines()
            .any(|l| l.contains("request{method=POST route=/mcp/{server} ")),
        "{text}"
    );
    assert!(!text.contains("secret-marker"), "{text}");
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
    // The dev root mint is refused off loopback (S-3), and the admin API on the main listener
    // (S-1), which is not what this test is about.
    cfg.dev.allow_root_mint = false;
    cfg.admin.listen = Some("127.0.0.1:9102".parse().unwrap());
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("public_url"), "{err}");
    cfg.server.public_url = Some("https://attenuo.example.com".into());
    let _ = attenuo_server::build(&cfg).unwrap();
    for bad in [
        "attenuo.example.com",
        "https://",
        "https://a.example/?x=1",
        "https://a.example/#f",
        "https://a.example /",
    ] {
        cfg.server.public_url = Some(bad.into());
        assert!(attenuo_server::build(&cfg).is_err(), "{bad}");
    }
}

/// S-9: off loopback, an `http://` `public_url` with a host that is not loopback stops the
/// server unless `allow_insecure_http`; an https URL (TLS at a reverse proxy) needs nothing.
#[test]
fn plain_http_public_url_off_loopback_is_refused_at_startup_s9() {
    let mut cfg = base_config();
    cfg.server.listen = "0.0.0.0:8080".parse().unwrap();
    cfg.dev.allow_root_mint = false;
    cfg.admin.listen = Some("127.0.0.1:9102".parse().unwrap());
    cfg.server.public_url = Some("http://attenuo.example.com".into());
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("allow_insecure_http"), "{err}");
    cfg.server.allow_insecure_http = true;
    let _ = attenuo_server::build(&cfg).unwrap();
    cfg.server.allow_insecure_http = false;
    cfg.server.public_url = Some("https://attenuo.example.com".into());
    let _ = attenuo_server::build(&cfg).unwrap();
    // A container that binds 0.0.0.0 but is reached on the host's loopback.
    cfg.server.public_url = Some("http://127.0.0.1:8080".into());
    let _ = attenuo_server::build(&cfg).unwrap();
}

/// S-3: the dev root mint stops the server off loopback unless the demo-only opt-in is set.
/// What counts is the listener the admin API is on: the main one here (S-1 opt-in), a
/// loopback `[admin] listen` at the end.
#[test]
fn dev_root_mint_off_loopback_is_refused_at_startup_s3() {
    let mut cfg = base_config();
    cfg.server.listen = "0.0.0.0:8080".parse().unwrap();
    cfg.server.public_url = Some("https://attenuo.example.com".into());
    cfg.admin.serve_on_main_listener = true;
    assert!(cfg.dev.allow_root_mint, "base_config turns the mint on");
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("allow_root_mint"), "{err}");
    cfg.dev.allow_root_mint_off_loopback = true;
    let _ = attenuo_server::build(&cfg).unwrap();
    cfg.dev.allow_root_mint_off_loopback = false;
    // On an admin listener of its own the mint is judged by that listener's address.
    cfg.admin.serve_on_main_listener = false;
    cfg.admin.listen = Some("0.0.0.0:9102".parse().unwrap());
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("allow_root_mint"), "{err}");
    cfg.admin.listen = Some("127.0.0.1:9102".parse().unwrap());
    let _ = attenuo_server::build(&cfg).unwrap();
    cfg.admin.listen = None;
    cfg.server.listen = "127.0.0.1:8080".parse().unwrap();
    let _ = attenuo_server::build(&cfg).unwrap();
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
    cfg.server.public_url = Some("https://attenuo.example.com/".into());
    let server = start(&cfg).await;
    let resp = discovery(&server, Some("attacker.example")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["policy_decision_point"], "https://attenuo.example.com");
    assert_eq!(
        v["access_evaluation_endpoint"],
        "https://attenuo.example.com/access/v1/evaluation"
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

/// SR-34: an upstream named `attenuo` wrote tool-call audit records under the server name the
/// server uses for its own events (`token.exchange`, `lease.renew`, `admin.*`).
#[test]
fn the_server_name_attenuo_is_reserved() {
    let mut cfg = Config::default();
    cfg.upstreams = vec![UpstreamConfig::new("attenuo", "http://127.0.0.1:9/mcp")];
    let err = cfg.check_server_names().unwrap_err().to_string();
    assert!(err.contains("reserved"), "{err}");
    cfg.upstreams = vec![UpstreamConfig::new("github", "http://127.0.0.1:9/mcp")];
    cfg.check_server_names().unwrap();
}

/// SR-34: the server name `attenuo` was already reserved for upstreams; agents, PEPs and
/// root grants may not use it as an agent id either.
#[test]
fn the_agent_id_attenuo_is_reserved() {
    let agent = |id: &str| AgentConfig::with_secret_sha256(id, hex::encode(Sha256::digest(b"s")));
    let mut cfg = Config::default();
    cfg.agents = vec![agent("attenuo")];
    assert!(cfg
        .check_server_names()
        .unwrap_err()
        .to_string()
        .contains("reserved"));
    let mut cfg = Config::default();
    cfg.peps = vec![agent("attenuo")];
    assert!(cfg.check_server_names().is_err());
    let mut cfg = Config::default();
    cfg.root_grants = vec![RootGrant {
        subject: None,
        issuer: "https://idp.example".into(),
        agent: "attenuo".into(),
        capabilities: vec![CapSpec::Short("github:*".into())],
        attributes: Default::default(),
        may_act: None,
    }];
    let err = cfg.check_server_names().unwrap_err().to_string();
    assert!(err.contains("reserved"), "{err}");
    assert!(err.starts_with("[[root_grants]] entry 0 "), "{err}");
    // A root-grant capability or catalog entry on the server `attenuo` is refused too.
    let mut cfg = Config::default();
    cfg.root_grants = vec![RootGrant {
        subject: None,
        issuer: "https://idp.example".into(),
        agent: "planner".into(),
        capabilities: vec![CapSpec::Short("attenuo:admin.lease.revoke".into())],
        attributes: Default::default(),
        may_act: None,
    }];
    let err = cfg.check_server_names().unwrap_err().to_string();
    assert!(err.contains("reserved"), "{err}");
    assert!(err.starts_with("[[root_grants]] entry 0 "), "{err}");
    let cfg = Config::from_toml("[policy.catalog.attenuo.\"token.exchange\"]\n").unwrap();
    let err = cfg.check_server_names().unwrap_err().to_string();
    assert!(err.contains("reserved"), "{err}");
}

/// SR-34: admin actions were audited with `originating_subject = "admin"`, which a real user
/// can have. They now use `urn:attenuo:admin`, and no user can get a subject under the
/// `urn:attenuo:` prefix. The log with those records still exports and verifies.
#[tokio::test]
async fn admin_records_use_a_subject_no_user_can_have() {
    let server = start(&base_config()).await;
    let client = reqwest::Client::new();

    for subject in ["urn:attenuo:admin", "URN:Attenuo:anything"] {
        let resp = mint_root(&server, subject, "planner").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{subject}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error_description"], "reserved_subject", "{v}");
    }
    let resp = mint_root(&server, "alice", "attenuo").await;
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
    let parsed = attenuo_audit::export::parse_export(&export).unwrap();
    let admin: Vec<(&str, &str)> = parsed
        .entries
        .iter()
        .filter(|e| e.record.server == "attenuo" && e.record.tool.starts_with("admin."))
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
            ("urn:attenuo:admin", "admin.root_token"),
            ("urn:attenuo:admin", "admin.root_token"),
            ("urn:attenuo:admin", "admin.lease.revoke"),
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
    let allow = attenuo_audit::VerifyOptions {
        allow_unsigned_tail: true,
    };
    let report = attenuo_audit::export::verify_export_with(&parsed, &keys, allow).unwrap();
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

// ---------------------------------------------------------------------------------------------
// SR-30: the release workflow.
// ---------------------------------------------------------------------------------------------

/// SR-30: the release workflow holds `packages: write`, `id-token: write` (keyless signing)
/// and `contents: write`. Every action it runs must be pinned to a full commit SHA, so a moved
/// tag in a third-party action cannot publish or sign an image in this repository's name, and
/// the release build must not restore a cache other workflows can write.
#[test]
fn release_workflow_actions_are_pinned_to_commits() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/release.yml"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut seen = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some(spec) = line
            .strip_prefix("- uses:")
            .or_else(|| line.strip_prefix("uses:"))
        else {
            continue;
        };
        let spec = spec.trim();
        let (_, reference) = spec
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("`{spec}` has no ref"));
        assert!(
            reference.len() == 40 && reference.bytes().all(|b| b.is_ascii_hexdigit()),
            "`{spec}` is not pinned to a commit SHA"
        );
        seen += 1;
    }
    assert!(seen >= 10, "found only {seen} `uses:` lines");
    assert!(
        !text.contains("Swatinem/rust-cache"),
        "the release build must not restore a shared cargo cache"
    );
}

/// Every `[[root_grants]]` refusal at start names the entry the way the limits one does (its
/// index from 0, issuer, agent and subject), then gives the reason it gave before: a reserved
/// agent id, a capability that does not parse, an invalid tool name and a reserved server
/// name. The SR-123 size bound is checked in `tests/run_limits.rs`.
#[test]
fn root_grant_refusals_name_the_entry() {
    let grant = |agent: &str, subject: Option<&str>, cap: &str| RootGrant {
        subject: subject.map(Into::into),
        issuer: "https://idp.example".into(),
        agent: agent.into(),
        capabilities: vec![CapSpec::Short(cap.into())],
        attributes: Default::default(),
        may_act: None,
    };
    for (agent, cap, reason) in [
        (
            "attenuo",
            "github:*",
            "agent id `attenuo` is reserved for the server's own records",
        ),
        (
            "planner",
            "github",
            "capability `github` must look like `server:tool`",
        ),
        ("planner", "github:a//b", "which is not allowed"),
        (
            "planner",
            "attenuo:admin.lease.revoke",
            "server name `attenuo` is reserved for the server's own audit records",
        ),
    ] {
        let mut cfg = Config::default();
        cfg.root_grants = vec![
            grant("planner", None, "github:*"),
            grant(agent, Some("alice"), cap),
        ];
        let err = cfg.check_server_names().unwrap_err().to_string();
        let entry = format!(
            "[[root_grants]] entry 1 (issuer \"https://idp.example\", agent \"{agent}\", \
             subject \"alice\"): "
        );
        assert!(err.starts_with(&entry), "{err}");
        assert!(err.contains(reason), "{err}");
    }
}

/// A `[[root_grants]]` capability whose limits no token may carry refuses to start, naming the
/// entry, the capability and the reason; it used to start and then fail every mint under the
/// grant with `invalid_capability` (the `[[root_grants]]` follow-up of SR-125). A grant with
/// well-formed limits still starts and mints.
#[tokio::test]
async fn root_grant_limits_no_token_may_carry_refuse_to_start() {
    let grant = |subject: Option<&str>, limits: Value| RootGrant {
        subject: subject.map(Into::into),
        issuer: "https://idp.example".into(),
        agent: "planner".into(),
        capabilities: vec![CapSpec::Full(
            serde_json::from_value(json!({"server": "github", "tool": "*", "limits": limits}))
                .unwrap(),
        )],
        attributes: Default::default(),
        may_act: None,
    };
    for (limits, reason) in [
        (json!({"sum": {"arg": "", "max": 1}}), "`arg` is empty"),
        (
            json!({"sum": {"arg": "n", "max": 1, "derive": "host"}}),
            "takes no `derive`",
        ),
    ] {
        let mut cfg = base_config();
        cfg.root_grants = vec![
            grant(None, json!({"calls": 5})),
            grant(Some("alice"), limits),
        ];
        let err = attenuo_server::build(&cfg)
            .err()
            .expect("must refuse")
            .to_string();
        assert!(
            err.starts_with(
                "[[root_grants]] entry 1 (issuer \"https://idp.example\", agent \"planner\", \
                 subject \"alice\"): limit `sum` of capability `github:* limits="
            ),
            "{err}"
        );
        assert!(err.contains(reason), "{err}");
        assert!(
            err.ends_with("no token may carry it, so every mint under this grant would fail"),
            "{err}"
        );
    }
    // SR-130: under `[logging] redact_subjects` the refusal does not write the subject out;
    // the index still names the entry.
    let mut cfg = base_config();
    cfg.logging.redact_subjects = true;
    cfg.root_grants = vec![
        grant(None, json!({"calls": 5})),
        grant(
            Some("alice@example.com"),
            json!({"sum": {"arg": "", "max": 1}}),
        ),
    ];
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("must refuse")
        .to_string();
    assert!(
        err.starts_with(
            "[[root_grants]] entry 1 (issuer \"https://idp.example\", agent \"planner\", \
             a subject (not shown: [logging] redact_subjects)): limit `sum`"
        ),
        "{err}"
    );
    assert!(!err.contains("alice"), "{err}");

    // Well-formed limits start, and a mint under the grant succeeds.
    let mut cfg = base_config();
    cfg.root_grants = vec![grant(
        None,
        json!({"calls": 5, "sum": {"arg": "n", "max": 9}}),
    )];
    let server = start(&cfg).await;
    assert_eq!(
        mint_root(&server, "alice", "planner").await.status(),
        StatusCode::OK
    );
}
