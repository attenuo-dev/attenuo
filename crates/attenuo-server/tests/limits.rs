//! `[limits]` over real connections (audit finding S-4): the per-run MCP rate limit, the
//! per-agent and per-peer `POST /token` limits, the in-flight cap with the body deadline, and
//! streams that neither the handler deadline nor the cap may cut. The servers run through
//! `attenuo_server::run`, so requests go through the server's own accept loop.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::{AppState, Config};
use futures_util::StreamExt as _;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use common::{agent_configs, Running};

const ADMIN: &str = "test-admin-token";
const AGENTS: &[&str] = &["coder", "reviewer"];

fn secret(id: &str) -> String {
    format!("{id}-secret")
}

const POLICY: &str = r#"
@id("reads")
permit(principal, action == Action::"github/read_file", resource);
"#;

struct Harness {
    _upstream: Spawned,
    running: Option<Running>,
    state: Arc<AppState>,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start(tweak: impl FnOnce(&mut Config)) -> Self {
        Self::start_against(FakeMcpServer::new(&["read_file"]), tweak).await
    }

    async fn start_against(upstream: FakeMcpServer, tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let upstream = upstream.spawn().await.unwrap();
        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.policy.policies_path = Some(policy_path);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([(
                "read_file".to_string(),
                ToolAttrs::new()
                    .with_input("repo", ArgType::String)
                    .readonly(true),
            )]),
        )]);
        cfg.audit.sqlite_path = ":memory:".into();
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = agent_configs(AGENTS, secret);
        tweak(&mut cfg);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let running = Running::start(cfg, state.clone(), router).await;
        Self {
            _upstream: upstream,
            running: Some(running),
            state,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    fn url(&self, path: &str) -> String {
        self.running.as_ref().unwrap().url(path)
    }

    fn addr(&self) -> String {
        self.url("").trim_start_matches("http://").to_string()
    }

    /// Stop the server and wait until it has let go of its state.
    async fn stop(self) {
        let Self { running, state, .. } = self;
        running.unwrap().stop(state).await;
    }

    /// A root token for `subject`, from the dev mint (no `POST /token`, so no token limit).
    async fn mint_root(&self, subject: &str, agent: &str) -> String {
        let resp = self
            .client
            .post(self.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": subject,
                "issuer": "https://idp.example",
                "agent": agent,
                "capabilities": ["github:read_file"],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json::<Value>().await.unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `POST /token` exchanging `parent` for `actor`, authenticated as `client`.
    async fn exchange(&self, parent: &str, actor: &str, client: (&str, &str)) -> reqwest::Response {
        self.client
            .post(self.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "attenuo_capabilities",
                    "capabilities": [{"server": "github", "tool": "read_file"}]}],
                "client_id": client.0,
                "client_secret": client.1,
            }))
            .send()
            .await
            .unwrap()
    }

    async fn list(&self, token: &str) -> reqwest::Response {
        self.client
            .post(self.url("/mcp/github"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .send()
            .await
            .unwrap()
    }

    fn metrics(&self) -> String {
        self.state.metrics.render()
    }
}

fn retry_after(resp: &reqwest::Response) -> u64 {
    resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// `mcp_requests_per_minute`: a run gets N requests a minute, its N+1st is `429` with
/// `Retry-After` and JSON-RPC `-32007` `rate_limited`, a delegated token of the same run
/// shares the count, and another run is not touched.
#[tokio::test]
async fn the_mcp_rate_limit_is_per_run() {
    let h = Harness::start(|c| c.limits.mcp_requests_per_minute = 3).await;
    let alice = h.mint_root("alice", "planner").await;
    let bob = h.mint_root("bob", "planner").await;
    for _ in 0..2 {
        assert_eq!(h.list(&alice).await.status(), StatusCode::OK);
    }
    // A child of alice's run, used once: the third request of the run.
    let child = h
        .exchange(&alice, "coder", ("coder", &secret("coder")))
        .await;
    assert_eq!(child.status(), StatusCode::OK);
    let child = child.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(h.list(&child).await.status(), StatusCode::OK);
    for token in [&alice, &child] {
        let resp = h.list(token).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!((1..=60).contains(&retry_after(&resp)));
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"]["code"], attenuo_proxy::jsonrpc::CODE_TOO_MANY);
        assert_eq!(v["error"]["data"]["reason"], "rate_limited");
        assert!(v["id"].is_null());
    }
    assert_eq!(h.list(&bob).await.status(), StatusCode::OK);
    // A bad token is still a 401, not counted against anyone.
    assert_eq!(
        h.list("not-a-token").await.status(),
        StatusCode::UNAUTHORIZED
    );
    let m = h.metrics();
    assert!(
        m.contains("attenuo_requests_rate_limited_total{limit=\"mcp\",cause=\"limit\"} 2\n"),
        "{m}"
    );
    assert!(m.contains("attenuo_requests_rate_limited_total{limit=\"token\",cause=\"limit\"} 0\n"));
    h.stop().await;
}

/// `token_requests_per_minute`: an agent gets N token requests a minute (refused ones count:
/// they did the work), the next is `429` `rate_limited` with `Retry-After`; another agent is
/// not touched.
#[tokio::test]
async fn the_token_rate_limit_is_per_agent() {
    let h = Harness::start(|c| c.limits.token_requests_per_minute = 2).await;
    let root = h.mint_root("alice", "planner").await;
    let coder = ("coder", secret("coder"));
    let coder = (coder.0, coder.1.as_str());
    assert_eq!(
        h.exchange(&root, "coder", coder).await.status(),
        StatusCode::OK
    );
    // A second exchange of the same parent for the same actor is refused as a replay, and
    // still counts.
    assert_eq!(
        h.exchange(&root, "coder", coder).await.status(),
        StatusCode::BAD_REQUEST
    );
    let resp = h.exchange(&root, "coder", coder).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!((1..=60).contains(&retry_after(&resp)));
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"], "rate_limited");
    assert_eq!(v["error_description"], "rate_limited");
    let reviewer = secret("reviewer");
    assert_eq!(
        h.exchange(&root, "reviewer", ("reviewer", &reviewer))
            .await
            .status(),
        StatusCode::OK
    );
    assert!(h
        .metrics()
        .contains("attenuo_requests_rate_limited_total{limit=\"token\",cause=\"limit\"} 1\n"));
    h.stop().await;
}

/// `token_unauthenticated_requests_per_minute`: requests that authenticate no agent count
/// against the peer address; once it has used them up, every `POST /token` from it is refused
/// before any work, a good client's too. Authenticated requests never count against the peer.
#[tokio::test]
async fn unauthenticated_token_requests_are_limited_per_peer() {
    let h = Harness::start(|c| c.limits.token_unauthenticated_requests_per_minute = 2).await;
    let root = h.mint_root("alice", "planner").await;
    let coder = secret("coder");
    // Authenticated requests from the same address, more than the peer's limit.
    for _ in 0..3 {
        let status = h.exchange(&root, "coder", ("coder", &coder)).await.status();
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
    }
    for _ in 0..2 {
        let resp = h.exchange(&root, "coder", ("coder", "wrong")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let resp = h.exchange(&root, "coder", ("coder", "wrong")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!((1..=60).contains(&retry_after(&resp)));
    let reviewer = secret("reviewer");
    let resp = h.exchange(&root, "reviewer", ("reviewer", &reviewer)).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(h.metrics().contains(
        "attenuo_requests_rate_limited_total{limit=\"token_unauthenticated\",cause=\"limit\"} 2\n"
    ));
    h.stop().await;
}

/// With the defaults no rate limit is on, and many requests of one run and one agent pass.
#[tokio::test]
async fn the_defaults_limit_no_rate() {
    let h = Harness::start(|_| {}).await;
    let root = h.mint_root("alice", "planner").await;
    for _ in 0..50 {
        assert_eq!(h.list(&root).await.status(), StatusCode::OK);
    }
    for _ in 0..20 {
        assert_ne!(
            h.exchange(&root, "coder", ("coder", "wrong"))
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    h.stop().await;
}

/// The in-flight cap over a real connection: a request whose body trickles holds the one
/// permit, so the next request is `503` at once while `/healthz` and `/readyz` are answered;
/// the body deadline then answers the slow request `408` and frees the permit.
#[tokio::test]
async fn a_slow_body_holds_a_permit_until_its_deadline() {
    let h = Harness::start(|c| {
        c.limits.max_in_flight = 1;
        c.limits.request_body_timeout_seconds = 1;
    })
    .await;
    let mut slow = tokio::net::TcpStream::connect(h.addr()).await.unwrap();
    slow.write_all(
        b"POST /token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
          Content-Length: 100\r\n\r\n{\"grant",
    )
    .await
    .unwrap();
    // The slow request has the permit once a second request is shed.
    let shed = loop {
        let resp = h
            .client
            .get(h.url("/.well-known/jwks.json"))
            .send()
            .await
            .unwrap();
        if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
            break resp;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(retry_after(&shed), 1);
    let v: Value = shed.json().await.unwrap();
    assert_eq!(v["error_description"], "overloaded");
    for probe in ["/healthz", "/readyz"] {
        let resp = h.client.get(h.url(probe)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{probe}");
    }
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), slow.read_to_end(&mut buf))
        .await
        .expect("the slow request is answered and closed")
        .unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(text.contains("request_timeout"), "{text}");
    let resp = h
        .client
        .get(h.url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let m = h.metrics();
    assert!(
        m.contains("attenuo_request_timeouts_total{kind=\"body\"} 1\n"),
        "{m}"
    );
    assert!(!m.contains("attenuo_requests_shed_total 0\n"), "{m}");
    h.stop().await;
}

/// A `GET` listen stream outlives `request_timeout_seconds` and does not hold an in-flight
/// permit once it has started: with a cap of one, other requests are served while it is open.
#[tokio::test]
async fn a_listen_stream_is_neither_cut_nor_counted() {
    let h = Harness::start_against(
        FakeMcpServer::new(&["read_file"]).with_listen_stream(true),
        |c| {
            c.limits.request_timeout_seconds = 1;
            c.limits.max_in_flight = 1;
        },
    )
    .await;
    let root = h.mint_root("alice", "planner").await;
    let init = h
        .client
        .post(h.url("/mcp/github"))
        .bearer_auth(&root)
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(init.status(), StatusCode::OK);
    let sid = init.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let resp = h
        .client
        .get(h.url("/mcp/github"))
        .header("accept", "text/event-stream")
        .header("mcp-session-id", &sid)
        .bearer_auth(&root)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("first event")
        .expect("stream open")
        .unwrap();
    assert!(!first.is_empty());
    // Past the handler deadline, the cap's one permit free for other requests.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    for _ in 0..3 {
        assert_eq!(h.list(&root).await.status(), StatusCode::OK);
    }
    // The stream is still open: no end within half a second (keep-alives are fine).
    match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
        Err(_) | Ok(Some(Ok(_))) => {}
        Ok(other) => panic!("the stream ended: {other:?}"),
    }
    assert!(h.metrics().contains("attenuo_requests_shed_total 0\n"));
    assert!(h
        .metrics()
        .contains("attenuo_request_timeouts_total{kind=\"handler\"} 0\n"));
    drop(stream);
    h.stop().await;
}

/// Nonsense `[limits]` values stop the server at startup with a message naming the key.
#[test]
fn nonsense_limits_refuse_to_start() {
    for (key, value) in [
        ("header_read_timeout_seconds", 0),
        ("header_read_timeout_seconds", 301),
        ("request_body_timeout_seconds", 0),
        ("request_timeout_seconds", 3_601),
        ("max_in_flight", 1_000_001),
        ("mcp_requests_per_minute", 1_000_001),
        ("rate_limit_max_keys", 99),
    ] {
        let mut cfg = Config::from_toml(&format!("[limits]\n{key} = {value}\n")).unwrap();
        cfg.audit.sqlite_path = ":memory:".into();
        let err = AppState::from_config(&cfg).err().expect(key).to_string();
        assert!(
            err.starts_with(&format!("[limits] {key} must be between")),
            "{err}"
        );
        assert!(err.ends_with(&format!("not {value}")), "{err}");
    }
    assert!(Config::from_toml("[limits]\nmax_in_flight = -1\n").is_err());
    assert!(Config::from_toml("[limits]\nunknown_key = 1\n").is_err());
}
