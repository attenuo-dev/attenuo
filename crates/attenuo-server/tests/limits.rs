//! `[limits]` over real connections (audit finding S-4): the per-run MCP and action search
//! (SR-117) rate limits, the per-agent and per-peer `POST /token` limits, the in-flight cap
//! with the body deadline, and streams that neither the handler deadline nor the cap may cut. The servers run through
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

/// The servers' config: the agents, the dev root mint and the `github` upstream.
fn base_config(dir: &tempfile::TempDir, upstream: &Spawned) -> Config {
    let policy_path = dir.path().join("policies.cedar");
    std::fs::write(&policy_path, POLICY).unwrap();
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
    cfg
}

impl Harness {
    async fn start(tweak: impl FnOnce(&mut Config)) -> Self {
        Self::start_against(FakeMcpServer::new(&["read_file"]), tweak).await
    }

    async fn start_against(upstream: FakeMcpServer, tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let upstream = upstream.spawn().await.unwrap();
        let mut cfg = base_config(&dir, &upstream);
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

/// SR-109 through the server's own `POST /token` handler, with simulated peer addresses (the
/// router is driven directly, with the address the accept loop would give it). Once one
/// unauthenticated request from each of `rate_limit_max_keys` addresses has filled the
/// per-peer table, an agent from an address not in the table still gets its token, at an
/// exchange and with either agent. A request from such an address that does not authenticate
/// gets the `429` a peer over its limit gets, whether its secret was wrong, it carried no
/// client credential, or it carried an actor token; so does hop 0 with a wrong secret. A peer
/// in the table and over its limit is refused before the handler runs, credentials or not.
#[tokio::test]
async fn a_full_peer_table_lets_agents_authenticate_sr109() {
    use axum::extract::ConnectInfo;
    use tower::ServiceExt as _;
    let dir = tempfile::tempdir().unwrap();
    let upstream = FakeMcpServer::new(&["read_file"]).spawn().await.unwrap();
    let mut cfg = base_config(&dir, &upstream);
    cfg.limits.token_unauthenticated_requests_per_minute = 2;
    cfg.limits.rate_limit_max_keys = 100;
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let send = |peer: [u8; 4], path: &'static str, body: Value| {
        let router = router.clone();
        async move {
            let mut req = axum::http::Request::post(path)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {ADMIN}"))
                .body(axum::body::Body::from(body.to_string()))
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(std::net::SocketAddr::from((peer, 40000))));
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let retry = resp.headers().get("retry-after").is_some();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap();
            let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            (status.as_u16(), retry, v)
        }
    };
    let (_, _, minted) = send(
        [127, 0, 0, 1],
        "/admin/root-token",
        json!({"subject": "alice", "issuer": "https://idp.example", "agent": "planner",
               "capabilities": ["github:read_file"]}),
    )
    .await;
    let root = minted["access_token"].as_str().unwrap().to_owned();
    let exchange = |actor: &str, extra: Value| {
        let mut body = json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": root,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": actor,
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        body
    };
    let creds = |id: &str, secret: &str| json!({"client_id": id, "client_secret": secret});
    // One request with a wrong secret from each of 100 addresses fills the table.
    for i in 0..100u8 {
        let (status, _, v) = send(
            [198, 51, 100, i],
            "/token",
            exchange("coder", creds("coder", "wrong")),
        )
        .await;
        assert_eq!(status, 401, "{v}");
    }
    // Agents from addresses never seen: served.
    let (status, _, v) = send(
        [192, 0, 2, 1],
        "/token",
        exchange("coder", creds("coder", &secret("coder"))),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    let (status, _, v) = send(
        [192, 0, 2, 2],
        "/token",
        exchange("reviewer", creds("reviewer", &secret("reviewer"))),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    // From new addresses, whatever does not authenticate gets one answer.
    let refusals = [
        exchange("coder", creds("coder", "wrong")),
        exchange("coder", creds("nobody", "wrong")),
        exchange("coder", json!({})),
        exchange(
            "coder",
            json!({"actor_token": "x.y.z",
                   "actor_token_type": "urn:ietf:params:oauth:token-type:jwt"}),
        ),
        json!({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
               "subject_token": "x.y.z",
               "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
               "client_id": "coder", "client_secret": "wrong"}),
    ];
    let mut answers = Vec::new();
    for (i, body) in refusals.iter().enumerate() {
        let (status, retry, v) = send([203, 0, 113, i as u8], "/token", body.clone()).await;
        assert_eq!((status, retry), (429, true), "{body}: {v}");
        answers.push(v);
    }
    assert_eq!(answers[0]["code"], "rate_limited");
    assert!(answers.iter().all(|v| *v == answers[0]), "{answers:?}");
    let render = state.metrics.render();
    assert!(render.contains(
        "attenuo_requests_rate_limited_total{limit=\"token_unauthenticated\",cause=\"table_full\"} 5\n"
    ), "{render}");
    // A peer in the table over its limit (2 a minute): refused up front, good secret or not,
    // with the same body.
    let (status, _, _) = send(
        [198, 51, 100, 7],
        "/token",
        exchange("coder", creds("coder", "wrong")),
    )
    .await;
    assert_eq!(status, 401);
    let (status, _, v) = send(
        [198, 51, 100, 7],
        "/token",
        exchange("coder", creds("coder", &secret("coder"))),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(v, answers[0]);
    assert!(state.metrics.render().contains(
        "attenuo_requests_rate_limited_total{limit=\"token_unauthenticated\",cause=\"limit\"} 1\n"
    ));
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
        ("authzen_search_requests_per_minute", 1_000_001),
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
    assert!(Config::from_toml("[limits]\nauthzen_search_requests_per_minute = -1\n").is_err());
    assert!(Config::from_toml("[limits]\nunknown_key = 1\n").is_err());
}

// ---------------------------------------------------------------------------------------------
// `authzen_search_requests_per_minute` (SR-117)
// ---------------------------------------------------------------------------------------------

/// The `[[peps]]` secret of the unsigned-chain search test.
const PEP_SECRET: &str = "gateway-secret";

/// An action search body for the `github` server.
fn search_body() -> Value {
    json!({
        "subject": {"type": "agent", "id": ""},
        "resource": {"type": "mcp_server", "id": "github"},
        "context": {"input": {"repo": "alice/public-site"}},
    })
}

impl Harness {
    async fn search(&self, token: &str) -> reqwest::Response {
        self.client
            .post(self.url("/access/v1/search/action"))
            .bearer_auth(token)
            .json(&search_body())
            .send()
            .await
            .unwrap()
    }

    async fn evaluate(&self, token: &str) -> reqwest::Response {
        self.client
            .post(self.url("/access/v1/evaluation"))
            .bearer_auth(token)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "read_file", "properties": {"server": "github"}},
                "resource": {"type": "mcp_server", "id": "github"},
                "context": {"input": {"repo": "alice/public-site"}},
            }))
            .send()
            .await
            .unwrap()
    }

    async fn evaluate_batch(&self, token: &str) -> reqwest::Response {
        let entry = json!({"action": {"name": "read_file", "properties": {"server": "github"}}});
        self.client
            .post(self.url("/access/v1/evaluations"))
            .bearer_auth(token)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "resource": {"type": "mcp_server", "id": "github"},
                "context": {"input": {"repo": "alice/public-site"}},
                "evaluations": [entry.clone(), entry],
            }))
            .send()
            .await
            .unwrap()
    }

    async fn audit_len(&self) -> usize {
        let resp = self
            .client
            .get(self.url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json::<Value>().await.unwrap()["entries"]
            .as_array()
            .unwrap()
            .len()
    }
}

/// Off by default: a run may search as often as it likes, and nothing is counted.
#[tokio::test]
async fn the_search_rate_limit_is_off_by_default() {
    let h = Harness::start(|_| {}).await;
    let alice = h.mint_root("alice", "planner").await;
    for _ in 0..30 {
        assert_eq!(h.search(&alice).await.status(), StatusCode::OK);
    }
    assert!(h.metrics().contains(
        "attenuo_requests_rate_limited_total{limit=\"authzen_search\",cause=\"limit\"} 0\n"
    ));
    h.stop().await;
}

/// `authzen_search_requests_per_minute`: a run gets N searches a minute, a delegated token of
/// the run shares them, the N+1st is `429` `rate_limited` with `Retry-After` and evaluates
/// nothing; another run is not touched; evaluation, batch evaluation and `/mcp` of the limited
/// run still answer, and MCP requests spend no searches (a table of its own); a bad token
/// counts against no one; and no search, admitted or refused, writes an audit record.
#[tokio::test]
async fn the_search_rate_limit_is_per_run() {
    let h = Harness::start(|c| {
        c.limits.authzen_search_requests_per_minute = 3;
        c.limits.mcp_requests_per_minute = 2;
    })
    .await;
    let alice = h.mint_root("alice", "planner").await;
    let bob = h.mint_root("bob", "planner").await;
    // Two MCP requests use up alice's MCP minute and none of her searches.
    for _ in 0..2 {
        assert_eq!(h.list(&alice).await.status(), StatusCode::OK);
    }
    assert_eq!(h.list(&alice).await.status(), StatusCode::TOO_MANY_REQUESTS);
    // A bad token is refused before anything is counted.
    for _ in 0..5 {
        assert_eq!(
            h.search("not-a-token").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    // A child of alice's run (its delegation is audited, before the count starts).
    let child = h
        .exchange(&alice, "coder", ("coder", &secret("coder")))
        .await;
    assert_eq!(child.status(), StatusCode::OK);
    let child = child.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = h.audit_len().await;
    for _ in 0..2 {
        let resp = h.search(&alice).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["results"][0]["name"], "read_file", "{v}");
    }
    // A child of alice's run: its third search.
    assert_eq!(h.search(&child).await.status(), StatusCode::OK);
    for token in [&alice, &child] {
        let resp = h.search(token).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!((1..=60).contains(&retry_after(&resp)));
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"], "rate_limited", "{v}");
        assert_eq!(v["code"], "rate_limited", "{v}");
        assert_eq!(v["error_description"], "rate_limited", "{v}");
        assert!(v.get("results").is_none(), "{v}");
    }
    assert_eq!(
        h.audit_len().await,
        before,
        "a search wrote an audit record"
    );
    // Another run searches as before.
    assert_eq!(h.search(&bob).await.status(), StatusCode::OK);
    // The limited run still evaluates (audited, not counted here).
    let e = h.evaluate(&alice).await;
    assert_eq!(e.status(), StatusCode::OK);
    assert_eq!(e.json::<Value>().await.unwrap()["decision"], true);
    let b = h.evaluate_batch(&alice).await;
    assert_eq!(b.status(), StatusCode::OK);
    assert_eq!(
        b.json::<Value>().await.unwrap()["evaluations"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(h.audit_len().await, before + 3);
    let m = h.metrics();
    assert!(
        m.contains(
            "attenuo_requests_rate_limited_total{limit=\"authzen_search\",cause=\"limit\"} 2\n"
        ),
        "{m}"
    );
    assert!(m.contains("attenuo_requests_rate_limited_total{limit=\"mcp\",cause=\"limit\"} 1\n"));
    h.stop().await;
}

/// A `[[peps]]` entry searching with an unsigned chain is counted against the chain's root
/// lease, the same run as the bearer's: requests that fail the PEP's authentication spend
/// nothing, and the run's own token shares the minute with the PEP.
#[tokio::test]
async fn a_pep_search_with_an_unsigned_chain_counts_against_its_run() {
    let h = Harness::start(|c| {
        c.limits.authzen_search_requests_per_minute = 2;
        c.authzen.allow_unsigned_chain = true;
        c.peps = vec![attenuo_server::config::PepConfig::with_secret_sha256(
            "gateway",
            common::sha256_hex(PEP_SECRET),
        )];
    })
    .await;
    let alice = h.mint_root("alice", "planner").await;
    let chain = h
        .state
        .verifier
        .verify(&alice, time::OffsetDateTime::now_utc())
        .unwrap()
        .chain;
    let call = attenuo_core::ToolCall::new("github", "read_file", json!({}));
    let pep_search = |secret: &str| {
        let mut body =
            serde_json::to_value(attenuo_policy::authzen::to_request(&chain, &call)).unwrap();
        let obj = body.as_object_mut().unwrap();
        obj.remove("action");
        obj.insert(
            "resource".into(),
            json!({"type": "mcp_server", "id": "github"}),
        );
        obj.insert("pep_id".into(), json!("gateway"));
        obj.insert("pep_secret".into(), json!(secret));
        h.client
            .post(h.url("/access/v1/search/action"))
            .json(&body)
            .send()
    };
    for _ in 0..5 {
        let resp = pep_search("wrong").await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        pep_search(PEP_SECRET).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(h.search(&alice).await.status(), StatusCode::OK);
    let resp = pep_search(PEP_SECRET).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.json::<Value>().await.unwrap()["code"], "rate_limited");
    assert_eq!(
        h.search(&alice).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    h.stop().await;
}
