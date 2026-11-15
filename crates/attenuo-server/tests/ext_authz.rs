//! `/ext-authz/v1/mcp/{server}`: attenuo as agentgateway's HTTP external authorizer
//! (`docs/design/agentgateway-ext-authz.md`).
//!
//! The decision must be the proxy's: every case of [`the_adapter_decides_as_the_proxy_does`]
//! sends the same agent request to `/mcp/github` and, through [`Harness::gateway`], to the
//! adapter, and compares allow or deny and the stable code. The other tests cover what only
//! the adapter has: the gateway's secret, the body checks, batches, DPoP against the gateway
//! URL, and the route being absent without `[[ext_authz]]`.
//!
//! No real agentgateway runs here. [`Harness::gateway`] sends what agentgateway's HTTP
//! `extAuthz` mode sends, as read in its source at commit
//! `18f83707118b3e2df500cc63299486958a0e86f5`, `crates/agentgateway/src/http/ext_authz.rs`
//! (`ExtAuthz::check_http`), for a route configured as in `docs/guides/agentgateway.md`
//! (`path` a fixed string, `includeRequestHeaders: [authorization, dpop]`, the secret in
//! `addRequestHeaders`, `includeRequestBody` without `allowPartialMessage`): the agent's
//! method, that fixed path, only the listed headers, `x-envoy-auth-partial-body: false`, and
//! the agent's body as it came.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use attenuo_core::ManualClock;
use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{FakeMcpServer, Spawned};
use attenuo_proxy::{ExtAuthzRoute, UpstreamConfig};
use attenuo_server::Config;
use attenuo_token::DpopKey;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

use common::{agent_configs, sha256_hex, Running};

const ADMIN: &str = "ext-authz-test-admin";
const GATEWAY_SECRET: &str = "gateway-secret-for-github";
const OTHER_SECRET: &str = "gateway-secret-for-gitlab";
/// The URL agents call on the gateway, which their DPoP proofs name.
const GATEWAY_URL: &str = "https://gateway.example/mcp";
const ADAPTER: &str = "/ext-authz/v1/mcp/github";

const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("no_secret_repo")
forbid(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo == "acme/secret" };

@id("ask_before_delete")
@obligation("approval")
forbid(principal, action == Action::"github/delete_repo", resource)
unless { context.approval.present };
"#;

fn secret(id: &str) -> String {
    format!("{id}-secret")
}

struct Harness {
    _upstream: Spawned,
    server: Running,
    clock: Arc<ManualClock>,
    client: reqwest::Client,
}

/// The server's config on `dir`, with `[[ext_authz]]` entries for `github` (with
/// `dpop_url`) and `gitlab` (without) when `ext_authz`.
fn config(dir: &Path, upstream: &str, ext_authz: bool) -> Config {
    let policy = dir.join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.private_key_pem_path = Some(dir.join("issuer.pem"));
    cfg.policy.policies_path = Some(policy);
    let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([
            ("read_file".to_string(), repo().readonly(true)),
            ("create_issue".to_string(), repo()),
            ("delete_repo".to_string(), repo().destructive(true)),
        ]),
    )]);
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream)];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = agent_configs(&["planner"], secret);
    cfg.proxy.max_request_body_bytes = 4096;
    if ext_authz {
        cfg.ext_authz = vec![
            ExtAuthzRoute {
                server: "github".into(),
                secret_sha256: sha256_hex(GATEWAY_SECRET),
                dpop_url: Some(GATEWAY_URL.into()),
            },
            ExtAuthzRoute {
                server: "gitlab".into(),
                secret_sha256: sha256_hex(OTHER_SECRET),
                dpop_url: None,
            },
        ];
    }
    cfg
}

impl Harness {
    async fn start(dir: &Path) -> Self {
        Self::start_with(dir, |_| {}).await
    }

    async fn start_with(dir: &Path, edit: impl FnOnce(&mut Config)) -> Self {
        let fake = FakeMcpServer::new(&["read_file", "create_issue", "delete_repo"]);
        let upstream = fake.spawn().await.unwrap();
        let mut cfg = config(dir, &upstream.url("/mcp"), true);
        edit(&mut cfg);
        let clock = ManualClock::new();
        let (router, state) = attenuo_server::build_with_clock(&cfg, clock.clone()).unwrap();
        Self {
            _upstream: upstream,
            server: Running::start(cfg, state, router).await,
            clock,
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    /// A root token for alice's planner with `capabilities`, bound to `key` when given, and
    /// its lease.
    async fn root(
        &self,
        capabilities: Value,
        ttl: Option<u64>,
        key: Option<&DpopKey>,
    ) -> (String, String) {
        let url = self.url("/admin/root-token");
        let mut body = json!({
            "subject": "alice",
            "issuer": "https://idp.example",
            "agent": "planner",
            "capabilities": capabilities,
        });
        if let Some(t) = ttl {
            body["ttl_seconds"] = json!(t);
        }
        let mut req = self.client.post(&url).bearer_auth(ADMIN).json(&body);
        if let Some(k) = key {
            req = req.header("DPoP", k.proof("POST", &url, None, now()));
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        (
            v["access_token"].as_str().unwrap().to_string(),
            v["lease"].as_str().unwrap().to_string(),
        )
    }

    async fn revoke(&self, lease: &str) {
        let resp = self
            .client
            .post(self.url(&format!("/admin/leases/{lease}/revoke")))
            .bearer_auth(ADMIN)
            .json(&json!({"reason": "test"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn admin_get(&self, path: &str) -> Value {
        self.client
            .get(self.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn audit(&self) -> Vec<Value> {
        let v = self.admin_get("/admin/audit?from=1&limit=1000").await;
        v["entries"].as_array().unwrap().clone()
    }

    /// The agent's request sent straight to the proxy.
    async fn proxy(&self, req: &AgentReq) -> (StatusCode, Value) {
        let mut b = self
            .client
            .request(req.method.clone(), self.url("/mcp/github"))
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json");
        b = req.auth(b);
        if let Some(body) = &req.body {
            b = b.body(body.clone());
        }
        read(b.send().await.unwrap()).await
    }

    /// The fake gateway: the check request agentgateway's HTTP `extAuthz` sends for the
    /// agent's request `req` (module docs), with the gateway secret `secret` and
    /// `x-envoy-auth-partial-body: partial`. `None` leaves a header out.
    async fn gateway_with(
        &self,
        path: &str,
        req: &AgentReq,
        secret: Option<&str>,
        partial: Option<&str>,
    ) -> (StatusCode, Value, Option<String>) {
        let mut b = self.client.request(req.method.clone(), self.url(path));
        // `includeRequestHeaders: [authorization, dpop]`: only these of the agent's headers.
        b = req.auth(b);
        // `addRequestHeaders`, then the header the gateway itself sets with the body.
        if let Some(s) = secret {
            b = b.header("x-attenuo-gateway-secret", s);
        }
        if let Some(p) = partial {
            b = b.header("x-envoy-auth-partial-body", p);
        }
        // `includeRequestBody`: the agent's body, unchanged (empty for `GET` and `DELETE`).
        b = b.body(req.body.clone().unwrap_or_default());
        let resp = b.send().await.unwrap();
        let id = resp
            .headers()
            .get("x-attenuo-decision-id")
            .map(|v| v.to_str().unwrap().to_string());
        let (status, body) = read(resp).await;
        (status, body, id)
    }

    /// [`Harness::gateway_with`] as a correctly configured gateway sends it.
    async fn gateway(&self, req: &AgentReq) -> (StatusCode, Value, Option<String>) {
        self.gateway_with(ADAPTER, req, Some(GATEWAY_SECRET), Some("false"))
            .await
    }
}

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

async fn read(resp: reqwest::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let text = resp.text().await.unwrap();
    // A JSON body, or the `data:` line of an SSE answer.
    let body = serde_json::from_str(&text)
        .ok()
        .or_else(|| {
            text.lines()
                .find_map(|l| l.strip_prefix("data:"))
                .and_then(|d| serde_json::from_str(d.trim()).ok())
        })
        .unwrap_or(Value::Null);
    (status, body)
}

/// One request as the agent sends it.
#[derive(Clone)]
struct AgentReq {
    method: Method,
    token: Option<String>,
    dpop: Option<String>,
    body: Option<String>,
}

impl AgentReq {
    fn post(token: &str, msg: Value) -> Self {
        Self {
            method: Method::POST,
            token: Some(token.to_string()),
            dpop: None,
            body: Some(msg.to_string()),
        }
    }

    fn call(token: &str, tool: &str, repo: &str) -> Self {
        Self::post(
            token,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": tool, "arguments": {"repo": repo}}}),
        )
    }

    fn auth(&self, b: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match (&self.token, &self.dpop) {
            (Some(t), Some(p)) => b
                .header("authorization", format!("DPoP {t}"))
                .header("dpop", p),
            (Some(t), None) => b.bearer_auth(t),
            (None, _) => b,
        }
    }
}

/// Allowed, or the stable code of the refusal: the proxy's JSON-RPC `data.code`.
fn outcome(status: StatusCode, body: &Value) -> Result<(), String> {
    match body["error"]["data"]["code"].as_str() {
        Some(code) => Err(code.to_string()),
        None if status.is_success() => Ok(()),
        None => Err(format!("HTTP {status}")),
    }
}

/// The same request through the proxy and through the adapter: the same allow or deny, with
/// the same code, and the adapter's deny is never a 2xx (which the gateway would forward).
async fn same_decision(h: &Harness, case: &str, req: &AgentReq) -> Result<(), String> {
    let (ps, pb) = h.proxy(req).await;
    let (gs, gb, _) = h.gateway(req).await;
    let (p, g) = (outcome(ps, &pb), outcome(gs, &gb));
    assert_eq!(p, g, "{case}: proxy {ps} {pb}, adapter {gs} {gb}");
    assert_eq!(g.is_ok(), gs.is_success(), "{case}: adapter {gs} {gb}");
    if g.is_ok() {
        assert_eq!(gs, StatusCode::OK, "{case}");
    }
    g
}

#[tokio::test]
async fn the_adapter_decides_as_the_proxy_does() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(dir.path()).await;
    let caps = json!(["github:read_file", "github:delete_repo"]);

    // Allowed call.
    let (token, _) = h.root(caps.clone(), None, None).await;
    let r = same_decision(
        &h,
        "allowed",
        &AgentReq::call(&token, "read_file", "acme/api"),
    )
    .await;
    assert_eq!(r, Ok(()));

    // Capability miss: `create_issue` is not in the token.
    let r = same_decision(
        &h,
        "capability miss",
        &AgentReq::call(&token, "create_issue", "acme/api"),
    )
    .await;
    assert_eq!(r, Err("capability_denied".into()));

    // Policy deny.
    let r = same_decision(
        &h,
        "policy deny",
        &AgentReq::call(&token, "read_file", "acme/secret"),
    )
    .await;
    assert_eq!(r, Err("policy_deny".into()));

    // Approval-gated call: both answer `-32008`; the adapter's is a 403.
    let r = same_decision(
        &h,
        "approval",
        &AgentReq::call(&token, "delete_repo", "acme/api"),
    )
    .await;
    assert_eq!(r, Err("approval_required".into()));

    // Exhausted run limit: one call allowed, spent through the proxy.
    let (limited, _) = h
        .root(
            json!([{"server": "github", "tool": "read_file", "limits": {"calls": 1}}]),
            None,
            None,
        )
        .await;
    let (s, b) = h
        .proxy(&AgentReq::call(&limited, "read_file", "acme/api"))
        .await;
    assert_eq!(outcome(s, &b), Ok(()));
    let r = same_decision(
        &h,
        "run limit",
        &AgentReq::call(&limited, "read_file", "acme/api"),
    )
    .await;
    assert_eq!(r, Err("budget_exhausted".into()));

    // Messages the proxy forwards after a lease check only.
    for (case, msg) in [
        (
            "initialize",
            json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"}}}),
        ),
        (
            "tools/list",
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
        ),
        (
            "notification",
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ),
    ] {
        assert_eq!(
            same_decision(&h, case, &AgentReq::post(&token, msg)).await,
            Ok(())
        );
    }

    // Invalid params: the proxy's own answer, not forwarded.
    let r = same_decision(
        &h,
        "invalid params",
        &AgentReq::post(
            &token,
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"arguments": {}}}),
        ),
    )
    .await;
    assert_eq!(r, Err("invalid_params".into()));

    // No token.
    let mut anon = AgentReq::call(&token, "read_file", "acme/api");
    anon.token = None;
    assert_eq!(
        same_decision(&h, "no token", &anon).await,
        Err("missing_token".into())
    );

    // Wrong audience: a token from another server sharing the issuer key.
    let other_dir = tempfile::tempdir().unwrap();
    let other = Harness::start_with(other_dir.path(), |c| {
        c.issuer.audience = "another-audience".into();
        c.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    })
    .await;
    let (foreign, _) = other.root(caps.clone(), None, None).await;
    assert_eq!(
        same_decision(
            &h,
            "wrong audience",
            &AgentReq::call(&foreign, "read_file", "acme/api")
        )
        .await,
        Err("invalid_token".into())
    );

    // Revoked lease: a call, and a message the proxy only lease-checks.
    let (revoked, lease) = h.root(caps.clone(), None, None).await;
    h.revoke(&lease).await;
    let r = same_decision(
        &h,
        "revoked call",
        &AgentReq::call(&revoked, "read_file", "acme/api"),
    )
    .await;
    assert_eq!(r, Err("lease_revoked".into()));
    let r = same_decision(
        &h,
        "revoked tools/list",
        &AgentReq::post(
            &revoked,
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
        ),
    )
    .await;
    assert_eq!(r, Err("lease_revoked".into()));

    // Expired token: the server's clock passes its lifetime.
    let (short, _) = h.root(caps, Some(60), None).await;
    h.clock.advance(std::time::Duration::from_secs(120));
    let r = same_decision(
        &h,
        "expired",
        &AgentReq::call(&short, "read_file", "acme/api"),
    )
    .await;
    assert_eq!(r, Err("token_expired".into()));
}

/// Every decision through the adapter is a decision record like the proxy's, and the log still
/// verifies.
#[tokio::test]
async fn adapter_decisions_are_audited_and_the_chain_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(dir.path()).await;
    let (token, _) = h.root(json!(["github:read_file"]), None, None).await;
    let (s, _, allow_id) = h
        .gateway(&AgentReq::call(&token, "read_file", "acme/api"))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, b, deny_id) = h
        .gateway(&AgentReq::call(&token, "read_file", "acme/secret"))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        b["error"]["data"]["decision_id"].as_str(),
        deny_id.as_deref()
    );
    let audit = h.audit().await;
    for (id, decision, reason) in [
        (allow_id.unwrap(), "allow", "policy_allow"),
        (deny_id.unwrap(), "deny", "policy_deny"),
    ] {
        let e = audit
            .iter()
            .find(|e| e["record"]["id"] == id.as_str())
            .unwrap_or_else(|| panic!("no record {id}"));
        let r = &e["record"];
        assert_eq!(r["kind"], "decision", "{r}");
        assert_eq!(r["server"], "github");
        assert_eq!(r["tool"], "read_file");
        assert_eq!(r["decision"], decision);
        assert_eq!(r["reason"], reason);
    }
    let report = h.admin_get("/admin/audit/verify").await;
    assert_eq!(report["ok"], true, "{report}");
}

/// Without the entry's secret nothing is decided, charged or recorded; a secret of another
/// entry does not open this server.
#[tokio::test]
async fn the_gateway_must_send_the_entrys_secret() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(dir.path()).await;
    let (token, _) = h.root(json!(["github:read_file"]), None, None).await;
    let req = AgentReq::call(&token, "read_file", "acme/api");
    let before = h.audit().await.len();
    for secret in [None, Some("wrong"), Some(OTHER_SECRET), Some("")] {
        let (s, b, id) = h.gateway_with(ADAPTER, &req, secret, Some("false")).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{secret:?}");
        assert_eq!(b["error"]["data"]["code"], "ext_authz_unauthenticated");
        assert_eq!(id, None);
    }
    // The other entry's secret opens only the other entry's path.
    let (s, b, _) = h
        .gateway_with(
            "/ext-authz/v1/mcp/gitlab",
            &req,
            Some(GATEWAY_SECRET),
            Some("false"),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(b["error"]["data"]["code"], "ext_authz_unauthenticated");
    // A server without an entry is unknown.
    let (s, b, _) = h
        .gateway_with(
            "/ext-authz/v1/mcp/jira",
            &req,
            Some(GATEWAY_SECRET),
            Some("false"),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(b["error"]["data"]["code"], "unknown_server");
    assert_eq!(h.audit().await.len(), before, "nothing was recorded");
}

/// A body the adapter cannot read whole and unambiguously is refused before any decision: a
/// truncated one, one the gateway was not configured to send, one over the size limit, one that
/// is not JSON, one with a duplicate member or a number read otherwise, and a batch.
#[tokio::test]
async fn bodies_that_are_not_whole_and_unambiguous_are_denied() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(dir.path()).await;
    let (token, _) = h
        .root(
            json!([{"server": "github", "tool": "read_file", "limits": {"calls": 1}}]),
            None,
            None,
        )
        .await;
    let call = AgentReq::call(&token, "read_file", "acme/api");
    let before = h.audit().await.len();

    for (partial, why) in [
        (Some("true"), "cut at maxRequestBytes (allowPartialMessage)"),
        (None, "includeRequestBody not configured"),
        (Some("False"), "not exactly false"),
    ] {
        let (s, b, _) = h
            .gateway_with(ADAPTER, &call, Some(GATEWAY_SECRET), partial)
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{why}");
        assert_eq!(
            b["error"]["data"]["code"], "ext_authz_body_incomplete",
            "{why}"
        );
    }

    // A cut body that a gateway claims is whole is not JSON, and is refused as such.
    let mut cut = call.clone();
    cut.body = Some(call.body.clone().unwrap()[..40].to_string());
    let (s, b, _) = h.gateway(&cut).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["error"]["data"]["code"], "parse_error");

    let big = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"repo": "x".repeat(8000)}}});
    let (s, b, _) = h.gateway(&AgentReq::post(&token, big)).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(b["error"]["data"]["code"], "request_too_large");

    let mut garbage = call.clone();
    garbage.body = Some("{not json".into());
    let (s, b, _) = h.gateway(&garbage).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["error"]["data"]["code"], "parse_error");

    for body in [
        // serde_json keeps the last `name`, a first-wins upstream the first.
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo","name":"read_file","arguments":{"repo":"acme/api"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"read_file","arguments":{}}}"#,
        // SR-133: no `method` for serde_json (allowed after a lease check before the fix),
        // `tools/call` for a decoder that ignores case; and two names that differ in case.
        r#"{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"delete_repo","arguments":{"repo":"acme/api"}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","Name":"delete_repo","arguments":{"repo":"acme/api"}}}"#,
        // Read as 0.1 here, with more digits by an upstream that keeps them.
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"a","n":0.10000000000000001}}}"#,
    ] {
        let mut req = call.clone();
        req.body = Some(body.into());
        let (s, b, _) = h.gateway(&req).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(b["error"]["data"]["code"], "ext_authz_ambiguous_body");
    }

    // A batch, even of one allowed call, is not decided: nothing is charged.
    let batch = json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"repo": "acme/api"}}}]);
    let (s, b, id) = h.gateway(&AgentReq::post(&token, batch)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["error"]["data"]["code"], "ext_authz_batch_unsupported");
    assert_eq!(id, None);

    assert_eq!(h.audit().await.len(), before, "nothing was decided");
    // The run's one call is still there.
    let (s, _, _) = h.gateway(&call).await;
    assert_eq!(s, StatusCode::OK);
}

/// `GET` (the listen stream) and `DELETE` (end of session) are allowed on a live lease and
/// refused, and recorded, on a revoked one, as the proxy does before forwarding them.
#[tokio::test]
async fn get_and_delete_need_a_live_lease() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(dir.path()).await;
    let (token, lease) = h.root(json!(["github:read_file"]), None, None).await;
    // axum routes `HEAD` to the `GET` handler, here as at `/mcp/{server}`.
    for method in [Method::GET, Method::DELETE, Method::HEAD] {
        let req = AgentReq {
            method: method.clone(),
            token: Some(token.clone()),
            dpop: None,
            body: None,
        };
        let (s, _, _) = h.gateway(&req).await;
        assert_eq!(s, StatusCode::OK, "{method}");
    }
    // Any other method is not routed: not a 2xx, so the gateway does not forward it.
    let put = AgentReq {
        method: Method::PUT,
        token: Some(token.clone()),
        dpop: None,
        body: None,
    };
    let (s, _, _) = h.gateway(&put).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);

    h.revoke(&lease).await;
    let get = AgentReq {
        method: Method::GET,
        token: Some(token),
        dpop: None,
        body: None,
    };
    let (s, b, _) = h.gateway(&get).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["data"]["code"], "lease_revoked");
    let audit = h.audit().await;
    assert!(
        audit
            .iter()
            .any(|e| e["record"]["tool"] == "http.GET" && e["record"]["reason"] == "lease_revoked"),
        "the refusal is recorded"
    );
}

/// A DPoP-bound token works through the adapter when the proof names the gateway URL the
/// agent called and the forwarded method; the proof is still single use. A proof for any
/// other URL or method, no proof, or a proof to an entry without `dpop_url` is refused.
#[tokio::test]
async fn dpop_proofs_are_checked_against_the_gateway_url() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(dir.path()).await;
    let key = DpopKey::generate().unwrap();
    let (token, _) = h.root(json!(["github:read_file"]), None, Some(&key)).await;
    let with_proof = |proof: Option<String>| {
        let mut r = AgentReq::call(&token, "read_file", "acme/api");
        r.dpop = proof;
        r
    };

    let good = key.proof("POST", GATEWAY_URL, Some(&token), now());
    let (s, b, _) = h.gateway(&with_proof(Some(good.clone()))).await;
    assert_eq!(s, StatusCode::OK, "{b}");

    // The same proof again: replayed.
    let (s, b, _) = h.gateway(&with_proof(Some(good))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["data"]["code"], "invalid_dpop_proof");

    for (method, url) in [
        ("POST", h.url(ADAPTER)),
        ("POST", h.url("/mcp/github")),
        ("GET", GATEWAY_URL.to_string()),
        ("POST", "https://gateway.example/mcp/other".to_string()),
    ] {
        let p = key.proof(method, &url, Some(&token), now());
        let (s, b, _) = h.gateway(&with_proof(Some(p))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {url}");
        assert_eq!(b["error"]["data"]["code"], "invalid_dpop_proof");
    }

    // A proof by another key.
    let thief = DpopKey::generate().unwrap();
    let p = thief.proof("POST", GATEWAY_URL, Some(&token), now());
    let (s, b, _) = h.gateway(&with_proof(Some(p))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["data"]["code"], "invalid_dpop_proof");

    // No proof for a bound token.
    let (s, b, _) = h.gateway(&with_proof(None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["data"]["code"], "dpop_required");

    // An entry without `dpop_url` takes no proof at all.
    let p = key.proof("POST", GATEWAY_URL, Some(&token), now());
    let (s, b, _) = h
        .gateway_with(
            "/ext-authz/v1/mcp/gitlab",
            &with_proof(Some(p)),
            Some(OTHER_SECRET),
            Some("false"),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["error"]["data"]["code"], "ext_authz_dpop_url_unset");
}

/// With no `[[ext_authz]]` entry the route is not mounted.
#[tokio::test]
async fn the_route_is_absent_without_ext_authz() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start_with(dir.path(), |c| c.ext_authz.clear()).await;
    let (token, _) = h.root(json!(["github:read_file"]), None, None).await;
    let (s, _, _) = h
        .gateway(&AgentReq::call(&token, "read_file", "acme/api"))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// `[[ext_authz]]` entries are checked at startup.
#[test]
fn bad_entries_are_refused_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let base = config(dir.path(), "http://127.0.0.1:1/mcp", true);
    let entry = |server: &str, secret: &str, url: Option<&str>| ExtAuthzRoute {
        server: server.into(),
        secret_sha256: secret.into(),
        dpop_url: url.map(Into::into),
    };
    let good = sha256_hex("x");
    for (entries, needle) in [
        (vec![entry("git/hub", &good, None)], "[[ext_authz]]"),
        (vec![entry("attenuo", &good, None)], "reserved"),
        (
            vec![entry("github", &good, None), entry("github", &good, None)],
            "twice",
        ),
        (vec![entry("github", "abc", None)], "secret_sha256"),
        (
            vec![entry("github", &good, Some("https://gw.example/mcp?x=1"))],
            "dpop_url",
        ),
        (vec![entry("github", &good, Some("/mcp"))], "dpop_url"),
        (
            vec![entry("github", &good, Some("ftp://gw.example/mcp"))],
            "dpop_url",
        ),
    ] {
        let mut cfg = base.clone();
        cfg.ext_authz = entries;
        let err = cfg.check_ext_authz().unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
        assert!(attenuo_server::build(&cfg).is_err());
    }
    base.check_ext_authz().unwrap();
}

/// SR-133's remainder, through the proxy and the adapter: `Repo` alone is what an upstream
/// that ignores case reads as `repo`, and the `has repo` forbid never saw it. Both now refuse
/// it as `argument_case_mismatch`, a decision recorded as a deny with its reason; the exact
/// name and an unrelated one are decided as before.
#[tokio::test]
async fn an_argument_in_another_case_is_refused_by_both_paths_sr133() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(dir.path()).await;
    let (token, _) = h.root(json!(["github:read_file"]), None, None).await;
    let call = |args: Value| {
        AgentReq::post(
            &token,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "read_file", "arguments": args}}),
        )
    };
    for (case, args, want) in [
        (
            "exact",
            json!({"repo": "acme/secret"}),
            Err("policy_deny".to_string()),
        ),
        (
            "case",
            json!({"Repo": "acme/secret"}),
            Err("argument_case_mismatch".into()),
        ),
        (
            "fold",
            json!({"REPO": "acme/secret"}),
            Err("argument_case_mismatch".into()),
        ),
        (
            "unrelated",
            json!({"repo": "acme/api", "Branch": "main"}),
            Ok(()),
        ),
    ] {
        assert_eq!(same_decision(&h, case, &call(args)).await, want, "{case}");
    }
    let audit = h.audit().await;
    let refused: Vec<_> = audit
        .iter()
        .filter(|e| e["record"]["reason"] == "argument_case_mismatch")
        .collect();
    assert_eq!(
        refused.len(),
        4,
        "two cases, each through the proxy and the adapter"
    );
    for e in refused {
        assert_eq!(e["record"]["kind"], "decision");
        assert_eq!(e["record"]["decision"], "deny");
        assert_eq!(e["record"]["tool"], "read_file");
    }
}
