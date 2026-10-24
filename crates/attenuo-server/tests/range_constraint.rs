//! The `range` argument constraint through the whole server (RFC-0001 section 3): minted into a
//! root token, narrowed at exchange, a widening exchange refused as `exchange_widening`, a
//! malformed range refused as `invalid_request`, and calls outside the range denied as
//! `capability_denied` before Cedar (whose policy here permits everything).

use std::collections::BTreeMap;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::jsonrpc::CODE_DENIED;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::Config;
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "range-test-admin";
const AGENTS: &[&str] = &["helper", "sneaky"];

const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);
"#;

fn secret(id: &str) -> String {
    format!("{id}-secret")
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

struct Harness {
    server: Spawned,
    _upstream_task: Spawned,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let upstream = FakeMcpServer::new(&["send_money"]);
        let upstream_task = upstream.spawn().await.unwrap();

        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.policy.policies_path = Some(policy_path);
        cfg.policy.catalog = BTreeMap::from([(
            "bank".to_string(),
            BTreeMap::from([(
                "send_money".to_string(),
                ToolAttrs::new()
                    .with_input("recipient", ArgType::String)
                    .with_input("amount", ArgType::Long),
            )]),
        )]);
        cfg.audit.sqlite_path = ":memory:".into();
        cfg.upstreams = vec![UpstreamConfig::new("bank", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = AGENTS
            .iter()
            .map(|id| attenuo_server::config::AgentConfig {
                id: (*id).into(),
                secret_sha256: sha256_hex(&secret(id)),
            })
            .collect();
        let (router, _state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            _upstream_task: upstream_task,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    async fn mint_root(&self, caps: Value) -> reqwest::Response {
        self.client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                          "agent": "planner", "capabilities": caps}))
            .send()
            .await
            .unwrap()
    }

    async fn exchange(&self, parent: &str, actor: &str, caps: Value) -> reqwest::Response {
        self.client
            .post(self.server.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "attenuo_capabilities", "capabilities": caps}],
                "client_id": actor,
                "client_secret": secret(actor),
            }))
            .send()
            .await
            .unwrap()
    }

    async fn pay(&self, token: &str, amount: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url("/mcp/bank"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "send_money",
                                     "arguments": {"recipient": "FR00EMMA", "amount": amount}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn last_decision(&self) -> Value {
        let v: Value = self
            .client
            .get(self.server.url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["entries"].as_array().unwrap().last().unwrap()["record"].clone()
    }
}

async fn token_of(resp: reqwest::Response) -> String {
    let status = resp.status();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{v}");
    v["access_token"].as_str().unwrap().to_string()
}

fn send_money(range: Value) -> Value {
    json!([{"server": "bank", "tool": "send_money",
            "constraints": {"amount": {"op": "range", "value": range}}}])
}

fn allowed(resp: &Value) -> bool {
    resp.get("result").is_some() && resp.get("error").is_none()
}

fn denied_reason(resp: &Value) -> String {
    assert_eq!(resp["error"]["code"], json!(CODE_DENIED), "{resp}");
    resp["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn range_narrows_at_exchange_and_bounds_every_call() {
    let h = Harness::start().await;
    let root = token_of(
        h.mint_root(send_money(json!({"min": 0, "max": 2000})))
            .await,
    )
    .await;

    // Within the root's range, on its bounds, a whole float: allowed. Outside: denied before
    // Cedar, which would allow anything.
    for ok in [json!(0), json!(2000), json!(150.0)] {
        assert!(allowed(&h.pay(&root, ok.clone()).await), "{ok}");
    }
    for bad in [json!(-1), json!(2001), json!(1.5), json!("100")] {
        assert_eq!(
            denied_reason(&h.pay(&root, bad.clone()).await),
            "capability_denied",
            "{bad}"
        );
    }
    let record = h.last_decision().await;
    assert_eq!(record["reason"], "capability_denied");

    // A widening exchange is refused and audited as such: a higher max, a lower min, a
    // missing bound, or no constraint at all.
    for wider in [
        send_money(json!({"min": 0, "max": 5000})),
        send_money(json!({"min": -10, "max": 2000})),
        send_money(json!({"max": 2000})),
        json!([{"server": "bank", "tool": "send_money"}]),
    ] {
        let resp = h.exchange(&root, "sneaky", wider.clone()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{wider}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "invalid_scope", "{body}");
        let record = h.last_decision().await;
        assert_eq!(record["reason"], "exchange_widening", "{wider}");
    }

    // A narrower range is accepted, carried in the child token, and enforced.
    let child = token_of(
        h.exchange(&root, "helper", send_money(json!({"min": 10, "max": 500})))
            .await,
    )
    .await;
    let claims = decode_payload(&child);
    assert_eq!(
        claims["chain"]["hops"][1]["capabilities"][0]["constraints"]["amount"],
        json!({"op": "range", "value": {"min": 10, "max": 500}})
    );
    assert!(allowed(&h.pay(&child, json!(500)).await));
    assert!(allowed(&h.pay(&child, json!(10)).await));
    assert_eq!(
        denied_reason(&h.pay(&child, json!(501)).await),
        "capability_denied"
    );
    assert_eq!(
        denied_reason(&h.pay(&child, json!(9)).await),
        "capability_denied"
    );
}

#[tokio::test]
async fn a_malformed_range_is_refused_not_ignored() {
    let h = Harness::start().await;
    for bad in [
        json!({}),
        json!({"min": 5, "max": 1}),
        json!({"min": 0, "maximum": 10}),
        json!({"max": 10.5}),
    ] {
        let resp = h.mint_root(send_money(bad.clone())).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    let root = token_of(h.mint_root(send_money(json!({"max": 100}))).await).await;
    let resp = h
        .exchange(&root, "helper", send_money(json!({"min": 50, "max": 10})))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request", "{body}");
}

fn decode_payload(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
