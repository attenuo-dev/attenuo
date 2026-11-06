//! Regression tests for findings of the 2026-10-23 security review, pass 4
//! (`docs/research/security-review-2026-10-23-pass4.md`). SR-44 and the `[[actor_trust]]` case
//! of SR-45 are in `actor_token.rs`, next to the actor-token harness they need; SR-46 is a unit
//! test in `src/authz.rs`.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::path::Path;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::AgentConfig;
use attenuo_server::Config;
use attenuo_token::DpopKey;
use reqwest::{RequestBuilder, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const ADMIN: &str = "pass4-admin-token";
const AGENTS: &[&str] = &["planner", "coder", "reviewer"];
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

fn secret(id: &str) -> String {
    format!("{id}-secret")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

struct Server {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    server: Spawned,
    client: reqwest::Client,
}

/// A server on loopback without `public_url`, one `github` upstream, the dev root mint and
/// three agents; `tweak` adjusts the config.
async fn start(dir: &Path, tweak: impl FnOnce(&mut Config)) -> Server {
    let upstream = FakeMcpServer::new(&["read_file"]);
    let upstream_task = upstream.spawn().await.unwrap();
    let policy = dir.join("policies.cedar");
    std::fs::write(
        &policy,
        r#"permit(principal, action == Action::"github/read_file", resource);"#,
    )
    .unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.private_key_pem_path = Some(dir.join("issuer.pem"));
    cfg.policy.policies_path = Some(policy);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([(
            "read_file".to_string(),
            ToolAttrs::new()
                .with_input("repo", ArgType::String)
                .readonly(true),
        )]),
    )]);
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = AGENTS
        .iter()
        .map(|id| AgentConfig {
            id: (*id).into(),
            secret_sha256: hex::encode(Sha256::digest(secret(id).as_bytes())),
        })
        .collect();
    tweak(&mut cfg);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    Server {
        upstream,
        _upstream_task: upstream_task,
        server: spawn_router(router).await.unwrap(),
        client: reqwest::Client::new(),
    }
}

impl Server {
    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    /// A root token for alice's planner, bound to `key`.
    async fn root_token(&self, key: &DpopKey) -> String {
        let url = self.url("/admin/root-token");
        let resp = self
            .client
            .post(&url)
            .bearer_auth(ADMIN)
            .header("DPoP", key.proof("POST", &url, None, now()))
            .json(&json!({
                "subject": "alice",
                "issuer": "https://idp.example",
                "agent": "planner",
                "capabilities": ["github:read_file"],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["token_type"], "DPoP");
        v["access_token"].as_str().unwrap().to_string()
    }

    /// An exchange of `parent` for `actor`, authenticated with the actor's secret, with the
    /// DPoP header `header` and the sign-off `sign_off`.
    async fn exchange(
        &self,
        parent: &str,
        actor: &str,
        header: String,
        sign_off: Option<String>,
    ) -> reqwest::Response {
        let mut body = json!({
            "grant_type": EXCHANGE,
            "subject_token": parent,
            "subject_token_type": JWT,
            "actor": actor,
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
            "client_id": actor,
            "client_secret": secret(actor),
        });
        if let Some(s) = sign_off {
            body["subject_token_dpop"] = s.into();
        }
        self.client
            .post(self.url("/token"))
            .header("DPoP", header)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// `tools/call read_file` through the proxy with `token` and the proof `dpop`.
    fn call(&self, token: &str, dpop: String) -> RequestBuilder {
        self.client
            .post(self.url("/mcp/github"))
            .header("authorization", format!("DPoP {token}"))
            .header("DPoP", dpop)
            .json(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"repo": "acme/api"}},
            }))
    }
}

/// Status, the reason code (`error` or JSON-RPC `data.reason`) and the body.
async fn outcome(resp: reqwest::Response) -> (StatusCode, String, Value) {
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    let code = v["error"]["data"]["reason"]
        .as_str()
        .or(v["error"].as_str())
        .unwrap_or_default()
        .to_string();
    (status, code, v)
}

/// SR-40: the parent's sign-off (`subject_token_dpop`) names the new token's key and agent.
/// Before the fix it was a plain proof by the parent's key, consent to "one exchange of this
/// token", which whoever held it could spend with any key and as any authenticated agent.
#[tokio::test]
async fn a_sign_off_is_good_only_for_the_key_and_agent_it_names_sr40() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), |_| {}).await;
    let (planner, coder, reviewer) = (
        DpopKey::generate().unwrap(),
        DpopKey::generate().unwrap(),
        DpopKey::generate().unwrap(),
    );
    let root = s.root_token(&planner).await;
    let url = s.url("/token");
    // The planner agrees to delegate to the coder's key, and hands over only this proof.
    let sign_off = planner.sign_off(&url, &root, coder.thumbprint(), "coder", now());

    // Another agent that gets hold of it (with the root token) cannot spend it on itself...
    let resp = s
        .exchange(
            &root,
            "reviewer",
            reviewer.proof("POST", &url, None, now()),
            Some(sign_off.clone()),
        )
        .await;
    let (status, code, v) = outcome(resp).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_dpop_proof"),
        "{v}"
    );
    // ...nor can the coder bind the new token to some other key.
    let resp = s
        .exchange(
            &root,
            "coder",
            reviewer.proof("POST", &url, None, now()),
            Some(sign_off.clone()),
        )
        .await;
    let (status, code, v) = outcome(resp).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_dpop_proof"),
        "{v}"
    );
    // The exchange it was made for goes through: the refused attempts did not use it up.
    let resp = s
        .exchange(
            &root,
            "coder",
            coder.proof("POST", &url, None, now()),
            Some(sign_off),
        )
        .await;
    let (status, _, v) = outcome(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let child = v["access_token"].as_str().unwrap();
    let mcp = s.url("/mcp/github");
    let resp = s
        .call(child, coder.proof("POST", &mcp, Some(child), now()))
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert!(v.get("result").is_some(), "{v}");
}

/// SR-41: a proof by the wrong key is refused before its `jti` is recorded. Before the fix,
/// whoever held a copy of a bound token (but not its key) could fill the per-process replay
/// cache with proofs by keys of its own, and every DPoP request failed until they expired.
#[tokio::test]
async fn wrong_key_proofs_cannot_lock_out_the_key_holder_sr41() {
    let dir = tempfile::tempdir().unwrap();
    // One slot for the root mint's proof, two for the holder's calls.
    let s = start(dir.path(), |cfg| cfg.token.dpop_replay_capacity = 3).await;
    let (key, thief) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
    let root = s.root_token(&key).await;
    let mcp = s.url("/mcp/github");
    for _ in 0..10 {
        let resp = s
            .call(&root, thief.proof("POST", &mcp, Some(&root), now()))
            .send()
            .await
            .unwrap();
        let (status, code, v) = outcome(resp).await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::UNAUTHORIZED, "invalid_dpop_proof"),
            "{v}"
        );
    }
    for _ in 0..2 {
        let resp = s
            .call(&root, key.proof("POST", &mcp, Some(&root), now()))
            .send()
            .await
            .unwrap();
        let (status, _, v) = outcome(resp).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert!(v.get("result").is_some(), "{v}");
    }
    assert_eq!(s.upstream.recorded_calls().len(), 2);
}

/// SR-42: without `public_url`, `htu` is checked against the request's `Host` only when that
/// is a loopback name. Before the fix any `Host` was taken, so a proof made for another server
/// was accepted here when sent with that server's name as `Host`.
#[tokio::test]
async fn a_proof_for_another_host_is_refused_sr42() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), |_| {}).await;
    let key = DpopKey::generate().unwrap();
    let root = s.root_token(&key).await;
    let elsewhere = "http://mcp.other.example/mcp/github";
    let resp = s
        .call(&root, key.proof("POST", elsewhere, Some(&root), now()))
        .header("host", "mcp.other.example")
        .send()
        .await
        .unwrap();
    let (status, code, v) = outcome(resp).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_dpop_proof"),
        "{v}"
    );
    assert!(s.upstream.recorded_calls().is_empty());
    // With the loopback URL the client actually used, the same key works.
    let mcp = s.url("/mcp/github");
    let resp = s
        .call(&root, key.proof("POST", &mcp, Some(&root), now()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// SR-43: a 500 says nothing about the cause. Before the fix the body carried the error text,
/// here the policy file's path; for agents, the lease and audit stores' SQLite errors.
#[tokio::test]
async fn internal_errors_do_not_reveal_paths_sr43() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), |_| {}).await;
    std::fs::remove_file(dir.path().join("policies.cedar")).unwrap();
    let resp = s
        .client
        .post(s.url("/admin/policies/reload"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let text = resp.text().await.unwrap();
    let dir_name = dir.path().to_string_lossy().into_owned();
    assert!(!text.contains(&dir_name), "{text}");
    assert!(!text.contains("policies.cedar"), "{text}");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["error"], "server_error");
    assert_eq!(v["detail"], attenuo_server::error::INTERNAL_DETAIL);
}

/// SR-45: the reserved agent id `attenuo` (SR-34) cannot be the actor of an exchange, also
/// when actor authentication is off. Before the fix the config check covered `[[agents]]`
/// only, and such an exchange minted a token whose audit records put `attenuo` next to the
/// server's own.
#[tokio::test]
async fn the_reserved_agent_id_cannot_receive_a_delegation_sr45() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), |cfg| cfg.token.require_actor_auth = false).await;
    let key = DpopKey::generate().unwrap();
    let root = s.root_token(&key).await;
    let url = s.url("/token");
    let resp = s
        .client
        .post(&url)
        .header("DPoP", key.proof("POST", &url, Some(&root), now()))
        .json(&json!({
            "grant_type": EXCHANGE,
            "subject_token": root,
            "subject_token_type": JWT,
            "actor": "attenuo",
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        }))
        .send()
        .await
        .unwrap();
    let (status, _, v) = outcome(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error_description"], "reserved_agent", "{v}");
}

/// SR-47: a full DPoP replay cache is a server-side limit. The proxy now answers 503 with
/// `Retry-After` and reason `dpop_replay_cache_full`, as the server's own routes do; before the
/// fix it answered 401 `invalid_dpop_proof`, which tells the client its proof or key is bad.
#[tokio::test]
async fn a_full_dpop_replay_cache_is_503_at_the_proxy_sr47() {
    let dir = tempfile::tempdir().unwrap();
    // One slot for the root mint's proof, one for the first call.
    let s = start(dir.path(), |cfg| cfg.token.dpop_replay_capacity = 2).await;
    let key = DpopKey::generate().unwrap();
    let root = s.root_token(&key).await;
    let mcp = s.url("/mcp/github");
    let resp = s
        .call(&root, key.proof("POST", &mcp, Some(&root), now()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = s
        .call(&root, key.proof("POST", &mcp, Some(&root), now()))
        .send()
        .await
        .unwrap();
    assert!(resp.headers().contains_key("retry-after"));
    let (status, code, v) = outcome(resp).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "dpop_replay_cache_full"),
        "{v}"
    );
    assert_eq!(s.upstream.recorded_calls().len(), 1);
}
