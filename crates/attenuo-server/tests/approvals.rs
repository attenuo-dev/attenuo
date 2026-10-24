//! Approvals through the whole server (ADR-0009): a call gated by `@obligation("approval")`
//! gets `-32008` with an approval id; the originating user (an ID token from a fake IdP) or an
//! operator (the admin bearer) grants or declines it; the identical retry is allowed once,
//! with `context.approval.by` set and the approval recorded as consumed; and leases, expiry,
//! the call hash, DPoP and the user check all hold.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_core::ToolCall;
use attenuo_policy::ToolAttrs;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::{DpopMode, IdpConfig};
use attenuo_server::{AppState, Config};
use attenuo_token::DpopKey;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use time::OffsetDateTime;

const ADMIN: &str = "approvals-test-admin";
const CLIENT_AUD: &str = "attenuo-client";

/// Ask before anything destructive once the run has read something untrusted, unless the
/// call carries a granted approval.
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
"#;

// ---------------------------------------------------------------------------------------------
// A fake IdP: OIDC discovery and a JWKS with one Ed25519 key, minting ID tokens.
// ---------------------------------------------------------------------------------------------

struct FakeIdp {
    issuer: String,
    kid: String,
    encoding: EncodingKey,
    _task: AbortOnDrop,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl FakeIdp {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                         "kid": "k1", "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())});
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "id_token_signing_alg_values_supported": ["EdDSA"],
        });
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let d = discovery.clone();
                    async move { Json(d) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let k = jwk.clone();
                    async move { Json(json!({ "keys": [k] })) }
                }),
            );
        let task = AbortOnDrop(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));
        Self {
            issuer,
            kid: "k1".into(),
            encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
            _task: task,
        }
    }

    /// A fresh ID token for `sub` (a new `jti` each time), issued to `aud`.
    fn id_token_for(&self, sub: &str, aud: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({
            "iss": self.issuer, "aud": aud, "sub": sub,
            "iat": now, "exp": now + 300, "jti": uuid::Uuid::new_v4().to_string(),
        });
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, &claims, &self.encoding).unwrap()
    }

    fn id_token(&self, sub: &str) -> String {
        self.id_token_for(sub, CLIENT_AUD)
    }
}

// ---------------------------------------------------------------------------------------------
// The attenuo server.
// ---------------------------------------------------------------------------------------------

struct Harness {
    idp: FakeIdp,
    server: Spawned,
    state: Arc<AppState>,
    cfg: Config,
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

/// What a gated call's `-32008` carried.
struct Gated {
    approval_id: String,
    call_hash: String,
    expires_at: String,
}

fn allowed(v: &Value) -> bool {
    v.get("result").is_some()
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    async fn start_with(tweak: impl FnOnce(&mut Config)) -> Self {
        let idp = FakeIdp::start().await;
        let upstream = FakeMcpServer::new(&["read_web", "delete_repo"]);
        let upstream_task = upstream.spawn().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.policy.policies_path = Some(policy_path);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([
                ("read_web".to_string(), ToolAttrs::new().readonly(true)),
                ("delete_repo".to_string(), ToolAttrs::new()),
            ]),
        )]);
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.idps = vec![IdpConfig {
            issuer: idp.issuer.clone(),
            audience: String::new(),
            jwks_url: None,
            allowed_algs: vec!["EdDSA".into()],
            attribute_claims: vec![],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            client_ids: [("planner".to_string(), CLIENT_AUD.to_string())].into(),
        }];
        tweak(&mut cfg);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            idp,
            server: spawn_router(router).await.unwrap(),
            state,
            cfg,
            upstream,
            _upstream_task: upstream_task,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    /// A root token for `subject` at the fake IdP, for agent `planner`: a new run. Bound to
    /// `key` when given.
    async fn root_for(&self, subject: &str, key: Option<&DpopKey>) -> String {
        let url = self.server.url("/admin/root-token");
        let mut req = self.client.post(&url).bearer_auth(ADMIN).json(&json!({
            "subject": subject,
            "issuer": self.idp.issuer,
            "agent": "planner",
            "capabilities": ["github:*"],
        }));
        if let Some(k) = key {
            req = req.header(
                "DPoP",
                k.proof("POST", &url, None, OffsetDateTime::now_utc()),
            );
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["access_token"].as_str().unwrap().to_string()
    }

    async fn root(&self) -> String {
        self.root_for("alice", None).await
    }

    async fn rpc(&self, token: &str, key: Option<&DpopKey>, body: Value) -> reqwest::Response {
        let url = self.server.url("/mcp/github");
        let mut req = self
            .client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        req = match key {
            Some(k) => req.header("authorization", format!("DPoP {token}")).header(
                "DPoP",
                k.proof("POST", &url, Some(token), OffsetDateTime::now_utc()),
            ),
            None => req.bearer_auth(token),
        };
        req.send().await.unwrap()
    }

    async fn call_with(&self, token: &str, key: Option<&DpopKey>, tool: &str, repo: &str) -> Value {
        let resp = self
            .rpc(
                token,
                key,
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": {"repo": repo}}}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn call(&self, token: &str, tool: &str, repo: &str) -> Value {
        self.call_with(token, None, tool, repo).await
    }

    /// Read something untrusted, so destructive calls of the run need an approval.
    async fn taint(&self, token: &str) {
        assert!(allowed(&self.call(token, "read_web", "x").await));
    }

    fn expect_gated(v: &Value) -> Gated {
        let err = &v["error"];
        assert_eq!(err["code"], -32008, "{v}");
        let data = &err["data"];
        assert_eq!(data["reason"], "approval_required");
        Gated {
            approval_id: data["approval_id"].as_str().expect("approval_id").into(),
            call_hash: data["call_hash"].as_str().unwrap().into(),
            expires_at: data["expires_at"].as_str().expect("expires_at").into(),
        }
    }

    async fn delete(&self, token: &str, repo: &str) -> Value {
        self.call(token, "delete_repo", repo).await
    }

    async fn gated(&self, token: &str, repo: &str) -> Gated {
        Self::expect_gated(&self.delete(token, repo).await)
    }

    async fn user_decide(&self, id: &str, bearer: &str, decision: &str) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.server.url(&format!("/approvals/{id}")))
            .bearer_auth(bearer)
            .json(&json!({ "decision": decision }))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn grant_as_alice(&self, id: &str) -> Value {
        let (status, v) = self
            .user_decide(id, &self.idp.id_token("alice"), "grant")
            .await;
        assert_eq!(status, StatusCode::OK, "{v}");
        v
    }

    async fn admin_decide(&self, id: &str, decision: &str) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.server.url(&format!("/admin/approvals/{id}")))
            .bearer_auth(ADMIN)
            .json(&json!({ "decision": decision }))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn admin_get(&self, path: &str) -> Value {
        let resp = self
            .client
            .get(self.server.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    /// Every audit record, with its `seq` folded in.
    async fn records(&self) -> Vec<Value> {
        let v = self.admin_get("/admin/audit?from=1&limit=1000").await;
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let mut r = e["record"].clone();
                r["seq"] = e["seq"].clone();
                r
            })
            .collect()
    }

    async fn verify_ok(&self) {
        let v = self.admin_get("/admin/audit/verify").await;
        assert_eq!(v["ok"], true, "{v}");
    }

    fn deletes_upstream(&self) -> usize {
        self.upstream
            .recorded_calls()
            .iter()
            .filter(|c| c.name == "delete_repo")
            .count()
    }
}

#[tokio::test]
async fn user_grant_lets_the_identical_retry_through_once() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    let expected = ToolCall::new("github", "delete_repo", json!({"repo": "alice/site"}));
    assert_eq!(g.call_hash, expected.call_hash());
    assert!(!g.expires_at.is_empty());

    // Repeating the gated call before anyone decides gives the same approval.
    assert_eq!(
        h.gated(&token, "alice/site").await.approval_id,
        g.approval_id
    );

    // The approval shows the exact call and the labels.
    let shown = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert_eq!(shown["state"], "pending");
    assert_eq!(shown["call"]["tool"], "delete_repo");
    assert_eq!(shown["call"]["arguments"], json!({"repo": "alice/site"}));
    assert_eq!(shown["labels"][0]["source"], "github/read_web");
    assert!(shown["labels"][0]["seq"].as_u64().is_some());
    assert_eq!(shown["subject"], "alice");
    assert_eq!(shown["expires_at"], g.expires_at);

    let granted = h.grant_as_alice(&g.approval_id).await;
    assert_eq!(granted["state"], "granted");
    assert_eq!(granted["approver"]["by"], "user");
    assert_eq!(granted["approver"]["method"], "id_token");

    // The identical retry runs, once.
    assert_eq!(h.deletes_upstream(), 0);
    let v = h.delete(&token, "alice/site").await;
    assert!(allowed(&v), "{v}");
    assert_eq!(h.deletes_upstream(), 1);
    let after = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert_eq!(after["state"], "consumed");

    // Single use: the next identical call asks again, with a new approval.
    let again = h.gated(&token, "alice/site").await;
    assert_ne!(again.approval_id, g.approval_id);
    assert_eq!(h.deletes_upstream(), 1);

    // The audit trail: request, grant, and the decision that consumed the approval.
    let records = h.records().await;
    let request = records
        .iter()
        .find(|r| r["kind"] == "approval_request" && r["approval"]["id"] == g.approval_id.as_str())
        .unwrap();
    assert_eq!(request["approval"]["call_hash"], g.call_hash);
    assert_eq!(request["approval"]["expires_at"], g.expires_at);
    assert_eq!(request["reason"], "approval_requested");
    let gated_decision = records
        .iter()
        .find(|r| r["id"] == request["decision_id"])
        .unwrap();
    assert_eq!(gated_decision["reason"], "approval_required");
    let grant = records
        .iter()
        .find(|r| r["kind"] == "approval_grant")
        .unwrap();
    assert_eq!(grant["approval"]["id"], g.approval_id.as_str());
    assert_eq!(grant["approval"]["outcome"], "grant");
    assert_eq!(grant["approval"]["approver"], "alice");
    assert_eq!(grant["approval"]["method"], "id_token");
    assert_eq!(grant["approval"]["by"], "user");
    assert_eq!(grant["reason"], "approval_granted");
    let used = records
        .iter()
        .find(|r| {
            r["kind"] == "decision" && r["reason"] == "policy_allow" && r["tool"] == "delete_repo"
        })
        .unwrap();
    assert_eq!(used["approval"], json!({"id": g.approval_id, "by": "user"}));
    assert_eq!(after["consumed_by"], used["id"]);
    // One request record per approval, however often the gated call was repeated.
    assert_eq!(
        records
            .iter()
            .filter(|r| r["kind"] == "approval_request")
            .count(),
        2
    );
    h.verify_ok().await;
}

#[tokio::test]
async fn decline_then_retry_is_gated_again() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    let (status, v) = h
        .user_decide(&g.approval_id, &h.idp.id_token("alice"), "decline")
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "declined");
    let again = h.gated(&token, "alice/site").await;
    assert_ne!(again.approval_id, g.approval_id);
    assert_eq!(h.deletes_upstream(), 0);
    // A declined approval cannot be granted afterwards.
    let (status, v) = h.admin_decide(&g.approval_id, "grant").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(v["error"], "approval_not_pending");
    let records = h.records().await;
    let decline = records
        .iter()
        .find(|r| r["kind"] == "approval_grant")
        .unwrap();
    assert_eq!(decline["approval"]["outcome"], "decline");
    assert_eq!(decline["decision"], "deny");
    assert_eq!(decline["reason"], "approval_declined");
    h.verify_ok().await;
}

#[tokio::test]
async fn expired_approval_is_gated() {
    let h = Harness::start_with(|c| c.approvals.ttl_seconds = 1).await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    h.grant_as_alice(&g.approval_id).await;
    let g2 = h.gated(&token, "alice/other").await;
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    // Granted but expired: not used.
    let v = h.delete(&token, "alice/site").await;
    assert_eq!(v["error"]["code"], -32008, "{v}");
    assert_eq!(h.deletes_upstream(), 0);
    // Pending and expired: cannot be granted.
    let (status, v) = h
        .user_decide(&g2.approval_id, &h.idp.id_token("alice"), "grant")
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"], "approval_expired");
    let shown = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert_eq!(shown["expired"], true);
}

#[tokio::test]
async fn only_the_originating_users_fresh_id_token_approves() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;

    // Another user of the same IdP.
    let (status, v) = h
        .user_decide(&g.approval_id, &h.idp.id_token("bob"), "grant")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"], "wrong_user");
    // The agent's own delegation token.
    let (status, v) = h.user_decide(&g.approval_id, &token, "grant").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"], "agent_token_refused");
    // An ID token issued to another client.
    let (status, _) = h
        .user_decide(
            &g.approval_id,
            &h.idp.id_token_for("alice", "some-other-client"),
            "grant",
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The admin bearer is not a user credential.
    let (status, _) = h.user_decide(&g.approval_id, ADMIN, "grant").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // No bearer at all.
    let resp = h
        .client
        .post(h.server.url(&format!("/approvals/{}", g.approval_id)))
        .json(&json!({"decision": "grant"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Nothing was granted.
    let shown = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert_eq!(shown["state"], "pending");

    // An ID token is used once: presenting it again is refused, even for another approval.
    let id_token = h.idp.id_token("alice");
    let (status, _) = h.user_decide(&g.approval_id, &id_token, "grant").await;
    assert_eq!(status, StatusCode::OK);
    let g2 = h.gated(&token, "alice/other").await;
    let (status, v) = h.user_decide(&g2.approval_id, &id_token, "grant").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error_description"], "replayed");

    // An unknown approval id.
    let (status, _) = h
        .user_decide(
            "00000000-0000-4000-8000-000000000000",
            &h.idp.id_token("alice"),
            "grant",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A malformed decision.
    let (status, _) = h
        .user_decide(&g2.approval_id, &h.idp.id_token("alice"), "maybe")
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_approval_for_a_different_call_hash_is_not_used() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    h.grant_as_alice(&g.approval_id).await;
    // Other arguments: another hash, so gated with a new approval.
    let other = h.gated(&token, "alice/prod").await;
    assert_ne!(other.approval_id, g.approval_id);
    assert_ne!(other.call_hash, g.call_hash);
    assert_eq!(h.deletes_upstream(), 0);
    // Another run of the same user cannot use it either: approvals are bound to the run.
    let other_run = h.root().await;
    h.taint(&other_run).await;
    assert_eq!(
        h.delete(&other_run, "alice/site").await["error"]["code"],
        -32008
    );
    // The approved call itself still goes through.
    assert!(allowed(&h.delete(&token, "alice/site").await));
    assert_eq!(h.deletes_upstream(), 1);
}

/// ADR-0009 `revoked_lease_kills_pending_and_granted_approvals`.
#[tokio::test]
async fn revoked_lease_kills_pending_and_granted_approvals() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let granted = h.gated(&token, "alice/site").await;
    h.grant_as_alice(&granted.approval_id).await;
    let pending = h.gated(&token, "alice/other").await;
    let chain = h
        .state
        .verifier
        .verify(&token, OffsetDateTime::now_utc())
        .unwrap()
        .chain;
    let lease = chain.hops[0].lease.0.clone();
    let resp = h
        .client
        .post(h.server.url(&format!("/admin/leases/{lease}/revoke")))
        .bearer_auth(ADMIN)
        .json(&json!({"reason": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The granted approval's call is denied on the lease, before any approval is looked at.
    let v = h.delete(&token, "alice/site").await;
    assert_eq!(v["error"]["code"], -32003, "{v}");
    assert_eq!(v["error"]["data"]["reason"], "lease_revoked");
    assert_eq!(h.deletes_upstream(), 0);
    // The approval was not spent by the denied call.
    let shown = h
        .admin_get(&format!("/admin/approvals/{}", granted.approval_id))
        .await;
    assert_eq!(shown["state"], "granted");
    // The pending one can no longer be granted.
    let (status, v) = h
        .user_decide(&pending.approval_id, &h.idp.id_token("alice"), "grant")
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"], "lease_revoked");
}

#[tokio::test]
async fn operator_grant_on_the_admin_listener() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    let chain_id = h
        .state
        .verifier
        .verify(&token, OffsetDateTime::now_utc())
        .unwrap()
        .chain
        .hops[0]
        .lease
        .0
        .clone();

    // The console listener lists and shows it, and grants with allow_write.
    let mut cfg = h.cfg.clone();
    cfg.admin_ui.allow_write = true;
    let console = spawn_router(attenuo_server::admin_ui::router(h.state.clone(), &cfg))
        .await
        .unwrap();
    let list: Value = h
        .client
        .get(console.url(&format!(
            "/admin/approvals?chain_id={chain_id}&state=pending"
        )))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let approvals = list["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0]["approval_id"], g.approval_id.as_str());
    let none: Value = h
        .client
        .get(console.url("/admin/approvals?chain_id=nobody"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(none["approvals"].as_array().unwrap().is_empty());
    // Without a JSON content type a write is refused there, as for revoke.
    let resp = h
        .client
        .post(console.url(&format!("/admin/approvals/{}", g.approval_id)))
        .bearer_auth(ADMIN)
        .body(r#"{"decision":"grant"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let resp = h
        .client
        .post(console.url(&format!("/admin/approvals/{}", g.approval_id)))
        .bearer_auth(ADMIN)
        .json(&json!({"decision": "grant"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["approver"]["by"], "operator");
    assert_eq!(v["approver"]["subject"], "urn:attenuo:admin");

    assert!(allowed(&h.delete(&token, "alice/site").await));
    let records = h.records().await;
    let used = records
        .iter()
        .find(|r| {
            r["kind"] == "decision" && r["reason"] == "policy_allow" && r["tool"] == "delete_repo"
        })
        .unwrap();
    assert_eq!(used["approval"]["by"], "operator");
    let grant = records
        .iter()
        .find(|r| r["kind"] == "approval_grant")
        .unwrap();
    assert_eq!(grant["approval"]["method"], "admin_token");
    h.verify_ok().await;

    // A read-only console does not mount the grant route.
    let ro = spawn_router(attenuo_server::admin_ui::router(h.state.clone(), &h.cfg))
        .await
        .unwrap();
    let g2 = h.gated(&token, "alice/other").await;
    let resp = h
        .client
        .post(ro.url(&format!("/admin/approvals/{}", g2.approval_id)))
        .bearer_auth(ADMIN)
        .json(&json!({"decision": "grant"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
    assert_ne!(resp.status(), StatusCode::OK);
    // And the operator route needs the admin bearer.
    let resp = h
        .client
        .post(
            h.server
                .url(&format!("/admin/approvals/{}", g2.approval_id)),
        )
        .bearer_auth(&token)
        .json(&json!({"decision": "grant"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn the_agent_can_poll_its_own_approval_only() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    let get = |bearer: String| {
        let url = h.server.url(&format!("/approvals/{}", g.approval_id));
        let client = h.client.clone();
        async move { client.get(url).bearer_auth(bearer).send().await.unwrap() }
    };
    let resp = get(token.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["state"], "pending");
    assert_eq!(v["call_hash"], g.call_hash);
    // The user sees it with an ID token, which is not used up by looking.
    let id_token = h.idp.id_token("alice");
    assert_eq!(get(id_token.clone()).await.status(), StatusCode::OK);
    assert_eq!(
        h.user_decide(&g.approval_id, &id_token, "grant").await.0,
        StatusCode::OK
    );
    let v: Value = get(token.clone()).await.json().await.unwrap();
    assert_eq!(v["state"], "granted");
    // Another run's agent, and another user, do not see it.
    let other = h.root_for("bob", None).await;
    assert_eq!(get(other).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        get(h.idp.id_token("bob")).await.status(),
        StatusCode::FORBIDDEN
    );
}

/// A DPoP-bound agent's retry needs a proof by its key, like any call: an approval does not
/// stand in for one.
#[tokio::test]
async fn a_dpop_bound_retry_needs_its_proof() {
    let h = Harness::start_with(|c| c.token.dpop = DpopMode::Optional).await;
    let key = DpopKey::generate().unwrap();
    let token = h.root_for("alice", Some(&key)).await;
    assert!(allowed(
        &h.call_with(&token, Some(&key), "read_web", "x").await
    ));
    let g = Harness::expect_gated(
        &h.call_with(&token, Some(&key), "delete_repo", "alice/site")
            .await,
    );
    h.grant_as_alice(&g.approval_id).await;
    // The token without a proof is refused before any decision.
    let resp = h
        .rpc(
            &token,
            None,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "delete_repo", "arguments": {"repo": "alice/site"}}}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // A proof by another key is refused too.
    let other = DpopKey::generate().unwrap();
    let resp = h
        .rpc(
            &token,
            Some(&other),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "delete_repo", "arguments": {"repo": "alice/site"}}}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(h.deletes_upstream(), 0);
    // Polling the approval with the bound token needs a proof as well.
    let url = h.server.url(&format!("/approvals/{}", g.approval_id));
    let resp = h.client.get(&url).bearer_auth(&token).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = h
        .client
        .get(&url)
        .header("authorization", format!("DPoP {token}"))
        .header(
            "DPoP",
            key.proof("GET", &url, Some(&token), OffsetDateTime::now_utc()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // With its proof the retry runs.
    assert!(allowed(
        &h.call_with(&token, Some(&key), "delete_repo", "alice/site")
            .await
    ));
    assert_eq!(h.deletes_upstream(), 1);
}

/// AuthZEN callers get the approval id too, and the retry through AuthZEN consumes it.
#[tokio::test]
async fn authzen_answers_carry_the_approval() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let eval = || async {
        let resp = h
            .client
            .post(h.server.url("/access/v1/evaluation"))
            .bearer_auth(&token)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "delete_repo"},
                "resource": {"type": "tool", "id": "github/delete_repo",
                             "properties": {"server": "github"}},
                "context": {"input": {"repo": "alice/site"}},
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json::<Value>().await.unwrap()
    };
    let v = eval().await;
    assert_eq!(v["decision"], false, "{v}");
    let id = v["context"]["approval_id"].as_str().unwrap().to_string();
    assert!(v["context"]["expires_at"].as_str().is_some());
    h.grant_as_alice(&id).await;
    let v = eval().await;
    assert_eq!(v["decision"], true, "{v}");
    assert_eq!(v["context"]["approval"]["id"], id.as_str());
    assert_eq!(v["context"]["approval"]["by"], "user");
}
