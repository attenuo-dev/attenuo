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

/// The value of the `/metrics` sample whose series is exactly `series`.
fn metric(h: &Harness, series: &str) -> u64 {
    let text = h.state.metrics.render();
    attenuo_server::metrics::check_text_format(&text).unwrap();
    let prefix = format!("{series} ");
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {series} in:\n{text}"))
        .trim()
        .parse()
        .unwrap()
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
    // And on /metrics: two approvals stored, one granted by the user and consumed, the
    // gated calls counted by reason, and the untrusted read that tainted the run.
    assert_eq!(metric(&h, "attenuo_approvals_created_total"), 2);
    assert_eq!(
        metric(
            &h,
            "attenuo_approvals_decided_total{outcome=\"granted\",by=\"user\"}"
        ),
        1
    );
    assert_eq!(
        metric(
            &h,
            "attenuo_approvals_decided_total{outcome=\"granted\",by=\"operator\"}"
        ),
        0
    );
    assert_eq!(
        metric(&h, "attenuo_approvals_consumed_total{by=\"user\"}"),
        1
    );
    assert_eq!(
        metric(
            &h,
            "attenuo_decisions_total{decision=\"deny\",reason=\"approval_required\"}"
        ),
        3
    );
    assert!(metric(&h, "attenuo_results_recorded_total{label=\"untrusted\"}") >= 1);
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
    // The refused grant of a declined approval is not counted.
    assert_eq!(
        metric(
            &h,
            "attenuo_approvals_decided_total{outcome=\"declined\",by=\"user\"}"
        ),
        1
    );
    assert_eq!(
        metric(
            &h,
            "attenuo_approvals_decided_total{outcome=\"granted\",by=\"operator\"}"
        ),
        0
    );
    assert_eq!(
        metric(&h, "attenuo_approvals_consumed_total{by=\"user\"}"),
        0
    );
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
    // The refused grant counts as expired; the granted one that lapsed unused does not
    // (expiry is not a state, nothing sees it go).
    assert_eq!(metric(&h, "attenuo_approvals_expired_total"), 1);
    assert_eq!(
        metric(&h, "attenuo_approvals_consumed_total{by=\"user\"}"),
        0
    );
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
    let approval_token = h.grant_as_alice(&granted.approval_id).await["approval_token"]
        .as_str()
        .unwrap()
        .to_string();
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
    // So is the call presenting the approval token: leases come first (ADR-0006).
    let v = h
        .delete_presenting(&token, None, "alice/site", &approval_token)
        .await;
    assert_eq!(v["error"]["data"]["reason"], "lease_revoked", "{v}");
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
    assert_eq!(
        metric(
            &h,
            "attenuo_approvals_decided_total{outcome=\"granted\",by=\"operator\"}"
        ),
        1
    );
    assert_eq!(
        metric(&h, "attenuo_approvals_consumed_total{by=\"operator\"}"),
        1
    );
    assert_eq!(
        metric(&h, "attenuo_approvals_consumed_total{by=\"user\"}"),
        0
    );

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

// ---------------------------------------------------------------------------------------------
// Signed approval tokens (design section 3.7): issued with a grant, presented in
// `params._meta["dev.attenuo/approval"]`, checked against the call and taken by id.
// ---------------------------------------------------------------------------------------------

impl Harness {
    /// `tools/call delete_repo {repo}` with `token` in `_meta` (and another `_meta` member, which
    /// must reach the upstream untouched).
    async fn delete_presenting(
        &self,
        token: &str,
        key: Option<&DpopKey>,
        repo: &str,
        approval_token: &str,
    ) -> Value {
        let resp = self
            .rpc(
                token,
                key,
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "delete_repo", "arguments": {"repo": repo},
                                  "_meta": {"progressToken": 7,
                                            "dev.attenuo/approval": approval_token}}}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    /// The `(chain_id, lease)` of a delegation token's run and last hop.
    fn run_of(&self, token: &str) -> (String, String) {
        let chain = self
            .state
            .verifier
            .verify(token, OffsetDateTime::now_utc())
            .unwrap()
            .chain;
        (
            chain.hops[0].lease.0.clone(),
            chain.hops.last().unwrap().lease.0.clone(),
        )
    }

    async fn exchange(&self, parent: &str, actor: &str) -> String {
        let resp = self
            .client
            .post(self.server.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "attenuo_capabilities",
                    "capabilities": [{"server": "github", "tool": "*"}]}],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["access_token"].as_str().unwrap().to_string()
    }
}

fn expect_approval_invalid(v: &Value) {
    assert_eq!(v["error"]["code"], -32003, "{v}");
    assert_eq!(v["error"]["data"]["reason"], "approval_invalid", "{v}");
}

#[tokio::test]
async fn approval_token_is_issued_with_the_grant_and_used_once() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    let (chain_id, lease) = h.run_of(&token);

    // No token while pending.
    let pending = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert!(pending.get("approval_token").is_none(), "{pending}");

    let granted = h.grant_as_alice(&g.approval_id).await;
    let approval_token = granted["approval_token"].as_str().expect("approval_token");

    // Signed with the issuer key (same kid as the JWKS), typ attenuo-approval+jwt.
    let header = jsonwebtoken::decode_header(approval_token).unwrap();
    assert_eq!(header.typ.as_deref(), Some("attenuo-approval+jwt"));
    assert_eq!(
        header.kid.as_deref(),
        Some(h.state.issuer.key_id().as_str())
    );
    let jwks: Value = h
        .client
        .get(h.server.url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(jwks["keys"][0]["kid"], h.state.issuer.key_id().as_str());
    let claims = h
        .state
        .verifier
        .verify_approval(approval_token, OffsetDateTime::now_utc())
        .unwrap();
    assert_eq!(claims.jti, g.approval_id);
    assert_eq!(claims.ch, g.call_hash);
    assert_eq!(claims.chain_id, chain_id);
    assert_eq!(claims.lease, lease);
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.by, "user");
    assert_eq!(claims.iss, h.state.issuer.config().issuer);
    assert_eq!(claims.aud, h.state.issuer.config().audience);
    assert!(claims.cnf.is_none());
    let expires = OffsetDateTime::parse(
        &g.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(claims.exp, expires.unix_timestamp());

    // Every GET of the granted approval carries the same token: the agent's, the operator's.
    let agent_view: Value = h
        .client
        .get(h.server.url(&format!("/approvals/{}", g.approval_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agent_view["approval_token"], approval_token);
    let admin_view = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert_eq!(admin_view["approval_token"], approval_token);

    // Presented with the call, it lets the call through; `_meta` does not change the call.
    let v = h
        .delete_presenting(&token, None, "alice/site", approval_token)
        .await;
    assert!(allowed(&v), "{v}");
    assert_eq!(h.deletes_upstream(), 1);
    let upstream = h.upstream.recorded_calls();
    let sent = &upstream.last().unwrap().params;
    assert_eq!(
        *sent,
        json!({"name": "delete_repo", "arguments": {"repo": "alice/site"},
               "_meta": {"progressToken": 7}}),
        "the approval token never reaches the upstream"
    );
    let records = h.records().await;
    let used = records
        .iter()
        .find(|r| {
            r["kind"] == "decision" && r["reason"] == "policy_allow" && r["tool"] == "delete_repo"
        })
        .unwrap();
    assert_eq!(
        used["approval"],
        json!({"id": g.approval_id, "by": "user", "presented": "token"})
    );
    // The call hash ignores `_meta`: the consuming decision's digest is the bare call's.
    let bare = ToolCall::new("github", "delete_repo", json!({"repo": "alice/site"}));
    assert_eq!(used["arguments_digest"], bare.arguments_digest());
    let after = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert_eq!(after["state"], "consumed");
    assert_eq!(after["consumed_by"], used["id"]);
    assert!(after.get("approval_token").is_none(), "{after}");

    // Single use: the same token again is refused with approval_invalid, not gated.
    let v = h
        .delete_presenting(&token, None, "alice/site", approval_token)
        .await;
    expect_approval_invalid(&v);
    assert_eq!(h.deletes_upstream(), 1);
    let records = h.records().await;
    assert!(records
        .iter()
        .any(|r| r["reason"] == "approval_invalid" && r["decision"] == "deny"));
    h.verify_ok().await;
}

#[tokio::test]
async fn approval_token_for_another_call_is_refused_and_the_approval_kept() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    let granted = h.grant_as_alice(&g.approval_id).await;
    let approval_token = granted["approval_token"].as_str().unwrap();
    // Wrong `ch`: another repo.
    let v = h
        .delete_presenting(&token, None, "alice/other", approval_token)
        .await;
    expect_approval_invalid(&v);
    assert_eq!(h.deletes_upstream(), 0);
    // The approval is untouched: the identical retry (no token) still uses it.
    let shown = h
        .admin_get(&format!("/admin/approvals/{}", g.approval_id))
        .await;
    assert_eq!(shown["state"], "granted");
    assert!(allowed(&h.delete(&token, "alice/site").await));
    assert_eq!(h.deletes_upstream(), 1);
    // A token that is not a JWT at all is refused the same way.
    let v = h
        .delete_presenting(&token, None, "alice/site", "not-a-token")
        .await;
    expect_approval_invalid(&v);
    // So is a delegation token in the approval slot.
    let v = h
        .delete_presenting(&token, None, "alice/site", &token)
        .await;
    expect_approval_invalid(&v);
}

#[tokio::test]
async fn approval_token_for_a_declined_approval_is_refused() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let g = h.gated(&token, "alice/site").await;
    let (chain_id, lease) = h.run_of(&token);
    let (status, v) = h.admin_decide(&g.approval_id, "decline").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v.get("approval_token").is_none(), "{v}");
    // A correctly signed token naming the declined approval (as an attacker who had the key
    // could not make, but a stale or replayed one would look) is refused by the store state.
    let now = OffsetDateTime::now_utc();
    let forged = h
        .state
        .issuer
        .issue_approval(&attenuo_token::ApprovalGrant {
            approval_id: &g.approval_id,
            approver: "urn:attenuo:admin",
            by: "operator",
            chain_id: &chain_id,
            lease: &lease,
            call_hash: &g.call_hash,
            granted_at: now,
            expires_at: now + time::Duration::seconds(60),
            jkt: None,
        })
        .unwrap();
    let v = h
        .delete_presenting(&token, None, "alice/site", &forged)
        .await;
    expect_approval_invalid(&v);
    assert_eq!(h.deletes_upstream(), 0);
}

/// An approval is bound to the hop that asked: a sibling hop of the same run cannot use it,
/// with or without the token.
#[tokio::test]
async fn approval_token_of_a_sibling_hop_is_refused() {
    let h = Harness::start_with(|c| c.token.require_actor_auth = false).await;
    let root = h.root().await;
    let coder = h.exchange(&root, "coder").await;
    let reviewer = h.exchange(&root, "reviewer").await;
    h.taint(&coder).await;
    let g = h.gated(&coder, "alice/site").await;
    let granted = h.grant_as_alice(&g.approval_id).await;
    let approval_token = granted["approval_token"].as_str().unwrap();
    let (_, coder_lease) = h.run_of(&coder);
    let claims = h
        .state
        .verifier
        .verify_approval(approval_token, OffsetDateTime::now_utc())
        .unwrap();
    assert_eq!(claims.lease, coder_lease);
    // Same run, same call, other hop: refused.
    let v = h
        .delete_presenting(&reviewer, None, "alice/site", approval_token)
        .await;
    expect_approval_invalid(&v);
    assert_eq!(h.deletes_upstream(), 0);
    // The hop it was granted to can use it.
    let v = h
        .delete_presenting(&coder, None, "alice/site", approval_token)
        .await;
    assert!(allowed(&v), "{v}");
}

/// For a DPoP-bound hop the token carries the hop's `cnf.jkt`, and only a token bound to the
/// key the request proved is accepted.
#[tokio::test]
async fn approval_token_of_a_dpop_bound_hop_is_bound_to_its_key() {
    let h = Harness::start_with(|c| c.token.dpop = DpopMode::Optional).await;
    let key = DpopKey::generate().unwrap();
    let token = h.root_for("alice", Some(&key)).await;
    let (chain_id, lease) = h.run_of(&token);
    assert!(allowed(
        &h.call_with(&token, Some(&key), "read_web", "x").await
    ));
    let g = Harness::expect_gated(
        &h.call_with(&token, Some(&key), "delete_repo", "alice/site")
            .await,
    );
    let granted = h.grant_as_alice(&g.approval_id).await;
    let approval_token = granted["approval_token"].as_str().unwrap();
    let claims = h
        .state
        .verifier
        .verify_approval(approval_token, OffsetDateTime::now_utc())
        .unwrap();
    assert_eq!(claims.cnf.unwrap().jkt, key.thumbprint());

    // A token for the same approval but minted for another key, or for no key, is refused
    // even with the right key's proof.
    let other = DpopKey::generate().unwrap();
    let now = OffsetDateTime::now_utc();
    let mint = |jkt: Option<&str>| {
        h.state
            .issuer
            .issue_approval(&attenuo_token::ApprovalGrant {
                approval_id: &g.approval_id,
                approver: "alice",
                by: "user",
                chain_id: &chain_id,
                lease: &lease,
                call_hash: &g.call_hash,
                granted_at: now,
                expires_at: now + time::Duration::seconds(60),
                jkt,
            })
            .unwrap()
    };
    for wrong in [mint(Some(other.thumbprint())), mint(None)] {
        let v = h
            .delete_presenting(&token, Some(&key), "alice/site", &wrong)
            .await;
        expect_approval_invalid(&v);
    }
    assert_eq!(h.deletes_upstream(), 0);
    // The real one, with the key's proof, goes through.
    let v = h
        .delete_presenting(&token, Some(&key), "alice/site", approval_token)
        .await;
    assert!(allowed(&v), "{v}");
    assert_eq!(h.deletes_upstream(), 1);
}

/// AuthZEN takes the token in `context.approval_token`.
#[tokio::test]
async fn authzen_takes_the_approval_token_in_context() {
    let h = Harness::start().await;
    let token = h.root().await;
    h.taint(&token).await;
    let eval = |approval_token: Option<String>| {
        let h = &h;
        let token = token.clone();
        async move {
            let mut context = json!({"input": {"repo": "alice/site"}});
            if let Some(t) = approval_token {
                context["approval_token"] = json!(t);
            }
            let resp = h
                .client
                .post(h.server.url("/access/v1/evaluation"))
                .bearer_auth(&token)
                .json(&json!({
                    "subject": {"type": "agent", "id": ""},
                    "action": {"name": "delete_repo"},
                    "resource": {"type": "tool", "id": "github/delete_repo",
                                 "properties": {"server": "github"}},
                    "context": context,
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            resp.json::<Value>().await.unwrap()
        }
    };
    let v = eval(None).await;
    let id = v["context"]["approval_id"].as_str().unwrap().to_string();
    let granted = h.grant_as_alice(&id).await;
    let approval_token = granted["approval_token"].as_str().unwrap().to_string();
    let v = eval(Some(approval_token.clone())).await;
    assert_eq!(v["decision"], true, "{v}");
    assert_eq!(
        v["context"]["approval"],
        json!({"id": id, "by": "user", "presented": "token"})
    );
    let v = eval(Some(approval_token)).await;
    assert_eq!(v["decision"], false, "{v}");
    assert_eq!(v["context"]["reason"], "approval_invalid");
}

/// SR-60: a sub-agent whose lease was revoked still holds a token whose signature verifies.
/// `GET /approvals/{id}` must not show it its run's approvals (the exact call, the labels, and
/// for a granted one the approval token) any more than a call would be allowed.
#[tokio::test]
async fn a_revoked_hop_cannot_read_its_runs_approvals_sr60() {
    let h = Harness::start_with(|c| c.token.require_actor_auth = false).await;
    let root = h.root().await;
    let coder = h.exchange(&root, "coder").await;
    let reviewer = h.exchange(&root, "reviewer").await;
    h.taint(&coder).await;
    let g = h.gated(&coder, "alice/site").await;
    h.grant_as_alice(&g.approval_id).await;
    let get = |bearer: String| {
        let url = h.server.url(&format!("/approvals/{}", g.approval_id));
        let client = h.client.clone();
        async move { client.get(url).bearer_auth(bearer).send().await.unwrap() }
    };
    let v: Value = get(reviewer.clone()).await.json().await.unwrap();
    assert!(v["approval_token"].is_string(), "{v}");
    let (_, reviewer_lease) = h.run_of(&reviewer);
    let resp = h
        .client
        .post(
            h.server
                .url(&format!("/admin/leases/{reviewer_lease}/revoke")),
        )
        .bearer_auth(ADMIN)
        .json(&json!({"reason": "compromised"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(get(reviewer).await.status(), StatusCode::NOT_FOUND);
    // The live hops of the run still see it.
    assert_eq!(get(coder).await.status(), StatusCode::OK);
    assert_eq!(get(root).await.status(), StatusCode::OK);
}

/// Run-state retention through the server's maintenance passes: alice's run (a charged
/// `read_web`, a consumed approval and a declined one) is revoked; while its lease is in the
/// registry nothing of it is pruned, however old; once the lease is pruned, its charge log,
/// counter and approvals stay for `[leases] run_state_retention_seconds` (30 days by default)
/// and go past it, counted in `run_state_pruned_total{kind}`. An operator refund of the pruned
/// charge answers 410 `charge_pruned` (its audit record shows the charge), unlike a decision
/// that charged nothing or an unknown id (404 `not_found`, each with its own detail); bob's
/// live run, as old, keeps everything and can still be refunded. The audit log keeps every
/// record.
#[tokio::test]
async fn run_state_of_pruned_runs_is_pruned_past_its_retention() {
    let h = Harness::start().await;
    assert_eq!(
        h.state.run_state_retention,
        Some(time::Duration::days(30)),
        "the default"
    );
    let mint = |subject: &'static str| {
        let h = &h;
        async move {
            let resp = h
                .client
                .post(h.server.url("/admin/root-token"))
                .bearer_auth(ADMIN)
                .json(&json!({
                    "subject": subject,
                    "issuer": h.idp.issuer,
                    "agent": "planner",
                    "capabilities": [
                        {"server": "github", "tool": "read_web", "limits": {"calls": 10}},
                        {"server": "github", "tool": "delete_repo"}
                    ],
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let v: Value = resp.json().await.unwrap();
            (
                v["access_token"].as_str().unwrap().to_string(),
                v["lease"].as_str().unwrap().to_string(),
            )
        }
    };
    let charged_read = |records: Vec<Value>, subject: &str| {
        records
            .iter()
            .rev()
            .find(|r| {
                r["kind"] == "decision"
                    && r["tool"] == "read_web"
                    && r["originating_subject"] == subject
            })
            .and_then(|r| r["id"].as_str())
            .unwrap()
            .to_string()
    };
    let refund = |decision: String| {
        let h = &h;
        async move {
            let resp = h
                .client
                .post(h.server.url("/admin/budgets/refund"))
                .bearer_auth(ADMIN)
                .json(&json!({"decision_id": decision}))
                .send()
                .await
                .unwrap();
            let status = resp.status();
            (status, resp.json::<Value>().await.unwrap())
        }
    };
    let pruned = |kind: &str| {
        metric(
            &h,
            &format!("attenuo_run_state_pruned_total{{kind=\"{kind}\"}}"),
        )
    };

    let (alice, alice_lease) = mint("alice").await;
    h.taint(&alice).await;
    let alice_read = charged_read(h.records().await, "alice");
    let consumed = h.gated(&alice, "alice/site").await;
    assert_eq!(
        h.admin_decide(&consumed.approval_id, "grant").await.0,
        StatusCode::OK
    );
    assert!(allowed(&h.delete(&alice, "alice/site").await));
    let declined = h.gated(&alice, "alice/other").await;
    assert_eq!(
        h.admin_decide(&declined.approval_id, "decline").await.0,
        StatusCode::OK
    );
    let (bob, _) = mint("bob").await;
    h.taint(&bob).await;
    let bob_read = charged_read(h.records().await, "bob");
    let bob_gated = h.gated(&bob, "bob/site").await;

    let resp = h
        .client
        .post(h.server.url(&format!("/admin/leases/{alice_lease}/revoke")))
        .bearer_auth(ADMIN)
        .json(&json!({"reason": "done"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Every charge and approval a month in the past, as far as the store can tell.
    let back = |days: i64| {
        (OffsetDateTime::now_utc() - time::Duration::days(days))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let (month, week) = (back(31), back(8));
    h.state
        .leases
        .with_connection(|c| {
            c.execute("UPDATE budget_charges SET at = ?1", [&month])?;
            c.execute(
                "UPDATE approvals SET created_at = ?1, expires_at = ?1, \
                 decided_at = CASE WHEN decided_at IS NULL THEN NULL ELSE ?1 END",
                [&month],
            )?;
            Ok(())
        })
        .unwrap();
    // alice's lease is revoked but still in the registry: nothing of her run goes.
    assert_eq!(attenuo_server::prune_run_state(&h.state).await, 0);

    // Her lease is pruned (revoked eight days ago, past the week of lease retention); the
    // same maintenance run then prunes her run state, which is past its 30 days.
    h.state
        .leases
        .with_connection(|c| {
            c.execute(
                "UPDATE leases SET revoked_at = ?1 WHERE revoked_at IS NOT NULL",
                [&week],
            )?;
            Ok(())
        })
        .unwrap();
    // The three passes of one maintenance run, in the ticker's order (the revoked run's
    // session binding, if the proxy recorded one, goes in the first).
    attenuo_server::prune_session_bindings(&h.state).await;
    assert_eq!(attenuo_server::prune_lease_registry(&h.state).await, 1);
    assert_eq!(attenuo_server::prune_run_state(&h.state).await, 4);
    assert_eq!(pruned("counters"), 1, "alice's read_web calls counter");
    assert_eq!(pruned("charges"), 1, "alice's read_web decision");
    assert_eq!(pruned("approvals"), 2);

    // The pruned charge: its decision record still shows it, so the refund is 410, not 404.
    let (status, v) = refund(alice_read.clone()).await;
    assert_eq!(status, StatusCode::GONE, "{v}");
    assert_eq!(v["error"], "charge_pruned");
    let detail = v["detail"].as_str().unwrap();
    assert!(
        detail.contains(&alice_read) && detail.contains("run_state_retention_seconds"),
        "the detail names the decision and the retention: {v}"
    );
    assert!(v.get("decision_id").is_none(), "no record was written: {v}");
    // alice's gated call was decided (approval required) but charged nothing: still 404.
    let gated_call = h
        .records()
        .await
        .iter()
        .find(|r| {
            r["kind"] == "decision"
                && r["tool"] == "delete_repo"
                && r["decision"] == "deny"
                && r["originating_subject"] == "alice"
        })
        .and_then(|r| r["id"].as_str())
        .unwrap()
        .to_string();
    let (status, v) = refund(gated_call.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
    assert_eq!(v["error"], "not_found");
    assert_eq!(
        v["detail"],
        format!(
            "decision `{gated_call}` charged nothing: its audit record shows no run limit or \
             run usage charged; nothing to refund"
        )
    );
    // No such decision at all, as a UUID or not.
    for unknown in ["00000000-0000-4000-8000-000000000000", "not-a-uuid"] {
        let (status, v) = refund(unknown.to_string()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
        assert_eq!(v["error"], "not_found");
        assert_eq!(
            v["detail"],
            format!("unknown decision `{unknown}`: no audit record has this id; nothing to refund")
        );
    }
    for id in [&consumed.approval_id, &declined.approval_id] {
        let resp = h
            .client
            .get(h.server.url(&format!("/admin/approvals/{id}")))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // bob's live run keeps its approval and its charge, which can still be refunded.
    let shown = h
        .admin_get(&format!("/admin/approvals/{}", bob_gated.approval_id))
        .await;
    assert_eq!(shown["state"], "pending");
    let (status, v) = refund(bob_read).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // The audit log still has alice's charged decision and is intact; nothing more to prune.
    assert!(h
        .records()
        .await
        .iter()
        .any(|r| r["id"].as_str() == Some(alice_read.as_str())));
    h.verify_ok().await;
    assert_eq!(attenuo_server::prune_run_state(&h.state).await, 0);
    assert_eq!(pruned("approvals"), 2);
}
