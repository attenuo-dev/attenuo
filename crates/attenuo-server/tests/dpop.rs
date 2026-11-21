//! SR-24: sender-constrained delegation tokens (DPoP, RFC 9449) through the whole server:
//! binding at issuance, proofs on every use (proxy, renewal, AuthZEN, exchange), the
//! attenuation rule for children of bound tokens, and the `[token] dpop` modes.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use attenuo_core::{Clock, ManualClock};
use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::{DpopMode, DpopNonceMode};
use attenuo_server::{AppState, Config};
use attenuo_token::DpopKey;
use reqwest::{RequestBuilder, StatusCode};
use serde_json::{json, Value};
use time::OffsetDateTime;

use common::{agent_configs, Running};

const ADMIN: &str = "dpop-test-admin";
const AGENTS: &[&str] = &["planner", "coder", "reviewer"];
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

fn secret(id: &str) -> String {
    format!("{id}-secret")
}

struct Server {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    server: Running,
    state: Arc<AppState>,
    client: reqwest::Client,
    /// The server's clock: the system clock, moved ahead for a server started by
    /// [`start_later`].
    clock: Arc<ManualClock>,
}

/// A server with `[token] dpop = mode`. Servers started on the same `dir` share the issuer key
/// and the SQLite file, so a token minted by one is accepted by the others. Only one runs on a
/// `dir` at a time (the single-writer fence on the SQLite file): [`Server::stop`] the previous
/// one first.
async fn start(dir: &Path, mode: DpopMode) -> Server {
    start_with(dir, mode, DpopNonceMode::Off).await
}

/// [`start`] with `[token] dpop_nonce = nonce`.
async fn start_with(dir: &Path, mode: DpopMode, nonce: DpopNonceMode) -> Server {
    start_later(dir, mode, nonce, Duration::ZERO).await
}

/// How far ahead [`start_later`] runs a restarted server: past the restart fence, which
/// refuses proofs for up to about 21 seconds after a quick restart (`attenuo_server::dpop`).
const RESTART_TAKES: Duration = Duration::from_secs(30);

/// [`start_with`] on a clock `after` ahead of the system clock: a server restarted on `dir`
/// that long after the previous one stopped, without the test waiting for it. Make proofs for
/// it with [`Server::proof`], at its time.
async fn start_later(dir: &Path, mode: DpopMode, nonce: DpopNonceMode, after: Duration) -> Server {
    start_at(dir, mode, nonce, after, None).await
}

/// [`start_later`] with `[server] public_url`, which then is what proofs name in `htu`
/// ([`Server::htu`]), whatever port the server listens on.
async fn start_at(
    dir: &Path,
    mode: DpopMode,
    nonce: DpopNonceMode,
    after: Duration,
    public_url: Option<&str>,
) -> Server {
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
    cfg.token.dpop = mode;
    cfg.token.dpop_nonce = nonce;
    cfg.agents = agent_configs(AGENTS, secret);
    cfg.server.public_url = public_url.map(str::to_owned);
    let clock = ManualClock::new();
    clock.advance(after);
    let (router, state) = attenuo_server::build_with_clock(&cfg, clock.clone()).unwrap();
    Server {
        upstream,
        _upstream_task: upstream_task,
        server: Running::start(cfg, state.clone(), router).await,
        state,
        client: reqwest::Client::new(),
        clock,
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// A proof for `POST <url>`, covering `token` when given.
fn proof(key: &DpopKey, url: &str, token: Option<&str>) -> String {
    key.proof("POST", url, token, now())
}

impl Server {
    /// The server's time.
    fn now(&self) -> OffsetDateTime {
        self.clock.now_utc()
    }

    /// A proof for `POST <url>` at the server's time, covering `token` when given.
    fn proof(&self, key: &DpopKey, url: &str, token: Option<&str>) -> String {
        key.proof("POST", url, token, self.now())
    }

    /// Stop this server as `serve` does after a signal; once this returns it has let go of
    /// the SQLite file, so the next server on the same `dir` can start ([`Running::stop`]).
    async fn stop(self) {
        let Self { server, state, .. } = self;
        server.stop(state).await;
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    /// The URL a proof for `path` names: `[server] public_url` plus the path when it is set.
    fn htu(&self, path: &str) -> String {
        match self.state.public_url {
            Some(_) => self.state.dpop.expected_url(None, path),
            None => self.url(path),
        }
    }

    /// `POST /admin/root-token` for alice's planner, bound to `key` when given.
    async fn root(&self, key: Option<&DpopKey>) -> reqwest::Response {
        let url = self.url("/admin/root-token");
        let htu = self.htu("/admin/root-token");
        let mut req = self.client.post(&url).bearer_auth(ADMIN).json(&json!({
            "subject": "alice",
            "issuer": "https://idp.example",
            "agent": "planner",
            "capabilities": ["github:read_file"],
        }));
        if let Some(k) = key {
            req = req.header("DPoP", self.proof(k, &htu, None));
        }
        req.send().await.unwrap()
    }

    async fn root_token(&self, key: Option<&DpopKey>) -> String {
        let resp = self.root(key).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        assert_eq!(
            v["token_type"],
            if key.is_some() { "DPoP" } else { "Bearer" }
        );
        v["access_token"].as_str().unwrap().to_string()
    }

    /// An exchange of `parent` for `actor`; `header` is the DPoP header, `sign_off` the
    /// body's `subject_token_dpop`.
    async fn exchange(
        &self,
        parent: &str,
        actor: &str,
        header: Option<String>,
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
        let mut req = self.client.post(self.url("/token")).json(&body);
        if let Some(h) = header {
            req = req.header("DPoP", h);
        }
        req.send().await.unwrap()
    }

    /// `tools/call read_file` through the proxy with `Authorization: DPoP <token>` and the
    /// given proof (or `Bearer` and no proof).
    fn call(&self, token: &str, dpop: Option<String>) -> RequestBuilder {
        let req = self.client.post(self.url("/mcp/github")).json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"repo": "acme/api"}},
        }));
        match dpop {
            Some(p) => req
                .header("authorization", format!("DPoP {token}"))
                .header("DPoP", p),
            None => req.bearer_auth(token),
        }
    }

    fn renew(&self, token: &str, dpop: Option<String>) -> RequestBuilder {
        let req = self
            .client
            .post(self.url("/token/renew"))
            .bearer_auth(token);
        match dpop {
            Some(p) => req.header("DPoP", p),
            None => req,
        }
    }

    fn authzen(&self, token: &str, dpop: Option<String>) -> RequestBuilder {
        let req = self
            .client
            .post(self.url("/access/v1/evaluation"))
            .bearer_auth(token)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "read_file"},
                "resource": {"type": "tool", "id": "github/read_file"},
                "context": {"input": {"repo": "acme/api"}},
            }));
        match dpop {
            Some(p) => req.header("DPoP", p),
            None => req,
        }
    }

    async fn audit(&self) -> Vec<Value> {
        let v: Value = self
            .client
            .get(self.url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["entries"].as_array().unwrap().clone()
    }
}

/// The token of a 200 exchange response, checking it is bound.
async fn bound_token(resp: reqwest::Response) -> String {
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["token_type"], "DPoP", "{v}");
    v["access_token"].as_str().unwrap().to_string()
}

/// Status, `error` and `WWW-Authenticate` of a refused request.
async fn refusal(resp: reqwest::Response) -> (StatusCode, String, String) {
    let status = resp.status();
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let v: Value = resp.json().await.unwrap();
    let code = v["error"]["data"]["reason"]
        .as_str()
        .or(v["error"].as_str())
        .unwrap_or_default()
        .to_string();
    (status, code, challenge)
}

fn allowed(v: &Value) -> bool {
    v.get("result").is_some() && v.get("error").is_none()
}

#[tokio::test]
async fn bound_chain_end_to_end_through_the_proxy_sr24() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), DpopMode::Optional).await;
    let (planner_key, coder_key) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
    let root = s.root_token(Some(&planner_key)).await;
    let token_url = s.url("/token");

    // The planner delegates to the coder, who has its own key: the coder's proof in the
    // header, the planner's sign-off (a proof covering the root token) in the body.
    let coder = bound_token(
        s.exchange(
            &root,
            "coder",
            Some(proof(&coder_key, &token_url, None)),
            Some(planner_key.sign_off(&token_url, &root, coder_key.thumbprint(), "coder", now())),
        )
        .await,
    )
    .await;
    // The coder delegates on with its own key: one proof, covering its token.
    let reviewer_same_key = bound_token(
        s.exchange(
            &coder,
            "reviewer",
            Some(proof(&coder_key, &token_url, Some(&coder))),
            None,
        )
        .await,
    )
    .await;

    // Calls through the proxy with a proof by the right key go through.
    let mcp = s.url("/mcp/github");
    let resp = s
        .call(&coder, Some(proof(&coder_key, &mcp, Some(&coder))))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(allowed(&resp.json().await.unwrap()));
    let resp = s
        .call(
            &reviewer_same_key,
            Some(proof(&coder_key, &mcp, Some(&reviewer_same_key))),
        )
        .send()
        .await
        .unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
    assert_eq!(s.upstream.recorded_calls().len(), 2);

    // Renewal and AuthZEN take the same proofs, for their own URLs.
    let resp = s
        .renew(
            &coder,
            Some(proof(&coder_key, &s.url("/token/renew"), Some(&coder))),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = s
        .authzen(
            &coder,
            Some(proof(
                &coder_key,
                &s.url("/access/v1/evaluation"),
                Some(&coder),
            )),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["decision"], true, "{v}");

    // Every record of this bound chain says so.
    let entries = s.audit().await;
    let flagged = |tool: &str| {
        entries
            .iter()
            .filter(|e| e["record"]["tool"] == tool)
            .map(|e| e["record"]["dpop_bound"] == true)
            .collect::<Vec<_>>()
    };
    assert_eq!(flagged("token.root"), vec![true]);
    assert_eq!(flagged("token.exchange"), vec![true, true]);
    // Three decisions plus the `tool_result` records of the two calls that went upstream.
    assert_eq!(flagged("read_file"), vec![true; 5]);
    assert_eq!(flagged("lease.renew"), vec![true]);

    // An unbound chain still works as before, and its records carry no flag.
    let plain = s.root_token(None).await;
    let resp = s.call(&plain, None).send().await.unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
    let entries = s.audit().await;
    let last = entries.last().unwrap();
    assert_eq!(last["record"]["tool"], "read_file");
    assert!(last["record"].get("dpop_bound").is_none(), "{last}");
}

#[tokio::test]
async fn stolen_bound_token_without_proof_is_refused_sr24() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), DpopMode::Optional).await;
    let (key, thief) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
    let token = s.root_token(Some(&key)).await;
    let mcp = s.url("/mcp/github");

    // No proof: 401 dpop_required, JSON-RPC -32001, a DPoP challenge.
    let resp = s.call(&token, None).send().await.unwrap();
    let (status, code, challenge) = refusal(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code, "dpop_required");
    assert!(challenge.starts_with("DPoP "), "{challenge}");
    assert!(challenge.contains("algs=\"EdDSA ES256\""), "{challenge}");

    // A proof by another key, for another URL, method or token, or replayed: invalid.
    let good = proof(&key, &mcp, Some(&token));
    let bad = [
        proof(&thief, &mcp, Some(&token)),
        proof(&key, &s.url("/mcp/other"), Some(&token)),
        key.proof("GET", &mcp, Some(&token), now()),
        proof(&key, &mcp, Some("another.token.value")),
        proof(&key, &mcp, None),
        key.proof(
            "POST",
            &mcp,
            Some(&token),
            now() - time::Duration::seconds(600),
        ),
    ];
    for p in bad {
        let (status, code, challenge) =
            refusal(s.call(&token, Some(p)).send().await.unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(code, "invalid_dpop_proof");
        assert!(challenge.starts_with("DPoP error=\"invalid_dpop_proof\""));
    }
    let resp = s.call(&token, Some(good.clone())).send().await.unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
    let (status, code, _) = refusal(s.call(&token, Some(good)).send().await.unwrap()).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_dpop_proof")
    );
    assert_eq!(s.upstream.recorded_calls().len(), 1);

    // Renewal, AuthZEN and exchange refuse the bare token too.
    for resp in [
        s.renew(&token, None).send().await.unwrap(),
        s.authzen(&token, None).send().await.unwrap(),
        s.exchange(&token, "coder", None, None).await,
    ] {
        let (status, code, challenge) = refusal(resp).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(code, "dpop_required");
        assert!(challenge.starts_with("DPoP "), "{challenge}");
    }
    // The thief's own key does not help with an exchange either.
    let token_url = s.url("/token");
    let resp = s
        .exchange(
            &token,
            "coder",
            Some(proof(&thief, &token_url, None)),
            Some(proof(&thief, &token_url, Some(&token))),
        )
        .await;
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
}

/// A renewal of a bound token on a revoked lease is audited only once its DPoP proof checked:
/// without a proof, or with another key's, it is a 401 and no record (SR-18).
#[tokio::test]
async fn refused_renewal_of_a_bound_token_is_audited_only_with_its_proof() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), DpopMode::Optional).await;
    let (key, thief) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
    let v: Value = s.root(Some(&key)).await.json().await.unwrap();
    let token = v["access_token"].as_str().unwrap().to_string();
    let lease = v["lease"].as_str().unwrap().to_string();
    let resp = s
        .client
        .post(s.url(&format!("/admin/leases/{lease}/revoke")))
        .bearer_auth(ADMIN)
        .json(&json!({"reason": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let renew_url = s.url("/token/renew");
    let before = s.audit().await.len();
    for p in [None, Some(proof(&thief, &renew_url, Some(&token)))] {
        let resp = s.renew(&token, p).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get("x-attenuo-decision-id").is_none());
    }
    assert_eq!(
        s.audit().await.len(),
        before,
        "no record without a good proof"
    );

    let resp = s
        .renew(&token, Some(proof(&key, &renew_url, Some(&token))))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let id = resp.headers()["x-attenuo-decision-id"]
        .to_str()
        .unwrap()
        .to_string();
    let entries = s.audit().await;
    assert_eq!(entries.len(), before + 1);
    let r = &entries.last().unwrap()["record"];
    assert_eq!(r["id"], id);
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["reason"], "lease_revoked");
    assert_eq!(r["tool"], "lease.renew");
    assert_eq!(r["dpop_bound"], true);
}

#[tokio::test]
async fn child_of_bound_parent_must_be_bound_sr24() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), DpopMode::Optional).await;
    let (parent_key, child_key) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
    let root = s.root_token(Some(&parent_key)).await;
    let url = s.url("/token");

    // A sign-off alone does not mint an unbound child.
    let resp = s
        .exchange(
            &root,
            "coder",
            None,
            Some(proof(&parent_key, &url, Some(&root))),
        )
        .await;
    assert_eq!(refusal(resp).await.1, "dpop_required");
    // The parent's key without `ath`: refused.
    let resp = s
        .exchange(&root, "coder", Some(proof(&parent_key, &url, None)), None)
        .await;
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    // Another key without the parent's sign-off: refused.
    let resp = s
        .exchange(&root, "coder", Some(proof(&child_key, &url, None)), None)
        .await;
    assert_eq!(refusal(resp).await.1, "dpop_required");
    // A sign-off that does not cover the subject token: refused.
    let resp = s
        .exchange(
            &root,
            "coder",
            Some(proof(&child_key, &url, None)),
            Some(proof(&parent_key, &url, None)),
        )
        .await;
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    // A plain proof by the parent's key is not a sign-off: it names no key and no agent
    // (SR-40).
    let resp = s
        .exchange(
            &root,
            "coder",
            Some(proof(&child_key, &url, None)),
            Some(proof(&parent_key, &url, Some(&root))),
        )
        .await;
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    // Done right, the child is bound to the child's key, and only that key can use it.
    let child = bound_token(
        s.exchange(
            &root,
            "coder",
            Some(proof(&child_key, &url, None)),
            Some(parent_key.sign_off(&url, &root, child_key.thumbprint(), "coder", now())),
        )
        .await,
    )
    .await;
    let mcp = s.url("/mcp/github");
    let resp = s
        .call(&child, Some(proof(&parent_key, &mcp, Some(&child))))
        .send()
        .await
        .unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    let resp = s
        .call(&child, Some(proof(&child_key, &mcp, Some(&child))))
        .send()
        .await
        .unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
}

#[tokio::test]
async fn required_mode_refuses_unbound_exchanges_sr24() {
    // Three servers over one issuer key and one lease store, differing only in `[token] dpop`,
    // one after the other (one server per SQLite file).
    let dir = tempfile::tempdir().unwrap();
    let optional = start(dir.path(), DpopMode::Optional).await;
    let key = DpopKey::generate().unwrap();
    let unbound = optional.root_token(None).await;
    let bound = optional.root_token(Some(&key)).await;
    optional.stop().await;
    let required = start_later(
        dir.path(),
        DpopMode::Required,
        DpopNonceMode::Off,
        RESTART_TAKES,
    )
    .await;

    // `required`: no unbound issuance, no unbound token accepted.
    assert_eq!(refusal(required.root(None).await).await.1, "dpop_required");
    let resp = required.exchange(&unbound, "coder", None, None).await;
    let (status, code, _) = refusal(resp).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "dpop_required")
    );
    let resp = required.call(&unbound, None).send().await.unwrap();
    assert_eq!(refusal(resp).await.1, "dpop_required");
    // A proof binds the child of an unbound parent, and the root mint.
    let url = required.url("/token");
    bound_token(
        required
            .exchange(
                &unbound,
                "coder",
                Some(required.proof(&key, &url, None)),
                None,
            )
            .await,
    )
    .await;
    required.root_token(Some(&key)).await;
    required.stop().await;

    // `off`: proofs are ignored at issuance, but a bound token still needs one.
    let off = start_later(
        dir.path(),
        DpopMode::Off,
        DpopNonceMode::Off,
        2 * RESTART_TAKES,
    )
    .await;
    let resp = off.root(Some(&key)).await;
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["token_type"], "Bearer");
    let resp = off.call(&bound, None).send().await.unwrap();
    assert_eq!(refusal(resp).await.1, "dpop_required");
    let mcp = off.url("/mcp/github");
    let resp = off
        .call(&bound, Some(off.proof(&key, &mcp, Some(&bound))))
        .send()
        .await
        .unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
}

#[tokio::test]
async fn several_dpop_headers_are_refused_sr24() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), DpopMode::Optional).await;
    let key = DpopKey::generate().unwrap();
    let token = s.root_token(Some(&key)).await;
    let mcp = s.url("/mcp/github");
    let resp = s
        .call(&token, Some(proof(&key, &mcp, Some(&token))))
        .header("DPoP", proof(&key, &mcp, Some(&token)))
        .send()
        .await
        .unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    let url = s.url("/admin/root-token");
    let resp = s
        .client
        .post(&url)
        .bearer_auth(ADMIN)
        .header("DPoP", proof(&key, &url, None))
        .header("DPoP", proof(&key, &url, None))
        .json(
            &json!({"subject": "alice", "issuer": "https://idp.example", "agent": "planner",
            "capabilities": ["github:read_file"]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
}

/// The `DPoP-Nonce` header of a response.
fn nonce_of(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("dpop-nonce")
        .map(|v| v.to_str().unwrap().to_string())
}

/// RFC 9449 §8: with `[token] dpop_nonce = "required"`, a proof without the server's nonce is
/// refused with `use_dpop_nonce` and the nonce to use; the retry carries it and goes through,
/// at issuance and through the proxy.
#[tokio::test]
async fn server_nonce_required_through_the_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let s = start_with(dir.path(), DpopMode::Optional, DpopNonceMode::Required).await;
    let key = DpopKey::generate().unwrap();

    // Issuance: the first proof has no nonce, so 401 `use_dpop_nonce` with a nonce.
    let root_url = s.url("/admin/root-token");
    let resp = s.root(Some(&key)).await;
    let nonce = nonce_of(&resp).expect("DPoP-Nonce on the use_dpop_nonce response");
    let (status, code, challenge) = refusal(resp).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "use_dpop_nonce")
    );
    assert!(
        challenge.starts_with("DPoP error=\"use_dpop_nonce\""),
        "{challenge}"
    );
    let resp = s
        .client
        .post(&root_url)
        .bearer_auth(ADMIN)
        .header(
            "DPoP",
            key.proof_with_nonce("POST", &root_url, None, Some(&nonce), now()),
        )
        .json(&json!({"subject": "alice", "issuer": "https://idp.example",
            "agent": "planner", "capabilities": ["github:read_file"]}))
        .send()
        .await
        .unwrap();
    assert!(
        nonce_of(&resp).is_some(),
        "every DPoP response carries a nonce"
    );
    let token = bound_token(resp).await;

    // Through the proxy: no nonce, then a wrong one, are refused with a fresh nonce.
    let mcp = s.url("/mcp/github");
    for bad in [None, Some("bm90LWEtbm9uY2U")] {
        let p = key.proof_with_nonce("POST", &mcp, Some(&token), bad, now());
        let resp = s.call(&token, Some(p)).send().await.unwrap();
        assert!(nonce_of(&resp).is_some());
        let (status, code, challenge) = refusal(resp).await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::UNAUTHORIZED, "use_dpop_nonce")
        );
        assert!(challenge.contains("use_dpop_nonce"), "{challenge}");
    }
    let p = key.proof_with_nonce("POST", &mcp, Some(&token), Some(&nonce), now());
    let resp = s.call(&token, Some(p)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(nonce_of(&resp).is_some());
    assert!(allowed(&resp.json().await.unwrap()));
    assert_eq!(s.upstream.recorded_calls().len(), 1);

    // A bad proof is still `invalid_dpop_proof`, and a challenge without a proof
    // (`dpop_required`) carries the nonce too, so the first proof can include it.
    let other = DpopKey::generate().unwrap();
    let p = other.proof_with_nonce("POST", &mcp, Some(&token), Some(&nonce), now());
    let resp = s.call(&token, Some(p)).send().await.unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    let resp = s.call(&token, None).send().await.unwrap();
    assert!(nonce_of(&resp).is_some());
    assert_eq!(refusal(resp).await.1, "dpop_required");

    // A server with the same issuer key accepts the nonce (no shared storage needed); one
    // with nonces off neither sends nor checks them. They run on the same file, so in turn.
    // A proof made before the restart is refused by the restart fence, nonce or not.
    s.stop().await;
    let twin = start_later(
        dir.path(),
        DpopMode::Optional,
        DpopNonceMode::Required,
        RESTART_TAKES,
    )
    .await;
    let twin_mcp = twin.url("/mcp/github");
    let before = key.proof_with_nonce("POST", &twin_mcp, Some(&token), Some(&nonce), now());
    let resp = twin.call(&token, Some(before)).send().await.unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    let p = key.proof_with_nonce("POST", &twin_mcp, Some(&token), Some(&nonce), twin.now());
    let resp = twin.call(&token, Some(p)).send().await.unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
    twin.stop().await;
    let off = start_later(
        dir.path(),
        DpopMode::Optional,
        DpopNonceMode::Off,
        2 * RESTART_TAKES,
    )
    .await;
    let off_mcp = off.url("/mcp/github");
    let resp = off
        .call(&token, Some(off.proof(&key, &off_mcp, Some(&token))))
        .send()
        .await
        .unwrap();
    assert!(nonce_of(&resp).is_none());
    assert!(allowed(&resp.json().await.unwrap()));
}

/// AuthZEN action search authenticates a bound token exactly as evaluation does: the bare
/// token is `dpop_required`, a proof made for the evaluation URL is `invalid_dpop_proof`, and a
/// proof for the search URL itself is accepted.
#[tokio::test]
async fn action_search_needs_a_proof_for_its_own_url() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path(), DpopMode::Optional).await;
    let key = DpopKey::generate().unwrap();
    let token = s.root_token(Some(&key)).await;
    let search_url = s.url("/access/v1/search/action");
    let search = |p: Option<String>| {
        let req = s.client.post(&search_url).bearer_auth(&token).json(&json!({
            "subject": {"type": "agent", "id": ""},
            "resource": {"type": "mcp_server", "id": "github"},
            "context": {"input": {"repo": "acme/api"}},
        }));
        match p {
            Some(p) => req.header("DPoP", p),
            None => req,
        }
    };
    let (status, code, challenge) = refusal(search(None).send().await.unwrap()).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "dpop_required")
    );
    assert!(challenge.starts_with("DPoP "), "{challenge}");
    let elsewhere = proof(&key, &s.url("/access/v1/evaluation"), Some(&token));
    let (status, code, _) = refusal(search(Some(elsewhere)).send().await.unwrap()).await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_dpop_proof")
    );
    let resp = search(Some(proof(&key, &search_url, Some(&token))))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(
        v["results"],
        json!([{"name": "read_file", "properties": {"server": "github"}}]),
        "{v}"
    );
}

/// The restart fence (`attenuo_server::dpop`): a proof one server accepted is refused by the
/// next server on the same database file, even right after a quick restart, though the
/// replay cache is in memory. A new proof is accepted once the clock is past the old server's
/// liveness marker.
#[tokio::test]
async fn a_proof_accepted_before_a_restart_is_refused_after_it() {
    let dir = tempfile::tempdir().unwrap();
    // One public URL, so a proof names the same `htu` whatever port each server listens on.
    let public = Some("http://127.0.0.1");
    let start = |after| {
        start_at(
            dir.path(),
            DpopMode::Optional,
            DpopNonceMode::Off,
            after,
            public,
        )
    };
    let first = start(Duration::ZERO).await;
    let key = DpopKey::generate().unwrap();
    let token = first.root_token(Some(&key)).await;
    let mcp = first.htu("/mcp/github");
    let captured = first.proof(&key, &mcp, Some(&token));
    let resp = first
        .call(&token, Some(captured.clone()))
        .send()
        .await
        .unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
    // Replayed to the same process: the replay cache refuses it.
    let resp = first
        .call(&token, Some(captured.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    first.stop().await;

    // Restarted at once, on the same file and the same clock.
    let next = start(Duration::ZERO).await;
    let marker = next.state.leases.dpop_max_iat().unwrap().unwrap();
    // Not ready while fenced, so a rolling deploy keeps DPoP traffic away; alive all along.
    let ready = next.client.get(next.url("/readyz")).send().await.unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let v: Value = ready.json().await.unwrap();
    assert_eq!(v["checks"]["dpop_restart_fence"], "fenced", "{v}");
    let health = next.client.get(next.url("/healthz")).send().await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    let resp = next
        .call(&token, Some(captured.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = resp.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        challenge.starts_with("DPoP error=\"invalid_dpop_proof\""),
        "{challenge}"
    );
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["data"]["reason"], "invalid_dpop_proof", "{v}");
    assert_eq!(next.upstream.recorded_calls().len(), 0);
    // A new proof made now is refused too, until the clock passes the old marker: the cost of
    // a quick restart. The same holds at `POST /token/renew`, whose `detail` says why.
    let fresh = next.proof(&key, &mcp, Some(&token));
    let resp = next.call(&token, Some(fresh)).send().await.unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    let resp = next
        .renew(
            &token,
            Some(next.proof(&key, &next.htu("/token/renew"), Some(&token))),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"], "invalid_dpop_proof", "{v}");
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("before this server started"),
        "{v}"
    );

    // Past the marker (the test moves the server's clock instead of waiting): a new proof
    // is accepted, and the captured one is still refused, though its `iat` is in the window.
    let wait = marker + 1 - next.now().unix_timestamp();
    assert!((1..=25).contains(&wait), "fenced for {wait} s");
    next.clock.advance(Duration::from_secs(wait.unsigned_abs()));
    // What the heartbeat would do within 5 s: write the marker at the moved clock.
    next.state.beat_dpop_liveness().unwrap();
    let ready = next.client.get(next.url("/readyz")).send().await.unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
    let v: Value = ready.json().await.unwrap();
    assert!(v["checks"].get("dpop_restart_fence").is_none(), "{v}");
    let resp = next.call(&token, Some(captured)).send().await.unwrap();
    assert_eq!(refusal(resp).await.1, "invalid_dpop_proof");
    let fresh = next.proof(&key, &mcp, Some(&token));
    let resp = next.call(&token, Some(fresh)).send().await.unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
    assert_eq!(next.upstream.recorded_calls().len(), 1);
}

/// The restart fence costs nothing on a new database file, and nothing after a restart that
/// comes once the old server's marker is in the past.
#[tokio::test]
async fn a_new_file_or_a_slow_restart_is_not_fenced() {
    let dir = tempfile::tempdir().unwrap();
    let first = start(dir.path(), DpopMode::Optional).await;
    // A new file has no marker: even a proof made before the server started is accepted.
    let key = DpopKey::generate().unwrap();
    let url = first.url("/admin/root-token");
    let early = key.proof("POST", &url, None, first.now() - Duration::from_secs(60));
    let resp = first
        .client
        .post(&url)
        .bearer_auth(ADMIN)
        .header("DPoP", early)
        .json(&json!({"subject": "alice", "issuer": "https://idp.example",
            "agent": "planner", "capabilities": ["github:read_file"]}))
        .send()
        .await
        .unwrap();
    let token = bound_token(resp).await;
    first.stop().await;

    // Restarted after the marker has passed: a proof made at once is accepted.
    let next = start_later(
        dir.path(),
        DpopMode::Optional,
        DpopNonceMode::Off,
        RESTART_TAKES,
    )
    .await;
    let marker = next.state.leases.dpop_max_iat().unwrap().unwrap();
    assert!(
        marker > next.now().unix_timestamp(),
        "a new marker is written at start"
    );
    let mcp = next.url("/mcp/github");
    let resp = next
        .call(&token, Some(next.proof(&key, &mcp, Some(&token))))
        .send()
        .await
        .unwrap();
    assert!(allowed(&resp.json().await.unwrap()));
}

/// A liveness marker behind the clock (here: the clock moved and the heartbeat has not
/// written yet) refuses proofs with 503 `dpop_liveness_stale` and `Retry-After: 1`, on a REST
/// route and through the proxy (`-32006`), and the request itself writes nothing.
#[tokio::test]
async fn a_stale_liveness_marker_is_a_503_with_retry_after() {
    for proxy in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let s = start(dir.path(), DpopMode::Optional).await;
        let key = DpopKey::generate().unwrap();
        let token = s.root_token(Some(&key)).await;
        let before = s.state.leases.dpop_max_iat().unwrap();
        // Past the marker; the heartbeat (every 5 s) has not run yet.
        s.clock.advance(Duration::from_secs(60));
        let resp = if proxy {
            let mcp = s.url("/mcp/github");
            s.call(&token, Some(s.proof(&key, &mcp, Some(&token))))
                .send()
                .await
                .unwrap()
        } else {
            let url = s.url("/token/renew");
            s.renew(&token, Some(s.proof(&key, &url, Some(&token))))
                .send()
                .await
                .unwrap()
        };
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "proxy {proxy}"
        );
        assert_eq!(resp.headers()["retry-after"], "1", "proxy {proxy}");
        let v: Value = resp.json().await.unwrap();
        if proxy {
            assert_eq!(v["error"]["code"], -32006, "{v}");
            assert_eq!(v["error"]["data"]["reason"], "dpop_liveness_stale", "{v}");
        } else {
            assert_eq!(v["error"], "temporarily_unavailable", "{v}");
            assert_eq!(v["code"], "dpop_liveness_stale", "{v}");
        }
        // The marker is written by the heartbeat (woken now), never by the request; a
        // heartbeat write that has already happened can only have moved it forward.
        assert!(s.state.leases.dpop_max_iat().unwrap() >= before);
        assert_eq!(s.upstream.recorded_calls().len(), 0);
        s.stop().await;
    }
}
