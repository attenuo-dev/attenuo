//! `private_key_jwt` client authentication (RFC 7523 §2.2, ADR-0017): agents and PEPs whose
//! `[[agents]]` / `[[peps]]` entries hold public keys (`jwks`) authenticate with a signed
//! client assertion, at hop 0, at an exchange and at the AuthZEN endpoints. Covers the happy
//! paths, key rotation, the refusals as HTTP answers, single use across a restart on the same
//! database, `[token] actor_auth` and the startup refusals.
//!
//! The per-claim refusal codes are unit-tested in `src/clientauth.rs`.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{
    ActorAuth, ActorTrustConfig, AgentConfig, CapSpec, IdpConfig, PepConfig, RootGrant,
    SubjectToAgent,
};
use attenuo_server::{AppState, Config};
use attenuo_token::client_assertion::{self, CLIENT_ASSERTION_TYPE};
use attenuo_token::DpopKey;
use axum::routing::get;
use axum::{Json, Router};
use reqwest::StatusCode;
use serde_json::{json, Value};
use time::OffsetDateTime;

use common::sha256_hex;

const ADMIN: &str = "test-admin-token";
/// `[issuer] issuer`: the only `aud` a client assertion may carry.
const ISSUER: &str = "https://attenuo.test";
const IDP: &str = "https://idp.test";
const CLIENT_AUD: &str = "attenuo-client";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// An agent's key pair and the `kid` its public half has in the server's config.
struct Key {
    key: DpopKey,
    kid: &'static str,
}

impl Key {
    fn new(kid: &'static str) -> Self {
        Self {
            key: DpopKey::generate().unwrap(),
            kid,
        }
    }

    fn public(&self) -> Value {
        let mut jwk = self.key.public_jwk().clone();
        jwk["kid"] = self.kid.into();
        jwk
    }

    /// A fresh assertion for `client`, as the CLI makes it.
    fn assertion(&self, client: &str) -> String {
        client_assertion::sign(
            &self.key,
            Some(self.kid),
            client,
            ISSUER,
            client_assertion::DEFAULT_LIFETIME,
            now(),
        )
    }

    /// An assertion with these claims.
    fn sign(&self, claims: &Value) -> String {
        self.key.sign_jws(
            &json!({"alg": "EdDSA", "kid": self.kid, "typ": "client-authentication+jwt"}),
            claims,
        )
    }
}

fn jwks(keys: &[&Key]) -> String {
    json!({ "keys": keys.iter().map(|k| k.public()).collect::<Vec<_>>() }).to_string()
}

fn assertion_fields(assertion: &str) -> Value {
    json!({"client_assertion_type": CLIENT_ASSERTION_TYPE, "client_assertion": assertion})
}

/// A fake IdP: an EdDSA key whose JWKS is served at `/jwks`.
struct Idp {
    key: DpopKey,
    server: Spawned,
}

impl Idp {
    async fn start() -> Self {
        let key = DpopKey::generate().unwrap();
        let mut jwk = key.public_jwk().clone();
        jwk["kid"] = "idp-1".into();
        jwk["alg"] = "EdDSA".into();
        let doc = json!({ "keys": [jwk] });
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let d = doc.clone();
                async move { Json(d) }
            }),
        );
        Self {
            key,
            server: spawn_router(app).await.unwrap(),
        }
    }

    fn id_token(&self, sub: &str) -> String {
        let t = now().unix_timestamp();
        self.key.sign_jws(
            &json!({"alg": "EdDSA", "kid": "idp-1", "typ": "JWT"}),
            &json!({"iss": IDP, "aud": CLIENT_AUD, "sub": sub, "iat": t, "exp": t + 300,
                    "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }
}

/// The agents' and the PEP's keys.
struct Keys {
    planner: Key,
    coder_old: Key,
    coder_new: Key,
    gateway: Key,
}

impl Keys {
    fn new() -> Self {
        Self {
            planner: Key::new("planner-1"),
            coder_old: Key::new("2026-10"),
            coder_new: Key::new("2026-11"),
            gateway: Key::new("gw-1"),
        }
    }
}

/// `planner` (keys only), `coder` (two keys: a rotation in progress), `reviewer` (secret
/// only), the PEP `gateway` (keys only), an IdP for hop 0, the dev root mint.
fn config(keys: &Keys, idp: &Idp) -> Config {
    let mut cfg = Config::default();
    cfg.issuer.issuer = ISSUER.into();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = vec![
        AgentConfig::with_jwks("planner", jwks(&[&keys.planner])),
        AgentConfig::with_jwks("coder", jwks(&[&keys.coder_old, &keys.coder_new])),
        AgentConfig::with_secret_sha256("reviewer", sha256_hex("reviewer-secret")),
    ];
    cfg.authzen.allow_unsigned_chain = true;
    cfg.peps = vec![PepConfig::with_jwks("gateway", jwks(&[&keys.gateway]))];
    cfg.idps = vec![IdpConfig {
        issuer: IDP.into(),
        audience: String::new(),
        jwks_url: Some(idp.server.url("/jwks")),
        allowed_algs: vec!["EdDSA".into()],
        attribute_claims: vec![],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 60,
        client_ids: BTreeMap::from([("planner".to_string(), CLIENT_AUD.to_string())]),
        tenant: None,
        id_jag_ceiling: None,
        credentials: attenuo_server::config::DEFAULT_IDP_CREDENTIALS.to_vec(),
        ca_pem_path: None,
    }];
    cfg.root_grants = vec![RootGrant {
        subject: None,
        issuer: IDP.into(),
        agent: "planner".into(),
        capabilities: vec![CapSpec::Short("github:*".into())],
        attributes: BTreeMap::new(),
        may_act: None,
    }];
    cfg
}

struct Harness {
    keys: Keys,
    idp: Idp,
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
}

impl Harness {
    async fn start(tweak: impl FnOnce(&mut Config)) -> Self {
        let keys = Keys::new();
        let idp = Idp::start().await;
        let mut cfg = config(&keys, &idp);
        tweak(&mut cfg);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            keys,
            idp,
            server: spawn_router(router).await.unwrap(),
            state,
            client: reqwest::Client::new(),
        }
    }

    async fn post(&self, path: &str, body: &Value) -> reqwest::Response {
        self.client
            .post(self.server.url(path))
            .json(body)
            .send()
            .await
            .unwrap()
    }

    /// A root token for `planner` from the dev mint: (token, lease).
    async fn root(&self) -> (String, String) {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(
                &json!({"subject": "alice", "issuer": IDP, "agent": "planner",
                          "capabilities": ["github:*"]}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        (
            v["access_token"].as_str().unwrap().into(),
            v["lease"].as_str().unwrap().into(),
        )
    }

    async fn audit(&self) -> Vec<Value> {
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
        v["entries"].as_array().unwrap().clone()
    }
}

fn exchange_body(parent: &str, actor: &str, extra: Value) -> Value {
    let mut body = json!({
        "grant_type": EXCHANGE, "subject_token": parent, "subject_token_type": JWT,
        "actor": actor,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]}],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn intake_body(id_token: &str, extra: Value) -> Value {
    let mut body = json!({
        "grant_type": EXCHANGE, "subject_token": id_token, "subject_token_type": ID_TOKEN,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]}],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

async fn answer(resp: reqwest::Response) -> (StatusCode, Option<String>, Value) {
    let status = resp.status();
    let challenge = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_owned());
    (status, challenge, resp.json().await.unwrap_or(Value::Null))
}

fn code(v: &Value) -> (&str, &str) {
    (
        v["error"].as_str().unwrap_or_default(),
        v["error_description"].as_str().unwrap_or_default(),
    )
}

/// The digest the exchange record's arguments have when the actor authenticated by `how`.
fn exchange_args_digest(actor: &str, parent_lease: &str, how: &str) -> String {
    let requested: attenuo_core::CapabilitySet =
        serde_json::from_value(json!([{"server": "github", "tool": "read_file"}])).unwrap();
    attenuo_core::ToolCall::new(
        "attenuo",
        "token.exchange",
        json!({"actor": actor, "requested": requested, "parent_lease": parent_lease,
               "actor_auth": how, "dpop_bound": false}),
    )
    .arguments_digest()
}

#[tokio::test]
async fn hop_0_with_a_client_assertion() {
    let h = Harness::start(|_| {}).await;
    let planner = &h.keys.planner;
    let a = planner.assertion("planner");
    let resp = h
        .post(
            "/token",
            &intake_body(&h.idp.id_token("alice"), assertion_fields(&a)),
        )
        .await;
    let (status, _, v) = answer(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let root = h
        .state
        .keys()
        .verifier
        .verify(v["access_token"].as_str().unwrap(), now())
        .unwrap();
    assert_eq!(root.chain.hops[0].agent.0, "planner");

    // The same assertion again, with a fresh ID token: used once.
    let resp = h
        .post(
            "/token",
            &intake_body(&h.idp.id_token("alice"), assertion_fields(&a)),
        )
        .await;
    let (status, challenge, v) = answer(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_assertion_replayed"));
    assert_eq!(challenge.as_deref(), Some("Basic realm=\"attenuo\""));

    // `client_id`, when sent, must be the assertion's `sub`; the answer never echoes it.
    let a = planner.assertion("planner");
    let mut extra = assertion_fields(&a);
    extra["client_id"] = "coder".into();
    let (status, _, v) = answer(
        h.post("/token", &intake_body(&h.idp.id_token("alice"), extra))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(
        code(&v),
        ("invalid_client", "client_assertion_subject_mismatch")
    );
    assert!(!v.to_string().contains(&a), "{v}");

    // The token endpoint URL is not an accepted audience.
    let t = now().unix_timestamp();
    let to_endpoint = planner.sign(&json!({"iss": "planner", "sub": "planner",
        "aud": format!("{ISSUER}/token"), "jti": "x1", "exp": t + 60}));
    let (status, _, v) = answer(
        h.post(
            "/token",
            &intake_body(&h.idp.id_token("alice"), assertion_fields(&to_endpoint)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(
        code(&v),
        ("invalid_client", "client_assertion_audience_mismatch")
    );

    // A key-only agent has no secret.
    let (status, _, v) = answer(
        h.post(
            "/token",
            &intake_body(
                &h.idp.id_token("alice"),
                json!({"client_id": "planner", "client_secret": "anything"}),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_authentication_failed"));

    // One method per request.
    let mut both = assertion_fields(&planner.assertion("planner"));
    both["client_secret"] = "anything".into();
    let (status, _, v) = answer(
        h.post("/token", &intake_body(&h.idp.id_token("alice"), both))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v), ("invalid_request", "multiple_client_auth"));

    // Another assertion type.
    let mut saml = assertion_fields(&planner.assertion("planner"));
    saml["client_assertion_type"] =
        "urn:ietf:params:oauth:client-assertion-type:saml2-bearer".into();
    let (status, _, v) = answer(
        h.post("/token", &intake_body(&h.idp.id_token("alice"), saml))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(
        code(&v),
        ("invalid_request", "client_assertion_type_unsupported")
    );
}

#[tokio::test]
async fn exchange_with_a_client_assertion_and_a_rotated_key() {
    let h = Harness::start(|_| {}).await;
    for key in [&h.keys.coder_old, &h.keys.coder_new] {
        let (root, lease) = h.root().await;
        let resp = h
            .post(
                "/token",
                &exchange_body(&root, "coder", assertion_fields(&key.assertion("coder"))),
            )
            .await;
        let (status, _, v) = answer(resp).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        let child = h
            .state
            .keys()
            .verifier
            .verify(v["access_token"].as_str().unwrap(), now())
            .unwrap();
        assert_eq!(child.claims.act.sub, "coder");
        // The record's arguments say how the actor authenticated.
        let digest = h
            .audit()
            .await
            .into_iter()
            .rfind(|e| e["record"]["tool"] == "token.exchange")
            .unwrap()["record"]["arguments_digest"]
            .clone();
        assert_eq!(
            digest,
            exchange_args_digest("coder", &lease, "private_key_jwt"),
            "the exchange record's arguments carry actor_auth = private_key_jwt"
        );
        assert_ne!(
            digest,
            exchange_args_digest("coder", &lease, "client_secret")
        );
    }

    // Form encoding, as RFC 7523 shows it.
    let (root, _) = h.root().await;
    let a = h.keys.coder_new.assertion("coder");
    let resp = h
        .client
        .post(h.server.url("/token"))
        .form(&[
            ("grant_type", EXCHANGE),
            ("subject_token", &root),
            ("subject_token_type", JWT),
            ("actor", "coder"),
            ("scope", "github:read_file"),
            ("client_id", "coder"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", &a),
        ])
        .send()
        .await
        .unwrap();
    let (status, _, v) = answer(resp).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // An assertion names the client; the actor must be that client.
    let (root, _) = h.root().await;
    let resp = h
        .post(
            "/token",
            &exchange_body(
                &root,
                "reviewer",
                assertion_fields(&h.keys.coder_new.assertion("coder")),
            ),
        )
        .await;
    let (status, _, v) = answer(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v), ("invalid_request", "actor_mismatch"));

    // Secret-based agents keep working next to key-based ones.
    let (root, _) = h.root().await;
    let resp = h
        .post(
            "/token",
            &exchange_body(
                &root,
                "reviewer",
                json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
            ),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // ... and a key-only agent cannot be impersonated by an assertion signed with another
    // agent's key under its name.
    let (root, _) = h.root().await;
    let forged = h
        .keys
        .planner
        .sign(&json!({"iss": "coder", "sub": "coder", "aud": ISSUER,
        "jti": "forged", "exp": now().unix_timestamp() + 60}));
    let (status, _, v) = answer(
        h.post(
            "/token",
            &exchange_body(&root, "coder", assertion_fields(&forged)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_authentication_failed"));
}

#[tokio::test]
async fn a_pep_authenticates_to_authzen_with_a_client_assertion() {
    let h = Harness::start(|_| {}).await;
    let (root, _) = h.root().await;
    let chain = h.state.keys().verifier.verify(&root, now()).unwrap().chain;
    let read = attenuo_core::ToolCall::new("github", "read_file", json!({"repo": "alice/site"}));
    let request = serde_json::to_value(attenuo_policy::authzen::to_request(&chain, &read)).unwrap();
    let with = |assertion: &str| {
        let mut body = request.clone();
        body["client_assertion_type"] = CLIENT_ASSERTION_TYPE.into();
        body["client_assertion"] = assertion.into();
        body
    };

    let a = h.keys.gateway.assertion("gateway");
    let (status, _, v) = answer(h.post("/access/v1/evaluation", &with(&a)).await).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // Decided and audited (the tool is not in this server's catalog, hence a deny).
    assert!(v["context"]["decision_id"].is_string(), "{v}");
    // Used once.
    let (status, challenge, v) = answer(h.post("/access/v1/evaluation", &with(&a)).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_assertion_replayed"));
    assert!(challenge.is_some());
    // `pep_id` must be the assertion's `sub`.
    let mut named = with(&h.keys.gateway.assertion("gateway"));
    named["pep_id"] = "other".into();
    let (status, _, v) = answer(h.post("/access/v1/evaluation", &named).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(
        code(&v),
        ("invalid_client", "client_assertion_subject_mismatch")
    );
    // An agent's key is not a PEP's.
    let (status, _, v) = answer(
        h.post(
            "/access/v1/evaluation",
            &with(&h.keys.planner.assertion("planner")),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_authentication_failed"));

    // A batch: the one assertion authenticates the whole request, whose entries are decided.
    let mut batch = with(&h.keys.gateway.assertion("gateway"));
    batch["evaluations"] = json!([{}, {}]);
    let (status, _, v) = answer(h.post("/access/v1/evaluations", &batch).await).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let results = v["evaluations"].as_array().unwrap();
    assert_eq!(results.len(), 2, "{v}");
    assert!(
        results
            .iter()
            .all(|r| r["context"]["decision_id"].is_string()),
        "{v}"
    );
    // An assertion inside an entry is that entry's error, not a second authentication.
    let mut inner = with(&h.keys.gateway.assertion("gateway"));
    inner["evaluations"] = json!([
        {},
        {"client_assertion_type": CLIENT_ASSERTION_TYPE,
         "client_assertion": h.keys.gateway.assertion("gateway")}
    ]);
    let (status, _, v) = answer(h.post("/access/v1/evaluations", &inner).await).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(
        v["evaluations"][0]["context"]["decision_id"].is_string(),
        "{v}"
    );
    assert_eq!(
        v["evaluations"][1]["context"]["error"]["code"], "malformed_request",
        "{v}"
    );
}

/// A client assertion's `jti` is in the database's replay markers: one used before a restart
/// is refused after it, on the same file.
#[tokio::test]
async fn an_assertion_used_before_a_restart_is_refused_after_it() {
    let keys = Keys::new();
    let idp = Idp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&keys, &idp);
    cfg.audit.sqlite_path = dir
        .path()
        .join("attenuo.sqlite")
        .to_string_lossy()
        .into_owned();
    let start = |cfg: Config| async move {
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        (
            common::Running::start(cfg, state.clone(), router).await,
            state,
        )
    };
    let client = reqwest::Client::new();
    let mint = |server: &common::Running| {
        let req = client
            .post(server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(
                &json!({"subject": "alice", "issuer": IDP, "agent": "planner",
                          "capabilities": ["github:*"]}),
            );
        async move {
            let v: Value = req.send().await.unwrap().json().await.unwrap();
            v["access_token"].as_str().unwrap().to_owned()
        }
    };
    let exchange = |server: &common::Running, root: String, a: String| {
        let req = client.post(server.url("/token")).json(&exchange_body(
            &root,
            "coder",
            assertion_fields(&a),
        ));
        async move { answer(req.send().await.unwrap()).await }
    };
    // Lives well past the restart.
    let a = keys.coder_new.assertion("coder");

    let (server, state) = start(cfg.clone()).await;
    let (status, _, v) = exchange(&server, mint(&server).await, a.clone()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    server.stop(state).await;

    let (server, state) = start(cfg.clone()).await;
    let (status, _, v) = exchange(&server, mint(&server).await, a.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_assertion_replayed"));
    let fresh = keys.coder_new.assertion("coder");
    let (status, _, v) = exchange(&server, mint(&server).await, fresh).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    server.stop(state).await;
}

/// `[token] actor_auth`: `"secret"` means client credentials, so an assertion is accepted;
/// `"actor_token"` refuses client credentials of both kinds.
#[tokio::test]
async fn actor_auth_modes_treat_an_assertion_as_client_credentials() {
    let h = Harness::start(|cfg| cfg.token.actor_auth = ActorAuth::Secret).await;
    let (root, _) = h.root().await;
    let (status, _, v) = answer(
        h.post(
            "/token",
            &exchange_body(
                &root,
                "coder",
                assertion_fields(&h.keys.coder_new.assertion("coder")),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, _, v) = answer(
        h.post(
            "/token",
            &intake_body(
                &h.idp.id_token("alice"),
                assertion_fields(&h.keys.planner.assertion("planner")),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let h = Harness::start(|cfg| {
        cfg.token.actor_auth = ActorAuth::ActorToken;
        // Never fetched: the request is refused before any actor token is looked at.
        cfg.actor_trust = vec![ActorTrustConfig {
            issuer: Some("https://workload.test".into()),
            jwks_url: Some("http://127.0.0.1:9/jwks".into()),
            spiffe_trust_domain: None,
            spiffe_bundle_url: None,
            ca_pem_path: None,
            audience: ISSUER.into(),
            subject_to_agent: SubjectToAgent::Sub,
            allowed_algs: vec!["EdDSA".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
        }];
    })
    .await;
    let (root, _) = h.root().await;
    let a = h.keys.coder_new.assertion("coder");
    let (status, _, v) = answer(
        h.post(
            "/token",
            &exchange_body(&root, "coder", assertion_fields(&a)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v), ("invalid_request", "client_auth_not_accepted"));
    let (status, _, v) = answer(
        h.post(
            "/token",
            &intake_body(
                &h.idp.id_token("alice"),
                assertion_fields(&h.keys.planner.assertion("planner")),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v), ("invalid_request", "client_auth_not_accepted"));
    // The refused request did not use the assertion up: it was never checked.
    assert_eq!(h.state.replay.len(), 0);
}

/// The server refuses to start on keys it could not use safely; the message names the entry
/// and the problem, never a private value.
#[tokio::test]
async fn startup_refuses_unusable_client_keys() {
    let keys = Keys::new();
    let idp = Idp::start().await;
    let private = keys.planner.key.private_jwk();
    let d = private["d"].as_str().unwrap().to_owned();
    let cases = [
        (
            AgentConfig::with_jwks("planner", json!({ "keys": [private] }).to_string()),
            "private key member `d`",
        ),
        (
            AgentConfig::with_jwks(
                "planner",
                json!({"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}).to_string(),
            ),
            "symmetric",
        ),
        (
            AgentConfig::with_jwks("planner", r#"{"keys": []}"#),
            "empty",
        ),
        (
            AgentConfig::with_jwks("planner", jwks(&[&keys.planner, &keys.planner])),
            "listed twice",
        ),
        (
            AgentConfig {
                id: "planner".into(),
                secret_sha256: None,
                jwks: None,
                jwks_url: None,
                jwks_ttl_seconds: None,
                ca_pem_path: None,
                tls_client_cert_sha256: None,
                tls_client_ca_pem_path: None,
                tls_client_auth_san_uri: None,
                tls_client_auth_san_dns: None,
            },
            "set secret_sha256, jwks",
        ),
    ];
    for (entry, want) in cases {
        let mut cfg = config(&keys, &idp);
        cfg.agents[0] = entry;
        let e = match attenuo_server::build(&cfg) {
            Ok(_) => panic!("started with a bad entry ({want})"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            e.contains("[[agents]] `planner`") && e.contains(want),
            "{e}"
        );
        assert!(!e.contains(&d), "{e}");
    }
    let mut cfg = config(&keys, &idp);
    cfg.token.client_assertion_max_lifetime_seconds = 0;
    assert!(attenuo_server::build(&cfg).is_err());
}

/// SR-108: an agent over `[limits] token_requests_per_minute` is refused before its client
/// assertion is recorded as used. Before the fix the assertion's `jti` was written to the
/// replay store first and the limit checked after, so a rate-limited agent still wrote one
/// marker per request (a database write and a slot of the store every single-use credential
/// shares), and a client that retried the same assertion after `Retry-After`, as the SDKs'
/// opt-in retry does, was refused as a replay.
#[tokio::test]
async fn a_rate_limited_agent_does_not_spend_its_assertion_sr108() {
    let h = Harness::start(|c| c.limits.token_requests_per_minute = 1).await;

    // Exchange: the first request of the minute goes through.
    let (root, _) = h.root().await;
    let a = h.keys.coder_new.assertion("coder");
    let (status, _, v) = answer(
        h.post(
            "/token",
            &exchange_body(&root, "coder", assertion_fields(&a)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let markers = h.state.replay.len();
    // The second is refused by the limit, and its assertion is not used up.
    let (root, _) = h.root().await;
    let b = h.keys.coder_new.assertion("coder");
    let (status, _, v) = answer(
        h.post(
            "/token",
            &exchange_body(&root, "coder", assertion_fields(&b)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_eq!(v["error"], "rate_limited", "{v}");
    assert_eq!(
        h.state.replay.len(),
        markers,
        "a rate-limited request wrote a replay marker"
    );

    // Hop 0, the same.
    let a = h.keys.planner.assertion("planner");
    let (status, _, v) = answer(
        h.post(
            "/token",
            &intake_body(&h.idp.id_token("alice"), assertion_fields(&a)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let markers = h.state.replay.len();
    let b = h.keys.planner.assertion("planner");
    let (status, _, v) = answer(
        h.post(
            "/token",
            &intake_body(&h.idp.id_token("alice"), assertion_fields(&b)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_eq!(
        h.state.replay.len(),
        markers,
        "a rate-limited hop-0 request wrote a replay marker"
    );
    assert!(h
        .state
        .metrics
        .render()
        .contains("attenuo_requests_rate_limited_total{limit=\"token\",cause=\"limit\"} 2\n"));
}

/// SR-111: with `[token] dpop_nonce = "required"`, a request whose DPoP proof has no current
/// nonce is refused with `use_dpop_nonce` so that the client sends it once more with the
/// nonce (RFC 9449 §8). The client assertion of that request must survive the retry: the
/// SDKs and the CLI resend the same body with a new proof. Before the fix the assertion was
/// recorded as used before the proof was checked, and the retry was refused as a replay.
#[tokio::test]
async fn a_nonce_retry_can_resend_its_assertion_sr111() {
    use attenuo_server::config::{DpopMode, DpopNonceMode};
    let h = Harness::start(|c| {
        c.token.dpop = DpopMode::Optional;
        c.token.dpop_nonce = DpopNonceMode::Required;
    })
    .await;
    let key = DpopKey::generate().unwrap();
    let url = h.server.url("/token");
    let send = |body: Value, nonce: Option<String>| {
        let proof = key.proof_with_nonce("POST", &url, None, nonce.as_deref(), now());
        h.client.post(&url).header("DPoP", proof).json(&body).send()
    };
    let nonce_of = |resp: &reqwest::Response| {
        resp.headers()
            .get("dpop-nonce")
            .map(|v| v.to_str().unwrap().to_owned())
    };

    // Exchange.
    let (root, _) = h.root().await;
    let body = exchange_body(
        &root,
        "coder",
        assertion_fields(&h.keys.coder_new.assertion("coder")),
    );
    let resp = send(body.clone(), None).await.unwrap();
    let nonce = nonce_of(&resp);
    let (status, _, v) = answer(resp).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v).1, "use_dpop_nonce", "{v}");
    let (status, _, v) = answer(send(body.clone(), nonce.clone()).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "the retry with the nonce: {v}");
    // Used once all the same.
    let (status, _, v) = answer(send(body, nonce.clone()).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_assertion_replayed"));

    // Hop 0.
    let body = intake_body(
        &h.idp.id_token("alice"),
        assertion_fields(&h.keys.planner.assertion("planner")),
    );
    let (status, _, v) = answer(send(body.clone(), None).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v).1, "use_dpop_nonce", "{v}");
    let (status, _, v) = answer(send(body, nonce).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "the retry with the nonce: {v}");
}

/// The status, the headers (all but `date`) and the body bytes of an answer.
async fn whole(resp: reqwest::Response) -> (StatusCode, Vec<(String, String)>, String) {
    let status = resp.status();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| *k != reqwest::header::DATE)
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
        .collect();
    headers.sort();
    (status, headers, resp.text().await.unwrap())
}

/// SR-110: a caller that holds no key of a client learns nothing about it from a refused
/// assertion. An unknown id, an entry with a secret only, an unknown `kid` (several keys and
/// none named, or a `kid` that is not there), a key of another algorithm and a bad signature
/// get the same answer, byte for byte apart from `Date`, at an exchange and at hop 0, as
/// `client_authentication_failed` does for a wrong secret. Before the fix the first two were
/// `client_authentication_failed` and the others `client_assertion_bad_signature`,
/// `client_assertion_unknown_kid` or `client_assertion_unsupported_alg`, which told which ids
/// have keys and whether one or several. Nothing is recorded in the replay store.
#[tokio::test]
async fn an_assertion_refusal_does_not_tell_which_client_ids_have_keys_sr110() {
    let h = Harness::start(|_| {}).await;
    let stranger = DpopKey::generate().unwrap();
    let probe = |client: &str, header: Value| {
        let t = now().unix_timestamp();
        stranger.sign_jws(
            &header,
            &json!({"iss": client, "sub": client, "aud": ISSUER,
                    "jti": uuid::Uuid::new_v4().to_string(), "exp": t + 60}),
        )
    };
    let cases = [
        // No such entry.
        ("nobody", json!({"alg": "EdDSA"})),
        // A secret only.
        ("reviewer", json!({"alg": "EdDSA"})),
        // Several keys and no kid; a kid that is not there.
        ("coder", json!({"alg": "EdDSA"})),
        ("coder", json!({"alg": "EdDSA", "kid": "nope"})),
        // An allowed algorithm the key is not for.
        ("planner", json!({"alg": "ES256", "kid": "planner-1"})),
        // The right kid, another key's signature.
        ("planner", json!({"alg": "EdDSA", "kid": "planner-1"})),
    ];
    let (root, _) = h.root().await;
    let mut exchange = Vec::new();
    let mut hop0 = Vec::new();
    for (client, header) in &cases {
        let resp = h
            .post(
                "/token",
                &exchange_body(
                    &root,
                    client,
                    assertion_fields(&probe(client, header.clone())),
                ),
            )
            .await;
        exchange.push(whole(resp).await);
        let resp = h
            .post(
                "/token",
                &intake_body(
                    &h.idp.id_token("alice"),
                    assertion_fields(&probe(client, header.clone())),
                ),
            )
            .await;
        hop0.push(whole(resp).await);
    }
    for answers in [&exchange, &hop0] {
        let (status, headers, body) = &answers[0];
        assert_eq!(*status, StatusCode::UNAUTHORIZED, "{body}");
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            v,
            json!({"error": "invalid_client", "code": "client_authentication_failed",
                   "error_description": "client_authentication_failed",
                   "detail": "unknown client, or the client_assertion is not signed by one of the client's keys"})
        );
        assert!(
            headers.contains(&(
                "www-authenticate".to_owned(),
                "Basic realm=\"attenuo\"".to_owned()
            )),
            "{headers:?}"
        );
        for (i, a) in answers.iter().enumerate() {
            assert_eq!(a, &answers[0], "case {i}: {:?}", cases[i]);
        }
    }
    assert_eq!(exchange[0], hop0[0]);
    // Nothing was recorded for any of them.
    assert_eq!(h.state.replay.len(), 0);
}

/// SR-110: the refusals that only a holder of the client's key can reach, because they come
/// after the signature verified, keep their specific codes: they tell a legitimate client
/// what to fix in its assertion. So do the checks made before the client is looked up, which
/// are the same whether it exists or not.
#[tokio::test]
async fn refusals_after_the_signature_keep_their_codes_sr110() {
    let h = Harness::start(|_| {}).await;
    let t = now().unix_timestamp();
    let claims = |patch: Value| {
        let mut c = json!({"iss": "planner", "sub": "planner", "aud": ISSUER,
                           "jti": uuid::Uuid::new_v4().to_string(), "exp": t + 60});
        for (k, v) in patch.as_object().unwrap() {
            if v.is_null() {
                c.as_object_mut().unwrap().remove(k);
            } else {
                c[k] = v.clone();
            }
        }
        c
    };
    let planner = &h.keys.planner;
    let reused = planner.sign(&claims(json!({"jti": "used-once"})));
    let cases = [
        (
            planner.sign(&claims(json!({"aud": format!("{ISSUER}/token")}))),
            "client_assertion_audience_mismatch",
        ),
        (
            planner.sign(&claims(json!({"exp": t - 3600}))),
            "client_assertion_expired",
        ),
        (
            planner.sign(&claims(json!({"exp": t + 3600}))),
            "client_assertion_lifetime_too_long",
        ),
        (
            planner.sign(&claims(json!({"iat": t + 3600}))),
            "client_assertion_not_yet_valid",
        ),
        (
            planner.sign(&claims(json!({"jti": null}))),
            "client_assertion_missing_claim",
        ),
        (
            planner.sign(&claims(json!({"iss": "coder"}))),
            "client_assertion_subject_mismatch",
        ),
        (
            planner.key.sign_jws(
                &json!({"alg": "HS256", "kid": "planner-1"}),
                &claims(json!({})),
            ),
            "client_assertion_unsupported_alg",
        ),
        (
            planner
                .key
                .sign_jws(&json!({"alg": "EdDSA", "kid": 1}), &claims(json!({}))),
            "client_assertion_malformed",
        ),
    ];
    for (assertion, want) in &cases {
        let (status, challenge, v) = answer(
            h.post(
                "/token",
                &intake_body(&h.idp.id_token("alice"), assertion_fields(assertion)),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
        assert_eq!(code(&v), ("invalid_client", *want), "{v}");
        assert_eq!(v["code"], *want);
        assert_eq!(challenge.as_deref(), Some("Basic realm=\"attenuo\""));
    }
    // A replay: the first use authenticates, the second is refused as such.
    let body = intake_body(&h.idp.id_token("alice"), assertion_fields(&reused));
    let (status, _, v) = answer(h.post("/token", &body).await).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let body = intake_body(&h.idp.id_token("alice"), assertion_fields(&reused));
    let (status, _, v) = answer(h.post("/token", &body).await).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_assertion_replayed"));
}
