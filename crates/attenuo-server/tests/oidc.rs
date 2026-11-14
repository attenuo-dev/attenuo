//! Hop-0 intake against a fake identity provider: an axum app on an ephemeral port serving OIDC
//! discovery and a JWKS with Ed25519 keys generated in the test, minting ID tokens and ID-JAGs.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::jsonrpc::CODE_DENIED;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::{AgentConfig, CapSpec, IdJagCeilingConfig, IdpConfig, RootGrant};
use attenuo_server::{AppState, Config};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use time::OffsetDateTime;

use common::sha256_hex;

const ISSUER: &str = "https://attenuo.test";
const AUDIENCE: &str = "attenuo-test";
const CLIENT_AUD: &str = "attenuo-client";
const ADMIN: &str = "test-admin-token";
const PLANNER_SECRET: &str = "planner-secret";
const CODER_SECRET: &str = "coder-secret";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

const POLICY: &str = r#"
@id("reads")
permit(principal, action == Action::"github/read_file", resource);

@id("issues")
permit(principal, action == Action::"github/create_issue", resource);
"#;

// ---------------------------------------------------------------------------------------------
// The fake IdP.
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct IdpKey {
    kid: String,
    encoding: EncodingKey,
    x: String,
}

impl IdpKey {
    fn generate(kid: &str) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        Self {
            kid: kid.into(),
            encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
            x: URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        }
    }

    fn jwk(&self) -> Value {
        json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
               "kid": self.kid, "x": self.x})
    }
}

struct FakeIdp {
    issuer: String,
    published: Arc<RwLock<Vec<IdpKey>>>,
    jwks_hits: Arc<AtomicUsize>,
    key: IdpKey,
    _task: AbortOnDrop,
}

impl FakeIdp {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let key = IdpKey::generate("k1");
        let published = Arc::new(RwLock::new(vec![key.clone()]));
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "id_token_signing_alg_values_supported": ["EdDSA"],
        });
        let (keys, hits) = (published.clone(), jwks_hits.clone());
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
                    hits.fetch_add(1, Ordering::SeqCst);
                    let jwks: Vec<Value> = keys.read().unwrap().iter().map(IdpKey::jwk).collect();
                    async move { Json(json!({ "keys": jwks })) }
                }),
            );
        let task = AbortOnDrop(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));
        Self {
            issuer,
            published,
            jwks_hits,
            key,
            _task: task,
        }
    }

    fn hits(&self) -> usize {
        self.jwks_hits.load(Ordering::SeqCst)
    }

    /// Publish exactly `keys` from now on.
    fn publish(&self, keys: &[&IdpKey]) {
        *self.published.write().unwrap() = keys.iter().map(|k| (*k).clone()).collect();
    }

    /// Standard ID token claims for `sub`, valid now.
    fn id_token_claims(&self, sub: &str) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        json!({
            "iss": self.issuer, "aud": CLIENT_AUD, "sub": sub,
            "iat": now, "exp": now + 300, "auth_time": now - 30,
            "nonce": "n-0S6_WzA2Mj",
            "email": format!("{sub}@example.com"), "groups": ["dev"], "amr": ["pwd", "otp"],
        })
    }

    /// ID-JAG claims: audience is attenuo itself, `client_id` names the agent.
    fn id_jag_claims(&self, sub: &str, client_id: &str) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        json!({
            "iss": self.issuer, "aud": ISSUER, "sub": sub, "client_id": client_id,
            "jti": uuid::Uuid::new_v4().to_string(), "iat": now, "exp": now + 300,
            "amr": ["hwk"],
        })
    }

    fn sign(&self, key: &IdpKey, typ: Option<&str>, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key.kid.clone());
        header.typ = typ.map(str::to_owned);
        jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
    }

    fn id_token(&self, sub: &str) -> String {
        self.sign(&self.key, Some("JWT"), &self.id_token_claims(sub))
    }
}

/// Aborts the server task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ---------------------------------------------------------------------------------------------
// The attenuo server.
// ---------------------------------------------------------------------------------------------

struct Harness {
    idp: FakeIdp,
    _upstream: FakeMcpServer,
    _upstream_task: Spawned,
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    async fn start_with(tweak: impl FnOnce(&mut Config)) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let idp = FakeIdp::start().await;
        let upstream = FakeMcpServer::new(&["read_file", "create_issue"]);
        let upstream_task = upstream.spawn().await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();

        let mut cfg = Config::default();
        cfg.issuer.issuer = ISSUER.into();
        cfg.issuer.audience = AUDIENCE.into();
        cfg.policy.policies_path = Some(policy_path);
        let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([
                ("read_file".to_string(), repo().readonly(true)),
                ("create_issue".to_string(), repo()),
            ]),
        )]);
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.idps = vec![IdpConfig {
            issuer: idp.issuer.clone(),
            audience: CLIENT_AUD.into(),
            jwks_url: None,
            allowed_algs: vec!["RS256".into(), "ES256".into(), "EdDSA".into()],
            attribute_claims: vec!["email".into(), "groups".into(), "amr".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 60,
            tenant: None,
            id_jag_ceiling: None,
            ca_pem_path: None,
            client_ids: ["planner", "coder"]
                .map(|a| (a.to_string(), CLIENT_AUD.to_string()))
                .into(),
        }];
        cfg.agents = vec![
            AgentConfig::with_secret_sha256("planner", sha256_hex(PLANNER_SECRET)),
            AgentConfig::with_secret_sha256("coder", sha256_hex(CODER_SECRET)),
        ];
        cfg.root_grants = vec![RootGrant {
            subject: None,
            issuer: idp.issuer.clone(),
            agent: "planner".into(),
            capabilities: vec![CapSpec::Short("github:*".into())],
            attributes: BTreeMap::new(),
            may_act: None,
        }];
        tweak(&mut cfg);

        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        // The tempdir only holds the policy file, which is read at build time.
        drop(dir);
        Self {
            idp,
            _upstream: upstream,
            _upstream_task: upstream_task,
            server,
            state,
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    async fn post_form(
        &self,
        pairs: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> (StatusCode, Value) {
        let body = serde_urlencoded::to_string(pairs).unwrap();
        let mut req = self
            .client
            .post(self.url("/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        if let Some((id, secret)) = basic {
            req = req.header(
                "authorization",
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            );
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// An ID-token intake as `planner` with form client credentials.
    async fn intake(&self, id_token: &str, scope: &str) -> (StatusCode, Value) {
        self.intake_as("planner", PLANNER_SECRET, id_token, scope)
            .await
    }

    async fn intake_as(
        &self,
        id: &str,
        secret: &str,
        id_token: &str,
        scope: &str,
    ) -> (StatusCode, Value) {
        self.post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", id_token),
                ("subject_token_type", ID_TOKEN),
                ("actor", id),
                ("client_id", id),
                ("client_secret", secret),
                ("scope", scope),
            ],
            None,
        )
        .await
    }

    fn verify(&self, token: &str) -> attenuo_core::DelegationChain {
        self.state
            .verifier
            .verify(token, OffsetDateTime::now_utc())
            .unwrap()
            .chain
    }

    async fn mcp_call(&self, token: &str, tool: &str) -> Value {
        let resp = self
            .client
            .post(self.url("/mcp/github"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": tool, "arguments": {"repo": "acme/api", "title": "t"}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }
}

/// Assert an OAuth error with a stable `error_description`.
fn assert_error(got: &(StatusCode, Value), status: StatusCode, error: &str, description: &str) {
    assert_eq!(got.0, status, "{}", got.1);
    assert_eq!(got.1["error"], error, "{}", got.1);
    assert_eq!(got.1["error_description"], description, "{}", got.1);
}

// ---------------------------------------------------------------------------------------------
// OIDC ID tokens.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn valid_id_token_yields_root_token_for_the_verified_user() {
    let h = Harness::start().await;
    let claims = h.idp.id_token_claims("alice");
    let token = h.idp.sign(&h.idp.key, Some("JWT"), &claims);
    let (status, body) = h
        .intake(&token, "github:read_file github:create_issue")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["issued_token_type"], JWT);
    assert_eq!(body["token_type"], "Bearer");

    let chain = h.verify(body["access_token"].as_str().unwrap());
    let user = &chain.originating_user;
    assert_eq!(user.subject, "alice");
    assert_eq!(user.issuer, h.idp.issuer);
    assert_eq!(
        user.authenticated_at.unix_timestamp(),
        claims["auth_time"].as_i64().unwrap()
    );
    assert_eq!(user.attributes["email"], "alice@example.com");
    assert_eq!(user.attributes["groups"], json!(["dev"]));
    assert_eq!(user.attributes["amr"], json!(["pwd", "otp"]));
    assert_eq!(user.attributes["mfa"], json!(true));
    assert!(!user.attributes.contains_key("nonce"));
    assert_eq!(chain.hops.len(), 1);
    assert_eq!(chain.hops[0].agent.0, "planner");
    assert_eq!(chain.hops[0].capabilities.len(), 2);
    assert_eq!(chain.hops[0].lease.0, body["lease"].as_str().unwrap());

    // The issuance is audited as a root mint.
    let audit: Value = h
        .client
        .get(h.url("/admin/audit?from=1&limit=10"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rec = &audit["entries"][0]["record"];
    assert_eq!(rec["tool"], "token.root");
    assert_eq!(rec["reason"], "token_issued");
    assert_eq!(rec["originating_subject"], "alice");
}

#[tokio::test]
async fn bad_id_tokens_are_rejected_with_stable_codes() {
    let h = Harness::start().await;
    let idp = &h.idp;
    let with = |k: &str, v: Value| {
        let mut c = idp.id_token_claims("alice");
        c[k] = v;
        idp.sign(&idp.key, Some("JWT"), &c)
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let bad = |code: &'static str, token: String| (code, token);

    // Same kid, different key: the signature cannot verify.
    let impostor = IdpKey {
        kid: idp.key.kid.clone(),
        ..IdpKey::generate("x")
    };
    let cases = vec![
        bad(
            "credential_audience_mismatch",
            with("aud", json!("someone-else")),
        ),
        bad(
            "credential_audience_mismatch",
            with("aud", json!(["a", "b"])),
        ),
        bad(
            "untrusted_issuer",
            with("iss", json!("https://evil.example")),
        ),
        bad("expired", with("exp", json!(now - 3600))),
        bad("not_yet_valid", with("iat", json!(now + 3600))),
        bad("missing_claim", with("sub", Value::Null)),
        bad(
            "bad_signature",
            idp.sign(&impostor, Some("JWT"), &idp.id_token_claims("alice")),
        ),
        bad(
            "typ_mismatch",
            idp.sign(
                &idp.key,
                Some("oauth-id-jag+jwt"),
                &idp.id_token_claims("alice"),
            ),
        ),
        bad("malformed_token", "not-a-jwt".to_string()),
    ];
    for (code, token) in cases {
        let got = h.intake(&token, "github:read_file").await;
        assert_error(&got, StatusCode::BAD_REQUEST, "invalid_grant", code);
    }

    // An audience given as an array that contains ours is fine when `azp` names us too; without
    // it, or with another party, the token is refused (SR-37).
    let no_azp = with("aud", json!(["other", CLIENT_AUD]));
    let got = h.intake(&no_azp, "github:read_file").await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "credential_audience_mismatch",
    );
    let mut claims = idp.id_token_claims("alice");
    claims["aud"] = json!(["other", CLIENT_AUD]);
    claims["azp"] = json!(CLIENT_AUD);
    let ok = idp.sign(&idp.key, Some("JWT"), &claims);
    assert_eq!(h.intake(&ok, "github:read_file").await.0, StatusCode::OK);

    // A kid the IdP never published: one refetch, then rejected.
    let before = idp.hits();
    let stranger = IdpKey::generate("never-published");
    let token = idp.sign(&stranger, Some("JWT"), &idp.id_token_claims("alice"));
    let got = h.intake(&token, "github:read_file").await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "unknown_kid",
    );
    assert_eq!(idp.hits(), before + 1);
    // A second unknown kid inside the cooldown does not hit the IdP again.
    let got = h.intake(&token, "github:read_file").await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "unknown_kid",
    );
    assert_eq!(idp.hits(), before + 1);
}

/// A refused credential's body carries only the stable sub-code: the verifier's text, which
/// names the issuer, the expected audience and the `kid`, stays in the server log (SR-17).
#[tokio::test]
async fn intake_refusals_do_not_echo_the_verifier() {
    let h = Harness::start().await;
    let idp = &h.idp;
    let assert_opaque = |got: &(StatusCode, Value), code: &str, secrets: &[&str]| {
        assert_error(got, StatusCode::BAD_REQUEST, "invalid_grant", code);
        assert_eq!(got.1["detail"], code, "{}", got.1);
        let text = got.1.to_string();
        for s in secrets {
            assert!(!text.contains(s), "body leaks {s:?}: {text}");
        }
    };

    // An ID token issued to another client.
    let mut c = idp.id_token_claims("alice");
    c["aud"] = json!("someone-else");
    let got = h
        .intake(&idp.sign(&idp.key, Some("JWT"), &c), "github:read_file")
        .await;
    assert_opaque(
        &got,
        "credential_audience_mismatch",
        &["someone-else", CLIENT_AUD, "planner", &idp.issuer],
    );

    // An ID-JAG whose audience is not attenuo.
    let mut c = idp.id_jag_claims("alice", "planner");
    c["aud"] = json!("https://elsewhere.example");
    let jag = idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c);
    let got = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &jag),
                ("subject_token_type", ID_JAG),
                ("scope", "github:read_file"),
            ],
            Some(("planner", PLANNER_SECRET)),
        )
        .await;
    assert_opaque(
        &got,
        "audience_mismatch",
        &["elsewhere.example", ISSUER, &idp.issuer],
    );

    // A key the IdP never published.
    let stranger = IdpKey::generate("never-published-kid");
    let token = idp.sign(&stranger, Some("JWT"), &idp.id_token_claims("alice"));
    let got = h.intake(&token, "github:read_file").await;
    assert_opaque(
        &got,
        "unknown_kid",
        &["never-published-kid", &idp.issuer, "kid "],
    );

    // An issuer that is not configured.
    let mut c = idp.id_token_claims("alice");
    c["iss"] = json!("https://evil.example");
    let got = h
        .intake(&idp.sign(&idp.key, Some("JWT"), &c), "github:read_file")
        .await;
    assert_opaque(&got, "untrusted_issuer", &["evil.example"]);
}

#[tokio::test]
async fn client_authentication_is_required() {
    let h = Harness::start().await;
    let token = h.idp.id_token("alice");
    for (id, secret, code) in [
        ("planner", "wrong", "client_authentication_failed"),
        ("ghost", PLANNER_SECRET, "client_authentication_failed"),
    ] {
        let got = h.intake_as(id, secret, &token, "github:read_file").await;
        assert_error(&got, StatusCode::UNAUTHORIZED, "invalid_client", code);
    }
    let got = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &token),
                ("subject_token_type", ID_TOKEN),
                ("scope", "github:read_file"),
            ],
            None,
        )
        .await;
    assert_error(
        &got,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "client_auth_missing",
    );
    // Basic with a wrong secret.
    let got = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &token),
                ("subject_token_type", ID_TOKEN),
                ("scope", "github:read_file"),
            ],
            Some(("planner", "nope")),
        )
        .await;
    assert_error(
        &got,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "client_authentication_failed",
    );
    // An authenticated agent cannot name another actor.
    let got = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &token),
                ("subject_token_type", ID_TOKEN),
                ("actor", "coder"),
                ("client_id", "planner"),
                ("client_secret", PLANNER_SECRET),
                ("scope", "github:read_file"),
            ],
            None,
        )
        .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "actor_mismatch",
    );
    // Client failures never reach the IdP.
    assert_eq!(h.idp.hits(), 0);
}

#[tokio::test]
async fn no_agents_configured_rejects_all_intake() {
    let h = Harness::start_with(|cfg| cfg.agents.clear()).await;
    let token = h.idp.id_token("alice");
    let got = h.intake(&token, "github:read_file").await;
    assert_error(
        &got,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "no_agents_configured",
    );
}

#[tokio::test]
async fn capabilities_are_capped_by_root_grants() {
    let h = Harness::start_with(|cfg| {
        // alice alone may also use slack; a subject-pinned grant wins over the general one.
        cfg.root_grants.push(RootGrant {
            subject: Some("alice".into()),
            issuer: cfg.idps[0].issuer.clone(),
            agent: "planner".into(),
            capabilities: vec![
                CapSpec::Short("github:*".into()),
                CapSpec::Short("slack:post_message".into()),
            ],
            attributes: BTreeMap::new(),
            may_act: None,
        });
    })
    .await;
    let alice = h.idp.id_token("alice");
    let bob = h.idp.id_token("bob");

    let got = h.intake(&bob, "github:read_file slack:post_message").await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "scope_exceeds_grant",
    );
    assert_eq!(h.intake(&bob, "github:read_file").await.0, StatusCode::OK);
    assert_eq!(
        h.intake(&alice, "github:read_file slack:post_message")
            .await
            .0,
        StatusCode::OK
    );
    let got = h.intake(&alice, "jira:*").await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "scope_exceeds_grant",
    );

    // `coder` is a known agent but has no root grant for this IdP.
    let got = h
        .intake_as("coder", CODER_SECRET, &alice, "github:read_file")
        .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "no_root_grant",
    );

    // Nothing requested.
    let got = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &alice),
                ("subject_token_type", ID_TOKEN),
                ("client_id", "planner"),
                ("client_secret", PLANNER_SECRET),
            ],
            None,
        )
        .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "no_capabilities_requested",
    );
}

#[tokio::test]
async fn jwks_is_cached_and_refetched_on_key_rotation() {
    let h = Harness::start().await;
    let idp = &h.idp;
    assert_eq!(
        h.intake(&idp.id_token("alice"), "github:read_file").await.0,
        StatusCode::OK
    );
    assert_eq!(idp.hits(), 1);
    assert_eq!(
        h.intake(&idp.id_token("bob"), "github:read_file").await.0,
        StatusCode::OK
    );
    assert_eq!(idp.hits(), 1, "second token is verified from the cache");

    // The IdP rotates to a new key and retires the old one.
    let k2 = IdpKey::generate("k2");
    idp.publish(&[&k2]);
    let token = idp.sign(&k2, None, &idp.id_token_claims("alice"));
    let (status, body) = h.intake(&token, "github:read_file").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(idp.hits(), 2, "unknown kid triggers exactly one refetch");
    assert_eq!(
        h.verify(body["access_token"].as_str().unwrap())
            .originating_user
            .subject,
        "alice"
    );

    // The retired key is gone from the cache.
    let got = h.intake(&idp.id_token("alice"), "github:read_file").await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "unknown_kid",
    );
}

#[tokio::test]
async fn unreachable_idp_is_temporarily_unavailable() {
    let h = Harness::start_with(|cfg| {
        cfg.idps[0].jwks_url = Some("http://127.0.0.1:9/jwks".into());
    })
    .await;
    let got = h.intake(&h.idp.id_token("alice"), "github:read_file").await;
    assert_error(
        &got,
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "jwks_unavailable",
    );
}

// ---------------------------------------------------------------------------------------------
// ID-JAG.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn id_jag_yields_root_token_and_typ_is_enforced() {
    let h = Harness::start().await;
    let idp = &h.idp;
    let jag = idp.sign(
        &idp.key,
        Some("oauth-id-jag+jwt"),
        &idp.id_jag_claims("alice", "planner"),
    );

    // As a token exchange, with HTTP Basic client authentication and no explicit actor.
    let (status, body) = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &jag),
                ("subject_token_type", ID_JAG),
                ("scope", "github:read_file"),
            ],
            Some(("planner", PLANNER_SECRET)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let chain = h.verify(body["access_token"].as_str().unwrap());
    assert_eq!(chain.originating_user.subject, "alice");
    assert_eq!(chain.originating_user.attributes["mfa"], json!(true));
    assert_eq!(chain.hops[0].agent.0, "planner");

    // Each ID-JAG is used once.
    let (status, body) = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &jag),
                ("subject_token_type", ID_JAG),
                ("scope", "github:read_file"),
            ],
            Some(("planner", PLANNER_SECRET)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error_description"], "replayed");

    // As the draft presents it: jwt-bearer with `assertion`.
    let jag = idp.sign(
        &idp.key,
        Some("oauth-id-jag+jwt"),
        &idp.id_jag_claims("alice", "planner"),
    );
    let (status, body) = h
        .post_form(
            &[
                ("grant_type", JWT_BEARER),
                ("assertion", &jag),
                ("client_id", "planner"),
                ("client_secret", PLANNER_SECRET),
                ("scope", "github:read_file"),
            ],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let jag_request = |token: String| {
        let h = &h;
        async move {
            h.post_form(
                &[
                    ("grant_type", EXCHANGE),
                    ("subject_token", &token),
                    ("subject_token_type", ID_JAG),
                    ("client_id", "planner"),
                    ("client_secret", PLANNER_SECRET),
                    ("scope", "github:read_file"),
                ],
                None,
            )
            .await
        }
    };
    // Without the ID-JAG typ (for example an ID token passed off as an ID-JAG).
    let untyped = idp.sign(
        &idp.key,
        Some("JWT"),
        &idp.id_jag_claims("alice", "planner"),
    );
    let got = jag_request(untyped).await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "typ_mismatch",
    );
    // Issued to a different client than the one presenting it.
    let other = idp.sign(
        &idp.key,
        Some("oauth-id-jag+jwt"),
        &idp.id_jag_claims("alice", "coder"),
    );
    let got = jag_request(other).await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "client_id_mismatch",
    );
    // Audience must be attenuo, not the IdP client id.
    let mut c = idp.id_jag_claims("alice", "planner");
    c["aud"] = json!(CLIENT_AUD);
    let got = jag_request(idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c)).await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "audience_mismatch",
    );
    // Missing client_id.
    let mut c = idp.id_jag_claims("alice", "planner");
    c.as_object_mut().unwrap().remove("client_id");
    let got = jag_request(idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c)).await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "missing_claim",
    );
}

/// An ID-JAG request as `planner` (jwt-bearer, form client credentials), with a `DPoP` header
/// when `dpop` is given.
async fn jag_bearer(h: &Harness, jag: &str, dpop: Option<String>) -> (StatusCode, Value) {
    let body = serde_urlencoded::to_string([
        ("grant_type", JWT_BEARER),
        ("assertion", jag),
        ("client_id", "planner"),
        ("client_secret", PLANNER_SECRET),
        ("scope", "github:read_file"),
    ])
    .unwrap();
    let mut req = h
        .client
        .post(h.url("/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body);
    if let Some(p) = dpop {
        req = req.header("DPoP", p);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The checks draft-ietf-oauth-identity-assertion-authz-grant-06 §4.4.1 adds to (or states more
/// plainly than) what -04 had: the `typ` media type in either spelling, a one-element `aud`,
/// `jti` required.
#[tokio::test]
async fn id_jag_draft_06_claim_rules() {
    let h = Harness::start().await;
    let idp = &h.idp;
    let ok = |got: &(StatusCode, Value)| assert_eq!(got.0, StatusCode::OK, "{}", got.1);

    // `typ` with the `application/` prefix is the same media type (RFC 7515 §4.1.9).
    for typ in ["application/oauth-id-jag+jwt", "OAuth-ID-JAG+JWT"] {
        let jag = idp.sign(&idp.key, Some(typ), &idp.id_jag_claims("alice", "planner"));
        ok(&jag_bearer(&h, &jag, None).await);
    }
    // Another `+jwt` type with the prefix is still refused.
    let jag = idp.sign(
        &idp.key,
        Some("application/at+jwt"),
        &idp.id_jag_claims("alice", "planner"),
    );
    assert_error(
        &jag_bearer(&h, &jag, None).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "typ_mismatch",
    );

    // `aud` as a one-element array is accepted; with a second audience it is refused, even
    // when attenuo is one of them.
    let mut c = idp.id_jag_claims("alice", "planner");
    c["aud"] = json!([ISSUER]);
    ok(&jag_bearer(&h, &idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c), None).await);
    for aud in [json!([ISSUER, "https://other-as.example"]), json!([])] {
        let mut c = idp.id_jag_claims("alice", "planner");
        c["aud"] = aud;
        assert_error(
            &jag_bearer(&h, &idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c), None).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "audience_mismatch",
        );
    }

    // `jti` is REQUIRED.
    let mut c = idp.id_jag_claims("alice", "planner");
    c.as_object_mut().unwrap().remove("jti");
    assert_error(
        &jag_bearer(&h, &idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c), None).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "missing_claim",
    );

    // Without `[[idps]] tenant`, a `tenant` claim is not checked.
    let mut c = idp.id_jag_claims("alice", "planner");
    c["tenant"] = json!("acme");
    ok(&jag_bearer(&h, &idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c), None).await);
}

/// `[[idps]] tenant`: the issuer is multi-tenant, and an ID-JAG must carry that `tenant`
/// (draft -06 §4.4.1). ID tokens are not affected.
#[tokio::test]
async fn id_jag_tenant_is_checked_when_configured() {
    let h = Harness::start_with(|cfg| cfg.idps[0].tenant = Some("acme".into())).await;
    let idp = &h.idp;
    let jag = |tenant: Option<Value>| {
        let mut c = idp.id_jag_claims("alice", "planner");
        if let Some(t) = tenant {
            c["tenant"] = t;
        }
        idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c)
    };
    let got = jag_bearer(&h, &jag(Some(json!("acme"))), None).await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    for (tenant, code) in [
        (None, "missing_claim"),
        (Some(json!("globex")), "tenant_mismatch"),
        (Some(json!(["acme"])), "tenant_mismatch"),
    ] {
        assert_error(
            &jag_bearer(&h, &jag(tenant), None).await,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            code,
        );
    }
    let (status, body) = h.intake(&idp.id_token("alice"), "github:read_file").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A sender-constrained ID-JAG (`cnf.jkt`, draft -04 §9.8.1.2, -06 §4.4.1) is accepted only
/// with a DPoP proof by that key, and the root token is bound to it.
#[tokio::test]
async fn id_jag_bound_to_a_dpop_key_needs_its_proof() {
    use attenuo_token::DpopKey;
    // `[token] dpop` is "optional" by default.
    let h = Harness::start().await;
    let idp = &h.idp;
    let (key, other) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
    let bound = |cnf: Value| {
        let mut c = idp.id_jag_claims("alice", "planner");
        c["cnf"] = cnf;
        idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c)
    };
    let url = h.url("/token");
    let proof = |k: &DpopKey| Some(k.proof("POST", &url, None, OffsetDateTime::now_utc()));
    let jkt = json!({ "jkt": key.thumbprint() });

    // No proof, or a proof by another key: refused.
    assert_error(
        &jag_bearer(&h, &bound(jkt.clone()), None).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "credential_pop_required",
    );
    assert_error(
        &jag_bearer(&h, &bound(jkt.clone()), proof(&other)).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "credential_pop_mismatch",
    );
    // A binding this server cannot check (not a DPoP key) is refused, not ignored.
    assert_error(
        &jag_bearer(&h, &bound(json!({"x5t#S256": "abc"})), proof(&key)).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "credential_pop_required",
    );
    // With the right proof: issued, and bound to the same key.
    let (status, body) = jag_bearer(&h, &bound(jkt.clone()), proof(&key)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "DPoP", "{body}");
    let verified = h
        .state
        .verifier
        .verify(
            body["access_token"].as_str().unwrap(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    assert_eq!(
        verified.claims.cnf.map(|c| c.jkt).as_deref(),
        Some(key.thumbprint())
    );
    // An unbound ID-JAG still works without a proof.
    let jag = idp.sign(
        &idp.key,
        Some("oauth-id-jag+jwt"),
        &idp.id_jag_claims("alice", "planner"),
    );
    let got = jag_bearer(&h, &jag, None).await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
}

/// The rest of draft -06 §9.11.1.2 at the Resource Authorization Server: a DPoP proof that is
/// sent is validated as RFC 9449 §4 says whether or not the ID-JAG has a `cnf` (a proof for
/// another URL, or one used before, is refused), an ID-JAG without `cnf` sent with a valid
/// proof gets a root token bound to the proof's key (the MAY), and with `[token] dpop =
/// "required"` an ID-JAG without `cnf` and without a proof is refused (as 401 `dpop_required`,
/// not the draft's `invalid_grant`; see the standards note).
#[tokio::test]
async fn id_jag_dpop_proofs_follow_draft_06_section_9_11() {
    use attenuo_server::config::DpopMode;
    use attenuo_token::DpopKey;
    let h = Harness::start().await;
    let idp = &h.idp;
    let key = DpopKey::generate().unwrap();
    let url = h.url("/token");
    let jag = |cnf: Option<Value>| {
        let mut c = idp.id_jag_claims("alice", "planner");
        if let Some(cnf) = cnf {
            c["cnf"] = cnf;
        }
        idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c)
    };
    let jkt = json!({ "jkt": key.thumbprint() });
    let now = OffsetDateTime::now_utc;

    // `cnf` and a proof by the right key, but for another URL: the proof is checked first.
    let wrong_url = key.proof("POST", "https://elsewhere.test/token", None, now());
    assert_error(
        &jag_bearer(&h, &jag(Some(jkt.clone())), Some(wrong_url)).await,
        StatusCode::UNAUTHORIZED,
        "invalid_dpop_proof",
        "invalid_dpop_proof",
    );

    // No `cnf`, a valid proof: issued, bound to the proof's key.
    let p = key.proof("POST", &url, None, now());
    let (status, body) = jag_bearer(&h, &jag(None), Some(p.clone())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "DPoP", "{body}");
    let verified = h
        .state
        .verifier
        .verify(body["access_token"].as_str().unwrap(), now())
        .unwrap();
    assert_eq!(
        verified.claims.cnf.map(|c| c.jkt).as_deref(),
        Some(key.thumbprint())
    );
    // The same proof again (no `cnf`, and with `cnf`): refused as replayed.
    for cnf in [None, Some(jkt.clone())] {
        assert_error(
            &jag_bearer(&h, &jag(cnf), Some(p.clone())).await,
            StatusCode::UNAUTHORIZED,
            "invalid_dpop_proof",
            "invalid_dpop_proof",
        );
    }
    // No `cnf`, a proof for another URL: refused, not ignored.
    let wrong_url = key.proof("POST", "https://elsewhere.test/token", None, now());
    assert_error(
        &jag_bearer(&h, &jag(None), Some(wrong_url)).await,
        StatusCode::UNAUTHORIZED,
        "invalid_dpop_proof",
        "invalid_dpop_proof",
    );

    // Sender-constrained tokens required: no `cnf` and no proof is refused.
    let h = Harness::start_with(|cfg| cfg.token.dpop = DpopMode::Required).await;
    let unbound = {
        let idp = &h.idp;
        idp.sign(
            &idp.key,
            Some("oauth-id-jag+jwt"),
            &idp.id_jag_claims("alice", "planner"),
        )
    };
    assert_error(
        &jag_bearer(&h, &unbound, None).await,
        StatusCode::UNAUTHORIZED,
        "dpop_required",
        "dpop_required",
    );
}

/// With `[token] dpop = "off"` the server checks no proofs, so a bound ID-JAG is refused.
#[tokio::test]
async fn id_jag_bound_to_a_key_is_refused_when_dpop_is_off() {
    use attenuo_server::config::DpopMode;
    use attenuo_token::DpopKey;
    let h = Harness::start_with(|cfg| cfg.token.dpop = DpopMode::Off).await;
    let idp = &h.idp;
    let key = DpopKey::generate().unwrap();
    let mut c = idp.id_jag_claims("alice", "planner");
    c["cnf"] = json!({ "jkt": key.thumbprint() });
    let jag = idp.sign(&idp.key, Some("oauth-id-jag+jwt"), &c);
    let p = key.proof("POST", &h.url("/token"), None, OffsetDateTime::now_utc());
    assert_error(
        &jag_bearer(&h, &jag, Some(p)).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "credential_pop_required",
    );
}

// ---------------------------------------------------------------------------------------------
// The dev mint is off by default.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn dev_root_mint_is_not_mounted_by_default() {
    let h = Harness::start().await;
    let resp = h
        .client
        .post(h.url("/admin/root-token"))
        .bearer_auth(ADMIN)
        .json(
            &json!({"subject": "alice", "issuer": h.idp.issuer, "agent": "planner",
                      "capabilities": ["github:*"]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// End to end: ID token -> root -> exchange -> proxy.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn id_token_to_root_to_exchange_to_proxy() {
    let h = Harness::start().await;
    // Hop 0 from the IdP, client authenticated with HTTP Basic.
    let (status, root) = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &h.idp.id_token("alice")),
                ("subject_token_type", ID_TOKEN),
                ("actor", "planner"),
                ("scope", "github:*"),
            ],
            Some(("planner", PLANNER_SECRET)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{root}");
    let root_token = root["access_token"].as_str().unwrap();

    // Hop 1: planner delegates read_file only to coder.
    let (status, child) = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", root_token),
                ("subject_token_type", JWT),
                ("actor", "coder"),
                ("scope", "github:read_file"),
            ],
            Some(("coder", CODER_SECRET)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{child}");
    let child_token = child["access_token"].as_str().unwrap();
    let chain = h.verify(child_token);
    assert_eq!(chain.originating_user.subject, "alice");
    assert_eq!(chain.originating_user.issuer, h.idp.issuer);
    assert_eq!(chain.hops.len(), 2);

    // Through the proxy: read_file is allowed, create_issue was never delegated to coder.
    let ok = h.mcp_call(child_token, "read_file").await;
    assert!(ok.get("result").is_some(), "{ok}");
    let denied = h.mcp_call(child_token, "create_issue").await;
    assert_eq!(denied["error"]["code"], json!(CODE_DENIED), "{denied}");
    assert_eq!(denied["error"]["data"]["reason"], "capability_denied");
    // The root holder itself may create issues.
    let ok = h.mcp_call(root_token, "create_issue").await;
    assert!(ok.get("result").is_some(), "{ok}");
}

/// An ID token mints one root token, and that token does not outlive it.
#[tokio::test]
async fn id_tokens_are_used_once_and_cap_the_root_ttl() {
    let h = Harness::start().await;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = h.idp.id_token_claims("alice");
    claims["exp"] = json!(now + 120);
    let token = h.idp.sign(&h.idp.key, Some("JWT"), &claims);

    // A long TTL is asked for; the root token ends when the ID token does.
    let (status, body) = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &token),
                ("subject_token_type", ID_TOKEN),
                ("client_id", "planner"),
                ("client_secret", PLANNER_SECRET),
                ("scope", "github:read_file"),
                ("requested_ttl_seconds", "86400"),
            ],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["expires_in"].as_i64().unwrap() <= 120, "{body}");
    let chain = h.verify(body["access_token"].as_str().unwrap());
    assert!(chain.hops[0].expires_at.unix_timestamp() <= now + 120);

    // The same ID token again (no `jti`, so keyed by its hash): refused.
    let again = h.intake(&token, "github:read_file").await;
    assert_error(&again, StatusCode::BAD_REQUEST, "invalid_grant", "replayed");
    // A token with a `jti` is keyed by (iss, jti).
    let mut claims = h.idp.id_token_claims("alice");
    claims["jti"] = json!("id-token-1");
    let with_jti = h.idp.sign(&h.idp.key, Some("JWT"), &claims);
    assert_eq!(
        h.intake(&with_jti, "github:read_file").await.0,
        StatusCode::OK
    );
    // A token re-signed with the same (iss, jti) is the same credential.
    claims["exp"] = json!(now + 200);
    let same_jti = h.idp.sign(&h.idp.key, Some("JWT"), &claims);
    assert_error(
        &h.intake(&same_jti, "github:read_file").await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "replayed",
    );

    // Inside the clock skew after `exp` the token still verifies, but there is no lifetime
    // left to give a root token.
    let mut claims = h.idp.id_token_claims("alice");
    claims["exp"] = json!(now - 5);
    let expiring = h.idp.sign(&h.idp.key, Some("JWT"), &claims);
    assert_error(
        &h.intake(&expiring, "github:read_file").await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "credential_expired",
    );
}

// ---------------------------------------------------------------------------------------------
// `[idps.id_jag_ceiling]`: the ID-JAG's own claims as a ceiling under `[[root_grants]]`.
// ---------------------------------------------------------------------------------------------

const GITHUB_RESOURCE: &str = "https://mcp.test/github";
const SLACK_RESOURCE: &str = "https://mcp.test/slack";
const JIRA_RESOURCE: &str = "https://mcp.test/jira";

/// A harness whose root grant gives `github:*` and `slack:*`, with a ceiling on the IdP when
/// `ceiling` is set: three resources (jira is mapped but not granted) and two scopes.
async fn ceiling_harness(ceiling: bool) -> Harness {
    Harness::start_with(|cfg| {
        cfg.root_grants[0].capabilities = vec![
            CapSpec::Short("github:*".into()),
            CapSpec::Short("slack:*".into()),
        ];
        if ceiling {
            cfg.idps[0].id_jag_ceiling = Some(IdJagCeilingConfig {
                resources: BTreeMap::from([
                    (GITHUB_RESOURCE.to_string(), vec!["github".to_string()]),
                    (SLACK_RESOURCE.to_string(), vec!["slack".to_string()]),
                    (JIRA_RESOURCE.to_string(), vec!["jira".to_string()]),
                ]),
                scopes: BTreeMap::from([
                    (
                        "files.read".to_string(),
                        vec![CapSpec::Short("github:read_file".into())],
                    ),
                    ("everything".to_string(), vec![CapSpec::Short("*:*".into())]),
                ]),
            });
        }
    })
    .await
}

/// An ID-JAG for alice and planner, with `extra` claims set.
fn jag_with(h: &Harness, extra: Value) -> String {
    let mut c = h.idp.id_jag_claims("alice", "planner");
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    h.idp.sign(&h.idp.key, Some("oauth-id-jag+jwt"), &c)
}

/// Present `jag` as planner (jwt-bearer), asking with `ask` (`scope` or
/// `authorization_details`).
async fn present(h: &Harness, jag: &str, ask: (&str, &str)) -> (StatusCode, Value) {
    h.post_form(
        &[
            ("grant_type", JWT_BEARER),
            ("assertion", jag),
            ("client_id", "planner"),
            ("client_secret", PLANNER_SECRET),
            ask,
        ],
        None,
    )
    .await
}

/// The audit record of the root token with this lease.
async fn root_record(h: &Harness, lease: &str) -> Value {
    let audit: Value = h
        .client
        .get(h.url("/admin/audit?from=1&limit=1000"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["record"].clone())
        .find(|r| r["tool"] == "token.root" && r["leases"][0] == lease)
        .unwrap_or_else(|| panic!("no token.root record for {lease}: {audit}"))
}

/// The arguments digest an intake record of `token` has, with `extra` members added to the
/// arguments the server has always recorded.
fn intake_digest(h: &Harness, token: &str, extra: Value) -> String {
    let chain = h.verify(token);
    let mut args = json!({
        "agent": "planner",
        "requested": chain.hops[0].capabilities,
        "credential": "id-jag",
        "idp": h.idp.issuer,
        "agent_auth": "client_secret",
        "dpop_bound": false,
    });
    for (k, v) in extra.as_object().unwrap() {
        args[k] = v.clone();
    }
    attenuo_core::ToolCall::new("attenuo", "token.root", args).arguments_digest()
}

fn caps(token_caps: &attenuo_core::CapabilitySet) -> Vec<String> {
    token_caps.iter().map(|c| c.display()).collect()
}

/// Without `[idps.id_jag_ceiling]` the claims are ignored: an ID-JAG whose claims name nothing
/// mappable still gets what the root grant and the request allow, and the audit record's
/// arguments are exactly the ones recorded before the option existed.
#[tokio::test]
async fn id_jag_claims_are_ignored_without_a_ceiling() {
    let h = ceiling_harness(false).await;
    let jag = jag_with(
        &h,
        json!({
            "resource": "https://unmapped.example",
            "scope": "nothing",
            "authorization_details": [{"type": "payment_initiation"}],
        }),
    );
    let got = present(&h, &jag, ("scope", "github:read_file slack:post_message")).await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let token = got.1["access_token"].as_str().unwrap();
    assert_eq!(
        caps(&h.verify(token).hops[0].capabilities),
        ["github:read_file", "slack:post_message"]
    );
    let rec = root_record(&h, got.1["lease"].as_str().unwrap()).await;
    assert_eq!(rec["arguments_digest"], intake_digest(&h, token, json!({})));
    // A request wider than the grant keeps its old code.
    let jag = jag_with(&h, json!({}));
    assert_error(
        &present(&h, &jag, ("scope", "jira:create_issue")).await,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "scope_exceeds_grant",
    );
}

/// With the ceiling, each of `resource`, `scope` and `authorization_details` narrows the root
/// grant; the audit record names the claims used.
#[tokio::test]
async fn id_jag_ceiling_narrows_by_each_claim() {
    let h = ceiling_harness(true).await;
    let exceeds = |got: &(StatusCode, Value)| {
        assert_error(
            got,
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope_exceeds_id_jag",
        )
    };

    // resource: github only, so slack is out.
    let res = json!({"resource": GITHUB_RESOURCE});
    exceeds(
        &present(
            &h,
            &jag_with(&h, res.clone()),
            ("scope", "slack:post_message"),
        )
        .await,
    );
    let got = present(
        &h,
        &jag_with(&h, res.clone()),
        ("scope", "github:create_issue"),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let token = got.1["access_token"].as_str().unwrap();
    let rec = root_record(&h, got.1["lease"].as_str().unwrap()).await;
    assert_eq!(
        rec["arguments_digest"],
        intake_digest(&h, token, json!({"id_jag_ceiling": ["resource"]}))
    );

    // scope: read_file only.
    let scope = json!({"scope": "files.read"});
    exceeds(
        &present(
            &h,
            &jag_with(&h, scope.clone()),
            ("scope", "github:create_issue"),
        )
        .await,
    );
    let got = present(
        &h,
        &jag_with(&h, scope.clone()),
        ("scope", "github:read_file"),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);

    // authorization_details: read_file under a repository prefix; the constraint carries over,
    // so asking without it is too much.
    let details = json!({"authorization_details": [{
        "type": "attenuo_capabilities",
        "capabilities": [{"server": "github", "tool": "read_file",
                          "constraints": {"repo": {"op": "prefix", "value": "acme/"}}}],
    }]});
    exceeds(
        &present(
            &h,
            &jag_with(&h, details.clone()),
            ("scope", "github:read_file"),
        )
        .await,
    );
    let ask = json!([{"type": "attenuo_capabilities", "capabilities": [
        {"server": "github", "tool": "read_file",
         "constraints": {"repo": {"op": "prefix", "value": "acme/api"}}}]}])
    .to_string();
    let got = present(
        &h,
        &jag_with(&h, details.clone()),
        ("authorization_details", &ask),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);

    // All three together: their intersection.
    let all = json!({"resource": [GITHUB_RESOURCE, SLACK_RESOURCE], "scope": "files.read",
                     "authorization_details": details["authorization_details"]});
    exceeds(
        &present(
            &h,
            &jag_with(&h, all.clone()),
            ("scope", "slack:post_message"),
        )
        .await,
    );
    let got = present(&h, &jag_with(&h, all), ("authorization_details", &ask)).await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let token = got.1["access_token"].as_str().unwrap();
    let rec = root_record(&h, got.1["lease"].as_str().unwrap()).await;
    assert_eq!(
        rec["arguments_digest"],
        intake_digest(
            &h,
            token,
            json!({"id_jag_ceiling": ["resource", "scope", "authorization_details"]})
        )
    );

    // None of the claims: the root grant as it is, and the record says the ceiling ran.
    let got = present(
        &h,
        &jag_with(&h, json!({})),
        ("scope", "slack:post_message"),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let token = got.1["access_token"].as_str().unwrap();
    let rec = root_record(&h, got.1["lease"].as_str().unwrap()).await;
    assert_eq!(
        rec["arguments_digest"],
        intake_digest(&h, token, json!({"id_jag_ceiling": []}))
    );

    // ID tokens are not affected by the ceiling.
    let got = h
        .intake(&h.idp.id_token("alice"), "slack:post_message")
        .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
}

/// A claim naming more than the root grant gives adds nothing; an unmapped resource or scope
/// and an unknown `authorization_details` type name nothing; when nothing is left the request
/// is refused with `id_jag_ceiling_empty`.
#[tokio::test]
async fn id_jag_ceiling_never_widens_and_fails_closed() {
    let h = ceiling_harness(true).await;

    // `everything` maps to `*:*` and jira is a mapped resource, but the grant has neither.
    for wide in [
        json!({"scope": "everything"}),
        json!({"resource": [GITHUB_RESOURCE, JIRA_RESOURCE]}),
    ] {
        assert_error(
            &present(
                &h,
                &jag_with(&h, wide.clone()),
                ("scope", "jira:create_issue"),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope_exceeds_grant",
        );
        let got = present(&h, &jag_with(&h, wide), ("scope", "github:read_file")).await;
        assert_eq!(got.0, StatusCode::OK, "{}", got.1);
        let token = got.1["access_token"].as_str().unwrap();
        assert_eq!(
            caps(&h.verify(token).hops[0].capabilities),
            ["github:read_file"]
        );
    }
    // Only jira, which the grant does not give: nothing is left.
    let empty = |got: &(StatusCode, Value)| {
        assert_error(
            got,
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "id_jag_ceiling_empty",
        )
    };
    empty(
        &present(
            &h,
            &jag_with(&h, json!({"resource": JIRA_RESOURCE})),
            ("scope", "github:read_file"),
        )
        .await,
    );

    // Unmapped, unknown or malformed: names nothing.
    for claims in [
        json!({"resource": "https://unmapped.example"}),
        json!({"resource": format!("{GITHUB_RESOURCE}/")}),
        json!({"scope": "admin"}),
        json!({"scope": ["files.read"]}),
        json!({"authorization_details": [{"type": "payment_initiation", "capabilities": [
            {"server": "github", "tool": "*"}]}]}),
        json!({"authorization_details": [{"type": "attenuo_capabilities", "capabilities": [
            {"server": "github", "tool": "*", "constraint": {}}]}]}),
        // A mapped resource with an unmapped scope: each claim present must allow it.
        json!({"resource": GITHUB_RESOURCE, "scope": "admin"}),
    ] {
        empty(&present(&h, &jag_with(&h, claims), ("scope", "github:read_file")).await);
    }
    // An unmapped token next to a mapped one: the mapped one counts.
    let got = present(
        &h,
        &jag_with(&h, json!({"scope": "admin files.read"})),
        ("scope", "github:read_file"),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);

    // A refusal does not use the ID-JAG up (as with `scope_exceeds_grant`).
    let jag = jag_with(&h, json!({"scope": "files.read"}));
    assert_error(
        &present(&h, &jag, ("scope", "github:create_issue")).await,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "scope_exceeds_id_jag",
    );
    assert_eq!(
        present(&h, &jag, ("scope", "github:read_file")).await.0,
        StatusCode::OK
    );
}

/// The ceiling bounds the whole chain: an exchange from the root token cannot ask for what the
/// root grant gives but the ID-JAG did not, and the proxy does not allow it either.
#[tokio::test]
async fn a_later_exchange_cannot_exceed_the_id_jag_ceiling() {
    let h = ceiling_harness(true).await;
    let jag = jag_with(&h, json!({"scope": "files.read"}));
    let got = present(&h, &jag, ("scope", "github:read_file")).await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let root = got.1["access_token"].as_str().unwrap().to_owned();

    for ask in ["github:create_issue", "github:*", "slack:post_message"] {
        let (status, body) = h
            .post_form(
                &[
                    ("grant_type", EXCHANGE),
                    ("subject_token", &root),
                    ("subject_token_type", JWT),
                    ("actor", "coder"),
                    ("scope", ask),
                ],
                Some(("coder", CODER_SECRET)),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ask}: {body}");
        assert_eq!(body["code"], "scope_exceeds_parent", "{ask}: {body}");
    }
    let ok = h.mcp_call(&root, "read_file").await;
    assert!(ok.get("result").is_some(), "{ok}");
    let denied = h.mcp_call(&root, "create_issue").await;
    assert_eq!(
        denied["error"]["data"]["reason"], "capability_denied",
        "{denied}"
    );
}

/// SR-124: `scope_exceeds_id_jag` names the capability as the caller asked for it, not with
/// the root grant's limits copied in, so a refusal does not tell the caller the grant's figures
/// for a capability its ID-JAG does not allow.
#[tokio::test]
async fn scope_exceeds_id_jag_does_not_show_the_grant_limits_sr124() {
    let h = Harness::start_with(|cfg| {
        let mut github: attenuo_core::Capability = attenuo_core::Capability::new("github", "*");
        github.limits = attenuo_core::Limits::default().with_calls(7);
        cfg.root_grants[0].capabilities = vec![CapSpec::Full(github)];
        cfg.idps[0].id_jag_ceiling = Some(IdJagCeilingConfig {
            resources: BTreeMap::new(),
            scopes: BTreeMap::from([(
                "files.read".to_string(),
                vec![CapSpec::Short("github:read_file".into())],
            )]),
        });
    })
    .await;
    let got = present(
        &h,
        &jag_with(&h, json!({"scope": "files.read"})),
        ("scope", "github:create_issue"),
    )
    .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "scope_exceeds_id_jag",
    );
    let detail = got.1["detail"].as_str().unwrap();
    assert!(detail.contains("github:create_issue"), "{detail}");
    assert!(!detail.contains("limits"), "{detail}");
    // Asking for both tools splits the grant's one `calls: 7` into two capabilities, which
    // hop 0 refuses before the ceiling is read (SR-121), without the figure either.
    let got = present(
        &h,
        &jag_with(&h, json!({"scope": "files.read"})),
        ("scope", "github:read_file github:create_issue"),
    )
    .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "limit_split_at_root",
    );
    let detail = got.1["detail"].as_str().unwrap();
    assert!(
        !detail.contains("limits=") && !detail.contains('7'),
        "{detail}"
    );
    // Within both, the root token carries the grant's limit, as before.
    let got = present(
        &h,
        &jag_with(&h, json!({"scope": "files.read"})),
        ("scope", "github:read_file"),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let token = got.1["access_token"].as_str().unwrap();
    assert_eq!(
        caps(&h.verify(token).hops[0].capabilities),
        [r#"github:read_file limits={"calls":7}"#]
    );
}

/// Three `banking:send_money` capabilities, one per recipient, as an `authorization_details`
/// request value.
fn three_payees() -> String {
    let pay = |who: &str| {
        json!({"server": "banking", "tool": "send_money",
               "constraints": {"to": {"op": "equals", "value": who}}})
    };
    json!([{"type": "attenuo_capabilities",
            "capabilities": [pay("alice"), pay("bob"), pay("carol")]}])
    .to_string()
}

/// SR-121, the budget in an ID-JAG claim: under an unlimited root grant `banking:*`, the
/// ID-JAG's `authorization_details` names `banking:send_money` with `sum` 100. A request split
/// into three capabilities, one per recipient, would get the 100 three times; it is refused
/// with `limit_split_at_root`, naming the capabilities as requested. One capability with
/// `one_of` gets the claim's figure once. Without the ceiling the claim is ignored and the
/// split is allowed under the unlimited grant, as before.
#[tokio::test]
async fn an_id_jag_budget_is_not_split_across_capabilities_sr121() {
    let tweak = |ceiling: bool| {
        move |cfg: &mut Config| {
            cfg.root_grants[0].capabilities = vec![CapSpec::Short("banking:*".into())];
            if ceiling {
                cfg.idps[0].id_jag_ceiling = Some(IdJagCeilingConfig {
                    resources: BTreeMap::new(),
                    scopes: BTreeMap::new(),
                });
            }
        }
    };
    let budget = json!({"authorization_details": [{"type": "attenuo_capabilities",
        "capabilities": [{"server": "banking", "tool": "send_money",
                          "limits": {"sum": {"arg": "amount", "max": 100}}}]}]});
    let h = Harness::start_with(tweak(true)).await;
    let got = present(
        &h,
        &jag_with(&h, budget.clone()),
        ("authorization_details", &three_payees()),
    )
    .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "limit_split_at_root",
    );
    let detail = got.1["detail"].as_str().unwrap();
    assert!(detail.contains("ID-JAG"), "{detail}");
    assert!(
        detail.contains("alice") && detail.contains("bob"),
        "{detail}"
    );
    assert!(
        !detail.contains("100") && !detail.contains("limits="),
        "{detail}"
    );

    let one = json!([{"type": "attenuo_capabilities", "capabilities": [
        {"server": "banking", "tool": "send_money", "constraints":
            {"to": {"op": "one_of", "value": ["alice", "bob", "carol"]}}}]}])
    .to_string();
    let got = present(
        &h,
        &jag_with(&h, budget.clone()),
        ("authorization_details", &one),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let token = got.1["access_token"].as_str().unwrap();
    let caps = caps(&h.verify(token).hops[0].capabilities);
    assert_eq!(caps.len(), 1);
    assert!(
        caps[0].contains(r#""sum":{"arg":"amount","max":100}"#),
        "{caps:?}"
    );

    // The ceiling off: the claim is not read, the grant is unlimited, the split is allowed.
    let h = Harness::start_with(tweak(false)).await;
    let got = present(
        &h,
        &jag_with(&h, budget),
        ("authorization_details", &three_payees()),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    assert_eq!(
        h.verify(got.1["access_token"].as_str().unwrap()).hops[0]
            .capabilities
            .len(),
        3
    );
}

/// SR-121, the budget in `[[root_grants]]`: the same split is refused at intake, for an
/// ID-JAG and for an ID token, before any ceiling is read.
#[tokio::test]
async fn a_root_grant_budget_is_not_split_at_intake_sr121() {
    let h = Harness::start_with(|cfg| {
        let mut banking = attenuo_core::Capability::new("banking", "*");
        banking.limits = attenuo_core::Limits::default().with_sum("amount", 100);
        cfg.root_grants[0].capabilities = vec![CapSpec::Full(banking)];
    })
    .await;
    let got = present(
        &h,
        &jag_with(&h, json!({})),
        ("authorization_details", &three_payees()),
    )
    .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "limit_split_at_root",
    );
    let detail = got.1["detail"].as_str().unwrap();
    assert!(detail.contains("[[root_grants]]"), "{detail}");
    assert!(!detail.contains("100"), "{detail}");

    let id_token = h
        .idp
        .sign(&h.idp.key, Some("JWT"), &h.idp.id_token_claims("alice"));
    let got = h
        .post_form(
            &[
                ("grant_type", EXCHANGE),
                ("subject_token", &id_token),
                ("subject_token_type", ID_TOKEN),
                ("client_id", "planner"),
                ("client_secret", PLANNER_SECRET),
                ("authorization_details", &three_payees()),
            ],
            None,
        )
        .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "limit_split_at_root",
    );
    // One payee is one capability, and fine.
    let got = present(
        &h,
        &jag_with(&h, json!({})),
        ("scope", "banking:send_money"),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
}

/// SR-123 at intake: a hop-0 request over 1,024 capabilities, or with a `one_of` over 1,024
/// values, is refused before it is attenuated against the root grant.
#[tokio::test]
async fn an_intake_request_is_bounded_in_size_sr123() {
    let h = Harness::start().await;
    let many: Vec<String> = (0..1025).map(|i| format!("github:t{i}")).collect();
    let got = present(&h, &jag_with(&h, json!({})), ("scope", &many.join(" "))).await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "too_many_capabilities",
    );
    let long = json!([{"type": "attenuo_capabilities", "capabilities": [
        {"server": "github", "tool": "read_file", "constraints":
            {"repo": {"op": "one_of", "value": (0..1025).collect::<Vec<_>>()}}}]}])
    .to_string();
    let got = present(
        &h,
        &jag_with(&h, json!({})),
        ("authorization_details", &long),
    )
    .await;
    assert_error(
        &got,
        StatusCode::BAD_REQUEST,
        "invalid_scope",
        "one_of_too_long",
    );
    let got = present(
        &h,
        &jag_with(&h, json!({})),
        ("scope", &many[..1024].join(" ")),
    )
    .await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
}
