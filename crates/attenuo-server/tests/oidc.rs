//! Hop-0 intake against a fake identity provider: an axum app on an ephemeral port serving OIDC
//! discovery and a JWKS with Ed25519 keys generated in the test, minting ID tokens and ID-JAGs.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::jsonrpc::CODE_DENIED;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::{AgentConfig, CapSpec, IdpConfig, RootGrant};
use attenuo_server::{AppState, Config};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

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

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
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
            client_ids: ["planner", "coder"]
                .map(|a| (a.to_string(), CLIENT_AUD.to_string()))
                .into(),
        }];
        cfg.agents = vec![
            AgentConfig {
                id: "planner".into(),
                secret_sha256: sha256_hex(PLANNER_SECRET),
            },
            AgentConfig {
                id: "coder".into(),
                secret_sha256: sha256_hex(CODER_SECRET),
            },
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
