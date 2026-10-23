//! Actor authentication with an RFC 8693 `actor_token` (`[[actor_trust]]`): a fake SPIRE bundle
//! endpoint (ES256 JWT-SVID keys, `use` = `jwt-svid`) and a fake generic workload issuer
//! (EdDSA, plain JWKS), both on ephemeral ports, in front of the whole server.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{
    ActorAuth, ActorTrustConfig, AgentConfig, SubjectToAgent, DEFAULT_IDP_ALGS,
};
use attenuo_server::{AppState, Config};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const ADMIN: &str = "test-admin-token";
const TRUST_DOMAIN: &str = "example.org";
/// The `aud` actor tokens must carry.
const ACTOR_AUD: &str = "https://attenuo.test";
const WL_ISSUER: &str = "https://workload.test";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const CODER_ID: &str = "spiffe://example.org/ns/agents/sa/coder";

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// A signing key and its public JWK.
struct Key {
    alg: Algorithm,
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
}

impl Key {
    fn es256(kid: &str, usage: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref().to_vec();
        Self {
            alg: Algorithm::ES256,
            kid: kid.into(),
            encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
            // As a SPIRE bundle publishes it: no `alg`, `use` = `jwt-svid`.
            jwk: json!({
                "kty": "EC", "crv": "P-256", "use": usage, "kid": kid,
                "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&point[33..]),
            }),
        }
    }

    fn ed25519(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        Self {
            alg: Algorithm::EdDSA,
            kid: kid.into(),
            encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
            jwk: json!({
                "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid,
                "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            }),
        }
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(self.alg);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".into());
        jsonwebtoken::encode(&header, claims, &self.encoding).unwrap()
    }
}

/// Serves a SPIFFE bundle at `/bundle` and a plain JWKS at `/jwks`.
struct KeyServer {
    svid: Key,
    workload: Key,
    server: Spawned,
}

impl KeyServer {
    async fn start() -> Self {
        let svid = Key::es256("svid-1", "jwt-svid");
        // An X.509 root in the same bundle must be ignored for JWT verification.
        let x509 = Key::es256("x509-1", "x509-svid");
        let workload = Key::ed25519("wl-1");
        let bundle = json!({
            "spiffe_sequence": 7, "spiffe_refresh_hint": 300,
            "keys": [x509.jwk, svid.jwk],
        });
        let jwks = json!({ "keys": [workload.jwk] });
        let app = Router::new()
            .route(
                "/bundle",
                get(move || {
                    let b = bundle.clone();
                    async move { Json(b) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let j = jwks.clone();
                    async move { Json(j) }
                }),
            );
        Self {
            svid,
            workload,
            server: spawn_router(app).await.unwrap(),
        }
    }

    /// A JWT-SVID for `spiffe_id` (no `iss`, as SPIRE issues them by default).
    fn svid(&self, spiffe_id: &str) -> String {
        self.svid.sign(&self.svid_claims(spiffe_id))
    }

    fn svid_claims(&self, spiffe_id: &str) -> Value {
        json!({
            "sub": spiffe_id, "aud": [ACTOR_AUD], "exp": now() + 300, "iat": now(),
            "jti": uuid::Uuid::new_v4().to_string(),
        })
    }

    fn workload_token(&self, sub: &str) -> String {
        self.workload.sign(&json!({
            "iss": WL_ISSUER, "sub": sub, "aud": ACTOR_AUD, "exp": now() + 300, "iat": now(),
            "jti": uuid::Uuid::new_v4().to_string(),
        }))
    }
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

struct Harness {
    keys: KeyServer,
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
}

impl Harness {
    async fn start(tweak: impl FnOnce(&mut Config)) -> Self {
        let keys = KeyServer::start().await;
        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = vec![AgentConfig {
            id: "reviewer".into(),
            secret_sha256: sha256_hex("reviewer-secret"),
        }];
        cfg.actor_trust = vec![
            ActorTrustConfig {
                issuer: None,
                jwks_url: None,
                spiffe_trust_domain: Some(TRUST_DOMAIN.into()),
                spiffe_bundle_url: Some(keys.server.url("/bundle")),
                audience: ACTOR_AUD.into(),
                subject_to_agent: SubjectToAgent::Map(BTreeMap::from([
                    (CODER_ID.to_string(), "coder".to_string()),
                    (
                        "spiffe://example.org/ns/agents/sa/reviewer".to_string(),
                        "reviewer".to_string(),
                    ),
                ])),
                allowed_algs: vec!["ES256".into()],
                jwks_ttl_seconds: 300,
                clock_skew_seconds: 0,
            },
            ActorTrustConfig {
                issuer: Some(WL_ISSUER.into()),
                jwks_url: Some(keys.server.url("/jwks")),
                spiffe_trust_domain: None,
                spiffe_bundle_url: None,
                audience: ACTOR_AUD.into(),
                subject_to_agent: SubjectToAgent::Sub,
                allowed_algs: DEFAULT_IDP_ALGS.iter().map(|s| s.to_string()).collect(),
                jwks_ttl_seconds: 300,
                clock_skew_seconds: 0,
            },
        ];
        tweak(&mut cfg);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            keys,
            server: spawn_router(router).await.unwrap(),
            state,
            client: reqwest::Client::new(),
        }
    }

    async fn root(&self, body: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn root_token(&self) -> String {
        let v = self
            .root(json!({
                "subject": "alice", "issuer": "https://idp.example", "agent": "planner",
                "capabilities": ["github:*"],
            }))
            .await;
        v["access_token"].as_str().unwrap().to_owned()
    }

    /// Exchange `parent` for `actor`, with `extra` merged into the JSON body.
    async fn exchange(&self, parent: &str, actor: &str, extra: Value) -> (StatusCode, Value) {
        let mut body = json!({
            "grant_type": EXCHANGE,
            "subject_token": parent,
            "subject_token_type": JWT,
            "actor": actor,
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let resp = self
            .client
            .post(self.server.url("/token"))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn with_actor_token(
        &self,
        parent: &str,
        actor: &str,
        token: &str,
    ) -> (StatusCode, Value) {
        self.exchange(
            parent,
            actor,
            json!({"actor_token": token, "actor_token_type": JWT}),
        )
        .await
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

fn code(v: &Value) -> (&str, &str) {
    (
        v["error"].as_str().unwrap_or_default(),
        v["error_description"].as_str().unwrap_or_default(),
    )
}

#[tokio::test]
async fn spiffe_jwt_svid_authenticates_the_actor() {
    let h = Harness::start(|_| {}).await;
    let root = h.root_token().await;
    let (status, v) = h
        .with_actor_token(&root, "coder", &h.keys.svid(CODER_ID))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let child = h
        .state
        .verifier
        .verify(
            v["access_token"].as_str().unwrap(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    assert_eq!(child.claims.act.sub, "coder");

    // The issuance is audited under the authenticated agent.
    let entries = h.audit().await;
    let rec = entries
        .iter()
        .find(|e| e["record"]["tool"] == "token.exchange")
        .expect("exchange audited");
    assert_eq!(rec["record"]["agents"], json!(["planner", "coder"]));

    // A generic JWT issuer with a JWKS works the same way (`subject_to_agent = "sub"`).
    let (status, v) = h
        .with_actor_token(&root, "wl:reviewer", &h.keys.workload_token("wl:reviewer"))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn bad_actor_tokens_are_refused_with_stable_codes() {
    let h = Harness::start(|_| {}).await;
    let root = h.root_token().await;
    let svid_with = |patch: Value| {
        let mut c = h.keys.svid_claims(CODER_ID);
        for (k, v) in patch.as_object().unwrap() {
            if v.is_null() {
                c.as_object_mut().unwrap().remove(k);
            } else {
                c[k] = v.clone();
            }
        }
        h.keys.svid.sign(&c)
    };
    let cases = [
        // Names another agent than the token proves.
        ("reviewer", h.keys.svid(CODER_ID), "actor_mismatch"),
        (
            "coder",
            svid_with(json!({"aud": "someone-else"})),
            "actor_token_audience_mismatch",
        ),
        (
            "coder",
            svid_with(json!({"exp": now() - 10})),
            "actor_token_expired",
        ),
        (
            "coder",
            svid_with(json!({"exp": null})),
            "actor_token_missing_claim",
        ),
        (
            "coder",
            h.keys.svid("spiffe://example.org/ns/agents/sa/unknown"),
            "actor_token_unmapped_subject",
        ),
        // Another trust domain: no [[actor_trust]] entry vouches for it.
        (
            "coder",
            h.keys.svid("spiffe://evil.org/ns/agents/sa/coder"),
            "actor_token_untrusted_issuer",
        ),
        // Signed by a key that is not in the bundle (same kid).
        (
            "coder",
            Key::es256("svid-1", "jwt-svid").sign(&h.keys.svid_claims(CODER_ID)),
            "actor_token_bad_signature",
        ),
        // The X.509 key in the bundle does not verify JWTs.
        (
            "coder",
            Key::es256("x509-1", "x509-svid").sign(&h.keys.svid_claims(CODER_ID)),
            "actor_token_unknown_kid",
        ),
        ("coder", "not-a-jwt".to_string(), "actor_token_malformed"),
    ];
    for (actor, token, want) in cases {
        let (status, v) = h.with_actor_token(&root, actor, &token).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{want}: {v}");
        assert_eq!(code(&v), ("invalid_request", want), "{v}");
    }
    // A delegation token is not an actor token, even if someone trusted its issuer.
    let (status, v) = h.with_actor_token(&root, "coder", &root).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v).1, "actor_token_typ_mismatch", "{v}");
    // actor_token_type is required and must be the JWT URN.
    let (_, v) = h
        .exchange(
            &root,
            "coder",
            json!({"actor_token": h.keys.svid(CODER_ID)}),
        )
        .await;
    assert_eq!(code(&v).1, "malformed_request", "{v}");
    let (_, v) = h
        .exchange(
            &root,
            "coder",
            json!({"actor_token": h.keys.svid(CODER_ID),
                   "actor_token_type": "urn:ietf:params:oauth:token-type:access_token"}),
        )
        .await;
    assert_eq!(code(&v).1, "actor_token_type_unsupported", "{v}");
    // Nothing was issued.
    assert!(!h
        .audit()
        .await
        .iter()
        .any(|e| e["record"]["tool"] == "token.exchange"));
}

#[tokio::test]
async fn either_mode_keeps_client_secrets_working() {
    let h = Harness::start(|_| {}).await;
    let root = h.root_token().await;
    // Client secret alone.
    let (status, v) = h
        .exchange(
            &root,
            "reviewer",
            json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // Nothing at all is still 401 invalid_client.
    let (status, v) = h.exchange(&root, "coder", json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&v), ("invalid_client", "client_auth_missing"));
    // Both: both are checked, and both must name the actor.
    let svid = h.keys.svid("spiffe://example.org/ns/agents/sa/reviewer");
    let root2 = h.root_token().await;
    let (status, v) = h
        .exchange(
            &root2,
            "reviewer",
            json!({"actor_token": svid, "actor_token_type": JWT,
                   "client_id": "reviewer", "client_secret": "wrong"}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    let (status, v) = h
        .exchange(
            &root2,
            "reviewer",
            json!({"actor_token": h.keys.svid("spiffe://example.org/ns/agents/sa/reviewer"),
                   "actor_token_type": JWT,
                   "client_id": "reviewer", "client_secret": "reviewer-secret"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn actor_auth_secret_refuses_actor_tokens() {
    let h = Harness::start(|cfg| cfg.token.actor_auth = ActorAuth::Secret).await;
    let root = h.root_token().await;
    let (status, v) = h
        .with_actor_token(&root, "coder", &h.keys.svid(CODER_ID))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_request", "actor_token_not_accepted"));
}

#[tokio::test]
async fn actor_auth_actor_token_refuses_client_secrets() {
    let h = Harness::start(|cfg| cfg.token.actor_auth = ActorAuth::ActorToken).await;
    let root = h.root_token().await;
    let (status, v) = h
        .exchange(
            &root,
            "reviewer",
            json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_request", "client_auth_not_accepted"));
    let (status, v) = h.exchange(&root, "coder", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_request", "actor_token_required"));
    let (status, v) = h
        .with_actor_token(&root, "coder", &h.keys.svid(CODER_ID))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// With `require_actor_auth = false` an exchange without credentials still works, but an
/// actor token that is sent is still verified.
#[tokio::test]
async fn presented_actor_tokens_are_checked_even_when_not_required() {
    let h = Harness::start(|cfg| cfg.token.require_actor_auth = false).await;
    let root = h.root_token().await;
    let (status, _) = h.exchange(&root, "anyone", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let (status, v) = h
        .with_actor_token(&root, "coder", &h.keys.svid("spiffe://evil.org/a"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v).1, "actor_token_untrusted_issuer");
}

/// RFC 8693 form encoding carries the actor token like any other field.
#[tokio::test]
async fn actor_token_in_form_encoding() {
    let h = Harness::start(|_| {}).await;
    let root = h.root_token().await;
    let svid = h.keys.svid(CODER_ID);
    let body = serde_urlencoded::to_string([
        ("grant_type", EXCHANGE),
        ("subject_token", root.as_str()),
        ("subject_token_type", JWT),
        ("actor", "coder"),
        ("scope", "github:read_file"),
        ("actor_token", svid.as_str()),
        ("actor_token_type", JWT),
    ])
    .unwrap();
    let resp = h
        .client
        .post(h.server.url("/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// An actor token authenticates one exchange, and the child never outlives it.
#[tokio::test]
async fn actor_tokens_are_single_use_and_cap_the_child_ttl() {
    let h = Harness::start(|_| {}).await;
    let svid = h.keys.svid(CODER_ID);
    let (status, _) = h
        .with_actor_token(&h.root_token().await, "coder", &svid)
        .await;
    assert_eq!(status, StatusCode::OK);
    // Same token, another parent: refused.
    let (status, v) = h
        .with_actor_token(&h.root_token().await, "coder", &svid)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_grant", "replayed"), "{v}");

    // Without a jti the signed content is the key.
    let mut claims = h.keys.svid_claims(CODER_ID);
    claims.as_object_mut().unwrap().remove("jti");
    let no_jti = h.keys.svid.sign(&claims);
    let (status, _) = h
        .with_actor_token(&h.root_token().await, "coder", &no_jti)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, v) = h
        .with_actor_token(&h.root_token().await, "coder", &no_jti)
        .await;
    assert_eq!(code(&v).1, "replayed", "{v}");

    // A short-lived actor token caps the child's expiry (the parent lives 900 s).
    let exp = now() + 45;
    let mut claims = h.keys.svid_claims(CODER_ID);
    claims["exp"] = exp.into();
    let (status, v) = h
        .with_actor_token(&h.root_token().await, "coder", &h.keys.svid.sign(&claims))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let child = h
        .state
        .verifier
        .verify(
            v["access_token"].as_str().unwrap(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    assert_eq!(child.claims.exp, exp);
    assert!(v["expires_in"].as_u64().unwrap() <= 45, "{v}");
}

/// A refused exchange (say, too wide) does not use up the actor token.
#[tokio::test]
async fn refused_exchange_does_not_consume_the_actor_token() {
    let h = Harness::start(|_| {}).await;
    let root = h.root_token().await;
    let svid = h.keys.svid(CODER_ID);
    let (status, v) = h
        .exchange(
            &root,
            "coder",
            json!({"actor_token": svid, "actor_token_type": JWT,
                   "authorization_details": [{"type": "attenuo_capabilities",
                       "capabilities": [{"server": "gitlab", "tool": "read_file"}]}]}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    let (status, v) = h.with_actor_token(&root, "coder", &svid).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// SR-44 (security review pass 4): an exchange refused because the parent already delegated
/// to this actor does not use up the actor token either. The two are recorded together, as
/// at hop 0.
#[tokio::test]
async fn exchange_refused_as_a_replay_does_not_consume_the_actor_token_sr44() {
    let h = Harness::start(|_| {}).await;
    let root = h.root_token().await;
    let (status, v) = h
        .with_actor_token(&root, "coder", &h.keys.svid(CODER_ID))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // The same parent to the same actor again: refused as a replay of the parent...
    let fresh = h.keys.svid(CODER_ID);
    let (status, v) = h.with_actor_token(&root, "coder", &fresh).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v), ("invalid_grant", "replayed"), "{v}");
    // ...and the fresh actor token is still good for an exchange of another parent.
    let (status, v) = h
        .with_actor_token(&h.root_token().await, "coder", &fresh)
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// SR-45 (security review pass 4): the agent id `attenuo`, reserved for the server's own
/// audit records (SR-34), cannot receive a delegation, even when an `[[actor_trust]]` mapping
/// yields it.
#[tokio::test]
async fn an_actor_token_mapped_to_the_reserved_agent_id_is_refused_sr45() {
    let h = Harness::start(|cfg| {
        if let SubjectToAgent::Map(m) = &mut cfg.actor_trust[0].subject_to_agent {
            m.insert(
                "spiffe://example.org/ns/agents/sa/attenuo".into(),
                "attenuo".into(),
            );
        }
    })
    .await;
    let svid = h.keys.svid("spiffe://example.org/ns/agents/sa/attenuo");
    let (status, v) = h
        .with_actor_token(&h.root_token().await, "attenuo", &svid)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v), ("invalid_request", "reserved_agent"), "{v}");
}
