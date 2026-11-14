//! Hop 0 with an RFC 8693 `actor_token`: the agent presenting a user's ID token authenticates
//! with a workload identity (a SPIFFE JWT-SVID from an `[[actor_trust]]` entry) instead of
//! `[[agents]]` client credentials. A fake IdP (EdDSA JWKS) and a fake SPIRE bundle endpoint
//! (ES256, `use` = `jwt-svid`) run on one ephemeral port in front of the whole server.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{
    ActorAuth, ActorTrustConfig, AgentConfig, CapSpec, IdpConfig, RootGrant, SubjectToAgent,
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
use time::OffsetDateTime;

use common::sha256_hex;

const ADMIN: &str = "test-admin-token";
const ISSUER: &str = "https://attenuo.test";
const IDP: &str = "https://idp.test";
const TRUST_DOMAIN: &str = "example.org";
const PLANNER_ID: &str = "spiffe://example.org/ns/agents/sa/planner";
const CODER_ID: &str = "spiffe://example.org/ns/agents/sa/coder";
const PLANNER_SECRET: &str = "planner-secret";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

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
    fn es256(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref().to_vec();
        Self {
            alg: Algorithm::ES256,
            kid: kid.into(),
            encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
            jwk: json!({
                "kty": "EC", "crv": "P-256", "use": "jwt-svid", "kid": kid,
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

struct Harness {
    idp: Key,
    svid: Key,
    _keys: Spawned,
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
}

impl Harness {
    async fn start(tweak: impl FnOnce(&mut Config)) -> Self {
        let idp = Key::ed25519("idp-1");
        let svid = Key::es256("svid-1");
        let idp_jwks = json!({ "keys": [idp.jwk] });
        let bundle = json!({ "spiffe_sequence": 1, "keys": [svid.jwk] });
        let app = Router::new()
            .route(
                "/idp/jwks",
                get(move || {
                    let j = idp_jwks.clone();
                    async move { Json(j) }
                }),
            )
            .route(
                "/bundle",
                get(move || {
                    let b = bundle.clone();
                    async move { Json(b) }
                }),
            );
        let keys = spawn_router(app).await.unwrap();

        let mut cfg = Config::default();
        cfg.issuer.issuer = ISSUER.into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.admin.token = Some(ADMIN.into());
        cfg.idps = vec![IdpConfig {
            issuer: IDP.into(),
            audience: String::new(),
            jwks_url: Some(keys.url("/idp/jwks")),
            allowed_algs: vec!["EdDSA".into()],
            attribute_claims: vec![],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
            tenant: None,
            ca_pem_path: None,
            client_ids: BTreeMap::new(),
        }];
        cfg.agents = vec![AgentConfig::with_secret_sha256(
            "planner",
            sha256_hex(PLANNER_SECRET),
        )];
        cfg.actor_trust = vec![ActorTrustConfig {
            issuer: None,
            jwks_url: None,
            spiffe_trust_domain: Some(TRUST_DOMAIN.into()),
            spiffe_bundle_url: Some(keys.url("/bundle")),
            ca_pem_path: None,
            audience: ISSUER.into(),
            subject_to_agent: SubjectToAgent::Map(BTreeMap::from([
                (PLANNER_ID.to_string(), "planner".to_string()),
                (CODER_ID.to_string(), "coder".to_string()),
            ])),
            allowed_algs: vec!["ES256".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 0,
        }];
        cfg.root_grants = vec![RootGrant {
            subject: None,
            issuer: IDP.into(),
            agent: "planner".into(),
            capabilities: vec![CapSpec::Short("github:*".into())],
            attributes: BTreeMap::new(),
            may_act: None,
        }];
        tweak(&mut cfg);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            idp,
            svid,
            _keys: keys,
            server: spawn_router(router).await.unwrap(),
            state,
            client: reqwest::Client::new(),
        }
    }

    /// An ID token for `sub`, issued to the client `aud` (the agent id by default).
    fn id_token(&self, sub: &str, aud: &str) -> String {
        self.idp.sign(&json!({
            "iss": IDP, "aud": aud, "sub": sub, "iat": now(), "exp": now() + 300,
            "auth_time": now() - 30, "jti": uuid::Uuid::new_v4().to_string(),
        }))
    }

    fn svid_claims(&self, spiffe_id: &str) -> Value {
        json!({
            "sub": spiffe_id, "aud": [ISSUER], "exp": now() + 300, "iat": now(),
            "jti": uuid::Uuid::new_v4().to_string(),
        })
    }

    fn jwt_svid(&self, spiffe_id: &str) -> String {
        self.svid.sign(&self.svid_claims(spiffe_id))
    }

    /// POST a form to `/token`.
    async fn post(&self, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.server.url("/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(pairs).unwrap())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// Hop 0 for `id_token`, authenticated by `actor_token`, with `extra` form fields.
    async fn intake(
        &self,
        id_token: &str,
        actor_token: &str,
        extra: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut pairs = vec![
            ("grant_type", EXCHANGE),
            ("subject_token", id_token),
            ("subject_token_type", ID_TOKEN),
            ("scope", "github:read_file"),
            ("actor_token", actor_token),
            ("actor_token_type", JWT),
        ];
        pairs.extend_from_slice(extra);
        self.post(&pairs).await
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

    fn roots_issued(entries: &[Value]) -> usize {
        entries
            .iter()
            .filter(|e| e["record"]["tool"] == "token.root")
            .count()
    }
}

fn code(v: &Value) -> (&str, &str) {
    (
        v["error"].as_str().unwrap_or_default(),
        v["error_description"].as_str().unwrap_or_default(),
    )
}

/// The whole chain without a single shared secret: hop 0 with the planner's JWT-SVID, hop 1
/// with the coder's.
#[tokio::test]
async fn jwt_svid_authenticates_the_agent_at_hop_0() {
    let h = Harness::start(|_| {}).await;
    let (status, v) = h
        .intake(
            &h.id_token("alice", "planner"),
            &h.jwt_svid(PLANNER_ID),
            &[("actor", "planner")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let root = v["access_token"].as_str().unwrap().to_owned();
    let verified = h
        .state
        .verifier
        .verify(&root, OffsetDateTime::now_utc())
        .unwrap();
    assert_eq!(verified.chain.hops[0].agent.0, "planner");
    assert_eq!(verified.chain.originating_user.subject, "alice");

    // `client_id` may name the agent instead of `actor`; no secret is needed.
    let (status, v) = h
        .intake(
            &h.id_token("alice", "planner"),
            &h.jwt_svid(PLANNER_ID),
            &[("client_id", "planner")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let (status, v) = h
        .post(&[
            ("grant_type", EXCHANGE),
            ("subject_token", &root),
            ("subject_token_type", JWT),
            ("actor", "coder"),
            ("scope", "github:read_file"),
            ("actor_token", &h.jwt_svid(CODER_ID)),
            ("actor_token_type", JWT),
        ])
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let entries = h.audit().await;
    let roots: Vec<&Value> = entries
        .iter()
        .filter(|e| e["record"]["tool"] == "token.root")
        .collect();
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0]["record"]["agents"], json!(["planner"]));
    assert_eq!(roots[0]["record"]["originating_subject"], "alice");
}

#[tokio::test]
async fn hop_0_actor_token_must_name_the_requested_agent_and_a_root_grant() {
    let h = Harness::start(|_| {}).await;
    let id_token = h.id_token("alice", "planner");
    // The SVID proves `coder`; the request names `planner`.
    for extra in [[("actor", "planner")], [("client_id", "planner")]] {
        let (status, v) = h.intake(&id_token, &h.jwt_svid(CODER_ID), &extra).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
        assert_eq!(code(&v), ("invalid_request", "actor_mismatch"), "{v}");
    }
    // `coder` authenticated, but no [[root_grants]] entry lets it act for users of the IdP.
    let (status, v) = h
        .intake(&h.id_token("alice", "coder"), &h.jwt_svid(CODER_ID), &[])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v), ("invalid_scope", "no_root_grant"), "{v}");
    // The ID token must have been issued to the authenticated agent's client.
    let (status, v) = h
        .intake(&h.id_token("alice", "coder"), &h.jwt_svid(PLANNER_ID), &[])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(code(&v).0, "invalid_grant", "{v}");
    // Untrusted, unmapped or malformed actor tokens are refused with the exchange's codes.
    let cases = [
        (
            h.jwt_svid("spiffe://evil.org/ns/agents/sa/planner"),
            "actor_token_untrusted_issuer",
        ),
        (
            h.jwt_svid("spiffe://example.org/ns/agents/sa/unknown"),
            "actor_token_unmapped_subject",
        ),
        ("not-a-jwt".into(), "actor_token_malformed"),
    ];
    for (token, want) in cases {
        let (status, v) = h.intake(&id_token, &token, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{want}: {v}");
        assert_eq!(code(&v), ("invalid_request", want), "{v}");
    }
    // The type is required, and must be the JWT URN.
    let (_, v) = h
        .post(&[
            ("grant_type", EXCHANGE),
            ("subject_token", &id_token),
            ("subject_token_type", ID_TOKEN),
            ("scope", "github:read_file"),
            ("actor_token", &h.jwt_svid(PLANNER_ID)),
        ])
        .await;
    assert_eq!(code(&v).1, "malformed_request", "{v}");
    assert_eq!(Harness::roots_issued(&h.audit().await), 0);
    // None of the refusals used up the ID token.
    let (status, v) = h.intake(&id_token, &h.jwt_svid(PLANNER_ID), &[]).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// The actor token is used once (across hop 0 and exchanges), and the root token never
/// outlives it.
#[tokio::test]
async fn hop_0_actor_tokens_are_single_use_and_cap_the_root_ttl() {
    // `coder` may also start chains here, so its SVID can be spent at hop 0.
    let h = Harness::start(|cfg| {
        let mut coder = cfg.root_grants[0].clone();
        coder.agent = "coder".into();
        cfg.root_grants.push(coder);
    })
    .await;
    let svid = h.jwt_svid(PLANNER_ID);
    let (status, v) = h.intake(&h.id_token("alice", "planner"), &svid, &[]).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let root = v["access_token"].as_str().unwrap().to_owned();

    // Same actor token, fresh ID token: refused, and the ID token is not used up.
    let fresh = h.id_token("alice", "planner");
    let (status, v) = h.intake(&fresh, &svid, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_grant", "replayed"), "{v}");
    let (status, v) = h.intake(&fresh, &h.jwt_svid(PLANNER_ID), &[]).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // An actor token spent at hop 0 cannot authenticate an exchange either.
    let coder_svid = h.jwt_svid(CODER_ID);
    let (status, v) = h
        .intake(&h.id_token("bob", "coder"), &coder_svid, &[])
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = h
        .post(&[
            ("grant_type", EXCHANGE),
            ("subject_token", &root),
            ("subject_token_type", JWT),
            ("actor", "coder"),
            ("scope", "github:read_file"),
            ("actor_token", &coder_svid),
            ("actor_token_type", JWT),
        ])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_grant", "replayed"), "{v}");

    // A short-lived actor token caps the root's expiry (the ID token lives 300 s).
    let exp = now() + 45;
    let mut claims = h.svid_claims(PLANNER_ID);
    claims["exp"] = exp.into();
    let (status, v) = h
        .intake(
            &h.id_token("alice", "planner"),
            &h.svid.sign(&claims),
            &[("requested_ttl_seconds", "3600")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["expires_in"].as_u64().unwrap() <= 45, "{v}");
    let chain = h
        .state
        .verifier
        .verify(
            v["access_token"].as_str().unwrap(),
            OffsetDateTime::now_utc(),
        )
        .unwrap()
        .chain;
    assert_eq!(chain.hops[0].expires_at.unix_timestamp(), exp);

    // Without a jti the signed content is the key.
    let mut claims = h.svid_claims(PLANNER_ID);
    claims.as_object_mut().unwrap().remove("jti");
    let no_jti = h.svid.sign(&claims);
    let (status, _) = h
        .intake(&h.id_token("alice", "planner"), &no_jti, &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, v) = h
        .intake(&h.id_token("alice", "planner"), &no_jti, &[])
        .await;
    assert_eq!(code(&v).1, "replayed", "{v}");
}

#[tokio::test]
async fn hop_0_follows_actor_auth_modes() {
    // "secret": actor tokens are refused at hop 0 as at exchanges.
    let h = Harness::start(|cfg| cfg.token.actor_auth = ActorAuth::Secret).await;
    let (status, v) = h
        .intake(
            &h.id_token("alice", "planner"),
            &h.jwt_svid(PLANNER_ID),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_request", "actor_token_not_accepted"));

    // "actor_token": client credentials are refused, and an actor token is required.
    let h = Harness::start(|cfg| cfg.token.actor_auth = ActorAuth::ActorToken).await;
    let id_token = h.id_token("alice", "planner");
    let secret_only = [
        ("grant_type", EXCHANGE),
        ("subject_token", id_token.as_str()),
        ("subject_token_type", ID_TOKEN),
        ("scope", "github:read_file"),
        ("client_id", "planner"),
        ("client_secret", PLANNER_SECRET),
    ];
    let (status, v) = h.post(&secret_only).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&v), ("invalid_request", "client_auth_not_accepted"));
    let (status, v) = h.post(&secret_only[..4]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&v), ("invalid_client", "actor_token_required"));
    let (status, v) = h.intake(&id_token, &h.jwt_svid(PLANNER_ID), &[]).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // "either" (default): both are checked when both are sent.
    let h = Harness::start(|_| {}).await;
    let (status, v) = h
        .intake(
            &h.id_token("alice", "planner"),
            &h.jwt_svid(PLANNER_ID),
            &[("client_id", "planner"), ("client_secret", "wrong")],
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    let (status, v) = h
        .intake(
            &h.id_token("alice", "planner"),
            &h.jwt_svid(PLANNER_ID),
            &[("client_id", "planner"), ("client_secret", PLANNER_SECRET)],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // Neither: 401 as before.
    let (status, v) = h.post(&secret_only[..4]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(code(&v), ("invalid_client", "client_auth_missing"));
}

/// Hop 0 with no credential at all (no secret, no assertion, no actor token) is 401
/// `invalid_client` in every `[token] actor_auth` mode, for an ID token and for an ID-JAG
/// (draft -06 §4.4), and the answer is the same whether `client_id` names a configured agent
/// or not (SR-110).
#[tokio::test]
async fn intake_without_any_credential_is_invalid_client_in_every_mode() {
    for (mode, expected) in [
        (ActorAuth::Either, "client_auth_missing"),
        (ActorAuth::Secret, "client_auth_missing"),
        (ActorAuth::ActorToken, "actor_token_required"),
    ] {
        let h = Harness::start(|cfg| cfg.token.actor_auth = mode).await;
        let id_token = h.id_token("alice", "planner");
        let by_id_token = vec![
            ("grant_type", EXCHANGE),
            ("subject_token", id_token.as_str()),
            ("subject_token_type", ID_TOKEN),
            ("scope", "github:read_file"),
        ];
        // The ID-JAG is not looked at before the agent authenticates, so any string will do.
        let by_id_jag = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", "eyJhbGciOiJSUzI1NiJ9.e30.c2ln"),
            ("scope", "github:read_file"),
        ];
        for base in [by_id_token, by_id_jag] {
            let mut answers = Vec::new();
            for client_id in [None, Some("planner"), Some("nobody")] {
                let mut pairs = base.clone();
                if let Some(id) = client_id {
                    pairs.push(("client_id", id));
                }
                let resp = h
                    .client
                    .post(h.server.url("/token"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(serde_urlencoded::to_string(&pairs).unwrap())
                    .send()
                    .await
                    .unwrap();
                let status = resp.status();
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .map(|v| v.to_str().unwrap().to_owned());
                let v: Value = resp.json().await.unwrap();
                assert_eq!(
                    status,
                    StatusCode::UNAUTHORIZED,
                    "{mode:?} {client_id:?}: {v}"
                );
                assert_eq!(
                    code(&v),
                    ("invalid_client", expected),
                    "{mode:?} {client_id:?}"
                );
                assert!(challenge.is_some(), "{mode:?}: no WWW-Authenticate");
                answers.push((status, challenge, v));
            }
            assert_eq!(
                answers[1], answers[2],
                "{mode:?}: known and unknown client_id differ"
            );
        }
    }
}
