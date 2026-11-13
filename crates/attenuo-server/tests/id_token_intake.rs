//! IdP intake of ID tokens: regression tests for SR-29 (ECDSA signature malleability and the
//! replay cache) and SR-37 (an ID token for one agent refused from another; the audience
//! check) from the 2026-10-23 security review, pass 3
//! (`docs/research/security-review-2026-10-23.md`). Formerly `security_pass3.rs`; its SR-30
//! and SR-34 tests are in `hardening.rs`.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{AgentConfig, CapSpec, IdpConfig, RootGrant};
use attenuo_server::Config;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const CLIENT_AUD: &str = "attenuo-client";
const PLANNER_SECRET: &str = "planner-secret";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// Order of the P-256 group, big-endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `a - b` for 32-byte big-endian integers with `a > b`.
fn sub_be(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = d as u8;
    }
    out
}

/// The same JWS with its ECDSA signature `(r, s)` replaced by `(r, n - s)`, which is also a
/// valid signature over the same message.
fn malleate_es256(jws: &str) -> String {
    let (input, sig) = jws.rsplit_once('.').unwrap();
    let raw = URL_SAFE_NO_PAD.decode(sig).unwrap();
    assert_eq!(raw.len(), 64);
    let mut out = raw[..32].to_vec();
    out.extend_from_slice(&sub_be(&P256_N, &raw[32..]));
    assert_ne!(out, raw);
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(out))
}

/// A fake IdP that publishes one ES256 key through OIDC discovery.
struct EcIdp {
    issuer: String,
    encoding: EncodingKey,
    _server: Spawned,
}

impl EcIdp {
    async fn start() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref().to_vec();
        assert_eq!(point.len(), 65, "uncompressed P-256 point");
        let jwk = json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "ec1",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..]),
        });
        // The issuer URL is only known once the listener is bound, so discovery reads it from
        // a cell filled in after spawning.
        let issuer_cell = std::sync::Arc::new(std::sync::OnceLock::<String>::new());
        let cell = issuer_cell.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let iss = cell.get().cloned().unwrap_or_default();
                    async move { Json(json!({ "issuer": iss, "jwks_uri": format!("{iss}/jwks") })) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let jwk = jwk.clone();
                    async move { Json(json!({ "keys": [jwk] })) }
                }),
            );
        let server = spawn_router(app).await.unwrap();
        let issuer = server.url("").trim_end_matches('/').to_string();
        issuer_cell.set(issuer.clone()).unwrap();
        Self {
            issuer,
            encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
            _server: server,
        }
    }

    /// An ID token for `sub` with no `jti`, as many IdPs issue them.
    fn id_token(&self, sub: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("ec1".into());
        header.typ = Some("JWT".into());
        let claims = json!({
            "iss": self.issuer, "aud": CLIENT_AUD, "sub": sub,
            "iat": now, "exp": now + 300, "amr": ["pwd"],
        });
        jsonwebtoken::encode(&header, &claims, &self.encoding).unwrap()
    }
}

async fn server_trusting(idp: &EcIdp) -> Spawned {
    let (router, _state) = attenuo_server::build(&config_trusting(idp)).unwrap();
    spawn_router(router).await.unwrap()
}

/// `planner` may present ID tokens of `idp` for `github:*`.
fn config_trusting(idp: &EcIdp) -> Config {
    let mut cfg = Config::default();
    cfg.idps = vec![IdpConfig {
        issuer: idp.issuer.clone(),
        audience: CLIENT_AUD.into(),
        jwks_url: None,
        allowed_algs: vec!["ES256".into()],
        attribute_claims: vec![],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 60,
        tenant: None,
        client_ids: BTreeMap::from([("planner".to_string(), CLIENT_AUD.to_string())]),
    }];
    cfg.agents = vec![AgentConfig {
        id: "planner".into(),
        secret_sha256: hex::encode(Sha256::digest(PLANNER_SECRET.as_bytes())),
    }];
    cfg.root_grants = vec![RootGrant {
        subject: None,
        issuer: idp.issuer.clone(),
        agent: "planner".into(),
        capabilities: vec![CapSpec::Short("github:*".into())],
        attributes: BTreeMap::new(),
        may_act: None,
    }];
    cfg
}

async fn intake(server: &Spawned, id_token: &str) -> (StatusCode, Value) {
    intake_at(&server.url("/token"), id_token).await
}

async fn intake_at(token_url: &str, id_token: &str) -> (StatusCode, Value) {
    let body = serde_urlencoded::to_string([
        ("grant_type", EXCHANGE),
        ("subject_token", id_token),
        ("subject_token_type", ID_TOKEN),
        ("client_id", "planner"),
        ("client_secret", PLANNER_SECRET),
        ("scope", "github:read_file"),
    ])
    .unwrap();
    let resp = reqwest::Client::new()
        .post(token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// SR-29: an ID token without `jti` was keyed in the replay cache by the SHA-256 of the whole
/// JWS. ECDSA signatures are malleable (`s` and `n - s` both verify), so re-encoding the
/// signature produced a "new" credential that minted a second root token from one login.
#[tokio::test]
async fn ecdsa_signature_malleability_does_not_bypass_the_replay_cache() {
    let idp = EcIdp::start().await;
    let server = server_trusting(&idp).await;
    let token = idp.id_token("alice");

    let (status, body) = intake(&server, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = intake(&server, &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error_description"], "replayed");

    // The malleated signature still verifies at the IdP's key...
    let twin = malleate_es256(&token);
    assert_ne!(twin, token);
    // ...but it is the same credential, so it is refused as a replay.
    let (status, body) = intake(&server, &twin).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error_description"], "replayed", "{body}");
}

impl EcIdp {
    /// An ID token with explicit `aud` (and `azp` when given); `n` makes tokens distinct.
    fn id_token_aud(&self, sub: &str, aud: Value, azp: Option<&str>, n: u32) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("ec1".into());
        let mut claims = json!({
            "iss": self.issuer, "aud": aud, "sub": sub,
            "iat": now, "exp": now + 300, "jti": format!("t{n}"),
        });
        if let Some(azp) = azp {
            claims["azp"] = json!(azp);
        }
        jsonwebtoken::encode(&header, &claims, &self.encoding).unwrap()
    }
}

/// `planner` is registered at the IdP as `planner-app`, `coder` as `coder-app`, and `reviewer`
/// has no `client_ids` entry (so its client id must be `reviewer`).
async fn server_with_two_clients(idp: &EcIdp) -> Spawned {
    let mut cfg = Config::default();
    cfg.idps = vec![IdpConfig {
        issuer: idp.issuer.clone(),
        audience: String::new(),
        jwks_url: None,
        allowed_algs: vec!["ES256".into()],
        attribute_claims: vec![],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 60,
        tenant: None,
        client_ids: BTreeMap::from([
            ("planner".to_string(), "planner-app".to_string()),
            ("coder".to_string(), "coder-app".to_string()),
        ]),
    }];
    let secret = |id: &str| hex::encode(Sha256::digest(format!("{id}-secret").as_bytes()));
    cfg.agents = ["planner", "coder", "reviewer"]
        .iter()
        .map(|id| AgentConfig {
            id: (*id).into(),
            secret_sha256: secret(id),
        })
        .collect();
    cfg.root_grants = ["planner", "coder", "reviewer"]
        .iter()
        .map(|id| RootGrant {
            subject: None,
            issuer: idp.issuer.clone(),
            agent: (*id).into(),
            capabilities: vec![CapSpec::Short("github:*".into())],
            attributes: BTreeMap::new(),
            may_act: None,
        })
        .collect();
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    spawn_router(router).await.unwrap()
}

async fn intake_as(server: &Spawned, agent: &str, id_token: &str) -> (StatusCode, Value) {
    let secret = format!("{agent}-secret");
    let body = serde_urlencoded::to_string([
        ("grant_type", EXCHANGE),
        ("subject_token", id_token),
        ("subject_token_type", ID_TOKEN),
        ("client_id", agent),
        ("client_secret", secret.as_str()),
        ("scope", "github:read_file"),
    ])
    .unwrap();
    let resp = reqwest::Client::new()
        .post(server.url("/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// SR-37: an ID token was accepted from any agent with a root grant, because `aud` was the
/// IdP-wide audience. It must now name the presenting agent's client id.
#[tokio::test]
async fn id_token_for_one_agent_is_refused_from_another() {
    let idp = EcIdp::start().await;
    let server = server_with_two_clients(&idp).await;

    // Alice logged in through planner's front end. Coder gets hold of the token.
    let for_planner = idp.id_token_aud("alice", json!(["planner-app"]), Some("planner-app"), 1);
    let (status, body) = intake_as(&server, "coder", &for_planner).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error_description"], "credential_audience_mismatch",
        "{body}"
    );
    // The refusal does not burn the token: planner can still redeem it.
    let (status, body) = intake_as(&server, "planner", &for_planner).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The old shared audience no longer works for an agent with its own client id.
    let shared = idp.id_token_aud("alice", json!(CLIENT_AUD), None, 2);
    let (status, body) = intake_as(&server, "planner", &shared).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error_description"], "credential_audience_mismatch",
        "{body}"
    );

    // Several audiences need an `azp` that names the presenter.
    for (n, azp) in [(3, None), (4, Some("coder-app"))] {
        let t = idp.id_token_aud("alice", json!(["planner-app", "coder-app"]), azp, n);
        let (status, body) = intake_as(&server, "planner", &t).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body["error_description"], "credential_audience_mismatch",
            "{body}"
        );
    }
}

/// With no `client_ids` entry the agent id itself is the client id.
#[tokio::test]
async fn without_client_ids_the_agent_id_is_the_default_audience() {
    let idp = EcIdp::start().await;
    let server = server_with_two_clients(&idp).await;
    let both = json!(["reviewer", "other"]);
    let t = idp.id_token_aud("alice", both.clone(), Some("reviewer"), 1);
    let (status, body) = intake_as(&server, "reviewer", &t).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The token whose aud only names the shared audience is refused.
    let t = idp.id_token_aud("alice", json!(CLIENT_AUD), None, 2);
    let (status, body) = intake_as(&server, "reviewer", &t).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error_description"], "credential_audience_mismatch",
        "{body}"
    );
}

/// The server's config of [`config_trusting`] on a database file in `dir`.
fn config_on_file(idp: &EcIdp, dir: &tempfile::TempDir) -> Config {
    let mut cfg = config_trusting(idp);
    cfg.audit.sqlite_path = dir
        .path()
        .join("attenuo.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg
}

async fn start_on(cfg: &Config) -> (common::Running, Arc<attenuo_server::AppState>) {
    let (router, state) = attenuo_server::build(cfg).unwrap();
    (
        common::Running::start(cfg.clone(), state.clone(), router).await,
        state,
    )
}

/// How many single-use markers the database file holds.
fn markers(state: &attenuo_server::AppState) -> i64 {
    state
        .leases
        .with_connection(|c| {
            Ok(c.query_row("SELECT COUNT(*) FROM used_credentials", [], |r| r.get(0))?)
        })
        .unwrap()
}

/// Hop-0 hardening: an ID token redeemed before a restart is still redeemed after it, on the
/// same database file, both when it is keyed by (`iss`, `jti`) and when it has no `jti` and is
/// keyed by its digest. Before, the replay cache was in memory and a restart forgot it, so the
/// same login minted a second root token until it expired. A fresh token still works.
#[tokio::test]
async fn an_id_token_redeemed_before_a_restart_is_refused_after_it() {
    let idp = EcIdp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_on_file(&idp, &dir);
    let without_jti = idp.id_token("alice");
    let with_jti = idp.id_token_aud("alice", json!(CLIENT_AUD), None, 1);

    let (server, state) = start_on(&cfg).await;
    for token in [&without_jti, &with_jti] {
        let (status, body) = intake_at(&server.url("/token"), token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(markers(&state), 2);
    server.stop(state).await;

    let (server, state) = start_on(&cfg).await;
    assert_eq!(markers(&state), 2, "the markers are in the file");
    for token in [&without_jti, &with_jti] {
        let (status, body) = intake_at(&server.url("/token"), token).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant", "{body}");
        assert_eq!(body["error_description"], "replayed", "{body}");
    }
    let fresh = idp.id_token_aud("alice", json!(CLIENT_AUD), None, 2);
    let (status, body) = intake_at(&server.url("/token"), &fresh).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    server.stop(state).await;
}

/// Several redemptions of one ID token at the same moment, on the file store: exactly one
/// mints a root token, every other one is a replay.
#[tokio::test]
async fn simultaneous_redemptions_of_one_id_token_mint_one_root_token() {
    let idp = EcIdp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_on_file(&idp, &dir);
    let (server, state) = start_on(&cfg).await;
    let url = server.url("/token");
    for round in 0..3 {
        let token = idp.id_token_aud("alice", json!(CLIENT_AUD), None, 100 + round);
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let (url, token) = (url.clone(), token.clone());
                tokio::spawn(async move { intake_at(&url, &token).await })
            })
            .collect();
        let mut ok = 0;
        for t in tasks {
            let (status, body) = t.await.unwrap();
            if status == StatusCode::OK {
                ok += 1;
            } else {
                assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                assert_eq!(body["error_description"], "replayed", "{body}");
            }
        }
        assert_eq!(ok, 1, "round {round}");
    }
    server.stop(state).await;
}

/// A marker that cannot be written refuses the redemption: 503 `temporarily_unavailable`,
/// `replay_store_unavailable`, and no token.
#[tokio::test]
async fn an_id_token_whose_use_cannot_be_recorded_is_refused() {
    let idp = EcIdp::start().await;
    let (router, state) = attenuo_server::build(&config_trusting(&idp)).unwrap();
    let server = spawn_router(router).await.unwrap();
    state
        .leases
        .with_connection(|c| Ok(c.execute_batch("DROP TABLE used_credentials")?))
        .unwrap();
    let (status, body) = intake(&server, &idp.id_token("alice")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "temporarily_unavailable", "{body}");
    assert_eq!(body["error_description"], "replay_store_unavailable", "{body}");
    assert!(body.get("access_token").is_none(), "{body}");
}
