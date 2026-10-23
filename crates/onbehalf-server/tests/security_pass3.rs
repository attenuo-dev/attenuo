//! Regression tests for findings of the 2026-10-23 security review, pass 3
//! (`docs/research/security-review-2026-10-23.md`).

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;

use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use onbehalf_proxy::testing::{spawn_router, Spawned};
use onbehalf_proxy::UpstreamConfig;
use onbehalf_server::config::{AgentConfig, CapSpec, IdpConfig, RootGrant};
use onbehalf_server::Config;
use reqwest::StatusCode;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const CLIENT_AUD: &str = "onbehalf-client";
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
    let mut cfg = Config::default();
    cfg.idps = vec![IdpConfig {
        issuer: idp.issuer.clone(),
        audience: CLIENT_AUD.into(),
        jwks_url: None,
        allowed_algs: vec!["ES256".into()],
        attribute_claims: vec![],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 60,
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
    }];
    let (router, _state) = onbehalf_server::build(&cfg).unwrap();
    spawn_router(router).await.unwrap()
}

async fn intake(server: &Spawned, id_token: &str) -> (StatusCode, Value) {
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
        .post(server.url("/token"))
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

/// SR-30: the release workflow holds `packages: write`, `id-token: write` (keyless signing)
/// and `contents: write`. Every action it runs must be pinned to a full commit SHA, so a moved
/// tag in a third-party action cannot publish or sign an image in this repository's name, and
/// the release build must not restore a cache other workflows can write.
#[test]
fn release_workflow_actions_are_pinned_to_commits() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/release.yml"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut seen = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some(spec) = line
            .strip_prefix("- uses:")
            .or_else(|| line.strip_prefix("uses:"))
        else {
            continue;
        };
        let spec = spec.trim();
        let (_, reference) = spec
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("`{spec}` has no ref"));
        assert!(
            reference.len() == 40 && reference.bytes().all(|b| b.is_ascii_hexdigit()),
            "`{spec}` is not pinned to a commit SHA"
        );
        seen += 1;
    }
    assert!(seen >= 10, "found only {seen} `uses:` lines");
    assert!(
        !text.contains("Swatinem/rust-cache"),
        "the release build must not restore a shared cargo cache"
    );
}

/// SR-34: an upstream named `onbehalf` wrote tool-call audit records under the server name the
/// server uses for its own events (`token.exchange`, `lease.renew`, `admin.*`).
#[test]
fn the_server_name_onbehalf_is_reserved() {
    let mut cfg = Config::default();
    cfg.upstreams = vec![UpstreamConfig::new("onbehalf", "http://127.0.0.1:9/mcp")];
    let err = cfg.check_server_names().unwrap_err().to_string();
    assert!(err.contains("reserved"), "{err}");
    cfg.upstreams = vec![UpstreamConfig::new("github", "http://127.0.0.1:9/mcp")];
    cfg.check_server_names().unwrap();
}
