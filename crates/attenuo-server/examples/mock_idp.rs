//! A mock OpenID Connect identity provider for the IdP exchange demo
//! (`examples/idp-exchange-demo`). **For demonstration only**: it signs an ID token for one
//! fixed user for anyone who asks, with no login at all.
//!
//! ```sh
//! cargo run -p attenuo-server --example mock_idp -- --port 0
//! ```
//!
//! It binds `127.0.0.1` only, generates a fresh P-256 key at start, prints
//! `listening on http://127.0.0.1:<port>` once bound (that URL is the issuer), and serves:
//!
//! | Route | Answer |
//! |---|---|
//! | `GET /.well-known/openid-configuration` | OIDC discovery: `issuer` and `jwks_uri` |
//! | `GET /jwks` | the public key, `kid` `demo-key-1`, ES256 |
//! | `GET /demo/id-token` | a fresh ES256 ID token for the demo user, as `text/plain` |
//!
//! `/demo/id-token` is not an OIDC endpoint. It stands in for the browser login and the
//! authorization-code flow that a real application runs to obtain an ID token. Each call
//! returns a new token (new `jti`, `iat` now, `exp` five minutes later) for `sub`
//! `--subject` (default `alice`), `aud` `--client-id` (default `agent-platform`), `email`
//! `<subject>@example.com` and `amr` `["pwd", "mfa"]`.
//!
//! It lives here as an example, not a binary, so it is never part of a release build or the
//! container image.

use std::sync::Arc;

use axum::http::header;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

const KID: &str = "demo-key-1";
/// Lifetime of each ID token, in seconds.
const TTL: i64 = 300;

struct Idp {
    issuer: String,
    client_id: String,
    subject: String,
    jwk: Value,
    key: EncodingKey,
}

impl Idp {
    fn id_token(&self) -> anyhow::Result<String> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(KID.into());
        header.typ = Some("JWT".into());
        let claims = json!({
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": self.subject,
            "email": format!("{}@example.com", self.subject),
            "amr": ["pwd", "mfa"],
            "iat": now,
            "auth_time": now,
            "exp": now + TTL,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        Ok(jsonwebtoken::encode(&header, &claims, &self.key)?)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut port: u16 = 0;
    let mut client_id = "agent-platform".to_string();
    let mut subject = "alice".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))
        };
        match a.as_str() {
            "--port" => {
                port = value("--port")?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--port needs a number"))?
            }
            "--client-id" => client_id = value("--client-id")?,
            "--subject" => subject = value("--subject")?,
            other => anyhow::bail!(
                "unknown argument `{other}` (try --port N, --client-id ID, --subject SUB)"
            ),
        }
    }

    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| anyhow::anyhow!("cannot generate a P-256 key"))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| anyhow::anyhow!("cannot load the generated key"))?;
    // Uncompressed point: 0x04 || x || y.
    let point = pair.public_key().as_ref();
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": KID,
        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..]),
    });

    // Loopback only: this mints tokens for anyone who asks.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let issuer = format!("http://{}", listener.local_addr()?);
    let idp = Arc::new(Idp {
        issuer: issuer.clone(),
        client_id,
        subject,
        jwk,
        key: EncodingKey::from_ec_der(pkcs8.as_ref()),
    });

    let (discovery, keys, mint) = (idp.clone(), idp.clone(), idp);
    let router = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || async move {
                eprintln!("GET /.well-known/openid-configuration");
                Json(json!({
                    "issuer": discovery.issuer,
                    "jwks_uri": format!("{}/jwks", discovery.issuer),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["ES256"],
                }))
            }),
        )
        .route(
            "/jwks",
            get(move || async move {
                eprintln!("GET /jwks");
                Json(json!({ "keys": [keys.jwk] }))
            }),
        )
        .route(
            "/demo/id-token",
            get(move || async move {
                eprintln!("GET /demo/id-token (sub {})", mint.subject);
                match mint.id_token() {
                    Ok(t) => Ok(([(header::CONTENT_TYPE, "text/plain")], t)),
                    Err(e) => Err((
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("cannot sign: {e}"),
                    )),
                }
            }),
        );
    println!("listening on {issuer}");
    axum::serve(listener, router).await?;
    Ok(())
}
