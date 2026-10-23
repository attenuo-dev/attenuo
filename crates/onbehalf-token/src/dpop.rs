//! Sender-constrained tokens: DPoP proofs (RFC 9449) and key confirmation (`cnf.jkt`).
//!
//! A delegation token may carry `cnf: {"jkt": "<thumbprint>"}`, the RFC 7638 JWK SHA-256
//! thumbprint of a key its holder controls. Whoever presents such a token must also send a
//! DPoP proof: a small JWT signed by that key, naming the HTTP method (`htm`) and URL (`htu`)
//! of the request, when it was made (`iat`), a unique id (`jti`) and the hash of the token
//! (`ath`). A token copied out of a log or a compromised process is then useless without the
//! private key.
//!
//! This module holds the parts that need no server state:
//!
//! - [`verify_proof`]: check a proof's header (`typ` = `dpop+jwt`, an `alg` from
//!   [`DPOP_ALGS`], a public `jwk` that matches `alg`), signature, `htm`, `htu` (compared with
//!   [`normalize_htu`]: scheme, host, port and path, without query or fragment), `iat` within
//!   a window, and `ath` when the request presents a bound token. Replay of `jti` is the
//!   caller's business (it needs a cache shared by requests); [`VerifiedProof::replay_key`]
//!   gives the key to use.
//! - [`jwk_thumbprint`] and [`access_token_hash`]: the two hashes the scheme is built on.
//! - [`DpopKey`]: a private key that makes proofs, for clients (the CLI) and tests. It
//!   generates Ed25519 keys and loads Ed25519 or P-256 private JWKs.
//!
//! Two signature algorithms are accepted: `EdDSA` (Ed25519, what the issuer itself signs
//! with, and what `onbehalf key gen --dpop` makes) and `ES256` (P-256, what browsers'
//! WebCrypto supports everywhere).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ED25519,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// `typ` header of a DPoP proof (RFC 9449 §4.2).
pub const DPOP_PROOF_TYPE: &str = "dpop+jwt";

/// Signature algorithms accepted in DPoP proofs, as advertised in `WWW-Authenticate: DPoP
/// algs="..."`.
pub const DPOP_ALGS: &[&str] = &["EdDSA", "ES256"];

/// Largest proof accepted, in bytes. A proof is a header with one public key and five short
/// claims; anything near this size is not one.
pub const MAX_PROOF_BYTES: usize = 4096;

/// Longest `jti` accepted, in bytes.
pub const MAX_JTI_BYTES: usize = 256;

/// The `cnf` (confirmation) claim of a sender-constrained token (RFC 7800, RFC 9449 §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// RFC 7638 SHA-256 thumbprint of the holder's public key, base64url without padding.
    pub jkt: String,
}

impl Confirmation {
    /// Bind to the key with this thumbprint.
    pub fn jkt(jkt: impl Into<String>) -> Self {
        Self { jkt: jkt.into() }
    }

    /// Is `jkt` a well-formed SHA-256 thumbprint (43 base64url characters)?
    pub fn is_well_formed(&self) -> bool {
        URL_SAFE_NO_PAD
            .decode(&self.jkt)
            .is_ok_and(|raw| raw.len() == 32)
    }
}

/// Why a DPoP proof was refused. The `Display` text is safe to return to the client: it
/// describes the client's own proof, not anything about the server's keys.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DpopError {
    /// Not a compact JWS, or a part is not base64url JSON of the expected shape.
    #[error("malformed DPoP proof: {0}")]
    Malformed(String),
    /// `typ` is not `dpop+jwt`.
    #[error("DPoP proof typ must be `dpop+jwt`")]
    WrongType,
    /// `alg` is not one of [`DPOP_ALGS`], or does not match the `jwk`.
    #[error("DPoP proof alg `{0}` is not supported (use EdDSA or ES256)")]
    UnsupportedAlg(String),
    /// The header `jwk` is missing, not a supported public key, or carries private members.
    #[error("DPoP proof jwk is invalid: {0}")]
    BadKey(String),
    /// The signature does not verify under the header `jwk`.
    #[error("DPoP proof signature does not verify")]
    BadSignature,
    /// `htm` is not the request method.
    #[error("DPoP proof htm does not match the request method")]
    MethodMismatch,
    /// `htu` is not the request URL (scheme, host, port and path).
    #[error("DPoP proof htu does not match the request URL")]
    UrlMismatch,
    /// `iat` is outside the accepted window around the server's clock.
    #[error("DPoP proof iat is outside the accepted window")]
    Stale,
    /// The request presents a bound token and the proof has no `ath`, or a wrong one.
    #[error("DPoP proof ath does not match the presented token")]
    AthMismatch,
    /// The proof was signed by another key than the one the token is bound to.
    #[error("DPoP proof key does not match the token's cnf.jkt")]
    KeyMismatch,
    /// This proof was already used.
    #[error("DPoP proof jti was already used")]
    Replayed,
}

/// What a request must look like for a proof to be accepted ([`verify_proof`]).
#[derive(Debug, Clone, Copy)]
pub struct ProofCheck<'a> {
    /// The request method, compared exactly with `htm` (`POST`, `GET`, ...).
    pub method: &'a str,
    /// The request URL as the server sees it; compared with `htu` after [`normalize_htu`].
    pub url: &'a str,
    /// The token presented with the request, when it is sender-constrained: `ath` must be its
    /// [`access_token_hash`]. `None` when no bound token is presented (an exchange that binds a
    /// new token); `ath` is then not checked.
    pub access_token: Option<&'a str>,
    /// The server's clock.
    pub now: OffsetDateTime,
    /// How far `iat` may be from `now`, either way.
    pub max_age: Duration,
}

/// A proof that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// Thumbprint of the key that signed the proof.
    pub jkt: String,
    /// The proof's `jti`.
    pub jti: String,
    /// The proof's `iat`, seconds since the Unix epoch.
    pub iat: i64,
    /// The proof's `ath`, if it has one.
    pub ath: Option<String>,
}

impl VerifiedProof {
    /// Does `ath` hash `token`?
    pub fn covers(&self, token: &str) -> bool {
        self.ath.as_deref() == Some(access_token_hash(token).as_str())
    }

    /// The key to record in a replay cache: a proof is unique by its key and `jti`.
    pub fn replay_key(&self) -> String {
        format!("dpop\n{}\n{}", self.jkt, self.jti)
    }

    /// The last instant (unix seconds) the proof could still be accepted: `iat + max_age`.
    pub fn replay_until(&self, max_age: Duration) -> i64 {
        self.iat
            .saturating_add(max_age.whole_seconds())
            .saturating_add(1)
    }
}

/// `ath`: base64url (no padding) of the SHA-256 of the token's ASCII bytes (RFC 9449 §4.2).
pub fn access_token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        token.as_bytes(),
    ))
}

/// Normalize an `htu` (or the request URL it is compared with): lowercase scheme and host,
/// no default port, no query or fragment, `/` for an empty path. `None` when `url` is not an
/// absolute `http` or `https` URL, or has user information.
pub fn normalize_htu(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let mut authority = authority.to_ascii_lowercase();
    let default_port = if scheme == "http" { ":80" } else { ":443" };
    if let Some(stripped) = authority.strip_suffix(default_port) {
        authority = stripped.to_owned();
    }
    Some(format!("{scheme}://{authority}{path}"))
}

/// A public key from a JWK, with its thumbprint.
enum PublicJwk {
    Ed25519 { x: Vec<u8> },
    P256 { point: Vec<u8> },
}

fn b64_field(
    jwk: &Map<String, Value>,
    name: &str,
    len: usize,
) -> Result<(String, Vec<u8>), DpopError> {
    let s = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| DpopError::BadKey(format!("`{name}` is missing")))?;
    let raw = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| DpopError::BadKey(format!("`{name}` is not base64url")))?;
    if raw.len() != len {
        return Err(DpopError::BadKey(format!("`{name}` must be {len} bytes")));
    }
    Ok((s.to_owned(), raw))
}

/// Parse a public JWK and compute its RFC 7638 thumbprint.
fn parse_public_jwk(jwk: &Value) -> Result<(PublicJwk, String), DpopError> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| DpopError::BadKey("not a JSON object".into()))?;
    for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
        if obj.contains_key(private) {
            return Err(DpopError::BadKey(format!(
                "carries the private member `{private}`"
            )));
        }
    }
    let field = |k: &str| obj.get(k).and_then(Value::as_str);
    match (field("kty"), field("crv")) {
        (Some("OKP"), Some("Ed25519")) => {
            let (x, raw) = b64_field(obj, "x", 32)?;
            let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
            Ok((PublicJwk::Ed25519 { x: raw }, thumbprint_of(&canonical)))
        }
        (Some("EC"), Some("P-256")) => {
            let (x, xr) = b64_field(obj, "x", 32)?;
            let (y, yr) = b64_field(obj, "y", 32)?;
            let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&xr);
            point.extend_from_slice(&yr);
            Ok((PublicJwk::P256 { point }, thumbprint_of(&canonical)))
        }
        (kty, crv) => Err(DpopError::BadKey(format!(
            "unsupported key type {kty:?} / curve {crv:?} (use OKP/Ed25519 or EC/P-256)"
        ))),
    }
}

fn thumbprint_of(canonical: &str) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        canonical.as_bytes(),
    ))
}

/// RFC 7638 JWK SHA-256 thumbprint of a public (or private: private members are ignored)
/// Ed25519 or P-256 JWK.
pub fn jwk_thumbprint(jwk: &Value) -> Result<String, DpopError> {
    let mut public = jwk.clone();
    if let Some(obj) = public.as_object_mut() {
        obj.remove("d");
    }
    parse_public_jwk(&public).map(|(_, t)| t)
}

fn decode_part(part: &str, what: &str) -> Result<Map<String, Value>, DpopError> {
    let raw = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| DpopError::Malformed(format!("{what} is not base64url")))?;
    match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(DpopError::Malformed(format!("{what} is not a JSON object"))),
    }
}

/// Verify a DPoP proof against the request it came with. See the module docs for what is
/// checked; `jti` replay is left to the caller ([`VerifiedProof::replay_key`]).
pub fn verify_proof(proof: &str, check: &ProofCheck<'_>) -> Result<VerifiedProof, DpopError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(DpopError::Malformed("proof is too large".into()));
    }
    let mut parts = proof.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopError::Malformed("not a compact JWS".into()));
    };
    let header = decode_part(h, "header")?;
    if header.get("typ").and_then(Value::as_str) != Some(DPOP_PROOF_TYPE) {
        return Err(DpopError::WrongType);
    }
    if header.contains_key("crit") {
        return Err(DpopError::Malformed("`crit` is not supported".into()));
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| DpopError::Malformed("`alg` is missing".into()))?;
    let jwk = header
        .get("jwk")
        .ok_or_else(|| DpopError::BadKey("`jwk` is missing".into()))?;
    let (key, jkt) = parse_public_jwk(jwk)?;
    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| DpopError::Malformed("signature is not base64url".into()))?;
    let signing_input = &proof.as_bytes()[..h.len() + 1 + p.len()];
    let verified = match (alg, &key) {
        ("EdDSA", PublicJwk::Ed25519 { x }) => {
            UnparsedPublicKey::new(&ED25519, x).verify(signing_input, &signature)
        }
        ("ES256", PublicJwk::P256 { point }) => {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                .verify(signing_input, &signature)
        }
        _ => return Err(DpopError::UnsupportedAlg(alg.to_owned())),
    };
    verified.map_err(|_| DpopError::BadSignature)?;

    let claims = decode_part(p, "payload")?;
    let str_claim = |k: &str| {
        claims
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| DpopError::Malformed(format!("`{k}` is missing or not a string")))
    };
    let jti = str_claim("jti")?;
    if jti.is_empty() || jti.len() > MAX_JTI_BYTES {
        return Err(DpopError::Malformed(format!(
            "`jti` must be 1 to {MAX_JTI_BYTES} bytes"
        )));
    }
    if str_claim("htm")? != check.method {
        return Err(DpopError::MethodMismatch);
    }
    let htu = normalize_htu(str_claim("htu")?).ok_or(DpopError::UrlMismatch)?;
    if Some(htu) != normalize_htu(check.url) {
        return Err(DpopError::UrlMismatch);
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| DpopError::Malformed("`iat` is missing or not an integer".into()))?;
    // `iat` is the caller's: `now - iat` can overflow (and `abs` of `i64::MIN` too), which
    // panics in a debug build and, wrapped in a release build, made a proof with
    // `iat = now - 2^63` look fresh. `abs_diff` is exact for every pair of `i64`s.
    let now = check.now.unix_timestamp();
    let max_age = u64::try_from(check.max_age.whole_seconds()).unwrap_or(0);
    if now.abs_diff(iat) > max_age {
        return Err(DpopError::Stale);
    }
    let ath = claims.get("ath").and_then(Value::as_str).map(str::to_owned);
    let proof = VerifiedProof {
        jkt,
        jti: jti.to_owned(),
        iat,
        ath,
    };
    if let Some(token) = check.access_token {
        if !proof.covers(token) {
            return Err(DpopError::AthMismatch);
        }
    }
    Ok(proof)
}

enum Secret {
    Ed25519 {
        seed: [u8; 32],
        pair: Ed25519KeyPair,
    },
    P256 {
        d: Vec<u8>,
        pair: EcdsaKeyPair,
    },
}

/// A DPoP private key that signs proofs: Ed25519 (`EdDSA`) or P-256 (`ES256`).
///
/// Stored as a private JWK (`{"kty":"OKP","crv":"Ed25519","x":...,"d":...}` or the EC
/// equivalent), which is also what the Python and TypeScript SDKs accept.
pub struct DpopKey {
    secret: Secret,
    public_jwk: Value,
    jkt: String,
}

impl std::fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopKey")
            .field("alg", &self.alg())
            .field("jkt", &self.jkt)
            .finish_non_exhaustive()
    }
}

impl DpopKey {
    /// A fresh random Ed25519 key.
    pub fn generate() -> Result<Self, DpopError> {
        let mut seed = [0u8; 32];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| DpopError::BadKey("system RNG unavailable".into()))?;
        Self::ed25519(seed)
    }

    fn ed25519(seed: [u8; 32]) -> Result<Self, DpopError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|e| DpopError::BadKey(format!("invalid Ed25519 seed: {e}")))?;
        let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
        let public_jwk = json!({"kty": "OKP", "crv": "Ed25519", "x": x});
        let jkt = jwk_thumbprint(&public_jwk)?;
        Ok(Self {
            secret: Secret::Ed25519 { seed, pair },
            public_jwk,
            jkt,
        })
    }

    /// Load a private JWK: `OKP`/`Ed25519` or `EC`/`P-256`, with `d`.
    pub fn from_jwk(jwk: &Value) -> Result<Self, DpopError> {
        let obj = jwk
            .as_object()
            .ok_or_else(|| DpopError::BadKey("not a JSON object".into()))?;
        let field = |k: &str| obj.get(k).and_then(Value::as_str);
        match (field("kty"), field("crv")) {
            (Some("OKP"), Some("Ed25519")) => {
                let (_, d) = b64_field(obj, "d", 32)?;
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&d);
                let key = Self::ed25519(seed)?;
                if field("x").is_some_and(|x| Some(x) != key.public_jwk["x"].as_str()) {
                    return Err(DpopError::BadKey("`x` does not match `d`".into()));
                }
                Ok(key)
            }
            (Some("EC"), Some("P-256")) => {
                let (_, d) = b64_field(obj, "d", 32)?;
                let (x, xr) = b64_field(obj, "x", 32)?;
                let (y, yr) = b64_field(obj, "y", 32)?;
                let mut point = vec![0x04];
                point.extend_from_slice(&xr);
                point.extend_from_slice(&yr);
                let pair = EcdsaKeyPair::from_private_key_and_public_key(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &d,
                    &point,
                    &SystemRandom::new(),
                )
                .map_err(|e| DpopError::BadKey(format!("invalid P-256 key: {e}")))?;
                let public_jwk = json!({"kty": "EC", "crv": "P-256", "x": x, "y": y});
                let jkt = jwk_thumbprint(&public_jwk)?;
                Ok(Self {
                    secret: Secret::P256 { d, pair },
                    public_jwk,
                    jkt,
                })
            }
            (kty, crv) => Err(DpopError::BadKey(format!(
                "unsupported key type {kty:?} / curve {crv:?} (use OKP/Ed25519 or EC/P-256)"
            ))),
        }
    }

    /// The JWS `alg` this key signs with.
    pub fn alg(&self) -> &'static str {
        match self.secret {
            Secret::Ed25519 { .. } => "EdDSA",
            Secret::P256 { .. } => "ES256",
        }
    }

    /// The public JWK, as put in every proof's header.
    pub fn public_jwk(&self) -> &Value {
        &self.public_jwk
    }

    /// The private JWK, for storage. Secret.
    pub fn private_jwk(&self) -> Value {
        let mut jwk = self.public_jwk.clone();
        let d = match &self.secret {
            Secret::Ed25519 { seed, .. } => URL_SAFE_NO_PAD.encode(seed),
            Secret::P256 { d, .. } => URL_SAFE_NO_PAD.encode(d),
        };
        jwk["d"] = d.into();
        jwk
    }

    /// RFC 7638 thumbprint of the public key: the `cnf.jkt` of tokens bound to it.
    pub fn thumbprint(&self) -> &str {
        &self.jkt
    }

    /// A proof for one request: `htm` = `method`, `htu` = `url` without query or fragment,
    /// `iat` = `now`, a random `jti`, and `ath` when `access_token` (a bound token sent with
    /// the request) is given.
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        now: OffsetDateTime,
    ) -> String {
        let htu = url.split(['?', '#']).next().unwrap_or(url);
        let mut claims = json!({
            "jti": uuid::Uuid::new_v4().to_string(),
            "htm": method,
            "htu": htu,
            "iat": now.unix_timestamp(),
        });
        if let Some(token) = access_token {
            claims["ath"] = access_token_hash(token).into();
        }
        self.sign_claims(&claims)
    }

    /// Sign arbitrary proof claims with a correct DPoP header. Mostly for tests that need a
    /// proof with a wrong claim.
    pub fn sign_claims(&self, claims: &Value) -> String {
        let header = json!({"typ": DPOP_PROOF_TYPE, "alg": self.alg(), "jwk": self.public_jwk});
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).expect("JSON"));
        let input = format!("{}.{}", enc(&header), enc(claims));
        let sig = match &self.secret {
            Secret::Ed25519 { pair, .. } => pair.sign(input.as_bytes()).as_ref().to_vec(),
            Secret::P256 { pair, .. } => pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .map(|s| s.as_ref().to_vec())
                .unwrap_or_default(),
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const URL: &str = "https://onbehalf.example/mcp/github";

    fn check<'a>(token: Option<&'a str>, now: OffsetDateTime) -> ProofCheck<'a> {
        ProofCheck {
            method: "POST",
            url: URL,
            access_token: token,
            now,
            max_age: Duration::seconds(300),
        }
    }

    fn now() -> OffsetDateTime {
        datetime!(2026-10-23 12:00 UTC)
    }

    #[test]
    fn thumbprint_matches_rfc7638_shape_and_ignores_private_parts() {
        let k = DpopKey::generate().unwrap();
        assert_eq!(k.thumbprint().len(), 43);
        assert_eq!(jwk_thumbprint(&k.private_jwk()).unwrap(), k.thumbprint());
        assert!(Confirmation::jkt(k.thumbprint()).is_well_formed());
        assert!(!Confirmation::jkt("short").is_well_formed());
        // RFC 8037 appendix A.3: the Ed25519 example key's thumbprint.
        let rfc =
            json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        assert_eq!(
            jwk_thumbprint(&rfc).unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn private_jwk_round_trips() {
        let k = DpopKey::generate().unwrap();
        let back = DpopKey::from_jwk(&k.private_jwk()).unwrap();
        assert_eq!(back.thumbprint(), k.thumbprint());
        let mut wrong = k.private_jwk();
        wrong["x"] = DpopKey::generate().unwrap().public_jwk()["x"].clone();
        assert!(DpopKey::from_jwk(&wrong).is_err());
        assert!(DpopKey::from_jwk(k.public_jwk()).is_err());
    }

    #[test]
    fn good_proofs_verify_for_both_algorithms() {
        // RFC 7515 appendix A.3 P-256 key.
        let p256 = DpopKey::from_jwk(&json!({
            "kty": "EC", "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        }))
        .unwrap();
        assert_eq!(p256.alg(), "ES256");
        for key in [DpopKey::generate().unwrap(), p256] {
            let proof = key.proof("POST", &format!("{URL}?x=1"), Some("tok"), now());
            let v = verify_proof(&proof, &check(Some("tok"), now())).unwrap();
            assert_eq!(v.jkt, key.thumbprint());
            assert!(v.replay_key().contains(&v.jti));
            assert_eq!(
                v.replay_until(Duration::seconds(300)),
                now().unix_timestamp() + 301
            );
        }
    }

    #[test]
    fn wrong_htm_htu_ath_iat_are_refused() {
        let k = DpopKey::generate().unwrap();
        let t = now();
        let ok = |p: &str| verify_proof(p, &check(Some("tok"), t));
        assert_eq!(
            ok(&k.proof("GET", URL, Some("tok"), t)),
            Err(DpopError::MethodMismatch)
        );
        assert_eq!(
            ok(&k.proof("POST", "https://onbehalf.example/mcp/other", Some("tok"), t)),
            Err(DpopError::UrlMismatch)
        );
        assert_eq!(
            ok(&k.proof("POST", "http://onbehalf.example/mcp/github", Some("tok"), t)),
            Err(DpopError::UrlMismatch)
        );
        assert_eq!(
            ok(&k.proof("POST", URL, Some("other"), t)),
            Err(DpopError::AthMismatch)
        );
        assert_eq!(
            ok(&k.proof("POST", URL, None, t)),
            Err(DpopError::AthMismatch)
        );
        assert_eq!(
            ok(&k.proof("POST", URL, Some("tok"), t - Duration::seconds(301))),
            Err(DpopError::Stale)
        );
        assert_eq!(
            ok(&k.proof("POST", URL, Some("tok"), t + Duration::seconds(301))),
            Err(DpopError::Stale)
        );
        // `iat` at the i64 edges is stale, not an overflow (found by the `dpop_proof` fuzz
        // target: `now - iat` overflowed, and in release builds `iat = now - 2^63` wrapped to a
        // "fresh" proof).
        for iat in [
            i64::MIN,
            i64::MAX,
            t.unix_timestamp().wrapping_sub(i64::MIN),
            t.unix_timestamp().wrapping_add(i64::MIN),
        ] {
            let claims = json!({
                "jti": "j", "htm": "POST", "htu": URL, "iat": iat,
                "ath": access_token_hash("tok"),
            });
            assert_eq!(
                ok(&k.sign_claims(&claims)),
                Err(DpopError::Stale),
                "iat {iat}"
            );
        }
        // Without a bound token, `ath` is not required.
        verify_proof(&k.proof("POST", URL, None, t), &check(None, t)).unwrap();
        // Case and default ports are normalized; the query is ignored.
        verify_proof(
            &k.proof("POST", "HTTPS://OnBehalf.example:443/mcp/github#f", None, t),
            &check(None, t),
        )
        .unwrap();
    }

    #[test]
    fn tampered_or_mis_typed_proofs_are_refused() {
        let k = DpopKey::generate().unwrap();
        let other = DpopKey::generate().unwrap();
        let t = now();
        let proof = k.proof("POST", URL, None, t);
        let (input, _) = proof.rsplit_once('.').unwrap();
        // Signed by another key than the header's jwk.
        let sig = other.proof("POST", URL, None, t);
        let forged = format!("{input}.{}", sig.rsplit_once('.').unwrap().1);
        assert_eq!(
            verify_proof(&forged, &check(None, t)),
            Err(DpopError::BadSignature)
        );
        assert!(matches!(
            verify_proof("a.b", &check(None, t)),
            Err(DpopError::Malformed(_))
        ));
        // Wrong typ, private key in the header, alg not matching the key.
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        let claims =
            enc(&json!({"jti": "1", "htm": "POST", "htu": URL, "iat": t.unix_timestamp()}));
        for (header, want) in [
            (
                json!({"typ": "JWT", "alg": "EdDSA", "jwk": k.public_jwk()}),
                DpopError::WrongType,
            ),
            (
                json!({"typ": DPOP_PROOF_TYPE, "alg": "EdDSA", "jwk": k.private_jwk()}),
                DpopError::BadKey("carries the private member `d`".into()),
            ),
            (
                json!({"typ": DPOP_PROOF_TYPE, "alg": "ES256", "jwk": k.public_jwk()}),
                DpopError::UnsupportedAlg("ES256".into()),
            ),
            (
                json!({"typ": DPOP_PROOF_TYPE, "alg": "none", "jwk": k.public_jwk()}),
                DpopError::UnsupportedAlg("none".into()),
            ),
        ] {
            let p = format!("{}.{claims}.AAAA", enc(&header));
            assert_eq!(verify_proof(&p, &check(None, t)), Err(want));
        }
        // Missing or oversized jti.
        let no_jti = k.sign_claims(&json!({"htm": "POST", "htu": URL, "iat": t.unix_timestamp()}));
        assert!(matches!(
            verify_proof(&no_jti, &check(None, t)),
            Err(DpopError::Malformed(_))
        ));
        let long = k.sign_claims(
            &json!({"jti": "x".repeat(300), "htm": "POST", "htu": URL, "iat": t.unix_timestamp()}),
        );
        assert!(matches!(
            verify_proof(&long, &check(None, t)),
            Err(DpopError::Malformed(_))
        ));
    }

    #[test]
    fn htu_normalization() {
        assert_eq!(
            normalize_htu("HTTP://Host:80").as_deref(),
            Some("http://host/")
        );
        assert_eq!(
            normalize_htu("https://h:8443/a/b?q#f").as_deref(),
            Some("https://h:8443/a/b")
        );
        assert_eq!(normalize_htu("ftp://h/"), None);
        assert_eq!(normalize_htu("https://u@h/"), None);
        assert_eq!(normalize_htu("/relative"), None);
    }
}
