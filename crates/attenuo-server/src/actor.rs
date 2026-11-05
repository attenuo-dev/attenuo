//! Actor authentication with an RFC 8693 `actor_token`: a workload-identity JWT (a SPIFFE
//! JWT-SVID, or any JWT from an issuer with a JWKS) that proves which agent is calling
//! `POST /token`, for an exchange (hop n to n+1) or for hop 0 (IdP intake,
//! [`crate::idp::intake`]).
//!
//! Trusted issuers are the `[[actor_trust]]` entries ([`ActorTrustConfig`]). Keys come from
//! the entry's `jwks_url`, or for a SPIFFE trust domain from its bundle endpoint
//! (`spiffe_bundle_url`, which serves a JWKS whose JWT-SVID keys have `use` = `jwt-svid`).
//! Neither is discovered: the URL is configured explicitly. Keys are cached and refreshed by
//! the same [`JwksCache`] the `[[idps]]` use (refetch once on an unknown `kid`, fail closed).
//!
//! # Verification ([`ActorTrustRegistry::verify`])
//!
//! 1. Header and payload decode. A header `typ` naming another kind of token (`attenuo+jwt`,
//!    `oauth-id-jag+jwt`, `at+jwt`) is refused, so a delegation token, an ID-JAG or an access
//!    token cannot double as an actor token.
//! 2. The entry is chosen from the unverified `iss` and `sub`: an entry with `issuer` needs the
//!    same `iss`; an entry with `spiffe_trust_domain` needs `sub` to be a SPIFFE ID in that
//!    trust domain. No match is refused before any network call.
//! 3. `alg` must be one of the entry's `allowed_algs` (asymmetric only); the key is looked up by
//!    `kid`.
//! 4. Signature; then `iss` (when the entry names one), `aud` (string or array containing the
//!    entry's `audience`), `exp` (required), `nbf` and `iat` (optional, not in the future), all
//!    with `clock_skew_seconds` of leeway; `sub` (required, a valid SPIFFE ID for a trust
//!    domain entry).
//! 5. `sub` is mapped to an agent id by `subject_to_agent`.
//!
//! The caller then checks that the agent equals the request's `actor`, uses the token once
//! ([`VerifiedActor::replay_key`]) and caps the new token's expiry at the actor token's `exp`.
//!
//! Every rejection is `400 invalid_request` (RFC 8693 §2.2.2) with a stable `error_description`
//! sub-code starting `actor_token_`, except `jwks_unavailable` (`503 temporarily_unavailable`).

use std::str::FromStr;
use std::time::Duration;

use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::config::{ActorTrustConfig, SubjectToAgent};
use crate::error::ApiError;
use crate::idp::jwks::{JwksCache, JwksError};
use crate::idp::numeric_date;

/// RFC 8693 §3 token type the `actor_token_type` must name.
pub const ACTOR_TOKEN_TYPE: &str = attenuo_token::JWT_TOKEN_TYPE_URN;

/// Timeout for JWKS requests.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Header `typ` values that mark a token as something other than an identity assertion.
const FOREIGN_TYPS: &[&str] = &[attenuo_token::TOKEN_TYPE, "oauth-id-jag+jwt", "at+jwt"];

/// A rejected actor token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActorTokenError {
    #[error("actor_token is not a well-formed JWT: {0}")]
    Malformed(String),
    #[error("actor_token typ `{0}` names another kind of token")]
    TypMismatch(String),
    #[error("actor_token issuer {0} is not a trusted [[actor_trust]] entry")]
    UntrustedIssuer(String),
    #[error("algorithm `{0}` is not allowed for this [[actor_trust]] entry")]
    UnsupportedAlg(String),
    #[error("actor_token has no kid and the issuer has several keys")]
    MissingKid,
    #[error("no key with this kid at the actor token's issuer")]
    UnknownKid,
    #[error("actor_token signature verification failed: {0}")]
    BadSignature(String),
    #[error("actor_token aud does not contain `{0}`")]
    AudienceMismatch(String),
    #[error("actor_token expired")]
    Expired,
    #[error("actor_token is not valid yet (iat or nbf in the future)")]
    NotYetValid,
    #[error("actor_token claim `{0}` is missing or has the wrong type")]
    MissingClaim(&'static str),
    #[error("actor_token sub `{0}` is not a SPIFFE ID in the trust domain")]
    InvalidSpiffeId(String),
    #[error("actor_token sub `{0}` does not map to an agent")]
    UnmappedSubject(String),
    #[error("cannot fetch the actor token issuer's keys: {0}")]
    JwksUnavailable(String),
}

impl ActorTokenError {
    /// The stable `error_description` sub-code.
    pub fn description(&self) -> &'static str {
        match self {
            ActorTokenError::Malformed(_) => "actor_token_malformed",
            ActorTokenError::TypMismatch(_) => "actor_token_typ_mismatch",
            ActorTokenError::UntrustedIssuer(_) => "actor_token_untrusted_issuer",
            ActorTokenError::UnsupportedAlg(_) => "actor_token_unsupported_alg",
            ActorTokenError::MissingKid => "actor_token_missing_kid",
            ActorTokenError::UnknownKid => "actor_token_unknown_kid",
            ActorTokenError::BadSignature(_) => "actor_token_bad_signature",
            ActorTokenError::AudienceMismatch(_) => "actor_token_audience_mismatch",
            ActorTokenError::Expired => "actor_token_expired",
            ActorTokenError::NotYetValid => "actor_token_not_yet_valid",
            ActorTokenError::MissingClaim(_) => "actor_token_missing_claim",
            ActorTokenError::InvalidSpiffeId(_) => "actor_token_invalid_spiffe_id",
            ActorTokenError::UnmappedSubject(_) => "actor_token_unmapped_subject",
            ActorTokenError::JwksUnavailable(_) => "jwks_unavailable",
        }
    }
}

impl From<ActorTokenError> for ApiError {
    fn from(e: ActorTokenError) -> Self {
        let d = e.description();
        match e {
            // The fetch error names the JWKS URL and the transport failure: log it, do not
            // return it (SR-17).
            ActorTokenError::JwksUnavailable(detail) => {
                tracing::warn!(detail = ?detail, "actor token issuer JWKS unavailable");
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "the actor token issuer's keys cannot be fetched; try again later",
                )
            }
            // The verifier's text names the expected audience, the issuer, the SPIFFE id and
            // the signature library's complaint: log it at debug level and return only the
            // stable sub-code, as `detail` and `error_description` (SR-17).
            _ => {
                tracing::debug!(reason = d, detail = ?e.to_string(), "actor token refused");
                ApiError::bad_request("invalid_request", d)
            }
        }
        .with_description(d)
    }
}

impl From<JwksError> for ActorTokenError {
    fn from(e: JwksError) -> Self {
        match e {
            JwksError::Unavailable(m) => ActorTokenError::JwksUnavailable(m),
            JwksError::UnknownKid => ActorTokenError::UnknownKid,
            JwksError::MissingKid => ActorTokenError::MissingKid,
            JwksError::AlgMismatch { .. } => ActorTokenError::UnsupportedAlg(e.to_string()),
        }
    }
}

/// An actor token whose signature and claims have been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedActor {
    /// The attenuo agent id `sub` maps to.
    pub agent: String,
    /// `sub` as in the token (for SPIFFE, the SPIFFE ID).
    pub subject: String,
    /// The entry that vouched for it: its `issuer`, or `spiffe://<trust domain>`.
    pub trust: String,
    /// `exp`, unix seconds.
    pub expires_at: i64,
    /// The entry's `clock_skew_seconds`.
    pub clock_skew_seconds: u64,
    /// `jti`, when present and non-empty.
    pub jti: Option<String>,
}

impl VerifiedActor {
    /// The key under which the token is used once: (entry, `jti`), or, without a `jti`, the
    /// SHA-256 of the JWS signing input (not of the signature, which may be malleable, SR-29).
    pub fn replay_key(&self, token: &str) -> String {
        use sha2::{Digest, Sha256};
        match &self.jti {
            Some(jti) => format!("actor\n{}\n{jti}", self.trust),
            None => {
                let input = token
                    .trim()
                    .rsplit_once('.')
                    .map_or(token, |(input, _sig)| input);
                format!(
                    "actor-sha256\n{}",
                    hex::encode(Sha256::digest(input.as_bytes()))
                )
            }
        }
    }

    /// Until when the replay entry must live: `exp` plus the skew.
    pub fn replay_until(&self) -> i64 {
        self.expires_at
            .saturating_add(i64::try_from(self.clock_skew_seconds).unwrap_or(i64::MAX))
    }
}

struct Entry {
    config: ActorTrustConfig,
    /// Lowercased trust domain, for SPIFFE entries.
    trust_domain: Option<String>,
    /// [`VerifiedActor::trust`] for this entry.
    label: String,
    algs: Vec<Algorithm>,
    jwks: JwksCache,
}

impl Entry {
    /// Could this entry have issued a token with these unverified claims?
    fn matches(&self, iss: Option<&str>, sub: Option<&str>) -> bool {
        if let Some(want) = &self.config.issuer {
            if iss != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(td) = &self.trust_domain {
            if !sub.and_then(parse_spiffe_id).is_some_and(|(t, _)| t == *td) {
                return false;
            }
        }
        true
    }
}

/// The configured `[[actor_trust]]` entries, each with its key cache.
pub struct ActorTrustRegistry {
    entries: Vec<Entry>,
}

impl ActorTrustRegistry {
    /// Validate the entries and build their key caches.
    pub fn from_config(entries: &[ActorTrustConfig]) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()?;
        let mut out: Vec<Entry> = Vec::with_capacity(entries.len());
        for cfg in entries {
            let entry = build_entry(cfg, &client)?;
            if out.iter().any(|e| {
                e.config.issuer == entry.config.issuer && e.trust_domain == entry.trust_domain
            }) {
                anyhow::bail!("[[actor_trust]] `{}` is listed twice", entry.label);
            }
            tracing::info!(trust = %entry.label, algs = ?cfg.allowed_algs, "trusted actor token issuer");
            out.push(entry);
        }
        Ok(Self { entries: out })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verify `token` as an actor token at `now`. See the module docs for the order.
    pub async fn verify(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedActor, ActorTokenError> {
        let (header, payload) = peek(token)?;
        if let Some(typ) = header.get("typ").and_then(Value::as_str) {
            if FOREIGN_TYPS.iter().any(|t| t.eq_ignore_ascii_case(typ)) {
                return Err(ActorTokenError::TypMismatch(typ.to_owned()));
            }
        }
        let iss = payload.get("iss").and_then(Value::as_str);
        let sub = payload.get("sub").and_then(Value::as_str);
        let entry = self
            .entries
            .iter()
            .find(|e| e.matches(iss, sub))
            .ok_or_else(|| {
                ActorTokenError::UntrustedIssuer(match (iss, sub) {
                    (Some(i), _) => format!("`{i}`"),
                    (None, Some(s)) => format!("(no iss; sub `{s}`)"),
                    (None, None) => "(no iss, no sub)".into(),
                })
            })?;

        let alg_name = header.get("alg").and_then(Value::as_str).unwrap_or("");
        let alg = Algorithm::from_str(alg_name)
            .ok()
            .filter(|a| entry.algs.contains(a))
            .ok_or_else(|| ActorTokenError::UnsupportedAlg(alg_name.to_owned()))?;
        let kid = header.get("kid").and_then(Value::as_str);
        let key = entry.jwks.key_for(kid, alg).await?;

        let mut validation = Validation::new(alg);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    ActorTokenError::BadSignature("signature does not match".into())
                }
                _ => ActorTokenError::BadSignature(e.to_string()),
            })?
            .claims;

        let (subject, expires_at) = check_claims(&claims, entry, now)?;
        let agent = map_subject(&entry.config.subject_to_agent, &subject)?;
        Ok(VerifiedActor {
            agent,
            subject,
            trust: entry.label.clone(),
            expires_at,
            clock_skew_seconds: entry.config.clock_skew_seconds,
            jti: claims
                .get("jti")
                .and_then(Value::as_str)
                .filter(|j| !j.is_empty())
                .map(str::to_owned),
        })
    }
}

fn build_entry(cfg: &ActorTrustConfig, client: &reqwest::Client) -> anyhow::Result<Entry> {
    let nonempty = |o: &Option<String>| o.as_deref().is_some_and(|s| !s.is_empty());
    let label = match (&cfg.issuer, &cfg.spiffe_trust_domain) {
        (_, Some(td)) => format!("spiffe://{}", td.to_ascii_lowercase()),
        (Some(i), None) => i.clone(),
        (None, None) => "(unnamed)".into(),
    };
    let fail = |msg: &str| anyhow::anyhow!("[[actor_trust]] `{label}`: {msg}");
    if cfg.audience.is_empty() {
        return Err(fail("audience must not be empty"));
    }
    if cfg.issuer.as_deref() == Some("") {
        return Err(fail("issuer must not be empty"));
    }
    let url = match (
        nonempty(&cfg.jwks_url),
        nonempty(&cfg.spiffe_trust_domain),
        nonempty(&cfg.spiffe_bundle_url),
    ) {
        (true, false, false) => {
            if cfg.issuer.is_none() {
                return Err(fail("jwks_url needs issuer"));
            }
            cfg.jwks_url.clone().unwrap_or_default()
        }
        (false, true, true) => cfg.spiffe_bundle_url.clone().unwrap_or_default(),
        (false, true, false) => return Err(fail(
            "spiffe_trust_domain needs spiffe_bundle_url (the bundle endpoint is never discovered)",
        )),
        (false, false, true) => return Err(fail("spiffe_bundle_url needs spiffe_trust_domain")),
        _ => {
            return Err(fail(
                "set exactly one of jwks_url, or spiffe_trust_domain with spiffe_bundle_url",
            ))
        }
    };
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(fail("the key URL must be http(s)"));
    }
    let trust_domain = match &cfg.spiffe_trust_domain {
        Some(td) => {
            let td = td.to_ascii_lowercase();
            if !valid_trust_domain(&td) {
                return Err(fail("spiffe_trust_domain is not a valid trust domain name"));
            }
            Some(td)
        }
        None => None,
    };
    match &cfg.subject_to_agent {
        SubjectToAgent::SpiffePath if trust_domain.is_none() => {
            return Err(fail(
                "subject_to_agent = \"spiffe_path\" needs spiffe_trust_domain",
            ))
        }
        SubjectToAgent::Map(m) if m.is_empty() => {
            return Err(fail("subject_to_agent table is empty"))
        }
        SubjectToAgent::Map(m) if m.values().any(String::is_empty) => {
            return Err(fail("subject_to_agent maps a subject to an empty agent id"))
        }
        _ => {}
    }
    if cfg.allowed_algs.is_empty() {
        return Err(fail("allowed_algs is empty"));
    }
    let algs = cfg
        .allowed_algs
        .iter()
        .map(|a| parse_asymmetric_alg(a))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| fail(&e))?;
    if cfg.jwks_ttl_seconds == 0 {
        return Err(fail("jwks_ttl_seconds must be positive"));
    }
    let jwks = JwksCache::new(
        client.clone(),
        label.clone(),
        Some(url),
        Duration::from_secs(cfg.jwks_ttl_seconds),
    );
    Ok(Entry {
        config: cfg.clone(),
        trust_domain,
        label,
        algs,
        jwks,
    })
}

/// Only asymmetric JWS algorithms: an HMAC "key" in a public JWKS would let anyone mint tokens.
fn parse_asymmetric_alg(name: &str) -> Result<Algorithm, String> {
    match Algorithm::from_str(name) {
        Err(_) => Err(format!("unknown algorithm `{name}`")),
        Ok(Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) => {
            Err(format!("symmetric algorithm `{name}` is not allowed"))
        }
        Ok(a) => Ok(a),
    }
}

type JsonObject = Map<String, Value>;

/// Decode header and payload without verifying anything.
fn peek(token: &str) -> Result<(JsonObject, JsonObject), ActorTokenError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ActorTokenError::Malformed(
            "expected three dot-separated parts".into(),
        ));
    };
    let part = |s: &str, what: &str| -> Result<JsonObject, ActorTokenError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| ActorTokenError::Malformed(format!("{what}: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| ActorTokenError::Malformed(format!("{what}: {e}")))
    };
    Ok((part(h, "header")?, part(p, "payload")?))
}

/// Check `iss`, `aud`, `exp`, `nbf`, `iat` and `sub`; return `sub` and `exp`.
fn check_claims(
    claims: &JsonObject,
    entry: &Entry,
    now: OffsetDateTime,
) -> Result<(String, i64), ActorTokenError> {
    let cfg = &entry.config;
    if let Some(want) = &cfg.issuer {
        if claims.get("iss").and_then(Value::as_str) != Some(want.as_str()) {
            return Err(ActorTokenError::UntrustedIssuer(
                claims
                    .get("iss")
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "(none)".into()),
            ));
        }
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => *a == cfg.audience,
        Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(&cfg.audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(ActorTokenError::AudienceMismatch(cfg.audience.clone()));
    }
    let now = now.unix_timestamp();
    let skew = i64::try_from(cfg.clock_skew_seconds).unwrap_or(i64::MAX);
    let exp = numeric_date(claims, "exp").ok_or(ActorTokenError::MissingClaim("exp"))?;
    if now >= exp.saturating_add(skew) {
        return Err(ActorTokenError::Expired);
    }
    for name in ["nbf", "iat"] {
        if numeric_date(claims, name).is_some_and(|t| t > now.saturating_add(skew)) {
            return Err(ActorTokenError::NotYetValid);
        }
    }
    let sub = match claims.get("sub").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => return Err(ActorTokenError::MissingClaim("sub")),
    };
    if let Some(td) = &entry.trust_domain {
        match parse_spiffe_id(&sub) {
            Some((t, _)) if t == *td => {}
            _ => return Err(ActorTokenError::InvalidSpiffeId(sub)),
        }
    }
    Ok((sub, exp))
}

/// The agent id for `sub`.
fn map_subject(mapping: &SubjectToAgent, sub: &str) -> Result<String, ActorTokenError> {
    match mapping {
        SubjectToAgent::Sub => Ok(sub.to_owned()),
        SubjectToAgent::SpiffePath => parse_spiffe_id(sub)
            .map(|(_, path)| path.trim_start_matches('/').to_owned())
            .ok_or_else(|| ActorTokenError::InvalidSpiffeId(sub.to_owned())),
        SubjectToAgent::Map(m) => m
            .get(sub)
            .cloned()
            .ok_or_else(|| ActorTokenError::UnmappedSubject(sub.to_owned())),
    }
}

fn valid_trust_domain(td: &str) -> bool {
    !td.is_empty()
        && td
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
}

/// Split a SPIFFE ID of a workload into (trust domain, path) per the SPIFFE ID spec: scheme
/// `spiffe`, lowercase trust domain of `[a-z0-9.-_]`, a non-empty path of `/`-separated
/// segments of `[a-zA-Z0-9.-_]` that are neither empty, `.` nor `..`; no query, fragment,
/// port or user info.
pub fn parse_spiffe_id(id: &str) -> Option<(String, String)> {
    let rest = id.strip_prefix("spiffe://")?;
    let (td, path) = rest.split_once('/')?;
    if !valid_trust_domain(td) {
        return None;
    }
    for seg in path.split('/') {
        let ok = !seg.is_empty()
            && seg != "."
            && seg != ".."
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
        if !ok {
            return None;
        }
    }
    Some((td.to_owned(), format!("/{path}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn spiffe_cfg() -> ActorTrustConfig {
        ActorTrustConfig {
            issuer: None,
            jwks_url: None,
            spiffe_trust_domain: Some("example.org".into()),
            spiffe_bundle_url: Some("https://spire.example.org/bundle".into()),
            audience: "attenuo".into(),
            subject_to_agent: SubjectToAgent::SpiffePath,
            allowed_algs: vec!["ES256".into(), "RS256".into()],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 60,
        }
    }

    fn entry(cfg: ActorTrustConfig) -> Entry {
        build_entry(&cfg, &reqwest::Client::new()).unwrap()
    }

    #[test]
    fn spiffe_ids_are_parsed_strictly() {
        assert_eq!(
            parse_spiffe_id("spiffe://example.org/ns/agents/sa/coder").unwrap(),
            ("example.org".into(), "/ns/agents/sa/coder".into())
        );
        for bad in [
            "spiffe://example.org",
            "spiffe://example.org/",
            "spiffe://Example.org/a",
            "spiffe://example.org//a",
            "spiffe://example.org/a/../b",
            "spiffe://example.org/a?x=1",
            "spiffe://example.org:443/a",
            "spiffe://u@example.org/a",
            "https://example.org/a",
        ] {
            assert!(parse_spiffe_id(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn subjects_map_to_agents() {
        let id = "spiffe://example.org/ns/agents/sa/coder";
        assert_eq!(map_subject(&SubjectToAgent::Sub, id).unwrap(), id);
        assert_eq!(
            map_subject(&SubjectToAgent::SpiffePath, id).unwrap(),
            "ns/agents/sa/coder"
        );
        let table = SubjectToAgent::Map(BTreeMap::from([(id.into(), "coder".into())]));
        assert_eq!(map_subject(&table, id).unwrap(), "coder");
        assert_eq!(
            map_subject(&table, "spiffe://example.org/other")
                .unwrap_err()
                .description(),
            "actor_token_unmapped_subject"
        );
    }

    #[test]
    fn entries_are_validated() {
        let ok = |c: ActorTrustConfig| ActorTrustRegistry::from_config(&[c]).is_ok();
        assert!(ok(spiffe_cfg()));
        assert!(!ok(ActorTrustConfig {
            spiffe_bundle_url: None,
            ..spiffe_cfg()
        }));
        assert!(!ok(ActorTrustConfig {
            jwks_url: Some("https://x/jwks".into()),
            ..spiffe_cfg()
        }));
        assert!(!ok(ActorTrustConfig {
            allowed_algs: vec!["HS256".into()],
            ..spiffe_cfg()
        }));
        assert!(!ok(ActorTrustConfig {
            audience: String::new(),
            ..spiffe_cfg()
        }));
        assert!(!ok(ActorTrustConfig {
            spiffe_trust_domain: Some("bad domain".into()),
            ..spiffe_cfg()
        }));
        let generic = ActorTrustConfig {
            issuer: Some("https://wl.example".into()),
            jwks_url: Some("https://wl.example/jwks".into()),
            spiffe_trust_domain: None,
            spiffe_bundle_url: None,
            subject_to_agent: SubjectToAgent::Sub,
            ..spiffe_cfg()
        };
        assert!(ok(generic.clone()));
        assert!(!ok(ActorTrustConfig {
            issuer: None,
            ..generic.clone()
        }));
        assert!(!ok(ActorTrustConfig {
            subject_to_agent: SubjectToAgent::SpiffePath,
            ..generic.clone()
        }));
        assert!(ActorTrustRegistry::from_config(&[generic.clone(), generic]).is_err());
    }

    #[test]
    fn entry_selection_uses_issuer_and_trust_domain() {
        let e = entry(spiffe_cfg());
        assert!(e.matches(None, Some("spiffe://example.org/a")));
        assert!(e.matches(Some("anything"), Some("spiffe://example.org/a")));
        assert!(!e.matches(None, Some("spiffe://evil.org/a")));
        assert!(!e.matches(None, None));
        let pinned = entry(ActorTrustConfig {
            issuer: Some("https://spire.example.org".into()),
            ..spiffe_cfg()
        });
        assert!(!pinned.matches(None, Some("spiffe://example.org/a")));
        assert!(pinned.matches(
            Some("https://spire.example.org"),
            Some("spiffe://example.org/a")
        ));
    }

    #[test]
    fn claim_checks_have_stable_codes() {
        let e = entry(spiffe_cfg());
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let base = serde_json::json!({
            "sub": "spiffe://example.org/agents/coder", "aud": ["x", "attenuo"],
            "exp": 1_000_100, "iat": 999_990,
        });
        let check = |patch: &[(&str, Value)], drop: Option<&str>| {
            let mut c = base.as_object().unwrap().clone();
            for (k, v) in patch {
                c.insert((*k).into(), v.clone());
            }
            if let Some(k) = drop {
                c.remove(k);
            }
            check_claims(&c, &e, now)
        };
        assert_eq!(
            check(&[], None).unwrap(),
            ("spiffe://example.org/agents/coder".into(), 1_000_100)
        );
        let code = |r: Result<(String, i64), ActorTokenError>| r.unwrap_err().description();
        assert_eq!(
            code(check(&[("aud", "nope".into())], None)),
            "actor_token_audience_mismatch"
        );
        assert_eq!(
            code(check(&[("exp", 999_900.into())], None)),
            "actor_token_expired"
        );
        assert_eq!(code(check(&[], Some("exp"))), "actor_token_missing_claim");
        assert_eq!(
            code(check(&[("nbf", 1_000_500.into())], None)),
            "actor_token_not_yet_valid"
        );
        assert_eq!(
            code(check(
                &[("sub", "spiffe://evil.org/agents/coder".into())],
                None
            )),
            "actor_token_invalid_spiffe_id"
        );
        assert_eq!(code(check(&[], Some("sub"))), "actor_token_missing_claim");
        // Within the skew is still fine.
        assert!(check(&[("exp", 999_970.into())], None).is_ok());
    }

    #[test]
    fn replay_key_uses_jti_or_the_signing_input() {
        let v = |jti: Option<&str>| VerifiedActor {
            agent: "coder".into(),
            subject: "s".into(),
            trust: "spiffe://example.org".into(),
            expires_at: 10,
            clock_skew_seconds: 5,
            jti: jti.map(Into::into),
        };
        assert_eq!(
            v(Some("j")).replay_key("a.b.c"),
            "actor\nspiffe://example.org\nj"
        );
        assert_eq!(v(None).replay_key("h.p.s1"), v(None).replay_key("h.p.s2"));
        assert_ne!(v(None).replay_key("h.p.s"), v(None).replay_key("h.q.s"));
        assert_eq!(v(None).replay_until(), 15);
    }
}
