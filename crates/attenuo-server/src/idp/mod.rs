//! Hop-0 intake: turning a verified user credential from a trusted identity provider into a
//! root delegation token (RFC-0001 §4, property P1).
//!
//! Two credential types are accepted at `POST /token` (RFC 8693 token exchange):
//!
//! | `subject_token_type` | Credential | `aud` must be |
//! |---|---|---|
//! | `urn:ietf:params:oauth:token-type:id_token` | OIDC ID token | `[[idps]] audience` |
//! | `urn:ietf:params:oauth:token-type:id-jag` | ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant, checked against -06), header `typ` = `oauth-id-jag+jwt` (or `application/oauth-id-jag+jwt`) | `[issuer] issuer` |
//!
//! An ID-JAG may also be presented as the draft describes it, with
//! `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and `assertion=<ID-JAG>`.
//!
//! Nothing here is specific to one IdP: any issuer that publishes a JWKS (directly or through
//! OIDC discovery) and signs with RS256, ES256 or EdDSA can be listed in `[[idps]]`.
//!
//! # Verification ([`IdpRegistry::verify`])
//!
//! 1. Header and payload decode; the header `typ` is checked: an ID-JAG must say
//!    `oauth-id-jag+jwt` (case-insensitive, with or without `application/`, RFC 7515
//!    §4.1.9); an ID token must not carry any other explicit `…+jwt` type (RFC 8725 §3.11),
//!    so an access token or an ID-JAG cannot be replayed as an ID token.
//! 2. The unverified `iss` selects the `[[idps]]` entry; unknown issuers are rejected before
//!    any network call.
//! 3. `alg` must be in that IdP's `allowed_algs` (asymmetric only).
//! 4. The key is looked up by `kid` in the IdP's cached JWKS ([`jwks::JwksCache`]), refetching
//!    once on an unknown `kid`.
//! 5. Signature, then `iss` (exact), `aud` (string or array containing the expected value),
//!    `exp` (required), `iat` (required, not in the future), `nbf` (optional), all with
//!    `clock_skew_seconds` of leeway, then `sub` (required, non-empty).
//! 6. For an ID-JAG only: `aud` must be a string or a one-element array, and with
//!    `[[idps]] tenant` set, `tenant` must equal it (draft -06 §4.4.1).
//!
//! The intake handler then reads the ID-JAG's own claims ([`claims::map_id_jag`]: `client_id`
//! and `jti` required, `cnf.jkt` if bound) and, for a bound ID-JAG, requires a DPoP proof by
//! that key on the request (`credential_pop_required`, `credential_pop_mismatch`; draft -04
//! §9.8.1.2, -06 §4.4.1).
//!
//! `nonce` is ignored: it binds an ID token to the browser session that requested it, and the
//! agent presenting the token here is not that session. Replay is bounded instead by requiring
//! the agent's own client credentials, by the root grants, and by using each credential once:
//! a second presentation of the same (`iss`, `jti`), or of the same credential when it has no
//! `jti`, is refused with `replayed` ([`crate::replay`]). The root token issued from a
//! credential never outlives the credential's `exp`.
//!
//! # Errors
//!
//! Every rejection has a stable `error_description` sub-code ([`IntakeError::description`]),
//! with the OAuth `error` code `invalid_grant` (400) except `jwks_unavailable`, which is
//! `temporarily_unavailable` (503). An `invalid_grant` carries the sub-code as `detail` too; the
//! verifier's message (issuer, audience, `kid`, client ids) is logged at debug level and never
//! returned (SR-17).

pub(crate) mod claims;
pub(crate) mod intake;
pub(crate) mod jwks;

use std::str::FromStr;
use std::time::Duration;

use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::config::IdpConfig;
use crate::error::ApiError;
use jwks::{JwksCache, JwksError};

/// RFC 8693 §3 token type of an OIDC ID token.
pub(crate) const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";
/// Token type of an ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant).
pub(crate) const ID_JAG_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";
/// Header `typ` of an ID-JAG.
pub(crate) const ID_JAG_TYP: &str = "oauth-id-jag+jwt";
/// RFC 7523 grant type, the draft's way of presenting an ID-JAG.
pub(crate) const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Timeout for discovery and JWKS requests.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Which credential is being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    IdToken,
    IdJag,
}

impl CredentialKind {
    /// Short name used in audit arguments and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::IdToken => "id_token",
            CredentialKind::IdJag => "id-jag",
        }
    }
}

/// A rejected user credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntakeError {
    #[error("credential is not a well-formed JWT: {0}")]
    Malformed(String),
    #[error("algorithm `{0}` is not allowed for this issuer")]
    UnsupportedAlg(String),
    #[error("JWT typ {0:?} does not match the subject_token_type")]
    TypMismatch(Option<String>),
    #[error("issuer `{0}` is not a trusted [[idps]] entry")]
    UntrustedIssuer(String),
    #[error("token has no kid and the issuer has several keys")]
    MissingKid,
    #[error("no key with this kid at the issuer")]
    UnknownKid,
    #[error("signature verification failed: {0}")]
    BadSignature(String),
    #[error("aud does not contain `{0}`")]
    AudienceMismatch(String),
    #[error("token expired")]
    Expired,
    #[error("token is not valid yet (iat or nbf in the future)")]
    NotYetValid,
    #[error("required claim `{0}` is missing or has the wrong type")]
    MissingClaim(&'static str),
    #[error("the credential was not issued to client `{0}`: aud/azp name another client")]
    CredentialAudienceMismatch(String),
    #[error("ID-JAG client_id `{assertion}` does not match the authenticated client `{client}`")]
    ClientIdMismatch { assertion: String, client: String },
    #[error("ID-JAG tenant {0:?} is not the [[idps]] tenant")]
    TenantMismatch(Option<String>),
    #[error("proof of possession required: {0}")]
    PopRequired(String),
    #[error("the DPoP proof's key is not the key the ID-JAG is bound to (cnf.jkt)")]
    PopMismatch,
    #[error("cannot fetch the issuer's keys: {0}")]
    JwksUnavailable(String),
}

impl IntakeError {
    /// The stable `error_description` sub-code.
    pub fn description(&self) -> &'static str {
        match self {
            IntakeError::Malformed(_) => "malformed_token",
            IntakeError::UnsupportedAlg(_) => "unsupported_alg",
            IntakeError::TypMismatch(_) => "typ_mismatch",
            IntakeError::UntrustedIssuer(_) => "untrusted_issuer",
            IntakeError::MissingKid => "missing_kid",
            IntakeError::UnknownKid => "unknown_kid",
            IntakeError::BadSignature(_) => "bad_signature",
            IntakeError::AudienceMismatch(_) => "audience_mismatch",
            IntakeError::Expired => "expired",
            IntakeError::NotYetValid => "not_yet_valid",
            IntakeError::MissingClaim(_) => "missing_claim",
            IntakeError::CredentialAudienceMismatch(_) => "credential_audience_mismatch",
            IntakeError::ClientIdMismatch { .. } => "client_id_mismatch",
            IntakeError::TenantMismatch(_) => "tenant_mismatch",
            IntakeError::PopRequired(_) => "credential_pop_required",
            IntakeError::PopMismatch => "credential_pop_mismatch",
            IntakeError::JwksUnavailable(_) => "jwks_unavailable",
        }
    }
}

impl From<IntakeError> for ApiError {
    fn from(e: IntakeError) -> Self {
        let d = e.description();
        match e {
            // The fetch error names the JWKS URL and the transport failure: log it, do not
            // return it (SR-17).
            IntakeError::JwksUnavailable(detail) => {
                tracing::warn!(detail = ?detail, "IdP JWKS unavailable");
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "the identity provider's keys cannot be fetched; try again later",
                )
            }
            // The verifier's text names the issuer, the expected audience, the client ids and
            // the signature library's complaint: log it at debug level and return only the
            // stable sub-code, as `detail` and `error_description` (SR-17).
            _ => {
                tracing::debug!(reason = d, detail = ?e.to_string(), "IdP credential refused");
                ApiError::bad_request("invalid_grant", d)
            }
        }
        .with_description(d)
    }
}

impl From<JwksError> for IntakeError {
    fn from(e: JwksError) -> Self {
        match e {
            JwksError::Unavailable(m) => IntakeError::JwksUnavailable(m),
            JwksError::UnknownKid => IntakeError::UnknownKid,
            JwksError::MissingKid => IntakeError::MissingKid,
            JwksError::AlgMismatch { .. } => IntakeError::UnsupportedAlg(e.to_string()),
        }
    }
}

/// A credential whose signature and standard claims have been checked.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedAssertion {
    pub kind: CredentialKind,
    /// `iss`, equal to the matching `[[idps]] issuer`.
    pub issuer: String,
    /// `sub`.
    pub subject: String,
    /// The whole verified payload.
    pub claims: Map<String, Value>,
    /// `[[idps]] attribute_claims` of the issuer.
    pub attribute_claims: Vec<String>,
    /// `exp`, unix seconds.
    pub expires_at: i64,
    /// `[[idps]] clock_skew_seconds` of the issuer: the credential is accepted until
    /// `expires_at` plus this.
    pub clock_skew_seconds: u64,
}

impl VerifiedAssertion {
    /// The key under which the credential is used once: (`iss`, `jti`), or, when it has no
    /// `jti`, the SHA-256 of its JWS signing input (`header.payload`).
    ///
    /// Not of the whole credential: ECDSA signatures are malleable (`(r, s)` and `(r, n - s)`
    /// both verify), so a hash over the signature would let one ES256/ES384 ID token be
    /// re-encoded into a "new" credential and redeemed twice (SR-29). The signing input is
    /// exactly what the signature covers, so it cannot change without failing verification.
    pub fn replay_key(&self, credential: &str) -> String {
        use sha2::{Digest, Sha256};
        match self.claims.get("jti").and_then(Value::as_str) {
            Some(jti) if !jti.is_empty() => format!("idp\n{}\n{jti}", self.issuer),
            _ => {
                let signing_input = credential
                    .trim()
                    .rsplit_once('.')
                    .map_or(credential, |(input, _signature)| input);
                format!(
                    "idp-sha256\n{}",
                    hex::encode(Sha256::digest(signing_input.as_bytes()))
                )
            }
        }
    }
}

struct TrustedIdp {
    config: IdpConfig,
    algs: Vec<Algorithm>,
    jwks: JwksCache,
}

/// The configured `[[idps]]`, each with its key cache.
pub struct IdpRegistry {
    idps: Vec<TrustedIdp>,
    /// `[issuer] issuer`: the `aud` an ID-JAG must carry.
    our_issuer: String,
}

impl IdpRegistry {
    /// Validate the `[[idps]]` entries and build their key caches.
    pub fn from_config(idps: &[IdpConfig], our_issuer: &str) -> anyhow::Result<Self> {
        let client = jwks::fetch_client(FETCH_TIMEOUT)?;
        let mut out = Vec::with_capacity(idps.len());
        for cfg in idps {
            if cfg.issuer.is_empty() {
                anyhow::bail!("[[idps]]: issuer must not be empty");
            }
            if !cfg.audience.is_empty() {
                tracing::warn!(
                    issuer = %cfg.issuer,
                    "[[idps]] audience is no longer used for ID tokens (SR-37); \
                     use client_ids = {{ <agent> = \"<client id at the IdP>\" }}"
                );
            }
            if out
                .iter()
                .any(|t: &TrustedIdp| t.config.issuer == cfg.issuer)
            {
                anyhow::bail!("[[idps]]: issuer `{}` is listed twice", cfg.issuer);
            }
            if cfg.allowed_algs.is_empty() {
                anyhow::bail!("[[idps]] `{}`: allowed_algs is empty", cfg.issuer);
            }
            let algs = cfg
                .allowed_algs
                .iter()
                .map(|a| parse_asymmetric_alg(a))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("[[idps]] `{}`: {e}", cfg.issuer))?;
            // An empty tenant would look set and could match no real ID-JAG (or one with an
            // empty `tenant` claim): a mistake in the file, so refuse it at startup.
            if cfg.tenant.as_deref().is_some_and(|t| t.trim().is_empty()) {
                anyhow::bail!(
                    "[[idps]] `{}`: tenant is empty; remove the line or name a tenant",
                    cfg.issuer
                );
            }
            if cfg.jwks_ttl_seconds == 0 {
                anyhow::bail!(
                    "[[idps]] `{}`: jwks_ttl_seconds must be positive",
                    cfg.issuer
                );
            }
            // S-8: the key source is https (or http on loopback). Without jwks_url the keys
            // are found by discovery at the issuer, so the issuer is the URL checked.
            let (key, source) = match &cfg.jwks_url {
                Some(u) => ("jwks_url", u.as_str()),
                None => (
                    "issuer (used for discovery, no jwks_url)",
                    cfg.issuer.as_str(),
                ),
            };
            jwks::check_fetch_url(source)
                .map_err(|e| anyhow::anyhow!("[[idps]] `{}`: {key} {source:?}: {e}", cfg.issuer))?;
            let jwks = JwksCache::new(
                client.clone(),
                cfg.issuer.clone(),
                cfg.jwks_url.clone(),
                Duration::from_secs(cfg.jwks_ttl_seconds),
            );
            tracing::info!(issuer = %cfg.issuer, algs = ?cfg.allowed_algs, "trusted IdP");
            out.push(TrustedIdp {
                config: cfg.clone(),
                algs,
                jwks,
            });
        }
        Ok(Self {
            idps: out,
            our_issuer: our_issuer.to_owned(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.idps.is_empty()
    }

    /// The `aud` an ID token must name when presented by `agent` at the IdP `issuer`: the
    /// `client_ids` entry, else the agent id.
    pub fn expected_client_id(&self, issuer: &str, agent: &str) -> Option<String> {
        let idp = self.idps.iter().find(|i| i.config.issuer == issuer)?;
        Some(client_id_for(&idp.config, agent))
    }

    /// Verify `token` as a credential of `kind` presented by `agent` at `now`. See the module
    /// docs for the order.
    pub async fn verify(
        &self,
        token: &str,
        kind: CredentialKind,
        agent: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedAssertion, IntakeError> {
        self.verify_for(token, kind, ClientId::Agent(agent), now)
            .await
    }

    /// Verify an OIDC ID token for an approval (ADR-0009): the same checks as hop-0 intake,
    /// with `aud` (and `azp`) bound to `client_id` when given, else to the client id intake
    /// expects for `agent` (the run's root agent).
    pub async fn verify_approval(
        &self,
        token: &str,
        client_id: Option<&str>,
        agent: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedAssertion, IntakeError> {
        let client = match client_id {
            Some(c) => ClientId::Fixed(c),
            None => ClientId::Agent(agent),
        };
        self.verify_for(token, CredentialKind::IdToken, client, now)
            .await
    }

    async fn verify_for(
        &self,
        token: &str,
        kind: CredentialKind,
        client: ClientId<'_>,
        now: OffsetDateTime,
    ) -> Result<VerifiedAssertion, IntakeError> {
        let (header, payload) = peek(token)?;

        let typ = header.get("typ").and_then(Value::as_str);
        let typ_ok = match kind {
            CredentialKind::IdJag => typ.is_some_and(|t| typ_is(t, ID_JAG_TYP)),
            CredentialKind::IdToken => {
                !typ.is_some_and(|t| t.to_ascii_lowercase().ends_with("+jwt"))
            }
        };
        if !typ_ok {
            return Err(IntakeError::TypMismatch(typ.map(str::to_owned)));
        }

        let iss = payload
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(IntakeError::MissingClaim("iss"))?;
        let idp = self
            .idps
            .iter()
            .find(|i| i.config.issuer == iss)
            .ok_or_else(|| IntakeError::UntrustedIssuer(iss.to_owned()))?;

        let alg_name = header.get("alg").and_then(Value::as_str).unwrap_or("");
        let alg = Algorithm::from_str(alg_name)
            .ok()
            .filter(|a| idp.algs.contains(a))
            .ok_or_else(|| IntakeError::UnsupportedAlg(alg_name.to_owned()))?;
        let kid = header.get("kid").and_then(Value::as_str);
        let key = idp.jwks.key_for(kid, alg).await?;

        let mut validation = Validation::new(alg);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    IntakeError::BadSignature("signature does not match".into())
                }
                _ => IntakeError::BadSignature(e.to_string()),
            })?
            .claims;

        // SR-37: an ID token is for one client, and the presenter must be that client. The
        // check comes first so its sub-code is the one a replayed-by-another-agent token gets.
        let client_id = match client {
            ClientId::Agent(agent) => client_id_for(&idp.config, agent),
            ClientId::Fixed(c) => c.to_owned(),
        };
        let expected_aud = match kind {
            CredentialKind::IdToken => {
                check_bound_to_agent(&claims, &client_id)?;
                client_id.as_str()
            }
            CredentialKind::IdJag => self.our_issuer.as_str(),
        };
        let subject = check_claims(
            &claims,
            &idp.config.issuer,
            expected_aud,
            now,
            idp.config.clock_skew_seconds,
        )?;
        if kind == CredentialKind::IdJag {
            check_id_jag(&claims, &idp.config, expected_aud)?;
        }
        // `check_claims` required a numeric `exp`; read it the same way (a JSON float is a
        // valid NumericDate, and `as_i64` alone would turn it into 0).
        let expires_at = numeric_date(&claims, "exp").unwrap_or(0);
        Ok(VerifiedAssertion {
            kind,
            issuer: idp.config.issuer.clone(),
            subject,
            claims,
            attribute_claims: idp.config.attribute_claims.clone(),
            expires_at,
            clock_skew_seconds: idp.config.clock_skew_seconds,
        })
    }
}

/// The ID-JAG checks beyond [`check_claims`] (draft -06 §4.4.1):
///
/// - `aud` names this server and nothing else: a string, or an array with exactly one element
///   ("If the aud claim is an array, it MUST contain exactly one element", also in -04). An
///   ID-JAG for several authorization servers could be redeemed at each of them.
/// - With `[[idps]] tenant` set (a multi-tenant issuer), the `tenant` claim must be present and
///   equal to it, so that `iss` and `tenant` together name the tenant whose users the
///   `[[root_grants]]` cover (-06 §4.4.1, §6.1).
fn check_id_jag(
    claims: &Map<String, Value>,
    cfg: &IdpConfig,
    audience: &str,
) -> Result<(), IntakeError> {
    if let Some(Value::Array(list)) = claims.get("aud") {
        if list.len() != 1 {
            return Err(IntakeError::AudienceMismatch(audience.to_owned()));
        }
    }
    if let Some(expected) = &cfg.tenant {
        let tenant = claims.get("tenant");
        match tenant.and_then(Value::as_str) {
            Some(t) if t == expected => {}
            Some(t) => return Err(IntakeError::TenantMismatch(Some(t.to_owned()))),
            None if tenant.is_none() => return Err(IntakeError::MissingClaim("tenant")),
            None => return Err(IntakeError::TenantMismatch(None)),
        }
    }
    Ok(())
}

/// Which client an ID token must have been issued to.
#[derive(Clone, Copy)]
enum ClientId<'a> {
    /// The client id configured for this agent (`client_ids`, else the agent id).
    Agent(&'a str),
    /// Exactly this client id (`[approvals] client_id`).
    Fixed(&'a str),
}

fn client_id_for(cfg: &IdpConfig, agent: &str) -> String {
    cfg.client_ids
        .get(agent)
        .cloned()
        .unwrap_or_else(|| agent.to_owned())
}

/// SR-37: the ID token must have been issued to the presenting agent's client. `aud` must
/// contain `client_id`; when `aud` has several values, or `azp` is present at all, `azp` must
/// equal it (OIDC Core 2.: `azp` names the party the token was issued to).
fn check_bound_to_agent(claims: &Map<String, Value>, client_id: &str) -> Result<(), IntakeError> {
    let mismatch = || IntakeError::CredentialAudienceMismatch(client_id.to_owned());
    let (aud_has, multiple) = match claims.get("aud") {
        Some(Value::String(a)) => (a == client_id, false),
        Some(Value::Array(l)) => (l.iter().any(|a| a.as_str() == Some(client_id)), l.len() > 1),
        _ => (false, false),
    };
    if !aud_has {
        return Err(mismatch());
    }
    match claims.get("azp") {
        Some(Value::String(azp)) if azp == client_id => Ok(()),
        Some(_) => Err(mismatch()),
        None if multiple => Err(mismatch()),
        None => Ok(()),
    }
}

/// Only asymmetric JWS algorithms may be trusted from an IdP: an HMAC "key" in a public JWKS
/// would let anyone mint tokens.
fn parse_asymmetric_alg(name: &str) -> Result<Algorithm, String> {
    let alg = Algorithm::from_str(name).map_err(|_| format!("unknown algorithm `{name}`"))?;
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Err(format!("symmetric algorithm `{name}` is not allowed"))
        }
        a => Ok(a),
    }
}

/// Does the JWT header `typ` value `typ` name the media type `expected` (given without its
/// `application/` prefix)? RFC 7515 §4.1.9: the comparison is case-insensitive, and a value
/// with no `/` is read as if `application/` were prepended, so `oauth-id-jag+jwt` and
/// `application/oauth-id-jag+jwt` are the same type.
pub(crate) fn typ_is(typ: &str, expected: &str) -> bool {
    const PREFIX: &str = "application/";
    let bare = match typ.get(..PREFIX.len()) {
        Some(p) if p.eq_ignore_ascii_case(PREFIX) => &typ[PREFIX.len()..],
        _ => typ,
    };
    bare.eq_ignore_ascii_case(expected)
}

type JsonObject = Map<String, Value>;

/// Decode header and payload without verifying anything.
/// The `iss` claim of a JWT, read without verifying anything. Used only to choose how to
/// verify a bearer that may be either a delegation token or an IdP ID token.
pub(crate) fn unverified_issuer(token: &str) -> Option<String> {
    let (_, payload) = peek(token).ok()?;
    payload.get("iss")?.as_str().map(str::to_owned)
}

fn peek(token: &str) -> Result<(JsonObject, JsonObject), IntakeError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(IntakeError::Malformed(
            "expected three dot-separated parts".into(),
        ));
    };
    let part = |s: &str, what: &str| -> Result<Map<String, Value>, IntakeError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| IntakeError::Malformed(format!("{what}: {e}")))?;
        serde_json::from_slice(&bytes).map_err(|e| IntakeError::Malformed(format!("{what}: {e}")))
    };
    Ok((part(h, "header")?, part(p, "payload")?))
}

/// A NumericDate claim as whole seconds.
///
/// RFC 7519 §2 allows a NumericDate to be a non-integer: a float is rounded down to the whole
/// second (`exp` of `5.5` expires at `5`, never later). A float that is not finite or is outside
/// the `i64` range of seconds (`1e300`) is not a NumericDate this server can compare, so the
/// claim reads as absent and a required claim is refused with `missing_claim`; it never
/// saturates into a far-future `exp`.
pub(crate) fn numeric_date(claims: &Map<String, Value>, name: &str) -> Option<i64> {
    let v = claims.get(name)?;
    v.as_i64().or_else(|| v.as_f64().and_then(float_seconds))
}

/// `f` rounded down to a whole number of seconds, if that fits in an `i64`.
fn float_seconds(f: f64) -> Option<i64> {
    // -2^63 is exact as an f64; i64::MAX is not (it rounds up to 2^63), so the upper bound is
    // exclusive. NaN and the infinities are outside the range too.
    const LIMIT: f64 = 9_223_372_036_854_775_808.0;
    let s = f.floor();
    if !(-LIMIT..LIMIT).contains(&s) {
        return None;
    }
    // In range and whole, so the cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    Some(s as i64)
}

/// Check `iss`, `aud`, `exp`, `iat`, `nbf` and `sub`; return `sub`.
fn check_claims(
    claims: &Map<String, Value>,
    issuer: &str,
    audience: &str,
    now: OffsetDateTime,
    skew_seconds: u64,
) -> Result<String, IntakeError> {
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(IntakeError::UntrustedIssuer(
            claims
                .get("iss")
                .map(ToString::to_string)
                .unwrap_or_default(),
        ));
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == audience,
        Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(IntakeError::AudienceMismatch(audience.to_owned()));
    }
    let now = now.unix_timestamp();
    let skew = i64::try_from(skew_seconds).unwrap_or(i64::MAX);
    let exp = numeric_date(claims, "exp").ok_or(IntakeError::MissingClaim("exp"))?;
    if now >= exp.saturating_add(skew) {
        return Err(IntakeError::Expired);
    }
    let iat = numeric_date(claims, "iat").ok_or(IntakeError::MissingClaim("iat"))?;
    if iat > now.saturating_add(skew) {
        return Err(IntakeError::NotYetValid);
    }
    if let Some(nbf) = numeric_date(claims, "nbf") {
        if nbf > now.saturating_add(skew) {
            return Err(IntakeError::NotYetValid);
        }
    }
    match claims.get("sub").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_owned()),
        _ => Err(IntakeError::MissingClaim("sub")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn typ_media_type_comparison_rfc7515() {
        for t in [
            "oauth-id-jag+jwt",
            "OAUTH-ID-JAG+JWT",
            "application/oauth-id-jag+jwt",
            "Application/OAuth-ID-JAG+JWT",
        ] {
            assert!(typ_is(t, ID_JAG_TYP), "{t}");
        }
        for t in [
            "",
            "JWT",
            "at+jwt",
            "application/",
            "text/oauth-id-jag+jwt",
            "application/application/oauth-id-jag+jwt",
            "oauth-id-jag+jwt ",
            "applicatio\u{20ac}x",
        ] {
            assert!(!typ_is(t, ID_JAG_TYP), "{t}");
        }
        // The actor-token check uses the same comparison.
        assert!(typ_is("application/attenuo+jwt", attenuo_token::TOKEN_TYPE));
    }

    #[test]
    fn float_numeric_dates_round_down_and_refuse_out_of_range() {
        assert_eq!(float_seconds(f64::NAN), None);
        assert_eq!(float_seconds(f64::INFINITY), None);
        assert_eq!(float_seconds(f64::NEG_INFINITY), None);
        assert_eq!(float_seconds(1e300), None);
        assert_eq!(float_seconds(-1e300), None);
        assert_eq!(float_seconds(9_223_372_036_854_775_808.0), None);
        assert_eq!(float_seconds(-9_223_372_036_854_775_808.0), Some(i64::MIN));
        assert_eq!(float_seconds(-1.0), Some(-1));
        assert_eq!(float_seconds(-0.5), Some(-1));
        assert_eq!(float_seconds(5.0), Some(5));
        assert_eq!(float_seconds(5.5), Some(5));

        // Through the claim reader: an integer is read as is, a fraction rounds down, and a
        // float too large for an i64 is absent rather than a saturated far-future date.
        let c = claims(json!({"a": 7, "b": 1_000_100.9, "c": 1e300, "d": -1.0, "e": "5"}));
        assert_eq!(numeric_date(&c, "a"), Some(7));
        assert_eq!(numeric_date(&c, "b"), Some(1_000_100));
        assert_eq!(numeric_date(&c, "c"), None);
        assert_eq!(numeric_date(&c, "d"), Some(-1));
        assert_eq!(numeric_date(&c, "e"), None);
        assert_eq!(numeric_date(&c, "missing"), None);

        // An `exp` of 1e300 used to saturate to i64::MAX and never expire; now it is refused.
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let c = claims(json!({"iss": "i", "aud": "a", "sub": "u", "exp": 1e300, "iat": 999_990}));
        assert_eq!(
            check_claims(&c, "i", "a", now, 60),
            Err(IntakeError::MissingClaim("exp"))
        );
        // A fractional `exp` in the past is expired, not read as 0 or as a later second.
        let c =
            claims(json!({"iss": "i", "aud": "a", "sub": "u", "exp": 999_900.5, "iat": 999_800.5}));
        assert_eq!(
            check_claims(&c, "i", "a", now, 60),
            Err(IntakeError::Expired)
        );
    }

    #[test]
    fn claim_checks_have_stable_codes() {
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let ok =
            json!({"iss": "i", "aud": ["x", "a"], "sub": "u", "exp": 1_000_100, "iat": 999_990});
        assert_eq!(
            check_claims(&claims(ok.clone()), "i", "a", now, 60).unwrap(),
            "u"
        );
        let with = |k: &str, v: Value| {
            let mut c = claims(ok.clone());
            c.insert(k.into(), v);
            check_claims(&c, "i", "a", now, 60)
                .unwrap_err()
                .description()
        };
        assert_eq!(with("aud", json!("b")), "audience_mismatch");
        assert_eq!(with("exp", json!(999_900)), "expired");
        assert_eq!(with("iat", json!(1_000_500)), "not_yet_valid");
        assert_eq!(with("nbf", json!(1_000_500)), "not_yet_valid");
        assert_eq!(with("sub", json!("")), "missing_claim");
        assert_eq!(with("iss", json!("j")), "untrusted_issuer");
        // Within the skew is still fine.
        let mut c = claims(ok);
        c.insert("exp".into(), json!(999_970));
        assert!(check_claims(&c, "i", "a", now, 60).is_ok());
        c.remove("exp");
        assert_eq!(
            check_claims(&c, "i", "a", now, 60).unwrap_err(),
            IntakeError::MissingClaim("exp")
        );
    }

    #[test]
    fn id_token_must_name_the_presenting_agent_sr37() {
        let c = |v: Value| check_bound_to_agent(&claims(v), "planner");
        assert!(c(json!({"aud": "planner"})).is_ok());
        assert!(c(json!({"aud": ["planner"]})).is_ok());
        assert!(c(json!({"aud": ["planner", "other"], "azp": "planner"})).is_ok());
        for bad in [
            json!({"aud": "coder"}),
            json!({"aud": ["coder"]}),
            json!({"aud": ["planner", "coder"]}),
            json!({"aud": ["planner", "coder"], "azp": "coder"}),
            json!({"aud": "planner", "azp": "coder"}),
            json!({"aud": "planner", "azp": 7}),
            json!({}),
        ] {
            assert_eq!(
                c(bad.clone()).unwrap_err().description(),
                "credential_audience_mismatch",
                "{bad}"
            );
        }
    }

    #[test]
    fn symmetric_algs_are_refused_in_config() {
        assert!(parse_asymmetric_alg("HS256").is_err());
        assert!(parse_asymmetric_alg("none").is_err());
        assert_eq!(parse_asymmetric_alg("EdDSA").unwrap(), Algorithm::EdDSA);
        let cfg = IdpConfig {
            issuer: "https://idp".into(),
            audience: "a".into(),
            jwks_url: None,
            allowed_algs: vec!["HS256".into()],
            attribute_claims: vec![],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 60,
            tenant: None,
            client_ids: Default::default(),
        };
        assert!(IdpRegistry::from_config(std::slice::from_ref(&cfg), "me").is_err());
        let good = IdpConfig {
            allowed_algs: vec!["RS256".into()],
            ..cfg
        };
        assert!(IdpRegistry::from_config(&[good.clone(), good], "me").is_err());
    }

    #[test]
    fn an_empty_tenant_is_refused_in_config() {
        let idp = |tenant: Option<&str>| IdpConfig {
            issuer: "https://idp.example".into(),
            audience: "a".into(),
            jwks_url: None,
            allowed_algs: vec!["RS256".into()],
            attribute_claims: vec![],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 60,
            tenant: tenant.map(str::to_owned),
            client_ids: Default::default(),
        };
        for ok in [None, Some("acme")] {
            IdpRegistry::from_config(&[idp(ok)], "me").unwrap();
        }
        for bad in ["", "  "] {
            let err = IdpRegistry::from_config(&[idp(Some(bad))], "me")
                .err()
                .expect("an empty tenant must be refused")
                .to_string();
            assert!(err.contains("tenant is empty"), "{err}");
        }
    }

    /// S-8: the JWKS (or, without `jwks_url`, the issuer used for discovery) is https, or plain
    /// http on a loopback host.
    #[test]
    fn key_sources_must_be_https_or_loopback_http_s8() {
        let idp = |issuer: &str, jwks_url: Option<&str>| IdpConfig {
            issuer: issuer.into(),
            audience: String::new(),
            jwks_url: jwks_url.map(str::to_owned),
            allowed_algs: vec!["RS256".into()],
            attribute_claims: vec![],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 60,
            tenant: None,
            client_ids: Default::default(),
        };
        for ok in [
            idp("https://idp.example", None),
            idp("https://idp.example", Some("https://keys.idp.example/jwks")),
            idp("http://127.0.0.1:9000", None),
            idp("https://idp.example", Some("http://localhost:9000/jwks")),
        ] {
            IdpRegistry::from_config(std::slice::from_ref(&ok), "me").unwrap();
        }
        for (bad, named) in [
            (idp("http://idp.example", None), "issuer"),
            (
                idp("https://idp.example", Some("http://idp.example/jwks")),
                "jwks_url",
            ),
            (idp("idp", None), "issuer"),
        ] {
            let err = IdpRegistry::from_config(std::slice::from_ref(&bad), "me")
                .err()
                .expect("must refuse")
                .to_string();
            assert!(err.contains(named), "{err}");
        }
    }

    #[test]
    fn peek_rejects_garbage() {
        assert_eq!(peek("a.b").unwrap_err().description(), "malformed_token");
        assert_eq!(peek("!.!.!").unwrap_err().description(), "malformed_token");
    }

    /// SR-29: without `jti`, the replay key covers what the signature covers and nothing else.
    #[test]
    fn replay_key_ignores_the_signature_encoding() {
        let v = |claims: Value| VerifiedAssertion {
            kind: CredentialKind::IdToken,
            issuer: "https://idp".into(),
            subject: "alice".into(),
            claims: claims.as_object().unwrap().clone(),
            attribute_claims: vec![],
            expires_at: 0,
            clock_skew_seconds: 0,
        };
        let no_jti = v(json!({}));
        assert_eq!(
            no_jti.replay_key("h.p.sig-one"),
            no_jti.replay_key("h.p.sig-two")
        );
        assert_ne!(no_jti.replay_key("h.p.s"), no_jti.replay_key("h.q.s"));
        let with_jti = v(json!({"jti": "j1"}));
        assert_eq!(with_jti.replay_key("a.b.c"), "idp\nhttps://idp\nj1");
    }
}
