//! Client authentication of agents (`[[agents]]`) and policy enforcement points (`[[peps]]`).
//!
//! Used for agents at `POST /token` (IdP intake and, with `[token] require_actor_auth`, every
//! exchange) and for PEPs at the AuthZEN endpoints (an unsigned body chain with
//! `[authzen] allow_unsigned_chain`, or diagnostics).
//!
//! A client authenticates in exactly one of two ways per request (RFC 6749 §2.3):
//!
//! - **Client secret.** HTTP Basic (RFC 6749 §2.3.1: id and secret form-encoded, then base64)
//!   or two body fields, never both. Secrets are stored as the lowercase hex SHA-256 of the
//!   secret (`secret_sha256`) and compared in constant time, against a dummy hash for unknown
//!   ids and for entries without a secret, so timing does not reveal which ids exist.
//! - **`private_key_jwt`** (RFC 7523 §2.2 and §3). `client_assertion_type` =
//!   `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion` = a JWT
//!   signed by one of the keys in the entry's `jwks`. See [`Clients::verify_assertion`] for the
//!   checks. The assertion's `jti` is recorded in the replay store
//!   ([`crate::replay::ReplayCache`]) when [`Authenticated::commit`] runs, so an assertion
//!   authenticates one request, across restarts when the store is a database file.
//!
//! An entry may hold a secret, keys, or both; it can only be authenticated by what it holds.
//! Sending a secret and an assertion together is `multiple_client_auth`.

use std::str::FromStr;

use axum::http::{header, HeaderMap, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub(crate) use attenuo_token::client_assertion::CLIENT_ASSERTION_TYPE;

use crate::config::{AgentConfig, CLIENT_ASSERTION_ALGS};
use crate::error::ApiError;
use crate::replay::ReplayCache;
use crate::routes::admin::constant_time_eq;

/// Which list is being authenticated against; only changes error texts and sub-codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientKind {
    /// `[[agents]]`, body fields `client_id` / `client_secret`.
    Agent,
    /// `[[peps]]`, body fields `pep_id` / `pep_secret`.
    Pep,
}

impl ClientKind {
    fn section(self) -> &'static str {
        match self {
            ClientKind::Agent => "[[agents]]",
            ClientKind::Pep => "[[peps]]",
        }
    }

    fn fields(self) -> (&'static str, &'static str) {
        match self {
            ClientKind::Agent => ("client_id", "client_secret"),
            ClientKind::Pep => ("pep_id", "pep_secret"),
        }
    }

    fn none_configured(self) -> &'static str {
        match self {
            ClientKind::Agent => "no_agents_configured",
            ClientKind::Pep => "no_peps_configured",
        }
    }

    /// The namespace of this list's assertion `jti`s in the replay store.
    fn replay_namespace(self) -> &'static str {
        match self {
            ClientKind::Agent => "agent",
            ClientKind::Pep => "pep",
        }
    }
}

/// How a client authenticated; the value recorded as `agent_auth` / `actor_auth` in the
/// arguments of the audit records of `POST /token`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientMethod {
    /// A client secret (HTTP Basic or the body fields).
    Secret,
    /// A `private_key_jwt` client assertion.
    PrivateKeyJwt,
}

impl ClientMethod {
    /// `client_secret` or `private_key_jwt`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ClientMethod::Secret => "client_secret",
            ClientMethod::PrivateKeyJwt => "private_key_jwt",
        }
    }

    /// The method together with an actor token that named the same agent.
    pub(crate) fn with_actor_token(self) -> &'static str {
        match self {
            ClientMethod::Secret => "actor_token+client_secret",
            ClientMethod::PrivateKeyJwt => "actor_token+private_key_jwt",
        }
    }
}

pub(crate) fn invalid_request(description: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError::bad_request("invalid_request", detail).with_description(description)
}

pub(crate) fn invalid_client(description: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid_client", detail).with_description(description)
}

/// Client credentials from HTTP Basic (RFC 6749 §2.3.1, form-encoded id and secret).
/// `Ok(None)` when there is no `Authorization` header or it is not Basic.
pub(crate) fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, ApiError> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw.to_str().unwrap_or_default();
    let Some((scheme, b64)) = raw.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let bad = || invalid_client("malformed_client_auth", "malformed Basic credentials");
    let decoded = STANDARD.decode(b64.trim()).map_err(|_| bad())?;
    let decoded = String::from_utf8(decoded).map_err(|_| bad())?;
    let (id, secret) = decoded.split_once(':').ok_or_else(bad)?;
    let unescape = |s: &str| -> Result<String, ApiError> {
        let pairs: Vec<(String, String)> =
            serde_urlencoded::from_str(&format!("v={s}")).map_err(|_| bad())?;
        Ok(pairs.into_iter().next().map(|(_, v)| v).unwrap_or_default())
    };
    Ok(Some((unescape(id)?, unescape(secret)?)))
}

/// Remove `client_assertion` / `client_assertion_type` from a request body and check them:
/// both or neither (`malformed_request`), and the type is [`CLIENT_ASSERTION_TYPE`]
/// (`client_assertion_type_unsupported`). Returns the assertion.
pub(crate) fn take_client_assertion(
    obj: &mut Map<String, Value>,
) -> Result<Option<String>, ApiError> {
    let take = |obj: &mut Map<String, Value>, k: &str| -> Result<Option<String>, ApiError> {
        match obj.remove(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(invalid_request(
                "malformed_request",
                format!("{k} must be a string"),
            )),
        }
    };
    let assertion = take(obj, "client_assertion")?;
    let assertion_type = take(obj, "client_assertion_type")?;
    match (assertion, assertion_type) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(invalid_request(
            "malformed_request",
            "client_assertion_type is required with client_assertion (RFC 7521 §4.2)",
        )),
        (None, Some(_)) => Err(invalid_request(
            "malformed_request",
            "client_assertion_type without client_assertion",
        )),
        (Some(a), Some(t)) if t == CLIENT_ASSERTION_TYPE => Ok(Some(a)),
        (Some(_), Some(_)) => Err(invalid_request(
            "client_assertion_type_unsupported",
            format!("unsupported client_assertion_type; use `{CLIENT_ASSERTION_TYPE}`"),
        )),
    }
}

/// Did the request present client credentials of either kind: a secret (HTTP Basic or the
/// body field) or an assertion?
pub(crate) fn presented(
    headers: &HeaderMap,
    body_secret: Option<&str>,
    assertion: Option<&str>,
) -> Result<bool, ApiError> {
    Ok(body_secret.is_some() || assertion.is_some() || basic_credentials(headers)?.is_some())
}

/// A public key of a client, bound at startup to the one algorithm it verifies.
#[derive(Clone)]
struct ClientKey {
    kid: Option<String>,
    alg: Algorithm,
    key: DecodingKey,
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

/// One `[[agents]]` or `[[peps]]` entry, validated.
#[derive(Clone)]
pub struct Client {
    /// The client id.
    pub id: String,
    /// Lowercase hex SHA-256 of the secret, when the entry has one.
    secret_sha256: Option<String>,
    /// The entry's `jwks`; empty when it has none.
    keys: Vec<ClientKey>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("secret", &self.secret_sha256.is_some())
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl Client {
    /// Whether the entry has a secret.
    pub fn has_secret(&self) -> bool {
        self.secret_sha256.is_some()
    }

    /// Whether the entry has keys for `private_key_jwt`.
    pub fn has_keys(&self) -> bool {
        !self.keys.is_empty()
    }
}

/// What a client assertion must satisfy beyond its signature: the server's issuer identifier
/// as `aud`, the most an `exp` may lie ahead, and the clock skew.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionPolicy {
    /// `[issuer] issuer`.
    pub audience: String,
    /// `[token] client_assertion_max_lifetime_seconds`.
    pub max_lifetime_seconds: i64,
    /// `[token] client_assertion_clock_skew_seconds`.
    pub clock_skew_seconds: i64,
}

impl AssertionPolicy {
    /// The policy `config` sets.
    pub fn from_config(config: &crate::config::Config) -> Self {
        let secs = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        Self {
            audience: config.issuer.issuer.clone(),
            max_lifetime_seconds: secs(config.token.client_assertion_max_lifetime_seconds),
            clock_skew_seconds: secs(config.token.client_assertion_clock_skew_seconds),
        }
    }
}

/// The validated `[[agents]]` or `[[peps]]` list, with the assertion policy.
#[derive(Debug, Clone)]
pub struct Clients {
    kind: ClientKind,
    list: Vec<Client>,
    policy: AssertionPolicy,
}

/// Most keys one entry's `jwks` may hold.
pub(crate) const MAX_CLIENT_KEYS: usize = 8;
/// Smallest RSA modulus accepted in a client's `jwks`, in bytes (2048 bits).
const MIN_RSA_MODULUS_BYTES: usize = 256;
/// Longest `jti` accepted in a client assertion, in bytes.
const MAX_JTI_BYTES: usize = 256;
/// Private-key and symmetric-key members of a JWK (RFC 7518 §6.2.2, §6.3.2, §6.4; RFC 8037
/// §2). None of them may appear in a client's `jwks`.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
/// Header `typ` values that mark a JWT as another kind of token.
const FOREIGN_TYPS: &[&str] = &[
    attenuo_token::TOKEN_TYPE,
    "oauth-id-jag+jwt",
    "at+jwt",
    "dpop+jwt",
];

impl Clients {
    /// Validate the `[[agents]]` entries.
    ///
    /// # Errors
    ///
    /// As [`Clients::from_config`].
    pub fn agents(entries: &[AgentConfig], policy: AssertionPolicy) -> anyhow::Result<Self> {
        Self::from_config(ClientKind::Agent, entries, policy)
    }

    /// Validate the `[[peps]]` entries.
    ///
    /// # Errors
    ///
    /// As [`Clients::from_config`].
    pub fn peps(entries: &[AgentConfig], policy: AssertionPolicy) -> anyhow::Result<Self> {
        Self::from_config(ClientKind::Pep, entries, policy)
    }

    /// Validate a list at startup: ids non-empty and unique; at least one of
    /// `secret_sha256` (64 hex characters) and `jwks` (see [`parse_client_jwks`]).
    pub(crate) fn from_config(
        kind: ClientKind,
        entries: &[AgentConfig],
        policy: AssertionPolicy,
    ) -> anyhow::Result<Self> {
        let section = kind.section();
        let mut list: Vec<Client> = Vec::with_capacity(entries.len());
        for a in entries {
            if a.id.is_empty() {
                anyhow::bail!("{section}: id must not be empty");
            }
            if list.iter().any(|b| b.id == a.id) {
                anyhow::bail!("{section}: id `{}` is listed twice", a.id);
            }
            let secret_sha256 = match &a.secret_sha256 {
                None => None,
                Some(h) => {
                    let h = h.to_ascii_lowercase();
                    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                        anyhow::bail!(
                            "{section} `{}`: secret_sha256 must be 64 hex characters",
                            a.id
                        );
                    }
                    Some(h)
                }
            };
            let keys = match &a.jwks {
                None => Vec::new(),
                Some(text) => parse_client_jwks(text)
                    .map_err(|e| anyhow::anyhow!("{section} `{}`: jwks: {e}", a.id))?,
            };
            if secret_sha256.is_none() && keys.is_empty() {
                anyhow::bail!(
                    "{section} `{}`: set secret_sha256, jwks (private_key_jwt), or both",
                    a.id
                );
            }
            list.push(Client {
                id: a.id.clone(),
                secret_sha256,
                keys,
            });
        }
        Ok(Self { kind, list, policy })
    }

    /// No entries.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The entries, in config order.
    pub fn iter(&self) -> impl Iterator<Item = &Client> {
        self.list.iter()
    }

    /// The assertion policy.
    pub fn policy(&self) -> &AssertionPolicy {
        &self.policy
    }

    fn find(&self, id: &str) -> Option<&Client> {
        self.list.iter().find(|c| c.id == id)
    }

    /// Authenticate a client by whichever credential the request carries; see the module
    /// docs. `body_id` / `body_secret` are the body fields ([`ClientKind`] names them),
    /// `assertion` the `client_assertion` taken by [`take_client_assertion`].
    ///
    /// Sub-codes: `client_auth_missing`, `multiple_client_auth`, `malformed_client_auth`,
    /// `client_authentication_failed`, `no_agents_configured` / `no_peps_configured`, and the
    /// `client_assertion_*` codes of [`AssertionError`]. The assertion's single use is recorded
    /// only by [`Authenticated::commit`].
    pub(crate) fn authenticate(
        &self,
        headers: &HeaderMap,
        body_id: Option<&str>,
        body_secret: Option<&str>,
        assertion: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Authenticated, ApiError> {
        let kind = self.kind;
        let (id_field, secret_field) = kind.fields();
        let basic = basic_credentials(headers)?;
        if let Some(assertion) = assertion {
            if basic.is_some() || body_secret.is_some() {
                return Err(invalid_request(
                    "multiple_client_auth",
                    "use either a client secret or client_assertion, not both (RFC 6749 §2.3)",
                ));
            }
            if self.is_empty() {
                return Err(invalid_client(
                    kind.none_configured(),
                    format!("no {} are configured", kind.section()),
                ));
            }
            let v = self.verify_assertion(assertion, body_id, now)?;
            return Ok(Authenticated {
                id: v.client,
                method: ClientMethod::PrivateKeyJwt,
                replay: Some((v.replay_key, v.replay_until)),
            });
        }
        let (id, secret) = match (basic, body_secret) {
            (Some(_), Some(_)) => {
                return Err(invalid_request(
                    "multiple_client_auth",
                    format!("use either HTTP Basic or {secret_field} in the body, not both"),
                ))
            }
            (Some((id, secret)), None) => {
                if body_id.is_some_and(|c| c != id) {
                    return Err(invalid_client(
                        "client_authentication_failed",
                        format!("{id_field} differs from the Basic credentials"),
                    ));
                }
                (id, secret)
            }
            (None, Some(secret)) => match body_id {
                Some(id) => (id.to_owned(), secret.to_owned()),
                None => {
                    return Err(invalid_client(
                        "client_auth_missing",
                        format!("{id_field} is required"),
                    ))
                }
            },
            (None, None) => {
                return Err(invalid_client(
                    "client_auth_missing",
                    format!(
                        "client authentication is required (HTTP Basic, {id_field} and \
                         {secret_field}, or client_assertion)"
                    ),
                ))
            }
        };
        if self.is_empty() {
            return Err(invalid_client(
                kind.none_configured(),
                format!("no {} are configured", kind.section()),
            ));
        }
        let presented = hex::encode(Sha256::digest(secret.as_bytes()));
        let known = self.find(&id);
        // Compare against something even for unknown ids and for entries without a secret, so
        // timing does not reveal which exist or how they authenticate.
        let expected = known
            .and_then(|a| a.secret_sha256.as_deref())
            .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
        let ok = constant_time_eq(presented.as_bytes(), expected.as_bytes());
        match known {
            Some(a) if ok && a.secret_sha256.is_some() => Ok(Authenticated {
                id: a.id.clone(),
                method: ClientMethod::Secret,
                replay: None,
            }),
            _ => Err(invalid_client(
                "client_authentication_failed",
                "unknown client or wrong secret",
            )),
        }
    }

    /// Verify a `private_key_jwt` client assertion (RFC 7523 §3), in this order:
    ///
    /// 1. Three base64url JSON parts; a header `typ` naming another kind of token (a
    ///    delegation token, an ID-JAG, an access token, a DPoP proof) is refused.
    /// 2. `iss` and `sub` are non-empty strings and equal, and equal the request's
    ///    `client_id` (`pep_id`) when it names one.
    /// 3. `sub` names an entry with keys; otherwise `client_authentication_failed`, as for a
    ///    wrong secret.
    /// 4. `alg` is in [`CLIENT_ASSERTION_ALGS`] (never `none` or an HMAC); the key is the one
    ///    with the header's `kid`, or the entry's only key when there is no `kid`; and the key
    ///    is for that `alg`.
    /// 5. The signature.
    /// 6. `aud` is the server's issuer identifier (`[issuer] issuer`): a string equal to it,
    ///    or a non-empty array whose every element equals it. The token endpoint URL and any
    ///    other value are refused.
    /// 7. `exp` is required, not past (with the skew), and at most
    ///    `client_assertion_max_lifetime_seconds` (plus the skew) ahead; `nbf` and `iat`, when
    ///    present, are not in the future (with the skew).
    /// 8. `jti` is a required non-empty string of at most 256 bytes.
    pub(crate) fn verify_assertion(
        &self,
        assertion: &str,
        body_id: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<VerifiedAssertion, AssertionError> {
        let (header, payload) = peek(assertion)?;
        if let Some(typ) = header.get("typ").and_then(Value::as_str) {
            if FOREIGN_TYPS.iter().any(|t| crate::idp::typ_is(typ, t)) {
                return Err(AssertionError::Malformed("typ names another kind of token"));
            }
        }
        let str_claim = |name: &str| {
            payload
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        };
        let (Some(iss), Some(sub)) = (str_claim("iss"), str_claim("sub")) else {
            return Err(AssertionError::SubjectMismatch("iss and sub are required"));
        };
        if iss != sub {
            return Err(AssertionError::SubjectMismatch("iss and sub differ"));
        }
        if body_id.is_some_and(|id| id != sub) {
            return Err(AssertionError::SubjectMismatch(
                "the request's client id is not the assertion's sub",
            ));
        }
        let client = self
            .find(sub)
            .filter(|c| c.has_keys())
            .ok_or(AssertionError::UnknownClient)?;

        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .and_then(|a| Algorithm::from_str(a).ok())
            .filter(|a| allowed_alg(*a))
            .ok_or(AssertionError::UnsupportedAlg)?;
        let key = match header.get("kid") {
            None | Some(Value::Null) => match client.keys.as_slice() {
                [only] => only,
                _ => return Err(AssertionError::UnknownKid),
            },
            Some(Value::String(kid)) => client
                .keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid.as_str()))
                .ok_or(AssertionError::UnknownKid)?,
            Some(_) => return Err(AssertionError::Malformed("kid is not a string")),
        };
        if key.alg != alg {
            return Err(AssertionError::UnsupportedAlg);
        }

        let mut validation = Validation::new(key.alg);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<Map<String, Value>>(assertion, &key.key, &validation)
            .map_err(|_| AssertionError::BadSignature)?
            .claims;
        // The verified payload is the one peeked at; `iss` and `sub` were checked on it.

        let p = &self.policy;
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => *a == p.audience,
            Some(Value::Array(list)) => {
                !list.is_empty() && list.iter().all(|a| a.as_str() == Some(p.audience.as_str()))
            }
            _ => false,
        };
        if !aud_ok {
            return Err(AssertionError::AudienceMismatch);
        }
        let now = now.unix_timestamp();
        let skew = p.clock_skew_seconds;
        let exp =
            crate::idp::numeric_date(&claims, "exp").ok_or(AssertionError::MissingClaim("exp"))?;
        if now >= exp.saturating_add(skew) {
            return Err(AssertionError::Expired);
        }
        if exp
            > now
                .saturating_add(p.max_lifetime_seconds)
                .saturating_add(skew)
        {
            return Err(AssertionError::LifetimeTooLong);
        }
        for name in ["nbf", "iat"] {
            if crate::idp::numeric_date(&claims, name).is_some_and(|t| t > now.saturating_add(skew))
            {
                return Err(AssertionError::NotYetValid);
            }
        }
        let jti = match claims.get("jti").and_then(Value::as_str) {
            Some(j) if !j.is_empty() && j.len() <= MAX_JTI_BYTES => j,
            Some(j) if !j.is_empty() => return Err(AssertionError::Malformed("jti is too long")),
            _ => return Err(AssertionError::MissingClaim("jti")),
        };
        Ok(VerifiedAssertion {
            client: client.id.clone(),
            replay_key: format!(
                "client-assertion\n{}\n{}\n{jti}",
                self.kind.replay_namespace(),
                client.id
            ),
            replay_until: exp.saturating_add(skew),
        })
    }
}

/// Is `alg` one of [`CLIENT_ASSERTION_ALGS`]?
fn allowed_alg(alg: Algorithm) -> bool {
    CLIENT_ASSERTION_ALGS
        .iter()
        .any(|a| Algorithm::from_str(a).is_ok_and(|x| x == alg))
}

/// A client assertion whose signature and claims have been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedAssertion {
    /// The client id (`sub`).
    pub(crate) client: String,
    /// The replay store key: client kind, client id and `jti`, under a prefix of its own.
    pub(crate) replay_key: String,
    /// `exp` plus the skew: the last instant the assertion could be accepted.
    pub(crate) replay_until: i64,
}

/// A client whose credential has been checked. An assertion is used up only by
/// [`Authenticated::commit`], which every caller must run before acting on the request.
#[must_use = "an assertion authenticates the request only once its use is recorded: call commit"]
#[derive(Debug)]
pub(crate) struct Authenticated {
    id: String,
    method: ClientMethod,
    replay: Option<(String, i64)>,
}

impl Authenticated {
    /// The client id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// How the client authenticated.
    pub(crate) fn method(&self) -> ClientMethod {
        self.method
    }

    /// Record the assertion's `jti` as used (nothing for a secret) and return the client id.
    /// A store write: call it on the blocking pool.
    ///
    /// # Errors
    ///
    /// `client_assertion_replayed` (401 `invalid_client`) for an assertion already used;
    /// `replay_cache_full` and `replay_store_unavailable` (503) as for every single-use
    /// credential ([`ReplayCache::use_once`]).
    pub(crate) fn commit(
        self,
        replay: &ReplayCache,
        now: OffsetDateTime,
    ) -> Result<String, ApiError> {
        if let Some((key, until)) = &self.replay {
            replay.use_once(key, *until, now).map_err(|e| {
                if e.description == Some("replayed") {
                    AssertionError::Replayed.into()
                } else {
                    e
                }
            })?;
        }
        Ok(self.id)
    }
}

/// A refused client assertion. The texts are fixed: nothing from the assertion is echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AssertionError {
    #[error("client_assertion is not a well-formed JWT: {0}")]
    Malformed(&'static str),
    #[error("client_assertion iss and sub must both name the client, and match the request's client id: {0}")]
    SubjectMismatch(&'static str),
    #[error("unknown client, or a client without keys")]
    UnknownClient,
    #[error("client_assertion algorithm is not accepted for the client's keys")]
    UnsupportedAlg,
    #[error("client_assertion kid names none of the client's keys (or is missing and the client has several)")]
    UnknownKid,
    #[error("client_assertion signature does not verify")]
    BadSignature,
    #[error("client_assertion aud must be this server's issuer identifier, and nothing else")]
    AudienceMismatch,
    #[error("client_assertion claim `{0}` is missing or has the wrong type")]
    MissingClaim(&'static str),
    #[error("client_assertion expired")]
    Expired,
    #[error(
        "client_assertion exp is further ahead than [token] client_assertion_max_lifetime_seconds"
    )]
    LifetimeTooLong,
    #[error("client_assertion is not valid yet (iat or nbf in the future)")]
    NotYetValid,
    #[error("client_assertion was already used; sign a new one with a fresh jti")]
    Replayed,
}

impl AssertionError {
    /// The stable `error_description` sub-code.
    pub(crate) fn description(&self) -> &'static str {
        match self {
            AssertionError::Malformed(_) => "client_assertion_malformed",
            AssertionError::SubjectMismatch(_) => "client_assertion_subject_mismatch",
            AssertionError::UnknownClient => "client_authentication_failed",
            AssertionError::UnsupportedAlg => "client_assertion_unsupported_alg",
            AssertionError::UnknownKid => "client_assertion_unknown_kid",
            AssertionError::BadSignature => "client_assertion_bad_signature",
            AssertionError::AudienceMismatch => "client_assertion_audience_mismatch",
            AssertionError::MissingClaim(_) => "client_assertion_missing_claim",
            AssertionError::Expired => "client_assertion_expired",
            AssertionError::LifetimeTooLong => "client_assertion_lifetime_too_long",
            AssertionError::NotYetValid => "client_assertion_not_yet_valid",
            AssertionError::Replayed => "client_assertion_replayed",
        }
    }
}

impl From<AssertionError> for ApiError {
    fn from(e: AssertionError) -> Self {
        let d = e.description();
        tracing::debug!(reason = d, detail = %e, "client assertion refused");
        invalid_client(d, e.to_string())
    }
}

type JsonObject = Map<String, Value>;

/// Decode header and payload without verifying anything.
fn peek(token: &str) -> Result<(JsonObject, JsonObject), AssertionError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AssertionError::Malformed(
            "expected three dot-separated parts",
        ));
    };
    let part = |s: &str, what: &'static str| -> Result<JsonObject, AssertionError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| AssertionError::Malformed(what))?;
        serde_json::from_slice(&bytes).map_err(|_| AssertionError::Malformed(what))
    };
    Ok((
        part(h, "header is not base64url JSON")?,
        part(p, "payload is not base64url JSON")?,
    ))
}

/// Parse and check a client's `jwks` (a JWK Set as JSON text) at startup. Refused: text that
/// is not a JSON object with a `keys` array, an empty set, more than [`MAX_CLIENT_KEYS`] keys,
/// a key with a private or symmetric member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`; the
/// message names the member, never its value), a symmetric (`oct`) key, a key whose `use` is
/// not `sig`, a key of a type, curve or `alg` outside [`CLIENT_ASSERTION_ALGS`] (RSA with
/// RS256, P-256 with ES256, Ed25519 with EdDSA), an RSA modulus under 2048 bits, a `kid`
/// listed twice, and a key without `kid` in a set of several.
fn parse_client_jwks(text: &str) -> Result<Vec<ClientKey>, String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("not JSON ({e})"))?;
    let keys = doc
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("must be a JWK Set: an object with a `keys` array")?;
    if keys.is_empty() {
        return Err("the key set is empty".into());
    }
    if keys.len() > MAX_CLIENT_KEYS {
        return Err(format!("at most {MAX_CLIENT_KEYS} keys"));
    }
    let mut out: Vec<ClientKey> = Vec::with_capacity(keys.len());
    for (i, raw) in keys.iter().enumerate() {
        let obj = raw
            .as_object()
            .ok_or_else(|| format!("key {i} is not a JSON object"))?;
        let label = match obj.get("kid").and_then(Value::as_str) {
            Some(kid) => format!("key {i} (kid `{kid}`)"),
            None => format!("key {i}"),
        };
        if obj.get("kty").and_then(Value::as_str) == Some("oct") {
            return Err(format!(
                "{label} is a symmetric (oct) key; only public keys of {CLIENT_ASSERTION_ALGS:?} \
                 are accepted"
            ));
        }
        if let Some(m) = PRIVATE_MEMBERS.iter().find(|m| obj.contains_key(**m)) {
            return Err(format!(
                "{label} contains the private key member `{m}`: put only the public key in the \
                 config, and keep the private key with the client"
            ));
        }
        if obj
            .get("kid")
            .is_some_and(|k| !k.is_string() || k.as_str() == Some(""))
        {
            return Err(format!("{label}: kid must be a non-empty string"));
        }
        let jwk: Jwk = serde_json::from_value(raw.clone())
            .map_err(|e| format!("{label} is not a JWK ({e})"))?;
        if let Some(u) = obj.get("use") {
            if u.as_str() != Some("sig") {
                return Err(format!("{label}: use must be `sig`"));
            }
        }
        let alg = key_alg(obj, &jwk).map_err(|e| format!("{label}: {e}"))?;
        let key =
            DecodingKey::from_jwk(&jwk).map_err(|e| format!("{label} is not usable ({e})"))?;
        let kid = jwk.common.key_id.clone();
        if let Some(kid) = &kid {
            if out.iter().any(|k| k.kid.as_deref() == Some(kid)) {
                return Err(format!("kid `{kid}` is listed twice"));
            }
        }
        out.push(ClientKey { kid, alg, key });
    }
    if out.len() > 1 && out.iter().any(|k| k.kid.is_none()) {
        return Err("with more than one key, every key needs a kid".into());
    }
    Ok(out)
}

/// The one algorithm a client key verifies: from its type and curve, which its `alg`, when
/// present, must agree with.
fn key_alg(obj: &Map<String, Value>, jwk: &Jwk) -> Result<Algorithm, String> {
    let by_type = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => {
            let n = URL_SAFE_NO_PAD
                .decode(&rsa.n)
                .map_err(|_| "RSA n is not base64url".to_string())?;
            let len = n.iter().skip_while(|b| **b == 0).count();
            if len < MIN_RSA_MODULUS_BYTES {
                return Err("RSA keys must be at least 2048 bits".into());
            }
            Algorithm::RS256
        }
        AlgorithmParameters::EllipticCurve(ec) if ec.curve == EllipticCurve::P256 => {
            Algorithm::ES256
        }
        AlgorithmParameters::OctetKeyPair(okp) if okp.curve == EllipticCurve::Ed25519 => {
            Algorithm::EdDSA
        }
        _ => {
            return Err(format!(
                "unsupported key type or curve; accepted: RSA (RS256), EC P-256 (ES256), OKP \
                 Ed25519 (EdDSA), the server's algorithms {CLIENT_ASSERTION_ALGS:?}"
            ))
        }
    };
    match obj.get("alg") {
        None => Ok(by_type),
        Some(Value::String(a)) if Algorithm::from_str(a).is_ok_and(|x| x == by_type) => Ok(by_type),
        Some(Value::String(a)) => Err(format!(
            "alg `{a}` is not accepted for this key; the server accepts {CLIENT_ASSERTION_ALGS:?}, \
             each with its own key type"
        )),
        Some(_) => Err("alg must be a string".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use attenuo_audit::{MemoryLeaseStore, SqliteLeaseStore};
    use attenuo_token::DpopKey;
    use axum::http::HeaderValue;
    use serde_json::json;

    const AUD: &str = "https://attenuo.example";

    fn policy() -> AssertionPolicy {
        AssertionPolicy {
            audience: AUD.into(),
            max_lifetime_seconds: 300,
            clock_skew_seconds: 60,
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_000_000).unwrap()
    }

    fn sha(s: &str) -> String {
        hex::encode(Sha256::digest(s.as_bytes()))
    }

    fn peps() -> Clients {
        Clients::peps(
            &[AgentConfig::with_secret_sha256(
                "gateway",
                sha("pep-s3cret"),
            )],
            policy(),
        )
        .unwrap()
    }

    fn code<T: std::fmt::Debug>(r: Result<T, ApiError>) -> &'static str {
        r.unwrap_err().description.unwrap()
    }

    /// Authenticate with a secret only, to the client id (no replay store needed).
    fn secret_auth(
        c: &Clients,
        h: &HeaderMap,
        id: Option<&str>,
        secret: Option<&str>,
    ) -> Result<String, ApiError> {
        c.authenticate(h, id, secret, None, now())
            .map(|a| a.id().to_owned())
    }

    fn basic(id: &str, secret: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Basic {}",
                STANDARD.encode(format!("{id}:{secret}"))
            ))
            .unwrap(),
        );
        h
    }

    #[test]
    fn pep_credentials_from_body_or_basic() {
        let h = HeaderMap::new();
        let auth = |id, secret| secret_auth(&peps(), &h, id, secret);
        assert_eq!(
            auth(Some("gateway"), Some("pep-s3cret")).unwrap(),
            "gateway"
        );
        assert_eq!(
            code(auth(Some("gateway"), Some("nope"))),
            "client_authentication_failed"
        );
        assert_eq!(code(auth(None, None)), "client_auth_missing");
        let none = Clients::peps(&[], policy()).unwrap();
        assert_eq!(
            code(secret_auth(&none, &h, Some("gateway"), Some("pep-s3cret"))),
            "no_peps_configured"
        );
        let b = basic("gateway", "pep-s3cret");
        assert_eq!(secret_auth(&peps(), &b, None, None).unwrap(), "gateway");
        assert_eq!(
            code(secret_auth(&peps(), &b, Some("other"), None)),
            "client_authentication_failed"
        );
    }

    // --- keys ---------------------------------------------------------------------------

    fn ed_key() -> DpopKey {
        DpopKey::generate().unwrap()
    }

    /// The public JWK of `key` with `kid`.
    fn public(key: &DpopKey, kid: Option<&str>) -> Value {
        let mut jwk = key.public_jwk().clone();
        if let Some(kid) = kid {
            jwk["kid"] = kid.into();
        }
        jwk
    }

    fn jwks(keys: &[Value]) -> String {
        json!({ "keys": keys }).to_string()
    }

    /// A 2048-bit RSA public key (the modulus need not be a real one to parse).
    fn rsa_jwk(kid: &str, bytes: usize) -> Value {
        let mut n = vec![0xC5u8; bytes];
        n[bytes - 1] = 0x01;
        json!({"kty": "RSA", "kid": kid, "n": URL_SAFE_NO_PAD.encode(n), "e": "AQAB"})
    }

    fn parse_err(keys: Value) -> String {
        match parse_client_jwks(&keys.to_string()) {
            Ok(_) => panic!("accepted {keys}"),
            Err(e) => e,
        }
    }

    #[test]
    fn jwks_accepts_public_keys_of_the_allowed_algorithms() {
        let ed = public(&ed_key(), Some("ed"));
        let ec = json!({"kty": "EC", "crv": "P-256", "kid": "ec", "alg": "ES256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"});
        let keys = parse_client_jwks(&jwks(&[ed, ec, rsa_jwk("rsa", 256)])).unwrap();
        let algs: Vec<_> = keys.iter().map(|k| k.alg).collect();
        assert_eq!(algs, [Algorithm::EdDSA, Algorithm::ES256, Algorithm::RS256]);
        // One key needs no kid.
        assert!(parse_client_jwks(&jwks(&[public(&ed_key(), None)])).is_ok());
    }

    #[test]
    fn jwks_refusals_name_the_problem_and_never_a_private_value() {
        let key = ed_key();
        let private = key.private_jwk();
        let d = private["d"].as_str().unwrap().to_owned();
        let e = parse_err(json!({"keys": [private]}));
        assert!(e.contains("private key member `d`"), "{e}");
        assert!(!e.contains(&d), "the private value is echoed: {e}");
        let mut rsa_private = rsa_jwk("r", 256);
        rsa_private["p"] = "AQAB".into();
        assert!(parse_err(json!({"keys": [rsa_private]})).contains("member `p`"));
        let e = parse_err(json!({"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}));
        assert!(e.contains("symmetric"), "{e}");
        assert!(!e.contains("c2VjcmV0"), "{e}");
        let mut hs = public(&key, None);
        hs["alg"] = "HS256".into();
        assert!(parse_err(json!({"keys": [hs]})).contains("not accepted"));
        let mut ps = rsa_jwk("r", 256);
        ps["alg"] = "PS256".into();
        assert!(parse_err(json!({"keys": [ps]})).contains("not accepted"));
        let p384 = json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"});
        assert!(parse_err(json!({"keys": [p384]})).contains("unsupported key type"));
        assert!(parse_err(json!({"keys": [rsa_jwk("small", 128)]})).contains("2048"));
        let mut enc = public(&key, None);
        enc["use"] = "enc".into();
        assert!(parse_err(json!({"keys": [enc]})).contains("use must be `sig`"));
        let dup = public(&key, Some("same"));
        assert!(
            parse_err(json!({"keys": [dup.clone(), public(&ed_key(), Some("same"))]}))
                .contains("listed twice")
        );
        assert!(parse_err(json!({"keys": [dup, public(&ed_key(), None)]}))
            .contains("every key needs a kid"));
        assert!(parse_err(json!({"keys": []})).contains("empty"));
        assert!(parse_err(json!({"nokeys": []})).contains("JWK Set"));
        assert!(parse_client_jwks("not json")
            .unwrap_err()
            .contains("not JSON"));
        let many: Vec<Value> = (0..=MAX_CLIENT_KEYS)
            .map(|i| public(&ed_key(), Some(&format!("k{i}"))))
            .collect();
        assert!(parse_err(json!({ "keys": many })).contains("at most"));
    }

    #[test]
    fn entries_need_a_secret_or_keys() {
        let only_keys = AgentConfig::with_jwks("coder", jwks(&[public(&ed_key(), None)]));
        let c = Clients::agents(&[only_keys], policy()).unwrap();
        assert!(c.iter().next().unwrap().has_keys());
        assert!(!c.iter().next().unwrap().has_secret());
        let neither = AgentConfig {
            id: "coder".into(),
            secret_sha256: None,
            jwks: None,
        };
        let e = Clients::agents(&[neither], policy())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("[[agents]] `coder`") && e.contains("jwks"),
            "{e}"
        );
        let bad = AgentConfig::with_jwks("coder", jwks(&[ed_key().private_jwk()]));
        let e = Clients::peps(&[bad], policy()).unwrap_err().to_string();
        assert!(e.starts_with("[[peps]] `coder`: jwks:"), "{e}");
    }

    // --- assertions ---------------------------------------------------------------------

    struct Signer {
        key: DpopKey,
        kid: Option<&'static str>,
    }

    impl Signer {
        fn sign(&self, claims: &Value) -> String {
            let mut header = json!({"alg": self.key.alg(), "typ": "client-authentication+jwt"});
            if let Some(kid) = self.kid {
                header["kid"] = kid.into();
            }
            self.key.sign_jws(&header, claims)
        }
    }

    fn claims(client: &str) -> Value {
        json!({"iss": client, "sub": client, "aud": AUD, "jti": "j-1",
               "iat": 1_000_000, "exp": 1_000_060})
    }

    fn patched(client: &str, patch: &[(&str, Value)], drop: &[&str]) -> Value {
        let mut c = claims(client);
        for (k, v) in patch {
            c[*k] = v.clone();
        }
        for k in drop {
            c.as_object_mut().unwrap().remove(*k);
        }
        c
    }

    /// `coder` with two keys (rotation), `solo` with one key and no kid, `secretive` with a
    /// secret only, `both` with a secret and a key.
    fn setup() -> (Clients, Signer, Signer, Signer, Signer) {
        let (old, new, solo, both) = (ed_key(), ed_key(), ed_key(), ed_key());
        let clients = Clients::agents(
            &[
                AgentConfig::with_jwks(
                    "coder",
                    jwks(&[public(&old, Some("2026-10")), public(&new, Some("2026-11"))]),
                ),
                AgentConfig::with_jwks("solo", jwks(&[public(&solo, None)])),
                AgentConfig::with_secret_sha256("secretive", sha("s3cret")),
                AgentConfig {
                    id: "both".into(),
                    secret_sha256: Some(sha("b0th")),
                    jwks: Some(jwks(&[public(&both, Some("b"))])),
                },
            ],
            policy(),
        )
        .unwrap();
        (
            clients,
            Signer {
                key: old,
                kid: Some("2026-10"),
            },
            Signer {
                key: new,
                kid: Some("2026-11"),
            },
            Signer {
                key: solo,
                kid: None,
            },
            Signer {
                key: both,
                kid: Some("b"),
            },
        )
    }

    fn verify(
        c: &Clients,
        a: &str,
        body_id: Option<&str>,
    ) -> Result<VerifiedAssertion, &'static str> {
        c.verify_assertion(a, body_id, now())
            .map_err(|e| e.description())
    }

    #[test]
    fn a_valid_assertion_authenticates_with_either_rotated_key() {
        let (c, old, new, solo, both) = setup();
        for s in [&old, &new] {
            let v = verify(&c, &s.sign(&claims("coder")), Some("coder")).unwrap();
            assert_eq!(v.client, "coder");
            assert_eq!(v.replay_key, "client-assertion\nagent\ncoder\nj-1");
            assert_eq!(v.replay_until, 1_000_120);
        }
        // No kid: tried only because the entry has exactly one key.
        assert_eq!(
            verify(&c, &solo.sign(&claims("solo")), None)
                .unwrap()
                .client,
            "solo"
        );
        // An `aud` array holding only the issuer identifier.
        let arr = patched("coder", &[("aud", json!([AUD]))], &[]);
        assert!(verify(&c, &new.sign(&arr), None).is_ok());
        // `nbf`, `iat` and `exp` within the skew; float dates.
        let skewed = patched(
            "coder",
            &[
                ("iat", 1_000_050.into()),
                ("nbf", json!(1_000_030.5)),
                ("exp", 1_000_350.into()),
            ],
            &[],
        );
        assert!(verify(&c, &new.sign(&skewed), None).is_ok());
        // `iat` is optional.
        assert!(verify(&c, &new.sign(&patched("coder", &[], &["iat"])), None).is_ok());
        let h = HeaderMap::new();
        let a = both.sign(&claims("both"));
        let auth = c.authenticate(&h, None, None, Some(&a), now()).unwrap();
        assert_eq!(
            (auth.id(), auth.method()),
            ("both", ClientMethod::PrivateKeyJwt)
        );
        let auth = c
            .authenticate(&h, Some("both"), Some("b0th"), None, now())
            .unwrap();
        assert_eq!((auth.id(), auth.method()), ("both", ClientMethod::Secret));
    }

    #[test]
    fn every_refusal_has_its_code() {
        let (c, old, new, solo, _) = setup();
        let sign = |cl: Value| new.sign(&cl);
        let v = |a: &str| verify(&c, a, None).unwrap_err();
        // Malformed.
        assert_eq!(v("a.b"), "client_assertion_malformed");
        assert_eq!(v("!!.!!.!!"), "client_assertion_malformed");
        let foreign = new.key.sign_jws(
            &json!({"alg": "EdDSA", "kid": "2026-11", "typ": "attenuo+jwt"}),
            &claims("coder"),
        );
        assert_eq!(v(&foreign), "client_assertion_malformed");
        // iss / sub.
        assert_eq!(
            v(&sign(patched("coder", &[("iss", "solo".into())], &[]))),
            "client_assertion_subject_mismatch"
        );
        assert_eq!(
            v(&sign(patched("coder", &[], &["iss"]))),
            "client_assertion_subject_mismatch"
        );
        assert_eq!(
            v(&sign(patched("coder", &[], &["sub"]))),
            "client_assertion_subject_mismatch"
        );
        assert_eq!(
            verify(&c, &sign(claims("coder")), Some("solo")).unwrap_err(),
            "client_assertion_subject_mismatch"
        );
        // Unknown client, and a client without keys, look like a wrong secret.
        assert_eq!(v(&sign(claims("ghost"))), "client_authentication_failed");
        assert_eq!(
            v(&sign(claims("secretive"))),
            "client_authentication_failed"
        );
        // kid.
        let other_kid = new
            .key
            .sign_jws(&json!({"alg": "EdDSA", "kid": "nope"}), &claims("coder"));
        assert_eq!(v(&other_kid), "client_assertion_unknown_kid");
        let no_kid = new.key.sign_jws(&json!({"alg": "EdDSA"}), &claims("coder"));
        assert_eq!(v(&no_kid), "client_assertion_unknown_kid");
        // Signature: the other rotated key's kid, signed by the new key; another client's key.
        let swapped = new
            .key
            .sign_jws(&json!({"alg": "EdDSA", "kid": "2026-10"}), &claims("coder"));
        assert_eq!(v(&swapped), "client_assertion_bad_signature");
        let by_solo = solo
            .key
            .sign_jws(&json!({"alg": "EdDSA", "kid": "2026-11"}), &claims("coder"));
        assert_eq!(v(&by_solo), "client_assertion_bad_signature");
        let mut tampered = old.sign(&claims("coder"));
        tampered.push('A');
        assert_eq!(v(&tampered), "client_assertion_bad_signature");
        // Audience: the token endpoint URL, another server, an extra value, an empty array.
        for aud in [
            json!(format!("{AUD}/token")),
            json!("https://other.example"),
            json!([AUD, "https://other.example"]),
            json!([]),
            json!(null),
        ] {
            assert_eq!(
                v(&sign(patched("coder", &[("aud", aud.clone())], &[]))),
                "client_assertion_audience_mismatch",
                "{aud}"
            );
        }
        // Time.
        assert_eq!(
            v(&sign(patched("coder", &[], &["exp"]))),
            "client_assertion_missing_claim"
        );
        assert_eq!(
            v(&sign(patched("coder", &[("exp", "soon".into())], &[]))),
            "client_assertion_missing_claim"
        );
        assert_eq!(
            v(&sign(patched("coder", &[("exp", 999_940.into())], &[]))),
            "client_assertion_expired"
        );
        assert_eq!(
            v(&sign(patched("coder", &[("exp", 1_000_361.into())], &[]))),
            "client_assertion_lifetime_too_long"
        );
        assert_eq!(
            v(&sign(patched("coder", &[("nbf", 1_000_061.into())], &[]))),
            "client_assertion_not_yet_valid"
        );
        assert_eq!(
            v(&sign(patched("coder", &[("iat", 1_000_061.into())], &[]))),
            "client_assertion_not_yet_valid"
        );
        // jti.
        assert_eq!(
            v(&sign(patched("coder", &[], &["jti"]))),
            "client_assertion_missing_claim"
        );
        assert_eq!(
            v(&sign(patched("coder", &[("jti", "".into())], &[]))),
            "client_assertion_missing_claim"
        );
        assert_eq!(
            v(&sign(patched(
                "coder",
                &[("jti", "x".repeat(257).into())],
                &[]
            ))),
            "client_assertion_malformed"
        );
    }

    /// Algorithm confusion: `alg: none`, an HMAC keyed with the public key's bytes, and an
    /// allowed algorithm the key is not for.
    #[test]
    fn algorithm_confusion_is_refused() {
        let (c, _, new, _, _) = setup();
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let none = format!(
            "{}.{}.",
            enc(&json!({"alg": "none", "kid": "2026-11"})),
            enc(&claims("coder"))
        );
        assert_eq!(
            verify(&c, &none, None).unwrap_err(),
            "client_assertion_unsupported_alg"
        );
        let x = URL_SAFE_NO_PAD
            .decode(new.key.public_jwk()["x"].as_str().unwrap())
            .unwrap();
        for secret in [x.clone(), new.key.public_jwk().to_string().into_bytes()] {
            let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
            header.kid = Some("2026-11".into());
            let hs = jsonwebtoken::encode(
                &header,
                &claims("coder"),
                &jsonwebtoken::EncodingKey::from_secret(&secret),
            )
            .unwrap();
            assert_eq!(
                verify(&c, &hs, None).unwrap_err(),
                "client_assertion_unsupported_alg"
            );
        }
        // ES256 is allowed, but not for an Ed25519 key.
        let es = new
            .key
            .sign_jws(&json!({"alg": "ES256", "kid": "2026-11"}), &claims("coder"));
        assert_eq!(
            verify(&c, &es, None).unwrap_err(),
            "client_assertion_unsupported_alg"
        );
        let ps = new
            .key
            .sign_jws(&json!({"alg": "PS256", "kid": "2026-11"}), &claims("coder"));
        assert_eq!(
            verify(&c, &ps, None).unwrap_err(),
            "client_assertion_unsupported_alg"
        );
    }

    /// A fresh P-256 key in the token crate's `DpopKey`, which signs ES256. `ring` makes the
    /// key; its private scalar is read out of the PKCS#8 document (the RFC 5915 ECPrivateKey:
    /// version 1, then the 32-byte key as an OCTET STRING) and `from_jwk` checks that it
    /// matches the public point.
    fn ec_key() -> DpopKey {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let der = pkcs8.as_ref();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng).unwrap();
        let point = pair.public_key().as_ref();
        let at = der
            .windows(5)
            .position(|w| w == [0x02, 0x01, 0x01, 0x04, 0x20])
            .unwrap()
            + 5;
        DpopKey::from_jwk(&json!({
            "kty": "EC", "crv": "P-256",
            "d": URL_SAFE_NO_PAD.encode(&der[at..at + 32]),
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        }))
        .unwrap()
    }

    /// Both elliptic-curve algorithms authenticate end to end, from one entry whose JWKS
    /// holds a P-256 and an Ed25519 key: an ES256 assertion and an EdDSA one. An assertion
    /// really signed with ES256 (by the P-256 key) but naming the Ed25519 key's `kid` is
    /// refused as an unsupported algorithm for that key, not tried against the other key.
    #[test]
    fn es256_and_eddsa_assertions_authenticate() {
        let (ec, ed) = (ec_key(), ed_key());
        assert_eq!((ec.alg(), ed.alg()), ("ES256", "EdDSA"));
        let c = Clients::agents(
            &[AgentConfig::with_jwks(
                "coder",
                jwks(&[public(&ec, Some("p256")), public(&ed, Some("ed25519"))]),
            )],
            policy(),
        )
        .unwrap();
        let ec = Signer {
            key: ec,
            kid: Some("p256"),
        };
        let ed = Signer {
            key: ed,
            kid: Some("ed25519"),
        };
        let h = HeaderMap::new();
        for s in [&ec, &ed] {
            let a = s.sign(&claims("coder"));
            let header: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(a.split('.').next().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(header["alg"], s.key.alg());
            let auth = c.authenticate(&h, None, None, Some(&a), now()).unwrap();
            assert_eq!(
                (auth.id(), auth.method()),
                ("coder", ClientMethod::PrivateKeyJwt)
            );
            assert_eq!(verify(&c, &a, Some("coder")).unwrap().client, "coder");
        }
        let crossed = Signer {
            key: ec.key,
            kid: Some("ed25519"),
        }
        .sign(&claims("coder"));
        assert_eq!(
            verify(&c, &crossed, None).unwrap_err(),
            "client_assertion_unsupported_alg"
        );
        assert_eq!(
            code(c.authenticate(&h, None, None, Some(&crossed), now())),
            "client_assertion_unsupported_alg"
        );
    }

    /// One method per request; and an entry is authenticated only by what it holds.
    #[test]
    fn methods_do_not_mix_or_substitute() {
        let (c, _, new, _, both) = setup();
        let a = new.sign(&claims("coder"));
        let h = HeaderMap::new();
        assert_eq!(
            code(c.authenticate(&h, None, Some("x"), Some(&a), now())),
            "multiple_client_auth"
        );
        assert_eq!(
            code(c.authenticate(&basic("coder", "x"), None, None, Some(&a), now())),
            "multiple_client_auth"
        );
        let b = both.sign(&claims("both"));
        assert_eq!(
            code(c.authenticate(&h, Some("both"), Some("b0th"), Some(&b), now())),
            "multiple_client_auth"
        );
        // A key-only entry has no secret, whatever is sent; an empty secret neither.
        for secret in [
            "",
            "x",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(
                code(secret_auth(&c, &h, Some("coder"), Some(secret))),
                "client_authentication_failed"
            );
        }
        // A secret-only entry cannot be authenticated by an assertion.
        let fake = new.sign(&claims("secretive"));
        assert_eq!(
            code(c.authenticate(&h, None, None, Some(&fake), now())),
            "client_authentication_failed"
        );
        let none = Clients::agents(&[], policy()).unwrap();
        assert_eq!(
            code(none.authenticate(&h, None, None, Some(&a), now())),
            "no_agents_configured"
        );
    }

    #[test]
    fn an_assertion_is_used_once_and_store_faults_fail_closed() {
        let (c, _, new, _, _) = setup();
        let h = HeaderMap::new();
        let a = new.sign(&claims("coder"));
        let replay = ReplayCache::new(Arc::new(MemoryLeaseStore::new()), 10);
        let auth = |a: &str| c.authenticate(&h, None, None, Some(a), now()).unwrap();
        assert_eq!(auth(&a).commit(&replay, now()).unwrap(), "coder");
        // The whole refusal, as it was when the replay was recognised by its sub-code.
        let e = auth(&a).commit(&replay, now()).unwrap_err();
        assert_eq!(
            e,
            ApiError {
                status: StatusCode::UNAUTHORIZED,
                code: "invalid_client".into(),
                detail: "client_assertion was already used; sign a new one with a fresh jti".into(),
                description: Some("client_assertion_replayed"),
                code_only: false,
                decision_id: None,
                retry_after: None,
            }
        );
        // Another jti is fine; the same jti for a PEP of the same name is another key.
        let fresh = new.sign(&patched("coder", &[("jti", "j-2".into())], &[]));
        assert_eq!(auth(&fresh).commit(&replay, now()).unwrap(), "coder");
        // A secret writes nothing.
        let s = Clients::agents(
            &[AgentConfig::with_secret_sha256("secretive", sha("s3cret"))],
            policy(),
        )
        .unwrap();
        let before = replay.len();
        s.authenticate(&h, Some("secretive"), Some("s3cret"), None, now())
            .unwrap()
            .commit(&replay, now())
            .unwrap();
        assert_eq!(replay.len(), before);
        // Full: 503 replay_cache_full, as for every single-use credential.
        let full = ReplayCache::new(Arc::new(MemoryLeaseStore::new()), 1);
        auth(&fresh).commit(&full, now()).unwrap();
        let e = auth(&a).commit(&full, now()).unwrap_err();
        assert_eq!(
            e,
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "too many credentials in flight; retry later",
            )
            .with_description("replay_cache_full")
        );
        // A store that cannot record it: 503 replay_store_unavailable.
        let store = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
        store
            .with_connection(|c| Ok(c.execute_batch("DROP TABLE used_credentials")?))
            .unwrap();
        let broken = ReplayCache::new(store, 10);
        let e = auth(&a).commit(&broken, now()).unwrap_err();
        assert_eq!(
            e,
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "the server cannot record the use of this credential; retry later",
            )
            .with_description("replay_store_unavailable")
        );
    }

    #[test]
    fn replay_keys_are_namespaced_by_list() {
        let key = ed_key();
        let entry = AgentConfig::with_jwks("gw", jwks(&[public(&key, None)]));
        let agents = Clients::agents(std::slice::from_ref(&entry), policy()).unwrap();
        let peps = Clients::peps(&[entry], policy()).unwrap();
        let a = Signer { key, kid: None }.sign(&claims("gw"));
        let ka = verify(&agents, &a, None).unwrap().replay_key;
        let kp = verify(&peps, &a, None).unwrap().replay_key;
        assert_ne!(ka, kp);
        assert!(ka.starts_with("client-assertion\n") && kp.starts_with("client-assertion\n"));
    }

    #[test]
    fn assertion_fields_come_in_pairs_with_the_jwt_bearer_type() {
        let take = |v: Value| {
            let mut obj = v.as_object().unwrap().clone();
            let r = take_client_assertion(&mut obj);
            (r, obj)
        };
        let (r, rest) = take(json!({"client_assertion": "a.b.c",
            "client_assertion_type": CLIENT_ASSERTION_TYPE, "actor": "x"}));
        assert_eq!(r.unwrap().as_deref(), Some("a.b.c"));
        assert_eq!(Value::Object(rest), json!({"actor": "x"}));
        assert_eq!(take(json!({"actor": "x"})).0.unwrap(), None);
        let c = |v: Value| take(v).0.unwrap_err().description;
        assert_eq!(
            c(json!({"client_assertion": "a.b.c"})),
            Some("malformed_request")
        );
        assert_eq!(
            c(json!({"client_assertion_type": CLIENT_ASSERTION_TYPE})),
            Some("malformed_request")
        );
        assert_eq!(
            c(json!({"client_assertion": 1, "client_assertion_type": CLIENT_ASSERTION_TYPE})),
            Some("malformed_request")
        );
        let e = take(json!({"client_assertion": "a.b.c",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"}))
        .0
        .unwrap_err();
        assert_eq!(e.description, Some("client_assertion_type_unsupported"));
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        // An HTTP-level refusal never carries the assertion.
        let (c2, _, new, _, _) = setup();
        let a = new.sign(&patched("coder", &[("aud", "https://other".into())], &[]));
        let e = c2
            .authenticate(&HeaderMap::new(), None, None, Some(&a), now())
            .unwrap_err();
        assert!(
            !e.detail.contains(&a) && !e.detail.contains("other"),
            "{}",
            e.detail
        );
    }
}
