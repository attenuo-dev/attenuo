//! Client authentication of agents (`[[agents]]`) and policy enforcement points (`[[peps]]`).
//!
//! Used for agents at `POST /token` (IdP intake and, with `[token] require_actor_auth`, every
//! exchange) and for PEPs at the AuthZEN endpoints (an unsigned body chain with
//! `[authzen] allow_unsigned_chain`, or diagnostics).
//!
//! A client authenticates in exactly one of four ways per request (RFC 6749 §2.3):
//!
//! - **Client secret.** HTTP Basic (RFC 6749 §2.3.1: id and secret form-encoded, then base64)
//!   or two body fields, never both. Secrets are stored as the lowercase hex SHA-256 of the
//!   secret (`secret_sha256`) and compared in constant time, against a dummy hash for unknown
//!   ids and for entries without a secret, so timing does not reveal which ids exist.
//! - **`private_key_jwt`** (RFC 7523 §2.2 and §3). `client_assertion_type` =
//!   `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion` = a JWT
//!   signed by one of the entry's keys. See [`Clients::verify_assertion`] for the checks. The
//!   assertion's `jti` is recorded in the replay store ([`crate::replay::ReplayCache`]) when
//!   [`Authenticated::commit`] runs, so an assertion authenticates one request, across restarts
//!   when the store is a database file.
//! - **`self_signed_tls_client_auth`** (RFC 8705 §2.2). The client presents a certificate in
//!   the TLS handshake of `[server.tls]` (with `client_certificates = "optional"`) and names
//!   itself with the id field (`client_id`, `pep_id`), with no secret, no HTTP Basic and no
//!   assertion. The TLS layer proved that the client holds the certificate's key
//!   ([`crate::client_cert_verifier`]); here the certificate's SHA-256 thumbprint must be one
//!   the entry lists in `tls_client_cert_sha256` (compared in constant time, against decoys
//!   for unknown ids and entries without thumbprints), and the certificate must be usable at
//!   the request's time ([`ClientCertificate::check_usable`]: its dates, not a CA, `clientAuth`
//!   when it names extended key usages). A certificate comes only from the connection, never
//!   from a header. With a secret or an assertion in the request, that credential decides and
//!   the certificate is ignored.
//! - **`tls_client_auth`** (RFC 8705 §2.1). The same request shape, but the certificate is
//!   issued by a CA: it must chain, through the intermediates the client sent, to a CA of the
//!   entry's `tls_client_ca_pem_path`, be usable for client authentication at the request's
//!   time, and carry the entry's `tls_client_auth_san_uri` or `tls_client_auth_san_dns`
//!   ([`crate::client_pki`]). No revocation check.
//!
//! An entry may hold a secret, keys and certificate settings, in any mix, except that it
//! checks certificates one way: `tls_client_cert_sha256` or `tls_client_ca_pem_path`, not
//! both. It can only be authenticated by what it holds. Sending a secret and an assertion
//! together is `multiple_client_auth`.
//!
//! # Keys from a URL (`jwks_url`)
//!
//! An entry's keys are inline (`jwks`) or published by the client at `jwks_url`, never both,
//! so one place says which keys are in force. Fetched keys pass the rules of inline ones
//! ([`parse_client_jwk_set`]: a private member, a symmetric key or an oversized set refuses the
//! whole document), except that a key the server does not use is skipped, and are checked the
//! same way. They come through the cache and fetch rules of the `[[idps]]` keys
//! ([`JwksCache`]): `https://` only (plain `http://` only to a loopback host), no redirects, a
//! 256 KiB and 5 second bound, `ca_pem_path`, kept for `jwks_ttl_seconds`, fetched again at
//! most once per 30 seconds on an unknown `kid`, and dropped when a refresh fails. Rules for
//! clients only ([`FailurePolicy`]): after a failed fetch, the next starts only after
//! [`CLIENT_JWKS_FAILURE_BACKOFF`]; a failed refetch for an unknown `kid` keeps the keys still
//! within their TTL; and the cache logs each failed fetch once. Nothing is fetched at startup;
//! a fetch is only ever for an id that is configured with `jwks_url`.
//!
//! Verification is synchronous (the AuthZEN endpoints and the exchange run on the blocking
//! pool), so the keys are fetched first, on the async side, by [`Clients::fetch_key`], and the
//! result is handed to [`Clients::authenticate_with`]. A client whose keys cannot be fetched
//! gets the same answer as an unknown client (`client_authentication_failed`, SR-110); the
//! cause is logged at warn level (`client JWKS unavailable`) once per failed fetch.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use axum::http::{header, HeaderMap, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub(crate) use attenuo_token::client_assertion::CLIENT_ASSERTION_TYPE;

use crate::client_cert::ClientCertificate;
use crate::client_pki::Pki;
use crate::config::{ActorAuth, AgentConfig, CLIENT_ASSERTION_ALGS};
use crate::error::ApiError;
use crate::idp::jwks::{FailurePolicy, JwksCache, JwksError};
use crate::replay::{ReplayCache, ReplayRefusal};
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
    /// A self-signed TLS client certificate pinned by its thumbprint (RFC 8705 §2.2).
    SelfSignedTls,
    /// A TLS client certificate issued by a CA, matched by a name (RFC 8705 §2.1).
    Tls,
}

impl ClientMethod {
    /// `client_secret`, `private_key_jwt`, `self_signed_tls_client_auth` or
    /// `tls_client_auth`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ClientMethod::Secret => "client_secret",
            ClientMethod::PrivateKeyJwt => "private_key_jwt",
            ClientMethod::SelfSignedTls => "self_signed_tls_client_auth",
            ClientMethod::Tls => "tls_client_auth",
        }
    }

    /// The method together with an actor token that named the same agent.
    pub(crate) fn with_actor_token(self) -> &'static str {
        match self {
            ClientMethod::Secret => "actor_token+client_secret",
            ClientMethod::PrivateKeyJwt => "actor_token+private_key_jwt",
            ClientMethod::SelfSignedTls => "actor_token+self_signed_tls_client_auth",
            ClientMethod::Tls => "actor_token+tls_client_auth",
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

/// Did the request present client credentials of any kind: a secret (HTTP Basic or the body
/// field), an assertion, or a client id (`body_id`) on a connection with a client certificate
/// (`cert`, from the TLS handshake)?
pub(crate) fn presented(
    headers: &HeaderMap,
    body_id: Option<&str>,
    body_secret: Option<&str>,
    assertion: Option<&str>,
    cert: Option<&ClientCertificate>,
) -> Result<bool, ApiError> {
    Ok(body_secret.is_some()
        || assertion.is_some()
        || basic_credentials(headers)?.is_some()
        || (body_id.is_some() && cert.is_some()))
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
    /// The key cache of the entry's `jwks_url`, when it has one. Built anew by every check of
    /// the lists, so an agents reload starts with no keys from before.
    remote: Option<Arc<JwksCache<ClientKey>>>,
    /// The SHA-256 (lowercase hex) of the entry's `ca_pem_path` file as it was read, for the
    /// list digest and the changes of a reload.
    ca_pem_sha256: Option<String>,
    /// The entry's `tls_client_cert_sha256`, decoded; empty when it has none.
    cert_sha256: Vec<[u8; 32]>,
    /// The entry's `tls_client_auth` settings: its CA file, read when the list was built, and
    /// the name its certificate must carry. Never together with `cert_sha256`.
    pki: Option<Arc<Pki>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("secret", &self.secret_sha256.is_some())
            .field("keys", &self.keys.len())
            .field("jwks_url", &self.remote.is_some())
            .field("certificates", &self.cert_sha256.len())
            .field("pki", &self.pki)
            .finish()
    }
}

impl Client {
    /// Whether the entry has a secret.
    pub fn has_secret(&self) -> bool {
        self.secret_sha256.is_some()
    }

    /// Whether the entry has keys for `private_key_jwt`, inline or at a `jwks_url`.
    pub fn has_keys(&self) -> bool {
        !self.keys.is_empty() || self.remote.is_some()
    }

    /// Whether the entry accepts client certificates (`tls_client_cert_sha256` or
    /// `tls_client_ca_pem_path`).
    pub fn has_certificates(&self) -> bool {
        !self.cert_sha256.is_empty() || self.pki.is_some()
    }

    /// The key that gives the entry its certificate settings, for a message.
    fn certificate_key(&self) -> &'static str {
        if self.pki.is_some() {
            "tls_client_ca_pem_path"
        } else {
            "tls_client_cert_sha256"
        }
    }
}

/// How long the fetch of a client's `jwks_url` may take, as for the `[[idps]]` keys.
const CLIENT_JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Default `jwks_ttl_seconds` of an entry with `jwks_url`, as for `[[idps]]`.
const DEFAULT_CLIENT_JWKS_TTL_SECONDS: u64 = 300;
/// After a failed fetch of a client's `jwks_url`, how long until the next may start. Until
/// then every assertion of that client is refused without a fetch, so a flood of assertions
/// naming a client whose URL is down makes at most one fetch per this time.
pub(crate) const CLIENT_JWKS_FAILURE_BACKOFF: Duration = Duration::from_secs(5);

/// The key one client assertion is verified with, fetched by [`Clients::fetch_key`] before
/// the (synchronous) check, for an entry with `jwks_url`. Empty for anything else.
#[derive(Default)]
pub(crate) struct FetchedKey(Option<Fetched>);

struct Fetched {
    /// The entry the assertion's `sub` named.
    client: String,
    /// That entry's cache, so that a key fetched for another list is never used.
    cache: Arc<JwksCache<ClientKey>>,
    outcome: Result<ClientKey, Unverified>,
}

impl FetchedKey {
    /// No key fetched: for a request without an assertion, or lists without `jwks_url`.
    pub(crate) fn none() -> Self {
        Self(None)
    }

    /// The outcome fetched for `client`, whose cache is `cache`.
    fn for_client(
        &self,
        client: &str,
        cache: &Arc<JwksCache<ClientKey>>,
    ) -> Option<&Result<ClientKey, Unverified>> {
        self.0
            .as_ref()
            .filter(|f| f.client == client && Arc::ptr_eq(&f.cache, cache))
            .map(|f| &f.outcome)
    }
}

/// The key of `keys` an assertion with header `kid` and `alg` is checked with, the same for
/// inline and fetched keys: the key the `kid` names, or without a `kid` the set's only key;
/// it must be a key of `alg`. `Ok(None)`: the `kid` names none of the keys (for fetched keys,
/// worth one refetch).
fn pick_key<'a>(
    keys: &'a [ClientKey],
    kid: Option<&str>,
    alg: Algorithm,
) -> Result<Option<&'a ClientKey>, Unverified> {
    let key = match kid {
        None => match keys {
            [only] => only,
            _ => return Err(Unverified::UnknownKid),
        },
        Some(kid) => match keys.iter().find(|k| k.kid.as_deref() == Some(kid)) {
            Some(k) => k,
            None => return Ok(None),
        },
    };
    if key.alg != alg {
        return Err(Unverified::KeyAlgMismatch);
    }
    Ok(Some(key))
}

/// The keys of a fetched client JWK Set: [`parse_client_jwk_set`] with `skip_foreign`, so a
/// key the server cannot use is left out instead of refusing the set.
fn parse_fetched_client_jwks(doc: &Value, label: &str) -> Result<Vec<ClientKey>, String> {
    parse_client_jwk_set(doc, Some(label))
        .map_err(|e| format!("the client's key set is refused: {e}"))
}

/// What an assertion's header and payload say before any key is looked up, once the checks
/// that do not depend on the client have passed (steps 1 to 3 of
/// [`Clients::verify_assertion`]).
struct Unverifiable<'a> {
    sub: &'a str,
    alg: Algorithm,
    kid: Option<&'a str>,
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
    /// [`DECOY_JWKS`], parsed.
    decoys: Vec<ClientKey>,
    /// The `tls_client_auth` names of the list (URI as written, DNS in lowercase), each to the
    /// index of its entry in `list`: a certificate that carries the name of another entry is
    /// refused ([`Clients::authenticate_pki`]).
    pki_names: HashMap<PkiNameKey, usize>,
}

/// A key of [`Clients::pki_names`]: (`true` for a DNS name, the name).
type PkiNameKey = (bool, String);

fn pki_name_key(name: &crate::client_pki::SanName) -> PkiNameKey {
    (
        matches!(name, crate::client_pki::SanName::Dns(_)),
        name.value().to_owned(),
    )
}

/// Most keys one entry's `jwks` may hold.
pub(crate) const MAX_CLIENT_KEYS: usize = 8;
/// Most thumbprints one entry's `tls_client_cert_sha256` may hold, as for keys.
pub(crate) const MAX_CLIENT_CERTS: usize = 8;
/// What a presented certificate's thumbprint is compared with in the slots an entry does not
/// fill, and for an unknown id: every check makes [`MAX_CLIENT_CERTS`] comparisons, so timing
/// does not tell which ids exist or how many certificates an entry lists. Never a real
/// thumbprint: its match counts for nothing.
const DECOY_CERT_SHA256: [u8; 32] = [0; 32];
/// The `detail` of every refused client certificate (SR-110).
const CERT_REFUSED: &str = "unknown client, or the TLS client certificate is not one the client's \
                            entry accepts";
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
        Self::from_config(ClientKind::Agent, entries, policy, &mut Vec::new())
    }

    /// Validate the `[[peps]]` entries.
    ///
    /// # Errors
    ///
    /// As [`Clients::from_config`].
    pub fn peps(entries: &[AgentConfig], policy: AssertionPolicy) -> anyhow::Result<Self> {
        Self::from_config(ClientKind::Pep, entries, policy, &mut Vec::new())
    }

    /// Validate a list at startup: ids non-empty and unique; at least one of
    /// `secret_sha256` (64 hex characters), keys, either `jwks` (see
    /// [`parse_client_jwks`]) or `jwks_url` (see [`remote_keys`]), not both, and
    /// certificate settings, either `tls_client_cert_sha256` (see [`client_cert_pins`]) or
    /// `tls_client_ca_pem_path` with one name (see [`client_pki_settings`]), not both; no
    /// thumbprint and no name on two entries. A CA file is read once per path: `ca_files`
    /// holds the files already read, by path, and is shared by the agents and PEPs of one
    /// start or reload, so both lists see the same bytes.
    pub(crate) fn from_config(
        kind: ClientKind,
        entries: &[AgentConfig],
        policy: AssertionPolicy,
        ca_files: &mut crate::client_pki::CaFiles,
    ) -> anyhow::Result<Self> {
        let section = kind.section();
        let mut list: Vec<Client> = Vec::with_capacity(entries.len());
        // One HTTP client for every entry with `jwks_url` and no `ca_pem_path`, made only
        // when there is one.
        let mut shared_client: Option<reqwest::Client> = None;
        let mut pki_names: HashMap<PkiNameKey, usize> = HashMap::new();
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
            let (remote, ca_pem_sha256) = match remote_keys(section, a, &mut shared_client)? {
                Some((cache, ca)) => (Some(Arc::new(cache)), ca),
                None => (None, None),
            };
            let cert_sha256 = client_cert_pins(section, a)?;
            let pki = client_pki_settings(section, a, ca_files)?.map(Arc::new);
            if secret_sha256.is_none()
                && keys.is_empty()
                && remote.is_none()
                && cert_sha256.is_empty()
                && pki.is_none()
            {
                anyhow::bail!(
                    "{section} `{}`: set secret_sha256, jwks or jwks_url (private_key_jwt), or \
                     tls_client_cert_sha256 or tls_client_ca_pem_path (a TLS client \
                     certificate); several may be set together",
                    a.id
                );
            }
            // One name, one client: a certificate from a shared CA would otherwise
            // authenticate both entries.
            if let Some(p) = &pki {
                if let Some(&other) = pki_names.get(&pki_name_key(&p.name)) {
                    anyhow::bail!(
                        "{section} `{}`: its {} is also the name of `{}`; one certificate name \
                         may authenticate only one client",
                        a.id,
                        p.name.key(),
                        list[other].id
                    );
                }
                pki_names.insert(pki_name_key(&p.name), list.len());
            }
            // One certificate, one client: the certificate alone would otherwise not say
            // which entry it stands for.
            if let Some(other) = list
                .iter()
                .find(|b| b.cert_sha256.iter().any(|p| cert_sha256.contains(p)))
            {
                anyhow::bail!(
                    "{section} `{}`: a tls_client_cert_sha256 value is also listed by `{}`; one \
                     certificate may authenticate only one client",
                    a.id,
                    other.id
                );
            }
            list.push(Client {
                id: a.id.clone(),
                secret_sha256,
                keys,
                remote,
                ca_pem_sha256,
                cert_sha256,
                pki,
            });
        }
        let decoys = parse_client_jwks(DECOY_JWKS)
            .map_err(|e| anyhow::anyhow!("the decoy client keys do not parse: {e}"))?;
        Ok(Self {
            kind,
            list,
            policy,
            decoys,
            pki_names,
        })
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

    /// The SHA-256 of the `ca_pem_path` file of entry `id`, as it was read when the list was
    /// built.
    fn ca_pem_sha256(&self, id: &str) -> Option<&str> {
        self.find(id).and_then(|c| c.ca_pem_sha256.as_deref())
    }

    /// Whether an entry takes its keys from a `jwks_url`, so that an assertion needs
    /// [`fetch_key`](Self::fetch_key) first. Without one, `fetch_key` does nothing.
    pub(crate) fn fetches_keys(&self) -> bool {
        self.list.iter().any(|c| c.remote.is_some())
    }

    /// Fetch, on the async side, the key `assertion` will be checked with, when its `sub`
    /// names an entry with `jwks_url`; hand the result to
    /// [`authenticate_with`](Self::authenticate_with). Nothing is fetched for an assertion
    /// that fails a check made before the client lookup, nor for an id that is not configured
    /// with `jwks_url`, and nothing here refuses the request: the check does, at its usual
    /// step.
    pub(crate) async fn fetch_key(&self, assertion: Option<&str>) -> FetchedKey {
        let Some(assertion) = assertion.filter(|_| self.fetches_keys()) else {
            return FetchedKey::none();
        };
        let Ok((header, payload)) = peek(assertion) else {
            return FetchedKey::none();
        };
        let Ok(Unverifiable { sub, alg, kid }) = unverifiable(&header, &payload, None) else {
            return FetchedKey::none();
        };
        let Some((client, cache)) = self
            .find(sub)
            .and_then(|c| c.remote.as_ref().map(|r| (c, r)))
        else {
            return FetchedKey::none();
        };
        let found = cache
            .find(kid, |keys| match pick_key(keys, kid, alg) {
                Ok(None) => Ok(None),
                Ok(Some(k)) => Ok(Some(Ok(k.clone()))),
                Err(why) => Ok(Some(Err(why))),
            })
            .await;
        let outcome = match found {
            Ok(picked) => picked,
            Err(JwksError::Unavailable(detail)) => {
                // The cache logged the failed fetch at warn level, once; a request answered
                // with it, or with the stored failure during the backoff, is logged here at
                // debug level only. The detail names the URL: logged, never answered (SR-17).
                tracing::debug!(
                    client = ?client.id,
                    list = self.kind.section(),
                    detail = ?detail,
                    "client JWKS unavailable; assertion refused"
                );
                Err(Unverified::KeysUnavailable)
            }
            Err(JwksError::AlgMismatch { .. }) => Err(Unverified::KeyAlgMismatch),
            Err(JwksError::UnknownKid | JwksError::MissingKid) => Err(Unverified::UnknownKid),
        };
        FetchedKey(Some(Fetched {
            client: client.id.clone(),
            cache: Arc::clone(cache),
            outcome,
        }))
    }

    /// Verify `assertion` against the decoy key of `alg` and throw the outcome away: the work
    /// a refusal without a key of the client to verify with does instead (SR-110).
    fn decoy_verify(&self, alg: Algorithm, assertion: &str) {
        if let Some(decoy) = self.decoys.iter().find(|k| k.alg == alg) {
            let outcome = jsonwebtoken::decode::<Map<String, Value>>(
                assertion,
                &decoy.key,
                &signature_only(alg),
            );
            std::hint::black_box(outcome.is_ok());
        }
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
        cert: Option<&ClientCertificate>,
        now: OffsetDateTime,
    ) -> Result<Authenticated, ApiError> {
        self.authenticate_with(
            headers,
            body_id,
            body_secret,
            assertion,
            &FetchedKey::none(),
            cert,
            now,
        )
    }

    /// [`authenticate`](Self::authenticate) with the key [`fetch_key`](Self::fetch_key)
    /// fetched for `assertion`. Without it, an assertion of an entry with `jwks_url` is
    /// refused. `cert` is the client certificate of the request's TLS connection, as the
    /// accept loop attached it ([`ClientCertificate`]); it authenticates only a request that
    /// carries no other credential and names the client in the id field.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate_with(
        &self,
        headers: &HeaderMap,
        body_id: Option<&str>,
        body_secret: Option<&str>,
        assertion: Option<&str>,
        fetched: &FetchedKey,
        cert: Option<&ClientCertificate>,
        now: OffsetDateTime,
    ) -> Result<Authenticated, ApiError> {
        let kind = self.kind;
        let (id_field, secret_field) = kind.fields();
        let basic = basic_credentials(headers)?;
        if cert.is_some() && (assertion.is_some() || basic.is_some() || body_secret.is_some()) {
            tracing::debug!(
                list = kind.section(),
                "the request carries a client credential: its TLS client certificate is not used \
                 to authenticate it"
            );
        }
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
            let v = self.verify_assertion(assertion, body_id, fetched, now)?;
            return Ok(Authenticated {
                id: v.client,
                method: ClientMethod::PrivateKeyJwt,
                replay: Some((v.replay_key, v.replay_until)),
                client_cert: None,
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
                if let (Some(id), Some(cert)) = (body_id, cert) {
                    return self.authenticate_certificate(id, cert, now);
                }
                return Err(invalid_client(
                    "client_auth_missing",
                    format!(
                        "client authentication is required (HTTP Basic, {id_field} and \
                         {secret_field}, or client_assertion)"
                    ),
                ));
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
                client_cert: None,
            }),
            _ => Err(invalid_client(
                "client_authentication_failed",
                "unknown client or wrong secret",
            )),
        }
    }

    /// Authenticate client `id` by the TLS client certificate `cert` (RFC 8705 §2.2): its
    /// thumbprint is one of the entry's `tls_client_cert_sha256`, and it is usable at `now`
    /// ([`ClientCertificate::check_usable`]). The certificate's own check runs first, whatever
    /// `id` names, and the thumbprint is compared with [`MAX_CLIENT_CERTS`] values in constant
    /// time (the entry's, then [`DECOY_CERT_SHA256`]), so the work does not depend on the id.
    /// Every refusal is the same answer, `client_authentication_failed` with the same
    /// `detail`; the reason (`unknown_client`, `no_certificate_settings`,
    /// `thumbprint_mismatch`, `certificate_expired`, `certificate_not_yet_valid`,
    /// `certificate_not_usable`) goes to the debug log only (SR-110).
    ///
    /// An entry with `tls_client_ca_pem_path` is checked by
    /// [`authenticate_pki`](Self::authenticate_pki) instead. That check takes longer than a
    /// refusal here, so timing can tell an id with CA settings from other ids; ids are not
    /// secret, and the answer is the same.
    fn authenticate_certificate(
        &self,
        id: &str,
        cert: &ClientCertificate,
        now: OffsetDateTime,
    ) -> Result<Authenticated, ApiError> {
        if self.is_empty() {
            return Err(invalid_client(
                self.kind.none_configured(),
                format!("no {} are configured", self.kind.section()),
            ));
        }
        let known = self.find(id);
        if let Some((c, pki)) = known.and_then(|c| c.pki.as_ref().map(|p| (c, p))) {
            return self.authenticate_pki(c, pki, cert, now);
        }
        let usable = cert.check_usable(now);
        let pins = known.map_or(&[][..], |c| c.cert_sha256.as_slice());
        let mut matched = false;
        for i in 0..MAX_CLIENT_CERTS {
            let (pin, real) = match pins.get(i) {
                Some(p) => (p, true),
                None => (&DECOY_CERT_SHA256, false),
            };
            matched |= constant_time_eq(pin, cert.sha256()) & real;
        }
        let refused = match (known, usable) {
            (None, _) => Some("unknown_client"),
            (Some(c), _) if c.cert_sha256.is_empty() => Some("no_certificate_settings"),
            (Some(_), _) if !matched => Some("thumbprint_mismatch"),
            (Some(_), Err(why)) => Some(why.reason()),
            (Some(_), Ok(())) => None,
        };
        match (refused, known) {
            (None, Some(c)) => Ok(Authenticated {
                id: c.id.clone(),
                method: ClientMethod::SelfSignedTls,
                replay: None,
                client_cert: Some(cert.clone()),
            }),
            (why, _) => {
                tracing::debug!(
                    reason = why.unwrap_or("unknown_client"),
                    client = ?id,
                    list = self.kind.section(),
                    x5t_s256 = %cert.x5t_s256(),
                    source = cert.source().as_str(),
                    "TLS client certificate refused"
                );
                Err(invalid_client("client_authentication_failed", CERT_REFUSED))
            }
        }
    }

    /// Authenticate entry `c` by the TLS client certificate `cert` issued by one of its CAs
    /// (RFC 8705 §2.1, [`crate::client_pki::verify`]). A refusal is the answer of every other
    /// refused certificate; the reason (`too_many_intermediates`, `certificate_not_usable`,
    /// `certificate_expired`, `certificate_not_yet_valid`, `chain_invalid`, `uri_san_count`,
    /// `san_mismatch`, `certificate_names_several_clients`) and the certificate's names,
    /// escaped, go to the debug log only (SR-110, SR-18).
    ///
    /// A certificate whose path and name are good is still refused when it also carries the
    /// `tls_client_auth_san_uri` or `tls_client_auth_san_dns` of another entry of this list:
    /// one certificate never authenticates two clients of a list. (An agent and a PEP may
    /// share a name: they are told apart by the endpoint.) The work is one lookup per name of
    /// the certificate.
    fn authenticate_pki(
        &self,
        c: &Client,
        pki: &Pki,
        cert: &ClientCertificate,
        now: OffsetDateTime,
    ) -> Result<Authenticated, ApiError> {
        let outcome = crate::client_pki::verify(pki, cert, now).and_then(|()| {
            let names = crate::client_pki::names(cert);
            let keys = names
                .uris
                .iter()
                .map(|n| (false, n))
                .chain(names.dns.iter().map(|n| (true, n)));
            for (dns, name) in keys {
                if let Some(&i) = self.pki_names.get(&(dns, name.clone())) {
                    if self.list[i].id != c.id {
                        return Err(crate::client_pki::Refused {
                            reason: "certificate_names_several_clients",
                            names: vec![format!("{} is the name of {:?}", name, self.list[i].id)],
                        });
                    }
                }
            }
            Ok(())
        });
        match outcome {
            Ok(()) => Ok(Authenticated {
                id: c.id.clone(),
                method: ClientMethod::Tls,
                replay: None,
                client_cert: Some(cert.clone()),
            }),
            Err(why) => {
                tracing::debug!(
                    reason = why.reason,
                    client = ?c.id,
                    list = self.kind.section(),
                    x5t_s256 = %cert.x5t_s256(),
                    source = cert.source().as_str(),
                    names = ?why.names,
                    "TLS client certificate refused"
                );
                Err(invalid_client("client_authentication_failed", CERT_REFUSED))
            }
        }
    }

    /// Verify a `private_key_jwt` client assertion (RFC 7523 §3), in this order:
    ///
    /// 1. Three base64url JSON parts; a header `typ` naming another kind of token (a
    ///    delegation token, an ID-JAG, an access token, a DPoP proof) is refused.
    /// 2. `iss` and `sub` are non-empty strings and equal, and equal the request's
    ///    `client_id` (`pep_id`) when it names one.
    /// 3. `alg` is in [`CLIENT_ASSERTION_ALGS`] (never `none` or an HMAC), and `kid`, when
    ///    present, is a string. These are server-wide, checked before the client is looked up.
    /// 4. `sub` names an entry with keys; the key is the one with the header's `kid`, or the
    ///    entry's only key when there is no `kid`; the key is for that `alg`; and the
    ///    signature verifies with it. For an entry with `jwks_url` the key is the one `fetched`
    ///    holds ([`Clients::fetch_key`]), chosen by the same rule from the fetched set; a set
    ///    that could not be fetched is a failure of this step too. Every failure of this step is the same answer,
    ///    `client_authentication_failed` as for a wrong secret, with the same `detail`, so a
    ///    caller that holds no key of the client cannot tell an unknown id, an id without
    ///    keys, an unknown `kid` or a key of another algorithm from a bad signature (SR-110);
    ///    the failures that have no key to verify with verify against a decoy key instead
    ///    ([`DECOY_JWKS`]). The reason is logged at debug level.
    /// 5. `aud` is the server's issuer identifier (`[issuer] issuer`): a string equal to it,
    ///    or a non-empty array whose every element equals it. The token endpoint URL and any
    ///    other value are refused.
    /// 6. `exp` is required, not past (with the skew), and at most
    ///    `client_assertion_max_lifetime_seconds` (plus the skew) ahead; `nbf` and `iat`, when
    ///    present, are not in the future (with the skew).
    /// 7. `jti` is a required non-empty string of at most 256 bytes.
    pub(crate) fn verify_assertion(
        &self,
        assertion: &str,
        body_id: Option<&str>,
        fetched: &FetchedKey,
        now: OffsetDateTime,
    ) -> Result<VerifiedAssertion, AssertionError> {
        let (header, payload) = peek(assertion)?;
        let Unverifiable { sub, alg, kid } = unverifiable(&header, &payload, body_id)?;

        // From here until the signature has verified, every refusal is the same answer
        // (`client_authentication_failed`, as for a wrong secret), and one that has no key of
        // the client to verify with verifies against a decoy key of the same algorithm, so that
        // an unknown id, an id without keys, an unknown `kid` and a key of another algorithm
        // cost a signature verification like a bad signature does (SR-110). The specific
        // reason goes to the debug log only.
        let refuse = |why: Unverified| {
            self.decoy_verify(alg, assertion);
            AssertionError::NotAuthenticated(why)
        };
        let Some(client) = self.find(sub) else {
            return Err(refuse(Unverified::UnknownClient));
        };
        if !client.has_keys() {
            return Err(refuse(Unverified::NoKeys));
        }
        let key = match &client.remote {
            None => match pick_key(&client.keys, kid, alg) {
                Ok(Some(k)) => k,
                Ok(None) => return Err(refuse(Unverified::UnknownKid)),
                Err(why) => return Err(refuse(why)),
            },
            Some(cache) => match fetched.for_client(&client.id, cache) {
                Some(Ok(k)) => k,
                Some(Err(why)) => return Err(refuse(*why)),
                None => {
                    // A caller that did not run `fetch_key` first: fail closed.
                    tracing::warn!(
                        client = ?client.id,
                        "client assertion checked without fetching the client's keys"
                    );
                    return Err(refuse(Unverified::KeysUnavailable));
                }
            },
        };

        let claims = jsonwebtoken::decode::<Map<String, Value>>(
            assertion,
            &key.key,
            &signature_only(key.alg),
        )
        .map_err(|_| AssertionError::NotAuthenticated(Unverified::BadSignature))?
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

/// The entry's `tls_client_cert_sha256`, decoded: 1 to [`MAX_CLIENT_CERTS`] values, each
/// exactly 64 lowercase hex characters (the SHA-256 of a certificate's DER bytes, as
/// `secret_sha256` writes a digest), none listed twice. Empty when the entry has none. A
/// refusal names the entry and the problem, never a value.
fn client_cert_pins(section: &str, a: &AgentConfig) -> anyhow::Result<Vec<[u8; 32]>> {
    let Some(values) = &a.tls_client_cert_sha256 else {
        return Ok(Vec::new());
    };
    let fail = |msg: String| anyhow::anyhow!("{section} `{}`: tls_client_cert_sha256 {msg}", a.id);
    if values.is_empty() || values.len() > MAX_CLIENT_CERTS {
        return Err(fail(format!(
            "must list 1 to {MAX_CLIENT_CERTS} certificate thumbprints, not {}",
            values.len()
        )));
    }
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(values.len());
    for (i, v) in values.iter().enumerate() {
        let lower_hex = v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let decoded = lower_hex
            .then(|| hex::decode(v).ok())
            .flatten()
            .and_then(|d| <[u8; 32]>::try_from(d).ok());
        let Some(pin) = decoded else {
            return Err(fail(format!(
                "value {}: must be 64 lowercase hex characters, the SHA-256 of the certificate's \
                 DER bytes (openssl x509 -in cert.pem -outform DER | openssl dgst -sha256)",
                i + 1
            )));
        };
        if out.contains(&pin) {
            return Err(fail(format!(
                "value {}: lists the same thumbprint twice",
                i + 1
            )));
        }
        out.push(pin);
    }
    Ok(out)
}

/// The entry's `tls_client_auth` settings: `None` when it has none of
/// `tls_client_ca_pem_path`, `tls_client_auth_san_uri` and `tls_client_auth_san_dns`.
/// Otherwise the CA file and exactly one name are required ([`crate::client_pki::san_uri`],
/// [`crate::client_pki::san_dns`], [`crate::client_pki::read_ca_file`]), and
/// `tls_client_cert_sha256` is refused next to them. `ca_files` holds the files already read
/// for this start or reload, by path, so each is read once. A refusal names the entry, the key
/// and the problem, never a name's value or the file's content.
fn client_pki_settings(
    section: &str,
    a: &AgentConfig,
    ca_files: &mut crate::client_pki::CaFiles,
) -> anyhow::Result<Option<Pki>> {
    let fail = |msg: String| anyhow::anyhow!("{section} `{}`: {msg}", a.id);
    let name = match (&a.tls_client_auth_san_uri, &a.tls_client_auth_san_dns) {
        (None, None) => None,
        (Some(_), Some(_)) => {
            return Err(fail(
                "set tls_client_auth_san_uri or tls_client_auth_san_dns, not both: a client \
                 certificate is matched by one name"
                    .into(),
            ))
        }
        (Some(uri), None) => Some(
            crate::client_pki::san_uri(uri)
                .map_err(|e| fail(format!("tls_client_auth_san_uri {e}")))?,
        ),
        (None, Some(dns)) => Some(
            crate::client_pki::san_dns(dns)
                .map_err(|e| fail(format!("tls_client_auth_san_dns {e}")))?,
        ),
    };
    let (path, name) = match (&a.tls_client_ca_pem_path, name) {
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err(fail(
                "tls_client_ca_pem_path needs tls_client_auth_san_uri or \
                 tls_client_auth_san_dns: the name the client's certificate must carry"
                    .into(),
            ))
        }
        (None, Some(name)) => {
            return Err(fail(format!(
                "{} needs tls_client_ca_pem_path: the CA certificates that issue the client's \
                 certificate",
                name.key()
            )))
        }
        (Some(path), Some(name)) => (path, name),
    };
    if a.tls_client_cert_sha256.is_some() {
        return Err(fail(
            "set tls_client_cert_sha256 (a self-signed certificate) or tls_client_ca_pem_path \
             (certificates from a CA), not both: an entry checks client certificates one way"
                .into(),
        ));
    }
    let ca = match ca_files.iter().find(|(p, _)| p == path) {
        Some((_, ca)) => ca.clone(),
        None => {
            let ca = crate::client_pki::read_ca_file(path).map_err(|e| {
                fail(format!(
                    "tls_client_ca_pem_path {:?}: {e}",
                    path.display().to_string()
                ))
            })?;
            let ca = Arc::new(ca);
            ca_files.push((path.clone(), ca.clone()));
            ca
        }
    };
    Ok(Some(Pki {
        ca_path: path.clone(),
        ca,
        name,
    }))
}

/// The key cache of an entry with `jwks_url`, checked as the `[[idps]]` key URLs are: the
/// URL is `https://` (plain `http://` only to a loopback host), `jwks_ttl_seconds` is
/// positive, and `ca_pem_path` names a readable PEM file of CA certificates. `jwks_url` and
/// `jwks` together are refused, and so are `jwks_ttl_seconds` and `ca_pem_path` without
/// `jwks_url`. Nothing is fetched here. `shared` is the HTTP client of the entries without
/// `ca_pem_path`, made on first need. Returns the cache and the SHA-256 of the `ca_pem_path`
/// file as it was read.
fn remote_keys(
    section: &str,
    a: &AgentConfig,
    shared: &mut Option<reqwest::Client>,
) -> anyhow::Result<Option<(JwksCache<ClientKey>, Option<String>)>> {
    let fail = |msg: String| anyhow::anyhow!("{section} `{}`: {msg}", a.id);
    let Some(url) = &a.jwks_url else {
        if a.jwks_ttl_seconds.is_some() || a.ca_pem_path.is_some() {
            return Err(fail(
                "jwks_ttl_seconds and ca_pem_path are only for keys fetched from jwks_url".into(),
            ));
        }
        return Ok(None);
    };
    if a.jwks.is_some() {
        return Err(fail(
            "set jwks or jwks_url, not both: an entry takes its keys from one place, so that \
             it is clear which keys are in force"
                .into(),
        ));
    }
    crate::idp::jwks::check_fetch_url(url).map_err(|e| fail(format!("jwks_url {url:?}: {e}")))?;
    let ttl = a
        .jwks_ttl_seconds
        .unwrap_or(DEFAULT_CLIENT_JWKS_TTL_SECONDS);
    if ttl == 0 {
        return Err(fail("jwks_ttl_seconds must be positive".into()));
    }
    let shared = match shared {
        Some(c) => c,
        None => shared.insert(crate::idp::jwks::fetch_client(
            CLIENT_JWKS_FETCH_TIMEOUT,
            &[],
        )?),
    };
    let (client, ca_pem_sha256) = crate::idp::jwks::entry_client_and_ca_digest(
        shared,
        a.ca_pem_path.as_deref(),
        CLIENT_JWKS_FETCH_TIMEOUT,
    )
    .map_err(fail)?;
    let cache = JwksCache::with_parser(
        client,
        format!("{section} `{}`", shown(&a.id)),
        Some(url.clone()),
        Duration::from_secs(ttl),
        FailurePolicy {
            backoff: CLIENT_JWKS_FAILURE_BACKOFF,
            keep_fresh_keys: true,
            warn: true,
        },
        parse_fetched_client_jwks,
    );
    Ok(Some((cache, ca_pem_sha256)))
}

/// The `[[agents]]` and `[[peps]]` in force, validated, with the entries they were built from
/// (so that a reload can tell what it changed). Built at startup and by
/// `POST /admin/agents/reload`, both through [`ClientRules::check`]; the set in force is a
/// [`SharedClients`].
pub struct ClientSets {
    /// `[[agents]]`.
    pub agents: Clients,
    /// `[[peps]]`.
    pub peps: Clients,
    agent_entries: Vec<AgentConfig>,
    pep_entries: Vec<AgentConfig>,
    agents_sha256: String,
    peps_sha256: String,
}

impl std::fmt::Debug for ClientSets {
    /// Ids and what each entry holds, never a digest or a key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSets")
            .field("agents", &self.agents)
            .field("peps", &self.peps)
            .finish_non_exhaustive()
    }
}

/// What an agents reload changed in one list, by id (never a digest or a key).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientChanges {
    /// Ids in the new list and not in the old one.
    pub added: Vec<String>,
    /// Ids in the old list and not in the new one: their credentials stop working.
    pub removed: Vec<String>,
    /// Ids in both whose `secret_sha256`, `jwks`, `jwks_url`, `jwks_ttl_seconds`,
    /// `ca_pem_path`, `tls_client_cert_sha256` (as a set), `tls_client_ca_pem_path` or
    /// certificate name differs, or whose `ca_pem_path` or `tls_client_ca_pem_path` file
    /// holds other bytes.
    pub changed: Vec<String>,
}

impl ClientSets {
    /// The [`list_sha256`] of `[[agents]]` and of `[[peps]]`.
    pub fn sha256(&self) -> (&str, &str) {
        (&self.agents_sha256, &self.peps_sha256)
    }

    /// What changed from `self` to `new`: `(agents, peps)`.
    pub fn changes_to(&self, new: &Self) -> (ClientChanges, ClientChanges) {
        (
            entry_changes(
                (&self.agent_entries, &self.agents),
                (&new.agent_entries, &new.agents),
            ),
            entry_changes(
                (&self.pep_entries, &self.peps),
                (&new.pep_entries, &new.peps),
            ),
        )
    }
}

/// The changes from `old` to `new` (each the entries and the list built from them), each list
/// sorted. A digest is compared without regard to case and a `jwks` as JSON, so rewriting the
/// same value differently is not a change. The settings of a `jwks_url` are compared as
/// [`remote_row`] gives them, so a new content of the `ca_pem_path` file is a change. The
/// thumbprints of `tls_client_cert_sha256` are compared as a set ([`cert_row`]), so a new order
/// is not a change. The `tls_client_auth` settings are compared as [`pki_row`] gives them, so
/// a new content of the `tls_client_ca_pem_path` file is a change.
fn entry_changes(
    (old, old_built): (&[AgentConfig], &Clients),
    (new, new_built): (&[AgentConfig], &Clients),
) -> ClientChanges {
    let digest = |a: &AgentConfig| a.secret_sha256.as_deref().map(str::to_ascii_lowercase);
    let keys = |a: &AgentConfig| {
        a.jwks
            .as_deref()
            .map(|t| serde_json::from_str::<Value>(t).unwrap_or_else(|_| Value::from(t)))
    };
    let mut out = ClientChanges::default();
    for n in new {
        match old.iter().find(|o| o.id == n.id) {
            None => out.added.push(n.id.clone()),
            Some(o)
                if digest(o) != digest(n)
                    || keys(o) != keys(n)
                    || remote_row(o, old_built) != remote_row(n, new_built)
                    || cert_row(o) != cert_row(n)
                    || pki_row(o, old_built) != pki_row(n, new_built) =>
            {
                out.changed.push(n.id.clone());
            }
            Some(_) => {}
        }
    }
    for o in old {
        if !new.iter().any(|n| n.id == o.id) {
            out.removed.push(o.id.clone());
        }
    }
    out.added.sort();
    out.removed.sort();
    out.changed.sort();
    out
}

/// What the check of `[[agents]]` and `[[peps]]` reads from the rest of the config: the
/// assertion policy and the settings it cross-checks the two lists against. Taken from the
/// config at startup and kept, so that `POST /admin/agents/reload` checks new lists against
/// the settings in force (which it does not reload), with the same rules as startup. A reload
/// also builds one from the file it read, to say whether the file as written would accept its
/// own lists after a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientRules {
    policy: AssertionPolicy,
    /// `[[idps]]`: each issuer and the agent ids its `client_ids` names.
    idps: Vec<(String, Vec<String>)>,
    actor_auth: ActorAuth,
    require_actor_auth: bool,
    /// What agent ids each `[[actor_trust]]` entry can turn a workload's `sub` into: `None`
    /// for an entry that maps `sub` (or a SPIFFE path) itself, so any id, else the ids of its
    /// table.
    actor_trust: Vec<Option<Vec<String>>>,
    allow_unsigned_chain: bool,
    /// `[server.tls] client_certificates = "optional"` (the listener asks for client
    /// certificates) or `[server.forwarded_client_cert]` (a proxy forwards them), so
    /// `tls_client_cert_sha256` and `tls_client_ca_pem_path` can be used.
    client_certificates: bool,
}

/// An id as it is written into a warning or a refusal: escaped, so that one with a newline or
/// another control character cannot forge a log line.
pub(crate) fn shown(id: &str) -> String {
    id.escape_debug().to_string()
}

impl ClientRules {
    /// The rules of `config`. `[[actor_trust]]` is read from the config, as the registry
    /// startup builds from it holds one entry per config entry.
    pub(crate) fn from_config(config: &crate::config::Config) -> Self {
        use crate::config::SubjectToAgent;
        Self {
            policy: AssertionPolicy::from_config(config),
            idps: config
                .idps
                .iter()
                .map(|i| (i.issuer.clone(), i.client_ids.keys().cloned().collect()))
                .collect(),
            actor_auth: config.token.actor_auth,
            require_actor_auth: config.token.require_actor_auth,
            actor_trust: config
                .actor_trust
                .iter()
                .map(|t| match &t.subject_to_agent {
                    SubjectToAgent::Map(m) => Some(m.values().cloned().collect()),
                    SubjectToAgent::Sub | SubjectToAgent::SpiffePath => None,
                })
                .collect(),
            allow_unsigned_chain: config.authzen.allow_unsigned_chain,
            client_certificates: config.server.takes_client_certificates(),
        }
    }

    /// Check `agents` and `peps` as startup does and build them: the reserved id
    /// ([`crate::config::check_reserved_client_ids`]), each list ([`Clients::from_config`]),
    /// and the cross-checks with the other settings. Returns the lists and the warnings to log
    /// (startup logs them; a reload logs them and answers them too). Ids in a warning are
    /// escaped ([`shown`]).
    ///
    /// # Errors
    ///
    /// As [`crate::config::check_reserved_client_ids`] and [`Clients::from_config`], when
    /// `[authzen] allow_unsigned_chain = true` and `peps` is empty, and when an entry has
    /// `tls_client_cert_sha256` or `tls_client_ca_pem_path` while no listener takes a client
    /// certificate (no `[server.tls]` with `client_certificates = "optional"`, and no
    /// `[server.forwarded_client_cert]`): such a setting could never be used. The message is
    /// the one startup fails with.
    pub(crate) fn check(
        &self,
        agents: &[AgentConfig],
        peps: &[AgentConfig],
    ) -> anyhow::Result<(ClientSets, Vec<String>)> {
        crate::config::check_reserved_client_ids(agents, peps)?;
        // One read of each CA file for both lists.
        let mut ca_files = Vec::new();
        let agent_list = Clients::from_config(
            ClientKind::Agent,
            agents,
            self.policy.clone(),
            &mut ca_files,
        )?;
        let pep_list =
            Clients::from_config(ClientKind::Pep, peps, self.policy.clone(), &mut ca_files)?;
        if !self.client_certificates {
            for list in [&agent_list, &pep_list] {
                if let Some(c) = list.iter().find(|c| c.has_certificates()) {
                    anyhow::bail!(
                        "{} `{}`: {} needs [server.tls] with client_certificates = \
                         \"optional\", or [server.forwarded_client_cert]; without either the \
                         server takes no client certificate, so this entry's certificates \
                         could never be used",
                        list.kind.section(),
                        c.id,
                        c.certificate_key()
                    );
                }
            }
        }
        let mut warnings = Vec::new();
        for (issuer, client_ids) in &self.idps {
            for agent in agent_list.iter().filter(|a| !client_ids.contains(&a.id)) {
                warnings.push(format!(
                    "[[idps]] `{}`: client_ids has no entry for the agent `{1}`: its ID \
                     tokens must carry aud = `{1}` (the agent id). Set client_ids.{1} = \
                     \"<client id at the IdP>\" to bind ID tokens to the agent explicitly (SR-37)",
                    shown(issuer),
                    shown(&agent.id)
                ));
            }
        }
        if self.actor_auth == ActorAuth::ActorToken && agent_list.iter().any(Client::has_keys) {
            warnings.push(
                "[[agents]] entries have keys (jwks or jwks_url) but [token] actor_auth = \
                 \"actor_token\": client assertions, like client secrets, are refused"
                    .into(),
            );
        }
        if self.actor_auth == ActorAuth::ActorToken
            && agent_list.iter().any(Client::has_certificates)
        {
            warnings.push(
                "[[agents]] entries have tls_client_cert_sha256 or tls_client_ca_pem_path but \
                 [token] actor_auth = \"actor_token\": TLS client certificates, like client \
                 secrets, are refused at POST /token"
                    .into(),
            );
        }
        if self.require_actor_auth && agent_list.is_empty() && self.actor_trust.is_empty() {
            warnings.push(
                "[[agents]] and [[actor_trust]] are empty and [token] require_actor_auth = \
                 true: every token exchange will be rejected"
                    .into(),
            );
        }
        if self.allow_unsigned_chain && pep_list.is_empty() {
            anyhow::bail!(
                "[authzen] allow_unsigned_chain = true needs at least one [[peps]] entry"
            );
        }
        if !self.idps.is_empty() && agent_list.is_empty() {
            warnings.push(
                "[[idps]] are configured but [[agents]] is empty; IdP intake rejects every \
                 request"
                    .into(),
            );
        }
        let agents_sha256 = list_sha256(agents, &agent_list);
        let peps_sha256 = list_sha256(peps, &pep_list);
        Ok((
            ClientSets {
                agents: agent_list,
                peps: pep_list,
                agent_entries: agents.to_vec(),
                pep_entries: peps.to_vec(),
                agents_sha256,
                peps_sha256,
            },
            warnings,
        ))
    }

    /// Warnings for agents a reload removed that can still be the agent of a new token under
    /// these settings: by name alone when `[token] require_actor_auth = false` (an exchange's
    /// `actor` is then not authenticated), and with a workload token when an `[[actor_trust]]`
    /// entry can map to the id and `[token] actor_auth` accepts actor tokens. Neither setting
    /// is reloaded.
    pub(crate) fn removed_agent_warnings(&self, removed: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let actor_tokens = self.actor_auth != ActorAuth::Secret;
        for id in removed {
            if !self.require_actor_auth {
                out.push(format!(
                    "the removed agent `{}` can still be named as the actor of an exchange: \
                     [token] require_actor_auth = false does not authenticate it (a restart \
                     with require_actor_auth = true stops that)",
                    shown(id)
                ));
            }
            let mapped = self
                .actor_trust
                .iter()
                .any(|ids| ids.as_ref().is_none_or(|ids| ids.contains(id)));
            if actor_tokens && mapped {
                out.push(format!(
                    "the removed agent `{}` may still authenticate with an actor_token: an \
                     [[actor_trust]] entry can map a workload to this id, and removing that \
                     takes a restart",
                    shown(id)
                ));
            }
        }
        out
    }
}

/// The SHA-256 (lowercase hex) of a list's canonical form: the compact JSON array of
/// `[id, secret_sha256, thumbprints]` per entry, sorted by id, where `secret_sha256` is the
/// lowercase digest or `null` and `thumbprints` the sorted RFC 7638 SHA-256 thumbprints
/// (base64url) of the entry's `jwks` keys. An entry with `jwks_url` has four more members,
/// [`remote_row`]: `[id, secret_sha256, [], jwks_url, jwks_ttl_seconds, ca_pem_path,
/// ca_pem_sha256]`; an entry without one keeps three, so a list without `jwks_url` has the
/// digest it had before the setting existed. An entry with `tls_client_cert_sha256` has one
/// more member after those, [`cert_row`]: `{"tls_client_cert_sha256": [sorted thumbprints]}`;
/// an entry without it has none, so a list without certificates keeps its digest too. An
/// entry with `tls_client_ca_pem_path` has one more member instead, [`pki_row`]; an entry
/// without it has none, so lists without it keep their digest as well. The keys
/// at a URL are not in it: they change without a reload. `built` is the list as built from `entries`, which holds the digest of
/// each `ca_pem_path` file as it was read. Recorded in the reload's audit record, so that a
/// config file can be shown to hold the lists that were put in force; no secret or key
/// material goes into it beyond digests and thumbprints.
pub(crate) fn list_sha256(entries: &[AgentConfig], built: &Clients) -> String {
    let mut rows: Vec<Value> = entries
        .iter()
        .map(|a| {
            let mut thumbprints: Vec<String> = a
                .jwks
                .as_deref()
                .and_then(|t| serde_json::from_str::<Value>(t).ok())
                .and_then(|v| v.get("keys").and_then(Value::as_array).cloned())
                .unwrap_or_default()
                .iter()
                .map(jwk_thumbprint)
                .collect();
            thumbprints.sort();
            let mut row = vec![
                Value::from(a.id.clone()),
                a.secret_sha256
                    .as_deref()
                    .map_or(Value::Null, |d| Value::from(d.to_ascii_lowercase())),
                Value::from(thumbprints),
            ];
            row.extend(remote_row(a, built).into_iter().flatten());
            row.extend(cert_row(a));
            row.extend(pki_row(a, built));
            Value::Array(row)
        })
        .collect();
    rows.sort_by(|x, y| x[0].as_str().cmp(&y[0].as_str()));
    hex::encode(Sha256::digest(Value::Array(rows).to_string().as_bytes()))
}

/// The settings of an entry's `jwks_url`, `None` without one: `[jwks_url, jwks_ttl_seconds,
/// ca_pem_path, ca_pem_sha256]`, with the URL and the path as written, the TTL in force (the
/// default when unset) and the lowercase hex SHA-256 of the CA file's bytes as `built` read
/// them; the path and its digest are `null` without `ca_pem_path`.
fn remote_row(a: &AgentConfig, built: &Clients) -> Option<[Value; 4]> {
    let url = a.jwks_url.as_ref()?;
    Some([
        Value::from(url.clone()),
        Value::from(
            a.jwks_ttl_seconds
                .unwrap_or(DEFAULT_CLIENT_JWKS_TTL_SECONDS),
        ),
        a.ca_pem_path
            .as_ref()
            .map_or(Value::Null, |p| Value::from(p.display().to_string())),
        built
            .ca_pem_sha256(&a.id)
            .map_or(Value::Null, |d| Value::from(d.to_owned())),
    ])
}

/// The certificate settings of an entry, `None` without `tls_client_cert_sha256`: the object
/// `{"tls_client_cert_sha256": [...]}` with the thumbprints sorted, as written (the list check
/// accepts lowercase hex only).
fn cert_row(a: &AgentConfig) -> Option<Value> {
    let mut pins = a.tls_client_cert_sha256.clone()?;
    pins.sort();
    Some(serde_json::json!({ "tls_client_cert_sha256": pins }))
}

/// The `tls_client_auth` settings of an entry, `None` without them: the object
/// `{"tls_client_ca_pem_path": <path as written>, "tls_client_ca_pem_sha256": <the lowercase
/// hex SHA-256 of the file's bytes as built read them>, <name key>: <name>}`, where the name
/// key is `tls_client_auth_san_uri` (the URI as written) or `tls_client_auth_san_dns` (the
/// name in lowercase).
fn pki_row(a: &AgentConfig, built: &Clients) -> Option<Value> {
    let pki = built.find(&a.id)?.pki.as_ref()?;
    let mut row = Map::new();
    row.insert(
        "tls_client_ca_pem_path".into(),
        Value::from(pki.ca_path.display().to_string()),
    );
    row.insert(
        "tls_client_ca_pem_sha256".into(),
        Value::from(pki.ca.sha256().to_owned()),
    );
    row.insert(
        pki.name.key().into(),
        Value::from(pki.name.value().to_owned()),
    );
    Some(Value::Object(row))
}

/// The RFC 7638 SHA-256 thumbprint (base64url) of a public JWK: the required members of its
/// `kty` (`RSA`: `e`, `kty`, `n`; `EC`: `crv`, `kty`, `x`, `y`; `OKP`: `crv`, `kty`, `x`), in
/// that order, as compact JSON. A key the list check accepted always has them; anything else
/// gives an empty string.
fn jwk_thumbprint(jwk: &Value) -> String {
    let member = |k: &str| jwk.get(k).and_then(Value::as_str);
    let members: &[&str] = match member("kty") {
        Some("RSA") => &["e", "kty", "n"],
        Some("EC") => &["crv", "kty", "x", "y"],
        Some("OKP") => &["crv", "kty", "x"],
        _ => return String::new(),
    };
    let mut canonical = String::from("{");
    for (i, k) in members.iter().enumerate() {
        let Some(v) = member(k) else {
            return String::new();
        };
        if i > 0 {
            canonical.push(',');
        }
        canonical.push_str(&format!("{}:{}", Value::from(*k), Value::from(v)));
    }
    canonical.push('}');
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The `[[agents]]` and `[[peps]]` in force, swapped whole by `POST /admin/agents/reload`, the
/// way [`crate::operators::SharedAdminCredentials`] holds the admin credentials. A request
/// takes one [`snapshot`](Self::snapshot) and authenticates against it; a reload builds the new
/// lists with no lock held and [`swap`](Self::swap)s them in. The lock is held only to copy or
/// replace the pointer, never across an `await`, so a request sees the old lists or the new
/// ones, never a mix, and agents and PEPs change together.
///
/// The lock guards a single `Arc` replaced in one store, so a panic cannot leave it
/// half-written: poisoning is ignored.
#[derive(Debug)]
pub struct SharedClients {
    current: RwLock<Arc<ClientSets>>,
}

impl SharedClients {
    /// Put `sets` in force.
    pub fn new(sets: ClientSets) -> Self {
        Self {
            current: RwLock::new(Arc::new(sets)),
        }
    }

    /// The lists in force now. They stay usable, unchanged, after a later swap.
    pub fn snapshot(&self) -> Arc<ClientSets> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Put `sets` in force and return the lists they replace.
    pub fn swap(&self, sets: Arc<ClientSets>) -> Arc<ClientSets> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *current, sets)
    }
}

/// A validation that checks the signature with `alg` and nothing else: the claims are checked
/// by [`Clients::verify_assertion`] itself.
fn signature_only(alg: Algorithm) -> Validation {
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation
}

/// Public keys, one per algorithm of [`CLIENT_ASSERTION_ALGS`], whose private halves were
/// thrown away when they were made. A refused assertion that has no key of the client to be
/// verified with is verified against the one of its algorithm (and refused whatever the
/// outcome), so that an unknown client id costs about what a bad signature does (SR-110). The
/// RSA key is 2048 bits, the smallest a client's may be.
const DECOY_JWKS: &str = r#"{"keys":[
{"kty":"RSA","kid":"decoy-rs256","e":"AQAB","n":"pX1GfhnQTCVuVfVtWZ1IAtNx378l1QCdWk5c0XGyBUGYiWrkfrdduEmOImieB-SnUzqgiM14prYqbp6Sd-JNykZjBNqU73pACESFAvaOVqObNjZBZtiNivSUkm5XoSjkKo7HStGhOdodar9CkSa-aVyUgSOsPtAeOyoY7HmxGzV7NO49VhS4W_Qz3BpH8x_6Ioto3m4sp2ft6UTXk190pWaxX--OxGbbWfgi9R8RqGPr3KxYIep5f3BNKjKQRODmuj-BaFXI92JjrDYfqkcAym9-a9x13y2UCUfjCQC_U_HVTU_LSUwreZlOUEZoxqoaV0AwhhK6Z8636ngBdrCyZQ"},
{"kty":"EC","crv":"P-256","kid":"decoy-es256","x":"QJClA3Kr1c2kNzeXMdgXZoq_cEKBoS0sYKQOM5ZXq7I","y":"dHQ7FmzYT66EeSK6zSWjjE8uQqNhHF-f5xlm3NWXTg4"},
{"kty":"OKP","crv":"Ed25519","kid":"decoy-eddsa","x":"DJ5bniDYAmrmCNJd5wUssJlPcouDf48lma3i-3DZ9K8"}
]}"#;

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
    /// The TLS client certificate that authenticated the client, for
    /// [`ClientMethod::SelfSignedTls`] only.
    client_cert: Option<ClientCertificate>,
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

    /// For a client authenticated by its TLS client certificate, the `client_cert` member of
    /// the audit record's arguments ([`ClientCertificate::audit_value`]); `None` otherwise, so
    /// the records of other requests digest as before.
    pub(crate) fn client_cert_audit(&self) -> Option<Value> {
        self.client_cert
            .as_ref()
            .map(ClientCertificate::audit_value)
    }

    /// For an agent at `POST /token`, the refusals that come before any work and leave the
    /// request to be sent again unchanged, made before [`commit`](Self::commit) uses an
    /// assertion up: the agent's `[limits] token_requests_per_minute` (checked, not counted;
    /// SR-108) and, for an assertion, a `DPoP` header proof that will be refused, such as one
    /// without the current server nonce (SR-111). Without them, a rate-limited agent wrote a
    /// replay marker on every request, and a client that sent its request again as told
    /// (`Retry-After`, `use_dpop_nonce`) was refused as a replay.
    ///
    /// # Errors
    ///
    /// `429` `rate_limited`, and the DPoP refusals of [`crate::dpop::Dpop::check_header_first`].
    pub(crate) fn check_before_commit(
        &self,
        state: &crate::state::AppState,
        headers: &HeaderMap,
        mark: Option<&crate::limits::CallerMark>,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        state.limits.check_agent(mark, &self.id)?;
        if self.replay.is_some() {
            state.dpop.check_header_first(
                crate::dpop::header_proof(headers)?,
                &state.dpop.expected_url_for(headers, "/token"),
                now,
            )?;
        }
        Ok(())
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
            replay.use_once(key, *until, now).map_err(|r| match r {
                ReplayRefusal::Replayed => ApiError::from(AssertionError::Replayed),
                ReplayRefusal::Full | ReplayRefusal::Unavailable => ApiError::from(r),
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
    /// `alg` is not one of [`CLIENT_ASSERTION_ALGS`]: a server-wide check, made before the
    /// client is looked up.
    #[error("client_assertion alg is not one this server accepts (RS256, ES256, EdDSA)")]
    UnsupportedAlg,
    /// No key of the named client verified the assertion; the reason is for the log only.
    #[error("unknown client, or the client_assertion is not signed by one of the client's keys")]
    NotAuthenticated(Unverified),
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
            AssertionError::UnsupportedAlg => "client_assertion_unsupported_alg",
            AssertionError::NotAuthenticated(_) => "client_authentication_failed",
            AssertionError::AudienceMismatch => "client_assertion_audience_mismatch",
            AssertionError::MissingClaim(_) => "client_assertion_missing_claim",
            AssertionError::Expired => "client_assertion_expired",
            AssertionError::LifetimeTooLong => "client_assertion_lifetime_too_long",
            AssertionError::NotYetValid => "client_assertion_not_yet_valid",
            AssertionError::Replayed => "client_assertion_replayed",
        }
    }
}

/// Why an assertion did not authenticate before its signature verified. Never sent: every
/// one is [`AssertionError::NotAuthenticated`], `client_authentication_failed` (SR-110).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unverified {
    /// No entry has the assertion's `sub` as its id.
    UnknownClient,
    /// The entry has no `jwks`.
    NoKeys,
    /// The `kid` names none of the entry's keys, or there is none and the entry has several.
    UnknownKid,
    /// The key the `kid` names is for another algorithm than the header's `alg`.
    KeyAlgMismatch,
    /// The signature does not verify with the key.
    BadSignature,
    /// The entry's keys are at a `jwks_url` that could not be fetched, or whose key set was
    /// refused. Answered like the others, so it does not tell which ids exist (SR-110); the
    /// cause is logged at warn level.
    KeysUnavailable,
}

impl Unverified {
    /// The reason in the server's debug log.
    fn reason(self) -> &'static str {
        match self {
            Unverified::UnknownClient => "unknown_client",
            Unverified::NoKeys => "client_without_keys",
            Unverified::UnknownKid => "unknown_kid",
            Unverified::KeyAlgMismatch => "key_alg_mismatch",
            Unverified::BadSignature => "bad_signature",
            Unverified::KeysUnavailable => "jwks_unavailable",
        }
    }
}

impl From<AssertionError> for ApiError {
    fn from(e: AssertionError) -> Self {
        let d = e.description();
        match e {
            // The specific reason stays in the log (SR-110).
            AssertionError::NotAuthenticated(why) => {
                tracing::debug!(reason = why.reason(), "client assertion refused");
            }
            _ => tracing::debug!(reason = d, detail = %e, "client assertion refused"),
        }
        invalid_client(d, e.to_string())
    }
}

type JsonObject = Map<String, Value>;

/// Steps 1 (after the decoding) to 3 of [`Clients::verify_assertion`]: the checks that do not
/// depend on the client. They come before the lookup, so that their specific codes cannot
/// tell which ids exist (SR-110).
fn unverifiable<'a>(
    header: &'a JsonObject,
    payload: &'a JsonObject,
    body_id: Option<&str>,
) -> Result<Unverifiable<'a>, AssertionError> {
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
    // The algorithms are server-wide.
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(|a| Algorithm::from_str(a).ok())
        .filter(|a| allowed_alg(*a))
        .ok_or(AssertionError::UnsupportedAlg)?;
    let kid = match header.get("kid") {
        None | Some(Value::Null) => None,
        Some(Value::String(kid)) => Some(kid.as_str()),
        Some(_) => return Err(AssertionError::Malformed("kid is not a string")),
    };
    Ok(Unverifiable { sub, alg, kid })
}

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
    parse_client_jwk_set(&doc, None)
}

/// [`parse_client_jwks`] of a parsed document. `fetched` is the label of the cache of a key
/// set fetched from a `jwks_url`, which is held to the same rules but for one thing: a key the
/// server does not use (`use` other than `sig`, such as `enc`; a key type, curve or `alg`
/// outside [`CLIENT_ASSERTION_ALGS`]; an RSA modulus under 2048 bits) is skipped, with one
/// info line naming its `kid` and the reason, never the key. A set published for several
/// consumers may hold such keys. Still refused whole: a private or symmetric member, a member
/// that is not a JWK, more than [`MAX_CLIENT_KEYS`] keys, a `kid` listed twice among the keys
/// kept, and a set with no key left.
fn parse_client_jwk_set(doc: &Value, fetched: Option<&str>) -> Result<Vec<ClientKey>, String> {
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
    // A key the server does not use: refused in an inline `jwks`, skipped in a fetched set.
    let foreign = |label: &str, kid: Option<&str>, why: String| -> Result<(), String> {
        match fetched {
            None => Err(format!("{label}{why}")),
            Some(cache) => {
                // Debug-formatted: the kid and the key type are the key host's text.
                tracing::info!(
                    client = %cache,
                    kid = ?kid,
                    reason = ?why.trim_start_matches([':', ' ']),
                    "skipping a key of the fetched client key set"
                );
                Ok(())
            }
        }
    };
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
        let kid = obj.get("kid").and_then(Value::as_str);
        let kty = obj.get("kty").and_then(Value::as_str);
        if fetched.is_some() && kty.is_some_and(|t| !matches!(t, "RSA" | "EC" | "OKP")) {
            foreign(
                &label,
                kid,
                format!(
                    " has the key type `{}`, which is not accepted",
                    kty.unwrap_or_default()
                ),
            )?;
            continue;
        }
        let jwk: Jwk = serde_json::from_value(raw.clone())
            .map_err(|e| format!("{label} is not a JWK ({e})"))?;
        match obj.get("use") {
            None => {}
            Some(Value::String(u)) if u == "sig" => {}
            Some(Value::String(_)) => {
                foreign(&label, kid, ": use must be `sig`".into())?;
                continue;
            }
            Some(_) => return Err(format!("{label}: use must be a string")),
        }
        let alg = match key_alg(obj, &jwk) {
            Ok(alg) => alg,
            Err(KeyProblem::Foreign(e)) => {
                foreign(&label, kid, format!(": {e}"))?;
                continue;
            }
            Err(KeyProblem::Malformed(e)) => return Err(format!("{label}: {e}")),
        };
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
    if out.is_empty() {
        return Err(format!(
            "no key of the set is usable: the server accepts public keys of \
             {CLIENT_ASSERTION_ALGS:?}, with use `sig` or no use"
        ));
    }
    if out.len() > 1 && out.iter().any(|k| k.kid.is_none()) {
        return Err("with more than one key, every key needs a kid".into());
    }
    Ok(out)
}

/// Why a JWK cannot be a client key.
enum KeyProblem {
    /// A key the server does not use: a type, curve, `alg` or size it does not accept.
    Foreign(String),
    /// A member that is not what a JWK holds.
    Malformed(String),
}

/// The one algorithm a client key verifies: from its type and curve, which its `alg`, when
/// present, must agree with.
fn key_alg(obj: &Map<String, Value>, jwk: &Jwk) -> Result<Algorithm, KeyProblem> {
    let by_type = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => {
            let n = URL_SAFE_NO_PAD
                .decode(&rsa.n)
                .map_err(|_| KeyProblem::Malformed("RSA n is not base64url".into()))?;
            let len = n.iter().skip_while(|b| **b == 0).count();
            if len < MIN_RSA_MODULUS_BYTES {
                return Err(KeyProblem::Foreign(
                    "RSA keys must be at least 2048 bits".into(),
                ));
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
            return Err(KeyProblem::Foreign(format!(
                "unsupported key type or curve; accepted: RSA (RS256), EC P-256 (ES256), OKP \
                 Ed25519 (EdDSA), the server's algorithms {CLIENT_ASSERTION_ALGS:?}"
            )))
        }
    };
    match obj.get("alg") {
        None => Ok(by_type),
        Some(Value::String(a)) if Algorithm::from_str(a).is_ok_and(|x| x == by_type) => Ok(by_type),
        Some(Value::String(a)) => Err(KeyProblem::Foreign(format!(
            "alg `{a}` is not accepted for this key; the server accepts {CLIENT_ASSERTION_ALGS:?}, \
             each with its own key type"
        ))),
        Some(_) => Err(KeyProblem::Malformed("alg must be a string".into())),
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
        c.authenticate(h, id, secret, None, None, now())
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

    /// A fetched set leaves out the keys the server does not use, where an inline `jwks`
    /// refuses them (above), and is still refused whole for anything else.
    #[test]
    fn a_fetched_set_skips_keys_the_server_does_not_use() {
        let fetched = |doc: Value| parse_fetched_client_jwks(&doc, "[[agents]] `coder`");
        let good = public(&ed_key(), Some("good"));
        let mut enc = public(&ed_key(), Some("enc"));
        enc["use"] = "enc".into();
        let p384 = json!({"kty": "EC", "crv": "P-384", "kid": "p384", "x": "AA", "y": "AA"});
        let mut ps = rsa_jwk("ps", 256);
        ps["alg"] = "PS256".into();
        let small = rsa_jwk("small", 128);
        let other_type = json!({"kty": "AKP", "kid": "pq", "alg": "ML-DSA-44", "pub": "AA"});
        // The same kid as a kept key, on a key that is skipped: not a duplicate.
        let mut enc_twin = public(&ed_key(), Some("good"));
        enc_twin["use"] = "enc".into();
        let keys = fetched(json!({"keys": [
            enc.clone(), p384, ps, small.clone(), other_type, good.clone(), enc_twin
        ]}))
        .unwrap();
        let kids: Vec<_> = keys.iter().map(|k| k.kid.as_deref()).collect();
        assert_eq!(kids, [Some("good")]);
        // Inline, each of those is still a refusal.
        assert!(parse_err(json!({"keys": [good.clone(), enc.clone()]})).contains("use must be"));
        assert!(parse_err(json!({"keys": [good.clone(), small.clone()]})).contains("2048"));

        let refused = |doc: Value, why: &str| {
            let e = match fetched(doc.clone()) {
                Ok(_) => panic!("accepted {doc}"),
                Err(e) => e,
            };
            assert!(e.contains(why), "{why}: {e}");
        };
        refused(json!({"keys": [enc, small]}), "no key of the set is usable");
        let private = ed_key().private_jwk();
        refused(
            json!({"keys": [good.clone(), private]}),
            "private key member",
        );
        refused(
            json!({"keys": [good.clone(), {"kty": "oct", "kid": "h", "k": "c2VjcmV0"}]}),
            "symmetric",
        );
        refused(
            json!({"keys": [good.clone(), "a string"]}),
            "not a JSON object",
        );
        refused(
            json!({"keys": [good.clone(), {"kty": "RSA", "kid": "r"}]}),
            "not a JWK",
        );
        let mut odd_use = public(&ed_key(), Some("odd"));
        odd_use["use"] = json!(1);
        refused(json!({"keys": [good.clone(), odd_use]}), "not a JWK");
        refused(
            json!({"keys": [good.clone(), public(&ed_key(), Some("good"))]}),
            "listed twice",
        );
        let many: Vec<Value> = (0..=MAX_CLIENT_KEYS)
            .map(|i| public(&ed_key(), Some(&format!("k{i}"))))
            .collect();
        refused(json!({ "keys": many }), "at most");
        refused(json!({"keys": []}), "empty");
        refused(json!({"nokeys": []}), "JWK Set");
    }

    /// `jwks_url` is checked as an `[[idps]] jwks_url` is, and is not combined with `jwks`.
    #[test]
    fn jwks_url_entries_are_checked() {
        let url = |u: &str| AgentConfig::with_jwks_url("coder", u);
        let refused = |a: AgentConfig| Clients::agents(&[a], policy()).unwrap_err().to_string();
        for ok in [
            "https://keys.example/jwks.json",
            "http://127.0.0.1:9/jwks",
            "http://localhost/jwks",
        ] {
            let c = Clients::agents(&[url(ok)], policy()).unwrap();
            assert!(c.fetches_keys());
            assert!(c.iter().next().unwrap().has_keys());
        }
        assert!(!Clients::agents(&[], policy()).unwrap().fetches_keys());
        let e = refused(url("http://keys.example/jwks"));
        assert!(
            e.starts_with(
                "[[agents]] `coder`: jwks_url \"http://keys.example/jwks\": must be https://"
            ),
            "{e}"
        );
        assert!(refused(url("ftp://keys.example/jwks")).contains("must be https://"));
        let both = AgentConfig {
            jwks: Some(jwks(&[public(&ed_key(), None)])),
            ..url("https://keys.example/jwks")
        };
        let e = Clients::peps(&[both], policy()).unwrap_err().to_string();
        assert!(
            e.starts_with("[[peps]] `coder`: set jwks or jwks_url, not both"),
            "{e}"
        );
        let zero = AgentConfig {
            jwks_ttl_seconds: Some(0),
            ..url("https://keys.example/jwks")
        };
        assert!(refused(zero).contains("jwks_ttl_seconds must be positive"));
        let stray = AgentConfig {
            jwks_ttl_seconds: Some(60),
            ..AgentConfig::with_secret_sha256("coder", sha("s"))
        };
        assert!(refused(stray).contains("only for keys fetched from jwks_url"));
        let stray = AgentConfig {
            ca_pem_path: Some("/nonexistent.pem".into()),
            ..AgentConfig::with_secret_sha256("coder", sha("s"))
        };
        assert!(refused(stray).contains("only for keys fetched from jwks_url"));
        let missing = AgentConfig {
            ca_pem_path: Some("/nonexistent/ca.pem".into()),
            ..url("https://keys.example/jwks")
        };
        let e = refused(missing);
        assert!(
            e.contains("ca_pem_path \"/nonexistent/ca.pem\": cannot read"),
            "{e}"
        );
    }

    /// A row of the canonical form gets the `jwks_url` as a fourth member; a row without one
    /// keeps three, so the digest of a list without `jwks_url` does not change. A change of the
    /// URL (or its settings) is a change of the entry.
    #[test]
    fn the_list_digest_and_the_changes_cover_jwks_url() {
        /// A self-signed CA certificate, as PEM.
        fn ca_pem(name: &str) -> String {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, name);
            params.self_signed(&key).unwrap().pem()
        }
        let built = |list: &[AgentConfig]| Clients::agents(list, policy()).unwrap();
        let sha256 = |list: &[AgentConfig]| list_sha256(list, &built(list));
        let changed = |old: &[AgentConfig], new: &[AgentConfig]| {
            entry_changes((old, &built(old)), (new, &built(new))).changed
        };
        let a = AgentConfig::with_jwks_url("coder", "https://keys.example/a");
        let b = AgentConfig::with_jwks_url("coder", "https://keys.example/b");
        let s = AgentConfig::with_secret_sha256("planner", sha("p"));
        let digest = |rows: Value| hex::encode(Sha256::digest(rows.to_string().as_bytes()));
        assert_eq!(
            sha256(&[s.clone(), a.clone()]),
            digest(json!([
                ["coder", null, [], "https://keys.example/a", 300, null, null],
                ["planner", sha("p"), []]
            ]))
        );
        // An entry without jwks_url keeps its three members.
        assert_eq!(
            sha256(std::slice::from_ref(&s)),
            digest(json!([["planner", sha("p"), []]]))
        );
        let one = std::slice::from_ref(&a);
        assert_ne!(sha256(one), sha256(std::slice::from_ref(&b)));
        assert_eq!(changed(&[a.clone(), s.clone()], &[b, s.clone()]), ["coder"]);
        // The TTL in force: written as the default, it is no change.
        let ttl = |t: u64| AgentConfig {
            jwks_ttl_seconds: Some(t),
            ..a.clone()
        };
        assert_eq!(changed(one, &[ttl(60)]), ["coder"]);
        assert_ne!(sha256(one), sha256(&[ttl(60)]));
        assert_eq!(sha256(one), sha256(&[ttl(300)]));
        assert!(changed(one, &[ttl(300)]).is_empty());
        assert_eq!(
            entry_changes((one, &built(one)), (one, &built(one))),
            ClientChanges::default()
        );
        // ca_pem_path: the path and the content of the file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, ca_pem("first")).unwrap();
        let with_ca = AgentConfig {
            ca_pem_path: Some(path.clone()),
            ..a.clone()
        };
        let ca = std::slice::from_ref(&with_ca);
        let before = built(ca);
        let file_sha = hex::encode(Sha256::digest(std::fs::read(&path).unwrap()));
        assert_eq!(
            list_sha256(ca, &before),
            digest(json!([[
                "coder",
                null,
                [],
                "https://keys.example/a",
                300,
                path.display().to_string(),
                file_sha
            ]]))
        );
        assert_eq!(changed(one, ca), ["coder"]);
        std::fs::write(&path, ca_pem("second")).unwrap();
        let after = built(ca);
        assert_ne!(list_sha256(ca, &before), list_sha256(ca, &after));
        assert_eq!(
            entry_changes((ca, &before), (ca, &after)).changed,
            ["coder"]
        );
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
            jwks_url: None,
            jwks_ttl_seconds: None,
            ca_pem_path: None,
            tls_client_cert_sha256: None,
            tls_client_ca_pem_path: None,
            tls_client_auth_san_uri: None,
            tls_client_auth_san_dns: None,
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

    // --- TLS client certificates (RFC 8705 self_signed_tls_client_auth) -----------------

    /// A self-signed client certificate valid around [`now`], and its lowercase hex SHA-256.
    fn client_cert() -> (ClientCertificate, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        params.not_before = now() - time::Duration::days(1);
        params.not_after = now() + time::Duration::days(1);
        let der = params.self_signed(&key).unwrap().der().clone();
        let hex = hex::encode(Sha256::digest(der.as_ref()));
        (ClientCertificate::new(der), hex)
    }

    fn pinned(id: &str, pins: &[&str]) -> AgentConfig {
        AgentConfig::with_tls_client_cert_sha256(id, pins.iter().copied())
    }

    #[test]
    fn tls_client_cert_sha256_is_checked() {
        let refused = |a: AgentConfig| Clients::agents(&[a], policy()).unwrap_err().to_string();
        let good = "ab".repeat(32);
        let other = "cd".repeat(32);
        // 1 to 8 values; a certificate alone is a credential.
        let c = Clients::agents(&[pinned("coder", &[&good])], policy()).unwrap();
        let entry = c.iter().next().unwrap();
        assert!(entry.has_certificates() && !entry.has_secret() && !entry.has_keys());
        let eight: Vec<String> = (0..8).map(|i| format!("{i:064x}")).collect();
        let eight_refs: Vec<&str> = eight.iter().map(String::as_str).collect();
        Clients::agents(&[pinned("coder", &eight_refs)], policy()).unwrap();
        let nine: Vec<String> = (0..9).map(|i| format!("{i:064x}")).collect();
        let nine_refs: Vec<&str> = nine.iter().map(String::as_str).collect();
        let e = refused(pinned("coder", &nine_refs));
        assert!(e.contains("1 to 8") && e.contains("not 9"), "{e}");
        let e = refused(pinned("coder", &[]));
        assert!(e.contains("1 to 8") && e.contains("not 0"), "{e}");
        // Exactly 64 lowercase hex characters; the message never quotes the value.
        for bad in [
            good.to_ascii_uppercase(),
            good[..63].to_string(),
            format!("{good}0"),
            format!("{}zz", &good[..62]),
            format!("sha256:{good}"),
            URL_SAFE_NO_PAD.encode([0xabu8; 32]),
            String::new(),
        ] {
            let e = refused(pinned("coder", &[&other, &bad]));
            assert!(
                e.starts_with(
                    "[[agents]] `coder`: tls_client_cert_sha256 value 2: must be 64 lowercase hex"
                ),
                "{bad}: {e}"
            );
            assert!(bad.is_empty() || !e.contains(&bad), "{e}");
        }
        let e = refused(pinned("coder", &[&good, &other, &good]));
        assert!(
            e.contains("value 3: lists the same thumbprint twice"),
            "{e}"
        );
        // The same certificate on two entries of one list: one certificate, one client.
        let e = Clients::peps(
            &[pinned("a", &[&good]), pinned("b", &[&other, &good])],
            policy(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.starts_with("[[peps]] `b`: a tls_client_cert_sha256 value is also listed by `a`"),
            "{e}"
        );
        // With a secret and keys too.
        let mixed = AgentConfig {
            tls_client_cert_sha256: Some(vec![good.clone()]),
            ..AgentConfig::with_jwks("coder", jwks(&[public(&ed_key(), None)]))
        };
        let mixed = AgentConfig {
            secret_sha256: Some(sha("s")),
            ..mixed
        };
        let c = Clients::agents(&[mixed], policy()).unwrap();
        let e = c.iter().next().unwrap();
        assert!(e.has_certificates() && e.has_secret() && e.has_keys());
        // The TOML key parses into the field, and unknown spellings are refused.
        let cfg = crate::config::Config::from_toml(&format!(
            "[[agents]]\nid = \"coder\"\ntls_client_cert_sha256 = [\"{good}\"]\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.agents[0].tls_client_cert_sha256,
            Some(vec![good.clone()])
        );
        assert!(crate::config::Config::from_toml(&format!(
            "[[agents]]\nid = \"coder\"\ntls_client_cert_sha256 = \"{good}\"\n"
        ))
        .is_err());
    }

    #[test]
    fn a_pinned_certificate_authenticates_its_client() {
        let (cert, hex) = client_cert();
        let (other_cert, other_hex) = client_cert();
        let c = Clients::agents(
            &[
                pinned("coder", &[&"00".repeat(32), &hex]),
                AgentConfig::with_secret_sha256("planner", sha("p")),
                pinned("reviewer", &[&other_hex]),
            ],
            policy(),
        )
        .unwrap();
        let h = HeaderMap::new();
        let auth = c
            .authenticate(&h, Some("coder"), None, None, Some(&cert), now())
            .unwrap();
        assert_eq!(auth.id(), "coder");
        assert_eq!(auth.method(), ClientMethod::SelfSignedTls);
        assert_eq!(
            auth.client_cert_audit(),
            Some(json!({"x5t#S256": cert.x5t_s256(), "source": "tls"}))
        );
        assert!(auth.replay.is_none());
        assert_eq!(
            auth.commit(
                &ReplayCache::new(Arc::new(MemoryLeaseStore::new()), 10),
                now()
            )
            .unwrap(),
            "coder"
        );

        // Every refusal is the same answer: status, error, sub-code, detail and headers.
        let refusals = [
            // Unknown id.
            c.authenticate(&h, Some("nobody"), None, None, Some(&cert), now()),
            // An entry without certificates.
            c.authenticate(&h, Some("planner"), None, None, Some(&cert), now()),
            // The certificate of another entry.
            c.authenticate(&h, Some("reviewer"), None, None, Some(&cert), now()),
            c.authenticate(&h, Some("coder"), None, None, Some(&other_cert), now()),
            // Expired and not yet valid, though pinned.
            c.authenticate(
                &h,
                Some("coder"),
                None,
                None,
                Some(&cert),
                now() + time::Duration::days(2),
            ),
            c.authenticate(
                &h,
                Some("coder"),
                None,
                None,
                Some(&cert),
                now() - time::Duration::days(2),
            ),
        ];
        let answers: Vec<_> = refusals
            .into_iter()
            .map(|r| {
                let e = r.unwrap_err();
                let resp = axum::response::IntoResponse::into_response(e.clone());
                (
                    e.status,
                    e.code.clone(),
                    e.description,
                    e.detail.clone(),
                    resp.headers().clone(),
                )
            })
            .collect();
        assert_eq!(answers[0].0, StatusCode::UNAUTHORIZED);
        assert_eq!(answers[0].1, "invalid_client");
        assert_eq!(answers[0].2, Some("client_authentication_failed"));
        assert_eq!(answers[0].3, CERT_REFUSED);
        for a in &answers {
            assert_eq!(a, &answers[0]);
        }
        // Without a client id the certificate authenticates nobody: no credential at all.
        assert_eq!(
            code(c.authenticate(&h, None, None, None, Some(&cert), now())),
            "client_auth_missing"
        );
        // A list with no entries.
        let none = Clients::agents(&[], policy()).unwrap();
        assert_eq!(
            code(none.authenticate(&h, Some("coder"), None, None, Some(&cert), now())),
            "no_agents_configured"
        );
        // Rotation: either of two pinned certificates.
        let both = Clients::peps(&[pinned("gw", &[&hex, &other_hex])], policy()).unwrap();
        for crt in [&cert, &other_cert] {
            assert_eq!(
                both.authenticate(&h, Some("gw"), None, None, Some(crt), now())
                    .unwrap()
                    .id(),
                "gw"
            );
        }
    }

    /// A body credential decides; the certificate is then ignored, even when it is pinned.
    #[test]
    fn a_body_credential_wins_over_the_certificate() {
        let (cert, hex) = client_cert();
        let mut entry = pinned("coder", &[&hex]);
        entry.secret_sha256 = Some(sha("s3cret"));
        let c = Clients::agents(&[entry, pinned("solo", &[&"11".repeat(32)])], policy()).unwrap();
        let h = HeaderMap::new();
        let auth = c
            .authenticate(&h, Some("coder"), Some("s3cret"), None, Some(&cert), now())
            .unwrap();
        assert_eq!(auth.method(), ClientMethod::Secret);
        assert_eq!(auth.client_cert_audit(), None);
        // A wrong secret is refused though the certificate would have authenticated.
        assert_eq!(
            code(c.authenticate(&h, Some("coder"), Some("nope"), None, Some(&cert), now())),
            "client_authentication_failed"
        );
        let b = basic("coder", "nope");
        assert_eq!(
            code(c.authenticate(&b, None, None, None, Some(&cert), now())),
            "client_authentication_failed"
        );
        let b = basic("coder", "s3cret");
        assert_eq!(
            c.authenticate(&b, Some("coder"), None, None, Some(&cert), now())
                .unwrap()
                .method(),
            ClientMethod::Secret
        );
        // An entry with certificates only and a secret in the request: the secret path refuses.
        assert_eq!(
            code(c.authenticate(&h, Some("solo"), Some("x"), None, Some(&cert), now())),
            "client_authentication_failed"
        );
    }

    #[test]
    fn a_client_id_with_a_certificate_counts_as_presented() {
        let (cert, _) = client_cert();
        let h = HeaderMap::new();
        assert!(presented(&h, Some("coder"), None, None, Some(&cert)).unwrap());
        assert!(!presented(&h, Some("coder"), None, None, None).unwrap());
        assert!(!presented(&h, None, None, None, Some(&cert)).unwrap());
        assert!(presented(&h, None, Some("s"), None, None).unwrap());
        assert!(presented(&h, None, None, Some("a.b.c"), None).unwrap());
        assert!(presented(&basic("a", "b"), None, None, None, None).unwrap());
        assert!(!presented(&h, None, None, None, None).unwrap());
    }

    #[test]
    fn client_method_strings() {
        assert_eq!(ClientMethod::Secret.as_str(), "client_secret");
        assert_eq!(ClientMethod::PrivateKeyJwt.as_str(), "private_key_jwt");
        assert_eq!(
            ClientMethod::SelfSignedTls.as_str(),
            "self_signed_tls_client_auth"
        );
        assert_eq!(
            ClientMethod::SelfSignedTls.with_actor_token(),
            "actor_token+self_signed_tls_client_auth"
        );
        assert_eq!(
            ClientMethod::Secret.with_actor_token(),
            "actor_token+client_secret"
        );
    }

    /// The digest of a list without certificates is the one the code gave before they
    /// existed (a fixed value); an entry with certificates gets one more member; the order of
    /// the thumbprints is no change, a new set is.
    #[test]
    fn the_list_digest_and_the_changes_cover_certificates() {
        let built = |list: &[AgentConfig]| Clients::agents(list, policy()).unwrap();
        let sha256 = |list: &[AgentConfig]| list_sha256(list, &built(list));
        let changed = |old: &[AgentConfig], new: &[AgentConfig]| {
            entry_changes((old, &built(old)), (new, &built(new))).changed
        };
        let s = AgentConfig::with_secret_sha256("planner", sha("p"));
        assert_eq!(
            sha256(std::slice::from_ref(&s)),
            "2344eebf03579c4299b82a1cbadce9f3e3c2dbc0fa2758e713d38b3353821746"
        );
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        let ab = pinned("coder", &[&a, &b]);
        let ba = pinned("coder", &[&b, &a]);
        let only_a = pinned("coder", &[&a]);
        let digest = |rows: Value| hex::encode(Sha256::digest(rows.to_string().as_bytes()));
        assert_eq!(
            sha256(&[s.clone(), ab.clone()]),
            digest(json!([
                ["coder", null, [], {"tls_client_cert_sha256": [a, b]}],
                ["planner", sha("p"), []]
            ]))
        );
        assert_eq!(
            sha256(std::slice::from_ref(&ab)),
            sha256(std::slice::from_ref(&ba))
        );
        assert!(changed(std::slice::from_ref(&ab), std::slice::from_ref(&ba)).is_empty());
        assert_eq!(
            changed(std::slice::from_ref(&ab), std::slice::from_ref(&only_a)),
            ["coder"]
        );
        assert_ne!(
            sha256(std::slice::from_ref(&ab)),
            sha256(std::slice::from_ref(&only_a))
        );
        // Adding certificates to an entry that had a secret is a change.
        let mut with = s.clone();
        with.tls_client_cert_sha256 = Some(vec![a.clone()]);
        assert_eq!(
            changed(std::slice::from_ref(&s), std::slice::from_ref(&with)),
            ["planner"]
        );
        assert_ne!(sha256(std::slice::from_ref(&s)), sha256(&[with]));
        // With jwks_url as well: the certificate member comes after its four.
        let url = AgentConfig {
            tls_client_cert_sha256: Some(vec![a.clone()]),
            ..AgentConfig::with_jwks_url("coder", "https://keys.example/a")
        };
        assert_eq!(
            sha256(&[url]),
            digest(json!([[
                "coder",
                null,
                [],
                "https://keys.example/a",
                300,
                null,
                null,
                {"tls_client_cert_sha256": [a]}
            ]]))
        );
    }

    /// `tls_client_cert_sha256` is refused at startup and at reload unless the listener asks
    /// for client certificates; with actor_auth = "actor_token" it is a warning.
    #[test]
    fn certificates_need_a_listener_that_asks_for_them() {
        let pin = "ab".repeat(32);
        let mut config = crate::config::Config::default();
        let off = ClientRules::from_config(&config);
        let agent = [pinned("coder", &[&pin])];
        let secret = [AgentConfig::with_secret_sha256("gw", sha("g"))];
        for (agents, peps, section) in [
            (&agent[..], &secret[..], "[[agents]] `coder`"),
            (&secret[..], &[pinned("gw2", &[&pin])][..], "[[peps]] `gw2`"),
        ] {
            let e = off.check(agents, peps).err().unwrap().to_string();
            assert!(
                e.starts_with(&format!(
                    "{section}: tls_client_cert_sha256 needs [server.tls]"
                )),
                "{e}"
            );
        }
        config.server.public_url = Some("https://localhost:8443".into());
        config.server.tls = Some(crate::config::ServerTlsSection {
            cert_pem_path: "c".into(),
            key_pem_path: "k".into(),
            client_certificates: crate::config::ClientCertificates::Off,
        });
        let tls_off = ClientRules::from_config(&config);
        assert!(tls_off.check(&agent, &secret).is_err());
        config.server.tls.as_mut().unwrap().client_certificates =
            crate::config::ClientCertificates::Optional;
        let on = ClientRules::from_config(&config);
        let (sets, warnings) = on.check(&agent, &secret).unwrap();
        assert!(sets.agents.iter().next().unwrap().has_certificates());
        assert!(warnings.is_empty(), "{warnings:?}");
        // The same thumbprint on an agent and a PEP is allowed: different lists.
        on.check(&agent, &[pinned("gw", &[&pin])]).unwrap();
        config.token.actor_auth = ActorAuth::ActorToken;
        let (_, warnings) = ClientRules::from_config(&config)
            .check(&agent, &secret)
            .unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("tls_client_cert_sha256")
                && w.contains("actor_auth = \"actor_token\"")),
            "{warnings:?}"
        );
    }

    // --- TLS client certificates from a CA (RFC 8705 tls_client_auth) ---------------------

    const CODER_ID: &str = "spiffe://example.org/ns/agents/sa/coder";
    const REVIEWER_ID: &str = "spiffe://example.org/ns/agents/sa/reviewer";

    /// A CA for the `tls_client_auth` tests, its certificate written to a file.
    struct TestCa {
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
        pem: String,
    }

    impl TestCa {
        fn new(name: &str) -> Self {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, name);
            let pem = params.self_signed(&key).unwrap().pem();
            Self { params, key, pem }
        }

        fn write(&self, dir: &std::path::Path, name: &str) -> std::path::PathBuf {
            let path = dir.join(name);
            std::fs::write(&path, &self.pem).unwrap();
            path
        }

        /// A client certificate with these names, valid around [`now`].
        fn client(&self, names: Vec<rcgen::SanType>) -> ClientCertificate {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = names;
            params.not_before = now() - time::Duration::days(1);
            params.not_after = now() + time::Duration::days(1);
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
            ClientCertificate::new(params.signed_by(&key, &issuer).unwrap().der().clone())
        }
    }

    fn uri(s: &str) -> rcgen::SanType {
        rcgen::SanType::URI(s.try_into().unwrap())
    }

    fn dns(s: &str) -> rcgen::SanType {
        rcgen::SanType::DnsName(s.try_into().unwrap())
    }

    #[test]
    fn tls_client_auth_settings_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let ca = TestCa::new("agents CA").write(dir.path(), "ca.pem");
        let refused = |a: AgentConfig| Clients::agents(&[a], policy()).unwrap_err().to_string();
        let entry = AgentConfig::with_tls_client_auth_san_uri("coder", &ca, CODER_ID);
        let c = Clients::agents(std::slice::from_ref(&entry), policy()).unwrap();
        let built = c.iter().next().unwrap();
        assert!(built.has_certificates() && !built.has_secret() && !built.has_keys());
        assert_eq!(built.certificate_key(), "tls_client_ca_pem_path");
        let by_dns = AgentConfig::with_tls_client_auth_san_dns("coder", &ca, "Coder.Agents");
        Clients::peps(std::slice::from_ref(&by_dns), policy()).unwrap();

        // A CA file without a name, a name without a CA file, two names.
        let e = refused(AgentConfig {
            tls_client_auth_san_uri: None,
            ..entry.clone()
        });
        assert!(
            e.starts_with(
                "[[agents]] `coder`: tls_client_ca_pem_path needs tls_client_auth_san_uri or \
                 tls_client_auth_san_dns"
            ),
            "{e}"
        );
        for name in [
            AgentConfig {
                tls_client_ca_pem_path: None,
                ..entry.clone()
            },
            AgentConfig {
                tls_client_ca_pem_path: None,
                ..by_dns.clone()
            },
        ] {
            let e = refused(name);
            assert!(e.contains("needs tls_client_ca_pem_path"), "{e}");
        }
        let e = refused(AgentConfig {
            tls_client_auth_san_dns: Some("coder.agents".into()),
            ..entry.clone()
        });
        assert!(
            e.contains("set tls_client_auth_san_uri or tls_client_auth_san_dns, not both"),
            "{e}"
        );
        // Not with pins; with a secret, fine.
        let e = refused(AgentConfig {
            tls_client_cert_sha256: Some(vec!["ab".repeat(32)]),
            ..entry.clone()
        });
        assert!(
            e.contains(
                "set tls_client_cert_sha256 (a self-signed certificate) or \
                        tls_client_ca_pem_path (certificates from a CA), not both"
            ),
            "{e}"
        );
        Clients::agents(
            &[AgentConfig {
                secret_sha256: Some(sha("s")),
                ..entry.clone()
            }],
            policy(),
        )
        .unwrap();
        // Bad names: the message names the key, never the value.
        for (uri_value, dns_value) in [
            (Some("spiffe://Example.org/x"), None),
            (Some("not a uri"), None),
            (None, Some("*.agents.internal")),
            (None, Some("10.0.0.1")),
        ] {
            let e = refused(AgentConfig {
                tls_client_auth_san_uri: uri_value.map(Into::into),
                tls_client_auth_san_dns: dns_value.map(Into::into),
                ..entry.clone()
            });
            let (key, value) = match (uri_value, dns_value) {
                (Some(v), _) => ("tls_client_auth_san_uri", v),
                (_, Some(v)) => ("tls_client_auth_san_dns", v),
                _ => unreachable!(),
            };
            assert!(e.starts_with(&format!("[[agents]] `coder`: {key} ")), "{e}");
            assert!(!e.contains(value), "{e}");
        }
        // A file that is not a CA file.
        let bad = dir.path().join("leaf.pem");
        std::fs::write(
            &bad,
            "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let e = refused(AgentConfig::with_tls_client_auth_san_uri(
            "coder", &bad, CODER_ID,
        ));
        assert!(
            e.contains("tls_client_ca_pem_path") && e.contains("holds a private key"),
            "{e}"
        );
        assert!(!e.contains("c2VjcmV0"), "{e}");
        let e = refused(AgentConfig::with_tls_client_auth_san_uri(
            "coder",
            dir.path().join("missing.pem"),
            CODER_ID,
        ));
        assert!(e.contains("cannot read the file"), "{e}");
        // One name, one client: the same name on two entries of a list is refused (a DNS name
        // without regard to case), on an agent and a PEP it is not.
        let e = Clients::agents(
            &[
                entry.clone(),
                AgentConfig::with_tls_client_auth_san_uri("other", &ca, CODER_ID),
            ],
            policy(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.starts_with(
                "[[agents]] `other`: its tls_client_auth_san_uri is also the name of `coder`"
            ),
            "{e}"
        );
        let e = Clients::peps(
            &[
                by_dns.clone(),
                AgentConfig::with_tls_client_auth_san_dns("gw", &ca, "coder.AGENTS"),
            ],
            policy(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("tls_client_auth_san_dns is also the name of `coder`"),
            "{e}"
        );
        Clients::agents(
            &[
                entry.clone(),
                AgentConfig::with_tls_client_auth_san_uri("reviewer", &ca, REVIEWER_ID),
                AgentConfig::with_tls_client_auth_san_dns("dns", &ca, "coder.agents"),
            ],
            policy(),
        )
        .unwrap();
        // The TOML keys parse into the fields.
        let cfg = crate::config::Config::from_toml(&format!(
            "[[agents]]\nid = \"coder\"\ntls_client_ca_pem_path = \"{}\"\n\
             tls_client_auth_san_uri = \"{CODER_ID}\"\n\n\
             [[peps]]\nid = \"gw\"\ntls_client_ca_pem_path = \"ca.pem\"\n\
             tls_client_auth_san_dns = \"gw.peps\"\n",
            ca.display()
        ))
        .unwrap();
        assert_eq!(cfg.agents[0], entry);
        assert_eq!(
            cfg.peps[0].tls_client_auth_san_dns.as_deref(),
            Some("gw.peps")
        );
    }

    #[test]
    fn a_certificate_from_the_ca_authenticates_its_client_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let agents_ca = TestCa::new("agents CA");
        let ca = agents_ca.write(dir.path(), "ca.pem");
        let other_ca = TestCa::new("other CA");
        let (pinned_cert, pinned_hex) = client_cert();
        let c = Clients::agents(
            &[
                AgentConfig::with_tls_client_auth_san_uri("coder", &ca, CODER_ID),
                AgentConfig::with_tls_client_auth_san_uri("reviewer", &ca, REVIEWER_ID),
                AgentConfig::with_tls_client_auth_san_dns("builder", &ca, "builder.agents"),
                pinned("pinned", &[&pinned_hex]),
                AgentConfig::with_secret_sha256("planner", sha("p")),
            ],
            policy(),
        )
        .unwrap();
        let h = HeaderMap::new();
        let coder = agents_ca.client(vec![uri(CODER_ID)]);
        let auth = c
            .authenticate(&h, Some("coder"), None, None, Some(&coder), now())
            .unwrap();
        assert_eq!((auth.id(), auth.method()), ("coder", ClientMethod::Tls));
        assert_eq!(
            auth.client_cert_audit(),
            Some(json!({"x5t#S256": coder.x5t_s256(), "source": "tls"}))
        );
        assert!(auth.replay.is_none());
        let builder = agents_ca.client(vec![dns("BUILDER.agents")]);
        assert_eq!(
            c.authenticate(&h, Some("builder"), None, None, Some(&builder), now())
                .unwrap()
                .method(),
            ClientMethod::Tls
        );
        // Both methods in one list.
        assert_eq!(
            c.authenticate(&h, Some("pinned"), None, None, Some(&pinned_cert), now())
                .unwrap()
                .method(),
            ClientMethod::SelfSignedTls
        );

        // Every refusal is the answer of any refused certificate.
        let pin_refusal = c
            .authenticate(&h, Some("pinned"), None, None, Some(&coder), now())
            .unwrap_err();
        let refusals = [
            // Another agent's certificate from the same CA, both ways.
            c.authenticate(&h, Some("reviewer"), None, None, Some(&coder), now()),
            c.authenticate(
                &h,
                Some("coder"),
                None,
                None,
                Some(&agents_ca.client(vec![uri(REVIEWER_ID)])),
                now(),
            ),
            // The right name from another CA.
            c.authenticate(
                &h,
                Some("coder"),
                None,
                None,
                Some(&other_ca.client(vec![uri(CODER_ID)])),
                now(),
            ),
            // Expired, and not yet valid.
            c.authenticate(
                &h,
                Some("coder"),
                None,
                None,
                Some(&coder),
                now() + time::Duration::days(2),
            ),
            c.authenticate(
                &h,
                Some("coder"),
                None,
                None,
                Some(&coder),
                now() - time::Duration::days(2),
            ),
            // A wildcard name for an exact one.
            c.authenticate(
                &h,
                Some("builder"),
                None,
                None,
                Some(&agents_ca.client(vec![dns("*.agents")])),
                now(),
            ),
            // A self-signed certificate pinned for another entry, sent for a CA entry.
            c.authenticate(&h, Some("coder"), None, None, Some(&pinned_cert), now()),
            // A CA-issued certificate for an entry with a secret only, or for nobody.
            c.authenticate(&h, Some("planner"), None, None, Some(&coder), now()),
            c.authenticate(&h, Some("nobody"), None, None, Some(&coder), now()),
        ];
        for r in refusals {
            assert_eq!(r.unwrap_err(), pin_refusal);
        }
        assert_eq!(pin_refusal.code, "invalid_client");
        assert_eq!(
            pin_refusal.description,
            Some("client_authentication_failed")
        );
        assert_eq!(pin_refusal.detail, CERT_REFUSED);
    }

    #[test]
    fn a_body_credential_wins_over_a_certificate_from_the_ca() {
        let dir = tempfile::tempdir().unwrap();
        let agents_ca = TestCa::new("agents CA");
        let ca = agents_ca.write(dir.path(), "ca.pem");
        let entry = AgentConfig {
            secret_sha256: Some(sha("s3cret")),
            ..AgentConfig::with_tls_client_auth_san_uri("coder", &ca, CODER_ID)
        };
        let c = Clients::agents(&[entry], policy()).unwrap();
        let h = HeaderMap::new();
        let cert = agents_ca.client(vec![uri(CODER_ID)]);
        let a = c
            .authenticate(&h, Some("coder"), Some("s3cret"), None, Some(&cert), now())
            .unwrap();
        assert_eq!(a.method(), ClientMethod::Secret);
        assert_eq!(a.client_cert_audit(), None);
        assert_eq!(
            code(c.authenticate(&h, Some("coder"), Some("nope"), None, Some(&cert), now())),
            "client_authentication_failed"
        );
        assert_eq!(
            c.authenticate(&h, Some("coder"), None, None, Some(&cert), now())
                .unwrap()
                .method(),
            ClientMethod::Tls
        );
    }

    /// A certificate that carries the configured name of another entry of the same list is
    /// refused for every entry, with the answer of any refused certificate. A name no entry
    /// uses is fine, and an agent and a PEP may share a name.
    #[test]
    fn one_certificate_never_authenticates_two_clients_of_a_list() {
        let dir = tempfile::tempdir().unwrap();
        let agents_ca = TestCa::new("agents CA");
        let ca = agents_ca.write(dir.path(), "ca.pem");
        let entries = [
            AgentConfig::with_tls_client_auth_san_dns("builder", &ca, "builder.agents"),
            AgentConfig::with_tls_client_auth_san_dns("tester", &ca, "tester.agents"),
            AgentConfig::with_tls_client_auth_san_uri("coder", &ca, CODER_ID),
            AgentConfig::with_tls_client_auth_san_uri("web", &ca, "https://agents.example/web"),
            AgentConfig::with_secret_sha256("planner", sha("p")),
        ];
        let c = Clients::agents(&entries, policy()).unwrap();
        let h = HeaderMap::new();
        let auth = |id: &str, cert: &ClientCertificate| {
            c.authenticate(&h, Some(id), None, None, Some(cert), now())
        };
        let refusal = auth("builder", &agents_ca.client(vec![dns("tester.agents")])).unwrap_err();
        assert_eq!(refusal.description, Some("client_authentication_failed"));
        assert_eq!(refusal.detail, CERT_REFUSED);
        let refused = |id: &str, cert: &ClientCertificate| {
            assert_eq!(auth(id, cert).unwrap_err(), refusal, "{id}");
        };

        // Two DNS names, each another agent's: refused for both.
        let both = agents_ca.client(vec![dns("builder.agents"), dns("TESTER.agents")]);
        refused("builder", &both);
        refused("tester", &both);
        // A SPIFFE ID and the DNS name of another entry.
        let spiffe_and_dns = agents_ca.client(vec![uri(CODER_ID), dns("builder.agents")]);
        refused("coder", &spiffe_and_dns);
        refused("builder", &spiffe_and_dns);
        // Two URI names, the second another entry's.
        let two_uris = agents_ca.client(vec![uri("https://agents.example/web"), uri(CODER_ID)]);
        refused("web", &two_uris);
        // A wildcard name never stands for an entry, so it does not refuse either.
        let wildcard = agents_ca.client(vec![dns("builder.agents"), dns("*.agents")]);
        assert_eq!(auth("builder", &wildcard).unwrap().id(), "builder");
        // Extra names that no entry uses are fine.
        let extra = agents_ca.client(vec![
            dns("builder.agents"),
            dns("builder.internal"),
            uri("https://agents.example/other"),
        ]);
        assert_eq!(auth("builder", &extra).unwrap().id(), "builder");
        let extra = agents_ca.client(vec![uri(CODER_ID), dns("coder.internal")]);
        assert_eq!(auth("coder", &extra).unwrap().id(), "coder");
        // The same again on that connection (the cached answer) still checks the other names.
        refused("builder", &both);
        refused("builder", &both);

        // The rule is per list: a PEP may carry an agent's name.
        let peps = Clients::peps(
            &[AgentConfig::with_tls_client_auth_san_dns(
                "gateway",
                &ca,
                "gateway.peps",
            )],
            policy(),
        )
        .unwrap();
        let shared = agents_ca.client(vec![dns("gateway.peps"), dns("builder.agents")]);
        assert_eq!(
            peps.authenticate(&h, Some("gateway"), None, None, Some(&shared), now())
                .unwrap()
                .id(),
            "gateway"
        );
        let builder_peps = Clients::peps(
            &[AgentConfig::with_tls_client_auth_san_dns(
                "builder",
                &ca,
                "builder.agents",
            )],
            policy(),
        )
        .unwrap();
        let builder = agents_ca.client(vec![dns("builder.agents")]);
        assert_eq!(auth("builder", &builder).unwrap().id(), "builder");
        assert_eq!(
            builder_peps
                .authenticate(&h, Some("builder"), None, None, Some(&builder), now())
                .unwrap()
                .id(),
            "builder"
        );
    }

    #[test]
    fn tls_client_auth_method_strings() {
        assert_eq!(ClientMethod::Tls.as_str(), "tls_client_auth");
        assert_eq!(
            ClientMethod::Tls.with_actor_token(),
            "actor_token+tls_client_auth"
        );
    }

    /// The digest of lists without `tls_client_auth` settings does not change (the fixed
    /// value of the test above); an entry with them gets one more member, with the CA file's
    /// digest; a new file content, a new name or a new path is a change, rewriting the same
    /// DNS name in another case is not.
    #[test]
    fn the_list_digest_and_the_changes_cover_tls_client_auth() {
        let dir = tempfile::tempdir().unwrap();
        let first = TestCa::new("first");
        let ca = first.write(dir.path(), "ca.pem");
        let built = |list: &[AgentConfig]| Clients::agents(list, policy()).unwrap();
        let s = AgentConfig::with_secret_sha256("planner", sha("p"));
        assert_eq!(
            list_sha256(std::slice::from_ref(&s), &built(std::slice::from_ref(&s))),
            "2344eebf03579c4299b82a1cbadce9f3e3c2dbc0fa2758e713d38b3353821746"
        );
        let coder = AgentConfig::with_tls_client_auth_san_uri("coder", &ca, CODER_ID);
        let list = [s.clone(), coder.clone()];
        let old = built(&list);
        let digest = |rows: Value| hex::encode(Sha256::digest(rows.to_string().as_bytes()));
        let file_sha = hex::encode(Sha256::digest(first.pem.as_bytes()));
        assert_eq!(
            list_sha256(&list, &old),
            digest(json!([
                ["coder", null, [], {
                    "tls_client_ca_pem_path": ca.display().to_string(),
                    "tls_client_ca_pem_sha256": file_sha,
                    "tls_client_auth_san_uri": CODER_ID,
                }],
                ["planner", sha("p"), []]
            ]))
        );
        let changed = |old: (&[AgentConfig], &Clients), new: (&[AgentConfig], &Clients)| {
            entry_changes(old, new).changed
        };
        // The same file: no change.
        let again = built(&list);
        assert!(changed((&list, &old), (&list, &again)).is_empty());
        assert_eq!(list_sha256(&list, &old), list_sha256(&list, &again));
        // Another CA in the same file: a change, and another digest.
        std::fs::write(&ca, TestCa::new("second").pem).unwrap();
        let rotated = built(&list);
        assert_eq!(changed((&list, &old), (&list, &rotated)), ["coder"]);
        assert_ne!(list_sha256(&list, &old), list_sha256(&list, &rotated));
        // Another name.
        let renamed = [
            s.clone(),
            AgentConfig::with_tls_client_auth_san_uri("coder", &ca, REVIEWER_ID),
        ];
        assert_eq!(
            changed((&list, &rotated), (&renamed, &built(&renamed))),
            ["coder"]
        );
        // A DNS name in another case is the same name.
        let lower = [AgentConfig::with_tls_client_auth_san_dns(
            "coder",
            &ca,
            "coder.agents",
        )];
        let upper = [AgentConfig::with_tls_client_auth_san_dns(
            "coder",
            &ca,
            "CODER.Agents",
        )];
        assert!(changed((&lower, &built(&lower)), (&upper, &built(&upper))).is_empty());
        assert_eq!(
            list_sha256(&lower, &built(&lower)),
            list_sha256(&upper, &built(&upper))
        );
        // From a secret to CA settings, and back.
        assert_eq!(
            changed(
                (std::slice::from_ref(&s), &built(std::slice::from_ref(&s))),
                (
                    &[AgentConfig::with_tls_client_auth_san_uri(
                        "planner", &ca, CODER_ID
                    )],
                    &built(&[AgentConfig::with_tls_client_auth_san_uri(
                        "planner", &ca, CODER_ID
                    )])
                )
            ),
            ["planner"]
        );
    }

    /// `tls_client_ca_pem_path` needs a listener that asks for client certificates, at start
    /// and at reload, like `tls_client_cert_sha256`; with actor_auth = "actor_token" it is a
    /// warning.
    #[test]
    fn tls_client_auth_needs_a_listener_that_asks_for_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let ca = TestCa::new("agents CA").write(dir.path(), "ca.pem");
        let mut config = crate::config::Config::default();
        let agent = [AgentConfig::with_tls_client_auth_san_uri(
            "coder", &ca, CODER_ID,
        )];
        let pep = [AgentConfig::with_tls_client_auth_san_dns(
            "gw", &ca, "gw.peps",
        )];
        let e = ClientRules::from_config(&config)
            .check(&agent, &[])
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.starts_with(
                "[[agents]] `coder`: tls_client_ca_pem_path needs [server.tls] with \
                 client_certificates = \"optional\""
            ),
            "{e}"
        );
        let e = ClientRules::from_config(&config)
            .check(&[], &pep)
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.starts_with("[[peps]] `gw`: tls_client_ca_pem_path needs"),
            "{e}"
        );
        config.server.public_url = Some("https://localhost:8443".into());
        config.server.tls = Some(crate::config::ServerTlsSection {
            cert_pem_path: "c".into(),
            key_pem_path: "k".into(),
            client_certificates: crate::config::ClientCertificates::Off,
        });
        assert!(ClientRules::from_config(&config)
            .check(&agent, &pep)
            .is_err());
        config.server.tls.as_mut().unwrap().client_certificates =
            crate::config::ClientCertificates::Optional;
        let (sets, warnings) = ClientRules::from_config(&config)
            .check(&agent, &pep)
            .unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        // The agents and the PEPs of one start or reload read a shared CA file once: both
        // lists hold the same file.
        let ca_of = |c: &Clients| c.iter().next().unwrap().pki.as_ref().unwrap().ca.clone();
        assert!(Arc::ptr_eq(&ca_of(&sets.agents), &ca_of(&sets.peps)));
        config.token.actor_auth = ActorAuth::ActorToken;
        let (_, warnings) = ClientRules::from_config(&config)
            .check(&agent, &pep)
            .unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("tls_client_ca_pem_path") && w.contains("actor_token")),
            "{warnings:?}"
        );
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
                    jwks_url: None,
                    jwks_ttl_seconds: None,
                    ca_pem_path: None,
                    tls_client_cert_sha256: None,
                    tls_client_ca_pem_path: None,
                    tls_client_auth_san_uri: None,
                    tls_client_auth_san_dns: None,
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
        c.verify_assertion(a, body_id, &FetchedKey::none(), now())
            .map_err(|e| e.description())
    }

    /// The logged reason of a refusal that is `client_authentication_failed` (SR-110).
    fn unverified(c: &Clients, a: &str) -> Unverified {
        match c.verify_assertion(a, None, &FetchedKey::none(), now()) {
            Err(AssertionError::NotAuthenticated(why)) => why,
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
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
        let auth = c
            .authenticate(&h, None, None, Some(&a), None, now())
            .unwrap();
        assert_eq!(
            (auth.id(), auth.method()),
            ("both", ClientMethod::PrivateKeyJwt)
        );
        let auth = c
            .authenticate(&h, Some("both"), Some("b0th"), None, None, now())
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
        // A kid that is not a string, checked before the lookup: the same for any client id.
        for id in ["coder", "ghost"] {
            let bad_kid = new
                .key
                .sign_jws(&json!({"alg": "EdDSA", "kid": 7}), &claims(id));
            assert_eq!(v(&bad_kid), "client_assertion_malformed", "{id}");
        }
        // Everything before the signature has verified is one answer, as for a wrong secret
        // (SR-110), with the specific reason kept for the log. Unknown client, and a client
        // without keys.
        let fail = "client_authentication_failed";
        let ghost = sign(claims("ghost"));
        assert_eq!(
            (v(&ghost), unverified(&c, &ghost)),
            (fail, Unverified::UnknownClient)
        );
        let secretive = sign(claims("secretive"));
        assert_eq!(
            (v(&secretive), unverified(&c, &secretive)),
            (fail, Unverified::NoKeys)
        );
        // kid.
        let other_kid = new
            .key
            .sign_jws(&json!({"alg": "EdDSA", "kid": "nope"}), &claims("coder"));
        assert_eq!(
            (v(&other_kid), unverified(&c, &other_kid)),
            (fail, Unverified::UnknownKid)
        );
        let no_kid = new.key.sign_jws(&json!({"alg": "EdDSA"}), &claims("coder"));
        assert_eq!(
            (v(&no_kid), unverified(&c, &no_kid)),
            (fail, Unverified::UnknownKid)
        );
        // Signature: the other rotated key's kid, signed by the new key; another client's key.
        let swapped = new
            .key
            .sign_jws(&json!({"alg": "EdDSA", "kid": "2026-10"}), &claims("coder"));
        let by_solo = solo
            .key
            .sign_jws(&json!({"alg": "EdDSA", "kid": "2026-11"}), &claims("coder"));
        let mut tampered = old.sign(&claims("coder"));
        tampered.push('A');
        for a in [&swapped, &by_solo, &tampered] {
            assert_eq!((v(a), unverified(&c, a)), (fail, Unverified::BadSignature));
        }
        // And all of them are the same ApiError: status, error, code, detail.
        let h = HeaderMap::new();
        let answers: Vec<ApiError> = [&ghost, &secretive, &other_kid, &no_kid, &swapped]
            .into_iter()
            .map(|a| {
                c.authenticate(&h, None, None, Some(a), None, now())
                    .unwrap_err()
            })
            .collect();
        assert!(answers.iter().all(|e| *e == answers[0]), "{answers:?}");
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
        // ES256 is allowed, but not for an Ed25519 key: refused like a bad signature, since
        // the answer would tell the key's algorithm (SR-110).
        let es = new
            .key
            .sign_jws(&json!({"alg": "ES256", "kid": "2026-11"}), &claims("coder"));
        assert_eq!(
            verify(&c, &es, None).unwrap_err(),
            "client_authentication_failed"
        );
        assert_eq!(unverified(&c, &es), Unverified::KeyAlgMismatch);
        // `none` and HMAC are refused before the lookup, so the same for an unknown id.
        let ghost_none = format!(
            "{}.{}.",
            enc(&json!({"alg": "none"})),
            enc(&claims("ghost"))
        );
        assert_eq!(
            verify(&c, &ghost_none, None).unwrap_err(),
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

    /// There is a decoy key for every accepted algorithm, so that every refusal without a key
    /// of the client verifies a signature (SR-110), and none has a private member.
    #[test]
    fn a_decoy_key_for_every_algorithm() {
        let (c, ..) = setup();
        for alg in CLIENT_ASSERTION_ALGS {
            let alg = Algorithm::from_str(alg).unwrap();
            assert_eq!(
                c.decoys.iter().filter(|k| k.alg == alg).count(),
                1,
                "{alg:?}"
            );
        }
        assert_eq!(c.decoys.len(), CLIENT_ASSERTION_ALGS.len());
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
    /// refused, not tried against the other key, with the answer of a bad signature (SR-110).
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
            let auth = c
                .authenticate(&h, None, None, Some(&a), None, now())
                .unwrap();
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
        assert_eq!(unverified(&c, &crossed), Unverified::KeyAlgMismatch);
        assert_eq!(
            code(c.authenticate(&h, None, None, Some(&crossed), None, now())),
            "client_authentication_failed"
        );
    }

    /// One method per request; and an entry is authenticated only by what it holds.
    #[test]
    fn methods_do_not_mix_or_substitute() {
        let (c, _, new, _, both) = setup();
        let a = new.sign(&claims("coder"));
        let h = HeaderMap::new();
        assert_eq!(
            code(c.authenticate(&h, None, Some("x"), Some(&a), None, now())),
            "multiple_client_auth"
        );
        assert_eq!(
            code(c.authenticate(&basic("coder", "x"), None, None, Some(&a), None, now())),
            "multiple_client_auth"
        );
        let b = both.sign(&claims("both"));
        assert_eq!(
            code(c.authenticate(&h, Some("both"), Some("b0th"), Some(&b), None, now())),
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
            code(c.authenticate(&h, None, None, Some(&fake), None, now())),
            "client_authentication_failed"
        );
        let none = Clients::agents(&[], policy()).unwrap();
        assert_eq!(
            code(none.authenticate(&h, None, None, Some(&a), None, now())),
            "no_agents_configured"
        );
    }

    #[test]
    fn an_assertion_is_used_once_and_store_faults_fail_closed() {
        let (c, _, new, _, _) = setup();
        let h = HeaderMap::new();
        let a = new.sign(&claims("coder"));
        let replay = ReplayCache::new(Arc::new(MemoryLeaseStore::new()), 10);
        let auth = |a: &str| {
            c.authenticate(&h, None, None, Some(a), None, now())
                .unwrap()
        };
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
                extra: None,
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
        s.authenticate(&h, Some("secretive"), Some("s3cret"), None, None, now())
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
            .authenticate(&HeaderMap::new(), None, None, Some(&a), None, now())
            .unwrap_err();
        assert!(
            !e.detail.contains(&a) && !e.detail.contains("other"),
            "{}",
            e.detail
        );
    }
}
