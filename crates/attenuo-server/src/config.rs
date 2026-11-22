//! Server configuration, read from a TOML file.
//!
//! The file path comes from `--config` or, if that is absent, the `ATTENUO_CONFIG`
//! environment variable. See `config/example.toml` for an annotated example. Relative paths in
//! the file are resolved against the current working directory.
//!
//! `ATTENUO__<SECTION>__<KEY>` variables override scalar keys of the file before the startup
//! checks run ([`Config::load_with_env`], `overrides`).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use attenuo_core::{Capability, CapabilitySet};
use attenuo_policy::{AnnotationImport, ToolAttrs, ToolCatalog, UnknownTools};
use attenuo_proxy::UpstreamConfig;
use attenuo_token::MayAct;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod overrides;

pub use overrides::{EnvOverride, OVERRIDE_PREFIX};

/// Environment variable that names the config file when `--config` is not given.
pub const CONFIG_ENV: &str = "ATTENUO_CONFIG";

/// Environment variable that, when set, replaces `[admin] token` (so the secret need not be in
/// the file). The CLI reads the same variable.
pub const ADMIN_TOKEN_ENV: &str = "ATTENUO_ADMIN_TOKEN";

/// Minimum length of `[admin] token` outside loopback.
pub const MIN_ADMIN_TOKEN_LEN: usize = 32;

/// Admin tokens that have appeared in examples and docs. Refused outside loopback whatever
/// their length.
pub const PLACEHOLDER_ADMIN_TOKENS: &[&str] = &[
    "dev-admin-token-change-me",
    "demo-admin-token",
    "test-admin-token",
    "change-me",
    "changeme",
    "admin",
    "secret",
    "password",
];

/// The whole configuration file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[server]`: listen address and public URL.
    #[serde(default)]
    pub server: ServerSection,
    /// `[issuer]`: token issuer identity, signing key, chain depth and lifetimes.
    #[serde(default)]
    pub issuer: IssuerSection,
    /// `[policy]`: the Cedar policy file and the tool catalog.
    #[serde(default)]
    pub policy: PolicySection,
    /// `[audit]`: the audit log database, checkpoints, durability and the optional external sink.
    #[serde(default)]
    pub audit: AuditSection,
    /// MCP servers mounted at `/mcp/{name}`.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    /// `[[ext_authz]]`: servers an external gateway (agentgateway's HTTP `extAuthz`) may ask
    /// about at `/ext-authz/v1/mcp/{server}`. Empty by default, and then the route is not
    /// mounted. Checked by [`Config::check_ext_authz`].
    #[serde(default)]
    pub ext_authz: Vec<attenuo_proxy::ExtAuthzRoute>,
    /// `[admin]`: the bearer token for `/admin/*`.
    #[serde(default)]
    pub admin: AdminSection,
    /// Trusted identity providers for hop-0 intake (OIDC ID tokens and ID-JAG). See [`IdpConfig`].
    #[serde(default)]
    pub idps: Vec<IdpConfig>,
    /// Agents (OAuth clients) that may present user credentials at `POST /token`. When empty,
    /// every IdP intake request is rejected with `invalid_client`.
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    /// The ceiling of what a root token may carry, per (IdP issuer, agent[, subject]). Used by
    /// IdP intake and by the dev root mint. See [`RootGrant`].
    #[serde(default)]
    pub root_grants: Vec<RootGrant>,
    /// `[dev]`: development-only switches, all off by default.
    #[serde(default)]
    pub dev: DevSection,
    /// `[metrics]`: the Prometheus listener.
    #[serde(default)]
    pub metrics: MetricsSection,
    /// The opt-in admin console listener. See [`AdminUiSection`].
    #[serde(default)]
    pub admin_ui: AdminUiSection,
    /// `[proxy]`: the MCP proxy at `/mcp/{server}`.
    #[serde(default)]
    pub proxy: ProxySection,
    /// `[authzen]`: the AuthZEN evaluation endpoints.
    #[serde(default)]
    pub authzen: AuthzenSection,
    /// `[token]`: the `POST /token` exchange endpoint.
    #[serde(default)]
    pub token: TokenSection,
    /// Approvals of calls gated by `@obligation("approval")` (ADR-0009). See
    /// [`ApprovalsSection`].
    #[serde(default)]
    pub approvals: ApprovalsSection,
    /// Retention of session bindings (revoke by session). See [`LeasesSection`].
    #[serde(default)]
    pub leases: LeasesSection,
    /// Policy enforcement points allowed to send unsigned chains to the AuthZEN endpoint when
    /// `[authzen] allow_unsigned_chain = true`. Same shape as `[[agents]]`.
    #[serde(default)]
    pub peps: Vec<PepConfig>,
    /// Workload-identity issuers whose JWTs are accepted as RFC 8693 `actor_token` on an
    /// exchange (hop n to n+1). See [`ActorTrustConfig`].
    #[serde(default)]
    pub actor_trust: Vec<ActorTrustConfig>,
    /// `[telemetry]`: OpenTelemetry trace export, off by default
    /// ([`crate::telemetry::TelemetrySection`]).
    #[serde(default)]
    pub telemetry: crate::telemetry::TelemetrySection,
    /// `[logging]`: the log format and subject redaction ([`crate::logging::LoggingSection`]).
    #[serde(default)]
    pub logging: crate::logging::LoggingSection,
    /// `[limits]`: the in-flight cap, request timeouts and per-caller rate limits of the main
    /// listener. See [`LimitsSection`].
    #[serde(default)]
    pub limits: LimitsSection,
    /// The file this configuration was read from: set by [`Config::load`] and
    /// [`Config::load_with_env`], `None` for a configuration built in code or parsed from text.
    /// Not a key of the file. `POST /admin/operators/reload` re-reads `[[admin.operators]]`
    /// from it, and refuses with 409 `reload_unavailable` when there is none.
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
}

/// `[authzen]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthzenSection {
    /// Accept `subject.properties.chain` from the request body when there is no bearer token.
    /// Default `false`: `POST /access/v1/evaluation` requires `Authorization: Bearer <attenuo
    /// token>`. When `true`, a body-only request must also authenticate as a `[[peps]]` entry
    /// (HTTP Basic, or `pep_id` / `pep_secret` in the body), and every hop of the body chain
    /// must match what this server issued for its lease.
    #[serde(default)]
    pub allow_unsigned_chain: bool,
    /// Most evaluations one `POST /access/v1/evaluations` request may carry. Default 64.
    /// Larger requests are refused with 400 `batch_too_large` before anything is decided or
    /// audited. Also the most candidate tools one page of `POST /access/v1/search/action`
    /// evaluates, and that page's default size. Must be at least 1.
    #[serde(default = "default_max_batch")]
    pub max_batch: usize,
    /// Who gets `context.diagnostics` (the effective capabilities a call fell outside, lease
    /// ids, Cedar evaluation errors) in evaluation responses: `"peps"` (default; only callers
    /// that authenticated as a `[[peps]]` entry), `"always"` or `"never"`. Everyone else gets
    /// an empty list; the reason code, policy ids and decision id are always returned (SR-17).
    #[serde(default)]
    pub diagnostics: AuthzenDiagnostics,
}

impl Default for AuthzenSection {
    fn default() -> Self {
        Self {
            allow_unsigned_chain: false,
            max_batch: default_max_batch(),
            diagnostics: AuthzenDiagnostics::default(),
        }
    }
}

/// `[authzen] diagnostics`: who sees `context.diagnostics`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthzenDiagnostics {
    /// Every caller, including one that only holds a delegation token.
    Always,
    /// Only a caller that authenticated as a `[[peps]]` entry (HTTP Basic, or `pep_id` and
    /// `pep_secret` in the body, which may accompany a bearer token).
    #[default]
    Peps,
    /// Nobody.
    Never,
}

impl AuthzenDiagnostics {
    /// Should a caller get diagnostics, given whether it authenticated as a PEP?
    pub fn allows(self, authenticated_pep: bool) -> bool {
        match self {
            AuthzenDiagnostics::Always => true,
            AuthzenDiagnostics::Peps => authenticated_pep,
            AuthzenDiagnostics::Never => false,
        }
    }
}

/// Default for `[authzen] max_batch`.
pub const DEFAULT_MAX_BATCH: usize = 64;

fn default_max_batch() -> usize {
    DEFAULT_MAX_BATCH
}

/// `[token]`: the `POST /token` exchange endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSection {
    /// Require the caller of an exchange (hop n to n+1) to authenticate as the `actor` it
    /// names, with `[[agents]]` client credentials. Default `true`. When `false` the actor is
    /// asserted, not authenticated (the server logs a warning at startup), though credentials
    /// that are presented are still checked.
    #[serde(default = "default_true")]
    pub require_actor_auth: bool,
    /// How the actor of an exchange, and the agent of a hop-0 intake, may authenticate:
    /// `"secret"` (`[[agents]]` client credentials only: the client secret or a
    /// `private_key_jwt` assertion, whichever the agent's entry holds), `"actor_token"` (a JWT
    /// from an `[[actor_trust]]` issuer only) or `"either"` (default). With
    /// `require_actor_auth = true` one accepted method is mandatory for an exchange; hop 0
    /// always needs one.
    #[serde(default)]
    pub actor_auth: ActorAuth,
    /// Sender-constrained tokens (DPoP, RFC 9449; SR-24): `"off"`, `"optional"` (default) or
    /// `"required"`. See [`crate::dpop`]. Tokens already bound to a key need a proof whatever
    /// this says.
    #[serde(default)]
    pub dpop: DpopMode,
    /// How far a DPoP proof's `iat` may be behind the server's clock, in seconds. Default 300.
    #[serde(default = "default_dpop_max_age")]
    pub dpop_max_age_seconds: u64,
    /// How far a DPoP proof's `iat` may be ahead of the server's clock (a client clock that
    /// runs fast), in seconds: 0 to `dpop_max_age_seconds`. Unset: 10, or
    /// `dpop_max_age_seconds` when that is smaller ([`TokenSection::dpop_future_skew`]). Also
    /// sets how long proofs are refused after a quick restart ([`crate::dpop`], "Restart
    /// fence").
    #[serde(default)]
    pub dpop_future_skew_seconds: Option<u64>,
    /// Most DPoP proofs remembered for replay detection (each until its `iat` plus
    /// `dpop_max_age_seconds`). When full of live proofs, new ones get 503. Default 1000000.
    #[serde(default = "default_dpop_replay_capacity")]
    pub dpop_replay_capacity: usize,
    /// Server-provided DPoP nonces (RFC 9449 §8): `"off"` (default) or `"required"`. When
    /// required, every proof the server checks must carry a `nonce` the server issued in a
    /// `DPoP-Nonce` response header within the last one to two `dpop_max_age_seconds`; see
    /// [`crate::dpop`].
    #[serde(default)]
    pub dpop_nonce: DpopNonceMode,
    /// How far in the future a `private_key_jwt` client assertion's `exp` may be, in seconds
    /// from the server's clock (RFC 7523 §3: the server may limit how long an assertion it
    /// accepts lives). Default 300; between 1 and 3600.
    #[serde(default = "default_client_assertion_max_lifetime")]
    pub client_assertion_max_lifetime_seconds: u64,
    /// Clock skew allowed for a client assertion's `exp`, `nbf` and `iat`, in seconds. Default
    /// 60, the default `clock_skew_seconds` of `[[idps]]` and `[[actor_trust]]`; at most 600.
    #[serde(default = "default_clock_skew")]
    pub client_assertion_clock_skew_seconds: u64,
}

/// Default for `[token] dpop_max_age_seconds`.
pub const DEFAULT_DPOP_MAX_AGE_SECONDS: u64 = 300;
/// Default for `[token] dpop_future_skew_seconds`.
pub const DEFAULT_DPOP_FUTURE_SKEW_SECONDS: u64 = 10;
/// Default for `[token] dpop_replay_capacity`.
pub const DEFAULT_DPOP_REPLAY_CAPACITY: usize = 1_000_000;

fn default_dpop_max_age() -> u64 {
    DEFAULT_DPOP_MAX_AGE_SECONDS
}

fn default_dpop_replay_capacity() -> usize {
    DEFAULT_DPOP_REPLAY_CAPACITY
}

/// Default for `[token] client_assertion_max_lifetime_seconds`.
pub const DEFAULT_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS: u64 = 300;

fn default_client_assertion_max_lifetime() -> u64 {
    DEFAULT_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS
}

impl Default for TokenSection {
    fn default() -> Self {
        Self {
            require_actor_auth: true,
            actor_auth: ActorAuth::default(),
            dpop: DpopMode::default(),
            dpop_max_age_seconds: DEFAULT_DPOP_MAX_AGE_SECONDS,
            dpop_future_skew_seconds: None,
            dpop_replay_capacity: DEFAULT_DPOP_REPLAY_CAPACITY,
            dpop_nonce: DpopNonceMode::default(),
            client_assertion_max_lifetime_seconds: DEFAULT_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS,
            client_assertion_clock_skew_seconds: default_clock_skew(),
        }
    }
}

impl TokenSection {
    /// `dpop_future_skew_seconds` as applied: the value set, else 10 or
    /// `dpop_max_age_seconds` when that is smaller.
    pub fn dpop_future_skew(&self) -> u64 {
        self.dpop_future_skew_seconds
            .unwrap_or_else(|| DEFAULT_DPOP_FUTURE_SKEW_SECONDS.min(self.dpop_max_age_seconds))
    }

    /// Startup check of the DPoP settings.
    ///
    /// # Errors
    ///
    /// When `dpop_max_age_seconds` is outside 1..=3600, `dpop_future_skew_seconds` is above
    /// `dpop_max_age_seconds`, or `dpop_replay_capacity` is 0.
    pub fn check_dpop(&self) -> anyhow::Result<()> {
        if !(1..=3600).contains(&self.dpop_max_age_seconds) {
            anyhow::bail!("[token] dpop_max_age_seconds must be between 1 and 3600");
        }
        if self
            .dpop_future_skew_seconds
            .is_some_and(|f| f > self.dpop_max_age_seconds)
        {
            anyhow::bail!(
                "[token] dpop_future_skew_seconds must be between 0 and dpop_max_age_seconds ({})",
                self.dpop_max_age_seconds
            );
        }
        if self.dpop_replay_capacity == 0 {
            anyhow::bail!("[token] dpop_replay_capacity must be at least 1");
        }
        Ok(())
    }

    /// Startup check of the client assertion settings.
    ///
    /// # Errors
    ///
    /// When `client_assertion_max_lifetime_seconds` is outside 1..=3600 or
    /// `client_assertion_clock_skew_seconds` is above 600.
    pub fn check_client_assertion(&self) -> anyhow::Result<()> {
        if !(1..=3600).contains(&self.client_assertion_max_lifetime_seconds) {
            anyhow::bail!(
                "[token] client_assertion_max_lifetime_seconds must be between 1 and 3600"
            );
        }
        if self.client_assertion_clock_skew_seconds > 600 {
            anyhow::bail!("[token] client_assertion_clock_skew_seconds must be at most 600");
        }
        Ok(())
    }
}

/// `[token] dpop`: when tokens are bound to a key with DPoP (RFC 9449).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpopMode {
    /// Never bind new tokens; `DPoP` headers on issuance are ignored. Bound tokens still need
    /// proofs.
    Off,
    /// Bind a new token when the request carries a valid proof.
    #[default]
    Optional,
    /// Every issuance needs a proof, and unbound tokens are refused wherever a token is
    /// presented.
    Required,
}

/// `[token] dpop_nonce`: whether DPoP proofs must carry a server-provided nonce (RFC 9449 §8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpopNonceMode {
    /// No nonces: a proof's `nonce` claim, if any, is ignored.
    #[default]
    Off,
    /// Every DPoP response carries a `DPoP-Nonce` header, and every proof the server checks
    /// must carry a current one; otherwise 401 `use_dpop_nonce`.
    Required,
}

/// `[token] actor_auth`: which credentials authenticate the actor of an exchange and the agent
/// of a hop-0 intake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorAuth {
    /// `[[agents]]` client credentials only: the client secret (HTTP Basic or `client_id` /
    /// `client_secret`) or a `private_key_jwt` client assertion, per agent as its entry
    /// allows. An `actor_token` is refused.
    Secret,
    /// An `actor_token` verified against `[[actor_trust]]` only. Client credentials of
    /// either kind (secret or assertion) are refused.
    ActorToken,
    /// Either; when both are sent, both are checked.
    #[default]
    Either,
}

/// One `[[actor_trust]]` entry: an issuer of workload identities (a SPIFFE trust domain, or any
/// JWT issuer with a JWKS) whose tokens authenticate the actor of an exchange, or the agent
/// at hop 0.
///
/// Exactly one key source: `jwks_url` (with `issuer`), or `spiffe_trust_domain` with
/// `spiffe_bundle_url` (the SPIRE server's bundle endpoint, which serves a JWKS; never
/// discovered). A verified token's `sub` is turned into an attenuo agent id by
/// `subject_to_agent`, and that id must equal the exchange's `actor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorTrustConfig {
    /// Exact `iss` the tokens must carry. Required with `jwks_url`. Optional for a SPIFFE trust
    /// domain (JWT-SVIDs often have no `iss`); when set, it is required and checked.
    #[serde(default)]
    pub issuer: Option<String>,
    /// JWKS location of a generic JWT issuer.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// SPIFFE trust domain (`example.org`): `sub` must be a SPIFFE ID in it.
    #[serde(default)]
    pub spiffe_trust_domain: Option<String>,
    /// The trust domain's bundle endpoint (SPIRE `federation.bundle_endpoint`), serving the
    /// JWT-SVID signing keys as a JWKS. Required with `spiffe_trust_domain`.
    #[serde(default)]
    pub spiffe_bundle_url: Option<String>,
    /// PEM file of CA certificates trusted, for this entry's key fetches only, in addition to
    /// the built-in web PKI roots: for a key URL whose certificate a private CA issued. Read
    /// once at start; a file that is missing, unreadable or holds no certificate refuses to
    /// start. Verification and the hostname check are unchanged. See [`IdpConfig::ca_pem_path`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem_path: Option<PathBuf>,
    /// `aud` the token must carry (string, or an array containing it). Pick a value that no
    /// other relying party uses, such as attenuo's own URL.
    pub audience: String,
    /// How `sub` becomes an agent id. Default `"sub"`.
    #[serde(default)]
    pub subject_to_agent: SubjectToAgent,
    /// JWS algorithms accepted. Only asymmetric algorithms are allowed.
    #[serde(default = "default_idp_algs")]
    pub allowed_algs: Vec<String>,
    /// How long a fetched JWKS is used before it is fetched again. Default 300.
    #[serde(default = "default_jwks_ttl")]
    pub jwks_ttl_seconds: u64,
    /// Allowed clock skew for `exp`, `nbf` and `iat`. Default 60.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
}

/// `[[actor_trust]] subject_to_agent`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SubjectToAgentWire", into = "SubjectToAgentWire")]
pub enum SubjectToAgent {
    /// The agent id is `sub` itself (for SPIFFE, the whole `spiffe://...` ID).
    #[default]
    Sub,
    /// The agent id is the SPIFFE ID's path without the leading `/`
    /// (`spiffe://example.org/agents/coder` is `agents/coder`). Needs `spiffe_trust_domain`.
    SpiffePath,
    /// An explicit table from `sub` to agent id. A `sub` missing from it is refused.
    Map(BTreeMap<String, String>),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum SubjectToAgentWire {
    Mode(String),
    Map(BTreeMap<String, String>),
}

impl TryFrom<SubjectToAgentWire> for SubjectToAgent {
    type Error = String;

    fn try_from(w: SubjectToAgentWire) -> Result<Self, String> {
        match w {
            SubjectToAgentWire::Mode(m) => match m.as_str() {
                "sub" => Ok(SubjectToAgent::Sub),
                "spiffe_path" => Ok(SubjectToAgent::SpiffePath),
                other => Err(format!(
                    "subject_to_agent must be \"sub\", \"spiffe_path\" or a table, not `{other}`"
                )),
            },
            SubjectToAgentWire::Map(m) => Ok(SubjectToAgent::Map(m)),
        }
    }
}

impl From<SubjectToAgent> for SubjectToAgentWire {
    fn from(s: SubjectToAgent) -> Self {
        match s {
            SubjectToAgent::Sub => SubjectToAgentWire::Mode("sub".into()),
            SubjectToAgent::SpiffePath => SubjectToAgentWire::Mode("spiffe_path".into()),
            SubjectToAgent::Map(m) => SubjectToAgentWire::Map(m),
        }
    }
}

fn default_true() -> bool {
    true
}

/// One `[[peps]]` entry: `id` with `secret_sha256`, `jwks` or both, as for [`AgentConfig`].
pub type PepConfig = AgentConfig;

/// `[server]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Address to bind. Default `127.0.0.1:8080`.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Externally visible base URL (e.g. `https://attenuo.example.com`), the only source of
    /// the URLs in discovery documents. Required when `listen` is not a loopback address (the
    /// server refuses to start without it, SR-19). On loopback it may be left out: discovery
    /// then uses `http://<Host>`, and only a `Host` of `localhost`, `127.0.0.1` or `[::1]`
    /// (with an optional port) is accepted.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Accept an `http://` `public_url` whose host is not a loopback name. Default `false`: the
    /// server has no TLS of its own, so such a URL means tokens and admin bearers cross the
    /// network in cleartext, and the server refuses to start (S-9). Terminate TLS at a reverse
    /// proxy and set an `https://` `public_url` instead. Set this only when the plain-HTTP hop
    /// is on a network you trust; a warning is still logged at startup.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl ServerSection {
    /// Startup check (SR-19): `public_url`, when set, is an absolute `http(s)://` URL with a
    /// host; when unset, `listen` must be a loopback address, because discovery would
    /// otherwise build its URLs from a `Host` header any client can choose.
    ///
    /// # Errors
    ///
    /// An `http://` `public_url` must name a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`)
    /// unless `allow_insecure_http` is set (S-9).
    ///
    /// # Errors
    ///
    /// When `public_url` does not start with `https://` or `http://`, has no host, or contains
    /// whitespace, a control character, `?` or `#`; when it is `http://` with a host that is not
    /// loopback and `allow_insecure_http` is not set; or when it is unset and `listen` is not a
    /// loopback address.
    pub fn check_public_url(&self) -> anyhow::Result<()> {
        match self.public_url.as_deref() {
            Some(url) => {
                let rest = url
                    .strip_prefix("https://")
                    .or_else(|| url.strip_prefix("http://"))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "[server] public_url = {url:?} must start with https:// or http://"
                        )
                    })?;
                let host = rest.split('/').next().unwrap_or_default();
                let bad_char =
                    |c: char| c.is_whitespace() || c.is_control() || c == '?' || c == '#';
                if host.is_empty() || url.chars().any(bad_char) {
                    anyhow::bail!(
                        "[server] public_url = {url:?} must be a base URL such as \
                         https://attenuo.example.com (a host, no query or fragment)"
                    );
                }
                if url.starts_with("http://") && !url_host_is_loopback(url) {
                    if !self.allow_insecure_http {
                        anyhow::bail!(
                            "[server] public_url = {url:?} is plain http:// on a host that is not \
                             loopback. The server has no TLS of its own, so tokens and the admin \
                             bearer would cross the network in cleartext. Terminate TLS at a \
                             reverse proxy and set an https:// public_url, or set \
                             [server] allow_insecure_http = true if this hop is on a network you \
                             trust."
                        );
                    }
                    tracing::warn!(
                        public_url = %url,
                        "[server] allow_insecure_http = true: public_url is plain http:// off \
                         loopback, so tokens cross the network in cleartext"
                    );
                }
                Ok(())
            }
            None if self.listen.ip().is_loopback() => Ok(()),
            None => anyhow::bail!(
                "[server] listen = {} is not a loopback address and [server] public_url is not \
                 set. Set public_url to the URL clients use (for example \
                 https://attenuo.example.com): without it the AuthZEN discovery document would \
                 be built from the request's Host header, which any client can choose.",
                self.listen
            ),
        }
    }
}

/// Is `host` (a `Host` header value) a loopback name, `localhost`, `127.0.0.1` or `[::1]`,
/// with an optional numeric port? Discovery accepts only these when `[server] public_url` is
/// unset (SR-19).
pub fn is_loopback_host(host: &str) -> bool {
    let (name, port) = match host.strip_prefix("[::1]") {
        Some(rest) => ("[::1]", rest),
        None => match host.find(':') {
            Some(i) => host.split_at(i),
            None => (host, ""),
        },
    };
    let port_ok = match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(p) => !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()),
    };
    port_ok && (name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1" || name == "[::1]")
}

/// Does the absolute URL `url` name a loopback host: `localhost`, an address in `127.0.0.0/8`
/// or `[::1]`? `false` for anything that does not parse as a URL with a host.
///
/// Used where plain `http://` is accepted only on the machine itself: `[server] public_url`
/// (S-9) and the JWKS and SPIFFE bundle fetches (S-8). `localhost` passes on its name; the
/// key-fetch client connects it to `127.0.0.1` or `[::1]` itself rather than ask the system
/// resolver, which could send it to DNS (`idp::jwks::fetch_client`, SR-107). Nothing is
/// fetched from `public_url`.
pub fn url_host_is_loopback(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // The parser lowercases domain names and prints IPv6 addresses in brackets.
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            public_url: None,
            allow_insecure_http: false,
        }
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

/// `[issuer]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerSection {
    /// `iss` of every token this server mints.
    #[serde(default = "default_issuer")]
    pub issuer: String,
    /// `aud` of every token this server mints (and requires on verification).
    #[serde(default = "default_audience")]
    pub audience: String,
    /// Most hops a chain may have, checked at exchange and at every call. Default
    /// [`attenuo_core::chain::DEFAULT_MAX_DEPTH`].
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    /// Lifetime of a minted token, in seconds (default 900); an exchanged hop never outlives its
    /// parent. Must be positive.
    #[serde(default = "default_ttl")]
    pub default_ttl_seconds: u64,
    /// How long a hop's lease lives after issuance or renewal (default 300). Revocation takes
    /// effect immediately; this bounds how long a lease the holder stopped renewing (for
    /// example a crashed agent) keeps authorizing calls. Always capped by the token's `exp`.
    #[serde(default = "default_lease_interval")]
    pub lease_interval_seconds: u64,
    /// PKCS#8 Ed25519 private key. Generated (and written with mode 0600) if the file does not
    /// exist. When unset, an ephemeral key is generated at every start.
    #[serde(default)]
    pub private_key_pem_path: Option<PathBuf>,
    /// Retired signing keys (PEM files, private or public) that stay trusted for verification
    /// and are published in the JWKS, so tokens signed before a rotation keep working until
    /// they expire. They never sign. Remove an entry once its tokens have expired.
    #[serde(default)]
    pub previous_key_paths: Vec<PathBuf>,
}

impl Default for IssuerSection {
    fn default() -> Self {
        Self {
            issuer: default_issuer(),
            audience: default_audience(),
            max_depth: default_max_depth(),
            default_ttl_seconds: default_ttl(),
            lease_interval_seconds: default_lease_interval(),
            private_key_pem_path: None,
            previous_key_paths: Vec::new(),
        }
    }
}

fn default_issuer() -> String {
    "http://127.0.0.1:8080".into()
}
fn default_audience() -> String {
    "attenuo".into()
}
fn default_max_depth() -> usize {
    attenuo_core::chain::DEFAULT_MAX_DEPTH
}
fn default_ttl() -> u64 {
    900
}
fn default_lease_interval() -> u64 {
    300
}

/// `[policy]`
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    /// Cedar policy file. Reloaded by `POST /admin/policies/reload`. When unset, the
    /// policy set is empty, so Cedar denies every call, and reload is unavailable.
    #[serde(default)]
    pub policies_path: Option<PathBuf>,
    /// Inline tool catalog: `[policy.catalog.<server>.<tool>]` tables with `readonly`,
    /// `sensitive` and `inputs = { arg = "string" | "long" | "bool" | "decimal" }`.
    #[serde(default)]
    pub catalog: BTreeMap<String, BTreeMap<String, ToolAttrs>>,
    /// JSON file with the same shape as `catalog`: `{ "<server>": { "<tool>": { ... } } }`.
    /// Merged over the inline catalog.
    #[serde(default)]
    pub catalog_path: Option<PathBuf>,
    /// Cedar schema file (Cedar schema syntax) that replaces the built-in base schema, the
    /// entity types the policies are validated against. Actions, context types and
    /// `UserAttributes` are still generated and appended. It must keep the entity types,
    /// attributes and hierarchy of the default (`attenuo_policy::DEFAULT_SCHEMA`), or the server
    /// refuses to start; it may add entity types and optional attributes. Read once at start.
    #[serde(default)]
    pub schema_path: Option<PathBuf>,
    /// Extra attributes of `originating_user.attributes` to declare in the Cedar schema, as
    /// `name = "string" | "long" | "bool" | "set<string>"` (any scalar inside `set<...>`).
    /// Merged over the built-in `mfa`, `roles`, `tenant` and `email`. Without a declaration, a
    /// policy that tests an attribute fails validation instead of silently never matching.
    #[serde(default)]
    pub user_attributes: BTreeMap<String, String>,
    /// What a `tools/call` for a `(server, tool)` pair missing from the catalog gets:
    /// `"deny"` (default; reason `tool_not_in_catalog`, audited like any decision),
    /// `"sensitive"` (evaluated with `resource.sensitive = true`) or `"allow"` (evaluated with
    /// default attributes, so `forbid ... when { resource.sensitive }` does not apply).
    #[serde(default)]
    pub unknown_tools: UnknownTools,
    /// **Deprecated.** Evaluate with the pre-SR-13 action ids, the bare tool name
    /// (`Action::"read_file"`), instead of `Action::"<server>/<tool>"`. A bare action matches
    /// that tool on every server. Default `false`; the server logs a warning when it is on.
    #[serde(default)]
    pub legacy_bare_actions: bool,
    /// Whether MCP tool annotations from `tools/list` (`readOnlyHint`, `destructiveHint`)
    /// change catalog entries: `"never"` (default) or `"narrowing"`, where an explicit
    /// `readOnlyHint: false` clears `readonly` and `destructiveHint: true` sets `destructive`,
    /// and nothing an annotation says makes a tool less restricted (ADR-0009).
    #[serde(default)]
    pub import_annotations: AnnotationImport,
    /// Whether run usage (`context.usage`) is kept for calls to destructive tools: `"auto"`
    /// (default) keeps it only when some loaded policy reads `context.usage` or the catalog
    /// declares `amount` or `destination` for some tool, re-decided on every policy reload;
    /// `true` always keeps it. Keeping it costs one lease-store write per allowed destructive
    /// call. `false` is refused.
    #[serde(default)]
    pub track_usage: attenuo_policy::TrackUsage,
}

impl PolicySection {
    /// The effective catalog: the inline table, then `catalog_path` on top.
    ///
    /// # Errors
    ///
    /// When `catalog_path` is set and the file cannot be read or does not parse as a catalog.
    pub fn load_catalog(&self) -> anyhow::Result<ToolCatalog> {
        let mut catalog = ToolCatalog::new();
        let mut add = |tables: &BTreeMap<String, BTreeMap<String, ToolAttrs>>| {
            for (server, tools) in tables {
                for (tool, attrs) in tools {
                    catalog.insert(server.clone(), tool.clone(), attrs.clone());
                }
            }
        };
        add(&self.catalog);
        if let Some(path) = &self.catalog_path {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading catalog {}: {e}", path.display()))?;
            let tables: BTreeMap<String, BTreeMap<String, ToolAttrs>> = serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("parsing catalog {}: {e}", path.display()))?;
            add(&tables);
        }
        Ok(catalog)
    }
}

/// `[audit]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    /// SQLite file holding the audit log and the lease registry. `":memory:"` keeps both in
    /// memory (lost on exit).
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,
    /// Sign a checkpoint (`{seq, head_hash, at, kid, signature}`, Ed25519 by the issuer key)
    /// every this many appended entries. Default 1000; 0 turns the count trigger off.
    #[serde(default = "default_checkpoint_every")]
    pub checkpoint_every: u64,
    /// Also sign one at least this often (in seconds) while entries are being appended, so a
    /// quiet log still gets its tail covered. Default 300; 0 turns the timer off. The two
    /// triggers are independent: whichever fires first writes the checkpoint.
    #[serde(default = "default_checkpoint_interval_seconds")]
    pub checkpoint_interval_seconds: u64,
    /// `"normal"` (default) or `"full"`: SQLite `synchronous` for a file-backed store, which
    /// always runs in WAL mode. `normal` does not sync on commit, so a power failure (not a
    /// process crash) can lose the newest decisions, never tear one or break the chain; `full`
    /// syncs every commit. Lease revocations always sync. Ignored for `":memory:"`.
    #[serde(default)]
    pub durability: attenuo_audit::Durability,
    /// How often (in seconds) a background thread checkpoints SQLite's write-ahead log into
    /// the database file (`PRAGMA wal_checkpoint(PASSIVE)`), so appends do not wait while a
    /// checkpoint copies and syncs. It also runs after every 256 commits; under continuous
    /// load, once the WAL passes 64 MB, appends pause for a short catch-up pass so the
    /// WAL starts over instead of growing. It truncates the WAL when the writer is idle, and
    /// once more at shutdown. Default 5; 0 leaves checkpoints to SQLite on the
    /// writer (every 1,000 pages, the behaviour before this setting). Unrelated to the signed
    /// audit checkpoints above. Ignored for `":memory:"`.
    #[serde(default = "default_wal_checkpoint_seconds")]
    pub wal_checkpoint_seconds: u64,
    /// Most audit appends that may wait for the writer thread at once. One more fails at once,
    /// and its decision is denied with `audit_error` (metric
    /// `audit_append_shed_total{cause="queue_full"}`). Default 1024, between 16 and 1000000.
    #[serde(default = "default_append_queue_max")]
    pub append_queue_max: u64,
    /// How long, in seconds, an audit append waits for the writer thread before it fails and
    /// its decision is denied with `audit_error` (metric
    /// `audit_append_shed_total{cause="timeout"}`), so a hung disk denies calls instead of
    /// piling up blocked threads. Default 10, between 1 and 300.
    #[serde(default = "default_append_timeout_seconds")]
    pub append_timeout_seconds: u64,
    /// Start even when `sqlite_path`'s directory is on a network filesystem (NFS, SMB/CIFS,
    /// 9p, CephFS, Lustre, AFS, ...). Default `false`: the server refuses to start there,
    /// because SQLite in WAL mode needs every process on one host and file locks there may
    /// not keep a second writer out (multi-replica design, step 2). Set it only when one host
    /// ever mounts the filesystem and its locking is known to work; the server then logs a
    /// warning at every start. Ignored for `":memory:"`.
    #[serde(default)]
    pub allow_network_filesystem: bool,
    /// `[audit.sink]`: ship every signed checkpoint off the host as it is created (SR-21).
    /// Unset by default.
    #[serde(default)]
    pub sink: Option<SinkSection>,
    /// `[audit.retention]`: whether and how the admin may prune the oldest part of the log
    /// behind a signed anchor (ADR-0015). Off by default: the log is never pruned.
    #[serde(default)]
    pub retention: RetentionSection,
}

/// `[audit.retention] prune`: who may prune the audit log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PruneMode {
    /// Never pruned (the default). The prune routes answer 409 `prune_disabled`.
    #[default]
    Off,
    /// Pruned only when the admin asks (`POST /admin/audit/prune`).
    Manual,
    /// Pruned by the server on a timer (`interval_seconds`), of what is older than
    /// `keep_seconds` and already delivered by `[audit.sink]`. The admin may still prune by
    /// hand, as with `"manual"`.
    Auto,
}

impl<'de> Deserialize<'de> for PruneMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "off" => Ok(Self::Off),
            "manual" => Ok(Self::Manual),
            "auto" => Ok(Self::Auto),
            other => Err(serde::de::Error::custom(format!(
                "[audit.retention] prune must be \"off\", \"manual\" or \"auto\", not {other:?}"
            ))),
        }
    }
}

impl std::fmt::Display for PruneMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Manual => "manual",
            Self::Auto => "auto",
        })
    }
}

/// Default `[audit.retention] min_age_seconds`: 90 days.
pub const DEFAULT_PRUNE_MIN_AGE_SECONDS: u64 = 7_776_000;
/// Default `[audit.retention] batch_rows`, from a measurement: one batch of 10000 rows took
/// about 0.35 s on a 200000-row file, far below `[audit] append_timeout_seconds`.
pub const DEFAULT_PRUNE_BATCH_ROWS: u64 = 10_000;
/// Largest `[audit.retention] batch_rows`.
pub const MAX_PRUNE_BATCH_ROWS: u64 = 1_000_000;
/// Largest `[audit.retention] min_age_seconds`: 100 years (of 365 days).
pub const MAX_PRUNE_MIN_AGE_SECONDS: u64 = 3_153_600_000;
/// Smallest `[audit.retention] keep_seconds`: a day, whatever `min_age_seconds` allows, so
/// that a value meant in days (`keep_seconds = 90`) does not start.
pub const MIN_AUTO_KEEP_SECONDS: u64 = 86_400;
/// Default `[audit.retention] interval_seconds`: an hour.
pub const DEFAULT_AUTO_INTERVAL_SECONDS: u64 = 3_600;
/// Largest `[audit.retention] interval_seconds`: a day.
pub const MAX_AUTO_INTERVAL_SECONDS: u64 = 86_400;
/// Default `[audit.retention] max_entries_per_run`: a million entries, so that the first
/// automatic prune of a large old log is split into several smaller ones.
pub const DEFAULT_AUTO_MAX_ENTRIES_PER_RUN: u64 = 1_000_000;

/// `[audit.retention]`: pruning the oldest entries of the audit log (ADR-0015). A prune
/// writes a signed anchor naming the last pruned seq and its hash, so the retained log still
/// verifies; the pruned rows are then deleted in batches by the maintenance task. See
/// `docs/design/audit-retention.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSection {
    /// `"off"` (default), `"manual"` or `"auto"`.
    #[serde(default)]
    pub prune: PruneMode,
    /// Nothing younger than this, in seconds, is pruned: the entry at the boundary must be
    /// older. Default 7776000 (90 days), at most 3153600000 (100 years). May not be below the
    /// run-state retentions of `[leases]`.
    #[serde(default = "default_prune_min_age_seconds")]
    pub min_age_seconds: u64,
    /// Rows deleted per transaction once a prune is committed. Default 10000, between 1 and
    /// 1000000.
    #[serde(default = "default_prune_batch_rows")]
    pub batch_rows: u64,
    /// With `prune = "auto"` only, and required there: the server prunes what is older than
    /// this, in seconds. At least `min_age_seconds` and a day, at most 100 years.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_seconds: Option<u64>,
    /// With `prune = "auto"` only: seconds between two checks for something to prune.
    /// Default 3600, between 1 and 86400.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<u64>,
    /// With `prune = "auto"` only: a directory where each automatic prune first writes the
    /// entries it removes, as an export file. It must exist and be writable. Unset: the
    /// entries are deleted and no copy is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_dir: Option<std::path::PathBuf>,
    /// With `prune = "auto"` only: at most this many entries per automatic prune (more when
    /// no checkpoint falls inside the limit). Default 1000000, at least 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entries_per_run: Option<u64>,
}

fn default_prune_min_age_seconds() -> u64 {
    DEFAULT_PRUNE_MIN_AGE_SECONDS
}
fn default_prune_batch_rows() -> u64 {
    DEFAULT_PRUNE_BATCH_ROWS
}

impl Default for RetentionSection {
    fn default() -> Self {
        Self {
            prune: PruneMode::Off,
            min_age_seconds: DEFAULT_PRUNE_MIN_AGE_SECONDS,
            batch_rows: DEFAULT_PRUNE_BATCH_ROWS,
            keep_seconds: None,
            interval_seconds: None,
            archive_dir: None,
            max_entries_per_run: None,
        }
    }
}

impl RetentionSection {
    /// The prune routes answer (`"manual"` and `"auto"`).
    pub fn allows_prune(&self) -> bool {
        self.prune != PruneMode::Off
    }

    /// `keep_seconds` as a duration, with `prune = "auto"`; `None` otherwise (start-up
    /// refuses `"auto"` without it).
    pub fn keep(&self) -> Option<time::Duration> {
        if self.prune != PruneMode::Auto {
            return None;
        }
        let secs = self.keep_seconds?.min(MAX_PRUNE_MIN_AGE_SECONDS);
        Some(time::Duration::seconds(
            i64::try_from(secs).unwrap_or(i64::MAX),
        ))
    }

    /// `interval_seconds` (default an hour) as a duration.
    pub fn interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.interval_seconds
                .unwrap_or(DEFAULT_AUTO_INTERVAL_SECONDS)
                .clamp(1, MAX_AUTO_INTERVAL_SECONDS),
        )
    }

    /// `max_entries_per_run` (default [`DEFAULT_AUTO_MAX_ENTRIES_PER_RUN`]), at least 1.
    pub fn max_entries_per_run(&self) -> u64 {
        self.max_entries_per_run
            .unwrap_or(DEFAULT_AUTO_MAX_ENTRIES_PER_RUN)
            .max(1)
    }

    /// `min_age_seconds` as a duration, at most [`MAX_PRUNE_MIN_AGE_SECONDS`] (start-up
    /// refuses more).
    pub fn min_age(&self) -> time::Duration {
        let secs = self.min_age_seconds.min(MAX_PRUNE_MIN_AGE_SECONDS);
        time::Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX))
    }
}

/// Where `[audit.sink]` ships checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SinkKind {
    /// `POST` each checkpoint to `url`.
    Webhook,
    /// Append each checkpoint as one JSON line to `path`.
    File,
    /// `PUT` each checkpoint as one object to an S3-compatible bucket (SigV4).
    S3,
}

impl std::fmt::Display for SinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Webhook => "webhook",
            Self::File => "file",
            Self::S3 => "s3",
        })
    }
}

/// Environment variable read for `[audit.sink] bearer_token` when the file leaves it unset.
pub const SINK_TOKEN_ENV: &str = "ATTENUO_AUDIT_SINK_TOKEN";

/// `[audit.sink]`: the checkpoint sink (SR-21). A signed checkpoint is only as trustworthy as
/// the host holding the signing key; a copy that has left the host cannot be re-signed. Every
/// checkpoint the log creates is queued (bounded, never blocking an append) and delivered by a
/// background thread with retries and jittered exponential backoff. See
/// `docs/concepts/audit-log.md#shipping-checkpoints-off-the-host`.
///
/// Only the fields of the chosen `kind` may be set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkSection {
    /// `"webhook"`, `"file"` or `"s3"`.
    pub kind: SinkKind,
    /// webhook: the URL to `POST` to. Any 2xx is success; redirects are not followed.
    #[serde(default)]
    pub url: Option<String>,
    /// webhook: sent as `Authorization: Bearer <token>`. Falls back to
    /// [`SINK_TOKEN_ENV`].
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// file: the JSON Lines file to append to (created if missing, synced after each line).
    /// Put it on another mount than the SQLite file, ideally append-only (`chattr +a`) and
    /// shipped by the operator's own agent.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// s3: endpoint base URL, e.g. `https://s3.eu-west-1.amazonaws.com` or
    /// `http://minio:9000`. Requests are path-style: `<endpoint>/<bucket>/<key>`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// s3: bucket name.
    #[serde(default)]
    pub bucket: Option<String>,
    /// s3: signing region. Default `us-east-1`.
    #[serde(default)]
    pub region: Option<String>,
    /// s3: key prefix; objects are `<prefix><seq, 20 digits>-<first 16 hex of
    /// checkpoint_sha256>.json`. Default `attenuo/checkpoints/`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// s3: access key id. Falls back to `AWS_ACCESS_KEY_ID`.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// s3: secret access key. Falls back to `AWS_SECRET_ACCESS_KEY`.
    #[serde(default)]
    pub secret_access_key: Option<String>,
    /// s3: session token for temporary credentials. Falls back to `AWS_SESSION_TOKEN`.
    /// Like the keys, read once at start: when the temporary credentials expire, every PUT is
    /// refused until the server is restarted with new ones.
    #[serde(default)]
    pub session_token: Option<String>,
    /// webhook and s3: PEM file of CA certificates trusted, for the sink's requests only, in
    /// addition to the built-in web PKI roots: for a receiver or an S3-compatible store whose
    /// certificate a private CA issued. Read once at start; a file that is missing, unreadable
    /// or holds no certificate refuses to start. Verification and the hostname check are
    /// unchanged. As `[[idps]] ca_pem_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem_path: Option<PathBuf>,
    /// Checkpoints waiting to be delivered, at most. When full, the oldest queued one is
    /// dropped (a later checkpoint covers every entry an earlier one does) and
    /// `attenuo_audit_sink_dropped_total` counts it. Default 1024.
    #[serde(default = "default_sink_queue_capacity")]
    pub queue_capacity: usize,
    /// `/readyz` reports the sink degraded once the oldest undelivered checkpoint is older
    /// than this, or the queue is full. Default 300.
    #[serde(default = "default_sink_max_lag_seconds")]
    pub max_lag_seconds: u64,
    /// Turn a degraded sink into a failed readiness check (503). Default `false`: `/readyz`
    /// stays 200 and reports `"degraded": true`.
    #[serde(default)]
    pub fail_readiness: bool,
    /// Per-request timeout for webhook and s3, in seconds. Default 10.
    #[serde(default = "default_sink_timeout_seconds")]
    pub timeout_seconds: u64,
    /// First retry delay in milliseconds; doubles per attempt, with jitter. Default 500.
    #[serde(default = "default_sink_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// Longest retry delay in seconds. Default 60.
    #[serde(default = "default_sink_max_backoff_seconds")]
    pub max_backoff_seconds: u64,
}

fn default_sink_queue_capacity() -> usize {
    1024
}
fn default_sink_max_lag_seconds() -> u64 {
    300
}
fn default_sink_timeout_seconds() -> u64 {
    10
}
fn default_sink_initial_backoff_ms() -> u64 {
    500
}
fn default_sink_max_backoff_seconds() -> u64 {
    60
}

impl SinkSection {
    /// A section of `kind` with every other field at its default.
    pub fn new(kind: SinkKind) -> Self {
        Self {
            kind,
            url: None,
            bearer_token: None,
            path: None,
            endpoint: None,
            bucket: None,
            region: None,
            prefix: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            ca_pem_path: None,
            queue_capacity: default_sink_queue_capacity(),
            max_lag_seconds: default_sink_max_lag_seconds(),
            fail_readiness: false,
            timeout_seconds: default_sink_timeout_seconds(),
            initial_backoff_ms: default_sink_initial_backoff_ms(),
            max_backoff_seconds: default_sink_max_backoff_seconds(),
        }
    }

    /// Startup check: the fields `kind` needs are set, no other kind's fields are, and the
    /// limits are positive.
    ///
    /// # Errors
    ///
    /// When a field `kind` needs is missing or another kind's field is set; when `url` or
    /// `endpoint` is not `http(s)://`, `endpoint` has a path, query or fragment, or `bucket` is not
    /// a bucket name; or when `queue_capacity` is 0 or a lag, timeout or backoff is 0.
    pub fn validate(&self) -> anyhow::Result<()> {
        let set = |name: &'static str, present: bool| present.then_some(name);
        let webhook = [
            set("url", self.url.is_some()),
            set("bearer_token", self.bearer_token.is_some()),
        ];
        let file = [set("path", self.path.is_some())];
        let https = [set("ca_pem_path", self.ca_pem_path.is_some())];
        let s3 = [
            set("endpoint", self.endpoint.is_some()),
            set("bucket", self.bucket.is_some()),
            set("region", self.region.is_some()),
            set("prefix", self.prefix.is_some()),
            set("access_key_id", self.access_key_id.is_some()),
            set("secret_access_key", self.secret_access_key.is_some()),
            set("session_token", self.session_token.is_some()),
        ];
        let kind = self.kind;
        let foreign: Vec<&str> = match kind {
            SinkKind::Webhook => file.iter().chain(&s3).flatten().copied().collect(),
            SinkKind::File => webhook
                .iter()
                .chain(&s3)
                .chain(&https)
                .flatten()
                .copied()
                .collect(),
            SinkKind::S3 => webhook.iter().chain(&file).flatten().copied().collect(),
        };
        if !foreign.is_empty() {
            anyhow::bail!(
                "[audit.sink] kind = \"{kind}\" does not use {}",
                foreign.join(", ")
            );
        }
        let need = |name: &str, present: bool| {
            if present {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "[audit.sink] kind = \"{kind}\" needs `{name}`"
                ))
            }
        };
        let http_url = |name: &str, v: &str| {
            if v.starts_with("https://") || v.starts_with("http://") {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "[audit.sink] {name} = {v:?} must start with https:// or http://"
                ))
            }
        };
        match kind {
            SinkKind::Webhook => {
                need("url", self.url.is_some())?;
                http_url("url", self.url.as_deref().unwrap_or_default())?;
            }
            SinkKind::File => need("path", self.path.is_some())?,
            SinkKind::S3 => {
                need("endpoint", self.endpoint.is_some())?;
                need("bucket", self.bucket.is_some())?;
                let ep = self.endpoint.as_deref().unwrap_or_default();
                http_url("endpoint", ep)?;
                let rest = ep.split_once("://").map_or("", |(_, r)| r);
                if rest.trim_end_matches('/').contains('/') || rest.contains(['?', '#']) {
                    anyhow::bail!(
                        "[audit.sink] endpoint = {ep:?} must be a base URL without a path \
                         (requests are path-style: <endpoint>/<bucket>/<key>)"
                    );
                }
                // As the HTTP client reads it (SR-119): `http://` has no host, and the
                // request URL `http:///<bucket>/<key>` would take the bucket as its host; a
                // backslash is a `/` to the URL parser, so a path the check above missed.
                crate::sink::check_s3_endpoint(ep)
                    .map_err(|e| anyhow::anyhow!("[audit.sink] endpoint = {ep:?} {e}"))?;
                let bucket = self.bucket.as_deref().unwrap_or_default();
                if bucket.is_empty() || bucket.contains('/') {
                    anyhow::bail!("[audit.sink] bucket = {bucket:?} is not a bucket name");
                }
            }
        }
        if self.queue_capacity == 0 {
            anyhow::bail!("[audit.sink] queue_capacity must be at least 1");
        }
        if self.max_lag_seconds == 0 || self.timeout_seconds == 0 {
            anyhow::bail!("[audit.sink] max_lag_seconds and timeout_seconds must be positive");
        }
        if self.initial_backoff_ms == 0 || self.max_backoff_seconds == 0 {
            anyhow::bail!(
                "[audit.sink] initial_backoff_ms and max_backoff_seconds must be positive"
            );
        }
        Ok(())
    }
}

impl Default for AuditSection {
    fn default() -> Self {
        Self {
            sqlite_path: default_sqlite_path(),
            checkpoint_every: default_checkpoint_every(),
            checkpoint_interval_seconds: default_checkpoint_interval_seconds(),
            durability: attenuo_audit::Durability::default(),
            wal_checkpoint_seconds: default_wal_checkpoint_seconds(),
            append_queue_max: default_append_queue_max(),
            append_timeout_seconds: default_append_timeout_seconds(),
            allow_network_filesystem: false,
            sink: None,
            retention: RetentionSection::default(),
        }
    }
}

/// Smallest `[audit] append_queue_max`.
pub const MIN_APPEND_QUEUE_MAX: u64 = 16;
/// Largest `[audit] append_queue_max`.
pub const MAX_APPEND_QUEUE_MAX: u64 = 1_000_000;
/// Largest `[audit] append_timeout_seconds`.
pub const MAX_APPEND_TIMEOUT_SECONDS: u64 = 300;

fn default_append_queue_max() -> u64 {
    attenuo_audit::DEFAULT_APPEND_QUEUE as u64
}

fn default_append_timeout_seconds() -> u64 {
    attenuo_audit::DEFAULT_APPEND_TIMEOUT.as_secs()
}

impl AuditSection {
    /// The bounds on audit appends waiting for the writer: (`append_queue_max`,
    /// `append_timeout_seconds`). Checked at startup.
    ///
    /// # Errors
    ///
    /// When `append_queue_max` is outside `MIN_APPEND_QUEUE_MAX` to `MAX_APPEND_QUEUE_MAX`
    /// or `append_timeout_seconds` outside 1 to `MAX_APPEND_TIMEOUT_SECONDS`; the message
    /// names the first.
    pub fn append_limits(&self) -> anyhow::Result<(usize, std::time::Duration)> {
        for (name, value, min, max) in [
            (
                "append_queue_max",
                self.append_queue_max,
                MIN_APPEND_QUEUE_MAX,
                MAX_APPEND_QUEUE_MAX,
            ),
            (
                "append_timeout_seconds",
                self.append_timeout_seconds,
                1,
                MAX_APPEND_TIMEOUT_SECONDS,
            ),
        ] {
            if !(min..=max).contains(&value) {
                anyhow::bail!("[audit] {name} must be between {min} and {max}, not {value}");
            }
        }
        Ok((
            usize::try_from(self.append_queue_max)?,
            std::time::Duration::from_secs(self.append_timeout_seconds),
        ))
    }
}

fn default_wal_checkpoint_seconds() -> u64 {
    attenuo_audit::DEFAULT_WAL_CHECKPOINT_INTERVAL.as_secs()
}

fn default_checkpoint_every() -> u64 {
    1000
}

fn default_checkpoint_interval_seconds() -> u64 {
    300
}

fn default_sqlite_path() -> String {
    ":memory:".into()
}

/// `[approvals]`: pending approvals for calls the policy gates with `@obligation("approval")`
/// (ADR-0009).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsSection {
    /// How long a pending or granted approval stays usable, in seconds. Default 120 (the
    /// output-labelling design, section 3.7). The approval also ends with the calling hop's
    /// lease or token, whichever comes first. 1 to 86400.
    #[serde(default = "default_approval_ttl_seconds")]
    pub ttl_seconds: u64,
    /// The `aud` an ID token presented at `POST /approvals/{id}` must carry. Default: the same
    /// client id hop-0 intake expects for the run's root agent (`[[idps]] client_ids`, else
    /// the agent id). Set it to a client the agent does not control, such as the approval
    /// page's own OAuth client, so that an ID token the agent can obtain for itself cannot
    /// approve its calls.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Start a server whose public listener is not loopback although a loaded policy asks for
    /// approvals and `client_id` is unset (SR-64). Default `false`: such a server refuses to
    /// start, because the root agent's own OAuth client could then obtain ID tokens that
    /// approve its gated calls. Set it only where the agent cannot obtain ID tokens for the
    /// user by itself.
    #[serde(default)]
    pub allow_unset_client_id: bool,
    /// `[approvals.notify]`: `POST` a signed notice to a webhook when an approval becomes
    /// pending, is decided, or expires. Unset by default.
    #[serde(default)]
    pub notify: Option<NotifySection>,
}

/// Environment variable `[approvals.notify] secret_env` names by default.
pub const NOTIFY_SECRET_ENV: &str = "ATTENUO_APPROVAL_NOTIFY_SECRET";

/// Environment variable `[leases.notify] secret_env` names by default.
pub const LEASE_NOTIFY_SECRET_ENV: &str = "ATTENUO_LEASE_NOTIFY_SECRET";

/// Fewest bytes the signing secret of `[approvals.notify]` or `[leases.notify]` may have.
pub const NOTIFY_SECRET_MIN_LEN: usize = 32;

/// Which notifier a [`NotifySection`] configures: the section's name in messages and the
/// default of its `secret_env`. Everything else the two sections share.
pub trait NotifyTarget:
    std::fmt::Debug + Clone + Copy + PartialEq + Eq + Default + Send + Sync + 'static
{
    /// The section, as messages name it (`[approvals.notify]`).
    const SECTION: &'static str;
    /// The default of `secret_env`.
    const SECRET_ENV: &'static str;
}

/// [`NotifySection`] of `[approvals.notify]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForApprovals;

impl NotifyTarget for ForApprovals {
    const SECTION: &'static str = "[approvals.notify]";
    const SECRET_ENV: &'static str = NOTIFY_SECRET_ENV;
}

/// [`NotifySection`] of `[leases.notify]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForLeases;

impl NotifyTarget for ForLeases {
    const SECTION: &'static str = "[leases.notify]";
    const SECRET_ENV: &'static str = LEASE_NOTIFY_SECRET_ENV;
}

/// `[leases.notify]`: the revocation notifier's section, the same keys as
/// `[approvals.notify]` with its own `secret_env` default ([`LEASE_NOTIFY_SECRET_ENV`]).
pub type LeaseNotifySection = NotifySection<ForLeases>;

/// The startup warning when `[approvals.notify]` and `[leases.notify]` read their signing
/// secret from the same variable; `None` when they do not. Not an error: it works, but then a
/// receiver of one kind of notice can sign notices of the other. Names the variable, never
/// its value.
pub fn shared_notify_secret(
    approvals: &NotifySection<ForApprovals>,
    leases: &LeaseNotifySection,
) -> Option<String> {
    (approvals.secret_env == leases.secret_env).then(|| {
        format!(
            "[approvals.notify] and [leases.notify] both sign with ${}: a receiver of one kind \
             of notice can then sign the other; give [leases.notify] a secret_env of its own",
            leases.secret_env
        )
    })
}

/// `[approvals.notify]`, and with `K` = [`ForLeases`] `[leases.notify]`: a notifier. For
/// `[approvals.notify]`, every approval that becomes pending, and again when it is decided or
/// expires; for `[leases.notify]`, every revocation request that revoked at least one lease.
/// Each notice is queued (bounded, never blocking a decision or a revocation) and `POST`ed to
/// `url` by a background thread with jittered retries, on the `[audit.sink]` queue
/// ([`crate::sink::Queue`]). The body is signed with HMAC-SHA-256 under the secret in the
/// environment variable `secret_env` (header `X-Attenuo-Signature`). Each notice is stored in
/// the lease store's `notice_outbox` table first, so a restart delivers what was left
/// undelivered ([`crate::notify`]). Best effort: a notification that fails `max_attempts`
/// times is dropped and counted. See `docs/design/server.md` ("Approvals").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifySection<K: NotifyTarget = ForApprovals> {
    /// The URL to `POST` to (`https://` or `http://`, with a host and no user info or
    /// fragment). Any 2xx is success; redirects are not followed.
    pub url: String,
    /// Extra request headers, as header name to the name of the environment variable that
    /// holds its value (for example `authorization = "ATTENUO_NOTIFY_AUTH"`). Read at
    /// startup; an unset or empty variable fails startup. `content-type`, `content-length`,
    /// `host`, `transfer-encoding` and `x-attenuo-*` are refused.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// The environment variable holding the HMAC signing secret, at least
    /// [`NOTIFY_SECRET_MIN_LEN`] bytes. Required at startup. Default [`NOTIFY_SECRET_ENV`]
    /// (`[approvals.notify]`) or [`LEASE_NOTIFY_SECRET_ENV`] (`[leases.notify]`).
    #[serde(default = "default_notify_secret_env::<K>")]
    pub secret_env: String,
    /// Per-request timeout in seconds. Default 5.
    #[serde(default = "default_notify_timeout_seconds")]
    pub timeout_seconds: u64,
    /// Notifications waiting to be delivered, at most; when full, the oldest queued one is
    /// dropped and `attenuo_approval_notify_dropped_total` (or
    /// `attenuo_lease_notify_dropped_total`) counts it. Default 256.
    #[serde(default = "default_notify_queue_capacity")]
    pub queue_capacity: usize,
    /// Attempts per notification before it is dropped (and counted). Default 5.
    #[serde(default = "default_notify_max_attempts")]
    pub max_attempts: u32,
    /// First retry delay in milliseconds; doubles per attempt, with jitter. Default 500.
    #[serde(default = "default_sink_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// Longest retry delay in seconds. Default 30.
    #[serde(default = "default_notify_max_backoff_seconds")]
    pub max_backoff_seconds: u64,
    /// `/readyz` reports the notifier degraded (never not ready) once the oldest undelivered
    /// notification, or the current run of failures, is older than this, or the queue is
    /// full. Default 300.
    #[serde(default = "default_sink_max_lag_seconds")]
    pub max_lag_seconds: u64,
    /// How long a notice stays in the outbox table after it was delivered or given up, so
    /// that it is not sent again after a restart. Approvals that expired longer ago than this
    /// get no `approval.expired` notice on start. Default 604800 (7 days).
    #[serde(default = "default_notify_outbox_retention_seconds")]
    pub outbox_retention_seconds: u64,
    /// Which section this is; not a key.
    #[serde(skip)]
    pub target: std::marker::PhantomData<K>,
}

fn default_notify_outbox_retention_seconds() -> u64 {
    7 * 24 * 3600
}
fn default_notify_secret_env<K: NotifyTarget>() -> String {
    K::SECRET_ENV.into()
}
fn default_notify_timeout_seconds() -> u64 {
    5
}
fn default_notify_queue_capacity() -> usize {
    256
}
fn default_notify_max_attempts() -> u32 {
    5
}
fn default_notify_max_backoff_seconds() -> u64 {
    30
}

/// Request headers `[approvals.notify] headers` and `[leases.notify] headers` may not set.
const NOTIFY_RESERVED_HEADERS: [&str; 4] = [
    "content-type",
    "content-length",
    "host",
    "transfer-encoding",
];

impl NotifySection {
    /// An `[approvals.notify]` section for `url` with every other field at its default.
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_url(url)
    }
}

impl<K: NotifyTarget> NotifySection<K> {
    /// A section for `url` with every other field at its default (`secret_env` is the
    /// section's own default).
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: BTreeMap::new(),
            secret_env: default_notify_secret_env::<K>(),
            timeout_seconds: default_notify_timeout_seconds(),
            queue_capacity: default_notify_queue_capacity(),
            max_attempts: default_notify_max_attempts(),
            initial_backoff_ms: default_sink_initial_backoff_ms(),
            max_backoff_seconds: default_notify_max_backoff_seconds(),
            max_lag_seconds: default_sink_max_lag_seconds(),
            outbox_retention_seconds: default_notify_outbox_retention_seconds(),
            target: std::marker::PhantomData,
        }
    }

    /// The section's name, as messages give it (`[approvals.notify]`, `[leases.notify]`).
    pub fn section(&self) -> &'static str {
        K::SECTION
    }

    /// Startup check of the file's values (the environment is read when the notifier
    /// starts). The URL must be `http(s)://` with a host and no user info or fragment, so no
    /// credential sits in a URL that error messages could carry; redirects are never
    /// followed, so the receiver cannot send the request on to another host.
    ///
    /// # Errors
    ///
    /// When `url` is not an `http(s)://` URL with a host, or carries user info or a fragment; when
    /// a header name is invalid, is one the server sets, or names no environment variable; when
    /// `secret_env` is empty; or when `queue_capacity`, `max_attempts`, a timeout, backoff, lag or
    /// retention is 0. The message starts with the section's name.
    pub fn validate(&self) -> anyhow::Result<()> {
        let section = K::SECTION;
        let url = reqwest::Url::parse(&self.url)
            .map_err(|e| anyhow::anyhow!("{section} url is not a URL: {e}"))?;
        if !matches!(url.scheme(), "https" | "http") {
            anyhow::bail!("{section} url must start with https:// or http://");
        }
        if url.host_str().is_none_or(str::is_empty) {
            anyhow::bail!("{section} url needs a host");
        }
        if !url.username().is_empty() || url.password().is_some() {
            anyhow::bail!(
                "{section} url must not carry user info; send credentials in `headers` \
                 from an environment variable"
            );
        }
        if url.fragment().is_some() {
            anyhow::bail!("{section} url must not have a fragment");
        }
        for (name, env) in &self.headers {
            let lower = name.to_ascii_lowercase();
            if reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
                anyhow::bail!("{section} headers: {name:?} is not a header name");
            }
            if NOTIFY_RESERVED_HEADERS.contains(&lower.as_str()) || lower.starts_with("x-attenuo-")
            {
                anyhow::bail!("{section} headers: {name:?} is set by the server");
            }
            if env.is_empty() {
                anyhow::bail!(
                    "{section} headers: {name:?} needs the name of an environment variable"
                );
            }
        }
        if self.secret_env.is_empty() {
            anyhow::bail!("{section} secret_env must name an environment variable");
        }
        if self.queue_capacity == 0 || self.max_attempts == 0 {
            anyhow::bail!("{section} queue_capacity and max_attempts must be at least 1");
        }
        if self.timeout_seconds == 0
            || self.initial_backoff_ms == 0
            || self.max_backoff_seconds == 0
            || self.max_lag_seconds == 0
            || self.outbox_retention_seconds == 0
        {
            anyhow::bail!(
                "{section} timeout_seconds, initial_backoff_ms, max_backoff_seconds, \
                 max_lag_seconds and outbox_retention_seconds must be positive"
            );
        }
        Ok(())
    }
}

/// What the server logs when a loaded policy asks for approvals and `[approvals] client_id`
/// is unset (SR-64), at startup and after a policy reload.
pub const UNSET_APPROVAL_CLIENT_ID: &str = "a loaded policy carries @obligation(\"approval\") \
     and [approvals] client_id is unset: POST /approvals/{id} accepts ID tokens whose audience \
     is the root agent's own OAuth client, so an agent that can get ID tokens for its user \
     (silent re-authentication, a refresh token with `openid`) can approve its own gated calls \
     (SR-64). Set [approvals] client_id to a client the agent does not control, such as the \
     approval page's own";

/// Default of `[approvals] ttl_seconds`.
pub const DEFAULT_APPROVAL_TTL_SECONDS: u64 = 120;

fn default_approval_ttl_seconds() -> u64 {
    DEFAULT_APPROVAL_TTL_SECONDS
}

impl Default for ApprovalsSection {
    fn default() -> Self {
        Self {
            ttl_seconds: DEFAULT_APPROVAL_TTL_SECONDS,
            client_id: None,
            allow_unset_client_id: false,
            notify: None,
        }
    }
}

impl ApprovalsSection {
    /// Startup check: `ttl_seconds` in 1..=86400, `client_id` not empty when set, and
    /// `[approvals.notify]` when set.
    ///
    /// # Errors
    ///
    /// When `ttl_seconds` is outside 1..=86400, `client_id` is set but empty, or
    /// `[approvals.notify]` is set and does not validate.
    pub fn check(&self) -> anyhow::Result<()> {
        if !(1..=86_400).contains(&self.ttl_seconds) {
            anyhow::bail!(
                "[approvals] ttl_seconds must be between 1 and 86400, got {}",
                self.ttl_seconds
            );
        }
        if self.client_id.as_deref().is_some_and(str::is_empty) {
            anyhow::bail!("[approvals] client_id must not be empty when set");
        }
        if let Some(n) = &self.notify {
            n.validate()?;
        }
        Ok(())
    }

    /// The approval audience check at startup (SR-64). With a loaded policy that asks for
    /// approvals (`asks`) and `client_id` unset, an ID token for the root agent's own OAuth
    /// client approves its calls. Returns whether to log [`UNSET_APPROVAL_CLIENT_ID`]. A policy
    /// reload only warns.
    ///
    /// # Errors
    ///
    /// When `asks` is true, `client_id` is unset, `listen` is not a loopback address and
    /// `allow_unset_client_id` is not set.
    pub fn audience_check(&self, asks: bool, listen: std::net::SocketAddr) -> anyhow::Result<bool> {
        if !asks || self.client_id.is_some() {
            return Ok(false);
        }
        if !listen.ip().is_loopback() && !self.allow_unset_client_id {
            anyhow::bail!(
                "{UNSET_APPROVAL_CLIENT_ID}. [server] listen = {listen} is not a loopback \
                 address, so the server refuses to start: set [approvals] client_id, or \
                 [approvals] allow_unset_client_id = true if the agent cannot obtain ID tokens \
                 for the user"
            );
        }
        Ok(true)
    }

    /// `ttl_seconds` as a duration.
    pub fn ttl(&self) -> time::Duration {
        time::Duration::seconds(i64::try_from(self.ttl_seconds).unwrap_or(i64::MAX))
    }
}

/// `[leases]`: retention of the lease registry and its side tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasesSection {
    /// How long a lease tree (a chain's root lease and everything delegated from it, with
    /// their recorded subjects, chain bindings and session bindings) is kept after its last
    /// lease ended, in seconds: after every lease in it is revoked or expired. Default 604800
    /// (a week). An expired lease can still be renewed while its token is valid, so keep this
    /// above the longest token lifetime the server issues; a tree pruned too early only makes
    /// a renewal fail as `lease_unknown`. A pruned chain is no longer found by revoke-by-user
    /// or shown in the console's lease tree; the audit log keeps every decision. 0 keeps every
    /// lease (no pruning).
    #[serde(default = "default_retention_seconds")]
    pub retention_seconds: u64,
    /// How long a session binding (revoke by session) is kept after its chain's root lease
    /// expired, in seconds. Default 86400 (a day). A binding of a revoked chain goes at the
    /// next pruning pass whatever this says. An expired lease can still be renewed while its
    /// token is valid, so keep this above the longest token lifetime the server issues. 0
    /// keeps every binding (no pruning).
    #[serde(default = "default_session_retention_seconds")]
    pub session_retention_seconds: u64,
    /// How long the run-limit counters, the charge log and the approvals of a run are kept
    /// once the run's leases are gone from the registry (pruned by `retention_seconds`, or
    /// unknown), in seconds. Default 2592000 (30 days). Nothing is deleted while any lease it
    /// belongs to is still in the registry, whatever its age. A charge goes once its charge
    /// and any refund are older than this, a counter once no charge under its lease is left,
    /// an approval once its creation, decision and expiry are older than this. After that an
    /// operator refund of the decision answers 410 `charge_pruned`; the audit log keeps every
    /// decision, charge and approval record. 0 keeps everything.
    #[serde(default = "default_run_state_retention_seconds")]
    pub run_state_retention_seconds: u64,
    /// How long a per-user window (run limits phase 3, `context.usage.user_window`) and the
    /// charges logged against it are kept after the window ended, in seconds. Default 3024000
    /// (35 days: a month of refunds after the longest window). Counted from the window's end,
    /// never from the leases, so revoking or pruning a run does not reset a window. Values
    /// from 1 to 86399 are refused at start: a retention below a day, the longest window,
    /// would not reset open windows (they are never pruned) but would drop a day's charges
    /// before they could be refunded. After a window is pruned, an operator refund of its
    /// charge answers 410 `charge_pruned` for that part. 0 keeps every window.
    #[serde(default = "default_user_window_retention_seconds")]
    pub user_window_retention_seconds: u64,
    /// Seconds between runs of the lease maintenance task (the session, lease and run-state
    /// passes above). Default 60, at least 1.
    #[serde(default = "default_maintenance_interval_seconds")]
    pub maintenance_interval_seconds: u64,
    /// Rows one pruning pass looks at, each pass one write transaction. Default 1000, between
    /// 1 and 100000. Smaller passes hold the write lock for less time and take more of them.
    #[serde(default = "default_maintenance_batch_rows")]
    pub maintenance_batch_rows: u64,
    /// Most passes of each kind in one run of the maintenance task; what is left waits for
    /// the next run. Default 100, between 1 and 10000.
    #[serde(default = "default_maintenance_max_passes")]
    pub maintenance_max_passes: u64,
    /// `[leases.notify]`: `POST` a signed `lease.revoked` notice to a webhook after each
    /// revocation request that revoked at least one lease, so that an enforcement point
    /// outside the server learns of it without asking. Unset by default. A hint, not
    /// enforcement ([`crate::notify`]).
    #[serde(default)]
    pub notify: Option<LeaseNotifySection>,
}

/// How the lease maintenance task runs: `[leases] maintenance_interval_seconds`,
/// `maintenance_batch_rows` and `maintenance_max_passes`, checked
/// ([`LeasesSection::maintenance`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseMaintenance {
    /// Time between runs.
    pub interval: std::time::Duration,
    /// Rows one pass looks at.
    pub batch_rows: usize,
    /// Most passes of each kind per run.
    pub max_passes: usize,
}

impl Default for LeaseMaintenance {
    fn default() -> Self {
        Self {
            interval: crate::LEASE_MAINTENANCE_PERIOD,
            batch_rows: crate::LEASE_PRUNE_BATCH,
            max_passes: crate::LEASE_PRUNE_MAX_PASSES,
        }
    }
}

/// Largest `[leases] maintenance_batch_rows`.
pub const MAX_MAINTENANCE_BATCH_ROWS: u64 = 100_000;

/// Largest `[leases] maintenance_max_passes`.
pub const MAX_MAINTENANCE_MAX_PASSES: u64 = 10_000;

fn default_maintenance_interval_seconds() -> u64 {
    crate::LEASE_MAINTENANCE_PERIOD.as_secs()
}

fn default_maintenance_batch_rows() -> u64 {
    crate::LEASE_PRUNE_BATCH as u64
}

fn default_maintenance_max_passes() -> u64 {
    crate::LEASE_PRUNE_MAX_PASSES as u64
}

/// Default of `[leases] run_state_retention_seconds`: 30 days, counted from the newest charge,
/// refund or approval event and only once the run's leases are gone (themselves kept a week
/// after the run ended by default). The charge log is what an operator refund
/// (`POST /admin/budgets/refund`) works from and what an incident review reads next to the
/// audit log, and refunds follow billing or incident processes that take weeks rather than
/// days; a month covers a monthly cycle. The rows are small (a charge row is about 200 bytes),
/// so the cost of keeping them a month is far below the audit log's.
pub const DEFAULT_RUN_STATE_RETENTION_SECONDS: u64 = 2_592_000;

fn default_run_state_retention_seconds() -> u64 {
    DEFAULT_RUN_STATE_RETENTION_SECONDS
}

/// Default of `[leases] user_window_retention_seconds`: 35 days after a window ends, enough
/// for a month of refunds after the longest window (a day). A user active every hour on one
/// tool with both kinds kept writes about 50 small rows a day.
pub const DEFAULT_USER_WINDOW_RETENTION_SECONDS: u64 = 3_024_000;

/// The smallest `[leases] user_window_retention_seconds` other than 0: the longest window.
pub const MIN_USER_WINDOW_RETENTION_SECONDS: u64 = 86_400;

fn default_user_window_retention_seconds() -> u64 {
    DEFAULT_USER_WINDOW_RETENTION_SECONDS
}

/// Default of `[leases] session_retention_seconds`.
pub const DEFAULT_SESSION_RETENTION_SECONDS: u64 = 86_400;

/// Default of `[leases] retention_seconds`: a week. Far above any token lifetime the server
/// grants by default (`[issuer] default_ttl_seconds` is 900, and a root token never outlives
/// its IdP credential, normally an hour or a day), so no renewable lease is pruned, and long
/// enough that an operator looking into an incident the following week still finds the
/// chain in the console and by user. A lease row with its subject and binding is a few
/// hundred bytes, so a week of them is small next to the audit log.
pub const DEFAULT_LEASE_RETENTION_SECONDS: u64 = 604_800;

fn default_retention_seconds() -> u64 {
    DEFAULT_LEASE_RETENTION_SECONDS
}

fn default_session_retention_seconds() -> u64 {
    DEFAULT_SESSION_RETENTION_SECONDS
}

impl Default for LeasesSection {
    fn default() -> Self {
        Self {
            retention_seconds: DEFAULT_LEASE_RETENTION_SECONDS,
            session_retention_seconds: DEFAULT_SESSION_RETENTION_SECONDS,
            run_state_retention_seconds: DEFAULT_RUN_STATE_RETENTION_SECONDS,
            user_window_retention_seconds: DEFAULT_USER_WINDOW_RETENTION_SECONDS,
            maintenance_interval_seconds: default_maintenance_interval_seconds(),
            maintenance_batch_rows: default_maintenance_batch_rows(),
            maintenance_max_passes: default_maintenance_max_passes(),
            notify: None,
        }
    }
}

impl LeasesSection {
    /// `session_retention_seconds` as a duration; `None` when pruning is off (0).
    pub fn session_retention(&self) -> Option<time::Duration> {
        seconds_or_off(self.session_retention_seconds)
    }

    /// `retention_seconds` as a duration; `None` when lease pruning is off (0).
    pub fn retention(&self) -> Option<time::Duration> {
        seconds_or_off(self.retention_seconds)
    }

    /// `run_state_retention_seconds` as a duration; `None` when run-state pruning is off (0).
    pub fn run_state_retention(&self) -> Option<time::Duration> {
        seconds_or_off(self.run_state_retention_seconds)
    }

    /// `user_window_retention_seconds` as a duration; `None` when per-user windows are never
    /// pruned (0).
    ///
    /// # Errors
    ///
    /// When it is below [`MIN_USER_WINDOW_RETENTION_SECONDS`] and not 0. Checked at startup.
    pub fn user_window_retention(&self) -> anyhow::Result<Option<time::Duration>> {
        let s = self.user_window_retention_seconds;
        if s != 0 && s < MIN_USER_WINDOW_RETENTION_SECONDS {
            anyhow::bail!(
                "[leases] user_window_retention_seconds = {s} is below a day \
                 ({MIN_USER_WINDOW_RETENTION_SECONDS}), the longest per-user window: use at \
                 least {MIN_USER_WINDOW_RETENTION_SECONDS}, or 0 to keep every window"
            );
        }
        Ok(seconds_or_off(s))
    }

    /// The maintenance settings. Checked at startup whether or not any retention is on.
    ///
    /// # Errors
    ///
    /// When `maintenance_interval_seconds` is 0, or `maintenance_batch_rows` or
    /// `maintenance_max_passes` is outside 1 to its cap (or does not fit a `usize`); the message
    /// names the setting.
    pub fn maintenance(&self) -> anyhow::Result<LeaseMaintenance> {
        if self.maintenance_interval_seconds == 0 {
            anyhow::bail!("[leases] maintenance_interval_seconds must be at least 1");
        }
        for (name, value, max) in [
            (
                "maintenance_batch_rows",
                self.maintenance_batch_rows,
                MAX_MAINTENANCE_BATCH_ROWS,
            ),
            (
                "maintenance_max_passes",
                self.maintenance_max_passes,
                MAX_MAINTENANCE_MAX_PASSES,
            ),
        ] {
            if !(1..=max).contains(&value) {
                anyhow::bail!("[leases] {name} must be between 1 and {max}, not {value}");
            }
        }
        Ok(LeaseMaintenance {
            interval: std::time::Duration::from_secs(self.maintenance_interval_seconds),
            batch_rows: usize::try_from(self.maintenance_batch_rows)?,
            max_passes: usize::try_from(self.maintenance_max_passes)?,
        })
    }
}

/// A retention in seconds as a duration, `None` for 0 (off).
fn seconds_or_off(seconds: u64) -> Option<time::Duration> {
    (seconds > 0).then(|| time::Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX)))
}

/// `[admin]`
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSection {
    /// Static bearer token for `/admin/*`: the operator `admin`, role `admin`, recorded as
    /// `urn:attenuo:admin` (ADR-0016). With neither this nor [`operators`](Self::operators),
    /// every admin endpoint answers 403.
    ///
    /// Outside a loopback `listen` address the server refuses to start when no admin
    /// credential is configured, or when this is set and shorter than [`MIN_ADMIN_TOKEN_LEN`]
    /// bytes or a known placeholder; on loopback it only warns. Generate one with `openssl rand -hex 32`, or set [`ADMIN_TOKEN_ENV`].
    #[serde(default)]
    pub token: Option<String>,
    /// Serve the admin API (`/admin/*`) on a listener of its own at this address, and not on
    /// `[server] listen` (S-1). Unset by default: the admin API is then served on the main
    /// listener, which the server accepts only when `[server] listen` is a loopback address or
    /// [`serve_on_main_listener`](Self::serve_on_main_listener) is set. With `listen` set, the
    /// main listener answers `/admin/*` as it answers any unknown path. The listener has the
    /// same admin bearer, request logging and shutdown as the main one; `/healthz` and
    /// `/readyz` stay on the main listener. Suggested: `127.0.0.1:9102`.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// Serve the admin API on `[server] listen` although that address is not loopback. Default
    /// `false`: without `listen` and without this, the server refuses to start off loopback, so
    /// that revoke, reload, approve, export and the dev root mint are not reachable on the port
    /// agents use unless an operator said so. Set it only when something in front of the
    /// server keeps `/admin/*` away from agents and the internet (a reverse proxy that does not
    /// forward `/admin/`, or a demo container that binds `0.0.0.0` behind a loopback-only
    /// published port); a warning is logged at startup. Cannot be combined with `listen`.
    #[serde(default)]
    pub serve_on_main_listener: bool,
    /// `[[admin.operators]]`: named admin credentials with a role (ADR-0016), next to
    /// [`token`](Self::token), which stays the operator `admin` with role `admin`. Read from
    /// the file only (an array of tables cannot be set by an environment override), at
    /// startup and again by `POST /admin/operators/reload`, which re-reads this array alone
    /// and swaps it in without a restart. Checked by [`Config::check_admin_operators`].
    #[serde(default)]
    pub operators: Vec<AdminOperator>,
}

/// One `[[admin.operators]]` entry: a named admin credential (ADR-0016).
///
/// ```toml
/// [[admin.operators]]
/// name = "alice"
/// token_sha256 = "<64 lowercase hex characters>"
/// role = "operator"
/// expires_at = "2026-12-31T23:59:59Z"   # optional
/// ```
///
/// `attenuo admin operator new --name alice --role operator` generates a token and prints
/// the entry. The file holds only the token's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminOperator {
    /// Unique, `[a-z0-9_-]{1,64}`, never `admin` (the name of `[admin] token`). Recorded as
    /// the actor of the operator's admin actions (`urn:attenuo:admin:<name>`).
    pub name: String,
    /// SHA-256 of the operator's bearer token, 64 lowercase hex characters.
    pub token_sha256: String,
    /// `viewer`, `operator` or `admin` ([`crate::operators::AdminRole`]).
    pub role: crate::operators::AdminRole,
    /// When the token stops authenticating: an RFC 3339 time with an offset
    /// (`"2026-12-31T23:59:59Z"`, quoted or as a TOML offset date-time). From then on the
    /// token is answered 401 `admin_credential_expired`. Optional: without it the token is
    /// valid until the entry is removed. A time that does not parse refuses the file; an
    /// entry that has already expired is accepted with a warning naming it.
    #[serde(
        default,
        with = "rfc3339_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<time::OffsetDateTime>,
}

/// `expires_at` of an `[[admin.operators]]` entry: an RFC 3339 time with an offset, written
/// as a string or as a TOML offset date-time; serialized as an RFC 3339 string.
mod rfc3339_option {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub(super) fn serialize<S: Serializer>(
        v: &Option<OffsetDateTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(t) => s.serialize_str(&t.format(&Rfc3339).map_err(serde::ser::Error::custom)?),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        let text = match toml::Value::deserialize(d)? {
            toml::Value::String(s) => s,
            toml::Value::Datetime(dt) => dt.to_string(),
            other => {
                return Err(D::Error::custom(format!(
                    "expires_at must be an RFC 3339 time with an offset (like \
                     \"2026-12-31T23:59:59Z\"), not a {}",
                    other.type_str()
                )))
            }
        };
        OffsetDateTime::parse(&text, &Rfc3339)
            .map(Some)
            .map_err(|_| {
                D::Error::custom(format!(
                    "expires_at `{text}` is not an RFC 3339 time with an offset (like \
                     2026-12-31T23:59:59Z)"
                ))
            })
    }
}

impl AdminSection {
    /// Where the admin API is served: `listen` when set, else `server_listen`.
    pub fn api_listen(&self, server_listen: SocketAddr) -> SocketAddr {
        self.listen.unwrap_or(server_listen)
    }

    /// Whether `/admin/*` is mounted on the main listener (`listen` unset).
    pub fn on_main_listener(&self) -> bool {
        self.listen.is_none()
    }

    /// Startup check (S-1): the admin API is served off a loopback `[server] listen` only with
    /// `serve_on_main_listener = true`; `listen` and `serve_on_main_listener` exclude each
    /// other, and `listen` must differ from `server_listen`. Logs the startup warnings.
    ///
    /// # Errors
    ///
    /// When `listen` is unset, `server_listen` is not loopback and `serve_on_main_listener` is
    /// not set; when both `listen` and `serve_on_main_listener` are set; or when `listen` is
    /// `server_listen` (a fixed port, not 0).
    pub fn check_listen(&self, server_listen: SocketAddr) -> anyhow::Result<()> {
        match self.listen {
            Some(listen) => {
                if self.serve_on_main_listener {
                    anyhow::bail!(
                        "[admin] listen = {listen} and [admin] serve_on_main_listener = true \
                         contradict each other: listen moves the admin API off the main \
                         listener. Keep one of the two."
                    );
                }
                if listen == server_listen && listen.port() != 0 {
                    anyhow::bail!(
                        "[admin] listen = {listen} is [server] listen too: give the admin API \
                         a port of its own (for example 127.0.0.1:9102)"
                    );
                }
                if !listen.ip().is_loopback() {
                    tracing::warn!(
                        %listen,
                        "[admin] listener is not on loopback: restrict it with network policy \
                         to the hosts operators use"
                    );
                }
                Ok(())
            }
            None if server_listen.ip().is_loopback() => Ok(()),
            None if self.serve_on_main_listener => {
                tracing::warn!(
                    listen = %server_listen,
                    "!!! [admin] serve_on_main_listener = true: /admin/* (revoke, reload, \
                     approve, export) is served on [server] listen, which is not loopback. \
                     Keep /admin/ away from agents and the internet in front of the server, or \
                     set [admin] listen. !!!"
                );
                Ok(())
            }
            None => anyhow::bail!(
                "[server] listen = {server_listen} is not a loopback address and the admin API \
                 (/admin/*: revoke, reload, approve, export) would be served on it, next to the \
                 agent-facing routes. Set [admin] listen to an address of its own (for example \
                 127.0.0.1:9102) and point the CLI's --server, or the SDKs' AdminClient, at it \
                 for admin commands. To keep the admin API on the main listener (only when \
                 something in front of the server keeps /admin/ away from agents), set [admin] \
                 serve_on_main_listener = true."
            ),
        }
    }
}

/// `[dev]`: development-only switches. Everything here defaults to off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevSection {
    /// Mount `POST /admin/root-token`, which mints hop-0 tokens for a user nobody verified.
    /// Default `false`; when `true` the server logs a warning at startup, and refuses to start
    /// when the admin API's listener (`[admin] listen` when set, else `[server] listen`) is not
    /// a loopback address (S-3) unless
    /// [`allow_root_mint_off_loopback`](Self::allow_root_mint_off_loopback) is also set.
    #[serde(default)]
    pub allow_root_mint: bool,
    /// Demo containers only: accept `allow_root_mint` although the admin API's listener is not
    /// a loopback address. Meant for a container that must bind `0.0.0.0` inside its own network
    /// namespace while the host publishes the port on loopback only (the docker-compose demo).
    /// Never set it in a deployment. Default `false`.
    #[serde(default)]
    pub allow_root_mint_off_loopback: bool,
}

impl DevSection {
    /// Startup check (S-3): the dev root mint is refused when `listen` (the listener the admin
    /// API, and so the route, is mounted on: `[admin] listen` when set, else `[server] listen`,
    /// see [`AdminSection::api_listen`]) is not a loopback address, unless
    /// `allow_root_mint_off_loopback` is set. Logs the startup warnings.
    ///
    /// # Errors
    ///
    /// When `allow_root_mint` is set, `listen` is not loopback and
    /// `allow_root_mint_off_loopback` is not set.
    pub fn check(&self, listen: SocketAddr) -> anyhow::Result<()> {
        if !self.allow_root_mint {
            if self.allow_root_mint_off_loopback {
                tracing::warn!(
                    "[dev] allow_root_mint_off_loopback = true has no effect without \
                     allow_root_mint = true"
                );
            }
            return Ok(());
        }
        if !listen.ip().is_loopback() {
            if !self.allow_root_mint_off_loopback {
                anyhow::bail!(
                    "[dev] allow_root_mint = true and the admin API's listener ({listen}: \
                     [admin] listen when set, else [server] listen) is not a loopback address. \
                     POST /admin/root-token mints root tokens for users nobody \
                     has verified, so it is refused off loopback. Mint root tokens from an OIDC \
                     ID token or ID-JAG instead ([[idps]]), or bind that listener to 127.0.0.1 \
                     for local development. (A demo container that binds 0.0.0.0 behind a \
                     loopback-only published port may set [dev] \
                     allow_root_mint_off_loopback = true; never in a deployment.)"
                );
            }
            tracing::warn!(
                %listen,
                "!!! [dev] allow_root_mint_off_loopback = true: the unverified root mint is \
                 served on a listener that is not loopback. Demo containers only. !!!"
            );
        }
        tracing::warn!(
            "!!! [dev] allow_root_mint = true: POST /admin/root-token mints root tokens for \
             users nobody has verified. Development only; never enable this in a deployment. !!!"
        );
        Ok(())
    }
}

/// `[metrics]`: the Prometheus endpoint, on its own listener so it is never reachable on the
/// proxy port by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSection {
    /// Serve `GET /metrics` on `listen`. Default `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Address of the metrics listener. Default `127.0.0.1:9100`. There is no authentication:
    /// keep it on loopback or a private network.
    #[serde(default = "default_metrics_listen")]
    pub listen: SocketAddr,
    /// Allow `listen` to be a non-loopback address. Default `false`: the server refuses to
    /// start with metrics enabled on a public address, because decision counts by reason are
    /// served without authentication. Set it only when the address is a private interface
    /// that network policy protects. A warning is still logged at startup.
    #[serde(default)]
    pub allow_public: bool,
}

impl MetricsSection {
    /// Startup check (SR-38): a metrics listener off loopback needs `allow_public = true`.
    ///
    /// # Errors
    ///
    /// When the listener is enabled, not on loopback, and `allow_public` is not set.
    pub fn check_listen(&self) -> anyhow::Result<()> {
        if !self.enabled || self.listen.ip().is_loopback() {
            return Ok(());
        }
        if !self.allow_public {
            anyhow::bail!(
                "[metrics] listen = {} is not a loopback address and /metrics has no \
                 authentication; bind 127.0.0.1 or set [metrics] allow_public = true",
                self.listen
            );
        }
        tracing::warn!(
            listen = %self.listen,
            "[metrics] listener is not on loopback: /metrics is unauthenticated, restrict it \
             with network policy"
        );
        Ok(())
    }
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics_listen(),
            allow_public: false,
        }
    }
}

fn default_metrics_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9100))
}

/// `[admin_ui]`: the admin console, on its own opt-in listener.
///
/// The console is served on a separate port rather than on the main listener so that it never
/// shares an origin with `/mcp/{server}`, where an upstream chooses the response content type
/// (see `docs/design/admin-console.md`). The listener serves the embedded console assets under
/// `/admin/ui/` and the admin API under `/admin/*` behind the same `[admin] token`; see
/// [`crate::admin_ui`]. An absent section means no console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminUiSection {
    /// Bind the console listener. Default `false`: no console, nothing extra is listening.
    #[serde(default)]
    pub enabled: bool,
    /// Address of the console listener. Default `127.0.0.1:9101`, so the console is reached
    /// from the host itself or through an SSH tunnel.
    #[serde(default = "default_admin_ui_listen")]
    pub listen: SocketAddr,
    /// Allow `listen` to be a non-loopback address. Default `false`: the server refuses to start
    /// with the console enabled on a public address, because the console exposes the admin API
    /// to a browser. When set, a warning is logged at startup and `[admin] token` must pass the
    /// same strength check as for a public `[server] listen`.
    #[serde(default)]
    pub allow_public: bool,
    /// Mount the routes that change state (`POST /admin/leases/{id}/revoke`,
    /// `POST /admin/policies/reload`, `POST /admin/approvals/{id}` and
    /// `POST /admin/budgets/refund`) on the console listener. Default `false`, so read-only is
    /// enforced by the server and not only by the page: those paths answer 404 there. The admin
    /// API's own listener (`[admin] listen`, else the main listener) keeps every admin route
    /// whatever this says.
    #[serde(default)]
    pub allow_write: bool,
}

impl AdminUiSection {
    /// Startup check, as for `[metrics]` (SR-38): a console listener off loopback needs
    /// `allow_public = true`, and gets a warning when it has it.
    ///
    /// # Errors
    ///
    /// When the console is enabled, not on loopback, and `allow_public` is not set.
    pub fn check_listen(&self) -> anyhow::Result<()> {
        if !self.enabled || self.listen.ip().is_loopback() {
            return Ok(());
        }
        if !self.allow_public {
            anyhow::bail!(
                "[admin_ui] listen = {} is not a loopback address and the console exposes the \
                 admin API to browsers; bind 127.0.0.1 (and use an SSH tunnel) or set \
                 [admin_ui] allow_public = true",
                self.listen
            );
        }
        tracing::warn!(
            listen = %self.listen,
            "[admin_ui] console listener is not on loopback: restrict it with network policy"
        );
        Ok(())
    }
}

impl Default for AdminUiSection {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_admin_ui_listen(),
            allow_public: false,
            allow_write: false,
        }
    }
}

fn default_admin_ui_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9101))
}

/// `[proxy]`: the MCP proxy mounted at `/mcp/{server}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySection {
    /// How often, in seconds, a long-lived response stream (the `GET` listen stream, or a
    /// `POST` answered over SSE) is re-checked against lease state and token expiry; it is
    /// ended at the first failed check (SR-28). Default 2, at least 1.
    #[serde(default = "default_stream_recheck_seconds")]
    pub stream_recheck_seconds: u64,
    /// Deny a `tools/call` (reason `tool_not_listed`, audited) whose exact name is neither in
    /// the upstream's `tools/list` results seen so far nor in `[policy.catalog]`, so an upstream
    /// that resolves names case-insensitively cannot run `delete_repo` for `Delete_Repo`
    /// (SR-25). Default `true`.
    #[serde(default = "default_true")]
    pub require_listed_tools: bool,
    /// Largest upstream body the proxy buffers (a JSON response it filters, one SSE event);
    /// larger gets `502` or ends the stream (SR-36). Default 16 MiB.
    #[serde(default = "default_max_upstream_body_bytes")]
    pub max_upstream_body_bytes: usize,
    /// Largest client request body; larger gets `413` (SR-36). Default 4 MiB.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    /// Idle lifetime of an `Mcp-Session-Id` binding, in seconds. Default 3600.
    #[serde(default = "default_session_ttl_seconds")]
    pub session_ttl_seconds: u64,
    /// Most live session bindings. When all are live, a new session gets `503`
    /// `session_registry_full`; live bindings are never evicted (SR-36). Default 100000.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Most live session bindings one principal (root lease) holds. One more gets `429`
    /// `too_many_sessions`, other principals are unaffected, and the upstream session is
    /// deleted (SR-49). Default 64.
    #[serde(default = "default_max_sessions_per_principal")]
    pub max_sessions_per_principal: usize,
    /// How long, in seconds, after an audit record of a repeated condition further
    /// occurrences of the same delegation chain, tool name and reason are counted (metric
    /// `audit_records_suppressed_total`, proxy log) instead of recorded. One knob for both
    /// bounded kinds, the `stream.end` records of `GET` listen streams and the lease refusals
    /// of undecided requests (`initialize`, the list methods, notifications, `GET`,
    /// `DELETE`): nobody has asked for them to differ, and two knobs would ask the operator a
    /// question with no good answer. Tool-call decisions are never bounded. Default 60,
    /// between 1 and 3600.
    #[serde(default = "default_record_window_seconds")]
    pub record_window_seconds: u64,
    /// Most (chain, tool, reason) windows each bounded kind keeps open at once. A table full
    /// of open windows records rather than suppresses, so a smaller figure only means more
    /// records under a flood of distinct chains. Default 10000, between 100 and 1000000.
    #[serde(default = "default_record_window_max_keys")]
    pub record_window_max_keys: u64,
    /// How `tools/list` answers are filtered (ADR-0011): `"capabilities"` (the default) keeps
    /// every tool some capability of the chain could permit; `"policy"` also hides a tool when
    /// the Cedar policy (approval obligations lifted) denies every possible call to it for the
    /// chain, or when the catalog lacks it under `unknown_tools = "deny"`. Advisory only: a
    /// hidden tool that is called is decided and audited as usual.
    #[serde(default)]
    pub list_filter: attenuo_proxy::ListFilterMode,
    /// How long, in seconds, the proxy waits for a TCP (and TLS) connection to an upstream.
    /// A connection not made in time answers `502` `upstream_unreachable`: nothing was sent,
    /// so a retry is safe. Default 5, between 1 and 300.
    #[serde(default = "default_upstream_connect_timeout_seconds")]
    pub upstream_connect_timeout_seconds: u64,
    /// How long, in seconds, the proxy waits for an upstream's response headers, and for the
    /// rest of a body it buffers (a JSON answer it filters or labels), counted from sending
    /// the request. Past it the proxy answers `504` `upstream_timeout`: the upstream may have
    /// acted on the request. A streamed body (SSE, the `GET` listen stream, a body relayed as
    /// it arrives) is not cut once its headers are in; `stream_recheck_seconds` governs those.
    /// Default 30, between 1 and 3600. Raise it for tools that answer in JSON after running
    /// for longer.
    #[serde(default = "default_upstream_response_timeout_seconds")]
    pub upstream_response_timeout_seconds: u64,
}

/// Largest `[proxy] upstream_connect_timeout_seconds`.
pub const MAX_UPSTREAM_CONNECT_TIMEOUT_SECONDS: u64 = 300;

/// Largest `[proxy] upstream_response_timeout_seconds`: an hour.
pub const MAX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS: u64 = 3_600;

fn default_upstream_connect_timeout_seconds() -> u64 {
    attenuo_proxy::config::DEFAULT_UPSTREAM_CONNECT_TIMEOUT.as_secs()
}

fn default_upstream_response_timeout_seconds() -> u64 {
    attenuo_proxy::config::DEFAULT_UPSTREAM_RESPONSE_TIMEOUT.as_secs()
}

/// Largest `[proxy] record_window_seconds`: an hour.
pub const MAX_RECORD_WINDOW_SECONDS: u64 = 3_600;

/// Smallest `[proxy] record_window_max_keys`.
pub const MIN_RECORD_WINDOW_MAX_KEYS: u64 = 100;

/// Largest `[proxy] record_window_max_keys`.
pub const MAX_RECORD_WINDOW_MAX_KEYS: u64 = 1_000_000;

fn default_record_window_seconds() -> u64 {
    attenuo_proxy::records::DEFAULT_RECORD_WINDOW.as_secs()
}

fn default_record_window_max_keys() -> u64 {
    attenuo_proxy::records::DEFAULT_RECORD_WINDOW_MAX_KEYS as u64
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            stream_recheck_seconds: default_stream_recheck_seconds(),
            require_listed_tools: true,
            max_upstream_body_bytes: default_max_upstream_body_bytes(),
            max_request_body_bytes: default_max_request_body_bytes(),
            session_ttl_seconds: default_session_ttl_seconds(),
            max_sessions: default_max_sessions(),
            max_sessions_per_principal: default_max_sessions_per_principal(),
            record_window_seconds: default_record_window_seconds(),
            record_window_max_keys: default_record_window_max_keys(),
            list_filter: attenuo_proxy::ListFilterMode::Capabilities,
            upstream_connect_timeout_seconds: default_upstream_connect_timeout_seconds(),
            upstream_response_timeout_seconds: default_upstream_response_timeout_seconds(),
        }
    }
}

fn default_max_upstream_body_bytes() -> usize {
    attenuo_proxy::config::DEFAULT_MAX_UPSTREAM_BODY_BYTES
}

fn default_max_request_body_bytes() -> usize {
    attenuo_proxy::config::DEFAULT_MAX_REQUEST_BODY_BYTES
}

fn default_session_ttl_seconds() -> u64 {
    attenuo_proxy::session::DEFAULT_SESSION_TTL.as_secs()
}

fn default_max_sessions() -> usize {
    attenuo_proxy::session::DEFAULT_MAX_SESSIONS
}

fn default_max_sessions_per_principal() -> usize {
    attenuo_proxy::session::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL
}

fn default_stream_recheck_seconds() -> u64 {
    attenuo_proxy::config::DEFAULT_STREAM_RECHECK.as_secs()
}

impl ProxySection {
    /// The re-check interval.
    ///
    /// # Errors
    ///
    /// When `stream_recheck_seconds` is 0.
    pub fn stream_recheck(&self) -> anyhow::Result<std::time::Duration> {
        if self.stream_recheck_seconds == 0 {
            anyhow::bail!("[proxy] stream_recheck_seconds must be at least 1");
        }
        Ok(std::time::Duration::from_secs(self.stream_recheck_seconds))
    }

    /// Reject limits of zero, which would refuse every request, body or session.
    ///
    /// # Errors
    ///
    /// When `max_upstream_body_bytes`, `max_request_body_bytes`, `session_ttl_seconds`,
    /// `max_sessions` or `max_sessions_per_principal` is 0; the message names the first.
    pub fn check_limits(&self) -> anyhow::Result<()> {
        for (name, value) in [
            (
                "max_upstream_body_bytes",
                self.max_upstream_body_bytes as u64,
            ),
            ("max_request_body_bytes", self.max_request_body_bytes as u64),
            ("session_ttl_seconds", self.session_ttl_seconds),
            ("max_sessions", self.max_sessions as u64),
            (
                "max_sessions_per_principal",
                self.max_sessions_per_principal as u64,
            ),
        ] {
            if value == 0 {
                anyhow::bail!("[proxy] {name} must be at least 1");
            }
        }
        Ok(())
    }

    /// The record window and its capacity (`record_window_seconds`, `record_window_max_keys`).
    /// Checked at startup.
    ///
    /// # Errors
    ///
    /// When `record_window_seconds` is outside 1 to `MAX_RECORD_WINDOW_SECONDS` or
    /// `record_window_max_keys` is outside `MIN_RECORD_WINDOW_MAX_KEYS` to
    /// `MAX_RECORD_WINDOW_MAX_KEYS` (or does not fit a `usize`); the message names the first.
    pub fn record_window(&self) -> anyhow::Result<(std::time::Duration, usize)> {
        for (name, value, min, max) in [
            (
                "record_window_seconds",
                self.record_window_seconds,
                1,
                MAX_RECORD_WINDOW_SECONDS,
            ),
            (
                "record_window_max_keys",
                self.record_window_max_keys,
                MIN_RECORD_WINDOW_MAX_KEYS,
                MAX_RECORD_WINDOW_MAX_KEYS,
            ),
        ] {
            if !(min..=max).contains(&value) {
                anyhow::bail!("[proxy] {name} must be between {min} and {max}, not {value}");
            }
        }
        Ok((
            std::time::Duration::from_secs(self.record_window_seconds),
            usize::try_from(self.record_window_max_keys)?,
        ))
    }

    /// The upstream deadlines: (`upstream_connect_timeout_seconds`,
    /// `upstream_response_timeout_seconds`). Checked at startup.
    ///
    /// # Errors
    ///
    /// When `upstream_connect_timeout_seconds` is outside 1 to
    /// `MAX_UPSTREAM_CONNECT_TIMEOUT_SECONDS` or `upstream_response_timeout_seconds` outside 1
    /// to `MAX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS`; the message names the first.
    pub fn upstream_timeouts(&self) -> anyhow::Result<(std::time::Duration, std::time::Duration)> {
        for (name, value, max) in [
            (
                "upstream_connect_timeout_seconds",
                self.upstream_connect_timeout_seconds,
                MAX_UPSTREAM_CONNECT_TIMEOUT_SECONDS,
            ),
            (
                "upstream_response_timeout_seconds",
                self.upstream_response_timeout_seconds,
                MAX_UPSTREAM_RESPONSE_TIMEOUT_SECONDS,
            ),
        ] {
            if !(1..=max).contains(&value) {
                anyhow::bail!("[proxy] {name} must be between 1 and {max}, not {value}");
            }
        }
        Ok((
            std::time::Duration::from_secs(self.upstream_connect_timeout_seconds),
            std::time::Duration::from_secs(self.upstream_response_timeout_seconds),
        ))
    }

    /// Apply this section to a proxy configuration.
    pub fn apply(&self, config: attenuo_proxy::ProxyConfig) -> attenuo_proxy::ProxyConfig {
        let (window, max_keys) = self.record_window().unwrap_or((
            attenuo_proxy::records::DEFAULT_RECORD_WINDOW,
            attenuo_proxy::records::DEFAULT_RECORD_WINDOW_MAX_KEYS,
        ));
        let (connect, response) = self.upstream_timeouts().unwrap_or((
            attenuo_proxy::config::DEFAULT_UPSTREAM_CONNECT_TIMEOUT,
            attenuo_proxy::config::DEFAULT_UPSTREAM_RESPONSE_TIMEOUT,
        ));
        config
            .with_stream_recheck(
                self.stream_recheck()
                    .unwrap_or(attenuo_proxy::config::DEFAULT_STREAM_RECHECK),
            )
            .with_require_listed_tools(self.require_listed_tools)
            .with_max_upstream_body_bytes(self.max_upstream_body_bytes)
            .with_max_request_body_bytes(self.max_request_body_bytes)
            .with_sessions(
                std::time::Duration::from_secs(self.session_ttl_seconds),
                self.max_sessions,
            )
            .with_max_sessions_per_principal(self.max_sessions_per_principal)
            .with_record_window(window, max_keys)
            .with_list_filter(self.list_filter)
            .with_upstream_timeouts(connect, response)
    }
}

/// `[limits]`: basic protection of one server process against too much work at once
/// (audit finding S-4). Every figure is per process: with one replica, per server.
///
/// - `max_in_flight` caps the requests of the main listener being handled at once; one more
///   is answered `503` with `Retry-After` at once instead of queueing. `/healthz` and `/readyz`
///   are never refused by it, and the `[metrics]`, `[admin] listen` and `[admin_ui]` listeners
///   are not counted. A request counts until its answer starts: a streamed MCP answer (SSE,
///   the `GET` listen stream) stops counting once its headers are sent.
/// - `header_read_timeout_seconds` bounds the wait for a request's headers on every listener,
///   the idle time of a kept-alive connection included; past it the connection is closed.
/// - `request_body_timeout_seconds` bounds the read of a request body, from the moment its
///   headers are in; past it the answer is `408` (`400` with the JSON-RPC shape on `/mcp`).
/// - `request_timeout_seconds` bounds the time to an answer of every route of the main
///   listener except `/mcp/{server}` (bounded by the `[proxy]` upstream deadlines, and whose
///   streams must stay open) and `/admin/*` (an audit verify or export of a large log may take
///   longer); past it the answer is `503` with `Retry-After`.
/// - `token_requests_per_minute`, `token_unauthenticated_requests_per_minute`,
///   `mcp_requests_per_minute` and `authzen_search_requests_per_minute` are per-caller
///   fixed-window rate limits, off (0) by default: `POST /token` per authenticated agent,
///   `POST /token` requests that authenticated no agent per peer address, `/mcp/{server}` per
///   run (the chain's root lease), and `POST /access/v1/search/action` per run, in a table of
///   its own. Over the limit the answer is `429` with `Retry-After`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Most requests the main listener handles at once; one more gets `503` `overloaded`.
    /// 0 turns the cap off. Default 1024, at most 1000000.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: u64,
    /// How long, in seconds, a connection may take to send a request's headers, or stay idle
    /// between requests. Default 30, between 1 and 300.
    #[serde(default = "default_header_read_timeout_seconds")]
    pub header_read_timeout_seconds: u64,
    /// How long, in seconds, a request body may take to arrive once the headers are in.
    /// Default 30, between 1 and 3600.
    #[serde(default = "default_request_body_timeout_seconds")]
    pub request_body_timeout_seconds: u64,
    /// How long, in seconds, a route other than `/mcp/{server}` and `/admin/*` may take to
    /// answer. Default 60, between 1 and 3600.
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    /// `POST /token` requests per minute per authenticated agent (client credentials or actor
    /// token). 0 (the default) turns it off; at most 1000000.
    #[serde(default)]
    pub token_requests_per_minute: u64,
    /// `POST /token` requests per minute per peer address (IPv6 by /64) that authenticated no
    /// agent: refused before authentication, failed it, or (with `[token] require_actor_auth =
    /// false`) sent no credentials. Once a peer has used them up, every `POST /token` from it
    /// is refused until the minute ends. 0 (the default) turns it off; at most 1000000.
    #[serde(default)]
    pub token_unauthenticated_requests_per_minute: u64,
    /// Requests per minute to `/mcp/{server}` per run (the delegation chain's root lease),
    /// counted once the token and its DPoP proof have verified. 0 (the default) turns it off;
    /// at most 1000000.
    #[serde(default)]
    pub mcp_requests_per_minute: u64,
    /// AuthZEN action searches (`POST /access/v1/search/action`) per minute per run (the
    /// chain's root lease, from the bearer token or a PEP's issued unsigned chain), counted
    /// once the caller has authenticated and before any candidate is evaluated. Its own table:
    /// searches do not use up `mcp_requests_per_minute`, nor the reverse. Evaluations are not
    /// counted (they are audited). 0 (the default) turns it off; at most 1000000.
    #[serde(default)]
    pub authzen_search_requests_per_minute: u64,
    /// Most callers each rate limit tracks at once. Callers whose minute has ended are dropped
    /// first; when every tracked caller is inside its minute, a new caller is refused (`429`)
    /// until one ends. Default 10000, between 100 and 1000000.
    #[serde(default = "default_rate_limit_max_keys")]
    pub rate_limit_max_keys: u64,
}

/// Default `[limits] max_in_flight`.
pub const DEFAULT_MAX_IN_FLIGHT: u64 = 1_024;
/// Default `[limits] header_read_timeout_seconds` (hyper's own default).
pub const DEFAULT_HEADER_READ_TIMEOUT_SECONDS: u64 = 30;
/// Default `[limits] request_body_timeout_seconds`.
pub const DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS: u64 = 30;
/// Default `[limits] request_timeout_seconds`.
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 60;
/// Default `[limits] rate_limit_max_keys`.
pub const DEFAULT_RATE_LIMIT_MAX_KEYS: u64 = 10_000;
/// Largest `[limits] max_in_flight` and largest per-minute rate.
pub const MAX_LIMITS_COUNT: u64 = 1_000_000;

fn default_max_in_flight() -> u64 {
    DEFAULT_MAX_IN_FLIGHT
}

fn default_header_read_timeout_seconds() -> u64 {
    DEFAULT_HEADER_READ_TIMEOUT_SECONDS
}

fn default_request_body_timeout_seconds() -> u64 {
    DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS
}

fn default_request_timeout_seconds() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECONDS
}

fn default_rate_limit_max_keys() -> u64 {
    DEFAULT_RATE_LIMIT_MAX_KEYS
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            header_read_timeout_seconds: DEFAULT_HEADER_READ_TIMEOUT_SECONDS,
            request_body_timeout_seconds: DEFAULT_REQUEST_BODY_TIMEOUT_SECONDS,
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
            token_requests_per_minute: 0,
            token_unauthenticated_requests_per_minute: 0,
            mcp_requests_per_minute: 0,
            authzen_search_requests_per_minute: 0,
            rate_limit_max_keys: DEFAULT_RATE_LIMIT_MAX_KEYS,
        }
    }
}

impl LimitsSection {
    /// Check every key's range. Called at startup.
    ///
    /// # Errors
    ///
    /// When a timeout is outside its range (`header_read_timeout_seconds` 1 to 300, the other
    /// two 1 to 3600), `max_in_flight` or a rate is over 1000000, or `rate_limit_max_keys` is
    /// outside 100 to 1000000; the message names the first.
    pub fn check(&self) -> anyhow::Result<()> {
        for (name, value, min, max) in [
            ("max_in_flight", self.max_in_flight, 0, MAX_LIMITS_COUNT),
            (
                "header_read_timeout_seconds",
                self.header_read_timeout_seconds,
                1,
                300,
            ),
            (
                "request_body_timeout_seconds",
                self.request_body_timeout_seconds,
                1,
                3_600,
            ),
            (
                "request_timeout_seconds",
                self.request_timeout_seconds,
                1,
                3_600,
            ),
            (
                "token_requests_per_minute",
                self.token_requests_per_minute,
                0,
                MAX_LIMITS_COUNT,
            ),
            (
                "token_unauthenticated_requests_per_minute",
                self.token_unauthenticated_requests_per_minute,
                0,
                MAX_LIMITS_COUNT,
            ),
            (
                "mcp_requests_per_minute",
                self.mcp_requests_per_minute,
                0,
                MAX_LIMITS_COUNT,
            ),
            (
                "authzen_search_requests_per_minute",
                self.authzen_search_requests_per_minute,
                0,
                MAX_LIMITS_COUNT,
            ),
            (
                "rate_limit_max_keys",
                self.rate_limit_max_keys,
                100,
                MAX_LIMITS_COUNT,
            ),
        ] {
            if !(min..=max).contains(&value) {
                anyhow::bail!("[limits] {name} must be between {min} and {max}, not {value}");
            }
        }
        Ok(())
    }

    /// `header_read_timeout_seconds` as a duration (clamped into its range, so an unchecked
    /// section still gives a usable value).
    pub fn header_read_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.header_read_timeout_seconds.clamp(1, 300))
    }
}

/// Default `[[idps]] allowed_algs`.
pub const DEFAULT_IDP_ALGS: &[&str] = &["RS256", "ES256", "EdDSA"];
/// Default `[[idps]] attribute_claims`.
pub const DEFAULT_ATTRIBUTE_CLAIMS: &[&str] = &["email", "groups", "amr"];

/// One `[[idps]]` entry: an identity provider whose ID tokens and ID-JAGs are trusted for
/// hop 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdpConfig {
    /// Exact `iss` value of the IdP's tokens (and of its discovery document).
    pub issuer: String,
    /// Deprecated and ignored (SR-37): an ID token's `aud` is checked against the presenting
    /// agent's entry in `client_ids`, not against one IdP-wide value. ID-JAG's `aud` is always
    /// `[issuer] issuer`. Still parsed so existing configs load; a warning is logged when set.
    #[serde(default)]
    pub audience: String,
    /// JWKS location. When absent, `jwks_uri` from `<issuer>/.well-known/openid-configuration`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// PEM file of CA certificates trusted, for this entry's key fetches only (the discovery
    /// document, the JWKS, and the refetch on an unknown `kid`), in addition to the built-in
    /// web PKI roots: for an IdP whose certificate a private CA issued. Never instead of
    /// them, and never for another entry. Certificate verification and the hostname check are
    /// unchanged, as are the `https://` rule and the refusal of redirects. Read once at start
    /// (no reload re-reads it; a new file needs a restart). A file that is missing,
    /// unreadable, empty or holds no certificate refuses to start. A relative path is resolved
    /// against the working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem_path: Option<PathBuf>,
    /// JWS algorithms accepted from this IdP. Only asymmetric algorithms are allowed.
    #[serde(default = "default_idp_algs")]
    pub allowed_algs: Vec<String>,
    /// Claims copied verbatim into `originating_user.attributes` when present.
    #[serde(default = "default_attribute_claims")]
    pub attribute_claims: Vec<String>,
    /// How long a fetched JWKS is used before it is fetched again. Default 300.
    #[serde(default = "default_jwks_ttl")]
    pub jwks_ttl_seconds: u64,
    /// Allowed clock skew for `exp`, `iat` and `nbf`. Default 60.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    /// Per-agent client id at this IdP: agent id to the `aud` its ID tokens carry. An ID
    /// token is accepted only from the agent whose entry its `aud` names, and `azp` must name
    /// it too when `aud` lists several values (SR-37). An agent without an entry must have a
    /// client id equal to its agent id; the server warns at startup for each such agent.
    #[serde(default)]
    pub client_ids: BTreeMap<String, String>,
    /// For a multi-tenant issuer (one `iss` for several tenants): the tenant whose users this
    /// entry trusts. When set, an ID-JAG must carry a `tenant` claim equal to it
    /// (draft-ietf-oauth-identity-assertion-authz-grant-06 §4.4.1), else `missing_claim` or
    /// `tenant_mismatch`. ID tokens are not affected. Default: unset, `tenant` is not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Opt-in: narrow the root token minted from this issuer's ID-JAGs to what the ID-JAG's own
    /// `resource`, `scope` and `authorization_details` claims name, under `[[root_grants]]`
    /// (draft-ietf-oauth-identity-assertion-authz-grant-06 §4.4.1). See
    /// [`IdJagCeilingConfig`]. Default: unset, those claims are ignored and the root token is
    /// bounded by the root grant and the request only. ID tokens are never affected, so an
    /// agent that can present this issuer's ID tokens (its `client_ids` entry, or its agent
    /// id, is their `aud`) is not bound by the ceiling unless [`credentials`](Self::credentials)
    /// leaves ID tokens out (SR-122); the server warns at start when it does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_jag_ceiling: Option<IdJagCeilingConfig>,
    /// The credentials this issuer's users may be brought in with at hop 0: `"id_token"`
    /// (an OIDC ID token), `"id-jag"` (an ID-JAG), or both. A credential of a kind not listed
    /// is refused with `credential_type_not_accepted`, before its signature is checked and
    /// before it is used up. Default: both. An empty list, or a name not in this list, refuses
    /// to start. Approval ID tokens (`[approvals]`) are not affected (SR-122).
    #[serde(default = "default_idp_credentials")]
    pub credentials: Vec<IdpCredential>,
}

/// A credential kind an `[[idps]] credentials` list names. The names are the ones the audit
/// record's `credential` member uses, which are also the ends of the RFC 8693 token type URNs
/// (`urn:ietf:params:oauth:token-type:id_token`, `...:id-jag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdpCredential {
    /// An OIDC ID token.
    #[serde(rename = "id_token")]
    IdToken,
    /// An ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant).
    #[serde(rename = "id-jag")]
    IdJag,
}

/// Default `[[idps]] credentials`: both kinds.
pub const DEFAULT_IDP_CREDENTIALS: &[IdpCredential] =
    &[IdpCredential::IdToken, IdpCredential::IdJag];

fn default_idp_credentials() -> Vec<IdpCredential> {
    DEFAULT_IDP_CREDENTIALS.to_vec()
}

/// `[idps.id_jag_ceiling]`: how an ID-JAG's `resource`, `scope` and `authorization_details`
/// claims name attenuo capabilities, so that the root token carries no more than both the
/// `[[root_grants]]` entry and the ID-JAG allow.
///
/// - `authorization_details` entries of attenuo's own type, `attenuo_capabilities`, name
///   capabilities directly (the token's capability objects, read strictly: an unknown member
///   makes that capability name nothing); entries of any other type name nothing.
/// - `resource` values name upstream servers through [`resources`](Self::resources): each
///   mapped server stands for `<server>:*`. An unmapped value names nothing.
/// - `scope` tokens (space-separated) name capabilities through [`scopes`](Self::scopes). An
///   unmapped token names nothing.
///
/// Each claim the ID-JAG carries narrows the ceiling further; a claim it does not carry
/// narrows nothing. When what is left is empty, the request is refused
/// (`id_jag_ceiling_empty`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdJagCeilingConfig {
    /// Resource identifier (an exact `resource` value, RFC 8707) to the `[[upstreams]]` server
    /// names it stands for. Compared as strings, with no URL normalisation.
    #[serde(default)]
    pub resources: BTreeMap<String, Vec<String>>,
    /// Scope token to the capabilities it stands for, written as in `[[root_grants]]
    /// capabilities` (`"server:tool"` with globs, or a full table).
    #[serde(default)]
    pub scopes: BTreeMap<String, Vec<CapSpec>>,
}

fn default_idp_algs() -> Vec<String> {
    DEFAULT_IDP_ALGS.iter().map(|s| s.to_string()).collect()
}
fn default_attribute_claims() -> Vec<String> {
    DEFAULT_ATTRIBUTE_CLAIMS
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_jwks_ttl() -> u64 {
    300
}
fn default_clock_skew() -> u64 {
    60
}

/// One `[[agents]]` entry: an OAuth client that may exchange user credentials for root tokens.
///
/// `id` is the `client_id` and becomes the root hop's agent id. The client authenticates with
/// a secret (`secret_sha256`, the lowercase hex SHA-256 of the client secret:
/// `printf %s "$SECRET" | sha256sum`), with a JWT signed by one of its keys (`private_key_jwt`,
/// RFC 7523 §2.2; see `crate::clientauth`), or with either when both are set. The keys are
/// inline (`jwks`) or fetched from a URL the client publishes them at (`jwks_url`), never
/// both. At least one of a secret and keys is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// The OAuth `client_id`; for an agent, also the root hop's agent id.
    pub id: String,
    /// Lowercase hex SHA-256 of the client secret. Unset: the client cannot authenticate
    /// with a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_sha256: Option<String>,
    /// The client's public keys, a JWK Set as JSON text (`{"keys": [...]}`), for
    /// `private_key_jwt` client assertions. Only public, asymmetric signing keys of the
    /// algorithms in [`CLIENT_ASSERTION_ALGS`]. Unset: the client cannot authenticate with an
    /// assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    /// Where the client publishes its public keys for `private_key_jwt`, instead of `jwks`:
    /// an `https://` URL (plain `http://` only to a loopback host, as for `[[idps]]
    /// jwks_url`) serving a JWK Set that `jwks` would accept. Fetched on first use, cached for
    /// `jwks_ttl_seconds`, and fetched again on an unknown `kid`, so the client can rotate its
    /// keys with no change here. Not with `jwks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    /// How long keys fetched from `jwks_url` are used before they are fetched again. Default
    /// 300; only with `jwks_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_ttl_seconds: Option<u64>,
    /// PEM file of CA certificates trusted, for this entry's `jwks_url` only, in addition to
    /// the built-in web PKI roots, as [`IdpConfig::ca_pem_path`]. Read at start and by an
    /// agents reload; only with `jwks_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem_path: Option<PathBuf>,
}

impl AgentConfig {
    /// An entry that authenticates with a client secret, given as its SHA-256 hex digest.
    pub fn with_secret_sha256(id: impl Into<String>, secret_sha256: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            secret_sha256: Some(secret_sha256.into()),
            jwks: None,
            jwks_url: None,
            jwks_ttl_seconds: None,
            ca_pem_path: None,
        }
    }

    /// An entry that authenticates with `private_key_jwt` only, with the keys of this JWK Set.
    pub fn with_jwks(id: impl Into<String>, jwks: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            secret_sha256: None,
            jwks: Some(jwks.into()),
            jwks_url: None,
            jwks_ttl_seconds: None,
            ca_pem_path: None,
        }
    }

    /// An entry that authenticates with `private_key_jwt` only, with the keys published at
    /// `jwks_url`.
    pub fn with_jwks_url(id: impl Into<String>, jwks_url: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            secret_sha256: None,
            jwks: None,
            jwks_url: Some(jwks_url.into()),
            jwks_ttl_seconds: None,
            ca_pem_path: None,
        }
    }
}

/// The JWS algorithms a `private_key_jwt` client assertion may be signed with, and so the
/// algorithms of the keys `[[agents]] jwks` and `[[peps]] jwks` may hold: the asymmetric
/// algorithms the server accepts from identity providers ([`DEFAULT_IDP_ALGS`]).
pub const CLIENT_ASSERTION_ALGS: &[&str] = DEFAULT_IDP_ALGS;

/// One `[[root_grants]]` entry: the ceiling of what a root token for users of `issuer`, held
/// by `agent`, may carry.
///
/// IdP intake picks the entry matching the verified token's `iss`, the authenticated agent and,
/// if the entry names one, the `subject` (an entry with a `subject` wins over one without).
/// No match means no root token. The requested capabilities are attenuated against the entry's.
///
/// The dev root mint (`[dev] allow_root_mint`) uses the same list; there, an empty list lets
/// the admin mint anything, and `attributes` are copied into the user block. IdP intake
/// ignores `attributes`: user attributes come only from the verified token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootGrant {
    /// Pin the grant to one user. When absent, the grant applies to every user of `issuer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The IdP issuer (`iss`) whose users the grant covers.
    pub issuer: String,
    /// The agent the root token is issued to: the authenticated `[[agents]]` id for IdP intake,
    /// the request's `agent` for the dev root mint.
    pub agent: String,
    /// The most a root token under this grant may carry; a request is attenuated against it.
    pub capabilities: Vec<CapSpec>,
    /// User attributes the dev root mint copies into the user block. Ignored by IdP intake.
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    /// RFC 8693 §4.4 `may_act` of root tokens minted under this grant: the agents allowed to
    /// exchange them. A request may narrow it (its own `may_act` must be a subset), never widen
    /// it. When absent, the request's `may_act` (if any) is used as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<Vec<String>>,
}

impl RootGrant {
    /// The entry as start-up errors name it: issuer, agent and subject (or "any subject").
    /// With `redact_subjects` (`[logging] redact_subjects`) a subject is not written out: it
    /// names a user, which that setting keeps out of the server's output, and the entry's
    /// index in the message already tells which entry it is (SR-130).
    pub(crate) fn describe(&self, redact_subjects: bool) -> String {
        let subject = match &self.subject {
            Some(_) if redact_subjects => {
                "a subject (not shown: [logging] redact_subjects)".to_string()
            }
            Some(s) => format!("subject {s:?}"),
            None => "any subject".to_string(),
        };
        format!(
            "issuer {:?}, agent {:?}, {subject}",
            self.issuer, self.agent
        )
    }

    /// Does this grant apply to `subject` of `issuer` acting through `agent`?
    pub fn matches(&self, issuer: &str, agent: &str, subject: &str) -> bool {
        self.issuer == issuer
            && self.agent == agent
            && self.subject.as_deref().is_none_or(|s| s == subject)
    }

    /// The most specific grant for (issuer, agent, subject): a subject-pinned entry first,
    /// then one without a subject, in file order.
    pub fn find<'a>(
        grants: &'a [RootGrant],
        issuer: &str,
        agent: &str,
        subject: &str,
    ) -> Option<&'a RootGrant> {
        let mut matching = grants.iter().filter(|g| g.matches(issuer, agent, subject));
        let first = matching.next()?;
        if first.subject.is_some() {
            return Some(first);
        }
        matching.find(|g| g.subject.is_some()).or(Some(first))
    }

    /// The `may_act` of a root token minted under this grant, given the request's: the
    /// request's when it is within the grant's, the grant's when the request has none.
    ///
    /// # Errors
    ///
    /// As [`resolve_may_act`]: the request's `may_act` names an agent the grant's does not.
    pub fn may_act_for(&self, requested: Option<MayAct>) -> Result<Option<MayAct>, String> {
        resolve_may_act(self.may_act.as_deref(), requested)
    }
}

/// `may_act` for a root token: `requested` must be within `ceiling` when both are set.
///
/// # Errors
///
/// When both are set and `requested` names an agent that `ceiling` does not.
pub fn resolve_may_act(
    ceiling: Option<&[String]>,
    requested: Option<MayAct>,
) -> Result<Option<MayAct>, String> {
    let ceiling = ceiling.map(|c| MayAct::new(c.iter().cloned()));
    match (ceiling, requested) {
        (None, r) => Ok(r),
        (Some(c), None) => Ok(Some(c)),
        (Some(c), Some(r)) if r.is_within(&c) => Ok(Some(r)),
        (Some(c), Some(r)) => Err(format!(
            "may_act {:?} is not within the [[root_grants]] may_act {:?}",
            r.sub, c.sub
        )),
    }
}

/// A capability written either as shorthand `"server:tool"` (globs allowed, e.g. `"github:*"`)
/// or as a full object `{ server, tool, constraints, limits }`.
///
/// The full form is read through [`CapabilityConfig`], which refuses unknown members: a
/// misspelt `constraint = {...}` would otherwise leave the grant unconstrained. The token
/// wire format ([`Capability`]) keeps ignoring unknown members, so that an older server can
/// read a newer token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum CapSpec {
    /// Shorthand `"server:tool"`, with no constraints or limits.
    Short(String),
    /// The full table form.
    Full(Capability),
}

/// The full-table form of a capability in configuration: [`Capability`]'s members, with
/// unknown ones refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityConfig {
    /// Server name pattern: exact, `*` or `prefix*`.
    pub server: String,
    /// Tool name pattern: exact, `*` or `prefix*`.
    pub tool: String,
    /// Constraints on named arguments; an argument not listed is unconstrained.
    #[serde(default)]
    pub constraints: BTreeMap<String, attenuo_core::ArgConstraint>,
    /// Run limits on calls the capability matches.
    #[serde(default)]
    pub limits: attenuo_core::Limits,
}

impl From<CapabilityConfig> for Capability {
    fn from(c: CapabilityConfig) -> Self {
        let mut cap = Capability::new(c.server, c.tool).with_limits(c.limits);
        cap.constraints = c.constraints;
        cap
    }
}

impl<'de> Deserialize<'de> for CapSpec {
    // By hand rather than `untagged`, so that an error in the table form (an unknown member)
    // is reported as such instead of as "did not match any variant".
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CapSpec;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a capability: \"server:tool\" or a table { server, tool, ... }")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<CapSpec, E> {
                Ok(CapSpec::Short(s.to_string()))
            }
            fn visit_string<E: serde::de::Error>(self, s: String) -> Result<CapSpec, E> {
                Ok(CapSpec::Short(s))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<CapSpec, A::Error> {
                let full = CapabilityConfig::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                Ok(CapSpec::Full(full.into()))
            }
        }
        d.deserialize_any(V)
    }
}

impl CapSpec {
    /// The capability this entry stands for.
    ///
    /// # Errors
    ///
    /// A shorthand that is not `server:tool` with both parts non-empty.
    pub fn to_capability(&self) -> Result<Capability, String> {
        match self {
            CapSpec::Full(c) => Ok(c.clone()),
            CapSpec::Short(s) => {
                let (server, tool) = s
                    .split_once(':')
                    .ok_or_else(|| format!("capability `{s}` must look like `server:tool`"))?;
                if server.is_empty() || tool.is_empty() {
                    return Err(format!("capability `{s}` must look like `server:tool`"));
                }
                Ok(Capability::new(server, tool))
            }
        }
    }
}

/// Parse a list of [`CapSpec`]s into a set.
///
/// # Errors
///
/// The first entry that [`CapSpec::to_capability`] refuses (a shorthand that is not `server:tool`).
pub fn capability_set(specs: &[CapSpec]) -> Result<CapabilitySet, String> {
    specs.iter().map(CapSpec::to_capability).collect()
}

/// One warning per `prefix` constraint in `grants` that sits on an argument that looks like a
/// file path ([`Capability::path_prefix_warnings`]), each starting with `[[root_grants]]`. A
/// capability that does not parse gives none: [`Config::check_server_names`] refuses it.
pub fn root_grant_warnings(grants: &[RootGrant]) -> Vec<String> {
    grants
        .iter()
        .filter_map(|g| capability_set(&g.capabilities).ok())
        .flat_map(|set| set.path_prefix_warnings())
        .map(|w| format!("[[root_grants]] {w}"))
        .collect()
}

/// A server name used in `[[upstreams]]`, the catalog or capabilities must follow
/// [`attenuo_core::names`] (no `/`: the Cedar resource and action ids are
/// `"<server>/<tool>"`, which would be ambiguous, SR-13). `attenuo` is reserved for the
/// server's own audit records (SR-34).
///
/// # Errors
///
/// When `name` breaks [`attenuo_core::names`] (empty, or with a `/` or another character names may
/// not hold) or is the reserved `attenuo`.
pub fn check_server_name(name: &str) -> Result<(), String> {
    attenuo_core::names::check_server_name(name).map_err(|e| e.to_string())?;
    if name == crate::routes::AUDIT_SERVER {
        // Audit records of the server's own events (issuance, renewal, admin actions) use
        // this server name; a tool call through an upstream of the same name would be
        // indistinguishable from them (SR-34).
        return Err(format!(
            "server name `{name}` is reserved for the server's own audit records"
        ));
    }
    Ok(())
}

/// Refuse the agent id `attenuo` in `section` (SR-34): an agent of that name would put its own
/// name next to the server's in audit records (`agents` beside `server = "attenuo"`).
fn reserved_agent_id(section: &str, id: &str) -> anyhow::Result<()> {
    if id == crate::routes::AUDIT_SERVER {
        anyhow::bail!("{section}: agent id `{id}` is reserved for the server's own records");
    }
    Ok(())
}

/// Refuse the reserved agent id `attenuo` in `[[agents]]` and `[[peps]]`. Part of
/// [`Config::check_server_names`], and of the check startup and `POST /admin/agents/reload`
/// share.
///
/// # Errors
///
/// When an entry's id is `attenuo`; the message names the section.
pub fn check_reserved_client_ids(agents: &[AgentConfig], peps: &[PepConfig]) -> anyhow::Result<()> {
    for a in agents {
        reserved_agent_id("[[agents]]", &a.id)?;
    }
    for p in peps {
        reserved_agent_id("[[peps]]", &p.id)?;
    }
    Ok(())
}

/// The message of a TOML error in `text`, with its line and, when the line names one, its key
/// and table, and without any value of the file. The default rendering quotes the line, and a
/// deserializer's message may repeat the value it refused (`invalid type: string "...",
/// expected u64`, `unknown variant `...``); either can be `[admin] token = "..."` or another
/// secret. So the line is never quoted, every double-quoted string in the message is replaced
/// by `"…"`, and so is every other occurrence of the refused value (the text the error points
/// at). What the reloads answer (`POST /admin/operators/reload`, `POST /admin/agents/reload`).
pub(crate) fn toml_error_text(text: &str, e: &toml::de::Error) -> String {
    let span = e.span();
    let start = span.as_ref().map(|s| s.start).filter(|&s| s <= text.len());
    let line = start
        .and_then(|s| text.get(..s))
        .map_or(0, |before| before.matches('\n').count() + 1);
    let mut message = e.message().to_string();
    // The refused value as written, without its quotes: every backquoted or bare copy of it
    // in the message goes.
    if let Some(value) = span
        .as_ref()
        .and_then(|s| text.get(s.clone()))
        .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\''))
        .filter(|v| !v.is_empty())
    {
        message = message.replace(&format!("`{value}`"), "`…`");
        message = message.replace(&format!("'{value}'"), "'…'");
    }
    let message = redact_quoted(&message);
    let place = start.map(|s| toml_place(text, s)).unwrap_or_default();
    format!("the config file is not valid TOML (line {line}{place}): {message}")
}

/// `message` with the content of each double-quoted string (escapes included) replaced by
/// `…`. A deserializer's message quotes values that way, never a type or a key.
fn redact_quoted(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut chars = message.chars();
    while let Some(c) = chars.next() {
        out.push(c);
        if c != '"' {
            continue;
        }
        out.push('…');
        let mut escaped = false;
        for c in chars.by_ref() {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                out.push('"');
                break;
            }
        }
    }
    out
}

/// `, key `k` in [table]` for the error at byte `at` of `text`: the bare key before `=` on its
/// line and the last table header above it, each only when it is made of the characters a bare
/// key or a header holds (nothing that could be a value). Empty when neither is found.
fn toml_place(text: &str, at: usize) -> String {
    let bare = |s: &str, extra: &[char]| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c) || extra.contains(&c))
    };
    let before = text.get(..at).unwrap_or_default();
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let line = text.get(line_start..).unwrap_or_default();
    let line = line.split('\n').next().unwrap_or_default();
    let key = line
        .split_once('=')
        .map(|(k, _)| k.trim())
        .filter(|k| bare(k, &[]));
    let table = before
        .get(..line_start)
        .unwrap_or_default()
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| l.starts_with('['))
        .filter(|h| bare(h, &['[', ']']));
    match (key, table) {
        (Some(k), Some(t)) => format!(", key `{k}` in {t}"),
        (Some(k), None) => format!(", key `{k}`"),
        (None, Some(t)) => format!(", in {t}"),
        (None, None) => String::new(),
    }
}

/// A digest of each top-level section of a config, but `[[agents]]`, `[[peps]]`,
/// `[[admin.operators]]` and the key files of `[issuer]` (`private_key_pem_path`,
/// `previous_key_paths`), which have reloads of their own: what `POST /admin/agents/reload`
/// and `POST /admin/keys/reload` compare the file with, to say which sections differ from the
/// ones in force and so need a restart. Only digests are kept, no value of the config.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SectionDigests(BTreeMap<String, [u8; 32]>);

impl std::fmt::Debug for SectionDigests {
    /// The section names only: a digest of a section with few possible values (one that holds
    /// a short token, say) could be guessed from it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl SectionDigests {
    /// The sections (`[server]`, `[[upstreams]]`) whose digest differs between `self` and
    /// `other`, or that only one of them has, in name order.
    pub fn differing(&self, other: &Self) -> Vec<String> {
        let mut out: Vec<String> = self
            .0
            .iter()
            .filter(|(k, v)| other.0.get(*k) != Some(*v))
            .map(|(k, _)| k.clone())
            .chain(other.0.keys().filter(|k| !self.0.contains_key(*k)).cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

impl Config {
    /// The [`SectionDigests`] of this config: each top-level key of its serialization, but
    /// `agents`, `peps`, `admin.operators` and the key files of `issuer`, as `[name]` for a table and `[[name]]` for an
    /// array of tables, with the SHA-256 of its JSON form. Defaults are serialized too, so a
    /// section left out of the file and one written with its default values compare equal.
    ///
    /// # Errors
    ///
    /// When the config cannot be serialized to JSON, which the types do not allow in practice.
    pub fn section_digests(&self) -> anyhow::Result<SectionDigests> {
        use anyhow::Context as _;
        use sha2::Digest as _;
        let value = serde_json::to_value(self).context("serializing the config")?;
        let serde_json::Value::Object(map) = value else {
            anyhow::bail!("the config does not serialize to an object");
        };
        let mut out = BTreeMap::new();
        for (key, mut v) in map {
            if key == "agents" || key == "peps" {
                continue;
            }
            if key == "admin" {
                if let Some(admin) = v.as_object_mut() {
                    admin.remove("operators");
                }
            }
            // The key files, which `POST /admin/keys/reload` reads.
            if key == "issuer" {
                if let Some(issuer) = v.as_object_mut() {
                    issuer.remove("private_key_pem_path");
                    issuer.remove("previous_key_paths");
                }
            }
            let name = if v.is_array() {
                format!("[[{key}]]")
            } else {
                format!("[{key}]")
            };
            let bytes = serde_json::to_vec(&v).context("serializing the config")?;
            out.insert(name, sha2::Sha256::digest(&bytes).into());
        }
        Ok(SectionDigests(out))
    }

    /// Parse the text of the config file as the server does at startup (the file, then the
    /// `ATTENUO__<SECTION>__<KEY>` overrides in `env`, then [`apply_env`](Self::apply_env)),
    /// for a reload: a TOML error names its line and never quotes it.
    ///
    /// # Errors
    ///
    /// As [`from_toml_with_env`](Self::from_toml_with_env).
    pub fn reparse<I, K, V>(text: &str, env: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<std::ffi::OsString>,
        V: Into<std::ffi::OsString>,
    {
        Ok(Self::reparse_with_overrides(text, env)?.0)
    }

    /// As [`reparse`](Self::reparse), and the keys an environment variable set (a value there
    /// wins over the file's, at a reload as at startup).
    ///
    /// # Errors
    ///
    /// As [`reparse`](Self::reparse).
    pub fn reparse_with_overrides<I, K, V>(
        text: &str,
        env: I,
    ) -> anyhow::Result<(Self, Vec<EnvOverride>)>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<std::ffi::OsString>,
        V: Into<std::ffi::OsString>,
    {
        let quiet = |e: toml::de::Error| anyhow::anyhow!(toml_error_text(text, &e));
        let base: Self = toml::from_str(text).map_err(quiet)?;
        let file: toml::Table = text.parse().map_err(quiet)?;
        let (mut config, set) = overrides::apply(file, base, env)?;
        config.apply_env();
        Ok((config, set))
    }

    /// Check `[[ext_authz]]`: each `server` a valid server name ([`check_server_name`]) named
    /// once, each `secret_sha256` 64 hex digits, and each `dpop_url` an absolute `http` or
    /// `https` URL with a host and no query or fragment.
    ///
    /// # Errors
    ///
    /// When an entry breaks one of these rules; the message names the entry's server.
    pub fn check_ext_authz(&self) -> anyhow::Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for e in &self.ext_authz {
            check_server_name(&e.server).map_err(|m| anyhow::anyhow!("[[ext_authz]]: {m}"))?;
            if !seen.insert(e.server.as_str()) {
                anyhow::bail!("[[ext_authz]]: server `{}` is listed twice", e.server);
            }
            let hex_ok = e.secret_sha256.len() == 64
                && e.secret_sha256.bytes().all(|b| b.is_ascii_hexdigit());
            if !hex_ok {
                anyhow::bail!(
                    "[[ext_authz]] `{}`: secret_sha256 must be 64 hex characters",
                    e.server
                );
            }
            if let Some(u) = &e.dpop_url {
                let ok = reqwest::Url::parse(u).is_ok_and(|p| {
                    matches!(p.scheme(), "http" | "https")
                        && p.host_str().is_some()
                        && p.query().is_none()
                        && p.fragment().is_none()
                });
                if !ok {
                    anyhow::bail!(
                        "[[ext_authz]] `{}`: dpop_url must be an absolute http or https URL \
                         with no query or fragment",
                        e.server
                    );
                }
            }
        }
        Ok(())
    }

    /// Reject server names that contain `/`, are empty or are the reserved `attenuo` in
    /// `[[upstreams]]`, the tool catalog (inline and `catalog_path`) and `[[root_grants]]`
    /// capabilities, and the agent id `attenuo` in `[[agents]]`, `[[peps]]` and
    /// `[[root_grants]]` (SR-34).
    ///
    /// # Errors
    ///
    /// When a server name in `[[upstreams]]`, the catalog or a `[[root_grants]]` capability is
    /// refused by [`check_server_name`], when the catalog cannot be loaded or does not validate,
    /// when a `[[root_grants]]` capability does not parse, is over the size bounds (SR-123) or
    /// has limits no token may carry ([`Capability::validate_limits`]), or when an agent id in
    /// `[[agents]]`, `[[peps]]` or `[[root_grants]]` is `attenuo`. The message names the
    /// section; for `[[root_grants]]` it also names the entry by index (from 0, in file
    /// order), issuer, agent and subject.
    pub fn check_server_names(&self) -> anyhow::Result<()> {
        for u in &self.upstreams {
            check_server_name(&u.name).map_err(|e| anyhow::anyhow!("[[upstreams]]: {e}"))?;
        }
        let catalog = self.policy.load_catalog()?;
        for ((server, _), _) in catalog.iter() {
            check_server_name(server).map_err(|e| anyhow::anyhow!("[policy] catalog: {e}"))?;
        }
        catalog
            .validate()
            .map_err(|e| anyhow::anyhow!("[policy] catalog: {e}"))?;
        check_reserved_client_ids(&self.agents, &self.peps)?;
        for (index, g) in self.root_grants.iter().enumerate() {
            // Every refusal names the entry: its index from 0 in file order, issuer, agent
            // and subject, since several entries may share an agent or an issuer.
            let entry = format!(
                "[[root_grants]] entry {index} ({})",
                g.describe(self.logging.redact_subjects)
            );
            reserved_agent_id(&entry, &g.agent)?;
            let caps =
                capability_set(&g.capabilities).map_err(|e| anyhow::anyhow!("{entry}: {e}"))?;
            // A request is attenuated against the grant at a cost of the product (SR-123).
            caps.validate_size()
                .map_err(|e| anyhow::anyhow!("{entry}: {e}"))?;
            for cap in caps.iter() {
                cap.validate()
                    .map_err(|e| anyhow::anyhow!("{entry}: {e}"))?;
                if cap.server != "*" {
                    check_server_name(&cap.server).map_err(|e| anyhow::anyhow!("{entry}: {e}"))?;
                }
                // The check every hop-0 mint makes (`Chain::root`): limits no token
                // may carry would start and then fail every mint under this grant with
                // `invalid_capability`, as `[idps.id_jag_ceiling] scopes` did (SR-125).
                cap.validate_limits().map_err(|e| {
                    anyhow::anyhow!(
                        "{entry}: {e}; no token may carry it, so every mint under this grant \
                         would fail"
                    )
                })?;
            }
        }
        Ok(())
    }

    /// Warnings about `[[root_grants]]` capabilities ([`root_grant_warnings`]), which the server
    /// logs at startup. `attenuo policy lint --config` prints the same ones.
    pub fn root_grant_warnings(&self) -> Vec<String> {
        root_grant_warnings(&self.root_grants)
    }

    /// Problems with the admin credentials, or `None` when they are acceptable: no
    /// credential at all (no `[admin] token` and no `[[admin.operators]]`), or an `[admin]
    /// token` that is weak. An operator's token is generated by the CLI and only its digest is
    /// configured, so there is nothing to check about its strength here.
    pub fn admin_token_problem(&self) -> Option<String> {
        let token = match self.admin.token.as_deref() {
            None if !self.admin.operators.is_empty() => return None,
            None => {
                return Some("[admin] token is not set and there are no [[admin.operators]]".into())
            }
            Some(t) => t,
        };
        if PLACEHOLDER_ADMIN_TOKENS
            .iter()
            .any(|p| p.eq_ignore_ascii_case(token.trim()))
        {
            return Some("[admin] token is a published placeholder value".into());
        }
        if token.len() < MIN_ADMIN_TOKEN_LEN {
            return Some(format!(
                "[admin] token is shorter than {MIN_ADMIN_TOKEN_LEN} bytes"
            ));
        }
        None
    }

    /// Refuse a weak or missing admin token unless the server listens on loopback only, where
    /// it is a warning (SR-15). An enabled `[admin_ui]` listener and an `[admin] listen`
    /// listener count as listeners here, since they serve the admin API too.
    ///
    /// # Errors
    ///
    /// When [`admin_token_problem`](Self::admin_token_problem) finds a problem (no admin
    /// credential at all, or an `[admin] token` that is a published placeholder or shorter than
    /// `MIN_ADMIN_TOKEN_LEN` bytes) and `[server] listen`, `[admin]
    /// listen` or an enabled `[admin_ui] listen` is not a loopback address. On loopback only the
    /// problem is a warning.
    pub fn check_admin_token(&self) -> anyhow::Result<()> {
        let Some(problem) = self.admin_token_problem() else {
            return Ok(());
        };
        // The console listener serves the admin API too, so it counts as exposure.
        let console = self
            .admin_ui
            .enabled
            .then_some(("[admin_ui] listen", self.admin_ui.listen));
        // So does an admin API listener of its own. `[server] listen` keeps counting when the
        // admin API is not on it: a weak token is refused on any server reachable off loopback.
        let admin = self.admin.listen.map(|addr| ("[admin] listen", addr));
        let exposed = std::iter::once(("[server] listen", self.server.listen))
            .chain(admin)
            .chain(console)
            .find(|(_, addr)| !addr.ip().is_loopback());
        let Some((key, addr)) = exposed else {
            tracing::warn!(
                listen = %self.server.listen,
                "{problem}; accepted because the server only listens on loopback. Generate a \
                 real one with `openssl rand -hex 32` before binding another address."
            );
            return Ok(());
        };
        anyhow::bail!(
            "{problem}, and {key} = {addr} is not loopback. Set a random token of at \
             least {MIN_ADMIN_TOKEN_LEN} bytes (`openssl rand -hex 32`) in [admin] token or \
             {ADMIN_TOKEN_ENV}, or add [[admin.operators]] (`attenuo admin operator new`)."
        )
    }

    /// Check `[[admin.operators]]` (ADR-0016): every name passes
    /// [`crate::operators::check_operator_name`] and is unique, every `token_sha256` is 64
    /// lowercase hex characters, no two operators share a digest, and no operator's digest is
    /// that of `[admin] token` (call it after [`apply_env`](Self::apply_env), so the token in
    /// force is the one compared).
    ///
    /// # Errors
    ///
    /// On the first entry that breaks one of those rules; the message names the entry, never
    /// a digest or the token.
    pub fn check_admin_operators(&self) -> anyhow::Result<()> {
        crate::operators::check_operators(
            &self.admin.operators,
            self.admin
                .token
                .as_deref()
                .map(crate::operators::token_sha256),
        )
    }

    /// Startup check of `[audit.retention]`, which needs the other sections: with `prune`
    /// other than `"off"`, refuse `sqlite_path = ":memory:"`, a log without `[audit.sink]`
    /// (the anchor must leave the host, ADR-0015), and a `min_age_seconds` below the run-state
    /// retentions (`[leases] retention_seconds + run_state_retention_seconds`, each term only
    /// when not 0, and `user_window_retention_seconds`), so that a record is never pruned
    /// before the run state that might need it. `batch_rows` is checked whatever `prune` is.
    /// The keys of `"auto"` (`keep_seconds`, `interval_seconds`, `archive_dir`,
    /// `max_entries_per_run`) are refused with another mode. With `"auto"`, `archive_dir` must
    /// be an existing directory a file can be written in (a probe file is created and
    /// removed); without it, a warning says the records are deleted without a copy.
    ///
    /// # Errors
    ///
    /// The message names the setting and the bound.
    pub fn check_retention(&self) -> anyhow::Result<()> {
        let r = &self.audit.retention;
        if !(1..=MAX_PRUNE_BATCH_ROWS).contains(&r.batch_rows) {
            anyhow::bail!(
                "[audit.retention] batch_rows must be between 1 and {MAX_PRUNE_BATCH_ROWS}, not {}",
                r.batch_rows
            );
        }
        if r.min_age_seconds > MAX_PRUNE_MIN_AGE_SECONDS {
            anyhow::bail!(
                "[audit.retention] min_age_seconds must be at most {MAX_PRUNE_MIN_AGE_SECONDS} \
                 (100 years), not {}",
                r.min_age_seconds
            );
        }
        if r.prune != PruneMode::Auto {
            for (key, set) in [
                ("keep_seconds", r.keep_seconds.is_some()),
                ("interval_seconds", r.interval_seconds.is_some()),
                ("archive_dir", r.archive_dir.is_some()),
                ("max_entries_per_run", r.max_entries_per_run.is_some()),
            ] {
                if set {
                    anyhow::bail!(
                        "[audit.retention] {key} is only for prune = \"auto\", and prune is \"{}\": \
                         remove it, or set prune = \"auto\"",
                        r.prune
                    );
                }
            }
        }
        if r.prune == PruneMode::Off {
            return Ok(());
        }
        if self.leases.retention_seconds == 0 {
            tracing::warn!(
                "[audit.retention] prune = \"{}\" with [leases] retention_seconds = 0: every \
                 lease tree stays in the registry, so the prune_live_run guard refuses any \
                 boundary at or above the first record of a chain that was ever issued; set \
                 retention_seconds to let old trees go",
                r.prune
            );
        }
        if self.audit.sqlite_path == ":memory:" {
            anyhow::bail!(
                "[audit.retention] prune = \"{}\" needs a file: [audit] sqlite_path is \
                 \":memory:\", which keeps nothing to prune",
                r.prune
            );
        }
        if self.audit.sink.is_none() {
            anyhow::bail!(
                "[audit.retention] prune = \"{}\" needs [audit.sink]: the signed anchor of a \
                 prune must be shipped off the host with the checkpoints",
                r.prune
            );
        }
        let runs = self
            .leases
            .retention_seconds
            .saturating_add(self.leases.run_state_retention_seconds);
        let floor = runs.max(self.leases.user_window_retention_seconds);
        if r.min_age_seconds < floor {
            anyhow::bail!(
                "[audit.retention] min_age_seconds = {} is below the run-state retention of \
                 [leases] ({floor}: retention_seconds + run_state_retention_seconds = {runs}, \
                 user_window_retention_seconds = {}): a record could be pruned while run state \
                 still points to it. Use at least {floor}",
                r.min_age_seconds,
                self.leases.user_window_retention_seconds
            );
        }
        if r.prune == PruneMode::Auto {
            let Some(keep) = r.keep_seconds else {
                anyhow::bail!(
                    "[audit.retention] prune = \"auto\" needs keep_seconds: how old, in seconds, \
                     an entry must be before the server prunes it (for example 7776000, 90 days)"
                );
            };
            let least = r.min_age_seconds.max(MIN_AUTO_KEEP_SECONDS);
            if keep < least {
                anyhow::bail!(
                    "[audit.retention] keep_seconds = {keep} is below {least}: it must be at least \
                     min_age_seconds ({}) and at least a day ({MIN_AUTO_KEEP_SECONDS})",
                    r.min_age_seconds
                );
            }
            if keep > MAX_PRUNE_MIN_AGE_SECONDS {
                anyhow::bail!(
                    "[audit.retention] keep_seconds must be at most {MAX_PRUNE_MIN_AGE_SECONDS} \
                     (100 years), not {keep}"
                );
            }
            if let Some(i) = r.interval_seconds {
                if !(1..=MAX_AUTO_INTERVAL_SECONDS).contains(&i) {
                    anyhow::bail!(
                        "[audit.retention] interval_seconds must be between 1 and \
                         {MAX_AUTO_INTERVAL_SECONDS} (a day), not {i}"
                    );
                }
            }
            if r.max_entries_per_run == Some(0) {
                anyhow::bail!("[audit.retention] max_entries_per_run must be at least 1");
            }
            match &r.archive_dir {
                Some(dir) => check_archive_dir(dir)?,
                None => tracing::warn!(
                    "[audit.retention] prune = \"auto\" without archive_dir: automatic pruning \
                     deletes audit records without keeping a copy of them. The shipped anchors \
                     prove what was pruned, not what it said. Set archive_dir to keep each \
                     pruned prefix as an export file"
                ),
            }
        }
        Ok(())
    }

    /// Apply environment overrides: [`ADMIN_TOKEN_ENV`] replaces `[admin] token`.
    pub fn apply_env(&mut self) {
        if let Some(t) = std::env::var(ADMIN_TOKEN_ENV)
            .ok()
            .filter(|t| !t.is_empty())
        {
            self.admin.token = Some(t);
        }
    }

    /// Parse TOML text.
    ///
    /// # Errors
    ///
    /// When `text` is not TOML or does not match the config's shape (an unknown key, a wrong type,
    /// a missing required field).
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// Parse TOML text, then apply the `ATTENUO__<SECTION>__<KEY>` overrides found in `env`
    /// (name and value pairs, normally [`std::env::vars_os`]). Returns the keys that were
    /// overridden, which the server logs by name. Every other variable in `env` is ignored,
    /// including `ATTENUO_ADMIN_TOKEN` and `ATTENUO_LOG_FORMAT`, which keep applying where they
    /// did ([`apply_env`](Self::apply_env), [`crate::logging::LoggingSection::resolve_format`]).
    ///
    /// # Errors
    ///
    /// As [`from_toml`](Self::from_toml) for the text. For the variables: one names no
    /// overridable key (unknown, a list, a table of names, an array of tables, an optional
    /// section the file lacks, or a `[dev]` key), has a value that is empty or does not parse
    /// as the key's type, sets the same key as another variable, or sets `[admin] token` or
    /// `[logging] format` while `ATTENUO_ADMIN_TOKEN` or `ATTENUO_LOG_FORMAT` is set too. The
    /// message names every such variable and none of their values.
    pub fn from_toml_with_env<I, K, V>(
        text: &str,
        env: I,
    ) -> anyhow::Result<(Self, Vec<EnvOverride>)>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<std::ffi::OsString>,
        V: Into<std::ffi::OsString>,
    {
        let base = Self::from_toml(text)?;
        let file: toml::Table = text.parse()?;
        overrides::apply(file, base, env)
    }

    /// Read and parse a file.
    ///
    /// # Errors
    ///
    /// When the file cannot be read, or as [`from_toml`](Self::from_toml); the message names the
    /// path. The path is kept as [`source_path`](Self::source_path).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        let mut config = Self::from_toml(&text)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        config.source_path = Some(path.to_path_buf());
        Ok(config)
    }

    /// Read and parse a file, then apply the environment overrides in `env`, as
    /// [`from_toml_with_env`](Self::from_toml_with_env).
    ///
    /// # Errors
    ///
    /// When the file cannot be read or parsed (the message names the path), or as
    /// [`from_toml_with_env`](Self::from_toml_with_env) for the variables.
    pub fn load_with_env<I, K, V>(path: &Path, env: I) -> anyhow::Result<(Self, Vec<EnvOverride>)>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<std::ffi::OsString>,
        V: Into<std::ffi::OsString>,
    {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        let base = Self::from_toml(&text)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        let file: toml::Table = text
            .parse()
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        let (mut config, applied) = overrides::apply(file, base, env)?;
        config.source_path = Some(path.to_path_buf());
        Ok((config, applied))
    }
}

/// Start-up check of `[audit.retention] archive_dir`: it exists, is a directory, and a file
/// can be created, written, flushed and removed in it.
fn check_archive_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Write;

    let shown = dir.display();
    let meta = std::fs::metadata(dir).map_err(|e| {
        anyhow::anyhow!("[audit.retention] archive_dir {shown} cannot be used: {e}")
    })?;
    if !meta.is_dir() {
        anyhow::bail!("[audit.retention] archive_dir {shown} is not a directory");
    }
    let probe = dir.join(format!(".attenuo-archive-probe-{}", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|mut f| {
            f.write_all(b"probe\n")?;
            f.sync_all()
        });
    let _ = std::fs::remove_file(&probe);
    written.map_err(|e| {
        anyhow::anyhow!(
            "[audit.retention] archive_dir {shown} is not writable: {e}; the automatic prune \
             writes each pruned prefix there before it prunes"
        )
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn prefix_on_a_path_argument_in_root_grants_is_a_warning_not_an_error() {
        let text = r#"
            [server]
            listen = "127.0.0.1:0"

            [[root_grants]]
            issuer = "https://idp.example"
            agent = "coder"
            capabilities = [
                "fs:list",
                { server = "fs", tool = "read_file", constraints = { path = { op = "prefix", value = "/workspace/" } } },
                { server = "fs", tool = "write_file", constraints = { path = { op = "path_prefix", value = "/workspace/" } } },
                { server = "web", tool = "fetch", constraints = { url = { op = "prefix", value = "https://a.example/" } } },
            ]
        "#;
        let cfg = Config::from_toml(text).unwrap();
        cfg.check_server_names().unwrap();
        let warnings = cfg.root_grant_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("[[root_grants]] fs:read_file argument \"path\": `prefix`"),
            "{warnings:?}"
        );
        // A malformed `path_prefix` is a config error, like a malformed range.
        let bad = text.replace(
            r#"op = "path_prefix", value = "/workspace/""#,
            r#"op = "path_prefix", value = "/workspace/../etc""#,
        );
        let err = Config::from_toml(&bad).unwrap_err().to_string();
        assert!(
            err.contains("a path_prefix constraint's path holds a `.` or `..` segment"),
            "{err}"
        );
    }

    #[test]
    fn proxy_limits_have_defaults_and_refuse_zero_sr36() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.proxy.max_upstream_body_bytes, 16 * 1024 * 1024);
        assert_eq!(cfg.proxy.max_request_body_bytes, 4 * 1024 * 1024);
        assert_eq!(cfg.proxy.session_ttl_seconds, 3600);
        assert_eq!(cfg.proxy.max_sessions, 100_000);
        assert_eq!(cfg.proxy.max_sessions_per_principal, 64);
        cfg.proxy.check_limits().unwrap();
        let applied = cfg.proxy.apply(attenuo_proxy::ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![],
        ));
        assert_eq!(applied.max_sessions, 100_000);
        assert_eq!(applied.max_sessions_per_principal, 64);
        for key in [
            "max_upstream_body_bytes",
            "max_request_body_bytes",
            "session_ttl_seconds",
            "max_sessions",
            "max_sessions_per_principal",
        ] {
            let cfg = Config::from_toml(&format!("[proxy]\n{key} = 0\n")).unwrap();
            let err = cfg.proxy.check_limits().unwrap_err().to_string();
            assert!(err.contains(key), "{err}");
        }
    }

    #[test]
    fn list_filter_defaults_to_capabilities_and_refuses_unknown_values() {
        use attenuo_proxy::ListFilterMode;
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.proxy.list_filter, ListFilterMode::Capabilities);
        let proxy = cfg.proxy.apply(attenuo_proxy::ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![],
        ));
        assert_eq!(proxy.list_filter, ListFilterMode::Capabilities);
        for (text, mode) in [
            ("capabilities", ListFilterMode::Capabilities),
            ("policy", ListFilterMode::Policy),
        ] {
            let cfg = Config::from_toml(&format!("[proxy]\nlist_filter = \"{text}\"\n")).unwrap();
            assert_eq!(cfg.proxy.list_filter, mode);
            let proxy = cfg.proxy.apply(attenuo_proxy::ProxyConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                vec![],
            ));
            assert_eq!(proxy.list_filter, mode);
        }
        for bad in ["\"Policy\"", "\"cedar\"", "\"\"", "true"] {
            let err = Config::from_toml(&format!("[proxy]\nlist_filter = {bad}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("list_filter") || err.contains("variant"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn require_listed_tools_defaults_to_on_sr25() {
        assert!(Config::from_toml("").unwrap().proxy.require_listed_tools);
        assert!(
            !Config::from_toml("[proxy]\nrequire_listed_tools = false\n")
                .unwrap()
                .proxy
                .require_listed_tools
        );
    }

    #[test]
    fn proxy_stream_recheck_defaults_to_two_seconds_and_refuses_zero() {
        let cfg = super::Config::from_toml("").unwrap();
        assert_eq!(
            cfg.proxy.stream_recheck().unwrap(),
            std::time::Duration::from_secs(2)
        );
        let cfg = super::Config::from_toml("[proxy]\nstream_recheck_seconds = 5\n").unwrap();
        assert_eq!(
            cfg.proxy.stream_recheck().unwrap(),
            std::time::Duration::from_secs(5)
        );
        let cfg = super::Config::from_toml("[proxy]\nstream_recheck_seconds = 0\n").unwrap();
        assert!(cfg.proxy.stream_recheck().is_err());
    }

    #[test]
    fn proxy_record_window_defaults_and_bounds() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.proxy.record_window_seconds, 60);
        assert_eq!(cfg.proxy.record_window_max_keys, 10_000);
        let (window, max_keys) = cfg.proxy.record_window().unwrap();
        assert_eq!(window, attenuo_proxy::records::DEFAULT_RECORD_WINDOW);
        assert_eq!(
            max_keys,
            attenuo_proxy::records::DEFAULT_RECORD_WINDOW_MAX_KEYS
        );
        let applied = cfg.proxy.apply(attenuo_proxy::ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![],
        ));
        assert_eq!(applied.record_window, std::time::Duration::from_secs(60));
        assert_eq!(applied.record_window_max_keys, 10_000);

        for (toml, secs, keys) in [
            (
                "record_window_seconds = 5\nrecord_window_max_keys = 500\n",
                5,
                500,
            ),
            (
                "record_window_seconds = 1\nrecord_window_max_keys = 100\n",
                1,
                100,
            ),
            (
                "record_window_seconds = 3600\nrecord_window_max_keys = 1000000\n",
                3600,
                1_000_000,
            ),
        ] {
            let cfg = Config::from_toml(&format!("[proxy]\n{toml}")).unwrap();
            assert_eq!(
                cfg.proxy.record_window().unwrap(),
                (std::time::Duration::from_secs(secs), keys)
            );
            let applied = cfg.proxy.apply(attenuo_proxy::ProxyConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                vec![],
            ));
            assert_eq!(
                (applied.record_window, applied.record_window_max_keys),
                (std::time::Duration::from_secs(secs), keys)
            );
        }

        for (line, expect) in [
            (
                "record_window_seconds = 0",
                "[proxy] record_window_seconds must be between 1 and 3600, not 0",
            ),
            (
                "record_window_seconds = 3601",
                "[proxy] record_window_seconds must be between 1 and 3600, not 3601",
            ),
            (
                "record_window_max_keys = 0",
                "[proxy] record_window_max_keys must be between 100 and 1000000, not 0",
            ),
            (
                "record_window_max_keys = 99",
                "[proxy] record_window_max_keys must be between 100 and 1000000, not 99",
            ),
            (
                "record_window_max_keys = 1000001",
                "[proxy] record_window_max_keys must be between 100 and 1000000, not 1000001",
            ),
        ] {
            let cfg = Config::from_toml(&format!("[proxy]\n{line}\n")).unwrap();
            let err = cfg.proxy.record_window().unwrap_err().to_string();
            assert_eq!(err, expect);
        }
        // Not a whole non-negative number: the parse error names the key.
        for line in [
            "record_window_seconds = \"60\"",
            "record_window_seconds = 1.5",
            "record_window_seconds = -1",
            "record_window_max_keys = \"many\"",
        ] {
            let err = Config::from_toml(&format!("[proxy]\n{line}\n"))
                .unwrap_err()
                .to_string();
            let key = line.split(' ').next().unwrap();
            assert!(err.contains(key), "{line}: {err}");
        }
    }

    #[test]
    fn session_retention_defaults_to_a_day_and_zero_turns_it_off() {
        let cfg = super::Config::from_toml("").unwrap();
        assert_eq!(
            cfg.leases.session_retention(),
            Some(time::Duration::hours(24))
        );
        let cfg = super::Config::from_toml("[leases]\nsession_retention_seconds = 7200\n").unwrap();
        assert_eq!(
            cfg.leases.session_retention(),
            Some(time::Duration::hours(2))
        );
        let cfg = super::Config::from_toml("[leases]\nsession_retention_seconds = 0\n").unwrap();
        assert_eq!(cfg.leases.session_retention(), None);
        assert!(super::Config::from_toml("[leases]\nsession_retention = 1\n").is_err());
    }

    #[test]
    fn lease_retention_defaults_to_a_week_and_zero_turns_it_off() {
        let cfg = super::Config::from_toml("").unwrap();
        assert_eq!(cfg.leases.retention(), Some(time::Duration::weeks(1)));
        assert_eq!(cfg.leases.retention_seconds, 604_800);
        // Independent of the session retention.
        let cfg = super::Config::from_toml(
            "[leases]\nretention_seconds = 172800\nsession_retention_seconds = 0\n",
        )
        .unwrap();
        assert_eq!(cfg.leases.retention(), Some(time::Duration::days(2)));
        assert_eq!(cfg.leases.session_retention(), None);
        let cfg = super::Config::from_toml("[leases]\nretention_seconds = 0\n").unwrap();
        assert_eq!(cfg.leases.retention(), None);
        assert_eq!(
            cfg.leases.session_retention(),
            Some(time::Duration::hours(24))
        );
        assert!(super::Config::from_toml("[leases]\nretention = 1\n").is_err());
    }

    #[test]
    fn user_window_retention_defaults_to_35_days_and_refuses_less_than_a_day() {
        let cfg = super::Config::from_toml("").unwrap();
        assert_eq!(
            cfg.leases.user_window_retention().unwrap(),
            Some(time::Duration::days(35))
        );
        let cfg =
            super::Config::from_toml("[leases]\nuser_window_retention_seconds = 0\n").unwrap();
        assert_eq!(cfg.leases.user_window_retention().unwrap(), None);
        let cfg =
            super::Config::from_toml("[leases]\nuser_window_retention_seconds = 86400\n").unwrap();
        assert_eq!(
            cfg.leases.user_window_retention().unwrap(),
            Some(time::Duration::days(1))
        );
        let cfg =
            super::Config::from_toml("[leases]\nuser_window_retention_seconds = 86399\n").unwrap();
        let err = cfg.leases.user_window_retention().unwrap_err().to_string();
        assert!(err.contains("below a day"), "{err}");
    }

    #[test]
    fn run_state_retention_defaults_to_thirty_days_and_zero_turns_it_off() {
        let cfg = super::Config::from_toml("").unwrap();
        assert_eq!(
            cfg.leases.run_state_retention(),
            Some(time::Duration::days(30))
        );
        assert_eq!(cfg.leases.run_state_retention_seconds, 2_592_000);
        // Independent of the lease and session retentions.
        let cfg = super::Config::from_toml(
            "[leases]\nrun_state_retention_seconds = 86400\nretention_seconds = 0\n",
        )
        .unwrap();
        assert_eq!(
            cfg.leases.run_state_retention(),
            Some(time::Duration::days(1))
        );
        assert_eq!(cfg.leases.retention(), None);
        assert_eq!(
            cfg.leases.session_retention(),
            Some(time::Duration::hours(24))
        );
        let cfg = super::Config::from_toml("[leases]\nrun_state_retention_seconds = 0\n").unwrap();
        assert_eq!(cfg.leases.run_state_retention(), None);
        assert_eq!(cfg.leases.retention(), Some(time::Duration::weeks(1)));
        assert!(super::Config::from_toml("[leases]\nrun_state_retention = 1\n").is_err());
    }

    #[test]
    fn lease_maintenance_defaults_and_bounds() {
        let cfg = super::Config::from_toml("").unwrap();
        assert_eq!(cfg.leases.maintenance_interval_seconds, 60);
        assert_eq!(cfg.leases.maintenance_batch_rows, 1_000);
        assert_eq!(cfg.leases.maintenance_max_passes, 100);
        let m = cfg.leases.maintenance().unwrap();
        assert_eq!(m, super::LeaseMaintenance::default());
        assert_eq!(m.interval, std::time::Duration::from_secs(60));
        assert_eq!((m.batch_rows, m.max_passes), (1_000, 100));

        let cfg = super::Config::from_toml(
            "[leases]\nmaintenance_interval_seconds = 1\nmaintenance_batch_rows = 100000\n\
             maintenance_max_passes = 10000\n",
        )
        .unwrap();
        let m = cfg.leases.maintenance().unwrap();
        assert_eq!(m.interval, std::time::Duration::from_secs(1));
        assert_eq!((m.batch_rows, m.max_passes), (100_000, 10_000));
        let cfg = super::Config::from_toml(
            "[leases]\nmaintenance_batch_rows = 1\nmaintenance_max_passes = 1\n",
        )
        .unwrap();
        assert_eq!(
            (
                cfg.leases.maintenance().unwrap().batch_rows,
                cfg.leases.maintenance().unwrap().max_passes
            ),
            (1, 1)
        );

        for (line, expect) in [
            (
                "maintenance_interval_seconds = 0",
                "[leases] maintenance_interval_seconds must be at least 1",
            ),
            (
                "maintenance_batch_rows = 0",
                "[leases] maintenance_batch_rows must be between 1 and 100000, not 0",
            ),
            (
                "maintenance_batch_rows = 100001",
                "[leases] maintenance_batch_rows must be between 1 and 100000, not 100001",
            ),
            (
                "maintenance_max_passes = 0",
                "[leases] maintenance_max_passes must be between 1 and 10000, not 0",
            ),
            (
                "maintenance_max_passes = 10001",
                "[leases] maintenance_max_passes must be between 1 and 10000, not 10001",
            ),
        ] {
            let cfg = super::Config::from_toml(&format!("[leases]\n{line}\n")).unwrap();
            let err = cfg.leases.maintenance().unwrap_err().to_string();
            assert_eq!(err, expect);
        }
        // Negative figures do not parse.
        assert!(super::Config::from_toml("[leases]\nmaintenance_batch_rows = -1\n").is_err());
    }

    use super::*;

    /// The `[limits]` defaults: a cap, the three deadlines, and every rate limit off.
    /// `prune = "auto"`: what it needs (everything `"manual"` needs, and `keep_seconds`), the
    /// bounds of its two keys, and that the two keys refuse to start with another mode.
    #[test]
    fn audit_retention_auto_startup_checks() {
        let auto = |extra: &str| {
            Config::from_toml(&format!(
                "[audit]\nsqlite_path = \"/var/lib/attenuo/a.sqlite\"\n\
                 [audit.sink]\nkind = \"file\"\npath = \"/mnt/s/c.jsonl\"\n\
                 [audit.retention]\nprune = \"auto\"\n{extra}"
            ))
            .unwrap()
        };
        let refused = |c: Config, needle: &str| {
            let e = c.check_retention().unwrap_err().to_string();
            assert!(e.contains(needle), "{needle}: {e}");
        };
        let c = auto("keep_seconds = 7776000\n");
        c.check_retention().unwrap();
        let r = &c.audit.retention;
        assert_eq!(r.prune, PruneMode::Auto);
        assert!(r.allows_prune());
        assert_eq!(r.keep(), Some(time::Duration::days(90)));
        assert_eq!(r.interval(), std::time::Duration::from_secs(3600));
        // keep_seconds is required.
        refused(auto(""), "needs keep_seconds");
        // At least min_age_seconds, and at least a day.
        refused(auto("keep_seconds = 7775999\n"), "at least min_age_seconds");
        let mut c = auto("keep_seconds = 86399\n");
        c.audit.retention.min_age_seconds = 1;
        c.leases.retention_seconds = 1;
        c.leases.run_state_retention_seconds = 0;
        c.leases.user_window_retention_seconds = 0;
        refused(c.clone(), "at least a day");
        c.audit.retention.keep_seconds = Some(86_400);
        c.check_retention().unwrap();
        refused(
            auto("keep_seconds = 3153600001\nmin_age_seconds = 7776000\n"),
            "at most 3153600000",
        );
        // The interval: 1 to a day.
        auto("keep_seconds = 7776000\ninterval_seconds = 1\n")
            .check_retention()
            .unwrap();
        refused(
            auto("keep_seconds = 7776000\ninterval_seconds = 0\n"),
            "interval_seconds must be between 1 and 86400",
        );
        refused(
            auto("keep_seconds = 7776000\ninterval_seconds = 86401\n"),
            "interval_seconds must be between 1 and 86400",
        );
        // Everything "manual" refuses, "auto" refuses too.
        let mut c = auto("keep_seconds = 7776000\n");
        c.audit.sink = None;
        refused(c, "needs [audit.sink]");
        let mut c = auto("keep_seconds = 7776000\n");
        c.audit.sqlite_path = ":memory:".into();
        refused(c, ":memory:");
        // The two keys with another mode refuse to start, so a typo in `prune` is not a
        // silent "never pruned".
        for mode in ["off", "manual"] {
            for key in [
                "keep_seconds = 7776000",
                "interval_seconds = 60",
                "archive_dir = \"/tmp\"",
                "max_entries_per_run = 10",
            ] {
                let c = Config::from_toml(&format!(
                    "[audit]\nsqlite_path = \"/var/lib/attenuo/a.sqlite\"\n\
                     [audit.sink]\nkind = \"file\"\npath = \"/mnt/s/c.jsonl\"\n\
                     [audit.retention]\nprune = \"{mode}\"\n{key}\n"
                ))
                .unwrap();
                refused(c, "is only for prune = \"auto\"");
            }
        }
        // Not "auto": no keep window.
        assert_eq!(RetentionSection::default().keep(), None);
        // max_entries_per_run: at least 1, default a million.
        assert_eq!(
            auto("keep_seconds = 7776000\n")
                .audit
                .retention
                .max_entries_per_run(),
            DEFAULT_AUTO_MAX_ENTRIES_PER_RUN
        );
        refused(
            auto("keep_seconds = 7776000\nmax_entries_per_run = 0\n"),
            "max_entries_per_run must be at least 1",
        );
        // archive_dir: an existing, writable directory; the probe file is gone after.
        let dir = tempfile::tempdir().unwrap();
        let with_dir = |p: &std::path::Path| {
            let mut c = auto("keep_seconds = 7776000\n");
            c.audit.retention.archive_dir = Some(p.to_path_buf());
            c
        };
        with_dir(dir.path()).check_retention().unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        refused(with_dir(&dir.path().join("missing")), "cannot be used");
        let file = dir.path().join("a-file");
        std::fs::write(&file, "x").unwrap();
        refused(with_dir(&file), "is not a directory");
    }

    /// `prune = "auto"` without `archive_dir` starts, with a warning that the records are
    /// deleted without a copy; with `archive_dir` it does not warn so.
    #[test]
    fn audit_retention_auto_without_archive_dir_warns() {
        #[derive(Clone, Default)]
        struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let logged = |c: &Config| {
            let buf = Buf::default();
            let w = buf.clone();
            let sub = tracing_subscriber::fmt()
                .with_writer(move || w.clone())
                .with_ansi(false)
                .finish();
            tracing::subscriber::with_default(sub, || c.check_retention().unwrap());
            let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
            text
        };
        let mut c = Config::from_toml(
            "[audit]\nsqlite_path = \"/var/lib/attenuo/a.sqlite\"\n\
             [audit.sink]\nkind = \"file\"\npath = \"/mnt/s/c.jsonl\"\n\
             [audit.retention]\nprune = \"auto\"\nkeep_seconds = 7776000\n",
        )
        .unwrap();
        let text = logged(&c);
        assert!(text.contains("WARN"), "{text}");
        assert!(
            text.contains("deletes audit records without keeping a copy"),
            "{text}"
        );
        let dir = tempfile::tempdir().unwrap();
        c.audit.retention.archive_dir = Some(dir.path().to_path_buf());
        let text = logged(&c);
        assert!(!text.contains("without keeping a copy"), "{text}");
    }

    /// `[audit.retention]`: off by default, an unknown mode refused, and the start-up
    /// refusals of a prune setting that cannot work (ADR-0015).
    #[test]
    fn audit_retention_defaults_and_startup_refusals() {
        let cfg = Config::from_toml("").unwrap();
        let r = &cfg.audit.retention;
        assert_eq!(
            (r.prune, r.min_age_seconds, r.batch_rows),
            (PruneMode::Off, 7_776_000, 10_000)
        );
        cfg.check_retention().unwrap();
        let e = Config::from_toml("[audit.retention]\nprune = \"daily\"\n").unwrap_err();
        assert!(
            e.to_string().contains("\"off\", \"manual\" or \"auto\""),
            "{e}"
        );
        // archive_dir is a key of "auto" only.
        let e = Config::from_toml("[audit.retention]\narchive_dir = \"/a\"\n")
            .unwrap()
            .check_retention()
            .unwrap_err();
        assert!(e.to_string().contains("only for prune = \"auto\""), "{e}");
        assert!(Config::from_toml("[audit.retention]\narchive = \"/a\"\n").is_err());

        let manual = |extra: &str| {
            Config::from_toml(&format!(
                "[audit]\nsqlite_path = \"/var/lib/attenuo/a.sqlite\"\n\
                 [audit.sink]\nkind = \"file\"\npath = \"/mnt/s/c.jsonl\"\n\
                 [audit.retention]\nprune = \"manual\"\n{extra}"
            ))
            .unwrap()
        };
        manual("").check_retention().unwrap();
        // In memory: nothing to prune.
        let mut c = manual("");
        c.audit.sqlite_path = ":memory:".into();
        let e = c.check_retention().unwrap_err().to_string();
        assert!(e.contains(":memory:"), "{e}");
        // No sink: the anchor would never leave the host.
        let mut c = manual("");
        c.audit.sink = None;
        let e = c.check_retention().unwrap_err().to_string();
        assert!(e.contains("[audit.sink]"), "{e}");
        // Below the run-state retention: a week of leases plus 30 days of run state.
        let e = manual("min_age_seconds = 3196799\n")
            .check_retention()
            .unwrap_err()
            .to_string();
        assert!(e.contains("3196800"), "{e}");
        manual("min_age_seconds = 3196800\n")
            .check_retention()
            .unwrap();
        // The per-user window retention counts too, and a retention of 0 drops its term.
        let mut c = manual("min_age_seconds = 3196800\n");
        c.leases.user_window_retention_seconds = 4_000_000;
        assert!(c.check_retention().is_err());
        let mut c = manual("min_age_seconds = 3024000\n");
        c.leases.retention_seconds = 0;
        c.check_retention().unwrap();
        // batch_rows is checked whatever prune is.
        let e = Config::from_toml("[audit.retention]\nbatch_rows = 0\n")
            .unwrap()
            .check_retention()
            .unwrap_err()
            .to_string();
        assert!(e.contains("batch_rows"), "{e}");
        // So is a min_age_seconds that would not fit below the clock.
        let e = Config::from_toml("[audit.retention]\nmin_age_seconds = 9223372036854775807\n")
            .unwrap()
            .check_retention()
            .unwrap_err()
            .to_string();
        assert!(e.contains("at most 3153600000"), "{e}");
        let huge = RetentionSection {
            min_age_seconds: u64::MAX,
            ..RetentionSection::default()
        };
        assert_eq!(
            huge.min_age(),
            time::Duration::seconds(i64::try_from(MAX_PRUNE_MIN_AGE_SECONDS).unwrap())
        );
    }

    #[test]
    fn limits_defaults() {
        let l = Config::from_toml("").unwrap().limits;
        assert_eq!(
            (
                l.max_in_flight,
                l.header_read_timeout_seconds,
                l.request_body_timeout_seconds,
                l.request_timeout_seconds,
            ),
            (1_024, 30, 30, 60)
        );
        assert_eq!(
            (
                l.token_requests_per_minute,
                l.token_unauthenticated_requests_per_minute,
                l.mcp_requests_per_minute,
                l.authzen_search_requests_per_minute,
                l.rate_limit_max_keys,
            ),
            (0, 0, 0, 0, 10_000)
        );
        l.check().unwrap();
        // The edges of each range are accepted.
        let edges = Config::from_toml(
            "[limits]\nmax_in_flight = 0\nheader_read_timeout_seconds = 300\n\
             request_body_timeout_seconds = 1\nrequest_timeout_seconds = 3600\n\
             mcp_requests_per_minute = 1000000\nauthzen_search_requests_per_minute = 1000000\n\
             rate_limit_max_keys = 100\n",
        )
        .unwrap();
        edges.limits.check().unwrap();
    }

    /// The section digests an agents reload compares: the example (every section in use)
    /// serializes; a config compares equal to itself; a change in a section names that section
    /// only; the lists that have reloads of their own are left out; a section the file leaves
    /// out compares equal to one written with its defaults.
    #[test]
    fn section_digests_name_the_sections_that_differ() {
        let text = include_str!("../../../config/example.toml");
        let cfg = Config::from_toml(text).unwrap();
        let base = cfg.section_digests().unwrap();
        assert!(base
            .differing(&cfg.clone().section_digests().unwrap())
            .is_empty());
        let mut other = cfg.clone();
        other
            .agents
            .push(AgentConfig::with_secret_sha256("x", "0".repeat(64)));
        other.peps.clear();
        other.admin.operators.clear();
        other.issuer.private_key_pem_path = Some("/elsewhere/issuer.pem".into());
        other.issuer.previous_key_paths = vec!["/elsewhere/old.pem".into()];
        assert!(base.differing(&other.section_digests().unwrap()).is_empty());
        other.server.public_url = Some("https://other.example".into());
        other.root_grants.clear();
        other.admin.token = Some("another".into());
        assert_eq!(
            base.differing(&other.section_digests().unwrap()),
            ["[[root_grants]]", "[admin]", "[server]"]
        );
        let empty = Config::from_toml("").unwrap().section_digests().unwrap();
        let spelled = Config::from_toml("[limits]\n[leases]\n").unwrap();
        assert!(empty
            .differing(&spelled.section_digests().unwrap())
            .is_empty());
    }

    /// A reload's parse names the line of a TOML error and never quotes it.
    #[test]
    fn reparse_does_not_quote_the_file() {
        let text = "[admin]\ntoken = \"a-secret-token-0123456789abcdef\"\n[[agents]\n";
        let err = format!(
            "{:#}",
            Config::reparse(text, std::iter::empty::<(String, String)>()).unwrap_err()
        );
        assert!(err.contains("line 3"), "{err}");
        assert!(!err.contains("a-secret-token"), "{err}");
        let shape = "[admin]\ntoken = \"a-secret-token-0123456789abcdef\"\n[[agents]]\nid = 1\n";
        let err = format!(
            "{:#}",
            Config::reparse(shape, std::iter::empty::<(String, String)>()).unwrap_err()
        );
        assert!(err.contains("line 4"), "{err}");
        assert!(!err.contains("a-secret-token"), "{err}");
    }

    /// A value the deserializer refused is never repeated: not a string of the wrong type, not
    /// an unknown variant, not a string inside a list. The key, the table and the expected type
    /// stay.
    #[test]
    fn toml_error_text_never_repeats_a_value() {
        let parse = |text: &str| {
            format!(
                "{:#}",
                Config::reparse(text, std::iter::empty::<(String, String)>()).unwrap_err()
            )
        };
        for (text, want) in [
            (
                "[limits]\nmax_in_flight = \"s3cret-hunter2-wrong-type\"\n",
                "(line 2, key `max_in_flight` in [limits]): invalid type: string \"…\", expected",
            ),
            (
                "[token]\nactor_auth = \"s3cret-hunter2-variant\"\n",
                "(line 2, key `actor_auth` in [token]): unknown variant `…`, expected one of",
            ),
            (
                "[server]\nlisten = [\"s3cret-hunter2-in-a-list\"]\n",
                "(line 2, key `listen` in [server]): invalid type: sequence",
            ),
            (
                "[server]\nlisten = 's3cret-hunter2-literal'\n",
                "(line 2, key `listen` in [server]):",
            ),
        ] {
            let err = parse(text);
            assert!(err.contains(want), "{want}: {err}");
            assert!(!err.contains("hunter2"), "{err}");
        }
    }

    #[test]
    fn redact_quoted_blanks_each_string() {
        assert_eq!(
            redact_quoted(r#"invalid type: string "a\"b", expected "c" or `d`"#),
            r#"invalid type: string "…", expected "…" or `d`"#
        );
        assert_eq!(redact_quoted("no quotes"), "no quotes");
        assert_eq!(redact_quoted("open \"never closed"), "open \"…");
    }

    /// `SectionDigests` prints its section names, never a digest.
    #[test]
    fn section_digests_debug_names_only() {
        let cfg = Config::from_toml("[admin]\ntoken = \"t-0123456789abcdef0123456789\"\n").unwrap();
        let shown = format!("{:?}", cfg.section_digests().unwrap());
        assert!(shown.contains("admin"), "{shown}");
        assert!(!shown.chars().any(|c| c.is_ascii_digit()), "{shown}");
    }

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../config/example.toml");
        let cfg = Config::from_toml(text).unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1:8080".parse().unwrap());
        // The example spells out the `[limits]` defaults.
        assert_eq!(cfg.limits, LimitsSection::default());
        cfg.limits.check().unwrap();
        assert_eq!(cfg.upstreams.len(), 1);
        assert!(
            cfg.admin.token.is_none(),
            "the example ships no admin token (SR-15)"
        );
        let catalog = cfg.policy.load_catalog().unwrap();
        assert!(catalog.get("github", "read_file").readonly);
        let fetch = catalog.get("web", "fetch");
        assert!(fetch.readonly && fetch.has_outbound());
        assert_eq!(fetch.outbound, vec!["url#host".to_string()]);
        assert!(!cfg.root_grants.is_empty());
        capability_set(&cfg.root_grants[0].capabilities).unwrap();
        assert_eq!(cfg.idps.len(), 1);
        assert_eq!(cfg.idps[0].allowed_algs, DEFAULT_IDP_ALGS);
        assert_eq!(cfg.agents.len(), 2);
        assert!(cfg.token.require_actor_auth);
        assert_eq!(cfg.token.actor_auth, ActorAuth::Either);
        assert!(
            cfg.actor_trust.is_empty(),
            "the [[actor_trust]] examples are commented out"
        );
        assert!(!cfg.dev.allow_root_mint);
    }

    #[test]
    fn demo_configs_parse() {
        for text in [
            include_str!("../../../examples/github-leak-demo/config.toml"),
            include_str!("../../../examples/github-leak-demo/config.docker.toml"),
        ] {
            let cfg = Config::from_toml(text).unwrap();
            assert_eq!(cfg.upstreams[0].name, "github");
            assert!(
                cfg.policy
                    .load_catalog()
                    .unwrap()
                    .get("github", "read_file")
                    .readonly
            );
            capability_set(&cfg.root_grants[0].capabilities).unwrap();
        }
    }

    #[test]
    fn empty_config_takes_defaults() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.audit.sqlite_path, ":memory:");
        assert_eq!(cfg.audit.checkpoint_every, 1000);
        assert_eq!(cfg.audit.checkpoint_interval_seconds, 300);
        assert_eq!(cfg.audit.durability, attenuo_audit::Durability::Normal);
        assert_eq!(cfg.audit.wal_checkpoint_seconds, 5);
        assert_eq!(
            Config::from_toml("[audit]\nwal_checkpoint_seconds = 0\n")
                .unwrap()
                .audit
                .wal_checkpoint_seconds,
            0
        );
        assert_eq!(
            Config::from_toml("[audit]\ndurability = \"full\"\n")
                .unwrap()
                .audit
                .durability,
            attenuo_audit::Durability::Full
        );
        assert!(Config::from_toml("[audit]\ndurability = \"off\"\n").is_err());
        assert!(!cfg.audit.allow_network_filesystem);
        assert!(
            Config::from_toml("[audit]\nallow_network_filesystem = true\n")
                .unwrap()
                .audit
                .allow_network_filesystem
        );
        assert!(Config::from_toml("[audit]\nallow_network_filesystem = \"yes\"\n").is_err());
        assert_eq!(cfg.issuer.default_ttl_seconds, 900);
        assert!(cfg.admin.token.is_none());
        assert!(
            !cfg.dev.allow_root_mint,
            "the dev root mint is off by default"
        );
        assert!(cfg.idps.is_empty() && cfg.agents.is_empty());
        assert!(
            !cfg.authzen.allow_unsigned_chain && cfg.peps.is_empty(),
            "unsigned AuthZEN chains are off by default"
        );
        assert!(cfg.token.require_actor_auth, "actor auth is on by default");
        assert_eq!(cfg.token.actor_auth, ActorAuth::Either);
        assert!(cfg.actor_trust.is_empty());
    }

    /// `[[agents]]` and `[[peps]]` take `jwks` (an inline JWK Set) next to or instead of
    /// `secret_sha256`; `[token]` has the client assertion bounds.
    #[test]
    fn client_keys_and_assertion_settings_parse() {
        let cfg = Config::from_toml(
            r#"
            [token]
            client_assertion_max_lifetime_seconds = 120

            [[agents]]
            id = "coder"
            jwks = '''{"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1",
                       "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}'''

            [[agents]]
            id = "planner"
            secret_sha256 = "00"

            [[peps]]
            id = "gw"
            secret_sha256 = "00"
            jwks = '{"keys": []}'
            "#,
        )
        .unwrap();
        assert!(cfg.agents[0].secret_sha256.is_none());
        assert!(cfg.agents[0].jwks.as_deref().unwrap().contains("Ed25519"));
        assert!(cfg.agents[1].jwks.is_none());
        assert!(cfg.peps[0].secret_sha256.is_some() && cfg.peps[0].jwks.is_some());
        assert_eq!(cfg.token.client_assertion_max_lifetime_seconds, 120);
        assert_eq!(cfg.token.client_assertion_clock_skew_seconds, 60);
        cfg.token.check_client_assertion().unwrap();
        let d = TokenSection::default();
        assert_eq!(
            d.client_assertion_max_lifetime_seconds,
            DEFAULT_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS
        );
        d.check_client_assertion().unwrap();
        for bad in [
            "[token]\nclient_assertion_max_lifetime_seconds = 0\n",
            "[token]\nclient_assertion_max_lifetime_seconds = 3601\n",
            "[token]\nclient_assertion_clock_skew_seconds = 601\n",
        ] {
            let cfg = Config::from_toml(bad).unwrap();
            assert!(cfg.token.check_client_assertion().is_err(), "{bad}");
        }
        // A jwks given as a table instead of JSON text is refused when parsing.
        assert!(Config::from_toml("[[agents]]\nid = \"a\"\njwks = { keys = [] }\n").is_err());
    }

    /// `dpop_future_skew_seconds`: default 10, or the max age when that is smaller; set, from
    /// 0 up to `dpop_max_age_seconds`.
    #[test]
    fn dpop_future_skew_is_bounded_by_the_max_age() {
        let d = TokenSection::default();
        assert_eq!(d.dpop_future_skew(), DEFAULT_DPOP_FUTURE_SKEW_SECONDS);
        d.check_dpop().unwrap();
        // A short max age with no skew set starts, with the skew at the max age.
        let short = Config::from_toml("[token]\ndpop_max_age_seconds = 5\n")
            .unwrap()
            .token;
        short.check_dpop().unwrap();
        assert_eq!(short.dpop_future_skew(), 5);
        let set = Config::from_toml("[token]\ndpop_future_skew_seconds = 0\n")
            .unwrap()
            .token;
        assert_eq!(set.dpop_future_skew(), 0);
        for good in [
            "[token]\ndpop_future_skew_seconds = 0\n",
            "[token]\ndpop_max_age_seconds = 60\ndpop_future_skew_seconds = 60\n",
        ] {
            Config::from_toml(good).unwrap().token.check_dpop().unwrap();
        }
        let bad = "[token]\ndpop_max_age_seconds = 60\ndpop_future_skew_seconds = 61\n";
        let err = Config::from_toml(bad)
            .unwrap()
            .token
            .check_dpop()
            .unwrap_err();
        assert!(
            err.to_string().contains("dpop_future_skew_seconds"),
            "{err}"
        );
    }

    #[test]
    fn actor_trust_and_actor_auth_parse() {
        let cfg = Config::from_toml(
            r#"
            [token]
            actor_auth = "actor_token"

            [[actor_trust]]
            spiffe_trust_domain = "example.org"
            spiffe_bundle_url = "https://spire.example.org:8443"
            audience = "https://attenuo.example.com"
            subject_to_agent = "spiffe_path"

            [[actor_trust]]
            issuer = "https://wl.example.com"
            jwks_url = "https://wl.example.com/jwks"
            audience = "attenuo"
            subject_to_agent = { "wl:coder" = "coder" }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.token.actor_auth, ActorAuth::ActorToken);
        assert_eq!(cfg.actor_trust.len(), 2);
        assert_eq!(
            cfg.actor_trust[0].subject_to_agent,
            SubjectToAgent::SpiffePath
        );
        assert_eq!(cfg.actor_trust[0].allowed_algs, DEFAULT_IDP_ALGS);
        assert_eq!(
            cfg.actor_trust[1].subject_to_agent,
            SubjectToAgent::Map(BTreeMap::from([("wl:coder".into(), "coder".into())]))
        );
        assert!(Config::from_toml(
            "[[actor_trust]]\naudience = \"a\"\nsubject_to_agent = \"path\"\n"
        )
        .is_err());
        assert!(Config::from_toml("[token]\nactor_auth = \"mtls\"\n").is_err());
    }

    #[test]
    fn root_grant_matching_prefers_a_pinned_subject() {
        let grant = |subject: Option<&str>, cap: &str| RootGrant {
            subject: subject.map(Into::into),
            issuer: "idp".into(),
            agent: "planner".into(),
            capabilities: vec![CapSpec::Short(cap.into())],
            attributes: BTreeMap::new(),
            may_act: None,
        };
        let grants = vec![
            grant(None, "github:read_*"),
            grant(Some("alice"), "github:*"),
        ];
        let pick = |sub: &str| RootGrant::find(&grants, "idp", "planner", sub);
        assert_eq!(pick("alice").unwrap().subject.as_deref(), Some("alice"));
        assert_eq!(pick("bob").unwrap().subject, None);
        assert!(RootGrant::find(&grants, "other", "planner", "alice").is_none());
        assert!(RootGrant::find(&grants, "idp", "coder", "alice").is_none());
    }

    #[test]
    fn root_grant_may_act_is_a_ceiling() {
        let m = |v: &[&str]| MayAct::new(v.iter().copied());
        let ceiling = vec!["coder".to_string(), "reviewer".to_string()];
        assert_eq!(resolve_may_act(None, None).unwrap(), None);
        assert_eq!(
            resolve_may_act(None, Some(m(&["x"]))).unwrap(),
            Some(m(&["x"]))
        );
        assert_eq!(
            resolve_may_act(Some(&ceiling), None).unwrap(),
            Some(m(&["coder", "reviewer"]))
        );
        assert_eq!(
            resolve_may_act(Some(&ceiling), Some(m(&["coder"]))).unwrap(),
            Some(m(&["coder"]))
        );
        assert!(resolve_may_act(Some(&ceiling), Some(m(&["coder", "sneaky"]))).is_err());
        let g: RootGrant = toml::from_str(
            "issuer = \"i\"\nagent = \"a\"\ncapabilities = [\"*:*\"]\nmay_act = [\"coder\"]\n",
        )
        .unwrap();
        assert_eq!(g.may_act_for(None).unwrap(), Some(m(&["coder"])));
    }

    #[test]
    fn unknown_tools_defaults_to_deny_and_parses() {
        assert_eq!(
            Config::from_toml("").unwrap().policy.unknown_tools,
            UnknownTools::Deny
        );
        for (text, want) in [
            ("deny", UnknownTools::Deny),
            ("sensitive", UnknownTools::Sensitive),
            ("allow", UnknownTools::Allow),
        ] {
            let cfg =
                Config::from_toml(&format!("[policy]\nunknown_tools = \"{text}\"\n")).unwrap();
            assert_eq!(cfg.policy.unknown_tools, want);
        }
        assert!(Config::from_toml("[policy]\nunknown_tools = \"maybe\"\n").is_err());
    }

    /// SR-13: `/` in a server name makes `Tool::"<server>/<tool>"` ambiguous.
    #[test]
    fn slash_in_server_names_is_rejected() {
        let upstream = "[[upstreams]]\nname = \"evil/x\"\nurl = \"http://127.0.0.1:1/mcp\"\n";
        assert!(Config::from_toml(upstream)
            .unwrap()
            .check_server_names()
            .is_err());
        let catalog = "[policy.catalog.\"a/b\".read_file]\nreadonly = true\n";
        assert!(Config::from_toml(catalog)
            .unwrap()
            .check_server_names()
            .is_err());
        let grant =
            "[[root_grants]]\nissuer = \"i\"\nagent = \"a\"\ncapabilities = [\"a/b:read\"]\n";
        assert!(Config::from_toml(grant)
            .unwrap()
            .check_server_names()
            .is_err());
        let ok = "[[upstreams]]\nname = \"github\"\nurl = \"http://127.0.0.1:1/mcp\"\n\
                  [[root_grants]]\nissuer = \"i\"\nagent = \"a\"\ncapabilities = [\"*:*\"]\n";
        Config::from_toml(ok).unwrap().check_server_names().unwrap();
        assert!(check_server_name("").is_err());
        // Tool names in the catalog and grants follow the same rules: `/` only between
        // segments of an MCP method name.
        let catalog = "[policy.catalog.github.\"/x\"]\nreadonly = true\n";
        assert!(Config::from_toml(catalog)
            .unwrap()
            .check_server_names()
            .is_err());
        let catalog = "[policy.catalog.github.\"resources/read\"]\nreadonly = true\n";
        Config::from_toml(catalog)
            .unwrap()
            .check_server_names()
            .unwrap();
        let grant =
            "[[root_grants]]\nissuer = \"i\"\nagent = \"a\"\ncapabilities = [\"github:a//b\"]\n";
        assert!(Config::from_toml(grant)
            .unwrap()
            .check_server_names()
            .is_err());
    }

    /// SR-13: actions are server-scoped unless the deprecated switch is on.
    #[test]
    fn track_usage_defaults_to_auto_and_takes_true_only() {
        use attenuo_policy::TrackUsage;
        assert_eq!(
            Config::from_toml("").unwrap().policy.track_usage,
            TrackUsage::Auto
        );
        let cfg = Config::from_toml("[policy]\ntrack_usage = true\n").unwrap();
        assert_eq!(cfg.policy.track_usage, TrackUsage::Always);
        let cfg = Config::from_toml("[policy]\ntrack_usage = \"auto\"\n").unwrap();
        assert_eq!(cfg.policy.track_usage, TrackUsage::Auto);
        assert!(Config::from_toml("[policy]\ntrack_usage = false\n").is_err());
    }

    #[test]
    fn import_annotations_defaults_to_never_and_parses() {
        assert_eq!(
            Config::from_toml("").unwrap().policy.import_annotations,
            AnnotationImport::Never
        );
        let cfg = Config::from_toml("[policy]\nimport_annotations = \"narrowing\"\n").unwrap();
        assert_eq!(cfg.policy.import_annotations, AnnotationImport::Narrowing);
        assert!(Config::from_toml("[policy]\nimport_annotations = \"always\"\n").is_err());
        // Catalog entries take `destructive` and `output` next to `readonly` and `sensitive`.
        let cfg = Config::from_toml(
            "[policy.catalog.bank.get_balance]\nreadonly = true\noutput = \"trusted\"\n\
             [policy.catalog.cal.create_event]\ndestructive = false\n",
        )
        .unwrap();
        let catalog = cfg.policy.load_catalog().unwrap();
        assert_eq!(
            catalog.get("bank", "get_balance").output,
            attenuo_policy::OutputLabel::Trusted
        );
        assert!(!catalog.get("cal", "create_event").is_destructive());
        assert!(Config::from_toml("[policy.catalog.a.b]\noutput = \"maybe\"\n").is_err());
    }

    #[test]
    fn legacy_bare_actions_defaults_to_off() {
        assert!(!Config::from_toml("").unwrap().policy.legacy_bare_actions);
        assert!(
            Config::from_toml("[policy]\nlegacy_bare_actions = true\n")
                .unwrap()
                .policy
                .legacy_bare_actions
        );
    }

    /// SR-15: weak, placeholder or missing admin tokens are refused off loopback.
    #[test]
    fn admin_token_is_checked_outside_loopback() {
        let strong = "0123456789abcdef0123456789abcdef";
        let with = |listen: &str, token: Option<&str>| {
            let mut cfg = Config::default();
            cfg.server.listen = listen.parse().unwrap();
            cfg.admin.token = token.map(Into::into);
            cfg.check_admin_token()
        };
        for token in [
            None,
            Some("short"),
            Some("dev-admin-token-change-me"),
            Some("demo-admin-token"),
        ] {
            assert!(with("0.0.0.0:8080", token).is_err(), "{token:?}");
            assert!(with("10.1.2.3:8080", token).is_err(), "{token:?}");
            // Loopback only warns.
            assert!(with("127.0.0.1:8080", token).is_ok(), "{token:?}");
            assert!(with("[::1]:8080", token).is_ok(), "{token:?}");
        }
        assert!(with("0.0.0.0:8080", Some(strong)).is_ok());
        let err = with("0.0.0.0:8080", Some("x")).unwrap_err().to_string();
        assert!(err.contains("openssl rand -hex 32"), "{err}");
        // The demo configs: loopback with a placeholder is fine, the docker variant (all
        // interfaces) has no token in the file and needs ATTENUO_ADMIN_TOKEN.
        let demo = Config::from_toml(include_str!(
            "../../../examples/github-leak-demo/config.toml"
        ))
        .unwrap();
        demo.check_admin_token().unwrap();
        let docker = Config::from_toml(include_str!(
            "../../../examples/github-leak-demo/config.docker.toml"
        ))
        .unwrap();
        assert!(docker.check_admin_token().is_err());
    }

    /// ADR-0016: `[[admin.operators]]` parse, and startup refuses bad names, duplicate names,
    /// malformed digests, two operators with one digest and an operator with the digest of
    /// `[admin] token`.
    #[test]
    fn admin_operators_are_checked() {
        use crate::operators::{token_sha256_hex, AdminRole};
        let a = token_sha256_hex("alice-token");
        let b = token_sha256_hex("bob-token");
        let cfg = Config::from_toml(&format!(
            "[admin]\ntoken = \"legacy-token-0123456789abcdef01234\"\n\
             [[admin.operators]]\nname = \"alice\"\ntoken_sha256 = \"{a}\"\nrole = \"viewer\"\n\
             [[admin.operators]]\nname = \"bob\"\ntoken_sha256 = \"{b}\"\nrole = \"operator\"\n"
        ))
        .unwrap();
        assert_eq!(cfg.admin.operators.len(), 2);
        assert_eq!(cfg.admin.operators[1].role, AdminRole::Operator);
        cfg.check_admin_operators().unwrap();
        // An unknown role or key does not parse.
        for bad in [
            format!("[[admin.operators]]\nname = \"x\"\ntoken_sha256 = \"{a}\"\nrole = \"root\"\n"),
            format!("[[admin.operators]]\nname = \"x\"\ntoken_sha256 = \"{a}\"\nrole = \"admin\"\ntoken = \"t\"\n"),
            "[[admin.operators]]\nname = \"x\"\nrole = \"admin\"\n".to_string(),
        ] {
            assert!(Config::from_toml(&bad).is_err(), "{bad}");
        }
        let with = |ops: Vec<(&str, String)>, token: Option<&str>| {
            let mut cfg = Config::default();
            cfg.admin.token = token.map(Into::into);
            cfg.admin.operators = ops
                .into_iter()
                .map(|(name, token_sha256)| AdminOperator {
                    name: name.into(),
                    token_sha256,
                    role: AdminRole::Viewer,
                    expires_at: None,
                })
                .collect();
            cfg.check_admin_operators().map_err(|e| e.to_string())
        };
        with(
            vec![("alice", a.clone()), ("bob", b.clone())],
            Some("legacy"),
        )
        .unwrap();
        for (ops, token, want) in [
            (vec![("admin", a.clone())], None, "reserved"),
            (vec![("Alice", a.clone())], None, "a-z"),
            (vec![("", a.clone())], None, "1 to 64"),
            (
                vec![("alice", a.clone()), ("alice", b.clone())],
                None,
                "used twice",
            ),
            (vec![("alice", a.to_uppercase())], None, "lowercase hex"),
            (vec![("alice", a[..10].to_string())], None, "lowercase hex"),
            (
                vec![("alice", a.clone()), ("bob", a.clone())],
                None,
                "same token_sha256",
            ),
            (
                vec![("alice", a.clone())],
                Some("alice-token"),
                "[admin] token",
            ),
        ] {
            let err = with(ops, token).unwrap_err();
            assert!(err.contains(want), "{err}");
            // Neither a digest nor the token is repeated.
            assert!(!err.contains(&a) && !err.contains("alice-token"), "{err}");
        }
    }

    /// ADR-0016: off loopback, operators alone are enough, but a legacy token that is set must
    /// still be strong.
    #[test]
    fn operators_count_as_an_admin_credential_off_loopback() {
        let mut cfg = Config::default();
        cfg.server.listen = "0.0.0.0:8080".parse().unwrap();
        let err = cfg.check_admin_token().unwrap_err().to_string();
        assert!(err.contains("[[admin.operators]]"), "{err}");
        cfg.admin.operators.push(AdminOperator {
            name: "alice".into(),
            token_sha256: crate::operators::token_sha256_hex("t"),
            role: crate::operators::AdminRole::Admin,
            expires_at: None,
        });
        cfg.check_admin_token().unwrap();
        cfg.admin.token = Some("change-me".into());
        assert!(cfg.check_admin_token().is_err());
        cfg.admin.token = Some("0123456789abcdef0123456789abcdef".into());
        cfg.check_admin_token().unwrap();
    }

    #[test]
    fn admin_ui_is_disabled_by_default() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.admin_ui, AdminUiSection::default());
        assert!(!cfg.admin_ui.enabled);
        assert!(!cfg.admin_ui.allow_public);
        assert!(!cfg.admin_ui.allow_write);
        assert_eq!(cfg.admin_ui.listen, "127.0.0.1:9101".parse().unwrap());
        cfg.admin_ui.check_listen().unwrap();
        // An empty section is the same as no section.
        assert_eq!(
            Config::from_toml("[admin_ui]\n").unwrap().admin_ui,
            AdminUiSection::default()
        );
        let cfg = Config::from_toml(
            "[admin_ui]\nenabled = true\nlisten = \"127.0.0.1:9200\"\nallow_write = true\n",
        )
        .unwrap();
        assert!(cfg.admin_ui.enabled && cfg.admin_ui.allow_write);
        assert_eq!(cfg.admin_ui.listen.port(), 9200);
        assert!(Config::from_toml("[admin_ui]\ncors = true\n").is_err());
    }

    #[test]
    fn admin_ui_listener_off_loopback_needs_allow_public() {
        let at = |addr: &str, enabled: bool, allow_public: bool| AdminUiSection {
            enabled,
            listen: addr.parse().unwrap(),
            allow_public,
            allow_write: false,
        };
        for ok in [
            at("127.0.0.1:9101", true, false),
            at("[::1]:9101", true, false),
            at("0.0.0.0:9101", false, false),
            at("0.0.0.0:9101", true, true),
            at("10.0.0.5:9101", true, true),
        ] {
            ok.check_listen().unwrap();
        }
        for bad in ["0.0.0.0:9101", "10.0.0.5:9101", "[::]:9101"] {
            let err = at(bad, true, false).check_listen().unwrap_err().to_string();
            assert!(err.contains("[admin_ui] listen"), "{err}");
            assert!(err.contains("allow_public"), "{err}");
        }
    }

    #[test]
    fn public_admin_ui_needs_a_strong_admin_token() {
        let mut cfg = Config::default();
        cfg.admin.token = Some("short".into());
        cfg.admin_ui.listen = "0.0.0.0:9101".parse().unwrap();
        cfg.admin_ui.allow_public = true;
        // Disabled: the console address does not matter.
        cfg.check_admin_token().unwrap();
        cfg.admin_ui.enabled = true;
        let err = cfg.check_admin_token().unwrap_err().to_string();
        assert!(err.contains("[admin_ui] listen"), "{err}");
        cfg.admin.token = Some("0123456789abcdef0123456789abcdef".into());
        cfg.check_admin_token().unwrap();
    }

    /// SR-19: the loopback `Host` names discovery accepts without `public_url`.
    #[test]
    fn loopback_hosts_sr19() {
        for ok in [
            "localhost",
            "LOCALHOST:8080",
            "127.0.0.1",
            "127.0.0.1:65535",
            "[::1]",
            "[::1]:8080",
        ] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.example",
            "localhost.evil.example",
            "127.0.0.1.evil",
            "127.0.0.2",
            "localhost:",
            "localhost:123456",
            "localhost:8080:1",
            "[::1]:",
            "[::1]x",
            "::1",
            "user@localhost",
        ] {
            assert!(!is_loopback_host(bad), "{bad}");
        }
        // The docker demo listens on all interfaces, so it names its public URL.
        let docker = Config::from_toml(include_str!(
            "../../../examples/github-leak-demo/config.docker.toml"
        ))
        .unwrap();
        docker.server.check_public_url().unwrap();
        assert!(Config::default().server.check_public_url().is_ok());
    }

    /// S-9: an `http://` `public_url` off loopback is refused unless `allow_insecure_http`;
    /// https (TLS at a reverse proxy) and loopback http need no new key.
    #[test]
    fn plain_http_public_url_off_loopback_needs_allow_insecure_http_s9() {
        let at = |url: &str, insecure: bool| ServerSection {
            listen: "0.0.0.0:8080".parse().unwrap(),
            public_url: Some(url.into()),
            allow_insecure_http: insecure,
        };
        for ok in [
            "https://attenuo.example.com",
            "https://10.0.0.5:8443/attenuo",
            "http://127.0.0.1:8080",
            "http://127.1.2.3",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://[::1]:8080/base",
        ] {
            at(ok, false).check_public_url().unwrap();
        }
        for bad in [
            "http://attenuo.example.com",
            "http://10.0.0.5:8080",
            "http://0.0.0.0:8080",
            "http://[::]:8080",
            "http://localhost.example.com",
            "http://127.0.0.1.nip.io",
        ] {
            let err = at(bad, false).check_public_url().unwrap_err().to_string();
            assert!(err.contains("allow_insecure_http"), "{bad}: {err}");
            assert!(err.contains("https://"), "{bad}: {err}");
            at(bad, true).check_public_url().unwrap();
        }
        // The flag does not loosen anything else.
        assert!(at("ftp://a.example", true).check_public_url().is_err());
        let toml = Config::from_toml(
            "[server]\nlisten = \"0.0.0.0:8080\"\npublic_url = \"http://a.example\"\n\
             allow_insecure_http = true\n",
        )
        .unwrap();
        assert!(toml.server.allow_insecure_http);
        toml.server.check_public_url().unwrap();
        assert!(!Config::default().server.allow_insecure_http);
    }

    #[test]
    fn url_host_is_loopback_parses_the_host() {
        for yes in [
            "http://localhost",
            "http://127.0.0.1:1/x",
            "http://127.255.0.1",
            "http://[::1]",
            "https://localhost:8443",
        ] {
            assert!(url_host_is_loopback(yes), "{yes}");
        }
        for no in [
            "http://user@example.com",
            "http://localhost@example.com",
            "http://example.com/127.0.0.1",
            "http://[::2]",
            "http://10.0.0.1",
            "not a url",
            "http://",
        ] {
            assert!(!url_host_is_loopback(no), "{no}");
        }
    }

    /// S-1: off a loopback `[server] listen`, the admin API needs a listener of its own or the
    /// explicit `serve_on_main_listener`; on loopback nothing changes. The two keys exclude each
    /// other, and the admin listener cannot be the main one.
    #[test]
    fn admin_api_off_loopback_needs_its_own_listener_or_the_opt_in_s1() {
        let addr = |a: &str| a.parse::<SocketAddr>().unwrap();
        let admin = |listen: Option<&str>, on_main: bool| AdminSection {
            token: None,
            listen: listen.map(addr),
            serve_on_main_listener: on_main,
            operators: Vec::new(),
        };
        // Loopback, nothing configured: on the main listener, as before.
        for main in ["127.0.0.1:8080", "[::1]:8080"] {
            let a = admin(None, false);
            a.check_listen(addr(main)).unwrap();
            assert!(a.on_main_listener());
            assert_eq!(a.api_listen(addr(main)), addr(main));
            admin(None, true).check_listen(addr(main)).unwrap();
        }
        for main in ["0.0.0.0:8080", "10.1.2.3:8080", "[::]:8080"] {
            let err = admin(None, false)
                .check_listen(addr(main))
                .unwrap_err()
                .to_string();
            assert!(err.contains("not a loopback address"), "{err}");
            assert!(err.contains("[admin] listen"), "{err}");
            assert!(err.contains("serve_on_main_listener = true"), "{err}");
            admin(None, true).check_listen(addr(main)).unwrap();
            for own in ["127.0.0.1:9102", "10.0.0.7:9102", "0.0.0.0:9102"] {
                let a = admin(Some(own), false);
                a.check_listen(addr(main)).unwrap();
                assert!(!a.on_main_listener());
                assert_eq!(a.api_listen(addr(main)), addr(own));
                let err = admin(Some(own), true)
                    .check_listen(addr(main))
                    .unwrap_err()
                    .to_string();
                assert!(err.contains("contradict"), "{err}");
            }
        }
        let err = admin(Some("127.0.0.1:8080"), false)
            .check_listen(addr("127.0.0.1:8080"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("port of its own"), "{err}");
        // Port 0 (tests): two different ports once bound.
        admin(Some("127.0.0.1:0"), false)
            .check_listen(addr("127.0.0.1:0"))
            .unwrap();
        // From TOML: absent by default, both keys read.
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.admin.listen, None);
        assert!(!cfg.admin.serve_on_main_listener);
        let cfg = Config::from_toml(
            "[server]\nlisten = \"0.0.0.0:8080\"\n\n[admin]\nlisten = \"127.0.0.1:9102\"\n",
        )
        .unwrap();
        assert_eq!(cfg.admin.listen, Some(addr("127.0.0.1:9102")));
        cfg.admin.check_listen(cfg.server.listen).unwrap();
        let cfg = Config::from_toml(
            "[server]\nlisten = \"0.0.0.0:8080\"\n\n[admin]\nserve_on_main_listener = true\n",
        )
        .unwrap();
        cfg.admin.check_listen(cfg.server.listen).unwrap();
        // Every shipped config still starts: the loopback ones as they are, the docker demo
        // through the opt-in (its port is published on the host's loopback only).
        for text in [
            include_str!("../../../examples/github-leak-demo/config.toml"),
            include_str!("../../../examples/multi-hop-demo/config.toml"),
            include_str!("../../../examples/github-leak-demo/config.docker.toml"),
            include_str!("../../../config/example.toml"),
        ] {
            let cfg = Config::from_toml(text).unwrap();
            cfg.admin.check_listen(cfg.server.listen).unwrap();
        }
    }

    /// SR-15 with S-1: an `[admin] listen` off loopback is exposure, as `[server] listen` is.
    #[test]
    fn an_admin_listener_off_loopback_needs_a_strong_admin_token() {
        let mut cfg = Config::default();
        cfg.admin.token = Some("short".into());
        cfg.admin.listen = Some("127.0.0.1:9102".parse().unwrap());
        cfg.check_admin_token().unwrap();
        cfg.admin.listen = Some("0.0.0.0:9102".parse().unwrap());
        let err = cfg.check_admin_token().unwrap_err().to_string();
        assert!(err.contains("[admin] listen = 0.0.0.0:9102"), "{err}");
        cfg.admin.token = Some("0123456789abcdef0123456789abcdef".into());
        cfg.check_admin_token().unwrap();
    }

    /// S-3: the dev root mint is refused when `[server] listen` is not loopback, unless the
    /// demo-only `allow_root_mint_off_loopback` is set.
    #[test]
    fn dev_root_mint_is_refused_off_loopback_s3() {
        let dev = |mint: bool, off: bool| DevSection {
            allow_root_mint: mint,
            allow_root_mint_off_loopback: off,
        };
        let addr = |a: &str| a.parse::<SocketAddr>().unwrap();
        for listen in ["0.0.0.0:8080", "10.1.2.3:8080", "[::]:8080"] {
            let err = dev(true, false)
                .check(addr(listen))
                .unwrap_err()
                .to_string();
            assert!(err.contains("not a loopback address"), "{err}");
            assert!(err.contains("allow_root_mint_off_loopback"), "{err}");
            dev(true, true).check(addr(listen)).unwrap();
            dev(false, false).check(addr(listen)).unwrap();
            dev(false, true).check(addr(listen)).unwrap();
        }
        for listen in ["127.0.0.1:8080", "[::1]:8080"] {
            dev(true, false).check(addr(listen)).unwrap();
        }
        // Through the whole config: the same refusal, from TOML.
        let mut cfg = Config::from_toml(
            "[server]\nlisten = \"0.0.0.0:8080\"\n\n[dev]\nallow_root_mint = true\n",
        )
        .unwrap();
        assert!(cfg.dev.check(cfg.server.listen).is_err());
        cfg.server.listen = addr("127.0.0.1:8080");
        cfg.dev.check(cfg.server.listen).unwrap();
        // Every shipped config that turns the mint on still loads: the loopback demos as they
        // are, the docker variant through the demo-only opt-in.
        for text in [
            include_str!("../../../examples/github-leak-demo/config.toml"),
            include_str!("../../../examples/multi-hop-demo/config.toml"),
            include_str!("../../../examples/github-leak-demo/config.docker.toml"),
            include_str!("../../../config/example.toml"),
        ] {
            let cfg = Config::from_toml(text).unwrap();
            cfg.dev.check(cfg.server.listen).unwrap();
            cfg.server.check_public_url().unwrap();
        }
        let docker = Config::from_toml(include_str!(
            "../../../examples/github-leak-demo/config.docker.toml"
        ))
        .unwrap();
        assert!(docker.dev.allow_root_mint && docker.dev.allow_root_mint_off_loopback);
        assert!(!docker.server.listen.ip().is_loopback());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml("[server]\nlisten = \"127.0.0.1:1\"\nlsten = 1\n").is_err());
    }

    /// Nested tables refuse unknown keys too, and the error names the key. Each of these
    /// would otherwise fail open: the tool would not be sensitive, the grant unconstrained.
    #[test]
    fn unknown_keys_in_nested_tables_are_rejected() {
        let refused = |text: &str, key: &str| {
            let err = Config::from_toml(text).unwrap_err().to_string();
            assert!(err.contains(&format!("unknown field `{key}`")), "{err}");
        };
        refused(
            "[policy.catalog.github.delete_repo]\nsensitve = true\n",
            "sensitve",
        );
        refused(
            "[[upstreams]]\nname = \"github\"\nurl = \"http://127.0.0.1:1/mcp\"\ntimeout = 5\n",
            "timeout",
        );
        refused(
            "[[root_grants]]\nissuer = \"i\"\nagent = \"a\"\n\
             capabilities = [{ server = \"github\", tool = \"create_issue\", \
             constraint = { repo = { op = \"prefix\", value = \"acme/\" } } }]\n",
            "constraint",
        );
        // The correctly spelt forms still load, string and table alike.
        let cfg = Config::from_toml(
            "[policy.catalog.github.delete_repo]\nsensitive = true\n\
             [[upstreams]]\nname = \"github\"\nurl = \"http://127.0.0.1:1/mcp\"\n\
             [[root_grants]]\nissuer = \"i\"\nagent = \"a\"\n\
             capabilities = [\"github:*\", { server = \"github\", tool = \"create_issue\", \
             constraints = { repo = { op = \"prefix\", value = \"acme/\" } }, \
             limits = { calls = 3 } }]\n",
        )
        .unwrap();
        let caps = capability_set(&cfg.root_grants[0].capabilities).unwrap();
        assert_eq!(caps.len(), 2);
        let full = cfg.root_grants[0].capabilities[1].to_capability().unwrap();
        assert_eq!(full.constraints.len(), 1);
        assert_eq!(full.limits.calls, Some(3));
        assert!(
            cfg.policy
                .load_catalog()
                .unwrap()
                .get("github", "delete_repo")
                .sensitive
        );
    }

    /// The JSON catalog at `catalog_path` is read through the same strict `ToolAttrs`.
    #[test]
    fn unknown_keys_in_catalog_path_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        std::fs::write(&path, r#"{"github": {"delete_repo": {"sensitve": true}}}"#).unwrap();
        let mut policy = Config::default().policy;
        policy.catalog_path = Some(path.clone());
        let err = policy.load_catalog().unwrap_err().to_string();
        assert!(err.contains("unknown field `sensitve`"), "{err}");
        std::fs::write(&path, r#"{"github": {"delete_repo": {"sensitive": true}}}"#).unwrap();
        assert!(
            policy
                .load_catalog()
                .unwrap()
                .get("github", "delete_repo")
                .sensitive
        );
    }

    #[test]
    fn cap_spec_forms() {
        let short: CapSpec = serde_json::from_value(serde_json::json!("github:read_*")).unwrap();
        assert_eq!(
            short.to_capability().unwrap(),
            Capability::new("github", "read_*")
        );
        let full: CapSpec = serde_json::from_value(serde_json::json!({
            "server": "github", "tool": "create_issue",
            "constraints": {"repo": {"op": "prefix", "value": "acme/"}}
        }))
        .unwrap();
        assert_eq!(full.to_capability().unwrap().constraints.len(), 1);
        // The table form is strict in JSON as in TOML.
        let err = serde_json::from_value::<CapSpec>(serde_json::json!({
            "server": "github", "tool": "create_issue",
            "constraint": {"repo": {"op": "prefix", "value": "acme/"}}
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown field `constraint`"), "{err}");
        assert!(CapSpec::Short("nocolon".into()).to_capability().is_err());
        assert!(CapSpec::Short(":x".into()).to_capability().is_err());
    }
}
