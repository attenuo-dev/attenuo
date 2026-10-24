//! Server configuration, read from a TOML file.
//!
//! The file path comes from `--config` or, if that is absent, the `ATTENUO_CONFIG`
//! environment variable. See `config/example.toml` for an annotated example. Relative paths in
//! the file are resolved against the current working directory.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use attenuo_core::{Capability, CapabilitySet};
use attenuo_policy::{AnnotationImport, ToolAttrs, ToolCatalog, UnknownTools};
use attenuo_proxy::UpstreamConfig;
use attenuo_token::MayAct;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub issuer: IssuerSection,
    #[serde(default)]
    pub policy: PolicySection,
    #[serde(default)]
    pub audit: AuditSection,
    /// MCP servers mounted at `/mcp/{name}`.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
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
    #[serde(default)]
    pub dev: DevSection,
    #[serde(default)]
    pub metrics: MetricsSection,
    /// The opt-in admin console listener. See [`AdminUiSection`].
    #[serde(default)]
    pub admin_ui: AdminUiSection,
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub authzen: AuthzenSection,
    #[serde(default)]
    pub token: TokenSection,
    /// Policy enforcement points allowed to send unsigned chains to the AuthZEN endpoint when
    /// `[authzen] allow_unsigned_chain = true`. Same shape as `[[agents]]`.
    #[serde(default)]
    pub peps: Vec<PepConfig>,
    /// Workload-identity issuers whose JWTs are accepted as RFC 8693 `actor_token` on an
    /// exchange (hop n to n+1). See [`ActorTrustConfig`].
    #[serde(default)]
    pub actor_trust: Vec<ActorTrustConfig>,
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
    /// audited. Must be at least 1.
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
    /// `"secret"` (`[[agents]]` client credentials only), `"actor_token"` (a JWT from an
    /// `[[actor_trust]]` issuer only) or `"either"` (default). With `require_actor_auth = true`
    /// one accepted method is mandatory for an exchange; hop 0 always needs one.
    #[serde(default)]
    pub actor_auth: ActorAuth,
    /// Sender-constrained tokens (DPoP, RFC 9449; SR-24): `"off"`, `"optional"` (default) or
    /// `"required"`. See [`crate::dpop`]. Tokens already bound to a key need a proof whatever
    /// this says.
    #[serde(default)]
    pub dpop: DpopMode,
    /// How far a DPoP proof's `iat` may be from the server's clock, either way, in seconds.
    /// Default 300.
    #[serde(default = "default_dpop_max_age")]
    pub dpop_max_age_seconds: u64,
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
}

/// Default for `[token] dpop_max_age_seconds`.
pub const DEFAULT_DPOP_MAX_AGE_SECONDS: u64 = 300;
/// Default for `[token] dpop_replay_capacity`.
pub const DEFAULT_DPOP_REPLAY_CAPACITY: usize = 1_000_000;

fn default_dpop_max_age() -> u64 {
    DEFAULT_DPOP_MAX_AGE_SECONDS
}

fn default_dpop_replay_capacity() -> usize {
    DEFAULT_DPOP_REPLAY_CAPACITY
}

impl Default for TokenSection {
    fn default() -> Self {
        Self {
            require_actor_auth: true,
            actor_auth: ActorAuth::default(),
            dpop: DpopMode::default(),
            dpop_max_age_seconds: DEFAULT_DPOP_MAX_AGE_SECONDS,
            dpop_replay_capacity: DEFAULT_DPOP_REPLAY_CAPACITY,
            dpop_nonce: DpopNonceMode::default(),
        }
    }
}

impl TokenSection {
    /// Startup check of the DPoP settings.
    pub fn check_dpop(&self) -> anyhow::Result<()> {
        if !(1..=3600).contains(&self.dpop_max_age_seconds) {
            anyhow::bail!("[token] dpop_max_age_seconds must be between 1 and 3600");
        }
        if self.dpop_replay_capacity == 0 {
            anyhow::bail!("[token] dpop_replay_capacity must be at least 1");
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
    /// `[[agents]]` client credentials (HTTP Basic or `client_id` / `client_secret`) only. An
    /// `actor_token` is refused.
    Secret,
    /// An `actor_token` verified against `[[actor_trust]]` only. Client credentials are refused.
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

/// One `[[peps]]` entry: `{ id, secret_sha256 }`, as for [`AgentConfig`].
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
}

impl ServerSection {
    /// Startup check (SR-19): `public_url`, when set, is an absolute `http(s)://` URL with a
    /// host; when unset, `listen` must be a loopback address, because discovery would
    /// otherwise build its URLs from a `Host` header any client can choose.
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

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            public_url: None,
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
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
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
    /// `sensitive` and `inputs = { arg = "string" | "long" | "bool" }`.
    #[serde(default)]
    pub catalog: BTreeMap<String, BTreeMap<String, ToolAttrs>>,
    /// JSON file with the same shape as `catalog`: `{ "<server>": { "<tool>": { ... } } }`.
    /// Merged over the inline catalog.
    #[serde(default)]
    pub catalog_path: Option<PathBuf>,
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
}

impl PolicySection {
    /// The effective catalog: the inline table, then `catalog_path` on top.
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
    /// `[audit.sink]`: ship every signed checkpoint off the host as it is created (SR-21).
    /// Unset by default.
    #[serde(default)]
    pub sink: Option<SinkSection>,
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
    #[serde(default)]
    pub session_token: Option<String>,
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
    pub fn validate(&self) -> anyhow::Result<()> {
        let set = |name: &'static str, present: bool| present.then_some(name);
        let webhook = [
            set("url", self.url.is_some()),
            set("bearer_token", self.bearer_token.is_some()),
        ];
        let file = [set("path", self.path.is_some())];
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
            SinkKind::File => webhook.iter().chain(&s3).flatten().copied().collect(),
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
            sink: None,
        }
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

/// `[admin]`
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSection {
    /// Static bearer token for `/admin/*`. When unset, every admin endpoint answers 403.
    /// v0 only: replace with real operator authentication before exposing the server.
    ///
    /// Outside a loopback `listen` address the server refuses to start when this is missing,
    /// shorter than [`MIN_ADMIN_TOKEN_LEN`] bytes or a known placeholder; on loopback it only
    /// warns. Generate one with `openssl rand -hex 32`, or set [`ADMIN_TOKEN_ENV`].
    #[serde(default)]
    pub token: Option<String>,
}

/// `[dev]`: development-only switches. Everything here defaults to off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevSection {
    /// Mount `POST /admin/root-token`, which mints hop-0 tokens for a user nobody verified.
    /// Default `false`; when `true` the server logs a warning at startup.
    #[serde(default)]
    pub allow_root_mint: bool,
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
    /// Mount the routes that change state (`POST /admin/leases/{id}/revoke` and
    /// `POST /admin/policies/reload`) on the console listener. Default `false`, so read-only is
    /// enforced by the server and not only by the page: those paths answer 404 there. The main
    /// listener keeps every admin route whatever this says.
    #[serde(default)]
    pub allow_write: bool,
}

impl AdminUiSection {
    /// Startup check, as for `[metrics]` (SR-38): a console listener off loopback needs
    /// `allow_public = true`, and gets a warning when it has it.
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
    2
}

impl ProxySection {
    /// The re-check interval, or an error when it is zero.
    pub fn stream_recheck(&self) -> anyhow::Result<std::time::Duration> {
        if self.stream_recheck_seconds == 0 {
            anyhow::bail!("[proxy] stream_recheck_seconds must be at least 1");
        }
        Ok(std::time::Duration::from_secs(self.stream_recheck_seconds))
    }

    /// Reject limits of zero, which would refuse every request, body or session.
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

    /// Apply this section to a proxy configuration.
    pub fn apply(&self, config: attenuo_proxy::ProxyConfig) -> attenuo_proxy::ProxyConfig {
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
/// `id` is the `client_id` and becomes the root hop's agent id. `secret_sha256` is the
/// lowercase hex SHA-256 of the client secret (`printf %s "$SECRET" | sha256sum`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    pub secret_sha256: String,
}

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
    pub issuer: String,
    pub agent: String,
    pub capabilities: Vec<CapSpec>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    /// RFC 8693 §4.4 `may_act` of root tokens minted under this grant: the agents allowed to
    /// exchange them. A request may narrow it (its own `may_act` must be a subset), never widen
    /// it. When absent, the request's `may_act` (if any) is used as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<Vec<String>>,
}

impl RootGrant {
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
    pub fn may_act_for(&self, requested: Option<MayAct>) -> Result<Option<MayAct>, String> {
        resolve_may_act(self.may_act.as_deref(), requested)
    }
}

/// `may_act` for a root token: `requested` must be within `ceiling` when both are set.
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
/// or as a full object `{ server, tool, constraints }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CapSpec {
    Short(String),
    Full(Capability),
}

impl CapSpec {
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
pub fn capability_set(specs: &[CapSpec]) -> Result<CapabilitySet, String> {
    specs.iter().map(CapSpec::to_capability).collect()
}

/// A server name used in `[[upstreams]]`, the catalog or capabilities must follow
/// [`attenuo_core::names`] (no `/`: the Cedar resource and action ids are
/// `"<server>/<tool>"`, which would be ambiguous, SR-13). `attenuo` is reserved for the
/// server's own audit records (SR-34).
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

impl Config {
    /// Reject server names that contain `/`, are empty or are the reserved `attenuo` in
    /// `[[upstreams]]`, the tool catalog (inline and `catalog_path`) and `[[root_grants]]`
    /// capabilities, and the agent id `attenuo` in `[[agents]]`, `[[peps]]` and
    /// `[[root_grants]]` (SR-34).
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
        // An agent called `attenuo` would put its own name next to the server's in audit
        // records (`agents` beside `server = "attenuo"`); refuse it with the server names.
        let reserved_agent = |section: &str, id: &str| {
            if id == crate::routes::AUDIT_SERVER {
                anyhow::bail!(
                    "{section}: agent id `{id}` is reserved for the server's own records"
                );
            }
            Ok(())
        };
        for a in &self.agents {
            reserved_agent("[[agents]]", &a.id)?;
        }
        for p in &self.peps {
            reserved_agent("[[peps]]", &p.id)?;
        }
        for g in &self.root_grants {
            reserved_agent("[[root_grants]]", &g.agent)?;
            for cap in capability_set(&g.capabilities)
                .map_err(|e| anyhow::anyhow!(e))?
                .iter()
            {
                cap.validate()
                    .map_err(|e| anyhow::anyhow!("[[root_grants]]: {e}"))?;
                if cap.server != "*" {
                    check_server_name(&cap.server)
                        .map_err(|e| anyhow::anyhow!("[[root_grants]]: {e}"))?;
                }
            }
        }
        Ok(())
    }

    /// Problems with `[admin] token`, or `None` when it is acceptable.
    pub fn admin_token_problem(&self) -> Option<String> {
        let token = match self.admin.token.as_deref() {
            None => return Some("[admin] token is not set".into()),
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
    /// it is a warning (SR-15). An enabled `[admin_ui]` listener counts as a listener here,
    /// since it serves the admin API too.
    pub fn check_admin_token(&self) -> anyhow::Result<()> {
        let Some(problem) = self.admin_token_problem() else {
            return Ok(());
        };
        // The console listener serves the admin API too, so it counts as exposure.
        let console = self
            .admin_ui
            .enabled
            .then_some(("[admin_ui] listen", self.admin_ui.listen));
        let exposed = std::iter::once(("[server] listen", self.server.listen))
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
             {ADMIN_TOKEN_ENV}."
        )
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
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// Read and parse a file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        Self::from_toml(&text).map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
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

    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../config/example.toml");
        let cfg = Config::from_toml(text).unwrap();
        assert_eq!(cfg.server.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.upstreams.len(), 1);
        assert!(
            cfg.admin.token.is_none(),
            "the example ships no admin token (SR-15)"
        );
        let catalog = cfg.policy.load_catalog().unwrap();
        assert!(catalog.get("github", "read_file").readonly);
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

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml("[server]\nlisten = \"127.0.0.1:1\"\nlsten = 1\n").is_err());
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
        assert!(CapSpec::Short("nocolon".into()).to_capability().is_err());
        assert!(CapSpec::Short(":x".into()).to_capability().is_err());
    }
}
