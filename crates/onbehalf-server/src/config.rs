//! Server configuration, read from a TOML file.
//!
//! The file path comes from `--config` or, if that is absent, the `ONBEHALF_CONFIG`
//! environment variable. See `config/example.toml` for an annotated example. Relative paths in
//! the file are resolved against the current working directory.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use onbehalf_core::{Capability, CapabilitySet};
use onbehalf_policy::{ToolAttrs, ToolCatalog, UnknownTools};
use onbehalf_proxy::UpstreamConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Environment variable that names the config file when `--config` is not given.
pub const CONFIG_ENV: &str = "ONBEHALF_CONFIG";

/// Environment variable that, when set, replaces `[admin] token` (so the secret need not be in
/// the file). The CLI reads the same variable.
pub const ADMIN_TOKEN_ENV: &str = "ONBEHALF_ADMIN_TOKEN";

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
    #[serde(default)]
    pub authzen: AuthzenSection,
    #[serde(default)]
    pub token: TokenSection,
    /// Policy enforcement points allowed to send unsigned chains to the AuthZEN endpoint when
    /// `[authzen] allow_unsigned_chain = true`. Same shape as `[[agents]]`.
    #[serde(default)]
    pub peps: Vec<PepConfig>,
}

/// `[authzen]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthzenSection {
    /// Accept `subject.properties.chain` from the request body when there is no bearer token.
    /// Default `false`: `POST /access/v1/evaluation` requires `Authorization: Bearer <onbehalf
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
}

impl Default for AuthzenSection {
    fn default() -> Self {
        Self {
            allow_unsigned_chain: false,
            max_batch: default_max_batch(),
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
}

impl Default for TokenSection {
    fn default() -> Self {
        Self {
            require_actor_auth: true,
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
    /// Externally visible base URL (e.g. `https://onbehalf.example.com`), used in discovery
    /// documents. When absent, the request's `Host` header is used with `http://`.
    #[serde(default)]
    pub public_url: Option<String>,
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
    "onbehalf".into()
}
fn default_max_depth() -> usize {
    onbehalf_core::chain::DEFAULT_MAX_DEPTH
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
}

impl Default for AuditSection {
    fn default() -> Self {
        Self {
            sqlite_path: default_sqlite_path(),
            checkpoint_every: default_checkpoint_every(),
            checkpoint_interval_seconds: default_checkpoint_interval_seconds(),
        }
    }
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
}

impl Default for MetricsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics_listen(),
        }
    }
}

fn default_metrics_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9100))
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
    /// `aud` an OIDC ID token must carry: the client id onbehalf (or the agent platform) is
    /// registered under at the IdP. Not used for ID-JAG, whose `aud` must be `[issuer] issuer`.
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

/// A server name used in `[[upstreams]]`, the catalog or capabilities must not be empty or
/// contain `/`: the Cedar resource id is `"<server>/<tool>"`, which would be ambiguous (SR-13).
/// `onbehalf` is reserved for the server's own audit records (SR-34).
pub fn check_server_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("server name must not be empty".into());
    }
    if name.contains('/') {
        return Err(format!("server name `{name}` must not contain `/`"));
    }
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
    /// Reject server names that contain `/`, are empty or are the reserved `onbehalf` in
    /// `[[upstreams]]`, the tool catalog (inline and `catalog_path`) and `[[root_grants]]`
    /// capabilities.
    pub fn check_server_names(&self) -> anyhow::Result<()> {
        for u in &self.upstreams {
            check_server_name(&u.name).map_err(|e| anyhow::anyhow!("[[upstreams]]: {e}"))?;
        }
        for ((server, _), _) in self.policy.load_catalog()?.iter() {
            check_server_name(server).map_err(|e| anyhow::anyhow!("[policy] catalog: {e}"))?;
        }
        for g in &self.root_grants {
            for cap in capability_set(&g.capabilities)
                .map_err(|e| anyhow::anyhow!(e))?
                .iter()
            {
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
    /// it is a warning (SR-15).
    pub fn check_admin_token(&self) -> anyhow::Result<()> {
        let Some(problem) = self.admin_token_problem() else {
            return Ok(());
        };
        if self.server.listen.ip().is_loopback() {
            tracing::warn!(
                listen = %self.server.listen,
                "{problem}; accepted because the server only listens on loopback. Generate a \
                 real one with `openssl rand -hex 32` before binding another address."
            );
            return Ok(());
        }
        anyhow::bail!(
            "{problem}, and [server] listen = {} is not loopback. Set a random token of at \
             least {MIN_ADMIN_TOKEN_LEN} bytes (`openssl rand -hex 32`) in [admin] token or \
             {ADMIN_TOKEN_ENV}.",
            self.server.listen
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
    }

    #[test]
    fn root_grant_matching_prefers_a_pinned_subject() {
        let grant = |subject: Option<&str>, cap: &str| RootGrant {
            subject: subject.map(Into::into),
            issuer: "idp".into(),
            agent: "planner".into(),
            capabilities: vec![CapSpec::Short(cap.into())],
            attributes: BTreeMap::new(),
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
        // interfaces) has no token in the file and needs ONBEHALF_ADMIN_TOKEN.
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
