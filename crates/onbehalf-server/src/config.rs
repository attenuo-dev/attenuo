//! Server configuration, read from a TOML file.
//!
//! The file path comes from `--config` or, if that is absent, the `ONBEHALF_CONFIG`
//! environment variable. See `config/example.toml` for an annotated example. Relative paths in
//! the file are resolved against the current working directory.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use onbehalf_core::{Capability, CapabilitySet};
use onbehalf_policy::{ToolAttrs, ToolCatalog};
use onbehalf_proxy::UpstreamConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Environment variable that names the config file when `--config` is not given.
pub const CONFIG_ENV: &str = "ONBEHALF_CONFIG";

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
}

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
    /// PKCS#8 Ed25519 private key. Generated (and written with mode 0600) if the file does not
    /// exist. When unset, an ephemeral key is generated at every start.
    #[serde(default)]
    pub private_key_pem_path: Option<PathBuf>,
}

impl Default for IssuerSection {
    fn default() -> Self {
        Self {
            issuer: default_issuer(),
            audience: default_audience(),
            max_depth: default_max_depth(),
            default_ttl_seconds: default_ttl(),
            private_key_pem_path: None,
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
}

impl Default for AuditSection {
    fn default() -> Self {
        Self {
            sqlite_path: default_sqlite_path(),
        }
    }
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

impl Config {
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
        assert!(cfg.admin.token.is_some());
        let catalog = cfg.policy.load_catalog().unwrap();
        assert!(catalog.get("github", "read_file").readonly);
        assert!(!cfg.root_grants.is_empty());
        capability_set(&cfg.root_grants[0].capabilities).unwrap();
        assert_eq!(cfg.idps.len(), 1);
        assert_eq!(cfg.idps[0].allowed_algs, DEFAULT_IDP_ALGS);
        assert_eq!(cfg.agents.len(), 1);
        assert!(!cfg.dev.allow_root_mint);
    }

    #[test]
    fn empty_config_takes_defaults() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.audit.sqlite_path, ":memory:");
        assert_eq!(cfg.issuer.default_ttl_seconds, 900);
        assert!(cfg.admin.token.is_none());
        assert!(
            !cfg.dev.allow_root_mint,
            "the dev root mint is off by default"
        );
        assert!(cfg.idps.is_empty() && cfg.agents.is_empty());
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
