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
    /// Development-only allowlist for `POST /admin/root-token`. See [`RootGrant`].
    #[serde(default)]
    pub root_grants: Vec<RootGrant>,
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
    /// How long a hop's lease lives after issuance or renewal (default 300). Revocation takes
    /// effect immediately; this bounds how long a lease the holder stopped renewing (for
    /// example a crashed agent) keeps authorizing calls. Always capped by the token's `exp`.
    #[serde(default = "default_lease_interval")]
    pub lease_interval_seconds: u64,
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
            lease_interval_seconds: default_lease_interval(),
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

/// One `[[root_grants]]` entry: who the dev root-mint endpoint may mint for, and the ceiling
/// of what it may grant.
///
/// When the list is empty, `POST /admin/root-token` mints whatever the admin asks for. When it
/// is non-empty, a request must match an entry on `subject`, `issuer` and `agent`, and the
/// requested capabilities must be covered by the entry's (omitting them takes the entry's).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootGrant {
    pub subject: String,
    pub issuer: String,
    pub agent: String,
    pub capabilities: Vec<CapSpec>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
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
    }

    #[test]
    fn empty_config_takes_defaults() {
        let cfg = Config::from_toml("").unwrap();
        assert_eq!(cfg.audit.sqlite_path, ":memory:");
        assert_eq!(cfg.issuer.default_ttl_seconds, 900);
        assert!(cfg.admin.token.is_none());
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
