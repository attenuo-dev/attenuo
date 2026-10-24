//! A declarative test harness for policies, the way operators test Cedar or OPA policies in CI.
//!
//! A test file is YAML. Each case describes who is asking (the originating user and the agent
//! chain), what they call, and the decision the policies must produce:
//!
//! ```yaml
//! policies: ./policy.cedar          # optional, relative to this file
//! catalog: ./config.toml            # optional: [policy.catalog] of a server config (or a JSON
//!                                   # catalog file); or an inline map, see below
//! unknown_tools: deny               # optional: deny | sensitive | allow; default is the
//!                                   # config's [policy] unknown_tools, else deny
//! legacy_bare_actions: false        # optional, deprecated: bare `Action::"<tool>"` ids;
//!                                   # default is the config's [policy] value, else false
//! now: 1760000000                   # optional, unix seconds the calls are evaluated at
//! cases:
//!   - name: coder may read public docs
//!     user: { subject: alice, issuer: https://idp.example, attributes: { mfa: true } }
//!     chain: [assistant, coder]     # agent ids, root first
//!     call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
//!     expect: allow                 # or deny
//!     reason: policy_allow          # optional
//!     policy_ids: [read_public]     # optional, compared as a set
//!     session:                      # optional: the run's output labels (ADR-0009)
//!       tainted_by: [web/fetch]     # sources as server/tool; tainted when non-empty
//!       tainted: true               # optional; set it alone for an unreadable taint state
//!       untrusted_args: [body]      # optional: arguments that matched an untrusted result
//!       args_contain_untrusted: true  # optional; defaults to untrusted_args being non-empty
//!     approval: { by: user }        # optional: the call carries a granted approval
//!     budget:                       # optional: what the run limits have left (ADR-0010)
//!       calls_remaining: 1          # each member optional; `limited` defaults to true
//!       amount_remaining: 40
//!       destination_new: false
//!     usage:                        # optional: the run's usage of this tool so far
//!       calls: 1                    # each member optional, default 0 / false
//!       amount: 10
//!       destination_seen: true
//! ```
//!
//! Without `session` the run is untainted, as for a run that has read nothing. Without
//! `approval`, `context.approval.present` is `false`. Without `budget`, no limit applies
//! (`context.budget.limited` is `false`, both remaining figures are Cedar's largest `Long`).
//! The harness keeps no counters: `budget` sets what Cedar sees, it does not enforce limits
//! a hop's capabilities carry. Without `usage`, the run has made no call of the tool
//! (`context.usage` is all zero and false); like `budget`, it sets what Cedar sees and counts
//! nothing.
//!
//! An inline catalog has the same shape as `[policy.catalog]` in the server config:
//!
//! ```yaml
//! catalog:
//!   github:
//!     read_file: { readonly: true, inputs: { repo: string } }
//!     delete_repo: { sensitive: true }
//!     create_event: { destructive: false }   # destructive defaults to !readonly
//!     get_balance: { readonly: true, output: trusted }
//! ```
//!
//! Calls to tools missing from the catalog are handled as the server handles them
//! (`[policy] unknown_tools`, SR-12): by default they are denied with `tool_not_in_catalog`
//! before Cedar runs. When `catalog` names a server config, its `unknown_tools` applies unless
//! the file sets its own.
//!
//! # How the chain is built
//!
//! The cases run through [`PolicyEngine::authorize`](crate::PolicyEngine::authorize), the same
//! code path the server uses, so both the capability stage and the Cedar stage are exercised.
//!
//! - `chain` lists hops root first. A hop is an agent id, or `{ agent, capabilities }` with
//!   capabilities as `server:tool` strings (globs allowed) or full capability objects.
//! - A hop without `capabilities` gets the previous hop's capabilities, and the first hop gets
//!   exactly the call's `server:tool`. So by default the capability stage passes and the case
//!   tests the policies. To test a capability denial, give the hops narrower capabilities.
//! - The finished chain is validated like a received one (attenuation, expiry, depth up to
//!   64), so a case cannot describe a chain the server would never accept. That is reported as
//!   a failed case with the reason.
//! - Time is fixed ([`DEFAULT_NOW_UNIX`] unless `now` is set), every hop lives one hour, the
//!   user authenticated one minute before `now` (override with `authenticated_at_unix`), and
//!   lease ids are random.
//!
//! # Running
//!
//! ```
//! use attenuo_policy::testing::TestFile;
//!
//! let file = TestFile::from_yaml_str(r#"
//! catalog:
//!   github: { read_file: { readonly: true } }
//! cases:
//!   - name: nothing permits it, so deny
//!     chain: [coder]
//!     call: { server: github, tool: read_file }
//!     expect: deny
//!     reason: policy_deny
//! "#).unwrap();
//! let report = file.run().unwrap();
//! assert!(report.all_passed());
//! ```
//!
//! # Unexercised policies
//!
//! A policy is *exercised* when it is among the determining policies (Cedar's
//! `diagnostics().reason()`, reported as `policy_ids`) of at least one evaluated case, passing
//! or not: a `permit` that allowed a call, or a `forbid` that denied one. [`TestReport::policies`]
//! lists every policy of the file's `policies` with the line it starts on, and [`coverage`]
//! folds several reports into the policies no case exercised. A `permit` overridden by a
//! `forbid` in every case it matched is not exercised: no decision depended on it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, Hop, LeaseId, OriginatingUser,
    ToolCall,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::{
    ArgLabels, ArgType, CallLabels, Outcome, PolicyEngine, PolicyEngineBuilder, PolicyError,
    SessionLabels, ToolAttrs, ToolCatalog, UnknownTools,
};

/// The evaluation time used when a test file does not set `now`: 2025-10-09T08:53:20Z.
pub const DEFAULT_NOW_UNIX: i64 = 1_760_000_000;

/// Deepest chain a case may describe.
const MAX_CASE_DEPTH: usize = 64;

/// Errors that stop a whole test file from running (as opposed to a case that fails).
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{what} is not valid: {message}")]
    Invalid { what: String, message: String },
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

impl HarnessError {
    fn invalid(what: impl Into<String>, message: impl ToString) -> Self {
        Self::Invalid {
            what: what.into(),
            message: message.to_string(),
        }
    }
}

type CatalogTables = BTreeMap<String, BTreeMap<String, ToolAttrs>>;

fn catalog_from_tables(tables: &CatalogTables) -> ToolCatalog {
    let mut catalog = ToolCatalog::new();
    for (server, tools) in tables {
        for (tool, attrs) in tools {
            catalog.insert(server.clone(), tool.clone(), attrs.clone());
        }
    }
    catalog
}

fn read(path: &Path) -> Result<String, HarnessError> {
    std::fs::read_to_string(path).map_err(|source| HarnessError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Read the tool catalog from a server config: the inline `[policy.catalog.<server>.<tool>]`
/// tables, with `[policy] catalog_path` (a JSON file, relative to the config) merged on top,
/// exactly as `attenuo-server` does. A config with no catalog yields an empty one.
pub fn load_catalog_from_config(path: &Path) -> Result<ToolCatalog, HarnessError> {
    let what = format!("catalog in {}", path.display());
    let doc: toml::Table = read(path)?
        .parse()
        .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e))?;
    let policy = doc.get("policy").and_then(|p| p.as_table());
    let mut tables = CatalogTables::new();
    if let Some(inline) = policy.and_then(|p| p.get("catalog")) {
        tables = inline
            .clone()
            .try_into()
            .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e))?;
    }
    let mut catalog = catalog_from_tables(&tables);
    if let Some(rel) = policy
        .and_then(|p| p.get("catalog_path"))
        .and_then(|p| p.as_str())
    {
        let json_path = path.parent().unwrap_or(Path::new(".")).join(rel);
        let merged = load_catalog_json(&json_path)?;
        for ((server, tool), attrs) in merged.iter() {
            catalog.insert(server.clone(), tool.clone(), attrs.clone());
        }
    }
    Ok(catalog)
}

/// Read `[policy] user_attributes` (`name = "string" | "long" | "bool" | "set<...>"`) from a
/// server config, the extra `originating_user.attributes` the schema should declare. A JSON
/// file or a config without the table yields an empty map.
pub fn load_user_attrs(path: &Path) -> Result<BTreeMap<String, ArgType>, HarnessError> {
    if path.extension().and_then(|e| e.to_str()) == Some("json") {
        return Ok(BTreeMap::new());
    }
    let what = format!("user_attributes in {}", path.display());
    let doc: toml::Table = read(path)?
        .parse()
        .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e))?;
    let Some(decls) = doc
        .get("policy")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("user_attributes"))
    else {
        return Ok(BTreeMap::new());
    };
    let decls: BTreeMap<String, String> = decls
        .clone()
        .try_into()
        .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e))?;
    crate::parse_user_attributes(&decls).map_err(|e| HarnessError::invalid(&what, e))
}

/// Read `[policy] unknown_tools` from a server config; `None` when it is not set.
pub fn load_unknown_tools_from_config(path: &Path) -> Result<Option<UnknownTools>, HarnessError> {
    let what = format!("unknown_tools in {}", path.display());
    let doc: toml::Table = read(path)?
        .parse()
        .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e))?;
    match doc
        .get("policy")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("unknown_tools"))
    {
        None => Ok(None),
        Some(v) => v
            .clone()
            .try_into()
            .map(Some)
            .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e)),
    }
}

/// Read `[policy] legacy_bare_actions` from a server config; `None` when it is not set.
pub fn load_legacy_bare_actions_from_config(path: &Path) -> Result<Option<bool>, HarnessError> {
    if path.extension().and_then(|e| e.to_str()) == Some("json") {
        return Ok(None);
    }
    let what = format!("legacy_bare_actions in {}", path.display());
    let doc: toml::Table = read(path)?
        .parse()
        .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e))?;
    match doc
        .get("policy")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("legacy_bare_actions"))
    {
        None => Ok(None),
        Some(toml::Value::Boolean(b)) => Ok(Some(*b)),
        Some(other) => Err(HarnessError::invalid(
            &what,
            format!("expected a boolean, got {other}"),
        )),
    }
}

/// Read `[policy] schema_path` from a server config, resolved against the config's directory
/// as `catalog_path` is; `None` when it is not set or the path is a JSON catalog.
pub fn load_schema_path_from_config(path: &Path) -> Result<Option<PathBuf>, HarnessError> {
    if path.extension().and_then(|e| e.to_str()) == Some("json") {
        return Ok(None);
    }
    let what = format!("schema_path in {}", path.display());
    let doc: toml::Table = read(path)?
        .parse()
        .map_err(|e: toml::de::Error| HarnessError::invalid(&what, e))?;
    match doc
        .get("policy")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("schema_path"))
    {
        None => Ok(None),
        Some(toml::Value::String(rel)) => {
            Ok(Some(path.parent().unwrap_or(Path::new(".")).join(rel)))
        }
        Some(other) => Err(HarnessError::invalid(
            &what,
            format!("expected a path, got {other}"),
        )),
    }
}

/// Read a JSON catalog file: `{ "<server>": { "<tool>": { "readonly": true, ... } } }`.
pub fn load_catalog_json(path: &Path) -> Result<ToolCatalog, HarnessError> {
    let tables: CatalogTables = serde_json::from_str(&read(path)?)
        .map_err(|e| HarnessError::invalid(format!("catalog {}", path.display()), e))?;
    Ok(catalog_from_tables(&tables))
}

/// Load a catalog from a path by extension: `.json` is a bare catalog, anything else is a
/// server config in TOML.
pub fn load_catalog(path: &Path) -> Result<ToolCatalog, HarnessError> {
    if path.extension().and_then(|e| e.to_str()) == Some("json") {
        load_catalog_json(path)
    } else {
        load_catalog_from_config(path)
    }
}

/// Where the catalog comes from: a path, or an inline map.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
enum CatalogSpec {
    Path(String),
    Inline(CatalogTables),
}

/// The user the agent acts for.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    #[serde(default = "default_subject")]
    pub subject: String,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    /// Unix seconds; default is one minute before `now`.
    #[serde(default)]
    pub authenticated_at_unix: Option<i64>,
}

fn default_subject() -> String {
    "alice".to_string()
}

fn default_issuer() -> String {
    "https://idp.example".to_string()
}

impl Default for UserSpec {
    fn default() -> Self {
        Self {
            subject: default_subject(),
            issuer: default_issuer(),
            attributes: BTreeMap::new(),
            authenticated_at_unix: None,
        }
    }
}

/// A capability in a test file: `server:tool` or a full capability object.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum CapSpec {
    Short(String),
    Full(Capability),
}

impl CapSpec {
    fn to_capability(&self) -> Result<Capability, String> {
        match self {
            CapSpec::Full(c) => Ok(c.clone()),
            CapSpec::Short(s) => s
                .split_once(':')
                .filter(|(a, b)| !a.is_empty() && !b.is_empty())
                .map(|(server, tool)| Capability::new(server, tool))
                .ok_or_else(|| format!("capability `{s}` must look like `server:tool`")),
        }
    }
}

/// One hop: an agent id, or an agent with explicit capabilities.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum HopSpec {
    Agent(String),
    Detailed(HopDetail),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopDetail {
    pub agent: String,
    #[serde(default)]
    pub capabilities: Option<Vec<CapSpec>>,
}

impl HopSpec {
    fn agent(&self) -> &str {
        match self {
            HopSpec::Agent(a) => a,
            HopSpec::Detailed(d) => &d.agent,
        }
    }

    fn capabilities(&self) -> Option<&[CapSpec]> {
        match self {
            HopSpec::Agent(_) => None,
            HopSpec::Detailed(d) => d.capabilities.as_deref(),
        }
    }
}

/// The tool call under test.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSpec {
    pub server: String,
    pub tool: String,
    #[serde(default = "empty_object")]
    pub arguments: Value,
    #[serde(default)]
    pub session_id: Option<String>,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

/// The output labels of the case's delegation run (`context.session`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSpec {
    /// Sources that labelled the run, as `server/tool`.
    #[serde(default)]
    pub tainted_by: Vec<String>,
    /// Defaults to `true` when `tainted_by` is non-empty. `true` with no sources is what the
    /// server evaluates when the run's taint state cannot be read.
    #[serde(default)]
    pub tainted: Option<bool>,
    /// Arguments of the call that matched an untrusted result (`context.untrusted_args`,
    /// output labelling phase 2).
    #[serde(default)]
    pub untrusted_args: Vec<String>,
    /// `context.args_contain_untrusted`. Defaults to whether `untrusted_args` is non-empty;
    /// `true` may be set alone, and it stays `true` whenever an argument is listed.
    #[serde(default)]
    pub args_contain_untrusted: Option<bool>,
}

impl SessionSpec {
    fn labels(&self) -> CallLabels {
        let mut session = SessionLabels::from_sources(self.tainted_by.iter().cloned());
        if let Some(t) = self.tainted {
            session.tainted = t || !session.tainted_by.is_empty();
        }
        let mut args = ArgLabels::from_args(self.untrusted_args.iter().cloned());
        if let Some(c) = self.args_contain_untrusted {
            args.contain_untrusted = c || !args.untrusted.is_empty();
        }
        CallLabels {
            session,
            args,
            ..Default::default()
        }
    }
}

/// A granted approval the case's call carries (`context.approval`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSpec {
    /// `context.approval.by`: `user` or `operator`.
    pub by: String,
}

/// What the run limits matching the case's call have left (`context.budget`). Members left out
/// take the values of a call no limit applies to; `limited` defaults to `true`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSpec {
    #[serde(default)]
    pub limited: Option<bool>,
    #[serde(default)]
    pub calls_remaining: Option<i64>,
    #[serde(default)]
    pub amount_remaining: Option<i64>,
    #[serde(default)]
    pub destination_new: Option<bool>,
}

impl BudgetSpec {
    fn context(&self) -> crate::BudgetContext {
        let d = crate::BudgetContext::default();
        crate::BudgetContext {
            limited: self.limited.unwrap_or(true),
            calls_remaining: self.calls_remaining.unwrap_or(d.calls_remaining),
            amount_remaining: self.amount_remaining.unwrap_or(d.amount_remaining),
            destination_new: self.destination_new.unwrap_or(d.destination_new),
            refusal: None,
        }
    }
}

/// The run's usage of the case's tool before the call (`context.usage`). Members left out are
/// 0 or `false`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageSpec {
    #[serde(default)]
    pub calls: i64,
    #[serde(default)]
    pub amount: i64,
    #[serde(default)]
    pub destination_seen: bool,
}

impl UsageSpec {
    fn context(&self) -> crate::UsageContext {
        crate::UsageContext {
            calls: self.calls,
            amount: self.amount,
            destination_seen: self.destination_seen,
        }
    }
}

/// The decision a case expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Allow,
    Deny,
}

impl Expect {
    fn matches(self, d: &Decision) -> bool {
        matches!(
            (self, d),
            (Expect::Allow, Decision::Allow) | (Expect::Deny, Decision::Deny)
        )
    }
}

impl std::fmt::Display for Expect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Expect::Allow => "allow",
            Expect::Deny => "deny",
        })
    }
}

/// One test case.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    pub name: String,
    #[serde(default)]
    pub user: UserSpec,
    /// Agent ids, root first. Defaults to a single agent called `agent`.
    #[serde(default)]
    pub chain: Vec<HopSpec>,
    pub call: CallSpec,
    pub expect: Expect,
    /// Expected reason code, e.g. `policy_deny` or `capability_denied`.
    #[serde(default)]
    pub reason: Option<String>,
    /// Expected policy ids that determined the decision, compared as a set.
    #[serde(default)]
    pub policy_ids: Option<Vec<String>>,
    /// The run's output labels; untainted when absent.
    #[serde(default)]
    pub session: Option<SessionSpec>,
    /// A granted approval the call carries; none when absent.
    #[serde(default)]
    pub approval: Option<ApprovalSpec>,
    /// What the run limits have left; no limit applies when absent.
    #[serde(default)]
    pub budget: Option<BudgetSpec>,
    /// The run's usage of the tool so far; none when absent.
    #[serde(default)]
    pub usage: Option<UsageSpec>,
}

/// A parsed test file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestFile {
    #[serde(default)]
    policies: Option<String>,
    #[serde(default)]
    catalog: Option<CatalogSpec>,
    #[serde(default)]
    unknown_tools: Option<UnknownTools>,
    #[serde(default)]
    legacy_bare_actions: Option<bool>,
    #[serde(default)]
    now: Option<i64>,
    pub cases: Vec<TestCase>,
    /// Directory relative paths resolve against. Set by [`TestFile::load`].
    #[serde(skip)]
    base_dir: Option<PathBuf>,
    /// Path the file was loaded from, for reports.
    #[serde(skip)]
    source: Option<PathBuf>,
    /// Base schema override, see [`TestFile::with_schema_file`].
    #[serde(skip)]
    schema_file: Option<PathBuf>,
}

impl TestFile {
    /// Parse a test file from YAML. Relative `policies` and `catalog` paths resolve against the
    /// current directory; use [`TestFile::load`] to resolve them against the file.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, HarnessError> {
        let file: TestFile =
            serde_yaml::from_str(yaml).map_err(|e| HarnessError::invalid("test file", e))?;
        file.checked()
    }

    /// Read and parse a test file. Relative paths inside it resolve against its directory.
    pub fn load(path: &Path) -> Result<Self, HarnessError> {
        let text = read(path)?;
        let mut file: TestFile = serde_yaml::from_str(&text)
            .map_err(|e| HarnessError::invalid(path.display().to_string(), e))?;
        file.base_dir = Some(path.parent().unwrap_or(Path::new(".")).to_path_buf());
        file.source = Some(path.to_path_buf());
        file.checked().map_err(|e| match e {
            HarnessError::Invalid { message, .. } => {
                HarnessError::invalid(path.display().to_string(), message)
            }
            other => other,
        })
    }

    fn checked(self) -> Result<Self, HarnessError> {
        if self.cases.is_empty() {
            return Err(HarnessError::invalid("test file", "`cases` is empty"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for case in &self.cases {
            if !seen.insert(case.name.as_str()) {
                return Err(HarnessError::invalid(
                    "test file",
                    format!("duplicate case name `{}`", case.name),
                ));
            }
        }
        Ok(self)
    }

    /// The file this was loaded from, if any.
    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    fn resolve(&self, rel: &str) -> PathBuf {
        match &self.base_dir {
            Some(base) => base.join(rel),
            None => PathBuf::from(rel),
        }
    }

    /// How calls to uncatalogued tools are handled: the file's `unknown_tools`, else the one of
    /// the server config `catalog` names, else deny (the server's default).
    pub fn load_unknown_tools(&self) -> Result<UnknownTools, HarnessError> {
        if let Some(u) = self.unknown_tools {
            return Ok(u);
        }
        match &self.catalog {
            Some(CatalogSpec::Path(p)) if !p.ends_with(".json") => {
                Ok(load_unknown_tools_from_config(&self.resolve(p))?.unwrap_or_default())
            }
            _ => Ok(UnknownTools::default()),
        }
    }

    /// Whether the engine uses the deprecated bare action ids: the file's
    /// `legacy_bare_actions`, else the one of the server config `catalog` names, else `false`.
    pub fn load_legacy_bare_actions(&self) -> Result<bool, HarnessError> {
        if let Some(b) = self.legacy_bare_actions {
            return Ok(b);
        }
        match &self.catalog {
            Some(CatalogSpec::Path(p)) => {
                Ok(load_legacy_bare_actions_from_config(&self.resolve(p))?.unwrap_or(false))
            }
            _ => Ok(false),
        }
    }

    /// The tool catalog the file selects (empty when it names none).
    pub fn load_catalog(&self) -> Result<ToolCatalog, HarnessError> {
        match &self.catalog {
            None => Ok(ToolCatalog::new()),
            Some(CatalogSpec::Inline(tables)) => Ok(catalog_from_tables(tables)),
            Some(CatalogSpec::Path(p)) => load_catalog(&self.resolve(p)),
        }
    }

    /// Build the engine the file describes. With no `policies`, the policy set is empty and
    /// Cedar denies everything.
    pub fn build_engine(&self) -> Result<PolicyEngine, HarnessError> {
        let mut builder = PolicyEngineBuilder::new()
            .with_catalog(self.load_catalog()?)
            .with_unknown_tools(self.load_unknown_tools()?)
            .with_legacy_bare_actions(self.load_legacy_bare_actions()?);
        if let Some(CatalogSpec::Path(p)) = &self.catalog {
            for (name, ty) in load_user_attrs(&self.resolve(p))? {
                builder = builder.with_user_attr(name, ty);
            }
        }
        if let Some(base) = self.load_base_schema()? {
            builder = builder.with_schema_str(&base);
        }
        if let Some(p) = &self.policies {
            builder = builder.with_policies_file(self.resolve(p));
        }
        Ok(builder.build()?)
    }

    /// Replace the base schema with the Cedar schema in `path` (the CLI's `--schema-file`),
    /// whatever the config `catalog` names says.
    pub fn with_schema_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.schema_file = Some(path.into());
        self
    }

    /// The base schema file in force: [`with_schema_file`](Self::with_schema_file), else the
    /// `[policy] schema_path` of the server config `catalog` names (relative to that config),
    /// else none (the built-in [`DEFAULT_SCHEMA`](crate::DEFAULT_SCHEMA)).
    pub fn base_schema_path(&self) -> Result<Option<PathBuf>, HarnessError> {
        if let Some(p) = &self.schema_file {
            return Ok(Some(p.clone()));
        }
        match &self.catalog {
            Some(CatalogSpec::Path(p)) => load_schema_path_from_config(&self.resolve(p)),
            _ => Ok(None),
        }
    }

    /// The text of [`base_schema_path`](Self::base_schema_path), if any.
    pub fn load_base_schema(&self) -> Result<Option<String>, HarnessError> {
        self.base_schema_path()?.map(|p| read(&p)).transpose()
    }

    /// Build the engine and run every case.
    pub fn run(&self) -> Result<TestReport, HarnessError> {
        let engine = self.build_engine()?;
        let mut report = self.run_with(&engine);
        report.policies = self.policy_refs()?;
        Ok(report)
    }

    /// The evaluation time of the cases: the file's `now`, else [`DEFAULT_NOW_UNIX`].
    pub fn now_unix(&self) -> i64 {
        self.now.unwrap_or(DEFAULT_NOW_UNIX)
    }

    /// Whether the file sets `now` itself.
    pub fn sets_now(&self) -> bool {
        self.now.is_some()
    }

    /// A report for case results produced some other way (for instance by a remote server),
    /// with the file's source and its policies (see [`TestFile::policy_refs`]).
    pub fn report_for(&self, cases: Vec<CaseReport>) -> Result<TestReport, HarnessError> {
        Ok(TestReport {
            source: self.source.clone(),
            cases,
            policies: self.policy_refs()?,
        })
    }

    /// Run every case against an engine you built yourself. [`TestReport::policies`] lists
    /// the engine's policies without a file or line.
    pub fn run_with(&self, engine: &PolicyEngine) -> TestReport {
        let now_unix = self.now_unix();
        TestReport {
            source: self.source.clone(),
            cases: self
                .cases
                .iter()
                .map(|c| run_case(engine, c, now_unix))
                .collect(),
            policies: engine
                .policy_ids()
                .into_iter()
                .map(|id| PolicyRef {
                    id,
                    file: None,
                    line: None,
                })
                .collect(),
        }
    }

    /// The files a run of this test file reads besides itself: its policy file, the catalog file
    /// or server config `catalog` names, and the base schema file in force. Paths that cannot
    /// be worked out (an unreadable config) are left out.
    pub fn input_paths(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = self.policies_path().into_iter().collect();
        if let Some(CatalogSpec::Path(p)) = &self.catalog {
            out.push(clean_path(&self.resolve(p)));
        }
        if let Ok(Some(s)) = self.base_schema_path() {
            out.push(clean_path(&s));
        }
        out
    }

    /// The policy file the test file names, resolved against the test file's directory.
    pub fn policies_path(&self) -> Option<PathBuf> {
        self.policies
            .as_deref()
            .map(|p| clean_path(&self.resolve(p)))
    }

    /// Every policy of the file's `policies`, with the line it starts on (empty when it names
    /// none).
    pub fn policy_refs(&self) -> Result<Vec<PolicyRef>, HarnessError> {
        match self.policies_path() {
            None => Ok(Vec::new()),
            Some(path) => policy_refs(&read(&path)?, Some(&path)),
        }
    }
}

/// `path` without `.` components, so `dir/./policy.cedar` prints as `dir/policy.cedar`.
fn clean_path(path: &Path) -> PathBuf {
    let cleaned: PathBuf = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();
    if cleaned.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        cleaned
    }
}

/// One policy of a policy set: its id as the engine reports it (the `@id` annotation, else
/// Cedar's `policy<N>`), and where it starts when known.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PolicyRef {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// 1-based line of the policy's first token (its first annotation, or `permit`/`forbid`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

impl std::fmt::Display for PolicyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(f, "{} ({}:{line})", self.id, file.display()),
            (Some(file), None) => write!(f, "{} ({})", self.id, file.display()),
            (None, Some(line)) => write!(f, "{} (line {line})", self.id),
            (None, None) => f.write_str(&self.id),
        }
    }
}

/// The policies (and templates) in Cedar policy text, as the engine names them, each with the
/// line it starts on, in file order. `file` is only recorded in the result.
pub fn policy_refs(text: &str, file: Option<&Path>) -> Result<Vec<PolicyRef>, HarnessError> {
    use std::str::FromStr as _;
    let parsed = cedar_policy::PolicySet::from_str(text)
        .map_err(|e| HarnessError::Policy(PolicyError::Parse(e.to_string())))?;
    let lines = crate::lint::statement_lines(text);
    let mut refs: Vec<PolicyRef> = parsed
        .policies()
        .map(|p| (p.id().to_string(), p.annotation("id").map(str::to_string)))
        .chain(
            parsed
                .templates()
                .map(|t| (t.id().to_string(), t.annotation("id").map(str::to_string))),
        )
        .map(|(default_id, annotated)| {
            // Cedar numbers the statements of a parsed set `policy0`, `policy1`, ... in order.
            let line = default_id
                .strip_prefix("policy")
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|n| lines.get(n).copied());
            PolicyRef {
                id: annotated.unwrap_or(default_id),
                file: file.map(Path::to_path_buf),
                line,
            }
        })
        .collect();
    refs.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.id.cmp(&b.id)));
    Ok(refs)
}

/// Which policies of one or more test runs no case exercised (see the module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Coverage {
    /// Distinct policies across the reports (by policy file and id).
    pub policies: usize,
    /// The ones no case's decision depended on, in file and line order.
    pub unexercised: Vec<PolicyRef>,
}

impl Coverage {
    pub fn exercised(&self) -> usize {
        self.policies - self.unexercised.len()
    }
}

/// Fold reports into one [`Coverage`]. Reports whose test files name the same policy file
/// share its policies, so a policy exercised by a case in any of them counts as exercised.
pub fn coverage<'a>(reports: impl IntoIterator<Item = &'a TestReport>) -> Coverage {
    type Key = (Option<PathBuf>, String);
    let key = |p: &PolicyRef| -> Key {
        let file = p
            .file
            .as_ref()
            .map(|f| std::fs::canonicalize(f).unwrap_or_else(|_| f.clone()));
        (file, p.id.clone())
    };
    let mut all: BTreeMap<Key, PolicyRef> = BTreeMap::new();
    let mut exercised: BTreeSet<Key> = BTreeSet::new();
    for report in reports {
        let ids = report.exercised_ids();
        for p in &report.policies {
            let k = key(p);
            if ids.contains(p.id.as_str()) {
                exercised.insert(k.clone());
            }
            all.entry(k).or_insert_with(|| p.clone());
        }
    }
    let policies = all.len();
    let mut unexercised: Vec<PolicyRef> = all
        .into_iter()
        .filter(|(k, _)| !exercised.contains(k))
        .map(|(_, p)| p)
        .collect();
    unexercised.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then_with(|| a.id.cmp(&b.id))
    });
    Coverage {
        policies,
        unexercised,
    }
}

/// What the engine decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Actual {
    pub decision: Decision,
    pub reason: String,
    pub policy_ids: Vec<String>,
    pub diagnostics: Vec<String>,
}

impl From<Outcome> for Actual {
    fn from(o: Outcome) -> Self {
        Self {
            decision: o.decision,
            reason: o.reason,
            policy_ids: o.policy_ids,
            diagnostics: o.diagnostics,
        }
    }
}

/// The result of one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseReport {
    pub name: String,
    pub passed: bool,
    pub expected: Expect,
    /// Absent when the case could not be evaluated (see `error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<Actual>,
    /// Why the case failed: one line per mismatched expectation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
    /// Set when the case itself is malformed, for instance a chain that violates attenuation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Set when the case was deliberately not run, with the reason; `passed` is then `false`
    /// but the case does not count as failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// The result of one test file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
    pub cases: Vec<CaseReport>,
    /// Every policy of the set under test, exercised or not.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyRef>,
}

impl TestReport {
    /// Ids of the policies some evaluated case's decision depended on.
    pub fn exercised_ids(&self) -> BTreeSet<&str> {
        self.cases
            .iter()
            .filter_map(|c| c.actual.as_ref())
            .flat_map(|a| a.policy_ids.iter().map(String::as_str))
            .collect()
    }

    /// The policies no case of this report exercised, in file order.
    pub fn unexercised(&self) -> Vec<&PolicyRef> {
        let ids = self.exercised_ids();
        self.policies
            .iter()
            .filter(|p| !ids.contains(p.id.as_str()))
            .collect()
    }

    pub fn passed(&self) -> usize {
        self.cases.iter().filter(|c| c.passed).count()
    }

    /// Cases that ran (or could not be built) and did not pass. Skipped cases are not failed.
    pub fn failed(&self) -> usize {
        self.cases.len() - self.passed() - self.skipped()
    }

    /// Cases deliberately not run, for instance ones the AuthZEN endpoint cannot express.
    pub fn skipped(&self) -> usize {
        self.cases.iter().filter(|c| c.skipped.is_some()).count()
    }

    pub fn all_passed(&self) -> bool {
        self.failed() == 0
    }
}

fn run_case(engine: &PolicyEngine, case: &TestCase, now_unix: i64) -> CaseReport {
    match case.input(now_unix) {
        Ok(i) => case.check(Actual::from(
            engine.authorize_labelled(&i.chain, &i.call, &i.labels, i.now),
        )),
        Err(e) => case.errored(e),
    }
}

/// What a case evaluates: the chain and call it describes, the run's labels and the time.
#[derive(Debug, Clone)]
pub struct CaseInput {
    pub chain: DelegationChain,
    pub call: ToolCall,
    pub labels: CallLabels,
    pub now: OffsetDateTime,
}

impl TestCase {
    /// Build what the case evaluates at `now_unix` (the file's [`TestFile::now_unix`]), exactly
    /// as the in-process run does. `Err` describes a malformed case, for instance a chain that
    /// violates attenuation.
    pub fn input(&self, now_unix: i64) -> Result<CaseInput, String> {
        let (chain, call, now) = build_case(self, now_unix)?;
        let mut labels = self
            .session
            .as_ref()
            .map(SessionSpec::labels)
            .unwrap_or_default();
        if let Some(a) = &self.approval {
            labels.approval = crate::ApprovalContext::by(a.by.clone());
        }
        if let Some(b) = &self.budget {
            labels.budget = b.context();
        }
        if let Some(u) = &self.usage {
            labels.usage = u.context();
        }
        Ok(CaseInput {
            chain,
            call,
            labels,
            now,
        })
    }

    fn report(&self) -> CaseReport {
        CaseReport {
            name: self.name.clone(),
            passed: false,
            expected: self.expect,
            actual: None,
            failures: Vec::new(),
            error: None,
            skipped: None,
        }
    }

    /// The report of a case that could not be evaluated.
    pub fn errored(&self, error: impl Into<String>) -> CaseReport {
        CaseReport {
            error: Some(error.into()),
            ..self.report()
        }
    }

    /// The report of a case that was deliberately not run (neither passed nor failed).
    pub fn skip(&self, why: impl Into<String>) -> CaseReport {
        CaseReport {
            skipped: Some(why.into()),
            ..self.report()
        }
    }

    /// Why this case cannot be sent to a server's AuthZEN endpoint with a token whose chain is
    /// `token_chain`, or `None` when it can. The server takes the chain from the token and the
    /// run's labels, approvals, budget and usage from its own state, so a case that sets any of
    /// those must match the token or be skipped:
    ///
    /// - `session`, `approval`, `budget`, `usage` and `user.authenticated_at_unix` cannot be sent;
    /// - a `user` other than the default must equal the token's user (subject, issuer and the
    ///   exact attributes);
    /// - a non-empty `chain` must name the token's agents in order, and a hop with explicit
    ///   `capabilities` must carry exactly the token hop's capabilities.
    pub fn authzen_skip_reason(&self, token_chain: &DelegationChain) -> Option<String> {
        for (set, field) in [
            (self.session.is_some(), "session"),
            (self.approval.is_some(), "approval"),
            (self.budget.is_some(), "budget"),
            (self.usage.is_some(), "usage"),
            (
                self.user.authenticated_at_unix.is_some(),
                "user.authenticated_at_unix",
            ),
        ] {
            if set {
                return Some(format!(
                    "`{field}` cannot be sent through AuthZEN (the server uses its own state)"
                ));
            }
        }
        let ou = &token_chain.originating_user;
        if self.user != UserSpec::default()
            && (self.user.subject != ou.subject
                || self.user.issuer != ou.issuer
                || self.user.attributes != ou.attributes)
        {
            return Some(format!(
                "`user` differs from the token's user ({} at {})",
                ou.subject, ou.issuer
            ));
        }
        if self.chain.is_empty() {
            return None;
        }
        let agents = |names: Vec<&str>| names.join(" > ");
        let case_agents: Vec<&str> = self.chain.iter().map(HopSpec::agent).collect();
        let token_agents: Vec<&str> = token_chain
            .hops
            .iter()
            .map(|h| h.agent.0.as_str())
            .collect();
        if case_agents != token_agents {
            return Some(format!(
                "`chain` {} differs from the token's chain {}",
                agents(case_agents),
                agents(token_agents)
            ));
        }
        for (spec, hop) in self.chain.iter().zip(&token_chain.hops) {
            let Some(caps) = spec.capabilities() else {
                continue;
            };
            let same = caps
                .iter()
                .map(CapSpec::to_capability)
                .collect::<Result<CapabilitySet, _>>()
                .is_ok_and(|c| c == hop.capabilities);
            if !same {
                return Some(format!(
                    "the capabilities of hop `{}` differ from the token's",
                    spec.agent()
                ));
            }
        }
        None
    }

    /// Why this case cannot be sent to a server's admin dry run (`POST /admin/policies/evaluate`
    /// with the case's chain), or `None` when it can. The dry run takes the chain, the call,
    /// `session`, `approval` and `usage` as given, but reads `context.budget` from the run
    /// limits in the chain's capabilities and the server's counters, so only `budget` cannot
    /// be sent.
    pub fn admin_evaluate_skip_reason(&self) -> Option<String> {
        self.budget.as_ref().map(|_| {
            "`budget` cannot be sent to the admin dry run (it reads the run limits from the \
             chain's capabilities and the server's counters)"
                .to_string()
        })
    }

    /// [`input`](Self::input) for a case evaluated at `at_unix` instead of the file's
    /// `file_now_unix`: the chain is stamped at `at_unix`, and an explicit
    /// `user.authenticated_at_unix` moves by the same amount, so the user's authentication keeps
    /// the age the case gives it. For a server that validates the chain at its own clock.
    pub fn input_at(&self, file_now_unix: i64, at_unix: i64) -> Result<CaseInput, String> {
        let Some(t) = self.user.authenticated_at_unix else {
            return self.input(at_unix);
        };
        let shifted = t
            .checked_add(at_unix.saturating_sub(file_now_unix))
            .ok_or_else(|| "`authenticated_at_unix` is out of range".to_string())?;
        let mut case = self.clone();
        case.user.authenticated_at_unix = Some(shifted);
        case.input(at_unix)
    }

    /// Compare what was decided with what the case expects.
    pub fn check(&self, actual: Actual) -> CaseReport {
        let case = self;
        let mut report = self.report();
        if !case.expect.matches(&actual.decision) {
            report.failures.push(format!(
                "expected {}, got {} ({})",
                case.expect,
                decision_str(&actual.decision),
                actual.reason
            ));
        }
        if let Some(want) = &case.reason {
            if *want != actual.reason {
                report
                    .failures
                    .push(format!("expected reason {want}, got {}", actual.reason));
            }
        }
        if let Some(want) = &case.policy_ids {
            let mut w = want.clone();
            let mut g = actual.policy_ids.clone();
            w.sort();
            g.sort();
            if w != g {
                report.failures.push(format!(
                    "expected policy_ids [{}], got [{}]",
                    want.join(", "),
                    actual.policy_ids.join(", ")
                ));
            }
        }
        report.passed = report.failures.is_empty();
        report.actual = Some(actual);
        report
    }
}

fn decision_str(d: &Decision) -> &'static str {
    if d.is_allow() {
        "allow"
    } else {
        "deny"
    }
}

fn build_case(
    case: &TestCase,
    now_unix: i64,
) -> Result<(DelegationChain, ToolCall, OffsetDateTime), String> {
    let now = OffsetDateTime::from_unix_timestamp(now_unix)
        .map_err(|e| format!("`now` is out of range: {e}"))?;
    let authenticated_at = match case.user.authenticated_at_unix {
        Some(t) => OffsetDateTime::from_unix_timestamp(t)
            .map_err(|e| format!("`authenticated_at_unix` is out of range: {e}"))?,
        None => now - Duration::minutes(1),
    };
    let user = OriginatingUser {
        subject: case.user.subject.clone(),
        issuer: case.user.issuer.clone(),
        authenticated_at,
        attributes: case.user.attributes.clone(),
    };

    let mut call = ToolCall::new(
        case.call.server.clone(),
        case.call.tool.clone(),
        case.call.arguments.clone(),
    );
    if let Some(s) = &case.call.session_id {
        call = call.with_session(s.clone());
    }

    let default_hops = [HopSpec::Agent("agent".to_string())];
    let specs: &[HopSpec] = if case.chain.is_empty() {
        &default_hops
    } else {
        &case.chain
    };
    let mut hops: Vec<Hop> = Vec::with_capacity(specs.len());
    for (i, spec) in specs.iter().enumerate() {
        let capabilities = match spec.capabilities() {
            Some(caps) => caps
                .iter()
                .map(CapSpec::to_capability)
                .collect::<Result<CapabilitySet, _>>()
                .map_err(|e| format!("hop {i} ({}): {e}", spec.agent()))?,
            None => match hops.last() {
                Some(prev) => prev.capabilities.clone(),
                None => CapabilitySet::from_iter([Capability::new(&call.server, &call.tool)]),
            },
        };
        hops.push(Hop {
            agent: AgentId::new(spec.agent()),
            capabilities,
            issued_at: now,
            expires_at: now + Duration::hours(1),
            lease: LeaseId::new(format!("lease-{}", uuid::Uuid::new_v4())),
        });
    }
    let chain = DelegationChain {
        originating_user: user,
        hops,
    };
    chain
        .validate_at(now, MAX_CASE_DEPTH)
        .map_err(|e| format!("the chain is not one the server would accept: {e}"))?;
    Ok((chain, call, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
@id("read_public")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("no_deep")
forbid(principal, action, resource) when { context.chain.depth > 2 };

@id("mfa_for_sensitive")
forbid(principal, action, resource)
when { resource.sensitive &&
  !(context.originating_user.attributes has mfa && context.originating_user.attributes.mfa == true) };

@id("allow_delete")
permit(principal, action == Action::"github/delete_repo", resource);
"#;

    const CATALOG: &str = r#"
catalog:
  github:
    read_file: { readonly: true, inputs: { repo: string } }
    delete_repo: { sensitive: true }
"#;

    fn file(cases: &str) -> (tempfile::TempDir, TestFile) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("p.cedar"), POLICY).unwrap();
        let yaml = format!("policies: ./p.cedar\n{CATALOG}\ncases:\n{cases}");
        let path = dir.path().join("t.yaml");
        std::fs::write(&path, yaml).unwrap();
        let f = TestFile::load(&path).unwrap();
        (dir, f)
    }

    #[test]
    fn passing_and_failing_cases() {
        let (_dir, f) = file(
            r#"
  - name: public read allowed
    chain: [assistant, coder]
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
    expect: allow
    reason: policy_allow
    policy_ids: [read_public]
  - name: private read denied
    chain: [coder]
    call: { server: github, tool: read_file, arguments: { repo: alice/private } }
    expect: deny
    reason: policy_deny
  - name: wrong expectation
    chain: [coder]
    call: { server: github, tool: read_file, arguments: { repo: alice/private } }
    expect: allow
    policy_ids: [read_public]
"#,
        );
        let r = f.run().unwrap();
        assert_eq!(r.cases.len(), 3);
        assert!(r.cases[0].passed, "{:?}", r.cases[0]);
        assert_eq!(
            r.cases[0].actual.as_ref().unwrap().policy_ids,
            vec!["read_public"]
        );
        assert!(r.cases[1].passed, "{:?}", r.cases[1]);
        let bad = &r.cases[2];
        assert!(!bad.passed);
        assert_eq!(bad.failures.len(), 2, "{:?}", bad.failures);
        assert!(bad.failures[0].contains("expected allow, got deny"));
        assert_eq!((r.passed(), r.failed()), (2, 1));
        assert!(!r.all_passed());
    }

    #[test]
    fn capability_stage_and_deep_chain_and_mfa() {
        let (_dir, f) = file(
            r#"
  - name: capability narrower than the call
    chain:
      - { agent: assistant, capabilities: ["github:*"] }
      - { agent: coder, capabilities: ["github:read_file"] }
    call: { server: github, tool: delete_repo }
    user: { attributes: { mfa: true } }
    expect: deny
    reason: capability_denied
  - name: deep chain forbidden
    chain: [a, b, c]
    call: { server: github, tool: read_file, arguments: { repo: alice/public-x } }
    expect: deny
    policy_ids: [no_deep]
  - name: delete without mfa
    chain: [a]
    call: { server: github, tool: delete_repo }
    expect: deny
    policy_ids: [mfa_for_sensitive]
  - name: delete with mfa
    chain: [a]
    user: { attributes: { mfa: true } }
    call: { server: github, tool: delete_repo }
    expect: allow
"#,
        );
        let r = f.run().unwrap();
        for c in &r.cases {
            assert!(c.passed, "{}: {:?} {:?}", c.name, c.failures, c.error);
        }
    }

    #[test]
    fn mistyped_user_attribute_is_denied_not_permitted_sr33() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("p.cedar"),
            r#"@id("not_suspended") permit(principal, action == Action::"github/read_file", resource)
               when { context.originating_user.attributes has status
                      && context.originating_user.attributes.status != "suspended" };"#,
        )
        .unwrap();
        let yaml = format!(
            "policies: ./p.cedar\n{CATALOG}\ncases:\n{}",
            r#"
  - name: string status allowed
    chain: [coder]
    user: { attributes: { status: active } }
    call: { server: github, tool: read_file, arguments: { repo: a/b } }
    expect: allow
  - name: list status is a type mismatch
    chain: [coder]
    user: { attributes: { status: [suspended] } }
    call: { server: github, tool: read_file, arguments: { repo: a/b } }
    expect: deny
    reason: attribute_type_mismatch
"#
        );
        let path = dir.path().join("t.yaml");
        std::fs::write(&path, yaml).unwrap();
        let f = TestFile::load(&path).unwrap();
        let engine = PolicyEngineBuilder::new()
            .with_catalog(f.load_catalog().unwrap())
            .with_user_attr("status", ArgType::String)
            .with_policies_file(dir.path().join("p.cedar"))
            .build()
            .unwrap();
        let r = f.run_with(&engine);
        for c in &r.cases {
            assert!(c.passed, "{}: {:?} {:?}", c.name, c.failures, c.error);
        }
        let d = &r.cases[1].actual.as_ref().unwrap().diagnostics;
        assert!(d[0].contains("attributes.status"), "{d:?}");
    }

    #[test]
    fn user_attributes_are_read_from_a_server_config() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("server.toml");
        std::fs::write(
            &cfg,
            "[policy.user_attributes]\ngroups = \"set<string>\"\ndepartment = \"string\"\n",
        )
        .unwrap();
        let attrs = load_user_attrs(&cfg).unwrap();
        assert_eq!(attrs["groups"], ArgType::Set(Box::new(ArgType::String)));
        assert_eq!(attrs["department"], ArgType::String);
        std::fs::write(&cfg, "[policy.user_attributes]\ngroups = \"nope\"\n").unwrap();
        assert!(load_user_attrs(&cfg).is_err());
        std::fs::write(&cfg, "[server]\n").unwrap();
        assert!(load_user_attrs(&cfg).unwrap().is_empty());
    }

    #[test]
    fn invalid_chain_is_a_failed_case_with_an_error() {
        let (_dir, f) = file(
            r#"
  - name: child wider than parent
    chain:
      - { agent: a, capabilities: ["github:read_file"] }
      - { agent: b, capabilities: ["github:delete_repo"] }
    call: { server: github, tool: read_file }
    expect: deny
"#,
        );
        let r = f.run().unwrap();
        let c = &r.cases[0];
        assert!(!c.passed);
        assert!(c.actual.is_none());
        assert!(c
            .error
            .as_deref()
            .unwrap()
            .contains("not one the server would accept"));
    }

    #[test]
    fn bad_capability_string_is_a_case_error() {
        let (_dir, f) = file(
            r#"
  - name: bad cap
    chain: [{ agent: a, capabilities: ["nocolon"] }]
    call: { server: github, tool: read_file }
    expect: deny
"#,
        );
        let c = &f.run().unwrap().cases[0];
        assert!(c.error.as_deref().unwrap().contains("server:tool"));
    }

    #[test]
    fn catalog_comes_from_a_server_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[policy.catalog.github.read_file]\nreadonly = true\ninputs = { repo = \"string\" }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("p.cedar"),
            "permit(principal, action, resource) when { resource.readonly };",
        )
        .unwrap();
        let path = dir.path().join("t.yaml");
        std::fs::write(
            &path,
            "policies: p.cedar\ncatalog: ./config.toml\ncases:\n  - name: readonly tool\n    call: { server: github, tool: read_file }\n    expect: allow\n  - name: unknown tool is not readonly\n    call: { server: github, tool: other }\n    expect: deny\n",
        )
        .unwrap();
        let r = TestFile::load(&path).unwrap().run().unwrap();
        assert!(r.all_passed(), "{r:?}");
    }

    #[test]
    fn config_catalog_path_is_merged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("cat.json"),
            r#"{"github":{"delete_repo":{"sensitive":true}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[policy]\ncatalog_path = \"cat.json\"\n[policy.catalog.github.read_file]\nreadonly = true\n",
        )
        .unwrap();
        let c = load_catalog_from_config(&dir.path().join("config.toml")).unwrap();
        assert!(c.get("github", "read_file").readonly);
        assert!(c.get("github", "delete_repo").sensitive);
    }

    #[test]
    fn no_policies_means_deny_everything() {
        let f = TestFile::from_yaml_str(
            "unknown_tools: allow\ncases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: deny\n    reason: policy_deny\n",
        )
        .unwrap();
        assert!(f.run().unwrap().all_passed());
    }

    #[test]
    fn uncatalogued_tools_follow_the_server_default() {
        let permit = "permit(principal, action, resource);";
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("p.cedar"), permit).unwrap();
        // No catalog and no setting: denied like the server does.
        let case = "cases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: deny\n    reason: tool_not_in_catalog\n";
        std::fs::write(
            dir.path().join("a.yaml"),
            format!("policies: p.cedar\n{case}"),
        )
        .unwrap();
        let r = TestFile::load(&dir.path().join("a.yaml"))
            .unwrap()
            .run()
            .unwrap();
        assert!(r.all_passed(), "{r:?}");
        // A server config's setting is picked up with its catalog.
        std::fs::write(
            dir.path().join("config.toml"),
            "[policy]\nunknown_tools = \"allow\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.yaml"),
            "policies: p.cedar\ncatalog: config.toml\ncases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: allow\n",
        )
        .unwrap();
        let r = TestFile::load(&dir.path().join("b.yaml"))
            .unwrap()
            .run()
            .unwrap();
        assert!(r.all_passed(), "{r:?}");
    }

    #[test]
    fn legacy_bare_actions_come_from_the_file_or_the_config_sr13() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("p.cedar"),
            r#"permit(principal, action == Action::"read_file", resource);"#,
        )
        .unwrap();
        let catalog = "[policy.catalog.github.read_file]\n[policy.catalog.evil.read_file]\n";
        std::fs::write(dir.path().join("new.toml"), catalog).unwrap();
        std::fs::write(
            dir.path().join("old.toml"),
            format!("[policy]\nlegacy_bare_actions = true\n{catalog}"),
        )
        .unwrap();
        let cases = "cases:\n  - name: gh\n    call: { server: github, tool: read_file }\n    expect: allow\n  - name: evil\n    call: { server: evil, tool: read_file }\n    expect: allow\n";
        // Off by default: the bare action does not validate.
        std::fs::write(
            dir.path().join("a.yaml"),
            format!("policies: p.cedar\ncatalog: new.toml\n{cases}"),
        )
        .unwrap();
        assert!(TestFile::load(&dir.path().join("a.yaml"))
            .unwrap()
            .run()
            .is_err());
        // From the config, or set in the file: it loads, and matches every server.
        for (name, head) in [
            ("b.yaml", "catalog: old.toml\n"),
            ("c.yaml", "catalog: new.toml\nlegacy_bare_actions: true\n"),
        ] {
            std::fs::write(
                dir.path().join(name),
                format!("policies: p.cedar\n{head}{cases}"),
            )
            .unwrap();
            let r = TestFile::load(&dir.path().join(name))
                .unwrap()
                .run()
                .unwrap();
            assert!(r.all_passed(), "{name}: {r:?}");
        }
    }

    #[test]
    fn malformed_files_are_rejected() {
        for (yaml, needle) in [
            ("cases: [", "test file"),
            ("cases: []", "`cases` is empty"),
            ("cases:\n  - name: x\n    call: { server: s, tool: t }\n", "expect"),
            (
                "cases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: maybe\n",
                "maybe",
            ),
            (
                "cases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: deny\n    typo: 1\n",
                "typo",
            ),
            (
                "cases:\n  - { name: x, call: { server: s, tool: t }, expect: deny }\n  - { name: x, call: { server: s, tool: t }, expect: deny }\n",
                "duplicate case name",
            ),
        ] {
            let err = TestFile::from_yaml_str(yaml).unwrap_err().to_string();
            assert!(err.contains(needle), "`{err}` should mention `{needle}`");
        }
    }

    #[test]
    fn missing_or_broken_inputs_are_errors() {
        let err = TestFile::load(Path::new("/nonexistent/t.yaml")).unwrap_err();
        assert!(matches!(err, HarnessError::Io { .. }));

        let f = TestFile::from_yaml_str(
            "policies: /nonexistent/p.cedar\ncases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: deny\n",
        )
        .unwrap();
        assert!(f.run().is_err());

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("p.cedar"),
            "permit(principal action resource);",
        )
        .unwrap();
        let f = TestFile::from_yaml_str(&format!(
            "policies: {}/p.cedar\ncases:\n  - name: x\n    call: {{ server: s, tool: t }}\n    expect: deny\n",
            dir.path().display()
        ))
        .unwrap();
        assert!(matches!(
            f.run().unwrap_err(),
            HarnessError::Policy(PolicyError::Parse(_))
        ));
    }

    #[test]
    fn report_serializes_to_json() {
        let (_dir, f) = file(
            "  - name: j\n    call: { server: github, tool: read_file, arguments: { repo: alice/private } }\n    expect: deny\n",
        );
        let v = serde_json::to_value(f.run().unwrap()).unwrap();
        assert_eq!(v["cases"][0]["actual"]["decision"], "deny");
        assert_eq!(v["cases"][0]["passed"], true);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    const POLICY: &str = "@id(\"read\")\npermit(principal, action == Action::\"github/read_file\", resource);\n\n// no id: Cedar calls it policy1\nforbid(principal, action, resource) when { context.chain.depth > 2 };\n\n@id(\"shadowed\")\npermit(principal, action == Action::\"github/read_file\", resource) when { context.chain.depth > 2 };\n\n@id(\"delete\")\npermit(principal, action == Action::\"github/delete_repo\", resource);\n";

    fn setup(cases: &str) -> (tempfile::TempDir, TestFile) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("p.cedar"), POLICY).unwrap();
        let path = dir.path().join("t.yaml");
        std::fs::write(
            &path,
            format!("policies: ./p.cedar\ncatalog:\n  github:\n    read_file: {{ readonly: true }}\n    delete_repo: {{}}\ncases:\n{cases}"),
        )
        .unwrap();
        let f = TestFile::load(&path).unwrap();
        (dir, f)
    }

    const READ: &str = "  - name: read\n    chain: [a]\n    call: { server: github, tool: read_file }\n    expect: allow\n";
    const DEEP: &str = "  - name: deep\n    chain: [a, b, c]\n    call: { server: github, tool: read_file }\n    expect: deny\n";
    const DELETE: &str = "  - name: delete\n    chain: [a]\n    call: { server: github, tool: delete_repo }\n    expect: allow\n";

    #[test]
    fn policy_refs_name_and_locate_every_policy() {
        let refs = policy_refs(POLICY, Some(Path::new("p.cedar"))).unwrap();
        let got: Vec<(&str, Option<usize>)> =
            refs.iter().map(|r| (r.id.as_str(), r.line)).collect();
        assert_eq!(
            got,
            vec![
                ("read", Some(1)),
                ("policy1", Some(5)),
                ("shadowed", Some(7)),
                ("delete", Some(10))
            ]
        );
        assert_eq!(refs[1].to_string(), "policy1 (p.cedar:5)");
        assert!(policy_refs("permit(principal action resource);", None).is_err());
    }

    #[test]
    fn unexercised_lists_policies_no_decision_depended_on() {
        let (_d, f) = setup(&format!("{READ}{DEEP}"));
        let report = f.run().unwrap();
        assert!(report.all_passed(), "{report:?}");
        assert_eq!(report.policies.len(), 4);
        let un: Vec<&str> = report.unexercised().iter().map(|p| p.id.as_str()).collect();
        // `shadowed` matched the deep call, but the forbid decided it.
        assert_eq!(un, vec!["shadowed", "delete"]);
        let file = report.policies[0].file.as_ref().unwrap();
        assert!(file.ends_with("p.cedar"), "{file:?}");
        assert!(!file.to_string_lossy().contains("/./"), "{file:?}");
    }

    #[test]
    fn failing_cases_still_exercise_and_coverage_merges_files() {
        // The case fails (expect deny, got allow), yet `delete` decided it.
        let wrong = "  - name: delete\n    chain: [a]\n    call: { server: github, tool: delete_repo }\n    expect: deny\n";
        let (d, f1) = setup(wrong);
        let r1 = f1.run().unwrap();
        assert_eq!(r1.failed(), 1);
        assert!(r1.exercised_ids().contains("delete"));

        // A second test file over the same policy file.
        let p2 = d.path().join("t2.yaml");
        std::fs::write(
            &p2,
            format!("policies: p.cedar\ncatalog:\n  github:\n    read_file: {{ readonly: true }}\n    delete_repo: {{}}\ncases:\n{READ}"),
        )
        .unwrap();
        let r2 = TestFile::load(&p2).unwrap().run().unwrap();
        let cov = coverage([&r1, &r2]);
        assert_eq!(cov.policies, 4);
        assert_eq!(cov.exercised(), 2);
        let un: Vec<&str> = cov.unexercised.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(un, vec!["policy1", "shadowed"]);

        let (_d, all) = setup(&format!("{READ}{DEEP}{DELETE}"));
        let cov = coverage([&all.run().unwrap()]);
        // `shadowed` can never decide: the forbid wins whenever it matches.
        let un: Vec<&str> = cov.unexercised.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(un, vec!["shadowed"]);
    }

    #[test]
    fn authzen_skip_reason_matches_cases_against_the_token_chain() {
        let f = TestFile::from_yaml_str(
            r#"
cases:
  - name: same
    user: { subject: carol, attributes: { mfa: true } }
    chain:
      - { agent: a, capabilities: ["github:*"] }
      - b
    call: { server: github, tool: read_file }
    expect: allow
  - name: any chain
    call: { server: github, tool: read_file }
    expect: allow
  - name: narrower hop
    chain:
      - { agent: a, capabilities: ["github:*"] }
      - { agent: b, capabilities: ["github:read_file"] }
    call: { server: github, tool: read_file }
    expect: allow
  - name: other attrs
    user: { subject: carol }
    call: { server: github, tool: read_file }
    expect: allow
  - name: with usage
    usage: { calls: 1 }
    call: { server: github, tool: read_file }
    expect: allow
"#,
        )
        .unwrap();
        // The token's chain is the one the first case describes.
        let token = f.cases[0].input(f.now_unix()).unwrap().chain;
        let why = |i: usize| f.cases[i].authzen_skip_reason(&token);
        assert_eq!(why(0), None);
        assert_eq!(why(1), None);
        assert!(why(2).unwrap().contains("hop `b`"), "{:?}", why(2));
        assert!(why(3).unwrap().contains("`user` differs"), "{:?}", why(3));
        assert!(
            why(4).unwrap().starts_with("`usage` cannot"),
            "{:?}",
            why(4)
        );
        let skipped = f.cases[4].skip("x");
        assert!(!skipped.passed && skipped.skipped.is_some());
        let report = TestReport {
            source: None,
            cases: vec![skipped, f.cases[0].errored("broken")],
            policies: Vec::new(),
        };
        assert_eq!(
            (report.passed(), report.failed(), report.skipped()),
            (0, 1, 1)
        );
    }

    #[test]
    fn admin_evaluate_skips_only_budget_and_input_at_keeps_the_authentication_age() {
        let f = TestFile::from_yaml_str(
            r#"
now: 1000000
cases:
  - name: everything the dry run takes
    user: { subject: carol, attributes: { mfa: true }, authenticated_at_unix: 999000 }
    chain:
      - { agent: a, capabilities: ["github:*"] }
      - b
    session: { tainted_by: [web/fetch], untrusted_args: [repo] }
    approval: { by: user }
    usage: { calls: 2 }
    call: { server: github, tool: read_file }
    expect: allow
  - name: with budget
    budget: { calls_remaining: 1 }
    call: { server: github, tool: read_file }
    expect: allow
  - name: default user
    call: { server: github, tool: read_file }
    expect: allow
"#,
        )
        .unwrap();
        assert_eq!(f.cases[0].admin_evaluate_skip_reason(), None);
        assert_eq!(f.cases[2].admin_evaluate_skip_reason(), None);
        let why = f.cases[1].admin_evaluate_skip_reason().unwrap();
        assert!(why.starts_with("`budget` cannot"), "{why}");

        let at = 2_000_000;
        let i = f.cases[0].input_at(f.now_unix(), at).unwrap();
        let stamp = |t: i64| OffsetDateTime::from_unix_timestamp(t).unwrap();
        assert_eq!(i.now, stamp(at));
        assert!(i.chain.hops.iter().all(|h| h.issued_at == stamp(at)));
        // Authenticated 1000 s before `now` in the file, and still 1000 s before `at`.
        assert_eq!(i.chain.originating_user.authenticated_at, stamp(at - 1000));
        assert!(i.labels.session.tainted && i.labels.args.contain_untrusted);
        assert_eq!(i.labels.usage.calls, 2);
        // Without an explicit time, the default (a minute before) applies at `at`.
        let d = f.cases[2].input_at(f.now_unix(), at).unwrap();
        assert_eq!(d.chain.originating_user.authenticated_at, stamp(at - 60));
    }

    #[test]
    fn run_with_lists_engine_policies_without_location_and_no_policies_means_none() {
        let (_d, f) = setup(READ);
        let engine = f.build_engine().unwrap();
        let r = f.run_with(&engine);
        assert_eq!(r.policies.len(), 4);
        assert!(r
            .policies
            .iter()
            .all(|p| p.file.is_none() && p.line.is_none()));

        let none = TestFile::from_yaml_str(
            "cases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: deny\n",
        )
        .unwrap();
        let r = none.run().unwrap();
        assert!(r.policies.is_empty());
        assert_eq!(coverage([&r]), Coverage::default());
    }
}
