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
//! ```
//!
//! An inline catalog has the same shape as `[policy.catalog]` in the server config:
//!
//! ```yaml
//! catalog:
//!   github:
//!     read_file: { readonly: true, inputs: { repo: string } }
//!     delete_repo: { sensitive: true }
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, Hop, LeaseId, OriginatingUser,
    ToolCall,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::{
    ArgType, Outcome, PolicyEngine, PolicyEngineBuilder, PolicyError, ToolAttrs, ToolCatalog,
    UnknownTools,
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
        if let Some(p) = &self.policies {
            builder = builder.with_policies_file(self.resolve(p));
        }
        Ok(builder.build()?)
    }

    /// Build the engine and run every case.
    pub fn run(&self) -> Result<TestReport, HarnessError> {
        let engine = self.build_engine()?;
        Ok(self.run_with(&engine))
    }

    /// Run every case against an engine you built yourself.
    pub fn run_with(&self, engine: &PolicyEngine) -> TestReport {
        let now_unix = self.now.unwrap_or(DEFAULT_NOW_UNIX);
        TestReport {
            source: self.source.clone(),
            cases: self
                .cases
                .iter()
                .map(|c| run_case(engine, c, now_unix))
                .collect(),
        }
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
}

/// The result of one test file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
    pub cases: Vec<CaseReport>,
}

impl TestReport {
    pub fn passed(&self) -> usize {
        self.cases.iter().filter(|c| c.passed).count()
    }

    pub fn failed(&self) -> usize {
        self.cases.len() - self.passed()
    }

    pub fn all_passed(&self) -> bool {
        self.failed() == 0
    }
}

fn run_case(engine: &PolicyEngine, case: &TestCase, now_unix: i64) -> CaseReport {
    let mut report = CaseReport {
        name: case.name.clone(),
        passed: false,
        expected: case.expect,
        actual: None,
        failures: Vec::new(),
        error: None,
    };
    let (chain, call, now) = match build_case(case, now_unix) {
        Ok(v) => v,
        Err(e) => {
            report.error = Some(e);
            return report;
        }
    };
    let actual = Actual::from(engine.authorize(&chain, &call, now));

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
