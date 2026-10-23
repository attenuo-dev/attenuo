//! The tool catalog: per-tool attributes that policies can refer to.
//!
//! Policies cannot pattern-match on action names (`Action::"read_*"` is not valid Cedar), so
//! the practical way to write "permit every read-only tool" is to tag tools in a catalog and
//! test the tag on the resource entity: `permit(...) when { resource.readonly }`.
//!
//! The catalog also drives the generated part of the Cedar schema: every tool becomes a
//! declared action (`Action::"<server>/<tool>"`) and every declared input argument becomes a typed, optional attribute of
//! `context.input`, so the validator can catch typos and type errors in policies at load time.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Cedar type of a tool argument, used only for schema generation and policy validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgType {
    String,
    Long,
    Bool,
    Set(Box<ArgType>),
}

impl std::str::FromStr for ArgType {
    type Err = String;

    /// Parse `string`, `long`, `bool` or `set<T>` (case-insensitive, spaces ignored), the
    /// notation used by `[policy] user_attributes` in the server config.
    fn from_str(s: &str) -> Result<Self, String> {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "string" => Ok(ArgType::String),
            "long" => Ok(ArgType::Long),
            "bool" => Ok(ArgType::Bool),
            _ => match t.strip_prefix("set<").and_then(|r| r.strip_suffix('>')) {
                Some(inner) => Ok(ArgType::Set(Box::new(inner.parse()?))),
                None => Err(format!(
                    "unknown type `{}`: expected string, long, bool or set<...>",
                    s.trim()
                )),
            },
        }
    }
}

/// Parse a `{ name = "type" }` table of user attribute declarations.
pub fn parse_user_attributes(
    decls: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, ArgType>, String> {
    decls
        .iter()
        .map(|(name, ty)| {
            ty.parse()
                .map(|t| (name.clone(), t))
                .map_err(|e| format!("user_attributes.{name}: {e}"))
        })
        .collect()
}

impl ArgType {
    /// Render as Cedar schema syntax.
    pub(crate) fn cedar(&self) -> String {
        match self {
            ArgType::String => "String".to_string(),
            ArgType::Long => "Long".to_string(),
            ArgType::Bool => "Bool".to_string(),
            ArgType::Set(inner) => format!("Set<{}>", inner.cedar()),
        }
    }
}

/// Attributes of one tool. Available in policies as `resource.readonly` and
/// `resource.sensitive`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolAttrs {
    /// The tool only reads; it never mutates state outside the agent.
    #[serde(default)]
    pub readonly: bool,
    /// The tool touches data or actions that warrant stronger user assurance (e.g. MFA).
    #[serde(default)]
    pub sensitive: bool,
    /// Declared argument types. Only used to type `context.input` for policy validation;
    /// arguments that are not declared are still passed to Cedar at evaluation time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, ArgType>,
}

impl ToolAttrs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn readonly(mut self, readonly: bool) -> Self {
        self.readonly = readonly;
        self
    }

    pub fn sensitive(mut self, sensitive: bool) -> Self {
        self.sensitive = sensitive;
        self
    }

    /// Declare the type of an argument so policies that read `context.input.<name>` validate.
    pub fn with_input(mut self, name: impl Into<String>, ty: ArgType) -> Self {
        self.inputs.insert(name.into(), ty);
        self
    }
}

/// What the engine does with a `tools/call` for a `(server, tool)` pair that is not in the
/// catalog. See [`PolicyEngineBuilder::with_unknown_tools`](crate::PolicyEngineBuilder::with_unknown_tools).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownTools {
    /// Deny with reason `tool_not_in_catalog` (after the capability stage). The default: a
    /// tool nobody classified cannot be reached by `forbid ... when { resource.sensitive }`
    /// failing open (SR-12), and a renamed tool (`Delete_Repo`) is not a different, unlisted
    /// tool that slips past rules keyed on the real name (SR-25).
    #[default]
    Deny,
    /// Evaluate with `sensitive = true` (and `readonly = false`).
    Sensitive,
    /// Evaluate with [`ToolAttrs::default`] (not read-only, not sensitive). The behaviour
    /// before SR-12: `forbid` rules keyed on `sensitive` do not apply.
    Allow,
}

/// Attributes for every known `(server, tool)` pair. What happens to a call for a tool that is
/// not here is set by [`UnknownTools`] (deny by default). Register every tool a server exposes
/// (MCP `tools/list` is the natural source).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ToolCatalog {
    // (server, tool) -> attrs. A BTreeMap keeps schema generation deterministic.
    tools: BTreeMap<(String, String), ToolAttrs>,
}

impl ToolCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool; replaces any previous entry for the same `(server, tool)`.
    pub fn insert(&mut self, server: impl Into<String>, tool: impl Into<String>, attrs: ToolAttrs) {
        self.tools.insert((server.into(), tool.into()), attrs);
    }

    /// Builder-style [`insert`](Self::insert).
    pub fn with(
        mut self,
        server: impl Into<String>,
        tool: impl Into<String>,
        attrs: ToolAttrs,
    ) -> Self {
        self.insert(server, tool, attrs);
        self
    }

    /// Attributes for a tool, or the default when it is not registered.
    pub fn get(&self, server: &str, tool: &str) -> ToolAttrs {
        self.tools
            .get(&(server.to_string(), tool.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contains(&self, server: &str, tool: &str) -> bool {
        self.tools
            .contains_key(&(server.to_string(), tool.to_string()))
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Iterate over `((server, tool), attrs)` in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&(String, String), &ToolAttrs)> {
        self.tools.iter()
    }

    /// Check every server and tool name against [`onbehalf_core::names`]: a server name has
    /// no `/`, and a tool is a tool name or an MCP method name (`resources/read`). Called by
    /// [`PolicyEngineBuilder::build`](crate::PolicyEngineBuilder::build).
    pub fn validate(&self) -> Result<(), String> {
        for (server, tool) in self.tools.keys() {
            onbehalf_core::names::check_server_name(server)
                .and_then(|()| onbehalf_core::names::check_call_name(tool))
                .map_err(|e| format!("catalog entry {server:?} / {tool:?}: {e}"))?;
        }
        Ok(())
    }

    /// Cedar action ids (see [`crate::action_id`]) with the union of their declared inputs.
    /// In legacy mode several servers can share an action; where two declare the same argument
    /// with different types, the first (in `(server, tool)` order) wins.
    pub(crate) fn actions(
        &self,
        legacy_bare_actions: bool,
    ) -> BTreeMap<String, BTreeMap<String, ArgType>> {
        let mut out: BTreeMap<String, BTreeMap<String, ArgType>> = BTreeMap::new();
        for ((server, tool), attrs) in &self.tools {
            let id = crate::schema::action_id(server, tool, legacy_bare_actions);
            let entry = out.entry(id).or_default();
            for (name, ty) in &attrs.inputs {
                entry.entry(name.clone()).or_insert_with(|| ty.clone());
            }
        }
        out
    }
}
