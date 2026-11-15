//! The tool catalog: per-tool attributes that policies can refer to.
//!
//! Policies cannot pattern-match on action names (`Action::"read_*"` is not valid Cedar), so
//! the practical way to write "permit every read-only tool" is to tag tools in a catalog and
//! test the tag on the resource entity: `permit(...) when { resource.readonly }`.
//!
//! The catalog also drives the generated part of the Cedar schema: every tool becomes a
//! declared action (`Action::"<server>/<tool>"`) and every declared input argument becomes a typed, optional attribute of
//! `context.input`, so the validator can catch typos and type errors in policies at load time.

use std::collections::{BTreeMap, BTreeSet};

pub use attenuo_core::OutputLabel;
use serde::{Deserialize, Deserializer, Serialize};

/// Cedar type of a tool argument or user attribute: used for schema generation and policy
/// validation, and checked against the call's value before Cedar runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgType {
    /// A JSON string; Cedar `String`.
    String,
    /// A JSON number with no fractional part (`5.0` counts); Cedar `Long`.
    Long,
    /// A JSON `true` or `false`; Cedar `Bool`.
    Bool,
    /// A JSON number with at most 4 fractional digits and a magnitude of at most
    /// 922337203685477; Cedar's `decimal` extension type. `12.5`, `12.50` and `12` are
    /// `decimal("12.5")`, `decimal("12.5")` and `decimal("12.0")`: the number's shortest
    /// decimal form, never rounded, so `12.34567` is refused. Compare it with the decimal
    /// methods, `context.input.amount.lessThan(decimal("100.0"))`. A catalog input type only:
    /// user attributes cannot be declared `decimal`.
    Decimal,
    /// A JSON array whose every element has the inner type; Cedar `Set<T>`.
    Set(Box<ArgType>),
}

impl std::str::FromStr for ArgType {
    type Err = String;

    /// Parse `string`, `long`, `bool`, `decimal` or `set<T>` (case-insensitive, spaces
    /// ignored), the notation used by `[policy] user_attributes` in the server config, which
    /// then refuses `decimal` ([`parse_user_attributes`]).
    fn from_str(s: &str) -> Result<Self, String> {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "string" => Ok(ArgType::String),
            "long" => Ok(ArgType::Long),
            "bool" => Ok(ArgType::Bool),
            "decimal" => Ok(ArgType::Decimal),
            _ => match t.strip_prefix("set<").and_then(|r| r.strip_suffix('>')) {
                Some(inner) => Ok(ArgType::Set(Box::new(inner.parse()?))),
                None => Err(format!(
                    "unknown type `{}`: expected string, long, bool, decimal or set<...>",
                    s.trim()
                )),
            },
        }
    }
}

/// Parse a `{ name = "type" }` table of user attribute declarations.
///
/// # Errors
///
/// A message `user_attributes.<name>: ...` for the first declaration (in name order) whose type
/// is not `string`, `long`, `bool` or `set<T>` of one of those. `decimal` parses but is
/// refused here: it is a catalog input type only ([`ArgType::Decimal`]).
pub fn parse_user_attributes(
    decls: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, ArgType>, String> {
    decls
        .iter()
        .map(|(name, ty)| {
            let t: ArgType = ty
                .parse()
                .map_err(|e| format!("user_attributes.{name}: {e}"))?;
            if t.contains_decimal() {
                return Err(format!(
                    "user_attributes.{name}: decimal is a catalog input type only; user \
                     attributes are string, long, bool or set<...>"
                ));
            }
            Ok((name.clone(), t))
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
            ArgType::Decimal => "__cedar::decimal".to_string(),
            ArgType::Set(inner) => format!("Set<{}>", inner.cedar()),
        }
    }

    /// As [`cedar`](Self::cedar), with `decimal` for the extension type: the name diagnostics
    /// use.
    pub(crate) fn shown(&self) -> String {
        match self {
            ArgType::Decimal => "decimal".to_string(),
            ArgType::Set(inner) => format!("Set<{}>", inner.shown()),
            other => other.cedar(),
        }
    }

    /// Is this `decimal`, or a set of it at any depth?
    pub(crate) fn contains_decimal(&self) -> bool {
        match self {
            ArgType::Decimal => true,
            ArgType::Set(inner) => inner.contains_decimal(),
            _ => false,
        }
    }
}

/// Attributes of one tool. Available in policies as `resource.readonly`,
/// `resource.sensitive`, `resource.destructive` and `resource.outbound`.
///
/// Unknown members are refused: a misspelt `sensitve = true` that was silently ignored would
/// leave the tool not sensitive, and a `forbid ... when { resource.sensitive }` would not apply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAttrs {
    /// The tool only reads; it never mutates state outside the agent.
    #[serde(default)]
    pub readonly: bool,
    /// The tool touches data or actions that warrant stronger user assurance (e.g. MFA).
    #[serde(default)]
    pub sensitive: bool,
    /// The tool can change or delete things in a way that matters (ADR-0009). Unset means
    /// `!readonly`, MCP's default for `destructiveHint`; read it with
    /// [`ToolAttrs::is_destructive`]. Set it to `false` for an additive tool (create an event,
    /// append to a file) that should not need an approval after an untrusted read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
    /// How the tool's results are labelled: `untrusted` (the default) taints the delegation
    /// run that reads them; `trusted` is recorded in the audit log but taints nothing. Mark a
    /// tool trusted only when its output cannot carry text an attacker chose (a balance from
    /// the user's own bank, a clock).
    #[serde(default, skip_serializing_if = "is_untrusted")]
    pub output: OutputLabel,
    /// Declared argument types. They type `context.input` for policy validation, and a call
    /// whose argument has another type is denied before Cedar (`input_type_mismatch`);
    /// arguments that are not declared are passed to Cedar unchecked.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, ArgType>,
    /// The input whose value run usage sums for this tool, `context.usage.amount`
    /// (run-limits design section 3.5). Only a destructive tool, or one with an
    /// [`outbound`](Self::outbound) argument, keeps usage. A value that is
    /// not a JSON integer of at least 0 adds nothing. When `inputs` declares it, it must be
    /// `long`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// The input that names where the call goes (a payee, a recipient), for
    /// `context.usage.destination_seen`. A list value counts each element. The server keeps
    /// only keyed hashes of the values, per run. `"<input>#host"` counts the host of a URL
    /// input instead of the whole value ([`attenuo_core::Derive::Host`]), so two pages of one
    /// site are one destination; a value with no host counts as itself, wrapped as
    /// `{"raw": value}` so it collides with no host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// The inputs whose values are delivered to a party the value names (a URL, a recipient):
    /// *outbound* arguments (read-side exfiltration design, option d). In the catalog either
    /// one name or a list, `outbound = "url#host"` or `outbound = ["url", "callback"]`; each
    /// entry is an input name with an optional `#host`, as for
    /// [`destination`](Self::destination). An outbound argument:
    ///
    /// - is a destination for run usage whatever `destructive` says, so a read-only fetch keeps
    ///   `context.usage` and a rule over `context.usage.destination_seen` applies to it. Its
    ///   values (hosts, with `#host`) are counted under the tool next to those of
    ///   `destination`, which stays the input for a tool whose payee is not outbound;
    /// - sets `context.untrusted_outbound` when argument taint matches it
    ///   ([`ToolAttrs::untrusted_outbound`]);
    /// - makes `resource.outbound` true ([`ToolAttrs::has_outbound`]).
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub outbound: Vec<String>,
}

/// A string or a list of strings, as a list.
fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged, expecting = "an input name or a list of input names")]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

fn is_untrusted(label: &OutputLabel) -> bool {
    *label == OutputLabel::Untrusted
}

impl ToolAttrs {
    /// No attributes: not read-only, not sensitive, `destructive` unset (so destructive), output
    /// untrusted, no declared inputs.
    pub fn new() -> Self {
        Self::default()
    }

    /// `destructive` as set, else `!readonly`.
    pub fn is_destructive(&self) -> bool {
        self.destructive.unwrap_or(!self.readonly)
    }

    /// Set `destructive` explicitly (see [`ToolAttrs::destructive`]).
    pub fn destructive(mut self, destructive: bool) -> Self {
        self.destructive = Some(destructive);
        self
    }

    /// Set how the tool's results are labelled (see [`ToolAttrs::output`]).
    pub fn output(mut self, output: OutputLabel) -> Self {
        self.output = output;
        self
    }

    /// These attributes made more restrictive by `narrowing`, never less: a tool the upstream
    /// says is not read-only stops being read-only (so an unset `destructive` becomes `true`
    /// through the `!readonly` default), and one it says is destructive becomes destructive.
    /// An explicit `destructive = false` in the catalog stays unless the upstream says
    /// `destructiveHint: true`.
    pub fn narrowed(&self, narrowing: &Narrowing) -> ToolAttrs {
        let mut out = self.clone();
        if narrowing.not_readonly {
            out.readonly = false;
        }
        if narrowing.destructive {
            out.destructive = Some(true);
        }
        out
    }

    /// Set `readonly` (see [`ToolAttrs::readonly`]).
    pub fn readonly(mut self, readonly: bool) -> Self {
        self.readonly = readonly;
        self
    }

    /// Set `sensitive` (see [`ToolAttrs::sensitive`]).
    pub fn sensitive(mut self, sensitive: bool) -> Self {
        self.sensitive = sensitive;
        self
    }

    /// Name the input run usage sums (see [`ToolAttrs::amount`]).
    pub fn with_amount(mut self, input: impl Into<String>) -> Self {
        self.amount = Some(input.into());
        self
    }

    /// Name the input that identifies the destination (see [`ToolAttrs::destination`]).
    pub fn with_destination(mut self, input: impl Into<String>) -> Self {
        self.destination = Some(input.into());
        self
    }

    /// Mark an input outbound, `"<input>"` or `"<input>#host"` (see [`ToolAttrs::outbound`]).
    pub fn with_outbound(mut self, input: impl Into<String>) -> Self {
        self.outbound.push(input.into());
        self
    }

    /// The tool has at least one outbound argument: `resource.outbound`.
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    /// The names of the outbound inputs, without any `#host`.
    pub fn outbound_inputs(&self) -> impl Iterator<Item = &str> {
        self.outbound
            .iter()
            .map(|r| r.rsplit_once('#').map_or(r.as_str(), |(arg, _)| arg))
    }

    /// `context.untrusted_outbound`: some argument in `untrusted` (the arguments that matched
    /// an untrusted result of the run, `context.untrusted_args`, including the fail-closed
    /// `unreadable` ones) is outbound.
    pub fn untrusted_outbound(&self, untrusted: &BTreeSet<String>) -> bool {
        self.outbound_inputs().any(|a| untrusted.contains(a))
    }

    /// Every argument name the entry names: the `inputs`, `amount`, `destination` and each
    /// `outbound` entry, the last two without a `#host` suffix. The names a call's arguments
    /// must not differ from only in case ([`crate::REASON_ARGUMENT_CASE_MISMATCH`]).
    pub fn argument_names(&self) -> impl Iterator<Item = &str> {
        fn strip(r: &str) -> &str {
            r.rsplit_once('#').map_or(r, |(arg, _)| arg)
        }
        self.inputs
            .keys()
            .map(String::as_str)
            .chain(self.amount.as_deref())
            .chain(self.destination.as_deref().map(strip))
            .chain(self.outbound_inputs())
    }

    /// Declare the type of an argument so policies that read `context.input.<name>` validate.
    pub fn with_input(mut self, name: impl Into<String>, ty: ArgType) -> Self {
        self.inputs.insert(name.into(), ty);
        self
    }
}

/// Whether MCP tool annotations from `tools/list` (`readOnlyHint`, `destructiveHint`) are
/// imported into the catalog (`[policy] import_annotations`, ADR-0009). Annotations come from
/// the upstream, which the threat model does not trust, so they can only narrow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationImport {
    /// Ignore annotations; the catalog alone decides. The default.
    #[default]
    Never,
    /// An explicit `readOnlyHint: false` clears `readonly`, and an explicit
    /// `destructiveHint: true` sets `destructive`. Nothing an annotation says can make a tool
    /// read-only, non-destructive or trusted. Narrowing is sticky for the life of the engine.
    Narrowing,
}

/// What imported annotations have narrowed for one tool (see [`AnnotationImport::Narrowing`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Narrowing {
    /// The upstream said `readOnlyHint: false`.
    pub not_readonly: bool,
    /// The upstream said `destructiveHint: true`.
    pub destructive: bool,
}

impl Narrowing {
    /// The narrowing explicit hints ask for. Absent hints, and hints that would widen
    /// (`readOnlyHint: true`, `destructiveHint: false`), ask for nothing.
    pub fn from_hints(read_only_hint: Option<bool>, destructive_hint: Option<bool>) -> Self {
        Self {
            not_readonly: read_only_hint == Some(false),
            destructive: destructive_hint == Some(true),
        }
    }

    /// Both narrowings together.
    pub fn union(self, other: Narrowing) -> Narrowing {
        Narrowing {
            not_readonly: self.not_readonly || other.not_readonly,
            destructive: self.destructive || other.destructive,
        }
    }

    /// No hint asked to narrow anything.
    pub fn is_empty(&self) -> bool {
        !self.not_readonly && !self.destructive
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
    /// Evaluate with `sensitive = true` (and `readonly = false`, so `destructive = true`).
    Sensitive,
    /// Evaluate with [`ToolAttrs::default`] (not read-only, so destructive; not sensitive).
    /// The behaviour before SR-12: `forbid` rules keyed on `sensitive` do not apply.
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
    /// An empty catalog: under the default [`UnknownTools::Deny`], every `tools/call` is denied.
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

    /// The entry for `(server, tool)`, if it is registered.
    pub(crate) fn entry(&self, server: &str, tool: &str) -> Option<&ToolAttrs> {
        self.tools.get(&(server.to_string(), tool.to_string()))
    }

    /// Is `(server, tool)` registered? Names are compared exactly.
    pub fn contains(&self, server: &str, tool: &str) -> bool {
        self.tools
            .contains_key(&(server.to_string(), tool.to_string()))
    }

    /// Number of registered `(server, tool)` pairs.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// No tool is registered.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Iterate over `((server, tool), attrs)` in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&(String, String), &ToolAttrs)> {
        self.tools.iter()
    }

    /// Check every server and tool name against [`attenuo_core::names`]: a server name has
    /// no `/`, and a tool is a tool name or an MCP method name (`resources/read`). A tool's
    /// `amount` and `destination` must name an input, and `amount` one not declared other than
    /// `long`; a `destination` with `#` must end in a known derivation (`#host`). Each
    /// `outbound` entry is checked as `destination` is, names its input once, and with `#host`
    /// names an input not declared other than `string` or `set<string>`. Called by
    /// [`PolicyEngineBuilder::build`](crate::PolicyEngineBuilder::build).
    ///
    /// # Errors
    ///
    /// A message naming the first offending `(server, tool)` entry, in order: an invalid server
    /// or call name, an empty `amount` or `destination`, a `destination` that
    /// [`parse_arg_ref`](attenuo_core::limits::parse_arg_ref) refuses, an `amount` whose input
    /// is declared with a type other than `long`, or an `outbound` entry that is empty, that
    /// `parse_arg_ref` refuses, that repeats an input, or whose `#host` names an input declared
    /// with a type other than `string` or `set<string>`.
    pub fn validate(&self) -> Result<(), String> {
        for ((server, tool), attrs) in &self.tools {
            attenuo_core::names::check_server_name(server)
                .and_then(|()| attenuo_core::names::check_call_name(tool))
                .map_err(|e| format!("catalog entry {server:?} / {tool:?}: {e}"))?;
            for (field, input) in [
                ("amount", &attrs.amount),
                ("destination", &attrs.destination),
            ] {
                if input.as_deref().is_some_and(str::is_empty) {
                    return Err(format!(
                        "catalog entry {server:?} / {tool:?}: `{field}` names no input"
                    ));
                }
            }
            if let Some(destination) = &attrs.destination {
                attenuo_core::limits::parse_arg_ref(destination).map_err(|e| {
                    format!("catalog entry {server:?} / {tool:?}: `destination` {e}")
                })?;
            }
            if let Some(input) = &attrs.amount {
                match attrs.inputs.get(input) {
                    None | Some(ArgType::Long) => {}
                    Some(ty) => {
                        return Err(format!(
                            "catalog entry {server:?} / {tool:?}: `amount` names input \
                             {input:?}, declared {}, not long",
                            ty.shown()
                        ))
                    }
                }
            }
            let mut seen = BTreeSet::new();
            for entry in &attrs.outbound {
                let at = || format!("catalog entry {server:?} / {tool:?}: `outbound`");
                if entry.is_empty() {
                    return Err(format!("{}: an entry names no input", at()));
                }
                let (input, derive) = attenuo_core::limits::parse_arg_ref(entry)
                    .map_err(|e| format!("{} {e}", at()))?;
                if !seen.insert(input.clone()) {
                    return Err(format!("{} names input {input:?} twice", at()));
                }
                if derive.is_some() {
                    match attrs.inputs.get(&input) {
                        None | Some(ArgType::String) => {}
                        Some(ArgType::Set(inner)) if **inner == ArgType::String => {}
                        Some(ty) => {
                            return Err(format!(
                                "{} `{entry}`: input {input:?} is declared {}; `#host` needs \
                                 a string (or a set of strings)",
                                at(),
                                ty.shown()
                            ))
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// What is likely a mistake in the catalog but does not stop it loading, one message per
    /// problem, in `(server, tool)` order: an `outbound` entry naming an input that the tool's
    /// `inputs` do not declare, when it declares some (a misspelt name would leave the real
    /// argument unwatched). A tool that declares no inputs is not checked. The engine adds
    /// these to [`PolicyEngine::validation_warnings`](crate::PolicyEngine::validation_warnings).
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for ((server, tool), attrs) in &self.tools {
            if attrs.inputs.is_empty() {
                continue;
            }
            for input in attrs.outbound_inputs() {
                if !attrs.inputs.contains_key(input) {
                    out.push(format!(
                        "catalog entry {server:?} / {tool:?}: `outbound` names input {input:?}, \
                         which `inputs` does not declare"
                    ));
                }
            }
        }
        out
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CallLabels, Decision, PolicyEngine, PolicyEngineBuilder};
    use attenuo_core::{
        AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser, ToolCall,
    };
    use serde_json::{json, Value};
    use time::{Duration, OffsetDateTime};

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_762_400_000).unwrap()
    }

    fn chain() -> DelegationChain {
        DelegationChain::root(
            OriginatingUser {
                subject: "alice".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: now(),
                attributes: Default::default(),
            },
            AgentId::new("planner"),
            CapabilitySet::from_iter([
                Capability::new("banking", "*"),
                Capability::new("web", "*"),
            ]),
            now(),
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap()
    }

    fn engine(attrs: ToolAttrs, policies: &str) -> Result<PolicyEngine, crate::PolicyError> {
        PolicyEngineBuilder::new()
            .with_catalog(ToolCatalog::new().with("banking", "send_money", attrs))
            .with_policies_str(policies)
            .build()
    }

    fn send(engine: &PolicyEngine, amount: Value) -> crate::Outcome {
        engine.authorize_labelled(
            &chain(),
            &ToolCall::new(
                "banking",
                "send_money",
                json!({"recipient": "A", "amount": amount}),
            ),
            &CallLabels::default(),
            now(),
        )
    }

    /// Today, with `amount` not declared: `context.input` is a closed record, so a policy that
    /// reads `context.input.amount` fails to load, and one that guards it with `has` loads
    /// with a "policy is impossible" warning. Evaluation is schema-free, though: the guarded
    /// rule still runs, a fraction reaches it as a Cedar `decimal`, and comparing that with
    /// `>` is a type error, so the call is denied as `policy_error`. A whole amount is a `Long`
    /// and the rule applies to it.
    #[test]
    fn an_undeclared_fractional_amount_cannot_be_read_by_a_policy() {
        let err = engine(
            ToolAttrs::new(),
            r#"forbid(principal, action, resource) when { context.input.amount > 100 };"#,
        )
        .unwrap_err();
        assert!(matches!(err, crate::PolicyError::Validation(_)), "{err}");

        let guarded = engine(
            ToolAttrs::new(),
            r#"permit(principal, action, resource);
               forbid(principal, action, resource) when {
                 context.input has amount && context.input.amount > 100 };"#,
        )
        .unwrap();
        assert!(
            guarded
                .validation_warnings()
                .iter()
                .any(|w| w.contains("policy is impossible")),
            "{:?}",
            guarded.validation_warnings()
        );
        let out = send(&guarded, json!(12.5));
        assert_eq!(out.reason, crate::REASON_POLICY_ERROR, "{out:?}");
        assert_eq!(send(&guarded, json!(500)).reason, crate::REASON_POLICY_DENY);
        assert_eq!(send(&guarded, json!(12)).decision, Decision::Allow);

        let open = engine(ToolAttrs::new(), r#"permit(principal, action, resource);"#).unwrap();
        assert_eq!(send(&open, json!(12.5)).decision, Decision::Allow);
    }

    /// Today, with `amount` declared `long`: a fraction is refused before Cedar.
    #[test]
    fn a_fractional_amount_declared_long_is_an_input_type_mismatch() {
        let e = engine(
            ToolAttrs::new().with_input("amount", ArgType::Long),
            r#"permit(principal, action, resource);"#,
        )
        .unwrap();
        let out = send(&e, json!(12.5));
        assert_eq!(out.reason, crate::REASON_INPUT_TYPE_MISMATCH);
        assert_eq!(
            out.diagnostics,
            vec!["input.amount: expected Long, got number".to_string()]
        );
        assert_eq!(send(&e, json!(12.0)).decision, Decision::Allow);
    }

    #[test]
    fn decimal_parses_and_is_a_catalog_input_type_only() {
        assert_eq!(" Decimal ".parse::<ArgType>().unwrap(), ArgType::Decimal);
        assert_eq!(
            "set<decimal>".parse::<ArgType>().unwrap(),
            ArgType::Set(Box::new(ArgType::Decimal))
        );
        let decls = BTreeMap::from([("limit".to_string(), "set<decimal>".to_string())]);
        let err = parse_user_attributes(&decls).unwrap_err();
        assert!(
            err.starts_with("user_attributes.limit: decimal is a catalog input type only"),
            "{err}"
        );
        let err = PolicyEngineBuilder::new()
            .with_user_attr("limit", ArgType::Decimal)
            .build()
            .err()
            .unwrap();
        assert!(matches!(err, crate::PolicyError::Schema(_)), "{err}");
        // The TOML and JSON catalog spelling.
        let attrs: ToolAttrs =
            serde_json::from_value(json!({"inputs": {"amount": "decimal"}})).unwrap();
        assert_eq!(attrs.inputs["amount"], ArgType::Decimal);
        // A run-usage `amount` still has to be a long.
        let err = ToolCatalog::new()
            .with("banking", "send_money", attrs.with_amount("amount"))
            .validate()
            .unwrap_err();
        assert!(err.ends_with("declared decimal, not long"), "{err}");
    }

    /// With `amount` declared `decimal`, a policy compares it with the decimal methods, for
    /// whole and fractional values alike, and a value that is not a decimal is refused before
    /// Cedar.
    #[test]
    fn a_decimal_amount_is_compared_in_a_policy() {
        let e = engine(
            ToolAttrs::new().with_input("amount", ArgType::Decimal),
            r#"@id("small") permit(principal, action == Action::"banking/send_money", resource)
               when { context.input has amount &&
                      context.input.amount.lessThan(decimal("100.0")) };"#,
        )
        .unwrap();
        for amount in [json!(12.5), json!(99.9999), json!(12), json!(0)] {
            let out = send(&e, amount.clone());
            assert_eq!(out.decision, Decision::Allow, "{amount} {out:?}");
            assert_eq!(out.policy_ids, vec!["small".to_string()]);
        }
        for amount in [json!(100), json!(100.0), json!(250.75)] {
            let out = send(&e, amount.clone());
            assert_eq!(out.reason, crate::REASON_POLICY_DENY, "{amount} {out:?}");
        }
        for amount in [json!(12.34567), json!("12.5"), json!(1e300)] {
            let out = send(&e, amount.clone());
            assert_eq!(
                out.reason,
                crate::REASON_INPUT_TYPE_MISMATCH,
                "{amount} {out:?}"
            );
        }
    }

    fn fetch_catalog(attrs: ToolAttrs) -> ToolCatalog {
        ToolCatalog::new().with("web", "fetch", attrs)
    }

    /// `outbound` is one name or a list, in TOML and JSON alike, and always a list in Rust.
    #[test]
    fn outbound_is_one_input_or_a_list() {
        let t: BTreeMap<String, ToolAttrs> = toml::from_str(
            r#"
            [fetch]
            readonly = true
            inputs = { url = "string" }
            outbound = "url#host"

            [post]
            outbound = ["url", "callback#host"]

            [read]
            readonly = true
            "#,
        )
        .unwrap();
        assert_eq!(t["fetch"].outbound, vec!["url#host".to_string()]);
        assert!(t["fetch"].has_outbound() && t["fetch"].readonly);
        assert_eq!(t["post"].outbound, vec!["url", "callback#host"]);
        assert_eq!(
            t["post"].outbound_inputs().collect::<Vec<_>>(),
            vec!["url", "callback"]
        );
        assert!(!t["read"].has_outbound());
        let j: ToolAttrs = serde_json::from_value(json!({"outbound": ["url"]})).unwrap();
        assert_eq!(j, ToolAttrs::new().with_outbound("url"));
        let err = serde_json::from_value::<ToolAttrs>(json!({"outbound": 3})).unwrap_err();
        assert!(
            err.to_string()
                .contains("an input name or a list of input names"),
            "{err}"
        );
        // Serialised as a list, and left out when empty.
        assert_eq!(
            serde_json::to_value(ToolAttrs::new().with_outbound("url#host")).unwrap()["outbound"],
            json!(["url#host"])
        );
        assert!(serde_json::to_value(ToolAttrs::new())
            .unwrap()
            .get("outbound")
            .is_none());
        // Which matched arguments are outbound.
        let untrusted: BTreeSet<String> = ["body".to_string(), "callback".to_string()].into();
        assert!(t["post"].untrusted_outbound(&untrusted));
        assert!(!t["fetch"].untrusted_outbound(&untrusted));
        assert!(!t["read"].untrusted_outbound(&untrusted));
    }

    #[test]
    fn outbound_entries_are_checked_at_load() {
        let ok = fetch_catalog(
            ToolAttrs::new()
                .with_input("url", ArgType::String)
                .with_input("urls", ArgType::Set(Box::new(ArgType::String)))
                .with_outbound("url#host")
                .with_outbound("urls#host")
                .with_outbound("undeclared#host"),
        );
        assert_eq!(ok.validate(), Ok(()));
        let refused = |attrs: ToolAttrs| fetch_catalog(attrs).validate().unwrap_err();
        let err = refused(
            ToolAttrs::new()
                .with_input("port", ArgType::Long)
                .with_outbound("port#host"),
        );
        assert!(
            err.contains("`outbound` `port#host`: input \"port\" is declared Long"),
            "{err}"
        );
        // A non-string input may still be outbound without `#host`: it counts as itself.
        assert_eq!(
            fetch_catalog(
                ToolAttrs::new()
                    .with_input("port", ArgType::Long)
                    .with_outbound("port")
            )
            .validate(),
            Ok(())
        );
        let err = refused(ToolAttrs::new().with_outbound(""));
        assert!(
            err.ends_with("`outbound`: an entry names no input"),
            "{err}"
        );
        let err = refused(ToolAttrs::new().with_outbound("url#path"));
        assert!(err.contains("unknown derivation `path`"), "{err}");
        let err = refused(ToolAttrs::new().with_outbound("#host"));
        assert!(err.contains("names no argument before `#`"), "{err}");
        let err = refused(
            ToolAttrs::new()
                .with_outbound("url")
                .with_outbound("url#host"),
        );
        assert!(err.ends_with("names input \"url\" twice"), "{err}");
    }

    /// A name the tool's `inputs` do not declare is a warning, not an error, and only when the
    /// tool declares inputs at all. The engine reports it with the policy warnings.
    #[test]
    fn an_undeclared_outbound_input_is_a_warning() {
        let c = fetch_catalog(
            ToolAttrs::new()
                .with_input("url", ArgType::String)
                .with_outbound("uri#host"),
        )
        .with("web", "ping", ToolAttrs::new().with_outbound("host"));
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(
            c.warnings(),
            vec![
                "catalog entry \"web\" / \"fetch\": `outbound` names input \"uri\", which \
                 `inputs` does not declare"
                    .to_string()
            ]
        );
        let engine = PolicyEngineBuilder::new()
            .with_catalog(c)
            .with_policies_str("permit(principal, action, resource);")
            .build()
            .unwrap();
        assert_eq!(engine.validation_warnings(), [c_warning()]);
        let mut engine = engine;
        engine
            .reload_policies_str("permit(principal, action, resource);")
            .unwrap();
        assert_eq!(engine.validation_warnings(), [c_warning()]);
    }

    fn c_warning() -> String {
        "catalog entry \"web\" / \"fetch\": `outbound` names input \"uri\", which `inputs` does \
         not declare"
            .to_string()
    }

    fn fetch(engine: &PolicyEngine, labels: &CallLabels) -> crate::Outcome {
        engine.authorize_labelled(
            &chain(),
            &ToolCall::new(
                "web",
                "fetch",
                json!({"url": "https://a.example/", "note": "x"}),
            ),
            labels,
            now(),
        )
    }

    /// `resource.outbound` and `context.untrusted_outbound` validate against the generated
    /// schema, and say what the catalog and the matched arguments say.
    #[test]
    fn policies_read_resource_outbound_and_context_untrusted_outbound() {
        let policies = r#"
            @id("open") permit(principal, action, resource);
            @id("ask_on_untrusted_outbound") @obligation("approval")
            forbid(principal, action, resource)
            when { context.untrusted_outbound == true && !context.approval.present };
            @id("outbound_tools") forbid(principal, action, resource)
            when { resource.outbound && context.input has note && context.input.note == "deny" };
        "#;
        let build = |attrs: ToolAttrs| {
            PolicyEngineBuilder::new()
                .with_catalog(fetch_catalog(
                    attrs
                        .readonly(true)
                        .with_input("url", ArgType::String)
                        .with_input("note", ArgType::String),
                ))
                .with_policies_str(policies)
                .build()
                .unwrap()
        };
        let flagged = build(ToolAttrs::new().with_outbound("url#host"));
        assert!(flagged.validation_warnings().is_empty());
        assert!(
            flagged.reads_arg_taint(),
            "reading untrusted_outbound reads arg taint"
        );
        let plain = build(ToolAttrs::new());
        let labels = |args: &[&str]| CallLabels {
            session: crate::SessionLabels::from_sources(["web/fetch"]),
            args: crate::ArgLabels::from_args(args.iter().copied()),
            ..CallLabels::default()
        };
        // The outbound argument matched: ask.
        let out = fetch(&flagged, &labels(&["url"]));
        assert_eq!(out.reason, crate::REASON_APPROVAL_REQUIRED, "{out:?}");
        assert_eq!(
            out.policy_ids,
            vec!["ask_on_untrusted_outbound".to_string()]
        );
        // Only another argument matched: no ask.
        assert_eq!(
            fetch(&flagged, &labels(&["note"])).decision,
            Decision::Allow
        );
        assert_eq!(fetch(&flagged, &labels(&[])).decision, Decision::Allow);
        // No outbound input in the catalog: a matched `url` is not outbound.
        assert_eq!(fetch(&plain, &labels(&["url"])).decision, Decision::Allow);

        // `resource.outbound`: true with the flag, false without.
        let deny_note = |e: &PolicyEngine| {
            e.authorize_labelled(
                &chain(),
                &ToolCall::new("web", "fetch", json!({"url": "u", "note": "deny"})),
                &CallLabels::default(),
                now(),
            )
        };
        assert_eq!(deny_note(&flagged).reason, crate::REASON_POLICY_DENY);
        assert_eq!(deny_note(&plain).decision, Decision::Allow);
    }

    /// A custom base schema written before `outbound` existed still loads; only a policy that
    /// reads `resource.outbound` needs it declared.
    #[test]
    fn a_custom_base_without_outbound_still_loads() {
        let base = crate::DEFAULT_SCHEMA.replace("    outbound: Bool,\n", "");
        assert!(!base.contains("outbound"));
        let build = |p: &str| {
            PolicyEngineBuilder::new()
                .with_catalog(fetch_catalog(ToolAttrs::new().with_outbound("url")))
                .with_schema_str(&base)
                .with_policies_str(p)
                .build()
        };
        build("permit(principal, action, resource) when { context.untrusted_outbound };").unwrap();
        let err =
            build("permit(principal, action, resource) when { resource.outbound };").unwrap_err();
        assert!(matches!(err, crate::PolicyError::Validation(_)), "{err}");
    }
}
