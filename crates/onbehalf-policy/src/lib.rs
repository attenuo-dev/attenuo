//! Policy decision point for `onbehalf`.
//!
//! Given a verified [`DelegationChain`] and a [`ToolCall`], [`PolicyEngine::authorize`] decides
//! [`Decision::Allow`] or [`Decision::Deny`] in two stages:
//!
//! 1. **Capability stage** (structural, always on). The call must be permitted by the
//!    capabilities in force for the current agent, `chain.effective_capabilities()`. This is
//!    what makes attenuation bite: no policy can grant what the chain did not delegate.
//!    Reason code: `capability_denied`.
//! 2. **Cedar stage**. The call is evaluated against the loaded [Cedar](https://www.cedarpolicy.com)
//!    policies. Cedar's semantics apply: any matching `forbid` wins, otherwise at least one
//!    `permit` must match, otherwise deny. Reason codes: `policy_allow`, `policy_deny`.
//!    The policies that determined the outcome are reported in [`Outcome::policy_ids`]
//!    (use `@id("...")` annotations to name them).
//!
//! The engine fails closed. If the request cannot be translated into Cedar terms, or if any
//! policy raises an evaluation error (Cedar would otherwise silently skip that policy, which
//! for a `forbid` means a silent grant), the outcome is Deny with reason `policy_error` and the
//! details in [`Outcome::diagnostics`].
//!
//! Declared `originating_user.attributes` types (the built-in `mfa`, `roles`, `tenant`,
//! `email` and anything added with [`PolicyEngineBuilder::with_user_attr`]) are enforced at
//! this boundary: a value of another type is denied with reason `attribute_type_mismatch`
//! rather than passed on, because Cedar's `!=` across types is `true` and would let a
//! `!= "suspended"` permit fire on `["suspended"]`. Nothing is coerced.
//!
//! # Request shape
//!
//! The Cedar request mirrors the shape used by AWS Bedrock AgentCore policies, so policies
//! port in either direction with little more than renaming.
//!
//! | Part        | Value |
//! |-------------|-------|
//! | `principal` | `Agent::"<current agent id>"` (the last hop of the chain) |
//! | `action`    | `Action::"<server>/<tool>"`, a member of the generic `Action::"invoke"` |
//! | `resource`  | `Tool::"<server>/<tool>"`, `in` its `Server::"<server>"` |
//! | `context`   | the record below |
//!
//! ```json
//! {
//!   "input": { "...": "the call's arguments, verbatim (see below)" },
//!   "originating_user": {
//!     "subject": "alice",
//!     "issuer": "https://idp.example",
//!     "attributes": { "mfa": true, "roles": ["dev"] },
//!     "authenticated_at_unix": 1760000000
//!   },
//!   "chain": {
//!     "depth": 2,
//!     "agents": ["planner", "coder"],
//!     "root_agent": "planner",
//!     "leases": ["l1", "l2"]
//!   },
//!   "session_id": "s-123",
//!   "now_unix": 1760000100
//! }
//! ```
//!
//! Through the MCP proxy, `session_id` is a 12-hex-digit SHA-256 prefix of the `Mcp-Session-Id`,
//! never the id itself. It is **absent** when the call carries none (Cedar has no `null`); test it with
//! `context has session_id`. The same goes for every `null` inside `input` and
//! `originating_user.attributes`: null-valued members are dropped, so write
//! `context.input has repo && context.input.repo like "acme/*"`. Integers (and floats with no
//! fractional part, so `5.0` is `5`) are Cedar `Long`, other floats are Cedar `decimal`, and
//! argument keys beginning with `__` are rejected (Cedar reserves them for escapes).
//!
//! ## Entities
//!
//! | Entity | Attributes | Parents |
//! |--------|-----------|---------|
//! | `User::"<subject>"` | `subject`, `issuer`, `authenticated_at_unix`, `attributes` (record) | none |
//! | `Agent::"<id>"`, one per hop | `id`, `chain_depth` (1-based position of the hop) | the `User`, and the previous hop's `Agent` |
//! | `Server::"<server>"` | `name` | none |
//! | `Tool::"<server>/<tool>"` | `server`, `name`, `readonly`, `sensitive` (from the [`ToolCatalog`]) | the `Server` |
//!
//! So policies can say `principal in User::"alice"`, `principal in Agent::"planner"`,
//! `resource in Server::"github"`, `resource.readonly`, or `principal.chain_depth > 2`.
//!
//! ## Actions are server-scoped (SR-13)
//!
//! The action id names the server: `action == Action::"github/read_file"` matches `read_file`
//! on `github` only, never `evil/read_file`. Server names cannot contain `/` and tool names
//! cannot either (except the MCP method names the proxy maps other requests to, such as
//! `resources/read`), see [`onbehalf_core::names`]; a call with a name outside those rules is
//! denied with reason `invalid_name` before anything else runs, and so is a catalog entry at
//! build time.
//!
//! Before SR-13 the action was the bare tool name, `Action::"read_file"`, which matched that
//! tool on every server. That form is still available, deprecated, behind
//! [`PolicyEngineBuilder::with_legacy_bare_actions`] (`[policy] legacy_bare_actions = true`);
//! the two forms cannot be mixed in one policy set. [`lint`] flags bare actions.
//!
//! ## Schema and validation
//!
//! Every policy set is validated (Cedar strict mode) against a schema at load time, and
//! validation errors are returned as [`PolicyError::Validation`]. The schema is the base
//! entity schema ([`DEFAULT_SCHEMA`], or [`PolicyEngineBuilder::with_schema_str`]) plus a
//! generated fragment: one action per catalog entry, typed `context.input`
//! attributes from [`ToolAttrs::inputs`], and `UserAttributes` from
//! [`PolicyEngineBuilder::with_user_attr`]. Because Cedar requires actions to be declared, a
//! policy that names `Action::"s/x"` validates only if the catalog has tool `x` on server `s`.
//! Evaluation itself is schema-free. A call to a tool that is not in the catalog is handled
//! as [`UnknownTools`] says: denied with reason `tool_not_in_catalog` by default
//! ([`PolicyEngineBuilder::with_unknown_tools`]), evaluated as sensitive, or evaluated with
//! default attributes.
//!
//! A starter policy set lives in `policies/default.cedar` ([`DEFAULT_POLICIES`]).
//!
//! # Example
//!
//! ```
//! use onbehalf_core::{AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser, ToolCall};
//! use onbehalf_policy::{PolicyEngineBuilder, ToolAttrs, ToolCatalog, ArgType};
//! use serde_json::json;
//! use time::{Duration, OffsetDateTime};
//!
//! let now = OffsetDateTime::now_utc();
//! let user = OriginatingUser {
//!     subject: "alice".into(),
//!     issuer: "https://idp.example".into(),
//!     authenticated_at: now,
//!     attributes: Default::default(),
//! };
//! let chain = DelegationChain::root(
//!     user,
//!     AgentId::new("coder"),
//!     CapabilitySet::from_iter([Capability::new("github", "*")]),
//!     now,
//!     Duration::hours(1),
//!     LeaseId::new("l1"),
//! )
//! .unwrap();
//!
//! let engine = PolicyEngineBuilder::new()
//!     .with_catalog(ToolCatalog::new().with(
//!         "github",
//!         "read_file",
//!         ToolAttrs::new().readonly(true).with_input("repo", ArgType::String),
//!     ))
//!     .with_policies_str(
//!         r#"@id("public_only")
//!            permit(principal, action == Action::"github/read_file", resource)
//!            when { context.input has repo && context.input.repo like "alice/public-*" };"#,
//!     )
//!     .build()
//!     .unwrap();
//!
//! let ok = engine.authorize(&chain, &ToolCall::new("github", "read_file", json!({"repo": "alice/public-site"})), now);
//! assert!(ok.decision.is_allow());
//! assert_eq!(ok.policy_ids, vec!["public_only"]);
//!
//! let no = engine.authorize(&chain, &ToolCall::new("github", "read_file", json!({"repo": "alice/private-salaries"})), now);
//! assert_eq!(no.reason, "policy_deny");
//! ```

#![forbid(unsafe_code)]

pub mod authzen;
mod catalog;
mod lint;
mod request;
mod schema;
pub mod testing;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Decision as CedarDecision, Policy, PolicyId, PolicySet, Request, Schema, Template,
    ValidationMode, Validator,
};
use onbehalf_core::{Decision, DelegationChain, ToolCall};
use time::OffsetDateTime;

pub use catalog::{parse_user_attributes, ArgType, ToolAttrs, ToolCatalog, UnknownTools};
pub use lint::{lint, LintIssue, LintReport, LintSeverity};
pub use lint::{lint_with_options, LintOptions};
pub use schema::{action_id, default_user_attrs, DEFAULT_SCHEMA, GENERIC_ACTION};

/// The starter policy set shipped with the crate (`policies/default.cedar`).
///
/// It references `Action::"github/create_issue"`, so it validates only when the catalog
/// registers a `create_issue` tool on server `github`.
pub const DEFAULT_POLICIES: &str = include_str!("../policies/default.cedar");

/// Reason code when the capability stage denies.
pub const REASON_CAPABILITY_DENIED: &str = "capability_denied";
/// Reason code when Cedar allows.
pub const REASON_POLICY_ALLOW: &str = "policy_allow";
/// Reason code when Cedar denies (explicit `forbid` or no matching `permit`).
pub const REASON_POLICY_DENY: &str = "policy_deny";
/// Reason code when the request could not be evaluated safely; always a deny.
pub const REASON_POLICY_ERROR: &str = "policy_error";
/// Reason code when the tool is not in the catalog and [`UnknownTools::Deny`] is in force.
pub const REASON_TOOL_NOT_IN_CATALOG: &str = "tool_not_in_catalog";

/// Reason code when the call's server or tool name breaks [`onbehalf_core::names`].
pub const REASON_INVALID_NAME: &str = "invalid_name";

/// Reason code when an originating-user attribute does not have its declared type (SR-33).
pub const REASON_ATTRIBUTE_TYPE_MISMATCH: &str = "attribute_type_mismatch";

/// Errors from loading policies or schema.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The policy text does not parse.
    #[error("policy parse error: {0}")]
    Parse(String),
    /// The policies parse but do not type-check against the schema.
    #[error("policy validation error: {0}")]
    Validation(String),
    /// The schema text does not parse.
    #[error("schema error: {0}")]
    Schema(String),
    /// A catalog entry names a server or tool that breaks [`onbehalf_core::names`].
    #[error("tool catalog: {0}")]
    Catalog(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The result of one authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    /// One of `invalid_name`, `capability_denied`, `tool_not_in_catalog`, `attribute_type_mismatch`,
    /// `policy_allow`, `policy_deny`, `policy_error`.
    pub reason: String,
    /// Ids of the policies that determined the decision (permits that matched for an allow,
    /// forbids that matched for a deny). Empty for a capability denial or a default deny.
    pub policy_ids: Vec<String>,
    /// Human-readable details: evaluation errors, translation problems, capability mismatches.
    pub diagnostics: Vec<String>,
}

impl Outcome {
    fn deny(reason: &str, diagnostics: Vec<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.to_string(),
            policy_ids: Vec::new(),
            diagnostics,
        }
    }
}

#[derive(Debug, Clone)]
enum PolicySource {
    Text(String),
    File(PathBuf),
}

/// Builder for [`PolicyEngine`].
#[derive(Debug, Clone)]
pub struct PolicyEngineBuilder {
    policy_sources: Vec<PolicySource>,
    base_schema: String,
    catalog: ToolCatalog,
    user_attrs: BTreeMap<String, ArgType>,
    unknown_tools: UnknownTools,
    legacy_bare_actions: bool,
}

impl Default for PolicyEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngineBuilder {
    pub fn new() -> Self {
        Self {
            policy_sources: Vec::new(),
            base_schema: DEFAULT_SCHEMA.to_string(),
            catalog: ToolCatalog::new(),
            user_attrs: default_user_attrs(),
            unknown_tools: UnknownTools::default(),
            legacy_bare_actions: false,
        }
    }

    /// Use the pre-SR-13 action ids, the bare tool name (`Action::"read_file"`), instead of
    /// `Action::"<server>/<tool>"`. **Deprecated**: a bare action matches that tool on every
    /// server. Off by default; meant only to keep an old policy set loading while it is
    /// rewritten. Callers should warn when it is on.
    pub fn with_legacy_bare_actions(mut self, on: bool) -> Self {
        self.legacy_bare_actions = on;
        self
    }

    /// What to do with calls to tools that are not in the catalog. Default
    /// [`UnknownTools::Deny`].
    pub fn with_unknown_tools(mut self, unknown_tools: UnknownTools) -> Self {
        self.unknown_tools = unknown_tools;
        self
    }

    /// Add Cedar policy text. May be called more than once; the sources are concatenated.
    pub fn with_policies_str(mut self, policies: &str) -> Self {
        self.policy_sources
            .push(PolicySource::Text(policies.to_string()));
        self
    }

    /// Add Cedar policy text read from `path` at build time. The builder stays infallible;
    /// an unreadable file surfaces as [`PolicyError::Io`] from [`build`](Self::build).
    pub fn with_policies_file(mut self, path: impl AsRef<Path>) -> Self {
        self.policy_sources
            .push(PolicySource::File(path.as_ref().to_path_buf()));
        self
    }

    /// Replace the base (entity) schema. See [`DEFAULT_SCHEMA`] for what it must declare.
    /// Actions and context types are still generated and appended.
    pub fn with_schema_str(mut self, schema: &str) -> Self {
        self.base_schema = schema.to_string();
        self
    }

    /// Set the tool catalog (tool attributes and declared actions).
    pub fn with_catalog(mut self, catalog: ToolCatalog) -> Self {
        self.catalog = catalog;
        self
    }

    /// Declare (or re-type) an attribute of `originating_user.attributes` for validation.
    pub fn with_user_attr(mut self, name: impl Into<String>, ty: ArgType) -> Self {
        self.user_attrs.insert(name.into(), ty);
        self
    }

    /// The complete schema text this builder would validate against.
    pub fn schema_text(&self) -> String {
        schema::generate(
            &self.base_schema,
            &self.catalog,
            &self.user_attrs,
            self.legacy_bare_actions,
        )
    }

    pub fn build(self) -> Result<PolicyEngine, PolicyError> {
        self.catalog.validate().map_err(PolicyError::Catalog)?;
        let schema_text = self.schema_text();
        let (schema, _warnings) = Schema::from_cedarschema_str(&schema_text)
            .map_err(|e| PolicyError::Schema(e.to_string()))?;
        let mut text = String::new();
        for src in &self.policy_sources {
            match src {
                PolicySource::Text(t) => text.push_str(t),
                PolicySource::File(path) => text.push_str(&std::fs::read_to_string(path)?),
            }
            text.push('\n');
        }
        let (policies, warnings) = load_policies(&text, &schema)?;
        Ok(PolicyEngine {
            schema,
            schema_text,
            policies,
            catalog: self.catalog,
            user_attrs: self.user_attrs,
            unknown_tools: self.unknown_tools,
            legacy_bare_actions: self.legacy_bare_actions,
            authorizer: Authorizer::new(),
            validation_warnings: warnings,
        })
    }
}

/// Parse, re-id (from `@id` annotations) and validate a policy set.
fn load_policies(text: &str, schema: &Schema) -> Result<(PolicySet, Vec<String>), PolicyError> {
    let parsed = PolicySet::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
    let policies = apply_id_annotations(&parsed)?;
    let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
    if !result.validation_passed() {
        let msgs: Vec<String> = result
            .validation_errors()
            .map(|e| format!("[{}] {e}", e.policy_id()))
            .collect();
        return Err(PolicyError::Validation(msgs.join("; ")));
    }
    let warnings = result
        .validation_warnings()
        .map(|w| format!("[{}] {w}", w.policy_id()))
        .collect();
    Ok((policies, warnings))
}

/// Cedar names policies `policy0`, `policy1`, ... when parsing a set. Rename each one that
/// carries an `@id("...")` annotation so reports and audit records use stable names.
fn apply_id_annotations(parsed: &PolicySet) -> Result<PolicySet, PolicyError> {
    let mut out = PolicySet::new();
    let mut add_policy = |p: Policy| {
        out.add(p)
            .map_err(|e| PolicyError::Parse(format!("duplicate or invalid policy id: {e}")))
    };
    for p in parsed.policies() {
        match p.annotation("id") {
            Some(id) => add_policy(p.new_id(PolicyId::new(id)))?,
            None => add_policy(p.clone())?,
        }
    }
    let mut add_template = |t: Template| {
        out.add_template(t)
            .map_err(|e| PolicyError::Parse(format!("duplicate or invalid template id: {e}")))
    };
    for t in parsed.templates() {
        match t.annotation("id") {
            Some(id) => add_template(t.new_id(PolicyId::new(id)))?,
            None => add_template(t.clone())?,
        }
    }
    Ok(out)
}

/// The policy decision point. Cheap to clone the parts that matter; build once per policy
/// version and share behind an `Arc`/`RwLock` if you need hot reload across threads.
#[derive(Debug)]
pub struct PolicyEngine {
    schema: Schema,
    schema_text: String,
    policies: PolicySet,
    catalog: ToolCatalog,
    user_attrs: BTreeMap<String, ArgType>,
    unknown_tools: UnknownTools,
    legacy_bare_actions: bool,
    authorizer: Authorizer,
    validation_warnings: Vec<String>,
}

impl PolicyEngine {
    /// Decide whether `call` may proceed for the agent at the end of `chain`, at time `now`.
    ///
    /// The chain is assumed to have been verified and `validate_at`-ed already; this method
    /// does not check signatures or expiry.
    pub fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> Outcome {
        // Stage 0: names. A name outside the rules could not have come from a well-behaved
        // client, and `/` in a server name would make the action and resource ids ambiguous.
        if let Err(e) = call.check_names() {
            return Outcome::deny(REASON_INVALID_NAME, vec![e.to_string()]);
        }

        // Stage 1: capabilities.
        let Some(caps) = chain.effective_capabilities() else {
            return Outcome::deny(
                REASON_CAPABILITY_DENIED,
                vec!["delegation chain has no hops".to_string()],
            );
        };
        if !caps.permits(call) {
            let have: Vec<String> = caps.iter().map(|c| c.display()).collect();
            return Outcome::deny(
                REASON_CAPABILITY_DENIED,
                vec![format!(
                    "call {}:{} is not permitted by the effective capabilities [{}]",
                    call.server,
                    call.tool,
                    have.join(", ")
                )],
            );
        }

        // Stage 1b: the catalog. An unclassified tool would otherwise get default attributes,
        // so every `forbid ... when { resource.sensitive }` would fail open for it.
        let attrs = if self.catalog.contains(&call.server, &call.tool) {
            self.catalog.get(&call.server, &call.tool)
        } else {
            match self.unknown_tools {
                UnknownTools::Deny => {
                    return Outcome::deny(
                        REASON_TOOL_NOT_IN_CATALOG,
                        vec![format!(
                            "tool {}:{} is not in the tool catalog",
                            call.server, call.tool
                        )],
                    )
                }
                UnknownTools::Sensitive => ToolAttrs::new().sensitive(true),
                UnknownTools::Allow => ToolAttrs::default(),
            }
        };

        // Stage 1c: declared attribute types. Evaluation is schema-free, and Cedar's `!=`
        // across types is `true` without an error, so a value of the wrong type (a list where
        // a string is declared) would make `attributes.status != "suspended"` permit.
        if let Err(e) = request::check_user_attributes(&chain.originating_user, &self.user_attrs) {
            return Outcome::deny(REASON_ATTRIBUTE_TYPE_MISMATCH, vec![e]);
        }

        // Stage 2: Cedar.
        let req = match request::build(chain, call, &attrs, now, self.legacy_bare_actions) {
            Ok(r) => r,
            Err(e) => return Outcome::deny(REASON_POLICY_ERROR, vec![e.to_string()]),
        };
        let request = match Request::new(req.principal, req.action, req.resource, req.context, None)
        {
            Ok(r) => r,
            Err(e) => return Outcome::deny(REASON_POLICY_ERROR, vec![e.to_string()]),
        };
        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &req.entities);
        let diagnostics = response.diagnostics();
        let errors: Vec<String> = diagnostics.errors().map(|e| e.to_string()).collect();
        let policy_ids: Vec<String> = diagnostics.reason().map(|id| id.to_string()).collect();
        if !errors.is_empty() {
            // Fail closed: a policy that errored was skipped by Cedar, and a skipped forbid
            // is a silent grant. Do not trust the decision.
            return Outcome {
                decision: Decision::Deny,
                reason: REASON_POLICY_ERROR.to_string(),
                policy_ids,
                diagnostics: errors,
            };
        }
        match response.decision() {
            CedarDecision::Allow => Outcome {
                decision: Decision::Allow,
                reason: REASON_POLICY_ALLOW.to_string(),
                policy_ids,
                diagnostics: Vec::new(),
            },
            CedarDecision::Deny => Outcome {
                decision: Decision::Deny,
                reason: REASON_POLICY_DENY.to_string(),
                policy_ids,
                diagnostics: Vec::new(),
            },
        }
    }

    /// Serve an AuthZEN evaluation request. The chain is taken from
    /// `subject.properties.chain`; see [`authzen`].
    pub fn evaluate(
        &self,
        req: &authzen::EvaluationRequest,
        now: OffsetDateTime,
    ) -> Result<authzen::EvaluationResponse, PolicyError> {
        let (chain, call) = authzen::to_chain_and_call(req)?;
        Ok(authzen::from_outcome(&self.authorize(&chain, &call, now)))
    }

    /// Replace the policy set. The new policies are parsed and validated against the engine's
    /// schema first; on error the previous policies stay in force.
    pub fn reload_policies_str(&mut self, policies: &str) -> Result<(), PolicyError> {
        let (policies, warnings) = load_policies(policies, &self.schema)?;
        self.policies = policies;
        self.validation_warnings = warnings;
        Ok(())
    }

    /// Ids of the loaded policies (static policies and templates), sorted.
    pub fn policy_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .policies
            .policies()
            .map(|p| p.id().to_string())
            .chain(self.policies.templates().map(|t| t.id().to_string()))
            .collect();
        ids.sort();
        ids
    }

    /// Validation warnings from the last successful load (for example "policy is impossible").
    pub fn validation_warnings(&self) -> &[String] {
        &self.validation_warnings
    }

    /// The complete schema text the policies were validated against.
    pub fn schema_text(&self) -> &str {
        &self.schema_text
    }

    pub fn catalog(&self) -> &ToolCatalog {
        &self.catalog
    }

    /// The policy for tools that are not in the catalog.
    pub fn unknown_tools(&self) -> UnknownTools {
        self.unknown_tools
    }

    /// Whether the deprecated bare action ids are in use
    /// ([`PolicyEngineBuilder::with_legacy_bare_actions`]).
    pub fn legacy_bare_actions(&self) -> bool {
        self.legacy_bare_actions
    }
}
