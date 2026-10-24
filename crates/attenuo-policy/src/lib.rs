//! Policy decision point for `attenuo`.
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
//! `!= "suspended"` permit fire on `["suspended"]`. Nothing is coerced. Call arguments get the
//! same treatment against the types the catalog declares in [`ToolAttrs::inputs`]: a present,
//! non-null argument of another type is denied with reason `input_type_mismatch` before Cedar
//! (an integral number, `5.0` included, is a `long`). Arguments the catalog declares no type
//! for, and every argument of a tool evaluated under [`UnknownTools::Sensitive`] or
//! [`UnknownTools::Allow`], are passed to Cedar unchecked.
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
//!   "now_unix": 1760000100,
//!   "session": { "tainted": true, "tainted_by": ["web/fetch"] },
//!   "args_contain_untrusted": true,
//!   "untrusted_args": ["body"],
//!   "approval": { "present": false, "by": "" },
//!   "budget": {
//!     "limited": false,
//!     "calls_remaining": 9223372036854775807,
//!     "amount_remaining": 9223372036854775807,
//!     "destination_new": true
//!   },
//!   "usage": { "calls": 0, "amount": 0, "destination_seen": false }
//! }
//! ```
//!
//! `session`, `args_contain_untrusted`, `untrusted_args` and `approval` come from output
//! labelling (ADR-0009) and are always present, so policies need no `has` guard.
//! `session.tainted` is true once the delegation run has read an untrusted upstream result
//! (or when its taint state could not be read), and `session.tainted_by` names the sources as
//! `"<server>/<tool>"`. They come from [`CallLabels`], which
//! [`PolicyEngine::authorize_labelled`] takes; [`PolicyEngine::authorize`] evaluates an
//! untainted run. `untrusted_args` names the arguments of the call that carry a verbatim span
//! of an untrusted result of the run (phase 2: the server's span index, matched only for a
//! destructive tool on a tainted run, with arguments pinned by `equals` or `one_of` exempt),
//! and `args_contain_untrusted` is `true` when there is at least one ([`ArgLabels`]); both
//! come from [`CallLabels::args`]. `approval.present` is `true` only when the call
//! carries a granted approval for its exact call hash ([`ApprovalContext`]), with
//! `approval.by` set to `user` or `operator`; otherwise it is `false` and `by` is empty.
//!
//! `budget` comes from run limits (ADR-0010) and is always present too ([`BudgetContext`]).
//! `budget.limited` is true when some limit in the chain matches the call;
//! `budget.calls_remaining` and `budget.amount_remaining` are, before this call, the smallest
//! `max - used` over every matching `calls` (or `sum`) limit in the chain, or Cedar's largest
//! `Long` when none applies; `budget.destination_new` is false when the call's value of a
//! `calls_per` argument appeared in an earlier allowed call under that limit (`true` when no
//! such limit applies). The server enforces the token's limits itself, in the capability
//! stage before Cedar (`budget_exhausted`, `budget_error`, `limit_arg_invalid`, set through
//! [`BudgetContext::refusal`]); policies read these figures to explain or to ask earlier.
//!
//! `usage` is the run's usage of the called tool (run-limits design section 3.5, phase 2),
//! always present too ([`UsageContext`]): `usage.calls` is how many calls of this server and
//! tool the run has had allowed so far, by any hop; `usage.amount` the sum of the catalog's
//! `amount` input over them (`0` when the catalog names none); `usage.destination_seen` whether
//! the catalog's `destination` input value appeared in one of them. The server keeps usage only
//! for tools the catalog marks destructive; for any other tool all three are zero or false.
//! It keeps it at all only when it can matter ([`PolicyEngine::tracks_usage`]): some loaded
//! policy reads `context.usage`, the catalog declares `amount` or `destination`, or
//! [`TrackUsage::Always`]; otherwise every tool sees zeros, which no loaded policy reads.
//! Nothing refuses a call because of usage unless a policy says so, which is how a deployment
//! writes limits without a number in every token, hard (`forbid`) or soft
//! (`@obligation("approval")`).
//!
//! # Obligations
//!
//! A `forbid` annotated `@obligation("approval")` asks rather than refuses. When every
//! `forbid` that applied to a denied call carries it, and the call would be allowed without
//! those forbids, the reason is `approval_required` instead of `policy_deny`. Any other
//! `forbid` that applies wins, so an approval can never unlock what the policy forbids for
//! another reason, and a call no `permit` allows stays `policy_deny`. The capability stage and
//! the catalog run first, as for every call. Any other `@obligation` value, or one on a
//! `permit`, is refused at load.
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
//! | `Tool::"<server>/<tool>"` | `server`, `name`, `readonly`, `sensitive`, `destructive` (from the [`ToolCatalog`]; `destructive` defaults to `!readonly`) | the `Server` |
//!
//! So policies can say `principal in User::"alice"`, `principal in Agent::"planner"`,
//! `resource in Server::"github"`, `resource.readonly`, or `principal.chain_depth > 2`.
//!
//! ## Actions are server-scoped (SR-13)
//!
//! The action id names the server: `action == Action::"github/read_file"` matches `read_file`
//! on `github` only, never `evil/read_file`. Server names cannot contain `/` and tool names
//! cannot either (except the MCP method names the proxy maps other requests to, such as
//! `resources/read`), see [`attenuo_core::names`]; a call with a name outside those rules is
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
//! use attenuo_core::{AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser, ToolCall};
//! use attenuo_policy::{PolicyEngineBuilder, ToolAttrs, ToolCatalog, ArgType};
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
mod usage;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::RwLock;

use attenuo_core::{Decision, DelegationChain, ToolCall};
use cedar_policy::{
    Authorizer, Decision as CedarDecision, Effect, Policy, PolicyId, PolicySet, Request, Schema,
    Template, ValidationMode, Validator,
};
use time::OffsetDateTime;

pub use catalog::{
    parse_user_attributes, AnnotationImport, ArgType, Narrowing, OutputLabel, ToolAttrs,
    ToolCatalog, UnknownTools,
};
pub use lint::{lint, LintIssue, LintReport, LintSeverity};
pub use lint::{lint_with_options, policy_action_names, LintOptions};
pub use schema::{
    action_id, default_user_attrs, DEFAULT_SCHEMA, GENERIC_ACTION, REQUIRED_ENTITY_TYPES,
};
pub use usage::{policies_read_usage, TrackUsage};

/// The starter policy set shipped with the crate (`policies/default.cedar`).
///
/// It references `Action::"github/create_issue"` and `Action::"github/delete_repo"`, so it
/// validates only when the catalog registers both tools on server `github`.
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

/// Reason code when the call's server or tool name breaks [`attenuo_core::names`].
pub const REASON_INVALID_NAME: &str = "invalid_name";

/// Reason code when an originating-user attribute does not have its declared type (SR-33).
pub const REASON_ATTRIBUTE_TYPE_MISMATCH: &str = "attribute_type_mismatch";

/// Reason code when a call argument does not have the type the catalog declares for it
/// ([`ToolAttrs::inputs`]). Decided before Cedar, so never `policy_error`.
pub const REASON_INPUT_TYPE_MISMATCH: &str = "input_type_mismatch";

/// Reason code when Cedar denies only through forbids annotated `@obligation("approval")`
/// and would allow without them (ADR-0009). Always a deny.
pub const REASON_APPROVAL_REQUIRED: &str = "approval_required";

/// The annotation that turns a `forbid` into a request for approval.
pub const OBLIGATION_ANNOTATION: &str = "obligation";

/// The one `@obligation` value the engine knows.
pub const OBLIGATION_APPROVAL: &str = "approval";

/// What the engine knows about the delegation run a call belongs to (output labelling,
/// ADR-0009): `context.session` in Cedar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionLabels {
    /// The run has read at least one untrusted result, or its taint state could not be read.
    pub tainted: bool,
    /// `"<server>/<tool>"` of every source that labelled the run.
    pub tainted_by: BTreeSet<String>,
}

impl SessionLabels {
    /// A run that has read nothing untrusted.
    pub fn untainted() -> Self {
        Self::default()
    }

    /// The labels of a run whose taint state could not be read: tainted, with no known
    /// source (fail closed).
    pub fn unknown() -> Self {
        Self {
            tainted: true,
            tainted_by: BTreeSet::new(),
        }
    }

    /// A run labelled by these sources; tainted when there is at least one.
    pub fn from_sources<S: Into<String>>(sources: impl IntoIterator<Item = S>) -> Self {
        let tainted_by: BTreeSet<String> = sources.into_iter().map(Into::into).collect();
        Self {
            tainted: !tainted_by.is_empty(),
            tainted_by,
        }
    }
}

/// `context.args_contain_untrusted` and `context.untrusted_args` (output labelling phase 2,
/// ADR-0009): which arguments of the call matched an untrusted result of the run. The default
/// is no match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgLabels {
    /// `context.args_contain_untrusted`. True when `untrusted` is non-empty; a policy test may
    /// also set it alone.
    pub contain_untrusted: bool,
    /// `context.untrusted_args`: the top-level names of the arguments that matched.
    pub untrusted: BTreeSet<String>,
}

impl ArgLabels {
    /// These arguments matched; `contain_untrusted` when there is at least one.
    pub fn from_args<S: Into<String>>(args: impl IntoIterator<Item = S>) -> Self {
        let untrusted: BTreeSet<String> = args.into_iter().map(Into::into).collect();
        Self {
            contain_untrusted: !untrusted.is_empty(),
            untrusted,
        }
    }
}

/// The per-call inputs to the Cedar context that the server computes from run state: output
/// labelling (ADR-0009) and run limits (ADR-0010). The default is an untainted run with no
/// limit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallLabels {
    /// `context.session`.
    pub session: SessionLabels,
    /// `context.args_contain_untrusted` and `context.untrusted_args`.
    pub args: ArgLabels,
    /// `context.approval`.
    pub approval: ApprovalContext,
    /// `context.budget`, and a refusal from the run-limit check.
    pub budget: BudgetContext,
    /// `context.usage`.
    pub usage: UsageContext,
}

/// `context.usage` (run-limits design section 3.5): the delegation run's usage of the called
/// tool before this call, computed by the server from the lease store. The default (all zero,
/// `destination_seen` false) is what a tool without usage, or a run's first call, sees.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageContext {
    /// `context.usage.calls`: allowed calls of this server and tool in the run so far, all
    /// hops.
    pub calls: i64,
    /// `context.usage.amount`: the sum of the catalog's `amount` input over those calls.
    pub amount: i64,
    /// `context.usage.destination_seen`: the catalog's `destination` input value appeared in an
    /// earlier allowed call of this tool in the run.
    pub destination_seen: bool,
}

/// `context.budget` (ADR-0010): what the run limits that match a call have left, computed by
/// the server from the lease store before evaluation. The default is a call no limit applies
/// to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetContext {
    /// `context.budget.limited`: some limit in the chain matches the call.
    pub limited: bool,
    /// `context.budget.calls_remaining`: before this call, the smallest `max - used` over
    /// every matching `calls` limit; `i64::MAX` when none applies.
    pub calls_remaining: i64,
    /// `context.budget.amount_remaining`: the same for `sum` limits.
    pub amount_remaining: i64,
    /// `context.budget.destination_new`: no value of the call's `calls_per` argument has
    /// appeared in an earlier allowed call under that limit; `true` when none applies.
    pub destination_new: bool,
    /// When set, the call is denied in the capability stage, after the capability check and
    /// before the catalog and Cedar, with this reason (`budget_exhausted`, `budget_error` or
    /// `limit_arg_invalid`). Token limits are hard: no policy or approval can pass the call.
    pub refusal: Option<BudgetRefusal>,
}

impl Default for BudgetContext {
    fn default() -> Self {
        Self {
            limited: false,
            calls_remaining: i64::MAX,
            amount_remaining: i64::MAX,
            destination_new: true,
            refusal: None,
        }
    }
}

/// Why the run-limit check refuses a call (see [`BudgetContext::refusal`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRefusal {
    /// The reason code.
    pub reason: String,
    /// A diagnostic naming the limit.
    pub detail: String,
}

/// `context.approval` (ADR-0009): whether the call carries a granted approval for its exact
/// call hash, and who granted it. The default is no approval.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalContext {
    /// `context.approval.present`.
    pub present: bool,
    /// `context.approval.by`: `user`, `operator` or `policy`; empty when absent.
    pub by: String,
}

impl ApprovalContext {
    /// An approval granted by `by` (`user` or `operator`).
    pub fn by(by: impl Into<String>) -> Self {
        Self {
            present: true,
            by: by.into(),
        }
    }
}

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
    /// A catalog entry names a server or tool that breaks [`attenuo_core::names`].
    #[error("tool catalog: {0}")]
    Catalog(String),
    /// An `@obligation` annotation the engine cannot honour: an unknown value, or one on a
    /// `permit`.
    #[error("policy obligation error: {0}")]
    Obligation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The result of one authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    /// One of `invalid_name`, `capability_denied`, `tool_not_in_catalog`, `attribute_type_mismatch`,
    /// `input_type_mismatch`, `policy_allow`, `policy_deny`, `approval_required`, `policy_error`.
    pub reason: String,
    /// Ids of the policies that determined the decision (permits that matched for an allow,
    /// forbids that matched for a deny, the approval forbids for `approval_required`). Empty
    /// for a capability denial or a default deny.
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
    annotation_import: AnnotationImport,
    track_usage: TrackUsage,
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
            annotation_import: AnnotationImport::default(),
            track_usage: TrackUsage::default(),
        }
    }

    /// Whether the server keeps run usage when nothing reads it (`[policy] track_usage`).
    /// Default [`TrackUsage::Auto`]; see [`PolicyEngine::tracks_usage`].
    pub fn with_track_usage(mut self, track_usage: TrackUsage) -> Self {
        self.track_usage = track_usage;
        self
    }

    /// Whether MCP tool annotations reported through [`PolicyEngine::import_annotations`] are
    /// used, narrowing only (`[policy] import_annotations`). Default
    /// [`AnnotationImport::Never`].
    pub fn with_annotation_import(mut self, import: AnnotationImport) -> Self {
        self.annotation_import = import;
        self
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

    /// Parse the complete schema and, when the base schema was replaced
    /// ([`with_schema_str`](Self::with_schema_str)), check that it still declares what the
    /// engine builds requests from: the entity types `User`, `Agent`, `Server` and `Tool` with
    /// every attribute of [`DEFAULT_SCHEMA`] (required, same type), `Agent in [User, Agent]`
    /// and `Tool in [Server]`. Actions are always generated, so a base that declares
    /// `Action::"invoke"` or a catalog action fails to parse. [`build`](Self::build) runs this
    /// too.
    pub fn check_schema(&self) -> Result<(), PolicyError> {
        self.parse_schema().map(|_| ())
    }

    fn parse_schema(&self) -> Result<Schema, PolicyError> {
        let custom = self.base_schema != DEFAULT_SCHEMA;
        let what = |e: String| {
            if custom {
                PolicyError::Schema(format!("custom base schema: {e}"))
            } else {
                PolicyError::Schema(e)
            }
        };
        if custom {
            let missing = schema::missing_entity_types(&self.base_schema);
            if !missing.is_empty() {
                return Err(what(format!(
                    "it does not declare the entity type(s) {}",
                    missing.join(", ")
                )));
            }
        }
        let (schema, _warnings) =
            Schema::from_cedarschema_str(&self.schema_text()).map_err(|e| what(e.to_string()))?;
        if custom {
            schema::check_required_shape(&schema).map_err(what)?;
        }
        Ok(schema)
    }

    pub fn build(self) -> Result<PolicyEngine, PolicyError> {
        self.catalog.validate().map_err(PolicyError::Catalog)?;
        let schema_text = self.schema_text();
        let schema = self.parse_schema()?;
        let mut text = String::new();
        for src in &self.policy_sources {
            match src {
                PolicySource::Text(t) => text.push_str(t),
                PolicySource::File(path) => text.push_str(&std::fs::read_to_string(path)?),
            }
            text.push('\n');
        }
        let loaded = load_policies(&text, &schema)?;
        let catalog_names_usage = self
            .catalog
            .iter()
            .any(|(_, a)| a.amount.is_some() || a.destination.is_some());
        Ok(PolicyEngine {
            policies_read_usage: loaded.reads_usage,
            catalog_names_usage,
            track_usage: self.track_usage,
            schema,
            schema_text,
            policies: loaded.policies,
            obligations: loaded.obligations,
            catalog: self.catalog,
            user_attrs: self.user_attrs,
            unknown_tools: self.unknown_tools,
            legacy_bare_actions: self.legacy_bare_actions,
            annotation_import: self.annotation_import,
            narrowed: RwLock::new(HashMap::new()),
            authorizer: Authorizer::new(),
            validation_warnings: loaded.warnings,
            request_cache: request::RequestCache::new(request::REQUEST_CACHE_CAPACITY),
        })
    }
}

/// A validated policy set and what the engine derives from it.
struct LoadedPolicies {
    policies: PolicySet,
    obligations: Obligations,
    warnings: Vec<String>,
    /// Some policy may read `context.usage` ([`policies_read_usage`]).
    reads_usage: bool,
}

/// The forbids annotated `@obligation("approval")`, and the policy set without them, used to
/// tell `approval_required` from `policy_deny`.
#[derive(Debug, Default)]
struct Obligations {
    approval_ids: BTreeSet<String>,
    /// `None` when no policy carries the annotation.
    without_approval: Option<PolicySet>,
}

/// Every `@obligation` annotation must be `"approval"` on a `forbid`. Returns the ids of the
/// policies (and templates) that carry it.
pub(crate) fn approval_obligations(
    policies: &PolicySet,
) -> Result<BTreeSet<String>, Vec<(String, String)>> {
    let mut ids = BTreeSet::new();
    let mut errors = Vec::new();
    let all = policies
        .policies()
        .map(|p| {
            (
                p.id().to_string(),
                p.effect(),
                p.annotation(OBLIGATION_ANNOTATION),
            )
        })
        .chain(policies.templates().map(|t| {
            (
                t.id().to_string(),
                t.effect(),
                t.annotation(OBLIGATION_ANNOTATION),
            )
        }));
    for (id, effect, value) in all {
        let Some(value) = value else { continue };
        if value != OBLIGATION_APPROVAL {
            errors.push((
                id,
                format!(
                    "unknown obligation `@obligation(\"{value}\")`: the only obligation is \
                     \"{OBLIGATION_APPROVAL}\""
                ),
            ));
        } else if effect != Effect::Forbid {
            errors.push((
                id,
                "`@obligation(\"approval\")` on a permit has no effect: put it on the forbid \
                 that should ask for approval"
                    .to_string(),
            ));
        } else {
            ids.insert(id);
        }
    }
    if errors.is_empty() {
        Ok(ids)
    } else {
        Err(errors)
    }
}

/// Parse, re-id (from `@id` annotations) and validate a policy set.
fn load_policies(text: &str, schema: &Schema) -> Result<LoadedPolicies, PolicyError> {
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
    let approval_ids = approval_obligations(&policies).map_err(|errs| {
        PolicyError::Obligation(
            errs.into_iter()
                .map(|(id, msg)| format!("[{id}] {msg}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    })?;
    let without_approval = if approval_ids.is_empty() {
        None
    } else {
        let mut set = PolicySet::new();
        for p in policies.policies() {
            if !approval_ids.contains(&p.id().to_string()) {
                set.add(p.clone())
                    .map_err(|e| PolicyError::Parse(format!("policy set: {e}")))?;
            }
        }
        Some(set)
    };
    Ok(LoadedPolicies {
        reads_usage: policies_read_usage(&policies),
        policies,
        obligations: Obligations {
            approval_ids,
            without_approval,
        },
        warnings,
    })
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

/// A Cedar request ready to evaluate, with its entity store.
struct Prepared {
    request: Request,
    parts: std::sync::Arc<request::RequestParts>,
}

/// Hooks for `benches/policy_stage.rs`: the two halves of the Cedar stage, timed apart.
/// Not a stable API.
#[doc(hidden)]
pub mod bench_support {
    use super::*;

    /// A prepared Cedar request (opaque).
    pub struct PreparedRequest(Prepared);

    /// Translate `(chain, call)` into a Cedar request and entity store, as
    /// [`PolicyEngine::authorize`] does after the capability and catalog stages.
    pub fn prepare(
        engine: &PolicyEngine,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> PreparedRequest {
        let attrs = engine.catalog.get(&call.server, &call.tool);
        PreparedRequest(
            engine
                .prepare(chain, call, &attrs, &CallLabels::default(), now)
                .expect("request translates"),
        )
    }

    /// Evaluate a prepared request.
    pub fn evaluate(engine: &PolicyEngine, prepared: &PreparedRequest) -> Outcome {
        engine.evaluate_prepared(&prepared.0)
    }

    /// Empty the engine's request cache, so the next call translates the chain again.
    pub fn clear_request_cache(engine: &PolicyEngine) {
        engine.request_cache.clear();
    }
}

/// The policy decision point. Build once per policy version and share behind an
/// `Arc`/`RwLock` if you need hot reload across threads.
///
/// The schema and policy set are parsed and validated once, at build or reload, never per
/// call. Translating a chain into Cedar entities and context records (Cedar parsing their
/// JSON) was about 90 percent of a decision, so the engine keeps the parts that depend only
/// on the chain and the tool (entity store, principal, action, resource, and the
/// `originating_user` and `chain` context records) in a bounded cache of 4,096 entries,
/// matched on every input they were built from. A call then builds only `context.input`,
/// `context.session_id` and `context.now_unix`. [`reload_policies_str`](Self::reload_policies_str)
/// empties the cache; a catalog change means a new engine, so a new cache.
#[derive(Debug)]
pub struct PolicyEngine {
    schema: Schema,
    schema_text: String,
    policies: PolicySet,
    obligations: Obligations,
    catalog: ToolCatalog,
    user_attrs: BTreeMap<String, ArgType>,
    unknown_tools: UnknownTools,
    legacy_bare_actions: bool,
    annotation_import: AnnotationImport,
    /// Narrowing imported from MCP tool annotations, per catalog tool (sticky; bounded by the
    /// catalog). Empty unless `annotation_import` is `Narrowing`.
    narrowed: RwLock<HashMap<(String, String), Narrowing>>,
    authorizer: Authorizer,
    validation_warnings: Vec<String>,
    request_cache: request::RequestCache,
    /// Some loaded policy may read `context.usage`; recomputed on reload.
    policies_read_usage: bool,
    /// The catalog declares `amount` or `destination` for some tool.
    catalog_names_usage: bool,
    track_usage: TrackUsage,
}

impl PolicyEngine {
    /// Decide whether `call` may proceed for the agent at the end of `chain`, at time `now`.
    ///
    /// The chain is assumed to have been verified and `validate_at`-ed already; this method
    /// does not check signatures or expiry. The run is evaluated as untainted; the server's
    /// pipeline uses [`authorize_labelled`](Self::authorize_labelled) with the run's labels.
    pub fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> Outcome {
        self.authorize_labelled(chain, call, &CallLabels::default(), now)
    }

    /// [`authorize`](Self::authorize) with the output labels of the call's delegation run
    /// (`context.session`, ADR-0009).
    pub fn authorize_labelled(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        labels: &CallLabels,
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
            // For each capability whose patterns match, the first constraint the call fails,
            // naming the argument and the bound or value the capability allows (already in the
            // list above), never the argument's value.
            let why: Vec<String> = caps
                .iter()
                .filter_map(|c| {
                    c.explain_denial(call)
                        .map(|w| format!("{}:{}: {w}", c.server, c.tool))
                })
                .collect();
            let mut detail = format!(
                "call {}:{} is not permitted by the effective capabilities [{}]",
                call.server,
                call.tool,
                have.join(", ")
            );
            if !why.is_empty() {
                detail.push_str(&format!("; {}", why.join("; ")));
            }
            return Outcome::deny(REASON_CAPABILITY_DENIED, vec![detail]);
        }

        // Stage 1a: run limits (ADR-0010). The server read the counters; a limit the call
        // would exceed, an argument a limit cannot count, or unreadable counters deny here,
        // before the catalog and Cedar, so no policy or approval can pass the call.
        if let Some(r) = &labels.budget.refusal {
            return Outcome::deny(&r.reason, vec![r.detail.clone()]);
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
        let attrs = self.narrow(&call.server, &call.tool, attrs);

        // Stage 1c: declared attribute types. Evaluation is schema-free, and Cedar's `!=`
        // across types is `true` without an error, so a value of the wrong type (a list where
        // a string is declared) would make `attributes.status != "suspended"` permit.
        if let Err(e) = request::check_user_attributes(&chain.originating_user, &self.user_attrs) {
            return Outcome::deny(REASON_ATTRIBUTE_TYPE_MISMATCH, vec![e]);
        }

        // Stage 1d: declared argument types, for the same reason. A number where the catalog
        // declares a string would otherwise make `like` raise a type error (`policy_error`),
        // or pass unread to the upstream when no policy tests it. A tool the catalog does not
        // know, or an argument it declares no type for, is not checked.
        if let Err(e) = request::check_tool_inputs(&call.arguments, &attrs.inputs) {
            return Outcome::deny(REASON_INPUT_TYPE_MISMATCH, vec![e]);
        }

        // Stage 2: Cedar.
        match self.prepare(chain, call, &attrs, labels, now) {
            Ok(prepared) => self.evaluate_prepared(&prepared),
            Err(e) => Outcome::deny(REASON_POLICY_ERROR, vec![e]),
        }
    }

    /// Stage 2, first half: the Cedar request and entity store for `call`. The parts that
    /// depend only on the chain and tool come from the request cache.
    fn prepare(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        attrs: &ToolAttrs,
        labels: &CallLabels,
        now: OffsetDateTime,
    ) -> Result<Prepared, String> {
        let parts = self
            .request_cache
            .get_or_build(chain, call, attrs, self.legacy_bare_actions)
            .map_err(|e| e.to_string())?;
        let request = parts
            .request(call, labels, now)
            .map_err(|e| e.to_string())?;
        Ok(Prepared { request, parts })
    }

    /// `attrs` with any narrowing imported from tool annotations applied.
    fn narrow(&self, server: &str, tool: &str, attrs: ToolAttrs) -> ToolAttrs {
        if self.annotation_import == AnnotationImport::Never {
            return attrs;
        }
        // A poisoned lock cannot be trusted to hold every narrowing: treat the tool as
        // neither read-only nor non-destructive (the most restricted reading).
        let narrowing = match self.narrowed.read() {
            Ok(map) => map
                .get(&(server.to_string(), tool.to_string()))
                .copied()
                .unwrap_or_default(),
            Err(_) => Narrowing {
                not_readonly: true,
                destructive: true,
            },
        };
        if narrowing.is_empty() {
            attrs
        } else {
            attrs.narrowed(&narrowing)
        }
    }

    /// Report the MCP annotations a server gave a tool in `tools/list` (`readOnlyHint`,
    /// `destructiveHint`). With [`AnnotationImport::Narrowing`] and a tool that is in the
    /// catalog, explicit hints that make the tool more restricted are kept for the life of
    /// the engine; nothing else changes anything (ADR-0009). Returns whether this narrowed
    /// the tool further.
    pub fn import_annotations(
        &self,
        server: &str,
        tool: &str,
        read_only_hint: Option<bool>,
        destructive_hint: Option<bool>,
    ) -> bool {
        if self.annotation_import == AnnotationImport::Never || !self.catalog.contains(server, tool)
        {
            return false;
        }
        let asked = Narrowing::from_hints(read_only_hint, destructive_hint);
        if asked.is_empty() {
            return false;
        }
        let Ok(mut map) = self.narrowed.write() else {
            return false;
        };
        let entry = map
            .entry((server.to_string(), tool.to_string()))
            .or_default();
        let merged = entry.union(asked);
        let changed = merged != *entry;
        *entry = merged;
        changed
    }

    /// The attributes a call to `(server, tool)` is evaluated with: the catalog entry with any
    /// imported narrowing, or what [`UnknownTools`] gives a tool missing from the catalog
    /// (`None` under [`UnknownTools::Deny`]).
    pub fn effective_attrs(&self, server: &str, tool: &str) -> Option<ToolAttrs> {
        let attrs = if self.catalog.contains(server, tool) {
            self.catalog.get(server, tool)
        } else {
            match self.unknown_tools {
                UnknownTools::Deny => return None,
                UnknownTools::Sensitive => ToolAttrs::new().sensitive(true),
                UnknownTools::Allow => ToolAttrs::default(),
            }
        };
        Some(self.narrow(server, tool, attrs))
    }

    /// How annotations are imported ([`PolicyEngineBuilder::with_annotation_import`]).
    pub fn annotation_import(&self) -> AnnotationImport {
        self.annotation_import
    }

    /// Stage 2, second half: evaluate a prepared request against the policy set.
    fn evaluate_prepared(&self, prepared: &Prepared) -> Outcome {
        let response = self.authorizer.is_authorized(
            &prepared.request,
            &self.policies,
            &prepared.parts.entities,
        );
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
            CedarDecision::Deny => self.deny_or_ask(prepared, policy_ids),
        }
    }

    /// A Cedar deny: `approval_required` when every forbid that applied carries
    /// `@obligation("approval")` and the call would be allowed without them, else
    /// `policy_deny`.
    fn deny_or_ask(&self, prepared: &Prepared, policy_ids: Vec<String>) -> Outcome {
        let deny = |policy_ids| Outcome {
            decision: Decision::Deny,
            reason: REASON_POLICY_DENY.to_string(),
            policy_ids,
            diagnostics: Vec::new(),
        };
        let Some(relaxed) = &self.obligations.without_approval else {
            return deny(policy_ids);
        };
        let only_approval = !policy_ids.is_empty()
            && policy_ids
                .iter()
                .all(|id| self.obligations.approval_ids.contains(id));
        if !only_approval {
            return deny(policy_ids);
        }
        // Would a permit allow the call once the approval forbids are lifted? If not, an
        // approval could not help, and the answer is a plain deny.
        let response =
            self.authorizer
                .is_authorized(&prepared.request, relaxed, &prepared.parts.entities);
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        if !errors.is_empty() {
            return Outcome {
                decision: Decision::Deny,
                reason: REASON_POLICY_ERROR.to_string(),
                policy_ids,
                diagnostics: errors,
            };
        }
        match response.decision() {
            CedarDecision::Allow => Outcome {
                decision: Decision::Deny,
                reason: REASON_APPROVAL_REQUIRED.to_string(),
                policy_ids,
                diagnostics: Vec::new(),
            },
            CedarDecision::Deny => deny(policy_ids),
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
        let loaded = load_policies(policies, &self.schema)?;
        self.policies = loaded.policies;
        self.obligations = loaded.obligations;
        self.validation_warnings = loaded.warnings;
        self.policies_read_usage = loaded.reads_usage;
        // The cached request parts do not depend on the policies, but a reload is the
        // operator's "start from scratch", so it starts with an empty cache too.
        self.request_cache.clear();
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

    /// Each loaded policy (static policies and templates) with its Cedar text, sorted by id.
    ///
    /// The admin console shows what is in force, which may differ from the file on disk after
    /// an edit that was not reloaded. The text is Cedar's rendering of the parsed policy: the
    /// source text where Cedar kept it, so comments between policies are not included.
    pub fn policy_texts(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .policies
            .policies()
            .map(|p| (p.id().to_string(), p.to_string()))
            .chain(
                self.policies
                    .templates()
                    .map(|t| (t.id().to_string(), t.to_string())),
            )
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
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

    /// How many `(chain, tool)` translations the request cache holds (at most 4,096).
    pub fn cached_requests(&self) -> usize {
        self.request_cache.len()
    }

    /// The policy for tools that are not in the catalog.
    pub fn unknown_tools(&self) -> UnknownTools {
        self.unknown_tools
    }

    /// Whether the server should keep run usage (`context.usage`, run-limits design section
    /// 3.5) for calls to destructive tools under this engine: some loaded policy may read
    /// `context.usage` ([`policies_read_usage`]), the catalog declares `amount` or
    /// `destination` for some tool, or `[policy] track_usage = true`. Decided at build and at
    /// every [`reload_policies_str`](Self::reload_policies_str), so a call pays nothing to find
    /// out. When `false`, keeping usage would cost a store write per allowed destructive call
    /// for figures no loaded policy can observe, so the server skips it and evaluates with
    /// zeros.
    pub fn tracks_usage(&self) -> bool {
        self.track_usage == TrackUsage::Always
            || self.policies_read_usage
            || self.catalog_names_usage
    }

    /// Whether some loaded policy carries `@obligation("approval")`, so that the server may
    /// ask for approvals (`approval_required`). Recomputed at every
    /// [`reload_policies_str`](Self::reload_policies_str).
    pub fn asks_for_approval(&self) -> bool {
        !self.obligations.approval_ids.is_empty()
    }

    /// Why [`tracks_usage`](Self::tracks_usage) is what it is, for the server's log: the
    /// reasons that hold (`"policy"`, `"catalog"`, `"config"`), empty when usage is not kept.
    pub fn usage_tracking_reasons(&self) -> Vec<&'static str> {
        [
            (self.policies_read_usage, "policy"),
            (self.catalog_names_usage, "catalog"),
            (self.track_usage == TrackUsage::Always, "config"),
        ]
        .into_iter()
        .filter_map(|(on, why)| on.then_some(why))
        .collect()
    }

    /// Whether the deprecated bare action ids are in use
    /// ([`PolicyEngineBuilder::with_legacy_bare_actions`]).
    pub fn legacy_bare_actions(&self) -> bool {
        self.legacy_bare_actions
    }
}
