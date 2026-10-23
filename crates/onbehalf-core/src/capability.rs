//! Capabilities: what an agent may call, with optional constraints on arguments.
//!
//! The central operation is *coverage*: `parent.covers(&child)` answers whether every call the
//! child permits is also permitted by the parent. Attenuation across delegation hops is defined
//! in terms of coverage, so the correctness of this module is the correctness of the
//! "capabilities only narrow" guarantee.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::call::ToolCall;
use crate::error::AttenuationError;
use crate::jcs::value_eq;
use crate::names::NameError;

/// A constraint on a single tool argument.
///
/// Constraints are compared by *implication*: `a.implies(&b)` is true when every value that
/// satisfies `a` also satisfies `b`. A child capability must carry constraints that imply the
/// parent's, so it can only be stricter.
///
/// JSON values are compared as their RFC 8785 canonical forms ([`crate::jcs::value_eq`]):
/// numbers by value (`1` equals `1.0`, as in JavaScript and in the Cedar translation) and
/// objects regardless of member order. Equality, ordering and the chain digest all use that
/// one notion, so two constraints with the same digest also admit the same arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "value", rename_all = "snake_case")]
pub enum ArgConstraint {
    /// Argument must equal this JSON value (canonically; see above).
    Equals(Value),
    /// Argument must equal one of these JSON values.
    OneOf(Vec<Value>),
    /// Argument must be a string starting with this prefix.
    Prefix(String),
}

impl ArgConstraint {
    /// Canonical (RFC 8785) JSON form; equality and ordering are defined on it, so
    /// constraints can live in `BTreeSet`/`BTreeMap`.
    fn canonical(&self) -> Vec<u8> {
        crate::jcs::to_vec(self).expect("a constraint has a canonical JSON form")
    }

    /// Does a concrete argument value satisfy this constraint?
    pub fn satisfied_by(&self, value: &Value) -> bool {
        match self {
            ArgConstraint::Equals(expected) => value_eq(value, expected),
            ArgConstraint::OneOf(options) => options.iter().any(|o| value_eq(o, value)),
            ArgConstraint::Prefix(prefix) => value
                .as_str()
                .map(|s| s.starts_with(prefix))
                .unwrap_or(false),
        }
    }

    /// Does every value satisfying `self` also satisfy `other`?
    pub fn implies(&self, other: &ArgConstraint) -> bool {
        match (self, other) {
            (ArgConstraint::Equals(a), ArgConstraint::Equals(b)) => value_eq(a, b),
            (ArgConstraint::Equals(a), ArgConstraint::OneOf(bs)) => {
                bs.iter().any(|b| value_eq(a, b))
            }
            (ArgConstraint::Equals(a), ArgConstraint::Prefix(p)) => a
                .as_str()
                .map(|s| s.starts_with(p.as_str()))
                .unwrap_or(false),
            // An empty `OneOf` is satisfied by no value, so it vacuously implies every
            // constraint (`all` over an empty set is true). That is sound: a capability
            // carrying it permits nothing, and it can still be re-delegated unchanged.
            (ArgConstraint::OneOf(as_), ArgConstraint::Equals(b)) => {
                as_.iter().all(|a| value_eq(a, b))
            }
            (ArgConstraint::OneOf(as_), ArgConstraint::OneOf(bs)) => {
                as_.iter().all(|a| bs.iter().any(|b| value_eq(a, b)))
            }
            (ArgConstraint::OneOf(as_), ArgConstraint::Prefix(p)) => as_.iter().all(|a| {
                a.as_str()
                    .map(|s| s.starts_with(p.as_str()))
                    .unwrap_or(false)
            }),
            (ArgConstraint::Prefix(p), ArgConstraint::Prefix(q)) => p.starts_with(q.as_str()),
            // A prefix admits infinitely many values; it cannot imply an exact or finite set.
            (ArgConstraint::Prefix(_), ArgConstraint::Equals(_))
            | (ArgConstraint::Prefix(_), ArgConstraint::OneOf(_)) => false,
        }
    }
}

impl PartialEq for ArgConstraint {
    fn eq(&self, other: &Self) -> bool {
        self.canonical() == other.canonical()
    }
}

impl Eq for ArgConstraint {}

impl PartialOrd for ArgConstraint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArgConstraint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.canonical().cmp(&other.canonical())
    }
}

/// A name pattern for servers and tools: either an exact name, `*`, or a `prefix*` glob.
///
/// Kept deliberately small so that pattern containment is decidable and obvious.
fn pattern_covers(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }
    match (parent.strip_suffix('*'), child.strip_suffix('*')) {
        // parent is `p*`
        (Some(p), Some(c)) => c.starts_with(p),
        (Some(p), None) => child.starts_with(p),
        // parent is exact; child must be the same exact name
        (None, Some(_)) => false,
        (None, None) => parent == child,
    }
}

fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(p) => name.starts_with(p),
        None => pattern == name,
    }
}

/// Permission to call tools matching `tool` on servers matching `server`, subject to
/// `constraints` on arguments. Arguments not mentioned in `constraints` are unconstrained.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Capability {
    pub server: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, ArgConstraint>,
}

impl Capability {
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            constraints: BTreeMap::new(),
        }
    }

    pub fn with_constraint(mut self, arg: impl Into<String>, c: ArgConstraint) -> Self {
        self.constraints.insert(arg.into(), c);
        self
    }

    /// Check the server and tool patterns against [`crate::names`]: `*`, `<prefix>*` or a
    /// name. A capability that fails this could only ever match names no call can have.
    pub fn validate(&self) -> Result<(), NameError> {
        crate::names::check_server_pattern(&self.server)?;
        crate::names::check_call_pattern(&self.tool)
    }

    /// Does this capability permit every call that `child` permits?
    pub fn covers(&self, child: &Capability) -> bool {
        if !pattern_covers(&self.server, &child.server) || !pattern_covers(&self.tool, &child.tool)
        {
            return false;
        }
        // Every constraint the parent imposes must be implied by a constraint on the child.
        self.constraints.iter().all(|(arg, parent_c)| {
            child
                .constraints
                .get(arg)
                .map(|child_c| child_c.implies(parent_c))
                .unwrap_or(false)
        })
    }

    /// Does this capability permit this concrete call? A call whose server or tool name is
    /// not valid ([`ToolCall::check_names`]) is never permitted.
    pub fn permits(&self, call: &ToolCall) -> bool {
        call.check_names().is_ok()
            && pattern_matches(&self.server, &call.server)
            && pattern_matches(&self.tool, &call.tool)
            && self.constraints.iter().all(|(arg, c)| {
                call.arguments
                    .get(arg)
                    .map(|v| c.satisfied_by(v))
                    .unwrap_or(false)
            })
    }

    /// Human-readable form used in errors and logs, e.g. `github:create_issue{repo=...}`.
    pub fn display(&self) -> String {
        if self.constraints.is_empty() {
            format!("{}:{}", self.server, self.tool)
        } else {
            let cs: Vec<String> = self
                .constraints
                .iter()
                .map(|(k, v)| format!("{k}={}", serde_json::to_string(v).unwrap_or_default()))
                .collect();
            format!("{}:{}{{{}}}", self.server, self.tool, cs.join(","))
        }
    }
}

/// A set of capabilities. A call is permitted if any member permits it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySet(pub BTreeSet<Capability>);

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, c: Capability) -> bool {
        self.0.insert(c)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.0.iter()
    }

    /// [`Capability::validate`] every member.
    pub fn validate(&self) -> Result<(), NameError> {
        self.0.iter().try_for_each(Capability::validate)
    }

    /// Does this set permit every call that `child` permits?
    ///
    /// Conservative: each child capability must be covered by a *single* parent capability.
    /// A child that is only covered by the union of several parents is rejected. That is
    /// sound (never widens) and keeps the check linear and explainable.
    pub fn covers(&self, child: &CapabilitySet) -> bool {
        child.0.iter().all(|c| self.0.iter().any(|p| p.covers(c)))
    }

    /// Derive `requested` from `self`, failing if that would widen anything.
    ///
    /// This is the attenuation step performed at every delegation hop.
    pub fn attenuate(&self, requested: &CapabilitySet) -> Result<CapabilitySet, AttenuationError> {
        if requested.is_empty() {
            return Err(AttenuationError::Empty);
        }
        for c in requested.0.iter() {
            if !self.0.iter().any(|p| p.covers(c)) {
                return Err(AttenuationError::NotCovered {
                    requested: c.display(),
                });
            }
        }
        Ok(requested.clone())
    }

    /// Does any capability in the set permit this call?
    pub fn permits(&self, call: &ToolCall) -> bool {
        self.0.iter().any(|c| c.permits(call))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn call(server: &str, tool: &str, args: Value) -> ToolCall {
        ToolCall::new(server, tool, args)
    }

    #[test]
    fn exact_and_glob_patterns() {
        assert!(pattern_covers("*", "github"));
        assert!(pattern_covers("git*", "github"));
        assert!(pattern_covers("git*", "gith*"));
        assert!(!pattern_covers("gith*", "git*"));
        assert!(!pattern_covers("github", "*"));
        assert!(!pattern_covers("github", "git*"));
        assert!(pattern_covers("github", "github"));
        assert!(!pattern_covers("github", "gitlab"));
    }

    #[test]
    fn constraint_implication() {
        let eq = ArgConstraint::Equals(json!("acme/api"));
        let one = ArgConstraint::OneOf(vec![json!("acme/api"), json!("acme/web")]);
        let pre = ArgConstraint::Prefix("acme/".into());
        assert!(eq.implies(&eq));
        assert!(eq.implies(&one));
        assert!(eq.implies(&pre));
        assert!(!one.implies(&eq));
        assert!(one.implies(&pre));
        assert!(!pre.implies(&eq));
        assert!(!pre.implies(&one));
        assert!(ArgConstraint::Prefix("acme/a".into()).implies(&pre));
        assert!(!pre.implies(&ArgConstraint::Prefix("acme/a".into())));
        // empty OneOf permits nothing, so it vacuously implies everything (and itself)
        assert!(ArgConstraint::OneOf(vec![]).implies(&eq));
        assert!(ArgConstraint::OneOf(vec![]).implies(&ArgConstraint::OneOf(vec![])));
        assert!(!ArgConstraint::OneOf(vec![]).satisfied_by(&json!("acme/api")));
    }

    #[test]
    fn child_with_extra_constraint_is_covered() {
        let parent = Capability::new("github", "create_issue");
        let child = Capability::new("github", "create_issue")
            .with_constraint("repo", ArgConstraint::Equals(json!("acme/api")));
        assert!(parent.covers(&child));
        assert!(!child.covers(&parent));
    }

    #[test]
    fn child_dropping_parent_constraint_is_not_covered() {
        let parent = Capability::new("github", "*")
            .with_constraint("repo", ArgConstraint::Prefix("acme/".into()));
        let child = Capability::new("github", "create_issue");
        assert!(!parent.covers(&child));
        let child_ok = Capability::new("github", "create_issue")
            .with_constraint("repo", ArgConstraint::Equals(json!("acme/api")));
        assert!(parent.covers(&child_ok));
    }

    #[test]
    fn permits_checks_arguments() {
        let cap = Capability::new("github", "create_issue")
            .with_constraint("repo", ArgConstraint::Prefix("acme/".into()));
        assert!(cap.permits(&call("github", "create_issue", json!({"repo": "acme/api"}))));
        assert!(!cap.permits(&call("github", "create_issue", json!({"repo": "evil/x"}))));
        // missing constrained argument is a deny, never an allow
        assert!(!cap.permits(&call("github", "create_issue", json!({}))));
        assert!(!cap.permits(&call("github", "delete_repo", json!({"repo": "acme/api"}))));
    }

    #[test]
    fn set_attenuation_only_narrows() {
        let parent = CapabilitySet::from_iter([
            Capability::new("github", "read_*"),
            Capability::new("github", "create_issue")
                .with_constraint("repo", ArgConstraint::Prefix("acme/".into())),
        ]);
        let ok = CapabilitySet::from_iter([
            Capability::new("github", "read_file"),
            Capability::new("github", "create_issue")
                .with_constraint("repo", ArgConstraint::Equals(json!("acme/api"))),
        ]);
        assert_eq!(parent.attenuate(&ok).unwrap(), ok);

        let widen_tool = CapabilitySet::from_iter([Capability::new("github", "delete_repo")]);
        assert!(matches!(
            parent.attenuate(&widen_tool),
            Err(AttenuationError::NotCovered { .. })
        ));

        let widen_arg = CapabilitySet::from_iter([Capability::new("github", "create_issue")]);
        assert!(matches!(
            parent.attenuate(&widen_arg),
            Err(AttenuationError::NotCovered { .. })
        ));

        assert_eq!(
            parent.attenuate(&CapabilitySet::new()),
            Err(AttenuationError::Empty)
        );
    }

    #[test]
    fn union_coverage_is_rejected_conservatively() {
        // parent permits repo A via one cap and repo B via another; a child asking for
        // "A or B" in one cap is not covered by any single parent cap.
        let parent = CapabilitySet::from_iter([
            Capability::new("github", "create_issue")
                .with_constraint("repo", ArgConstraint::Equals(json!("a"))),
            Capability::new("github", "create_issue")
                .with_constraint("repo", ArgConstraint::Equals(json!("b"))),
        ]);
        let child = CapabilitySet::from_iter([Capability::new("github", "create_issue")
            .with_constraint("repo", ArgConstraint::OneOf(vec![json!("a"), json!("b")]))]);
        assert!(!parent.covers(&child));
    }

    /// SR-20: equality, ordering and satisfaction agree with the canonical (RFC 8785) form
    /// that the chain digest hashes.
    #[test]
    fn constraints_compare_canonically_sr20() {
        let a = ArgConstraint::Equals(serde_json::from_str(r#"{"x":1,"y":[2.0]}"#).unwrap());
        let b = ArgConstraint::Equals(serde_json::from_str(r#"{"y":[2],"x":1.0}"#).unwrap());
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
        assert!(a.implies(&b) && b.implies(&a));
        let one = ArgConstraint::Equals(json!(1));
        assert!(one.satisfied_by(&json!(1.0)));
        assert!(!one.satisfied_by(&json!("1")));
        assert!(ArgConstraint::OneOf(vec![json!(1.0)]).implies(&one));
        let c = ArgConstraint::Equals(json!({"x": 2}));
        assert_ne!(a, c);
        assert_ne!(a.cmp(&c), std::cmp::Ordering::Equal);
        // A set holds one of two canonically equal constraints.
        let set: std::collections::BTreeSet<_> = [a.clone(), b, c].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn names_are_checked_sr13() {
        assert!(Capability::new("github", "read_*").validate().is_ok());
        assert!(Capability::new("*", "resources/read").validate().is_ok());
        // `/` in a server name would make `Tool::"a/b/c"` ambiguous.
        assert!(Capability::new("a/b", "c").validate().is_err());
        assert!(Capability::new("github", "/x").validate().is_err());
        assert!(Capability::new("github", "").validate().is_err());
        let set = CapabilitySet::from_iter([
            Capability::new("github", "*"),
            Capability::new("evil/x", "*"),
        ]);
        assert!(set.validate().is_err());
        // A call with an invalid name is never permitted, even by `*:*`.
        let all = Capability::new("*", "*");
        assert!(all.permits(&call("github", "read_file", json!({}))));
        assert!(!all.permits(&call("evil/x", "read_file", json!({}))));
        assert!(!all.permits(&call("github", "", json!({}))));
        assert!(!all.permits(&call("github", "a//b", json!({}))));
    }

    #[test]
    fn serde_round_trip() {
        let cap = Capability::new("github", "create_issue")
            .with_constraint("repo", ArgConstraint::OneOf(vec![json!("a"), json!("b")]));
        let s = serde_json::to_string(&cap).unwrap();
        let back: Capability = serde_json::from_str(&s).unwrap();
        assert_eq!(cap, back);
        assert!(s.contains("\"op\":\"one_of\""));
    }
}
