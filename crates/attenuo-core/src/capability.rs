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
use crate::limits::{LimitError, LimitKind, Limits};
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
///
/// An argument carries at most one constraint (a capability maps each argument name to one
/// `ArgConstraint`), so kinds are never combined on one argument: a range that also excludes
/// a value is a Cedar rule, not a constraint.
///
/// Deserialization checks a `range`: at least one bound, `min <= max`, integer bounds and no
/// other members ([`ArgConstraint::range`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "value",
    rename_all = "snake_case",
    try_from = "RawConstraint"
)]
pub enum ArgConstraint {
    /// Argument must equal this JSON value (canonically; see above).
    Equals(Value),
    /// Argument must equal one of these JSON values.
    OneOf(Vec<Value>),
    /// Argument must be a string starting with this prefix.
    Prefix(String),
    /// Argument must be an integer (a Cedar `long`, read as [`as_long`] reads it) between the
    /// bounds, both inclusive. A missing bound is unbounded on that side. Serialized as
    /// `{"op": "range", "value": {"min": 0, "max": 2000}}`, a missing bound omitted. Build it
    /// with [`ArgConstraint::range`], which checks the bounds.
    Range {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<i64>,
    },
}

/// The wire form of [`ArgConstraint`], checked by `TryFrom` on the way in.
#[derive(Deserialize)]
#[serde(tag = "op", content = "value", rename_all = "snake_case")]
enum RawConstraint {
    Equals(Value),
    OneOf(Vec<Value>),
    Prefix(String),
    Range(RawRange),
}

/// The `value` of a `range`: an object with optional integer members `min` and `max` and
/// nothing else. Read by hand so that a list (`[0, 5]`, which a derived struct would accept as
/// a tuple), a repeated member or a misspelt one (`maximum`, which would otherwise read as no
/// upper bound) is refused.
struct RawRange {
    min: Option<i64>,
    max: Option<i64>,
}

impl<'de> Deserialize<'de> for RawRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = RawRange;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object with integer members `min` and/or `max`")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<RawRange, A::Error> {
                use serde::de::Error;
                let mut out = RawRange {
                    min: None,
                    max: None,
                };
                while let Some(key) = map.next_key::<String>()? {
                    let slot = match key.as_str() {
                        "min" => &mut out.min,
                        "max" => &mut out.max,
                        other => return Err(A::Error::unknown_field(other, &["min", "max"])),
                    };
                    if slot.is_some() {
                        return Err(A::Error::custom(format!("duplicate range member `{key}`")));
                    }
                    *slot = Some(map.next_value::<i64>()?);
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}

impl TryFrom<RawConstraint> for ArgConstraint {
    type Error = RangeError;

    fn try_from(raw: RawConstraint) -> Result<Self, RangeError> {
        Ok(match raw {
            RawConstraint::Equals(v) => ArgConstraint::Equals(v),
            RawConstraint::OneOf(vs) => ArgConstraint::OneOf(vs),
            RawConstraint::Prefix(p) => ArgConstraint::Prefix(p),
            RawConstraint::Range(r) => ArgConstraint::range(r.min, r.max)?,
        })
    }
}

/// Why a `range` constraint is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    /// Neither `min` nor `max`: it would constrain nothing but the type.
    #[error("a range constraint needs `min`, `max` or both")]
    Unbounded,
    /// `min > max`: no value could satisfy it.
    #[error("a range constraint's min {min} is greater than its max {max}")]
    Inverted { min: i64, max: i64 },
}

/// Largest magnitude of a float that counts as a whole number, as the Cedar translation in
/// `attenuo-policy` reads it (its `DECIMAL_MAX`, inside Cedar's `decimal` range and below
/// 2^53, so every such float is exactly one integer).
const WHOLE_FLOAT_MAX: f64 = 922_337_203_685_477.0;

/// A JSON value as the Cedar `long` the policy engine would see, or `None` when it is not one:
/// an integer that fits in `i64`, or a float with no fractional part and a magnitude of at
/// most 922337203685477 (`5.0` is `5`). A fraction, a string, a larger number, `null` or
/// anything else is `None`, and satisfies no `range`.
pub fn as_long(value: &Value) -> Option<i64> {
    let n = value.as_number()?;
    if let Some(i) = n.as_i64() {
        return Some(i);
    }
    let f = n.as_f64()?;
    // |f| <= WHOLE_FLOAT_MAX < 2^63, so the cast is exact.
    (f.is_finite() && f.fract() == 0.0 && f.abs() <= WHOLE_FLOAT_MAX).then_some(f as i64)
}

/// Does `range` admit every value canonically equal to `v` ([`value_eq`])? `satisfied_by(v)`
/// alone is not enough: an integer above [`WHOLE_FLOAT_MAX`] in magnitude can also equal a
/// float (`10^16` and `1e16` have the same canonical form), and no range admits a float that
/// large, so `equals 10^16` would let through a value the range refuses (SR-71). Such an
/// integer has an equal float exactly when the float nearest to it is written with its digits.
fn range_admits_all_equal(range: &ArgConstraint, v: &Value) -> bool {
    range.satisfied_by(v)
        && as_long(v).is_some_and(|n| {
            n.unsigned_abs() <= WHOLE_FLOAT_MAX as u64
                || crate::jcs::format_f64(n as f64).as_deref() != Some(n.to_string().as_str())
        })
}

impl ArgConstraint {
    /// A checked `range`: at least one bound, and `min <= max` when both are given.
    pub fn range(min: Option<i64>, max: Option<i64>) -> Result<Self, RangeError> {
        match (min, max) {
            (None, None) => Err(RangeError::Unbounded),
            (Some(lo), Some(hi)) if lo > hi => Err(RangeError::Inverted { min: lo, max: hi }),
            _ => Ok(ArgConstraint::Range { min, max }),
        }
    }

    /// Canonical (RFC 8785) JSON form; equality and ordering are defined on it, so
    /// constraints can live in `BTreeSet`/`BTreeMap`.
    fn canonical(&self) -> Vec<u8> {
        crate::jcs::to_vec(self).expect("a constraint has a canonical JSON form")
    }

    /// A range's inclusive bounds over `i64`, a missing bound as the end of the type. `None`
    /// for other kinds. A range built unchecked with `min > max` has `lo > hi`: it is empty.
    fn bounds(&self) -> Option<(i64, i64)> {
        match self {
            ArgConstraint::Range { min, max } => {
                Some((min.unwrap_or(i64::MIN), max.unwrap_or(i64::MAX)))
            }
            _ => None,
        }
    }

    /// Does no value satisfy this constraint (an empty `one_of`, or a range with `min > max`,
    /// which only the unchecked variant can spell)?
    fn is_empty(&self) -> bool {
        match self {
            ArgConstraint::OneOf(vs) => vs.is_empty(),
            ArgConstraint::Range { .. } => self.bounds().is_some_and(|(lo, hi)| lo > hi),
            _ => false,
        }
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
            ArgConstraint::Range { .. } => match (self.bounds(), as_long(value)) {
                (Some((lo, hi)), Some(n)) => lo <= n && n <= hi,
                _ => false,
            },
        }
    }

    /// Why `value` (`None`: the argument is absent) does not satisfy this constraint, or `None`
    /// when it does. The text names the constraint's own figures (already in the token), never
    /// the value, which may be sensitive.
    pub fn violation(&self, value: Option<&Value>) -> Option<String> {
        let Some(value) = value else {
            return Some("is absent".into());
        };
        if self.satisfied_by(value) {
            return None;
        }
        Some(match self {
            ArgConstraint::Equals(_) => "does not equal the permitted value".into(),
            ArgConstraint::OneOf(_) => "is not one of the permitted values".into(),
            ArgConstraint::Prefix(p) => format!("does not start with {p:?}"),
            ArgConstraint::Range { min, max } => match (as_long(value), min, max) {
                (None, _, _) => "is not an integer".into(),
                (Some(n), Some(lo), _) if n < *lo => format!("is below the minimum {lo}"),
                (Some(n), _, Some(hi)) if n > *hi => format!("is above the maximum {hi}"),
                // Only an unchecked inverted range gets here.
                _ => "is outside the range".into(),
            },
        })
    }

    /// Does every value satisfying `self` also satisfy `other`?
    pub fn implies(&self, other: &ArgConstraint) -> bool {
        // A constraint no value satisfies (an empty `OneOf`, an unchecked inverted range)
        // vacuously implies every constraint. That is sound: a capability carrying it permits
        // nothing, and it can still be re-delegated unchanged.
        if self.is_empty() {
            return true;
        }
        match (self, other) {
            (ArgConstraint::Equals(a), ArgConstraint::Equals(b)) => value_eq(a, b),
            (ArgConstraint::Equals(a), ArgConstraint::OneOf(bs)) => {
                bs.iter().any(|b| value_eq(a, b))
            }
            (ArgConstraint::Equals(a), ArgConstraint::Prefix(p)) => a
                .as_str()
                .map(|s| s.starts_with(p.as_str()))
                .unwrap_or(false),
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
            // A value implies a range when it is an integer in it and every value equal to it is
            // one too; a set, when every member does.
            (ArgConstraint::Equals(a), ArgConstraint::Range { .. }) => {
                range_admits_all_equal(other, a)
            }
            (ArgConstraint::OneOf(as_), ArgConstraint::Range { .. }) => {
                as_.iter().all(|a| range_admits_all_equal(other, a))
            }
            // Containment of intervals over i64 (a missing bound is the end of the type).
            (ArgConstraint::Range { .. }, ArgConstraint::Range { .. }) => {
                match (self.bounds(), other.bounds()) {
                    (Some((a, b)), Some((c, d))) => c <= a && b <= d,
                    _ => false,
                }
            }
            // A range implies a value or a set only when it holds exactly one integer and that
            // integer is the value or in the set (`5` and `5.0` are the same value).
            (ArgConstraint::Range { .. }, ArgConstraint::Equals(_) | ArgConstraint::OneOf(_)) => {
                match self.bounds() {
                    Some((lo, hi)) if lo == hi => other.satisfied_by(&Value::from(lo)),
                    _ => false,
                }
            }
            // Strings and integers never meet.
            (ArgConstraint::Prefix(_), ArgConstraint::Range { .. })
            | (ArgConstraint::Range { .. }, ArgConstraint::Prefix(_)) => false,
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

/// Does `name` match a server or tool `pattern` of a capability: `*` matches anything,
/// `prefix*` matches names starting with `prefix`, anything else matches only itself.
pub fn pattern_matches(pattern: &str, name: &str) -> bool {
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
/// `limits` bound how many matched calls, and how much in total, the run may make under it
/// ([`crate::limits`]); absent (and omitted from the token) when there are none.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Capability {
    pub server: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, ArgConstraint>,
    #[serde(default, skip_serializing_if = "Limits::is_empty")]
    pub limits: Limits,
}

impl Capability {
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            constraints: BTreeMap::new(),
            limits: Limits::default(),
        }
    }

    pub fn with_constraint(mut self, arg: impl Into<String>, c: ArgConstraint) -> Self {
        self.constraints.insert(arg.into(), c);
        self
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Check the capability's limits ([`Limits::validate`]).
    pub fn validate_limits(&self) -> Result<(), LimitError> {
        self.limits.validate(self)
    }

    /// Check the server and tool patterns against [`crate::names`]: `*`, `<prefix>*` or a
    /// name. A capability that fails this could only ever match names no call can have.
    pub fn validate(&self) -> Result<(), NameError> {
        crate::names::check_server_pattern(&self.server)?;
        crate::names::check_call_pattern(&self.tool)
    }

    /// Does this capability permit every call that `child` permits, with limits no larger
    /// ([`Limits::narrows`])?
    pub fn covers(&self, child: &Capability) -> bool {
        self.covers_calls(child) && child.limits.narrows(&self.limits)
    }

    /// The call half of [`covers`](Self::covers): patterns and constraints, ignoring limits.
    pub fn covers_calls(&self, child: &Capability) -> bool {
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

    /// Why this capability does not permit `call` although its server and tool patterns match
    /// it: the first constraint the call fails, as ``argument `amount` is above the maximum
    /// 2000`` ([`ArgConstraint::violation`]; the argument's value is never echoed). `None` when
    /// the patterns do not match or every constraint is met.
    pub fn explain_denial(&self, call: &ToolCall) -> Option<String> {
        if !pattern_matches(&self.server, &call.server) || !pattern_matches(&self.tool, &call.tool)
        {
            return None;
        }
        self.constraints.iter().find_map(|(arg, c)| {
            c.violation(call.arguments.get(arg))
                .map(|why| format!("argument `{arg}` {why}"))
        })
    }

    /// Human-readable form used in errors and logs, e.g. `github:create_issue{repo=...}`,
    /// with ` limits={...}` appended when the capability has limits.
    pub fn display(&self) -> String {
        let mut s = if self.constraints.is_empty() {
            format!("{}:{}", self.server, self.tool)
        } else {
            let cs: Vec<String> = self
                .constraints
                .iter()
                .map(|(k, v)| format!("{k}={}", serde_json::to_string(v).unwrap_or_default()))
                .collect();
            format!("{}:{}{{{}}}", self.server, self.tool, cs.join(","))
        };
        if !self.limits.is_empty() {
            s.push_str(" limits=");
            s.push_str(&serde_json::to_string(&self.limits).unwrap_or_default());
        }
        s
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

    /// [`Capability::validate_limits`] every member.
    pub fn validate_limits(&self) -> Result<(), LimitError> {
        self.0.iter().try_for_each(Capability::validate_limits)
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
    /// This is the attenuation step performed at every delegation hop. Limits are clamped, not
    /// refused ([`attenuate_with`](Self::attenuate_with) with nothing spent yet).
    pub fn attenuate(&self, requested: &CapabilitySet) -> Result<CapabilitySet, AttenuationError> {
        self.attenuate_with(requested, |_, _, _| None)
    }

    /// [`attenuate`](Self::attenuate), with each requested capability's limits clamped at
    /// exchange time (ADR-0010):
    ///
    /// - A requested capability that a parent capability covers as it is keeps its limits,
    ///   lowered by `remaining` below. The one other change: a `calls_per` or `distinct` above
    ///   the parent's on the same argument is lowered to the parent's figure. Such a request is
    ///   covered only because its `calls` is no larger than that figure
    ///   ([`Limits::narrows`]), so the bound in force is the same before and after.
    /// - Otherwise the first parent capability that covers its calls
    ///   ([`Capability::covers_calls`]) is its parent: limits the parent has and the request
    ///   lacks are copied, and larger figures are lowered to the parent's
    ///   ([`Limits::clamp_to`]).
    /// - Then `calls` and `sum` are lowered further to `remaining(parent_index, kind, max)`
    ///   when it returns `Some`: what the parent capability (by its index in `self`) has
    ///   left of `max`. The server reads that from the lease store; the static check cannot.
    ///
    /// The result must then be covered by `self`, or the request fails as not covered. A
    /// child requesting no limit under a limited parent so gets the parent's figure.
    pub fn attenuate_with(
        &self,
        requested: &CapabilitySet,
        remaining: impl Fn(usize, LimitKind, u64) -> Option<u64>,
    ) -> Result<CapabilitySet, AttenuationError> {
        if requested.is_empty() {
            return Err(AttenuationError::Empty);
        }
        let mut out = BTreeSet::new();
        for c in requested.0.iter() {
            let not_covered = || AttenuationError::NotCovered {
                requested: c.display(),
            };
            let (index, parent) = self
                .0
                .iter()
                .enumerate()
                .find(|(_, p)| p.covers(c))
                .or_else(|| self.0.iter().enumerate().find(|(_, p)| p.covers_calls(c)))
                .ok_or_else(not_covered)?;
            let mut child = c.clone();
            child.limits = c.limits.clamp_to(&parent.limits);
            if let (Some(calls), Some(max)) = (child.limits.calls, parent.limits.calls) {
                if let Some(left) = remaining(index, LimitKind::Calls, max) {
                    child.limits.calls = Some(calls.min(left));
                }
            }
            if let (Some(sum), Some(p)) = (child.limits.sum.as_mut(), parent.limits.sum.as_ref()) {
                if sum.arg == p.arg {
                    if let Some(left) = remaining(index, LimitKind::Sum, p.max) {
                        sum.max = sum.max.min(left);
                    }
                }
            }
            if !parent.covers(&child) {
                return Err(not_covered());
            }
            out.insert(child);
        }
        Ok(CapabilitySet(out))
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

    fn range(min: Option<i64>, max: Option<i64>) -> ArgConstraint {
        ArgConstraint::range(min, max).unwrap()
    }

    #[test]
    fn range_members_are_checked_whatever_the_member_order() {
        // With `value` before `op`, serde buffers the value before choosing the variant; the
        // range checks still apply to the buffered form.
        let parse = |s: &str| serde_json::from_str::<ArgConstraint>(s);
        assert_eq!(
            parse(r#"{"value":{"max":5},"op":"range"}"#).unwrap(),
            range(None, Some(5))
        );
        for s in [
            r#"{"value":{"max":5,"max":9},"op":"range"}"#,
            r#"{"op":"range","value":{"max":5,"max":9}}"#,
            r#"{"value":{"maximum":5},"op":"range"}"#,
            r#"{"value":[0,5],"op":"range"}"#,
            r#"{"value":{"max":5.0},"op":"range"}"#,
            r#"{"value":{"max":1e3},"op":"range"}"#,
            r#"{"value":{"max":9223372036854775808},"op":"range"}"#,
            r#"{"value":{"min":2,"max":1},"op":"range"}"#,
        ] {
            assert!(parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn range_serde_round_trip_and_validation() {
        let r = range(Some(0), Some(2000));
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"op":"range","value":{"min":0,"max":2000}}"#);
        assert_eq!(serde_json::from_str::<ArgConstraint>(&s).unwrap(), r);
        // A missing bound is omitted, and read back as unbounded.
        let upper = range(None, Some(5));
        assert_eq!(
            serde_json::to_value(&upper).unwrap(),
            json!({"op": "range", "value": {"max": 5}})
        );
        let lower: ArgConstraint =
            serde_json::from_value(json!({"op": "range", "value": {"min": -3}})).unwrap();
        assert_eq!(
            lower,
            ArgConstraint::Range {
                min: Some(-3),
                max: None
            }
        );
        // A capability carrying it round-trips, and its canonical form sorts the bounds.
        let cap = Capability::new("bank", "send_money").with_constraint("amount", r.clone());
        let back: Capability = serde_json::from_str(&serde_json::to_string(&cap).unwrap()).unwrap();
        assert_eq!(back, cap);
        assert_eq!(
            crate::jcs::to_vec(&r).unwrap(),
            br#"{"op":"range","value":{"max":2000,"min":0}}"#
        );

        let bad = |v: Value| {
            serde_json::from_value::<ArgConstraint>(v)
                .unwrap_err()
                .to_string()
        };
        assert!(bad(json!({"op": "range", "value": {}})).contains("needs `min`, `max` or both"));
        assert!(bad(json!({"op": "range", "value": {"min": 3, "max": 2}}))
            .contains("min 3 is greater than its max 2"));
        // Bounds are integers; a typo is refused rather than read as a missing bound.
        bad(json!({"op": "range", "value": {"min": 1.5}}));
        bad(json!({"op": "range", "value": {"min": "1"}}));
        bad(json!({"op": "range", "value": {"min": 1, "maximum": 5}}));
        bad(json!({"op": "range", "value": [0, 5]}));
        bad(json!({"op": "range", "value": {"min": null}}));
        let dup = r#"{"op":"range","value":{"max":5,"max":5000}}"#;
        assert!(serde_json::from_str::<ArgConstraint>(dup)
            .unwrap_err()
            .to_string()
            .contains("duplicate range member `max`"));
        bad(json!({"op": "range", "value": {"max": 9_223_372_036_854_775_808u64}}));
        assert_eq!(ArgConstraint::range(None, None), Err(RangeError::Unbounded));
        assert_eq!(
            ArgConstraint::range(Some(1), Some(0)),
            Err(RangeError::Inverted { min: 1, max: 0 })
        );
        assert!(ArgConstraint::range(Some(7), Some(7)).is_ok());
    }

    #[test]
    fn range_is_satisfied_by_integers_in_bounds() {
        let r = range(Some(0), Some(2000));
        for ok in [json!(0), json!(1), json!(2000), json!(5.0), json!(2000.0)] {
            assert!(r.satisfied_by(&ok), "{ok}");
        }
        for no in [
            json!(-1),
            json!(2001),
            json!(1.5),
            json!("5"),
            json!(null),
            json!(true),
            json!([5]),
            json!({"v": 5}),
            json!(1e300),
            json!(18_446_744_073_709_551_615u64),
        ] {
            assert!(!r.satisfied_by(&no), "{no}");
        }
        // Unbounded sides reach the ends of i64, and no further.
        let neg = range(None, Some(-1));
        assert!(neg.satisfied_by(&json!(i64::MIN)));
        assert!(!neg.satisfied_by(&json!(0)));
        let big = range(Some(0), None);
        assert!(big.satisfied_by(&json!(i64::MAX)));
        assert!(!big.satisfied_by(&json!(9_223_372_036_854_775_808u64)));
        // A whole float beyond Cedar's decimal range is not a long the engine would see.
        assert!(!big.satisfied_by(&json!(1e15)));
        assert_eq!(
            as_long(&json!(922_337_203_685_477.0)),
            Some(922_337_203_685_477)
        );
    }

    #[test]
    fn range_violation_names_the_bound_not_the_value() {
        let r = range(Some(10), Some(2000));
        assert_eq!(r.violation(Some(&json!(500))), None);
        assert_eq!(
            r.violation(Some(&json!(9))).unwrap(),
            "is below the minimum 10"
        );
        assert_eq!(
            r.violation(Some(&json!(2001))).unwrap(),
            "is above the maximum 2000"
        );
        assert_eq!(r.violation(Some(&json!(2.5))).unwrap(), "is not an integer");
        assert_eq!(r.violation(None).unwrap(), "is absent");
        let cap = Capability::new("bank", "send_money").with_constraint("amount", r);
        let why = cap
            .explain_denial(&call("bank", "send_money", json!({"amount": 31337})))
            .unwrap();
        assert_eq!(why, "argument `amount` is above the maximum 2000");
        assert!(!why.contains("31337"));
        assert_eq!(
            cap.explain_denial(&call("bank", "send_money", json!({"amount": 20}))),
            None
        );
        assert_eq!(
            cap.explain_denial(&call("bank", "other", json!({"amount": 1}))),
            None
        );
    }

    #[test]
    fn equals_a_large_integer_implies_a_range_only_when_every_equal_value_is_a_long_sr71() {
        // `equals 10^16` admits the float `1e16` too (the same canonical number), and a range
        // refuses a float of that size, so `equals` would let through a value the parent's
        // range does not: not an implication.
        let big: i64 = 10_000_000_000_000_000;
        let r = range(Some(0), Some(2 * big));
        let eq = ArgConstraint::Equals(json!(big));
        assert!(eq.satisfied_by(&json!(1e16)));
        assert!(!r.satisfied_by(&json!(1e16)));
        assert!(!eq.implies(&r));
        assert!(!ArgConstraint::OneOf(vec![json!(1), json!(big)]).implies(&r));
        // No float equals an integer that has no exact double, and every float that equals a
        // small integer is a long: those still imply the range.
        let odd = (1i64 << 53) + 1;
        assert!(ArgConstraint::Equals(json!(odd)).implies(&range(Some(0), None)));
        assert!(ArgConstraint::Equals(json!(i64::MAX)).implies(&range(Some(0), None)));
        assert!(ArgConstraint::Equals(json!(922_337_203_685_477i64)).implies(&r));
        assert!(
            ArgConstraint::Equals(json!(-922_337_203_685_477i64)).implies(&range(None, Some(0)))
        );
        assert!(
            !ArgConstraint::Equals(json!(-922_337_203_685_478i64)).implies(&range(None, Some(0)))
        );
        // Exhaustively near the edge: whenever `equals n` implies the range, every value that
        // satisfies `equals n` satisfies the range.
        for n in [
            922_337_203_685_476i64,
            922_337_203_685_477,
            922_337_203_685_478,
            1 << 53,
            (1 << 53) + 1,
            (1 << 53) + 2,
            i64::MAX - 1,
            i64::MAX,
            i64::MIN,
        ] {
            let eq = ArgConstraint::Equals(json!(n));
            let all = range(Some(i64::MIN), Some(i64::MAX));
            if eq.implies(&all) {
                for v in [json!(n), json!(n as f64)] {
                    assert!(!eq.satisfied_by(&v) || all.satisfied_by(&v), "{n}: {v}");
                }
            }
        }
    }

    #[test]
    fn range_implication() {
        let r = range(Some(0), Some(2000));
        // range ⊑ range: containment, a missing bound unbounded.
        assert!(r.implies(&r));
        assert!(range(Some(10), Some(500)).implies(&r));
        assert!(range(Some(0), Some(0)).implies(&r));
        assert!(!range(Some(-1), Some(500)).implies(&r));
        assert!(!range(Some(10), Some(2001)).implies(&r));
        assert!(!range(Some(10), None).implies(&r));
        assert!(range(Some(10), None).implies(&range(Some(0), None)));
        assert!(r.implies(&range(None, Some(2000))));
        assert!(!range(None, Some(5)).implies(&r));
        // A missing bound is the end of i64, so it equals the explicit extreme.
        assert!(range(None, Some(5)).implies(&range(Some(i64::MIN), Some(5))));
        assert!(range(Some(i64::MIN), Some(5)).implies(&range(None, Some(5))));
        // equals / one_of ⊑ range: every member an integer in range.
        assert!(ArgConstraint::Equals(json!(2000)).implies(&r));
        assert!(ArgConstraint::Equals(json!(5.0)).implies(&r));
        assert!(!ArgConstraint::Equals(json!(2001)).implies(&r));
        assert!(!ArgConstraint::Equals(json!(1.5)).implies(&r));
        assert!(!ArgConstraint::Equals(json!("5")).implies(&r));
        assert!(ArgConstraint::OneOf(vec![json!(0), json!(7), json!(2000)]).implies(&r));
        assert!(!ArgConstraint::OneOf(vec![json!(0), json!("7")]).implies(&r));
        assert!(!ArgConstraint::OneOf(vec![json!(0), json!(2001)]).implies(&r));
        assert!(ArgConstraint::OneOf(vec![]).implies(&r));
        // range ⊑ equals / one_of: only a single-integer range whose integer is covered.
        let seven = range(Some(7), Some(7));
        assert!(seven.implies(&ArgConstraint::Equals(json!(7))));
        assert!(seven.implies(&ArgConstraint::Equals(json!(7.0))));
        assert!(seven.implies(&ArgConstraint::OneOf(vec![json!(1), json!(7)])));
        assert!(!seven.implies(&ArgConstraint::Equals(json!(8))));
        assert!(!seven.implies(&ArgConstraint::Equals(json!("7"))));
        assert!(!range(Some(7), Some(8)).implies(&ArgConstraint::OneOf(vec![json!(7), json!(8)])));
        assert!(!r.implies(&ArgConstraint::Equals(json!(0))));
        // prefix never relates to range.
        let p = ArgConstraint::Prefix("1".into());
        assert!(!p.implies(&r));
        assert!(!r.implies(&p));
        assert!(!seven.implies(&ArgConstraint::Prefix(String::new())));
        // An inverted range, which only the unchecked variant can spell, admits nothing.
        let empty = ArgConstraint::Range {
            min: Some(1),
            max: Some(0),
        };
        assert!(!empty.satisfied_by(&json!(0)) && !empty.satisfied_by(&json!(1)));
        assert!(empty.implies(&p) && empty.implies(&ArgConstraint::Equals(json!(3))));
    }

    #[test]
    fn range_attenuation_narrows_and_refuses_widening() {
        let parent = CapabilitySet::from_iter([Capability::new("bank", "send_money")
            .with_constraint("amount", range(Some(0), Some(2000)))]);
        let narrower = CapabilitySet::from_iter([Capability::new("bank", "send_money")
            .with_constraint("amount", range(Some(0), Some(500)))]);
        assert_eq!(parent.attenuate(&narrower).unwrap(), narrower);
        let pinned = CapabilitySet::from_iter([Capability::new("bank", "send_money")
            .with_constraint("amount", ArgConstraint::OneOf(vec![json!(10), json!(20)]))]);
        assert_eq!(parent.attenuate(&pinned).unwrap(), pinned);
        for wider in [
            range(Some(0), Some(5000)),
            range(Some(-1), Some(2000)),
            range(None, Some(2000)),
            range(Some(0), None),
        ] {
            let child = CapabilitySet::from_iter([
                Capability::new("bank", "send_money").with_constraint("amount", wider.clone())
            ]);
            assert!(
                matches!(
                    parent.attenuate(&child),
                    Err(AttenuationError::NotCovered { .. })
                ),
                "{wider:?}"
            );
        }
        // Dropping the constraint widens too.
        let bare = CapabilitySet::from_iter([Capability::new("bank", "send_money")]);
        assert!(parent.attenuate(&bare).is_err());
        // The range is enforced on calls, absent argument included.
        let cap = parent.iter().next().unwrap();
        assert!(cap.permits(&call("bank", "send_money", json!({"amount": 2000}))));
        assert!(!cap.permits(&call("bank", "send_money", json!({"amount": 2001}))));
        assert!(!cap.permits(&call("bank", "send_money", json!({}))));
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
