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
/// other members ([`ArgConstraint::range`]); and a `path_prefix`: its own path must pass the
/// rules it applies to values ([`ArgConstraint::path_prefix`]).
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
    /// Argument must be a string starting with this prefix. A plain string comparison: `"/a/"`
    /// admits `"/a/../etc/passwd"`, and `"/a"` admits `"/a-secrets"`. For file paths use
    /// [`ArgConstraint::PathPrefix`].
    Prefix(String),
    /// Argument must be a string naming a path at or below this one, compared segment by
    /// segment on `/`: `{"op": "path_prefix", "value": "/workspace"}` admits `/workspace` and
    /// `/workspace/a/b.txt`, not `/workspace-secrets/x`. A value holding a `.` or `..`
    /// segment, an empty segment (`//`), a backslash, a control character or a percent-encoded
    /// `.`, `/` or `\` (`%2e`, `%2f`, `%5c`, any case) is refused, never normalised: so is
    /// `/workspace/../etc/passwd`. A trailing `/` on the value is ignored; a trailing `/` on
    /// the constraint's path asks for one more segment or a trailing `/` on the value, so that
    /// `/workspace/` admits `/workspace/` and `/workspace/a` but not `/workspace`. An absolute
    /// path (leading `/`) admits only absolute values, a relative one only relative values.
    /// Every value it admits starts with its path as a string, so `path_prefix: P` is always
    /// narrower than `prefix: P`. Build it with [`ArgConstraint::path_prefix`], which checks
    /// the path; an unchecked one whose path breaks the rules admits nothing.
    PathPrefix(String),
    /// Argument must be an integer (a Cedar `long`, read as [`as_long`] reads it) between the
    /// bounds, both inclusive. A missing bound is unbounded on that side. Serialized as
    /// `{"op": "range", "value": {"min": 0, "max": 2000}}`, a missing bound omitted. Build it
    /// with [`ArgConstraint::range`], which checks the bounds.
    Range {
        /// Smallest allowed value, inclusive; `None` for no lower bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<i64>,
        /// Largest allowed value, inclusive; `None` for no upper bound.
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
    PathPrefix(String),
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
    type Error = ConstraintError;

    fn try_from(raw: RawConstraint) -> Result<Self, ConstraintError> {
        Ok(match raw {
            RawConstraint::Equals(v) => ArgConstraint::Equals(v),
            RawConstraint::OneOf(vs) => ArgConstraint::OneOf(vs),
            RawConstraint::Prefix(p) => ArgConstraint::Prefix(p),
            RawConstraint::PathPrefix(p) => ArgConstraint::path_prefix(p)?,
            RawConstraint::Range(r) => ArgConstraint::range(r.min, r.max)?,
        })
    }
}

/// Why a constraint read from the wire is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConstraintError {
    /// A `range` with no bound or with `min > max`.
    #[error(transparent)]
    Range(#[from] RangeError),
    /// A `path_prefix` whose own path breaks the path rules.
    #[error("a path_prefix constraint's path {0}")]
    PathPrefix(#[from] PathError),
}

/// Why a string is not a plain path as `path_prefix` reads one. Each variant reads as the end
/// of a sentence about the string ("the value holds a `..` segment").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The empty string.
    #[error("is empty")]
    Empty,
    /// A `.` or `..` segment, which a file system resolves to another directory.
    #[error("holds a `.` or `..` segment")]
    DotSegment,
    /// Two `/` in a row: an empty segment.
    #[error("holds an empty segment (`//`)")]
    EmptySegment,
    /// A `\`, which Windows and WHATWG URL parsers read as a separator.
    #[error("holds a backslash")]
    Backslash,
    /// A control character (NUL, tab, line feed, DEL and the C1 range).
    #[error("holds a control character")]
    Control,
    /// `%2e`, `%2f` or `%5c` in either case, which a tool that percent-decodes reads as `.`,
    /// `/` or `\`.
    #[error("holds a percent-encoded `.`, `/` or `\\`")]
    EncodedSeparator,
}

/// A string read as a path by [`parse_path`]: whether it starts with `/`, its segments
/// between `/`, and whether it ends with `/`.
struct PathSegments<'a> {
    absolute: bool,
    segments: Vec<&'a str>,
    dir: bool,
}

/// Read `s` as a plain path, refusing what a file system or a decoding tool could resolve
/// outside the segments it spells: see [`PathError`]. `/` is absolute with no segments; a
/// trailing `/` is noted and not a segment.
fn parse_path(s: &str) -> Result<PathSegments<'_>, PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.contains('\\') {
        return Err(PathError::Backslash);
    }
    if s.chars().any(char::is_control) {
        return Err(PathError::Control);
    }
    let encoded = s.as_bytes().windows(3).any(|w| {
        w[0] == b'%'
            && matches!(
                (w[1], w[2].to_ascii_lowercase()),
                (b'2', b'e') | (b'2', b'f') | (b'5', b'c')
            )
    });
    if encoded {
        return Err(PathError::EncodedSeparator);
    }
    if s.contains("//") {
        return Err(PathError::EmptySegment);
    }
    let absolute = s.starts_with('/');
    let body = s.strip_prefix('/').unwrap_or(s);
    let dir = s.ends_with('/');
    let body = body.strip_suffix('/').unwrap_or(body);
    let segments: Vec<&str> = if body.is_empty() {
        Vec::new()
    } else {
        body.split('/').collect()
    };
    if segments.iter().any(|seg| *seg == "." || *seg == "..") {
        return Err(PathError::DotSegment);
    }
    Ok(PathSegments {
        absolute,
        segments,
        dir,
    })
}

/// Does the path `value` lie at or below the path `base` ([`ArgConstraint::PathPrefix`])?
/// Both already passed [`parse_path`]. The same test decides whether one `path_prefix` is
/// within another, since every value the narrower one admits has at least its segments and,
/// when it ends in `/`, one more segment or a trailing `/`.
fn path_within(base: &PathSegments<'_>, value: &PathSegments<'_>) -> bool {
    base.absolute == value.absolute
        && value.segments.starts_with(&base.segments)
        && (!base.dir || value.dir || value.segments.len() > base.segments.len())
}

/// [`path_within`] on strings: `false` when either is not a plain path.
fn path_str_within(base: &str, value: &str) -> bool {
    match (parse_path(base), parse_path(value)) {
        (Ok(b), Ok(v)) => path_within(&b, &v),
        _ => false,
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
    Inverted {
        /// The lower bound given.
        min: i64,
        /// The upper bound given, smaller than `min`.
        max: i64,
    },
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
    if !(f.is_finite() && f.fract() == 0.0 && f.abs() <= WHOLE_FLOAT_MAX) {
        return None;
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "|f| <= WHOLE_FLOAT_MAX < 2^63 and f has no fraction, so the cast is exact"
    )]
    let whole = f as i64;
    Some(whole)
}

/// Does `range` admit every value canonically equal to `v` ([`value_eq`])? `satisfied_by(v)`
/// alone is not enough: an integer above [`WHOLE_FLOAT_MAX`] in magnitude can also equal a
/// float (`10^16` and `1e16` have the same canonical form), and no range admits a float that
/// large, so `equals 10^16` would let through a value the range refuses (SR-71). Such an
/// integer has an equal float exactly when the float nearest to it is written with its digits.
fn range_admits_all_equal(range: &ArgConstraint, v: &Value) -> bool {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "WHOLE_FLOAT_MAX is a positive whole number far below 2^64"
    )]
    const WHOLE_FLOAT_MAX_U64: u64 = WHOLE_FLOAT_MAX as u64;
    range.satisfied_by(v)
        && as_long(v).is_some_and(|n| {
            n.unsigned_abs() <= WHOLE_FLOAT_MAX_U64
                || crate::jcs::format_f64(n as f64).as_deref() != Some(n.to_string().as_str())
        })
}

impl ArgConstraint {
    /// A checked `range`: at least one bound, and `min <= max` when both are given.
    ///
    /// # Errors
    ///
    /// [`RangeError::Unbounded`] when both bounds are `None`, and [`RangeError::Inverted`] when
    /// `min > max`.
    pub fn range(min: Option<i64>, max: Option<i64>) -> Result<Self, RangeError> {
        match (min, max) {
            (None, None) => Err(RangeError::Unbounded),
            (Some(lo), Some(hi)) if lo > hi => Err(RangeError::Inverted { min: lo, max: hi }),
            _ => Ok(ArgConstraint::Range { min, max }),
        }
    }

    /// A checked `path_prefix`: `path` must itself be a plain path, non-empty, with no `.`,
    /// `..` or empty segment, backslash, control character or percent-encoded `.`, `/` or `\`
    /// ([`ArgConstraint::PathPrefix`] has the matching rules). Absolute and relative paths are
    /// both allowed.
    ///
    /// # Errors
    ///
    /// The [`PathError`] that `path` breaks.
    pub fn path_prefix(path: impl Into<String>) -> Result<Self, PathError> {
        let path = path.into();
        parse_path(&path)?;
        Ok(ArgConstraint::PathPrefix(path))
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

    /// Does no value satisfy this constraint (an empty `one_of`, a range with `min > max` or a
    /// `path_prefix` whose path breaks the path rules, which only the unchecked variants can
    /// spell)?
    fn is_empty(&self) -> bool {
        match self {
            ArgConstraint::OneOf(vs) => vs.is_empty(),
            ArgConstraint::Range { .. } => self.bounds().is_some_and(|(lo, hi)| lo > hi),
            ArgConstraint::PathPrefix(p) => parse_path(p).is_err(),
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
            ArgConstraint::PathPrefix(base) => {
                value.as_str().is_some_and(|s| path_str_within(base, s))
            }
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
            ArgConstraint::PathPrefix(p) => match value.as_str().map(parse_path) {
                None => "is not a string".into(),
                Some(Err(e)) => format!("is not a plain path: it {e}"),
                Some(Ok(_)) => format!("is not a path at or below {p:?}"),
            },
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
            // A value or a set is within a path prefix when every member is.
            (ArgConstraint::Equals(a), ArgConstraint::PathPrefix(_)) => other.satisfied_by(a),
            (ArgConstraint::OneOf(as_), ArgConstraint::PathPrefix(_)) => {
                as_.iter().all(|a| other.satisfied_by(a))
            }
            // One path prefix within another: the child's own path is a value the parent
            // admits, and so is everything below it ([`path_within`]). `self` is a plain path
            // here (an invalid one is empty, handled above).
            (ArgConstraint::PathPrefix(q), ArgConstraint::PathPrefix(_)) => {
                other.satisfied_by(&Value::String(q.clone()))
            }
            // Every value a path prefix admits starts with its path as a string (it admits its
            // own path, and everything else it admits continues it after a `/`), so it is
            // within a string prefix exactly when its path starts with that prefix.
            (ArgConstraint::PathPrefix(q), ArgConstraint::Prefix(p)) => q.starts_with(p.as_str()),
            // A string prefix admits `P../x`; no path prefix holds that.
            (ArgConstraint::Prefix(_), ArgConstraint::PathPrefix(_)) => false,
            // A prefix admits infinitely many values; it cannot imply an exact or finite set.
            (ArgConstraint::Prefix(_) | ArgConstraint::PathPrefix(_), ArgConstraint::Equals(_))
            | (ArgConstraint::Prefix(_) | ArgConstraint::PathPrefix(_), ArgConstraint::OneOf(_)) => {
                false
            }
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
            (
                ArgConstraint::Prefix(_) | ArgConstraint::PathPrefix(_),
                ArgConstraint::Range { .. },
            )
            | (
                ArgConstraint::Range { .. },
                ArgConstraint::Prefix(_) | ArgConstraint::PathPrefix(_),
            ) => false,
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
    /// Server name pattern: exact, `*` or `prefix*` ([`pattern_matches`]).
    pub server: String,
    /// Tool name pattern: exact, `*` or `prefix*` ([`pattern_matches`]).
    pub tool: String,
    /// Constraints on named arguments; an argument not listed here is unconstrained.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, ArgConstraint>,
    /// Run limits on calls this capability matches; empty when there are none.
    #[serde(default, skip_serializing_if = "Limits::is_empty")]
    pub limits: Limits,
}

impl Capability {
    /// A capability for `tool` on `server` with no constraints and no limits.
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            constraints: BTreeMap::new(),
            limits: Limits::default(),
        }
    }

    /// Add (or replace) the constraint on argument `arg`.
    pub fn with_constraint(mut self, arg: impl Into<String>, c: ArgConstraint) -> Self {
        self.constraints.insert(arg.into(), c);
        self
    }

    /// Set the run limits.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Check the capability's limits ([`Limits::validate`]).
    ///
    /// # Errors
    ///
    /// The first [`LimitError`] that [`Limits::validate`] finds in this capability's limits.
    pub fn validate_limits(&self) -> Result<(), LimitError> {
        self.limits.validate(self)
    }

    /// Check the server and tool patterns against [`crate::names`]: `*`, `<prefix>*` or a
    /// name. A capability that fails this could only ever match names no call can have.
    ///
    /// # Errors
    ///
    /// [`NameError`] if the server pattern or the tool pattern is neither `*` nor a valid name or
    /// `<prefix>*`: a `*` anywhere but the end, an empty or over-long pattern, or a character
    /// outside the name set.
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

/// Argument names that usually hold a file path ([`prefix_looks_like_path`]).
const PATH_ARG_NAMES: &[&str] = &["path", "file", "filename", "dir", "directory", "folder"];

/// Does a `prefix` constraint on argument `arg` with prefix `prefix` look meant for a file
/// path, where `path_prefix` is the constraint that holds? True when the argument is named
/// `path`, `file`, `filename`, `dir`, `directory` or `folder` or ends with `_path`, `_dir` or
/// `_file` (ASCII case ignored), or when the prefix starts with `/`, `./` or `~`, or holds a
/// `/` and no `://`. A heuristic for warnings only: it never refuses anything.
pub fn prefix_looks_like_path(arg: &str, prefix: &str) -> bool {
    let name = arg.to_ascii_lowercase();
    PATH_ARG_NAMES.contains(&name.as_str())
        || ["_path", "_dir", "_file"].iter().any(|s| name.ends_with(s))
        || prefix.starts_with('/')
        || prefix.starts_with("./")
        || prefix.starts_with('~')
        || (prefix.contains('/') && !prefix.contains("://"))
}

impl Capability {
    /// One warning per `prefix` constraint of this capability that looks meant for a file
    /// path ([`prefix_looks_like_path`]), recommending `path_prefix`: a string prefix also
    /// admits `..` segments below it. Empty when there is none. The capability is unchanged
    /// and still valid; this is advice for whoever wrote it.
    pub fn path_prefix_warnings(&self) -> Vec<String> {
        self.constraints
            .iter()
            .filter_map(|(arg, c)| match c {
                ArgConstraint::Prefix(p) if prefix_looks_like_path(arg, p) => {
                    let escape = if p.ends_with('/') { "../x" } else { "/../x" };
                    Some(format!(
                        "{}:{} argument {arg:?}: `prefix` {p:?} compares strings, so it also \
                         admits {:?}; use `path_prefix` for a file path",
                        self.server.escape_debug(),
                        self.tool.escape_debug(),
                        format!("{p}{escape}"),
                    ))
                }
                _ => None,
            })
            .collect()
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
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a capability; `false` if an identical one was already there.
    pub fn insert(&mut self, c: Capability) -> bool {
        self.0.insert(c)
    }

    /// Does the set hold no capabilities?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of capabilities in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The capabilities, in their canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.0.iter()
    }

    /// [`Capability::validate`] every member.
    ///
    /// # Errors
    ///
    /// The [`NameError`] of the first member, in canonical order, whose patterns
    /// [`Capability::validate`] refuses.
    pub fn validate(&self) -> Result<(), NameError> {
        self.0.iter().try_for_each(Capability::validate)
    }

    /// [`Capability::validate_limits`] every member.
    ///
    /// # Errors
    ///
    /// The [`LimitError`] of the first member, in canonical order, whose limits
    /// [`Limits::validate`] refuses.
    pub fn validate_limits(&self) -> Result<(), LimitError> {
        self.0.iter().try_for_each(Capability::validate_limits)
    }

    /// [`Capability::path_prefix_warnings`] of every member, in canonical order.
    pub fn path_prefix_warnings(&self) -> Vec<String> {
        self.0
            .iter()
            .flat_map(Capability::path_prefix_warnings)
            .collect()
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
    ///
    /// # Errors
    ///
    /// As [`attenuate_with`](Self::attenuate_with): [`AttenuationError::Empty`] for an empty
    /// `requested`, [`AttenuationError::NotCovered`] for the first requested capability no member
    /// of `self` covers.
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
    ///
    /// # Errors
    ///
    /// [`AttenuationError::Empty`] when `requested` is empty. [`AttenuationError::NotCovered`],
    /// naming the capability, when no member of `self` covers a requested capability's calls, or
    /// when the clamped capability is still not covered by its parent (a constraint or limit
    /// clamping cannot fix).
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

    // ------------------------------------------------------------ path_prefix (S-7, SR-73)

    fn pp(p: &str) -> ArgConstraint {
        ArgConstraint::path_prefix(p).unwrap()
    }

    #[test]
    fn path_prefix_refuses_each_class_whatever_the_base() {
        let c = pp("/workspace");
        let refused = [
            ("/workspace/../etc/passwd", PathError::DotSegment),
            ("/workspace/..", PathError::DotSegment),
            ("/workspace/./a", PathError::DotSegment),
            ("/workspace/a/.", PathError::DotSegment),
            ("/workspace//a", PathError::EmptySegment),
            ("/workspace/a//", PathError::EmptySegment),
            ("//workspace/a", PathError::EmptySegment),
            ("/workspace\\..\\etc", PathError::Backslash),
            ("/workspace/a\\b", PathError::Backslash),
            ("/workspace/a\u{0}", PathError::Control),
            ("/workspace/a\tb", PathError::Control),
            ("/workspace/a\nb", PathError::Control),
            ("/workspace/\u{7f}", PathError::Control),
            ("/workspace/\u{85}", PathError::Control),
            ("/workspace/%2e%2e/etc", PathError::EncodedSeparator),
            ("/workspace/%2E%2E/etc", PathError::EncodedSeparator),
            ("/workspace/.%2e/etc", PathError::EncodedSeparator),
            ("/workspace%2fa", PathError::EncodedSeparator),
            ("/workspace/a%2Fb", PathError::EncodedSeparator),
            ("/workspace/a%5cb", PathError::EncodedSeparator),
            ("/workspace/a%5Cb", PathError::EncodedSeparator),
            ("", PathError::Empty),
        ];
        for (v, why) in refused {
            assert_eq!(parse_path(v).err(), Some(why), "{v:?}");
            assert!(!c.satisfied_by(&json!(v)), "{v:?} must be refused");
            assert_eq!(
                c.violation(Some(&json!(v))),
                Some(format!("is not a plain path: it {why}")),
                "{v:?}"
            );
        }
        // Other escapes and dots inside a name are plain characters.
        for v in [
            "/workspace/a%20b",
            "/workspace/a%2",
            "/workspace/...",
            "/workspace/.env",
        ] {
            assert!(c.satisfied_by(&json!(v)), "{v:?}");
        }
    }

    #[test]
    fn prefix_keeps_admitting_what_path_prefix_refuses() {
        // Pinned: `prefix` is a string comparison and stays one (SR-73).
        let p = ArgConstraint::Prefix("/workspace/".into());
        assert!(p.satisfied_by(&json!("/workspace/../etc/passwd")));
        assert!(!pp("/workspace/").satisfied_by(&json!("/workspace/../etc/passwd")));
        let p = ArgConstraint::Prefix("/workspace".into());
        assert!(p.satisfied_by(&json!("/workspace-secrets/x")));
        assert!(!pp("/workspace").satisfied_by(&json!("/workspace-secrets/x")));
        assert_eq!(
            pp("/workspace").violation(Some(&json!("/workspace-secrets/x"))),
            Some("is not a path at or below \"/workspace\"".into())
        );
    }

    #[test]
    fn path_prefix_segments_and_trailing_slashes() {
        let admits = |c: &ArgConstraint, v: &str| c.satisfied_by(&json!(v));
        // No trailing slash on the base: the directory itself, with or without one, and below.
        let bare = pp("/workspace");
        for v in [
            "/workspace",
            "/workspace/",
            "/workspace/a",
            "/workspace/a/",
            "/workspace/a/b",
        ] {
            assert!(admits(&bare, v), "{v:?}");
        }
        for v in [
            "/workspac",
            "/workspacex",
            "/",
            "workspace/a",
            "/other/workspace",
        ] {
            assert!(!admits(&bare, v), "{v:?}");
        }
        // A trailing slash on the base: a value must continue it as a string.
        let dir = pp("/workspace/");
        for v in ["/workspace/", "/workspace/a", "/workspace/a/"] {
            assert!(admits(&dir, v), "{v:?}");
        }
        assert!(!admits(&dir, "/workspace"));
        // The root admits every absolute path and no relative one.
        let root = pp("/");
        for v in ["/", "/a", "/a/b/"] {
            assert!(admits(&root, v), "{v:?}");
        }
        assert!(!admits(&root, "a"));
        // A relative base admits only relative values.
        let rel = pp("docs");
        for v in ["docs", "docs/", "docs/a.md"] {
            assert!(admits(&rel, v), "{v:?}");
        }
        for v in ["/docs/a.md", "docsx", "./docs/a.md", "docs/../a"] {
            assert!(!admits(&rel, v), "{v:?}");
        }
        // Not a string.
        for v in [json!(1), json!(null), json!(["/workspace/a"])] {
            assert!(!bare.satisfied_by(&v));
            assert_eq!(bare.violation(Some(&v)), Some("is not a string".into()));
        }
        // Every value admitted starts with the base as a string.
        for (c, base) in [(&bare, "/workspace"), (&dir, "/workspace/"), (&rel, "docs")] {
            for v in [
                "/workspace",
                "/workspace/",
                "/workspace/a",
                "docs",
                "docs/a",
            ] {
                if admits(c, v) {
                    assert!(v.starts_with(base), "{v:?} under {base:?}");
                }
            }
        }
    }

    #[test]
    fn path_prefix_base_is_checked_when_built_and_read() {
        assert_eq!(ArgConstraint::path_prefix(""), Err(PathError::Empty));
        assert_eq!(
            ArgConstraint::path_prefix("/a/../b"),
            Err(PathError::DotSegment)
        );
        assert_eq!(
            ArgConstraint::path_prefix("./a"),
            Err(PathError::DotSegment)
        );
        assert_eq!(
            ArgConstraint::path_prefix("a//b"),
            Err(PathError::EmptySegment)
        );
        assert_eq!(
            ArgConstraint::path_prefix("C:\\a"),
            Err(PathError::Backslash)
        );
        assert_eq!(ArgConstraint::path_prefix("/a\n"), Err(PathError::Control));
        assert_eq!(
            ArgConstraint::path_prefix("/a%2F"),
            Err(PathError::EncodedSeparator)
        );
        for ok in ["/", "/a", "/a/", "a", "a/b/", "~/x", "/a b/c"] {
            assert!(ArgConstraint::path_prefix(ok).is_ok(), "{ok:?}");
        }
        for bad in ["", "/a/..", "/a//b", "/a\\b", "/a%2e%2e"] {
            let wire = json!({"op": "path_prefix", "value": bad});
            let err = serde_json::from_value::<ArgConstraint>(wire).unwrap_err();
            assert!(
                err.to_string().contains("a path_prefix constraint's path"),
                "{bad:?}: {err}"
            );
        }
        assert!(
            serde_json::from_value::<ArgConstraint>(json!({"op": "path_prefix", "value": 1}))
                .is_err()
        );
        // Built unchecked, a malformed base admits nothing and vacuously implies everything,
        // as an empty `one_of` does; nothing but an empty constraint implies it.
        let broken = ArgConstraint::PathPrefix("/a/../b".into());
        assert!(!broken.satisfied_by(&json!("/a/../b")));
        assert!(!broken.satisfied_by(&json!("/a/../b/c")));
        assert!(broken.implies(&ArgConstraint::Equals(json!("x"))));
        assert!(!pp("/a").implies(&broken));
        assert!(!ArgConstraint::Equals(json!("/a/../b")).implies(&broken));
        let empty = ArgConstraint::PathPrefix(String::new());
        assert!(!empty.satisfied_by(&json!("a")));
    }

    #[test]
    fn path_prefix_serde_round_trip() {
        let cap = Capability::new("fs", "read_file")
            .with_constraint("path", pp("/workspace/"))
            .with_constraint("dir", pp("docs"));
        let s = serde_json::to_string(&cap).unwrap();
        assert!(
            s.contains(r#"{"op":"path_prefix","value":"/workspace/"}"#),
            "{s}"
        );
        let back: Capability = serde_json::from_str(&s).unwrap();
        assert_eq!(cap, back);
        assert_ne!(pp("/workspace"), ArgConstraint::Prefix("/workspace".into()));
        assert_eq!(
            cap.display(),
            r#"fs:read_file{dir={"op":"path_prefix","value":"docs"},path={"op":"path_prefix","value":"/workspace/"}}"#
        );
    }

    #[test]
    fn path_prefix_narrows_under_path_prefix_by_segment() {
        let implies = |child: &str, parent: &str| pp(child).implies(&pp(parent));
        assert!(implies("/w", "/w"));
        assert!(implies("/w/", "/w/"));
        assert!(implies("/w/a", "/w"));
        assert!(implies("/w/a", "/w/"));
        assert!(implies("/w/a/b/", "/w/a"));
        assert!(implies("/w/", "/w"));
        assert!(implies("/w", "/"));
        assert!(implies("docs/a", "docs"));
        // Wider, a sibling or the other kind of path.
        assert!(!implies("/w", "/w/a"));
        assert!(!implies("/w", "/w/"));
        assert!(!implies("/w-x", "/w"));
        assert!(!implies("/wx/a", "/w"));
        assert!(!implies("w", "/w"));
        assert!(!implies("/w", "w"));
        assert!(!implies("/", "/w"));
        // Values and sets: each member must be admitted.
        let parent = pp("/w");
        assert!(ArgConstraint::Equals(json!("/w/a")).implies(&parent));
        assert!(!ArgConstraint::Equals(json!("/w/../etc")).implies(&parent));
        assert!(!ArgConstraint::Equals(json!(1)).implies(&parent));
        assert!(ArgConstraint::OneOf(vec![json!("/w"), json!("/w/a/")]).implies(&parent));
        assert!(!ArgConstraint::OneOf(vec![json!("/w/a"), json!("/w-x")]).implies(&parent));
        // A path prefix admits infinitely many strings and never an integer.
        assert!(!pp("/w/a").implies(&ArgConstraint::Equals(json!("/w/a"))));
        assert!(!pp("/w/a").implies(&ArgConstraint::OneOf(vec![json!("/w/a")])));
        assert!(!pp("/w/a").implies(&range(Some(0), None)));
        assert!(!range(Some(1), Some(1)).implies(&pp("/w")));
    }

    #[test]
    fn path_prefix_against_string_prefix() {
        let narrower =
            |child: &str, parent: &str| pp(child).implies(&ArgConstraint::Prefix(parent.into()));
        // Under a string prefix: only when the child's base starts with it, since the child
        // admits its own base.
        assert!(narrower("/workspace/", "/workspace/"));
        assert!(narrower("/workspace/a", "/workspace/"));
        assert!(narrower("/workspace", "/workspace"));
        assert!(narrower("/workspace", "/work"));
        assert!(narrower("/workspace", ""));
        assert!(!narrower("/workspace", "/workspace/"));
        assert!(!narrower("/w", "/x"));
        // A string prefix is never within a path prefix: it admits `P../x`.
        for (child, parent) in [("/w/", "/w"), ("/w/a/", "/w"), ("/w/a", "/")] {
            assert!(
                !ArgConstraint::Prefix(child.into()).implies(&pp(parent)),
                "{child}"
            );
        }
        // Through attenuation: switching a path argument from `prefix` to `path_prefix` with
        // the same string narrows; the other way round widens and is refused.
        let parent = CapabilitySet::from_iter([Capability::new("fs", "read_file")
            .with_constraint("path", ArgConstraint::Prefix("/workspace/".into()))]);
        let child = CapabilitySet::from_iter([
            Capability::new("fs", "read_file").with_constraint("path", pp("/workspace/"))
        ]);
        assert!(parent.attenuate(&child).is_ok());
        assert!(child.attenuate(&parent).is_err());
        let loose = CapabilitySet::from_iter([
            Capability::new("fs", "read_file").with_constraint("path", pp("/workspace"))
        ]);
        assert!(
            parent.attenuate(&loose).is_err(),
            "admits /workspace itself"
        );
    }

    #[test]
    fn prefix_on_a_path_like_argument_gets_a_warning() {
        let looks = prefix_looks_like_path;
        for arg in [
            "path",
            "File",
            "filename",
            "dir",
            "directory",
            "folder",
            "src_path",
        ] {
            assert!(looks(arg, "x"), "{arg}");
        }
        for arg in ["log_dir", "config_file", "OUT_FILE"] {
            assert!(looks(arg, "x"), "{arg}");
        }
        for p in ["/workspace/", "./src", "~/notes", "acme/", "a/b"] {
            assert!(looks("repo", p), "{p}");
        }
        for (arg, p) in [
            ("uri", "file:///public/"),
            ("url", "https://a.example/"),
            ("repo", "acme-"),
            ("paths", "x"),
        ] {
            assert!(!looks(arg, p), "{arg} {p}");
        }
        let set = CapabilitySet::from_iter([
            Capability::new("fs", "read_file")
                .with_constraint("path", ArgConstraint::Prefix("/workspace/".into()))
                .with_constraint("mode", ArgConstraint::Prefix("r".into())),
            Capability::new("fs", "write_file").with_constraint("path", pp("/workspace/")),
            Capability::new("web", "fetch")
                .with_constraint("url", ArgConstraint::Prefix("https://a.example/".into())),
        ]);
        assert_eq!(
            set.path_prefix_warnings(),
            vec![
                "fs:read_file argument \"path\": `prefix` \"/workspace/\" compares strings, so it \
                 also admits \"/workspace/../x\"; use `path_prefix` for a file path"
                    .to_string()
            ]
        );
        let bare = Capability::new("fs", "ls")
            .with_constraint("dir", ArgConstraint::Prefix("/srv".into()));
        assert!(bare.path_prefix_warnings()[0].contains("\"/srv/../x\""));
    }
}
