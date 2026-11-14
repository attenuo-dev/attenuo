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
use crate::error::{AttenuationError, SizeError};
use crate::jcs::value_eq;
use crate::limits::{LimitError, LimitKind, Limits};
use crate::names::NameError;

mod prepared;
use prepared::{PreparedCap, PreparedSet};

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
    ///
    /// The comparison is on text only. It does not resolve symbolic links, so a link under
    /// the path (one in a cloned repository, or one a granted tool created) leads the upstream
    /// outside it: with `/workspace/docs` linked to `/home/user/.ssh`, `/workspace/` admits
    /// `/workspace/docs/id_ed25519`. Pair it with an upstream that resolves the real path and
    /// checks it (the reference MCP filesystem server does), or do not grant tools that can
    /// create links under the path (SR-106).
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
    /// A character that compatibility normalisation (NFKC) or Windows "best fit" conversion
    /// turns into `.`, `/` or `\` ([`LOOKALIKE_SEPARATORS`]), such as `．` (U+FF0E) or `／`
    /// (U+FF0F): a tool that normalises or converts the path could read a `..` segment or a
    /// separator the path does not spell (SR-105).
    #[error("holds a character that normalises to `.`, `/` or `\\`")]
    LookalikeSeparator,
    /// `%25` followed by two hex digits, which one percent-decode turns into another escape
    /// (`%252e` to `%2e`): a tool that decodes twice reads what the path does not spell
    /// (SR-105).
    #[error("holds a percent escape that is itself percent-encoded (`%25` and two hex digits)")]
    DoubleEncoded,
}

/// The code points `path_prefix` refuses because another tool may read them as `.`, `/` or
/// `\` ([`PathError::LookalikeSeparator`]). `path_prefix` reads a path as ASCII separators
/// after at most one percent-decode and does not normalise Unicode, so it refuses what it
/// cannot reason about instead:
///
/// - every code point whose NFKC form is made only of `.`, `/` and `\` (Unicode 15.1):
///   U+2024 `․`, U+2025 `‥`, U+2026 `…`, U+FE19 `︙`, U+FE30 `︰`, U+FE52 `﹒`, U+FE68 `﹨`,
///   U+FF0E `．`, U+FF0F `／`, U+FF3C `＼`;
/// - three slashes that Windows best-fit code-page conversion maps to `/` in an ANSI API
///   call: U+2044 `⁄`, U+2215 `∕`, U+29F8 `⧸`.
///
/// Code points whose NFKC form mixes these with letters or digits (`⒈` is `1.`, `℀` is
/// `a/c`) cannot form a `.` or `..` segment on their own and are admitted. Code-page
/// specific best-fit mappings beyond these (the yen sign read as `\` on a Japanese code
/// page, for one) are not modelled: grant such a tool a narrower path or run it on a
/// Unicode API.
pub const LOOKALIKE_SEPARATORS: &[char] = &[
    '\u{2024}', '\u{2025}', '\u{2026}', '\u{fe19}', '\u{fe30}', '\u{fe52}', '\u{fe68}', '\u{ff0e}',
    '\u{ff0f}', '\u{ff3c}', '\u{2044}', '\u{2215}', '\u{29f8}',
];

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
    let double = s
        .as_bytes()
        .windows(5)
        .any(|w| w.starts_with(b"%25") && w[3].is_ascii_hexdigit() && w[4].is_ascii_hexdigit());
    if double {
        return Err(PathError::DoubleEncoded);
    }
    if s.contains(LOOKALIKE_SEPARATORS) {
        return Err(PathError::LookalikeSeparator);
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
    range.satisfied_by(v) && exact_long(v).is_some()
}

/// [`as_long`] of `v` when every value canonically equal to `v` reads as the same integer, so
/// a range judges them all as it judges `v` ([`range_admits_all_equal`]); `None` otherwise.
fn exact_long(v: &Value) -> Option<i64> {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "WHOLE_FLOAT_MAX is a positive whole number far below 2^64"
    )]
    const WHOLE_FLOAT_MAX_U64: u64 = WHOLE_FLOAT_MAX as u64;
    as_long(v).filter(|&n| {
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
    ///
    /// Written straight from the constraint, which is the bytes [`crate::jcs::to_vec`] gives
    /// for it (a test checks that on generated constraints) without building a tree of the
    /// value first: a set of capabilities is ordered by this, once per comparison (SR-123).
    fn canonical(&self) -> Vec<u8> {
        use crate::jcs::{write_str, write_value};
        let mut out = Vec::with_capacity(32);
        let op = match self {
            ArgConstraint::Equals(_) => "equals",
            ArgConstraint::OneOf(_) => "one_of",
            ArgConstraint::Prefix(_) => "prefix",
            ArgConstraint::PathPrefix(_) => "path_prefix",
            ArgConstraint::Range { .. } => "range",
        };
        out.extend_from_slice(b"{\"op\":");
        write_str(&mut out, op);
        out.extend_from_slice(b",\"value\":");
        match self {
            ArgConstraint::Equals(v) => write_value(&mut out, v),
            ArgConstraint::OneOf(vs) => {
                out.push(b'[');
                for (i, v) in vs.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write_value(&mut out, v);
                }
                out.push(b']');
            }
            ArgConstraint::Prefix(p) | ArgConstraint::PathPrefix(p) => write_str(&mut out, p),
            // Members sorted by name: `max` before `min`.
            ArgConstraint::Range { min, max } => {
                let members = [("max", max), ("min", min)];
                out.push(b'{');
                let mut first = true;
                for (name, bound) in members {
                    if let Some(n) = bound {
                        if !first {
                            out.push(b',');
                        }
                        first = false;
                        write_str(&mut out, name);
                        out.push(b':');
                        out.extend_from_slice(n.to_string().as_bytes());
                    }
                }
                out.push(b'}');
            }
        }
        out.push(b'}');
        out
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
    ///
    /// Linear in the sizes of the two constraints: a `one_of` is compared through the set of
    /// its values' canonical keys, not value by value with the other's list (SR-123).
    pub fn implies(&self, other: &ArgConstraint) -> bool {
        if self.is_small() && other.is_small() {
            return self.implies_direct(other);
        }
        prepared::Prepared::new(self).implies(&prepared::Prepared::new(other))
    }

    /// Is this constraint cheap to compare value by value: anything but a `one_of` of more than
    /// [`SMALL_LIST`] values? Two such constraints are compared by
    /// [`implies_direct`](Self::implies_direct), which hashes nothing.
    fn is_small(&self) -> bool {
        !matches!(self, ArgConstraint::OneOf(vs) if vs.len() > SMALL_LIST)
    }

    /// [`implies`](Self::implies) by its definition, arm by arm, comparing values pairwise.
    /// The arms between a `one_of` and a list or a summary of a list cost the product of the
    /// two lengths, and [`prepared::Prepared::implies`] answers those itself; it calls this
    /// for the others, which compare at most one value with one constraint.
    /// [`implies`](Self::implies) calls it for two small constraints
    /// ([`is_small`](Self::is_small)). The tests check every answer of the prepared
    /// implication against this one.
    fn implies_direct(&self, other: &ArgConstraint) -> bool {
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
        if self.is_small() && child.is_small() {
            return self.covers_calls_direct(child);
        }
        PreparedCap::new(self).covers_calls(&PreparedCap::new(child))
    }

    /// Is this capability cheap to compare constraint by constraint: at most [`SMALL_LIST`]
    /// constraints, each [`ArgConstraint::is_small`]?
    fn is_small(&self) -> bool {
        self.constraints.len() <= SMALL_LIST
            && self.constraints.values().all(ArgConstraint::is_small)
    }

    /// [`covers_calls`](Self::covers_calls) with [`ArgConstraint::implies_direct`]: the
    /// definition, which the tests compare the prepared check with, and the check for small
    /// capabilities, where preparing costs more than it saves.
    fn covers_calls_direct(&self, child: &Capability) -> bool {
        if !pattern_covers(&self.server, &child.server) || !pattern_covers(&self.tool, &child.tool)
        {
            return false;
        }
        // Every constraint the parent imposes must be implied by a constraint on the child.
        self.constraints.iter().all(|(arg, parent_c)| {
            child
                .constraints
                .get(arg)
                .map(|child_c| child_c.implies_direct(parent_c))
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
/// `_file` (ASCII case ignored), or when the prefix starts with `/`, `./` or `~`. A
/// prefix such as `acme/` on a repository argument is left alone: `path_prefix` suits it too,
/// but most such prefixes are not paths. A heuristic for warnings only: it never refuses
/// anything.
pub fn prefix_looks_like_path(arg: &str, prefix: &str) -> bool {
    let name = arg.to_ascii_lowercase();
    PATH_ARG_NAMES.contains(&name.as_str())
        || ["_path", "_dir", "_file"].iter().any(|s| name.ends_with(s))
        || prefix.starts_with('/')
        || prefix.starts_with("./")
        || prefix.starts_with('~')
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

/// The most capabilities one token request, and one hop of a token, may hold (SR-123).
/// Attenuation compares every requested capability with the parent's, so its cost is the
/// product of the two sizes; every path that mints a token bounds the request with
/// [`CapabilitySet::validate_size`] before comparing anything.
pub const MAX_CAPABILITIES: usize = 1024;

/// A `one_of` of at most this many values, and a capability of at most this many constraints,
/// are compared pairwise, without hashing ([`ArgConstraint::is_small`]).
const SMALL_LIST: usize = 8;

/// Two sets of at most this many pairs of small capabilities are compared pairwise
/// ([`CapabilitySet::small_with`]): the common case of a few capabilities, where preparing the
/// parent costs more than it saves.
const SMALL_PAIRS: usize = 64;

/// The most values one `one_of` constraint may list (SR-123).
pub const MAX_ONE_OF_VALUES: usize = 1024;

/// The most argument constraints one token request, and one hop of a token, may hold over all
/// its capabilities (SR-123). Attenuation and [`CapabilitySet::covers`] compare a requested
/// capability with every parent capability whose patterns cover it, constraint by constraint,
/// so their cost grows with the constraints of one side times the capabilities of the other;
/// this bounds that product as [`MAX_CAPABILITIES`] bounds the number of pairs.
pub const MAX_CONSTRAINTS: usize = 1024;

/// The most `one_of` values one token request, and one hop of a token, may hold over all its
/// capabilities (SR-123). Each value of a requested `one_of` is looked up in the list of every
/// parent capability compared with it, so the cost grows with the values of one side times
/// the capabilities of the other; this bounds that product.
pub const MAX_ONE_OF_VALUES_TOTAL: usize = 1024;

impl Capability {
    /// Is every `one_of` of this capability at most [`MAX_ONE_OF_VALUES`] long?
    ///
    /// # Errors
    ///
    /// [`SizeError::OneOfTooLong`] for the first constraint, by argument name, over the bound.
    pub fn validate_size(&self) -> Result<(), SizeError> {
        for (arg, c) in &self.constraints {
            if let ArgConstraint::OneOf(values) = c {
                if values.len() > MAX_ONE_OF_VALUES {
                    return Err(SizeError::OneOfTooLong {
                        capability: format!("{}:{}", self.server, self.tool),
                        arg: arg.clone(),
                        count: values.len(),
                        max: MAX_ONE_OF_VALUES,
                    });
                }
            }
        }
        Ok(())
    }
}

/// A set of capabilities. A call is permitted if any member permits it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CapabilitySet(pub BTreeSet<Capability>);

/// Collected as a `BTreeSet` collects: of capabilities that are equal, the last is kept.
impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self(sorted_set(iter.into_iter().collect(), Keep::Last))
    }
}

/// Read as a `BTreeSet` is read, one member after the other: of capabilities that are equal,
/// the first is kept.
impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(sorted_set(Vec::deserialize(d)?, Keep::First)))
    }
}

/// Which of several equal capabilities [`sorted_set`] keeps. Equal capabilities can differ in
/// how a value is written (`1` and `1.0`), which the set's serialization shows.
#[derive(Clone, Copy)]
enum Keep {
    First,
    Last,
}

/// The set of `caps`, built in time linear in their size plus a sort of precomputed keys.
///
/// `BTreeSet` orders capabilities by [`Capability`]'s `Ord`, which compares constraints by
/// their canonical bytes, written afresh on every comparison, so inserting `n` large
/// capabilities one at a time wrote each of them about `2 log n` times, before any bound of
/// [`CapabilitySet::validate_size`] could be checked: a 2 MiB request took 0.8 s to read
/// (SR-123). Here each capability's sort key is written once and the keys are sorted. The key
/// orders exactly as `Ord` does (the server, the tool, then each constraint's argument name and
/// canonical bytes in argument order, as a `BTreeMap` compares, then the limits), so the set
/// built from the sorted capabilities, whose own sort then only confirms the order, is the
/// one `BTreeSet` would build.
fn sorted_set(caps: Vec<Capability>, keep: Keep) -> BTreeSet<Capability> {
    type SortKey<'a> = (&'a str, &'a str, Vec<(&'a str, Vec<u8>)>, &'a Limits);
    if caps.len() < 2 {
        return caps.into_iter().collect();
    }
    let order: Vec<usize> = {
        let keys: Vec<SortKey<'_>> = caps
            .iter()
            .map(|c| {
                let constraints = c
                    .constraints
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.canonical()))
                    .collect();
                (c.server.as_str(), c.tool.as_str(), constraints, &c.limits)
            })
            .collect();
        let mut order: Vec<usize> = (0..caps.len()).collect();
        // Stable, so equal capabilities stay in the order given.
        order.sort_by(|&a, &b| keys[a].cmp(&keys[b]));
        let mut kept: Vec<usize> = Vec::with_capacity(order.len());
        for i in order {
            match kept.last_mut() {
                Some(last) if keys[*last] == keys[i] => {
                    if matches!(keep, Keep::Last) {
                        *last = i;
                    }
                }
                _ => kept.push(i),
            }
        }
        kept
    };
    let mut slots: Vec<Option<Capability>> = caps.into_iter().map(Some).collect();
    order
        .into_iter()
        .map(|i| slots[i].take().expect("each index is kept once"))
        .collect()
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

    /// Is the set no larger than one request or token may be: at most [`MAX_CAPABILITIES`]
    /// members, each passing [`Capability::validate_size`], with at most [`MAX_CONSTRAINTS`]
    /// constraints and [`MAX_ONE_OF_VALUES_TOTAL`] `one_of` values among them (SR-123)?
    /// Linear in the set's size.
    ///
    /// # Errors
    ///
    /// Checked in this order: [`SizeError::TooManyCapabilities`]; the
    /// [`SizeError::OneOfTooLong`] of the first member, in canonical order, with a `one_of`
    /// over the bound; [`SizeError::TooManyConstraints`]; [`SizeError::TooManyOneOfValues`].
    pub fn validate_size(&self) -> Result<(), SizeError> {
        if self.0.len() > MAX_CAPABILITIES {
            return Err(SizeError::TooManyCapabilities {
                count: self.0.len(),
                max: MAX_CAPABILITIES,
            });
        }
        self.0.iter().try_for_each(Capability::validate_size)?;
        let constraints: usize = self.0.iter().map(|c| c.constraints.len()).sum();
        if constraints > MAX_CONSTRAINTS {
            return Err(SizeError::TooManyConstraints {
                count: constraints,
                max: MAX_CONSTRAINTS,
            });
        }
        let values: usize = self
            .0
            .iter()
            .flat_map(|c| c.constraints.values())
            .map(|c| match c {
                ArgConstraint::OneOf(vs) => vs.len(),
                _ => 0,
            })
            .sum();
        if values > MAX_ONE_OF_VALUES_TOTAL {
            return Err(SizeError::TooManyOneOfValues {
                count: values,
                max: MAX_ONE_OF_VALUES_TOTAL,
            });
        }
        Ok(())
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
        if self.small_with(child) {
            return self.covers_direct(child);
        }
        self.covers_prepared(child)
    }

    /// Are `self` and `other` small enough that comparing them pair by pair costs less than
    /// preparing them: at most [`SMALL_PAIRS`] pairs of capabilities, each
    /// [`Capability::is_small`]? Then each pair costs at most [`SMALL_LIST`] constraints of at
    /// most [`SMALL_LIST`] squared value comparisons.
    fn small_with(&self, other: &CapabilitySet) -> bool {
        self.len().saturating_mul(other.len()) <= SMALL_PAIRS
            && self
                .0
                .iter()
                .chain(other.0.iter())
                .all(Capability::is_small)
    }

    /// [`covers`](Self::covers) with `self` prepared once.
    fn covers_prepared(&self, child: &CapabilitySet) -> bool {
        let parents = PreparedSet::new(&self.0);
        child.0.iter().all(|c| {
            let c = PreparedCap::new(c);
            parents.0.iter().any(|p| p.covers(&c))
        })
    }

    /// The members of `child` that a single member of `self` covers, in canonical order: what
    /// [`covers`](Self::covers) checks, member by member, with `self` prepared once instead of
    /// once per member ([`Capability::covers`] in a loop would hash `self`'s lists again for
    /// each, SR-123).
    pub fn covered<'c>(&self, child: &'c CapabilitySet) -> Vec<&'c Capability> {
        let parents = PreparedSet::new(&self.0);
        child
            .0
            .iter()
            .filter(|c| {
                let c = PreparedCap::new(c);
                parents.0.iter().any(|p| p.covers(&c))
            })
            .collect()
    }

    /// [`covers`](Self::covers) by its definition, pair by pair: the tests' reference, and
    /// the check for small sets ([`small_with`](Self::small_with)).
    fn covers_direct(&self, child: &CapabilitySet) -> bool {
        child.0.iter().all(|c| {
            self.0
                .iter()
                .any(|p| p.covers_calls_direct(c) && c.limits.narrows(&p.limits))
        })
    }

    /// Derive `requested` from `self`, failing if that would widen anything.
    ///
    /// This is the attenuation step performed at every delegation hop. Limits are clamped, not
    /// refused ([`attenuate_with`](Self::attenuate_with) with nothing spent yet).
    ///
    /// # Errors
    ///
    /// As [`attenuate_with`](Self::attenuate_with): [`AttenuationError::Empty`] for an empty
    /// `requested`, [`AttenuationError::TooLarge`] for one over [`CapabilitySet::validate_size`],
    /// [`AttenuationError::NotCovered`] for the first requested capability no member of `self`
    /// covers.
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
    /// [`AttenuationError::Empty`] when `requested` is empty; [`AttenuationError::TooLarge`]
    /// when it fails [`CapabilitySet::validate_size`], before anything is compared.
    /// [`AttenuationError::NotCovered`],
    /// naming the capability, when no member of `self` covers a requested capability's calls, or
    /// when the clamped capability is still not covered by its parent (a constraint or limit
    /// clamping cannot fix).
    pub fn attenuate_with(
        &self,
        requested: &CapabilitySet,
        remaining: impl Fn(usize, LimitKind, u64) -> Option<u64>,
    ) -> Result<CapabilitySet, AttenuationError> {
        Ok(self
            .attenuate_indexed(requested, remaining)?
            .into_iter()
            .map(|(_, _, child)| child)
            .collect())
    }

    /// [`attenuate`](Self::attenuate) of each of `requested` alone, in the order given:
    /// `self.attenuate(&{c})` for each `c`, with `self` prepared once (SR-123). For saying which
    /// requested capability a refusal is about.
    pub fn attenuate_each<'r>(
        &self,
        requested: impl IntoIterator<Item = &'r Capability>,
    ) -> Vec<Result<Capability, AttenuationError>> {
        let parents = PreparedSet::new(&self.0);
        requested
            .into_iter()
            .map(|c| {
                CapabilitySet::from_iter([c.clone()]).validate_size()?;
                self.attenuate_one(&parents, c, &|_, _, _| None)
                    .map(|(_, child)| child)
            })
            .collect()
    }

    /// [`attenuate`](Self::attenuate) at hop 0, where `self` is not a hop but a root grant (or
    /// a ceiling under one) that the root token's capabilities are taken from. A limit there
    /// bounds the run only if a single capability of the root token carries it: each call is
    /// charged against the capabilities that match it, and no parent hop is charged too, as
    /// at an exchange. So in addition to [`attenuate`](Self::attenuate), two capabilities of
    /// the result may not take their limits from the same limited capability of `self` (one
    /// whose [`Limits`] are not empty), whatever limits they request themselves (SR-121). The
    /// parent of each requested capability is the one [`attenuate`](Self::attenuate) clamps
    /// it to. Requested capabilities that are the same after clamping are one capability of
    /// the result and are not a split. A capability of `self` without limits may be split
    /// freely.
    ///
    /// # Errors
    ///
    /// As [`attenuate`](Self::attenuate), which is checked first; then
    /// [`AttenuationError::LimitSplit`] naming two requested capabilities, as requested, that
    /// share a limited parent.
    pub fn attenuate_root(
        &self,
        requested: &CapabilitySet,
    ) -> Result<CapabilitySet, AttenuationError> {
        let attenuated = self.attenuate_indexed(requested, |_, _, _| None)?;
        let parents: Vec<&Capability> = self.0.iter().collect();
        let mut first: BTreeMap<usize, (&Capability, &Capability)> = BTreeMap::new();
        for (index, req, child) in &attenuated {
            if parents[*index].limits.is_empty() {
                continue;
            }
            match first.get(index) {
                Some((req0, child0)) if *child0 != child => {
                    return Err(AttenuationError::LimitSplit {
                        first: req0.display(),
                        second: req.display(),
                    });
                }
                Some(_) => {}
                None => {
                    first.insert(*index, (req, child));
                }
            }
        }
        Ok(attenuated.into_iter().map(|(_, _, child)| child).collect())
    }

    /// The step of [`attenuate_with`](Self::attenuate_with) for each requested capability, in
    /// canonical order: the index in `self` of the parent it was clamped to, the capability as
    /// requested, and the clamped capability.
    fn attenuate_indexed<'r>(
        &self,
        requested: &'r CapabilitySet,
        remaining: impl Fn(usize, LimitKind, u64) -> Option<u64>,
    ) -> Result<Vec<(usize, &'r Capability, Capability)>, AttenuationError> {
        if requested.is_empty() {
            return Err(AttenuationError::Empty);
        }
        // Before anything is compared: the loop below costs the product of both sizes (SR-123).
        requested.validate_size()?;
        if self.small_with(requested) {
            return self.attenuate_indexed_direct(requested, remaining);
        }
        self.attenuate_indexed_prepared(requested, remaining)
    }

    /// [`attenuate_indexed`](Self::attenuate_indexed) with `self` prepared once, for a
    /// `requested` that passed [`CapabilitySet::validate_size`].
    fn attenuate_indexed_prepared<'r>(
        &self,
        requested: &'r CapabilitySet,
        remaining: impl Fn(usize, LimitKind, u64) -> Option<u64>,
    ) -> Result<Vec<(usize, &'r Capability, Capability)>, AttenuationError> {
        if requested.is_empty() {
            return Err(AttenuationError::Empty);
        }
        let parents = PreparedSet::new(&self.0);
        let mut out = Vec::with_capacity(requested.len());
        for c in requested.0.iter() {
            let (index, child) = self.attenuate_one(&parents, c, &remaining)?;
            out.push((index, c, child));
        }
        Ok(out)
    }

    /// The step of [`attenuate_indexed`](Self::attenuate_indexed) for one requested capability
    /// `c`, `parents` being `self` prepared: the index of the parent it is clamped to, and the
    /// clamped capability.
    fn attenuate_one(
        &self,
        parents: &PreparedSet<'_>,
        c: &Capability,
        remaining: &impl Fn(usize, LimitKind, u64) -> Option<u64>,
    ) -> Result<(usize, Capability), AttenuationError> {
        let not_covered = || AttenuationError::NotCovered {
            requested: c.display(),
        };
        // The first parent that covers `c`, else the first that covers its calls: one
        // pass, each pair compared once (SR-123).
        let prepared = PreparedCap::new(c);
        let mut calls_only = None;
        let mut covering = None;
        for (i, p) in parents.0.iter().enumerate() {
            if p.covers_calls(&prepared) {
                if c.limits.narrows(&p.cap.limits) {
                    covering = Some(i);
                    break;
                }
                calls_only = calls_only.or(Some(i));
            }
        }
        let index = covering.or(calls_only).ok_or_else(not_covered)?;
        let parent = parents.0[index].cap;
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
        // `parent.covers(&child)`: `child` has `c`'s patterns and constraints, whose
        // calls `parent` covers, so only the clamped limits are left to check.
        if !child.limits.narrows(&parent.limits) {
            return Err(not_covered());
        }
        Ok((index, child))
    }

    /// The attenuation step as it was written before SR-123's fix, pair by pair with the
    /// pairwise implication: the tests' reference for the prepared step, and the step for small
    /// sets ([`small_with`](Self::small_with)).
    fn attenuate_indexed_direct<'r>(
        &self,
        requested: &'r CapabilitySet,
        remaining: impl Fn(usize, LimitKind, u64) -> Option<u64>,
    ) -> Result<Vec<(usize, &'r Capability, Capability)>, AttenuationError> {
        if requested.is_empty() {
            return Err(AttenuationError::Empty);
        }
        requested.validate_size()?;
        let covers = |p: &Capability, c: &Capability| {
            p.covers_calls_direct(c) && c.limits.narrows(&p.limits)
        };
        let mut out = Vec::with_capacity(requested.len());
        for c in requested.0.iter() {
            let not_covered = || AttenuationError::NotCovered {
                requested: c.display(),
            };
            let (index, parent) = self
                .0
                .iter()
                .enumerate()
                .find(|(_, p)| covers(p, c))
                .or_else(|| {
                    self.0
                        .iter()
                        .enumerate()
                        .find(|(_, p)| p.covers_calls_direct(c))
                })
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
            if !covers(parent, &child) {
                return Err(not_covered());
            }
            out.push((index, c, child));
        }
        Ok(out)
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

    /// SR-106: the comparison is lexical. A path through a link under the prefix is
    /// admitted, since the engine cannot see the upstream's file system; the docs say so.
    #[test]
    fn path_prefix_compares_text_and_does_not_see_links_sr106() {
        let c = pp("/workspace/");
        assert!(c.satisfied_by(&json!("/workspace/link/id_ed25519")));
    }

    /// SR-105: spellings outside the ASCII, single-decode model are refused, not admitted:
    /// code points that compatibility-normalise (NFKC) or Windows best-fit map to `.`, `/` or
    /// `\\`, and an escape that one decode leaves behind (`%252e`). Ordinary non-ASCII names
    /// and a literal `%` still pass.
    #[test]
    fn path_prefix_refuses_what_its_model_cannot_reason_about_sr105() {
        let c = pp("/workspace");
        for (v, why) in [
            (
                "/workspace/\u{ff0e}\u{ff0e}/secrets/key",
                PathError::LookalikeSeparator,
            ),
            ("/workspace/\u{2025}/x", PathError::LookalikeSeparator),
            (
                "/workspace/a\u{ff0f}..\u{ff0f}..\u{ff0f}etc",
                PathError::LookalikeSeparator,
            ),
            ("/workspace/a\u{ff3c}b", PathError::LookalikeSeparator),
            (
                "/workspace/\u{fe52}\u{2024}/x",
                PathError::LookalikeSeparator,
            ),
            ("/workspace/\u{2026}", PathError::LookalikeSeparator),
            ("/workspace/\u{fe30}/x", PathError::LookalikeSeparator),
            ("/workspace/a\u{2215}b", PathError::LookalikeSeparator),
            ("/workspace/a\u{2044}b", PathError::LookalikeSeparator),
            ("/workspace/a\u{29f8}b", PathError::LookalikeSeparator),
            ("/workspace/%252e%252e/etc/passwd", PathError::DoubleEncoded),
            ("/workspace/%252F", PathError::DoubleEncoded),
            ("/workspace/a%2541", PathError::DoubleEncoded),
            ("/workspace/%25252e", PathError::DoubleEncoded),
        ] {
            assert_eq!(parse_path(v).err(), Some(why), "{v:?}");
            assert!(!c.satisfied_by(&json!(v)), "{v:?} must be refused");
        }
        for v in [
            "/workspace/caf\u{e9}.txt",
            "/workspace/\u{65e5}\u{672c}\u{8a9e}/\u{6587}\u{66f8}.md",
            "/workspace/\u{43e}\u{442}\u{447}\u{451}\u{442}.pdf",
            "/workspace/na\u{ef}ve r\u{e9}sum\u{e9}.docx",
            "/workspace/100%25.txt",
            "/workspace/50%.txt",
            "/workspace/a%25",
            "/workspace/\u{2488}notes",
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
        for p in ["/workspace/", "./src", "~/notes"] {
            assert!(looks("repo", p), "{p}");
        }
        for (arg, p) in [
            ("uri", "file:///public/"),
            ("url", "https://a.example/"),
            ("repo", "acme-"),
            ("repo", "acme/"),
            ("repo", "a/b"),
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

    fn to(who: &str) -> Capability {
        Capability::new("banking", "send_money")
            .with_constraint("to", ArgConstraint::Equals(json!(who)))
    }

    /// SR-121: a root grant's limit copied into several requested capabilities would bound
    /// each of them, not the run. `attenuate` allows it (an exchange is charged against its
    /// parent hop too); `attenuate_root` refuses it.
    #[test]
    fn a_limited_grant_capability_is_not_split_at_the_root_sr121() {
        let grant =
            CapabilitySet::from_iter([Capability::new("banking", "*")
                .with_limits(Limits::default().with_sum("amount", 100))]);
        let split = CapabilitySet::from_iter([to("alice"), to("bob"), to("carol")]);
        let out = grant.attenuate(&split).unwrap();
        assert_eq!(out.len(), 3, "each carries the whole figure");
        assert!(out
            .iter()
            .all(|c| c.limits.sum.as_ref().unwrap().max == 100));
        let err = grant.attenuate_root(&split).unwrap_err();
        assert!(
            matches!(err, AttenuationError::LimitSplit { .. }),
            "{err:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains("banking:send_money{to=") && text.contains("alice"),
            "{text}"
        );
        assert!(
            !text.contains("100"),
            "the grant's figure is not shown: {text}"
        );

        // One capability is fine, and so is one with a wider constraint.
        let one = CapabilitySet::from_iter([to("alice")]);
        assert_eq!(grant.attenuate_root(&one), grant.attenuate(&one));
        let wide = CapabilitySet::from_iter([Capability::new("banking", "send_money")
            .with_constraint(
                "to",
                ArgConstraint::OneOf(vec![json!("alice"), json!("bob"), json!("carol")]),
            )]);
        assert_eq!(grant.attenuate_root(&wide), grant.attenuate(&wide));

        // Its own lower figures do not make it sound to allow: still a split.
        let own = CapabilitySet::from_iter([
            to("alice").with_limits(Limits::default().with_sum("amount", 50)),
            to("bob").with_limits(Limits::default().with_sum("amount", 50)),
        ]);
        assert!(matches!(
            grant.attenuate_root(&own),
            Err(AttenuationError::LimitSplit { .. })
        ));

        // Requested capabilities that clamp to the same one are one capability.
        let same = CapabilitySet::from_iter([
            to("alice"),
            to("alice").with_limits(Limits::default().with_sum("amount", 100)),
        ]);
        let out = grant.attenuate_root(&same).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out, grant.attenuate(&same).unwrap());

        // A not-covered request still answers not covered first.
        let wider = CapabilitySet::from_iter([to("alice"), Capability::new("github", "x")]);
        assert!(matches!(
            grant.attenuate_root(&wider),
            Err(AttenuationError::NotCovered { .. })
        ));
        assert_eq!(
            grant.attenuate_root(&CapabilitySet::new()),
            Err(AttenuationError::Empty)
        );
    }

    /// Every kind of limit counts, and the parent is the one `attenuate` clamps to.
    #[test]
    fn a_split_is_judged_by_the_parent_attenuate_picks_sr121() {
        let fetch = |p: &str| {
            Capability::new("web", "fetch").with_constraint("url", ArgConstraint::Prefix(p.into()))
        };
        let two =
            CapabilitySet::from_iter([fetch("https://a.example/"), fetch("https://b.example/")]);
        for limits in [
            Limits::default().with_calls(3),
            Limits::default().with_calls_per("url", 1),
            Limits {
                distinct: Some(crate::ArgLimit::new("url", 1).derived(crate::limits::Derive::Host)),
                ..Limits::default()
            },
        ] {
            let grant = CapabilitySet::from_iter([
                Capability::new("web", "fetch").with_limits(limits.clone())
            ]);
            assert_eq!(grant.attenuate(&two).unwrap().len(), 2);
            assert!(
                matches!(
                    grant.attenuate_root(&two),
                    Err(AttenuationError::LimitSplit { .. })
                ),
                "{limits:?}"
            );
        }

        // An unlimited grant capability may be split, as before.
        let free = CapabilitySet::from_iter([Capability::new("web", "*")]);
        assert_eq!(free.attenuate_root(&two), free.attenuate(&two));

        // Two grant capabilities cover both; `attenuate` picks the first that covers as it
        // is, `web:*` (unlimited, sorts first), so nothing is split.
        let both = CapabilitySet::from_iter([
            Capability::new("web", "*"),
            Capability::new("web", "fetch").with_limits(Limits::default().with_calls(3)),
        ]);
        assert!(both
            .attenuate(&two)
            .unwrap()
            .iter()
            .all(|c| c.limits.is_empty()));
        assert_eq!(both.attenuate_root(&two), both.attenuate(&two));

        // `attenuate` prefers a capability that covers the request as it is: the unlimited
        // `web:fetch{url=a}` is chosen for `fetch(a)` although the limited, unconstrained
        // `web:fetch` sorts first, so only `fetch(b)` takes the limited one: no split.
        let covering_first = CapabilitySet::from_iter([
            Capability::new("web", "fetch").with_limits(Limits::default().with_calls(3)),
            fetch("https://a.example/"),
        ]);
        let out = covering_first.attenuate(&two).unwrap();
        assert_eq!(
            out.iter().filter(|c| c.limits.is_empty()).count(),
            1,
            "{out:?}"
        );
        assert_eq!(covering_first.attenuate_root(&two), Ok(out));
        // With a third request that also only the limited one covers, it is split.
        let three =
            CapabilitySet::from_iter(two.iter().cloned().chain([fetch("https://c.example/")]));
        assert!(matches!(
            covering_first.attenuate_root(&three),
            Err(AttenuationError::LimitSplit { .. })
        ));
        // Split across two different limited capabilities is not a split of either.
        let apart = CapabilitySet::from_iter([
            fetch("https://a.example/").with_limits(Limits::default().with_calls(3)),
            fetch("https://b.example/").with_limits(Limits::default().with_calls(3)),
        ]);
        assert_eq!(apart.attenuate_root(&two), apart.attenuate(&two));
    }

    /// SR-123: a request holds at most `MAX_CAPABILITIES` capabilities and a `one_of` at most
    /// `MAX_ONE_OF_VALUES` values; attenuation refuses a larger one before comparing anything,
    /// and so do `DelegationChain::root` and `extend`.
    #[test]
    fn requests_are_bounded_in_size_sr123() {
        let many = |n: usize| -> CapabilitySet {
            (0..n)
                .map(|i| Capability::new("s", format!("t{i}")))
                .collect()
        };
        let one_of = |n: usize| -> CapabilitySet {
            CapabilitySet::from_iter([Capability::new("s", "t").with_constraint(
                "a",
                ArgConstraint::OneOf((0..n).map(|i| json!(i)).collect()),
            )])
        };
        assert_eq!(many(MAX_CAPABILITIES).validate_size(), Ok(()));
        assert_eq!(one_of(MAX_ONE_OF_VALUES).validate_size(), Ok(()));
        assert_eq!(
            many(MAX_CAPABILITIES + 1).validate_size(),
            Err(SizeError::TooManyCapabilities {
                count: MAX_CAPABILITIES + 1,
                max: MAX_CAPABILITIES
            })
        );
        assert!(matches!(
            one_of(MAX_ONE_OF_VALUES + 1).validate_size(),
            Err(SizeError::OneOfTooLong { count: 1025, .. })
        ));
        // Refused before the parent is read: even an empty parent answers "too large".
        let none = CapabilitySet::new();
        assert!(matches!(
            none.attenuate(&many(MAX_CAPABILITIES + 1)),
            Err(AttenuationError::TooLarge(_))
        ));
        assert!(matches!(
            none.attenuate_root(&one_of(MAX_ONE_OF_VALUES + 1)),
            Err(AttenuationError::TooLarge(_))
        ));
        let all = CapabilitySet::from_iter([Capability::new("*", "*")]);
        assert!(all.attenuate(&many(MAX_CAPABILITIES)).is_ok());

        let user = crate::OriginatingUser {
            subject: "u".into(),
            issuer: "i".into(),
            authenticated_at: time::OffsetDateTime::UNIX_EPOCH,
            attributes: Default::default(),
        };
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
        let hour = time::Duration::hours(1);
        let lease = |s: &str| crate::LeaseId(s.into());
        let err = crate::DelegationChain::root(
            user.clone(),
            crate::AgentId("a".into()),
            many(MAX_CAPABILITIES + 1),
            now,
            hour,
            lease("l0"),
        )
        .unwrap_err();
        assert!(
            matches!(err, crate::ChainError::TooLarge { index: 0, .. }),
            "{err}"
        );
        let root = crate::DelegationChain::root(
            user,
            crate::AgentId("a".into()),
            all,
            now,
            hour,
            lease("l0"),
        )
        .unwrap();
        let err = root
            .extend(
                crate::AgentId("b".into()),
                one_of(MAX_ONE_OF_VALUES + 1),
                now,
                hour,
                lease("l1"),
                8,
            )
            .unwrap_err();
        assert!(
            matches!(err, crate::ChainError::TooLarge { index: 1, .. }),
            "{err}"
        );
    }

    /// SR-123, the rest: a request also holds at most `MAX_CONSTRAINTS` argument constraints
    /// and `MAX_ONE_OF_VALUES_TOTAL` `one_of` values over all its capabilities, since
    /// attenuation costs each of those times the parent's capabilities. Refused before
    /// anything is compared, at the same places as the other bounds.
    #[test]
    fn requests_are_bounded_in_total_constraints_and_values_sr123() {
        // `n` capabilities with `k` constraints each, `one_of` lists of `v` values when `v > 0`.
        let set = |n: usize, k: usize, v: usize| -> CapabilitySet {
            (0..n)
                .map(|i| {
                    (0..k).fold(Capability::new("s", format!("t{i}")), |c, j| {
                        let constraint = if v > 0 {
                            ArgConstraint::OneOf((0..v).map(|x| json!(x)).collect())
                        } else {
                            ArgConstraint::Equals(json!(j))
                        };
                        c.with_constraint(format!("a{j}"), constraint)
                    })
                })
                .collect()
        };
        assert_eq!(set(MAX_CONSTRAINTS, 1, 0).validate_size(), Ok(()));
        assert_eq!(set(MAX_CONSTRAINTS / 2, 2, 0).validate_size(), Ok(()));
        assert_eq!(
            set(MAX_CONSTRAINTS / 2 + 1, 2, 0).validate_size(),
            Err(SizeError::TooManyConstraints {
                count: MAX_CONSTRAINTS + 2,
                max: MAX_CONSTRAINTS
            })
        );
        // One list at the bound, or two halves, fit; one value more over the set does not.
        assert_eq!(set(1, 1, MAX_ONE_OF_VALUES_TOTAL).validate_size(), Ok(()));
        assert_eq!(
            set(2, 1, MAX_ONE_OF_VALUES_TOTAL / 2).validate_size(),
            Ok(())
        );
        let over = {
            let mut s = set(2, 1, MAX_ONE_OF_VALUES_TOTAL / 2);
            s.insert(
                Capability::new("s", "u")
                    .with_constraint("a", ArgConstraint::OneOf(vec![json!(0)])),
            );
            s
        };
        assert_eq!(
            over.validate_size(),
            Err(SizeError::TooManyOneOfValues {
                count: MAX_ONE_OF_VALUES_TOTAL + 1,
                max: MAX_ONE_OF_VALUES_TOTAL
            })
        );
        // A single list over the per-list bound is still named as such.
        assert!(matches!(
            set(1, 1, MAX_ONE_OF_VALUES + 1).validate_size(),
            Err(SizeError::OneOfTooLong { .. })
        ));
        let none = CapabilitySet::new();
        assert!(matches!(
            none.attenuate(&over),
            Err(AttenuationError::TooLarge(
                SizeError::TooManyOneOfValues { .. }
            ))
        ));
        assert!(matches!(
            none.attenuate_root(&set(MAX_CONSTRAINTS / 2 + 1, 2, 0)),
            Err(AttenuationError::TooLarge(
                SizeError::TooManyConstraints { .. }
            ))
        ));
    }
}
