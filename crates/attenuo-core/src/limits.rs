//! Run limits (ADR-0010, `docs/design/run-limits.md`): how many calls a capability may be used
//! for, and how much in total, across a delegation run.
//!
//! A [`Capability`] may carry [`Limits`] next to its constraints:
//!
//! ```json
//! { "server": "banking", "tool": "send_money",
//!   "limits": { "calls": 1, "sum": { "arg": "amount", "max": 10 },
//!               "calls_per": { "arg": "recipient", "max": 1 },
//!               "distinct": { "arg": "recipient", "max": 2 } } }
//! ```
//!
//! - `calls`: at most n allowed calls matched by the capability.
//! - `sum`: the sum of argument `arg` (a JSON integer >= 0) over those calls is at most `max`.
//! - `calls_per`: at most `max` allowed calls per distinct value of `arg`; a list-valued
//!   argument counts each distinct element.
//! - `distinct`: at most `max` distinct values of `arg` across those calls; a list-valued
//!   argument counts each element.
//!
//! `calls_per` and `distinct` may count a value derived from the argument instead of the
//! argument itself: `"derive": "host"` counts the host of a URL argument
//! (`{ "arg": "url", "derive": "host", "max": 1 }`), so `https://a.example/x` and
//! `https://a.example/y?q=1` are one destination ([`Derive`]). Records, error data and
//! catalogs write such a derived argument `url#host` ([`ArgLimit::counted`],
//! [`parse_arg_ref`]).
//!
//! The maxima are static numbers in the signed token. What has been used is server state (the
//! lease store), one counter per (hop lease, capability index, kind, argument, value). Every
//! allowed call is charged against every limited capability, in every hop of the chain, whose
//! patterns and constraints match it ([`charges_for`]); if any one would go over, the call is
//! denied. Because hop 0's lease is the run's `chain_id`, a limit on the root hop is the run's
//! budget, and a sub-agent cannot reset it by delegating again.
//!
//! Narrowing (P2): a child capability under a limited parent must carry the same limit with a
//! `max` no larger ([`Limits::narrows`], checked by [`Capability::covers`]). A child may add
//! limits. `calls: m` in the child also satisfies `calls_per: {arg, max: n}` and
//! `distinct: {arg, max: n}` in the parent when `m <= n`, since m calls cannot reach any value
//! more than m times, nor more than m values. At exchange the
//! child's figures are clamped to the parent's ([`Limits::clamp_to`]) and, by the server, to
//! what the parent has left.
//!
//! **Run usage** (design section 3.5, phase 2) uses the same counters without a limit in any
//! token: for every call to a tool the catalog marks destructive, the server keeps, per run
//! (`chain_id`) and tool, how many calls were allowed, the sum of the catalog's `amount` input
//! over them and the keyed hashes of the catalog's `destination` input values
//! ([`usage_charges`]). Policies read them as `context.usage.*`; they never refuse a call by
//! themselves.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::call::ToolCall;
use crate::capability::{ArgConstraint, Capability};
use crate::chain::{DelegationChain, LeaseId};

/// The largest `max` a limit may carry: Cedar's largest `Long`, so every figure the server
/// derives from a limit (`context.budget.*`) is representable in policy.
pub const MAX_LIMIT: u64 = i64::MAX as u64;

/// The most values (list elements) a `calls_per` or `distinct` limit counts in one call. A
/// call whose argument lists more is refused with [`REASON_LIMIT_ARG_INVALID`]; in run usage
/// such a list counts as one destination. Every value counted is a counter row and a
/// charge-log row written in the charge's transaction, which holds the store's write lock,
/// so an unbounded list would let one call stall every decision and grow the store (SR-57).
pub const MAX_COUNTED_VALUES: usize = 256;

/// Reason code: a limit in the chain would be exceeded by this call.
pub const REASON_BUDGET_EXHAUSTED: &str = "budget_exhausted";
/// Reason code: the counters a limit needs could not be read or written (fail closed).
pub const REASON_BUDGET_ERROR: &str = "budget_error";
/// Reason code: the argument a `sum`, `calls_per` or `distinct` limit counts is missing, (for
/// `sum`) not a non-negative integer, or (for a derived value) has no value to derive.
pub const REASON_LIMIT_ARG_INVALID: &str = "limit_arg_invalid";

/// A value derived from an argument, which a `calls_per` or `distinct` limit (or a catalog's
/// `destination`) counts instead of the argument itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Derive {
    /// The host of a URL argument: parsed as a WHATWG URL, lowercased, without port, user
    /// info or one trailing dot. A value that is not a string, or not an absolute URL with a
    /// host (`example.com/x`, `mailto:a@b`), has none. Nor does a string with a backslash,
    /// whitespace or a control character in it: WHATWG reads `https://a.example\@b.example/`
    /// as host `a.example`, while common HTTP clients (Python's `urllib` and `httpx`, among
    /// others) fetch `b.example`, so the host counted would not be the host reached (SR-56).
    Host,
}

impl Derive {
    /// The wire name: `host`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Derive::Host => "host",
        }
    }

    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Derive::Host),
            _ => None,
        }
    }

    /// The derived value of `v`, or `None` when it has none.
    pub fn apply(&self, v: &Value) -> Option<String> {
        match self {
            Derive::Host => {
                let raw = v.as_str()?;
                // Characters on which URL parsers disagree about where the host ends (SR-56).
                if raw
                    .chars()
                    .any(|c| c == '\\' || c.is_whitespace() || c.is_control())
                {
                    return None;
                }
                let url = url::Url::parse(raw).ok()?;
                let host = url.host_str()?.to_ascii_lowercase();
                let host = host.strip_suffix('.').unwrap_or(&host);
                (!host.is_empty()).then(|| host.to_string())
            }
        }
    }
}

impl std::fmt::Display for Derive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Split an argument reference as records and catalogs write it: `url#host` is the host of
/// argument `url` ([`Derive`]), anything without `#` is the argument itself. A `#` followed by
/// anything but a known derivation, or with nothing before it, is an error.
pub fn parse_arg_ref(s: &str) -> Result<(String, Option<Derive>), String> {
    match s.rsplit_once('#') {
        None => Ok((s.to_string(), None)),
        Some((arg, d)) => {
            let derive = Derive::parse(d)
                .ok_or_else(|| format!("`{s}`: unknown derivation `{d}` (known: `host`)"))?;
            if arg.is_empty() {
                return Err(format!("`{s}` names no argument before `#`"));
            }
            Ok((arg.to_string(), Some(derive)))
        }
    }
}

/// A limit on one argument: `sum`, `calls_per` or `distinct`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgLimit {
    /// The argument the limit counts.
    pub arg: String,
    /// The most the limit allows (a total for `sum`, calls per value for `calls_per`, values
    /// for `distinct`).
    pub max: u64,
    /// For `calls_per` and `distinct`: count a value derived from `arg` instead of `arg`
    /// itself. Absent (and omitted from the token) for the argument as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derive: Option<Derive>,
}

impl ArgLimit {
    pub fn new(arg: impl Into<String>, max: u64) -> Self {
        Self {
            arg: arg.into(),
            max,
            derive: None,
        }
    }

    /// The same limit, counting `derive` of the argument.
    pub fn derived(mut self, derive: Derive) -> Self {
        self.derive = Some(derive);
        self
    }

    /// What the limit counts, as records and error data name it: `arg`, or `arg#host` for a
    /// derived value.
    pub fn counted(&self) -> String {
        match self.derive {
            None => self.arg.clone(),
            Some(d) => format!("{}#{}", self.arg, d),
        }
    }

    /// Do `self` and `other` count the same thing (argument and derivation)?
    fn same_target(&self, other: &ArgLimit) -> bool {
        self.arg == other.arg && self.derive == other.derive
    }
}

/// The limits of one capability. Every member is optional; an empty `Limits` is omitted from
/// the token, so capabilities without limits serialize (and hash) as before.
///
/// Unknown members are refused rather than ignored: a token carrying a limit kind this
/// version does not enforce must not be read as unlimited.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// At most this many allowed calls matched by the capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls: Option<u64>,
    /// The sum of `arg` over allowed matched calls is at most `max`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sum: Option<ArgLimit>,
    /// At most `max` allowed matched calls per distinct value of `arg`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls_per: Option<ArgLimit>,
    /// At most `max` distinct values of `arg` across allowed matched calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distinct: Option<ArgLimit>,
}

/// The kind of a limit, as counters, records and error data name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    Calls,
    Sum,
    CallsPer,
    Distinct,
}

impl LimitKind {
    /// The wire name: `calls`, `sum`, `calls_per` or `distinct`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitKind::Calls => "calls",
            LimitKind::Sum => "sum",
            LimitKind::CallsPer => "calls_per",
            LimitKind::Distinct => "distinct",
        }
    }

    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "calls" => Some(LimitKind::Calls),
            "sum" => Some(LimitKind::Sum),
            "calls_per" => Some(LimitKind::CallsPer),
            "distinct" => Some(LimitKind::Distinct),
            _ => None,
        }
    }
}

impl std::fmt::Display for LimitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a capability's limits are not well formed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("limit `{kind}` of capability `{capability}`: {detail}")]
pub struct LimitError {
    pub capability: String,
    pub kind: LimitKind,
    pub detail: String,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        self.calls.is_none()
            && self.sum.is_none()
            && self.calls_per.is_none()
            && self.distinct.is_none()
    }

    pub fn with_calls(mut self, max: u64) -> Self {
        self.calls = Some(max);
        self
    }

    pub fn with_sum(mut self, arg: impl Into<String>, max: u64) -> Self {
        self.sum = Some(ArgLimit::new(arg, max));
        self
    }

    pub fn with_calls_per(mut self, arg: impl Into<String>, max: u64) -> Self {
        self.calls_per = Some(ArgLimit::new(arg, max));
        self
    }

    pub fn with_distinct(mut self, arg: impl Into<String>, max: u64) -> Self {
        self.distinct = Some(ArgLimit::new(arg, max));
        self
    }

    /// Does `self` (a child's limits) narrow `parent`? For every limit the parent has, the
    /// child has the same kind on the same argument (and derivation) with a `max` no larger;
    /// or, for the parent's `calls_per` and `distinct`, the child's `calls` is no larger than
    /// its `max`. A child may carry limits the parent lacks.
    pub fn narrows(&self, parent: &Limits) -> bool {
        let calls_ok = match parent.calls {
            None => true,
            Some(p) => self.calls.is_some_and(|c| c <= p),
        };
        let sum_ok = match &parent.sum {
            None => true,
            Some(p) => self
                .sum
                .as_ref()
                .is_some_and(|c| c.arg == p.arg && c.max <= p.max),
        };
        // `calls: m` bounds both the calls per value and the number of values by m.
        let per_value_ok = |child: &Option<ArgLimit>, parent: &Option<ArgLimit>| match parent {
            None => true,
            Some(p) => {
                child
                    .as_ref()
                    .is_some_and(|c| c.same_target(p) && c.max <= p.max)
                    || self.calls.is_some_and(|c| c <= p.max)
            }
        };
        let per_ok = per_value_ok(&self.calls_per, &parent.calls_per);
        let distinct_ok = per_value_ok(&self.distinct, &parent.distinct);
        calls_ok && sum_ok && per_ok && distinct_ok
    }

    /// The static half of clamping at exchange: `self` (what a child requested) lowered to
    /// `parent`'s figures, with every limit the parent has and the child lacks copied from the
    /// parent. Limits the parent lacks are kept as requested. A child `sum`, `calls_per` or
    /// `distinct` on another argument (or derivation) than the parent's is left alone, so the
    /// result does not narrow the parent and the request fails as not covered.
    pub fn clamp_to(&self, parent: &Limits) -> Limits {
        let mut out = self.clone();
        if let Some(p) = parent.calls {
            out.calls = Some(out.calls.map_or(p, |c| c.min(p)));
        }
        if let Some(p) = &parent.sum {
            match &mut out.sum {
                None => out.sum = Some(p.clone()),
                Some(c) if c.arg == p.arg => c.max = c.max.min(p.max),
                Some(_) => {}
            }
        }
        let calls = out.calls;
        for (child, parent) in [
            (&mut out.calls_per, &parent.calls_per),
            (&mut out.distinct, &parent.distinct),
        ] {
            let Some(p) = parent else { continue };
            match child {
                Some(c) if c.same_target(p) => c.max = c.max.min(p.max),
                Some(_) => {}
                None if calls.is_some_and(|c| c <= p.max) => {}
                None => *child = Some(p.clone()),
            }
        }
        out
    }

    /// The limits that apply to an argument (`sum`, `calls_per` and `distinct`), with their
    /// kinds.
    fn arg_limits(&self) -> impl Iterator<Item = (LimitKind, &ArgLimit)> {
        self.sum
            .iter()
            .map(|l| (LimitKind::Sum, l))
            .chain(self.calls_per.iter().map(|l| (LimitKind::CallsPer, l)))
            .chain(self.distinct.iter().map(|l| (LimitKind::Distinct, l)))
    }

    /// Check the limits of `cap` (which carries them): every `max` at most [`MAX_LIMIT`], every
    /// `arg` a non-empty name with no control character or `#` in it, no `derive` on a
    /// `sum`, and a `sum` argument that its
    /// constraint, if any, lets be a
    /// non-negative integer (otherwise no call could ever be charged and the limit is a
    /// mistake). Negative or fractional maxima cannot be written: they do not deserialize.
    pub fn validate(&self, cap: &Capability) -> Result<(), LimitError> {
        let err = |kind, detail: String| LimitError {
            capability: cap.display(),
            kind,
            detail,
        };
        if let Some(c) = self.calls {
            if c > MAX_LIMIT {
                return Err(err(
                    LimitKind::Calls,
                    format!("max {c} exceeds {MAX_LIMIT}"),
                ));
            }
        }
        for (kind, l) in self.arg_limits() {
            if l.max > MAX_LIMIT {
                return Err(err(kind, format!("max {} exceeds {MAX_LIMIT}", l.max)));
            }
            if l.arg.is_empty() {
                return Err(err(kind, "`arg` is empty".into()));
            }
            // A child may add limits on any argument name, and the name reaches the console,
            // the CLI and the log: no control characters (terminal escapes), and no `#`, which
            // records and catalogs use for a derived value (`url#host`) (SR-59).
            if l.arg.chars().any(|c| c.is_control() || c == '#') {
                return Err(err(
                    kind,
                    format!(
                        "`arg` {:?} has a control character or `#`",
                        l.arg.escape_debug().to_string()
                    ),
                ));
            }
            if kind == LimitKind::Sum && l.derive.is_some() {
                return Err(err(
                    kind,
                    "a `sum` counts the argument itself and takes no `derive`".into(),
                ));
            }
        }
        if let Some(l) = &self.sum {
            if let Some(c) = cap.constraints.get(&l.arg) {
                if !admits_amount(c) {
                    return Err(err(
                        LimitKind::Sum,
                        format!(
                            "the constraint on `{}` admits no non-negative integer, so no call \
                             could be charged",
                            l.arg
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Can a value satisfying `c` be a valid `sum` amount?
fn admits_amount(c: &ArgConstraint) -> bool {
    match c {
        ArgConstraint::Equals(v) => amount_of(v).is_some(),
        ArgConstraint::OneOf(vs) => vs.iter().any(|v| amount_of(v).is_some()),
        ArgConstraint::Prefix(_) => false,
    }
}

/// A `sum` amount: a JSON number that is a non-negative integer no larger than
/// [`MAX_LIMIT`]. A float with no fractional part counts as that integer (`5.0` is `5`, as
/// in the constraint comparison and the Cedar translation); anything else is `None`.
pub fn amount_of(v: &Value) -> Option<u64> {
    let n = v.as_number()?;
    if let Some(u) = n.as_u64() {
        return (u <= MAX_LIMIT).then_some(u);
    }
    if n.is_i64() {
        return None; // negative
    }
    let f = n.as_f64()?;
    // 2^53: beyond it a double no longer stands for one integer.
    (f.is_finite() && f >= 0.0 && f.fract() == 0.0 && f <= 9_007_199_254_740_992.0)
        .then_some(f as u64)
}

/// One counter a call would be charged against: a limit of a capability of a hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charge {
    /// Position of the hop in the chain (0 is the root).
    pub hop: usize,
    /// Index of the capability in the hop's capability set (its canonical order).
    pub cap: usize,
    /// The hop's lease: the counter lives under it.
    pub lease: LeaseId,
    pub kind: LimitKind,
    /// The argument a `sum`, `calls_per` or `distinct` limit counts, `arg#host` for a derived
    /// value ([`ArgLimit::counted`]); `None` for `calls`.
    pub arg: Option<String>,
    /// For `calls_per` and `distinct`: the RFC 8785 canonical JSON of the value counted (the
    /// derived value, for a derived limit). The store keeps only a keyed hash of it. A
    /// `distinct` charge adds 1 to its limit's count only when the value is new under it; the
    /// store decides that in the charge's transaction.
    pub value: Option<Vec<u8>>,
    /// What the call adds: 1, or the summed amount.
    pub amount: u64,
    /// The limit's `max`.
    pub max: u64,
    /// A run-usage counter ([`usage_charges`]) rather than a token limit: kept under the run's
    /// chain id and the tool (`arg` is `"<server>/<tool>"`), never exhausted (it saturates at
    /// `max`), left out of the decision record's `budget` member, and not synced like a `sum`
    /// limit.
    pub usage: bool,
}

impl Charge {
    /// A charge with no amount, for reading what a counter holds.
    pub fn probe(
        lease: LeaseId,
        cap: usize,
        kind: LimitKind,
        arg: Option<String>,
        max: u64,
    ) -> Self {
        Self {
            hop: 0,
            cap,
            lease,
            kind,
            arg,
            value: None,
            amount: 0,
            max,
            usage: false,
        }
    }
}

/// Why a call cannot be charged: the argument a limit counts is missing, for `sum` not an
/// amount, or for a derived value has none. Reason [`REASON_LIMIT_ARG_INVALID`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("limit `{kind}` of hop {hop} counts argument `{arg}`, which {problem}")]
pub struct LimitArgError {
    pub hop: usize,
    pub kind: LimitKind,
    pub arg: String,
    pub problem: String,
}

/// Every counter `call` would be charged against: for each hop, each capability that carries
/// limits and permits the call ([`Capability::permits`]), one charge per limit (and, for
/// `calls_per` and `distinct` on a list-valued argument, one per distinct element; a list of
/// more than [`MAX_COUNTED_VALUES`] elements is refused). Ordered
/// by hop, then capability index, then kind. Empty when no limit in the chain matches.
pub fn charges_for(chain: &DelegationChain, call: &ToolCall) -> Result<Vec<Charge>, LimitArgError> {
    let mut out = Vec::new();
    for (hop_index, hop) in chain.hops.iter().enumerate() {
        for (cap_index, cap) in hop.capabilities.iter().enumerate() {
            let limits = &cap.limits;
            if limits.is_empty() || !cap.permits(call) {
                continue;
            }
            let base = |kind, arg: Option<String>, value, amount, max| Charge {
                hop: hop_index,
                cap: cap_index,
                lease: hop.lease.clone(),
                kind,
                arg,
                value,
                amount,
                max,
                usage: false,
            };
            if let Some(max) = limits.calls {
                out.push(base(LimitKind::Calls, None, None, 1, max));
            }
            if let Some(l) = &limits.sum {
                let bad = |problem: &str| LimitArgError {
                    hop: hop_index,
                    kind: LimitKind::Sum,
                    arg: l.arg.clone(),
                    problem: problem.to_string(),
                };
                let v = call
                    .arguments
                    .get(&l.arg)
                    .filter(|v| !v.is_null())
                    .ok_or_else(|| bad("is missing"))?;
                let amount = amount_of(v).ok_or_else(|| {
                    bad("is not a non-negative integer (a string, a fraction or a negative number)")
                })?;
                out.push(base(
                    LimitKind::Sum,
                    Some(l.arg.clone()),
                    None,
                    amount,
                    l.max,
                ));
            }
            for (kind, l) in [
                (LimitKind::CallsPer, &limits.calls_per),
                (LimitKind::Distinct, &limits.distinct),
            ] {
                let Some(l) = l else { continue };
                let bad = |problem: String| LimitArgError {
                    hop: hop_index,
                    kind,
                    arg: l.counted(),
                    problem,
                };
                let v = call
                    .arguments
                    .get(&l.arg)
                    .filter(|v| !v.is_null())
                    .ok_or_else(|| bad("is missing".into()))?;
                // Each value is a counter row and a charge-log row, written in the charge's
                // transaction: bound them per call (SR-57).
                if v.as_array().is_some_and(|a| a.len() > MAX_COUNTED_VALUES) {
                    return Err(bad(format!("lists more than {MAX_COUNTED_VALUES} values")));
                }
                let values = match l.derive {
                    None => destinations(v),
                    Some(d) => derived_destinations(v, d).ok_or_else(|| {
                        bad(format!(
                            "has no {d} to count (each value must be an absolute URL with a host)"
                        ))
                    })?,
                };
                for value in values {
                    out.push(base(kind, Some(l.counted()), Some(value), 1, l.max));
                }
            }
        }
    }
    Ok(out)
}

/// The run-usage counters a call to a destructive tool is charged against (design section 3.5):
/// all under the run's `chain_id` and keyed by the tool, `"<server>/<tool>"`.
///
/// - always a `calls` counter, charged 1;
/// - when the catalog names an `amount` input, a `sum` counter charged that argument's value
///   if it is an amount ([`amount_of`]), else 0: a missing, string, fractional or negative
///   amount adds nothing (the policy sees it in `context.input` and decides);
/// - when the catalog names a `destination` input and the call carries a non-null value, one
///   `calls_per` counter per distinct value (each element of a list), whose canonical JSON the
///   store keeps only as a keyed hash. A destination written `input#host` counts the host of
///   each value ([`Derive::Host`]); a value with no host counts as itself, wrapped as
///   `{"raw": value}` (a host is a string, so it collides with none), so a new unparseable
///   value is a new destination (SR-63). A list of more than [`MAX_COUNTED_VALUES`] elements
///   is one destination, the whole list (wrapped the same way under `#host`). A `destination`
///   that [`parse_arg_ref`] refuses counts nothing; the catalog refuses it at load.
///
/// Each has `max` [`MAX_LIMIT`] and [`Charge::usage`] set. Ordered calls, amount, destinations.
pub fn usage_charges(
    chain_id: &LeaseId,
    call: &ToolCall,
    amount_arg: Option<&str>,
    destination_arg: Option<&str>,
) -> Vec<Charge> {
    let tool = format!("{}/{}", call.server, call.tool);
    let base = |kind, value, amount| Charge {
        hop: 0,
        cap: 0,
        lease: chain_id.clone(),
        kind,
        arg: Some(tool.clone()),
        value,
        amount,
        max: MAX_LIMIT,
        usage: true,
    };
    let mut out = vec![base(LimitKind::Calls, None, 1)];
    if let Some(arg) = amount_arg {
        let amount = call.arguments.get(arg).and_then(amount_of).unwrap_or(0);
        out.push(base(LimitKind::Sum, None, amount));
    }
    let destination = destination_arg.and_then(|d| parse_arg_ref(d).ok());
    if let Some((v, derive)) = destination
        .as_ref()
        .and_then(|(arg, d)| Some((call.arguments.get(arg)?, *d)))
        .filter(|(v, _)| !v.is_null())
    {
        let values = match derive {
            // More values than a call may count (SR-57): the list as a whole is one
            // destination, new unless the very same list was seen.
            None if v.as_array().is_some_and(|a| a.len() > MAX_COUNTED_VALUES) => {
                vec![canonical(v)]
            }
            Some(_) if v.as_array().is_some_and(|a| a.len() > MAX_COUNTED_VALUES) => {
                vec![canonical(&raw(v))]
            }
            None => destinations(v),
            Some(d) => hosts_or_raw(v, d),
        };
        for value in values {
            out.push(base(LimitKind::CallsPer, Some(value), 1));
        }
    }
    out
}

fn canonical(v: &Value) -> Vec<u8> {
    crate::jcs::to_vec(v).expect("a JSON value has a canonical form")
}

/// The elements of a list value, or the value itself.
fn elements(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    }
}

/// The derived values of `v` (each element of a list), as canonical JSON strings, distinct
/// and sorted. `None` when any element has no derived value.
fn derived_destinations(v: &Value, derive: Derive) -> Option<Vec<Vec<u8>>> {
    let mut out = BTreeSet::new();
    for item in elements(v) {
        out.insert(canonical(&Value::String(derive.apply(item)?)));
    }
    Some(out.into_iter().collect())
}

/// A value with no derived value, as run usage counts it: `{"raw": value}`, which no derived
/// value (a JSON string) can equal (SR-63).
fn raw(v: &Value) -> Value {
    serde_json::json!({ "raw": v })
}

/// As [`derived_destinations`], for run usage: an element with no derived value counts as
/// itself, [`raw`], instead of refusing the call.
fn hosts_or_raw(v: &Value, derive: Derive) -> Vec<Vec<u8>> {
    elements(v)
        .into_iter()
        .map(|item| canonical(&derive.apply(item).map_or_else(|| raw(item), Value::String)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The values a `calls_per` or `distinct` argument counts, as canonical JSON: each distinct
/// element of a list, or the value itself.
fn destinations(v: &Value) -> Vec<Vec<u8>> {
    elements(v)
        .into_iter()
        .map(canonical)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilitySet;
    use crate::chain::{AgentId, OriginatingUser, DEFAULT_MAX_DEPTH};
    use crate::error::ChainError;
    use serde_json::json;
    use time::macros::datetime;
    use time::Duration;

    fn root(caps: Vec<Capability>) -> DelegationChain {
        DelegationChain::root(
            OriginatingUser {
                subject: "user:mudit".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: datetime!(2026-10-24 08:00 UTC),
                attributes: Default::default(),
            },
            AgentId::new("planner"),
            CapabilitySet::from_iter(caps),
            datetime!(2026-10-24 09:00 UTC),
            Duration::hours(1),
            LeaseId::new("l0"),
        )
        .unwrap()
    }

    fn extend(chain: &DelegationChain, agent: &str, caps: Vec<Capability>) -> DelegationChain {
        chain
            .extend(
                AgentId::new(agent),
                CapabilitySet::from_iter(caps),
                datetime!(2026-10-24 09:01 UTC),
                Duration::minutes(30),
                LeaseId::new(format!("l-{agent}")),
                DEFAULT_MAX_DEPTH,
            )
            .unwrap()
    }

    fn send_money() -> Capability {
        Capability::new("banking", "send_money")
    }

    #[test]
    fn extend_inherits_and_clamps_limits_and_validate_rejects_widening() {
        let chain =
            root(vec![send_money().with_limits(
                Limits::default().with_calls(2).with_sum("amount", 500),
            )]);
        // A child that asks for no limit gets the parent's; one that asks for more gets the
        // parent's figure; one that asks for less keeps it.
        let child = extend(&chain, "helper", vec![send_money()]);
        assert_eq!(
            child.hops[1].capabilities.iter().next().unwrap().limits,
            Limits::default().with_calls(2).with_sum("amount", 500)
        );
        let child = extend(
            &chain,
            "helper",
            vec![send_money().with_limits(Limits::default().with_calls(9).with_sum("amount", 40))],
        );
        assert_eq!(
            child.hops[1].capabilities.iter().next().unwrap().limits,
            Limits::default().with_calls(2).with_sum("amount", 40)
        );
        child
            .validate_at(datetime!(2026-10-24 09:02 UTC), DEFAULT_MAX_DEPTH)
            .unwrap();
        // Raising a figure in a signed chain (P2) is caught at validation.
        let mut widened = child.clone();
        widened.hops[1].capabilities = CapabilitySet::from_iter([
            send_money().with_limits(Limits::default().with_calls(3).with_sum("amount", 40))
        ]);
        assert!(matches!(
            widened.validate_at(datetime!(2026-10-24 09:02 UTC), DEFAULT_MAX_DEPTH),
            Err(ChainError::AttenuationViolated { index: 1, .. })
        ));
        // So is dropping one.
        let mut dropped = child;
        dropped.hops[1].capabilities = CapabilitySet::from_iter([send_money()]);
        assert!(dropped
            .validate_at(datetime!(2026-10-24 09:02 UTC), DEFAULT_MAX_DEPTH)
            .is_err());
    }

    #[test]
    fn malformed_limits_are_refused_in_a_chain() {
        let mut chain = root(vec![send_money()]);
        chain.hops[0].capabilities = CapabilitySet::from_iter([send_money()
            .with_constraint("amount", ArgConstraint::Prefix("1".into()))
            .with_limits(Limits::default().with_sum("amount", 5))]);
        assert!(matches!(
            chain.validate_at(datetime!(2026-10-24 09:02 UTC), DEFAULT_MAX_DEPTH),
            Err(ChainError::InvalidLimit { index: 0, .. })
        ));
    }

    #[test]
    fn charges_cover_every_matching_limited_capability_in_every_hop() {
        let chain = root(vec![
            send_money().with_limits(Limits::default().with_calls(3)),
            Capability::new("banking", "*").with_limits(Limits::default().with_sum("amount", 100)),
            Capability::new("banking", "read_file"),
        ]);
        let child = extend(
            &chain,
            "helper",
            vec![send_money()
                .with_constraint("recipient", ArgConstraint::Equals(json!("emma")))
                .with_limits(
                    Limits::default()
                        .with_calls(1)
                        .with_sum("amount", 40)
                        .with_calls_per("recipient", 1),
                )],
        );
        let call = ToolCall::new(
            "banking",
            "send_money",
            json!({"recipient": "emma", "amount": 40}),
        );
        let charges = charges_for(&child, &call).unwrap();
        let shape: Vec<(usize, LimitKind, u64, u64)> = charges
            .iter()
            .map(|c| (c.hop, c.kind, c.amount, c.max))
            .collect();
        // Root: `banking:*` (sum 100) sorts before `banking:send_money` (calls 3).
        assert_eq!(
            shape,
            vec![
                (0, LimitKind::Sum, 40, 100),
                (0, LimitKind::Calls, 1, 3),
                (1, LimitKind::Calls, 1, 1),
                (1, LimitKind::Sum, 40, 40),
                (1, LimitKind::CallsPer, 1, 1),
            ]
        );
        assert_eq!(charges[0].lease, LeaseId::new("l0"));
        assert_eq!(charges[4].lease, LeaseId::new("l-helper"));
        assert_eq!(charges[4].value.as_deref(), Some(&b"\"emma\""[..]));
        // The root's `banking:*` sum matches every banking call, so one without `amount` is
        // refused: a `sum` limit on a wildcard capability needs the argument on every call.
        let read = ToolCall::new("banking", "read_file", json!({"path": "bills/x"}));
        assert_eq!(charges_for(&chain, &read).unwrap_err().hop, 0);
        // A call no limited capability matches is charged nothing.
        let none = charges_for(&root(vec![Capability::new("banking", "read_file")]), &read);
        assert_eq!(none.unwrap(), vec![]);
    }

    #[test]
    fn negative_or_string_amount_is_refused() {
        let chain = root(vec![
            send_money().with_limits(Limits::default().with_sum("amount", 100))
        ]);
        for amount in [json!("1500"), json!(-1200), json!(0.5), json!(null)] {
            let call = ToolCall::new("banking", "send_money", json!({"amount": amount}));
            let err = charges_for(&chain, &call).unwrap_err();
            assert_eq!(err.kind, LimitKind::Sum, "{amount}");
        }
        let missing = ToolCall::new("banking", "send_money", json!({}));
        assert!(charges_for(&chain, &missing).is_err());
    }

    #[test]
    fn list_valued_destinations_count_each_distinct_element() {
        let chain =
            root(vec![Capability::new("mail", "send")
                .with_limits(Limits::default().with_calls_per("to", 1))]);
        let call = ToolCall::new("mail", "send", json!({"to": ["b@x", "a@x", "b@x"]}));
        let charges = charges_for(&chain, &call).unwrap();
        let values: Vec<_> = charges.iter().map(|c| c.value.clone().unwrap()).collect();
        assert_eq!(values, vec![b"\"a@x\"".to_vec(), b"\"b@x\"".to_vec()]);
        let missing = ToolCall::new("mail", "send", json!({}));
        assert_eq!(
            charges_for(&chain, &missing).unwrap_err().kind,
            LimitKind::CallsPer
        );
    }

    #[test]
    fn serde_shape_and_unknown_kinds() {
        let l = Limits::default()
            .with_calls(1)
            .with_sum("amount", 10)
            .with_calls_per("recipient", 1);
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(
            v,
            json!({"calls": 1, "sum": {"arg": "amount", "max": 10},
                   "calls_per": {"arg": "recipient", "max": 1}})
        );
        assert_eq!(serde_json::from_value::<Limits>(v).unwrap(), l);
        assert_eq!(serde_json::to_value(Limits::default()).unwrap(), json!({}));
        // `distinct` and a derived value round-trip; an unknown kind or derivation is
        // refused, not ignored.
        let d = Limits::default()
            .with_distinct("recipient", 2)
            .with_calls_per("url", 1);
        let mut d = d;
        d.calls_per = d.calls_per.map(|l| l.derived(Derive::Host));
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(
            v,
            json!({"calls_per": {"arg": "url", "max": 1, "derive": "host"},
                   "distinct": {"arg": "recipient", "max": 2}})
        );
        assert_eq!(serde_json::from_value::<Limits>(v).unwrap(), d);
        for bad in [
            json!({"window": {"arg": "recipient", "max": 1}}),
            json!({"distinct": {"arg": "url", "max": 1, "derive": "path"}}),
            json!({"distinct": {"arg": "url", "max": 1, "extra": true}}),
        ] {
            assert!(
                serde_json::from_value::<Limits>(bad.clone()).is_err(),
                "{bad}"
            );
        }
        // Negative, fractional and string maxima do not deserialize.
        for bad in [
            json!({"calls": -1}),
            json!({"calls": 1.5}),
            json!({"calls": "1"}),
        ] {
            assert!(
                serde_json::from_value::<Limits>(bad.clone()).is_err(),
                "{bad}"
            );
        }
        assert!(serde_json::from_value::<Limits>(json!({"sum": {"arg": "a", "max": -3}})).is_err());
    }

    #[test]
    fn narrowing_rules() {
        let parent = Limits::default().with_calls(2).with_sum("amount", 500);
        assert!(parent.narrows(&parent));
        assert!(Limits::default()
            .with_calls(1)
            .with_sum("amount", 100)
            .narrows(&parent));
        // A child may add a limit.
        assert!(Limits::default()
            .with_calls(1)
            .with_sum("amount", 100)
            .with_calls_per("recipient", 1)
            .narrows(&parent));
        // ... but not drop one, raise one, or move a sum to another argument.
        assert!(!Limits::default().with_calls(1).narrows(&parent));
        assert!(!Limits::default()
            .with_calls(3)
            .with_sum("amount", 100)
            .narrows(&parent));
        assert!(!Limits::default()
            .with_calls(1)
            .with_sum("fee", 100)
            .narrows(&parent));
        // Anything narrows no limits.
        assert!(Limits::default().narrows(&Limits::default()));
        assert!(!Limits::default().narrows(&Limits::default().with_calls(5)));
        // Cross-kind: `calls: m` satisfies `calls_per: {arg, n}` when m <= n.
        let per = Limits::default().with_calls_per("recipient", 2);
        assert!(Limits::default().with_calls(2).narrows(&per));
        assert!(!Limits::default().with_calls(3).narrows(&per));
        assert!(!Limits::default().with_calls_per("other", 1).narrows(&per));
    }

    #[test]
    fn clamp_fills_and_lowers() {
        let parent = Limits::default()
            .with_calls(2)
            .with_sum("amount", 500)
            .with_calls_per("recipient", 1);
        let got = Limits::default().clamp_to(&parent);
        assert_eq!(got, parent);
        let got = Limits::default()
            .with_calls(9)
            .with_sum("amount", 100)
            .clamp_to(&parent);
        assert_eq!(got.calls, Some(2));
        assert_eq!(got.sum, Some(ArgLimit::new("amount", 100)));
        assert_eq!(got.calls_per, Some(ArgLimit::new("recipient", 1)));
        assert!(got.narrows(&parent));
        // `calls: 1` already implies `calls_per: 1`, so it is not added.
        let got = Limits::default()
            .with_calls(1)
            .clamp_to(&Limits::default().with_calls_per("recipient", 1));
        assert_eq!(got, Limits::default().with_calls(1));
        // A sum on another argument stays, and does not narrow.
        let got = Limits::default().with_sum("fee", 1).clamp_to(&parent);
        assert!(!got.narrows(&parent));
    }

    #[test]
    fn distinct_narrowing_and_clamping() {
        let parent = Limits::default().with_distinct("to", 2);
        assert!(parent.narrows(&parent));
        assert!(Limits::default().with_distinct("to", 1).narrows(&parent));
        assert!(!Limits::default().with_distinct("to", 3).narrows(&parent));
        assert!(!Limits::default().with_distinct("cc", 1).narrows(&parent));
        assert!(!Limits::default().narrows(&parent));
        // `calls_per` bounds no number of values, so it does not stand in for `distinct`.
        assert!(!Limits::default().with_calls_per("to", 1).narrows(&parent));
        // Cross-kind: `calls: m` satisfies `distinct: {arg, n}` when m <= n.
        assert!(Limits::default().with_calls(2).narrows(&parent));
        assert!(!Limits::default().with_calls(3).narrows(&parent));
        // A derived limit narrows only the same derivation of the same argument.
        let host = |l: Limits| Limits {
            distinct: l.distinct.map(|d| d.derived(Derive::Host)),
            ..l
        };
        let parent_host = host(Limits::default().with_distinct("url", 2));
        assert!(host(Limits::default().with_distinct("url", 1)).narrows(&parent_host));
        assert!(!Limits::default()
            .with_distinct("url", 1)
            .narrows(&parent_host));
        assert!(!host(Limits::default().with_distinct("url", 1)).narrows(&parent));
        assert!(Limits::default().with_calls(1).narrows(&parent_host));
        // Clamping fills, lowers, and leaves `calls` alone when it already implies it.
        assert_eq!(Limits::default().clamp_to(&parent_host), parent_host);
        assert_eq!(
            host(Limits::default().with_distinct("url", 9)).clamp_to(&parent_host),
            host(Limits::default().with_distinct("url", 2))
        );
        assert_eq!(
            Limits::default().with_calls(2).clamp_to(&parent),
            Limits::default().with_calls(2)
        );
        assert_eq!(
            Limits::default().with_calls(3).clamp_to(&parent),
            Limits::default().with_calls(3).with_distinct("to", 2)
        );
        // Another derivation of the same argument is left alone, and does not narrow.
        let got = Limits::default()
            .with_distinct("url", 1)
            .clamp_to(&parent_host);
        assert!(!got.narrows(&parent_host));
    }

    #[test]
    fn distinct_charges_and_derived_hosts() {
        let host = ArgLimit::new("url", 2).derived(Derive::Host);
        let chain = root(vec![
            Capability::new("web", "get_webpage").with_limits(Limits {
                distinct: Some(host.clone()),
                ..Limits::default()
            }),
            Capability::new("mail", "send").with_limits(Limits::default().with_distinct("to", 3)),
        ]);
        let call = ToolCall::new(
            "web",
            "get_webpage",
            json!({"url": "https://News.Example:8443/a?q=1"}),
        );
        let charges = charges_for(&chain, &call).unwrap();
        assert_eq!(charges.len(), 1);
        assert_eq!(charges[0].kind, LimitKind::Distinct);
        assert_eq!(charges[0].arg.as_deref(), Some("url#host"));
        assert_eq!(charges[0].value.as_deref(), Some(&b"\"news.example\""[..]));
        assert_eq!((charges[0].amount, charges[0].max), (1, 2));
        // No host: refused, naming the derived argument.
        for url in [
            json!("news.example/a"),
            json!("mailto:a@b.example"),
            json!(7),
        ] {
            let call = ToolCall::new("web", "get_webpage", json!({ "url": url }));
            let err = charges_for(&chain, &call).unwrap_err();
            assert_eq!(
                (err.kind, err.arg.as_str()),
                (LimitKind::Distinct, "url#host")
            );
        }
        // A list counts each distinct element.
        let call = ToolCall::new("mail", "send", json!({"to": ["b@x", "a@x", "b@x"]}));
        let values: Vec<_> = charges_for(&chain, &call)
            .unwrap()
            .into_iter()
            .map(|c| (c.kind, c.value.unwrap()))
            .collect();
        assert_eq!(
            values,
            vec![
                (LimitKind::Distinct, b"\"a@x\"".to_vec()),
                (LimitKind::Distinct, b"\"b@x\"".to_vec())
            ]
        );
    }

    #[test]
    fn host_derivation_and_arg_refs() {
        let h = |s: &str| Derive::Host.apply(&json!(s));
        assert_eq!(h("https://a.example/x").as_deref(), Some("a.example"));
        assert_eq!(h("HTTPS://A.Example./y?z#f").as_deref(), Some("a.example"));
        assert_eq!(
            h("http://user:pw@a.example:81/").as_deref(),
            Some("a.example")
        );
        assert_eq!(h("http://[::1]:8080/").as_deref(), Some("[::1]"));
        assert_eq!(h("a.example/x"), None);
        assert_eq!(h("mailto:a@b.example"), None);
        assert_eq!(h("file:///etc/passwd"), None);
        assert_eq!(Derive::Host.apply(&json!(["https://a.example"])), None);
        assert_eq!(parse_arg_ref("url").unwrap(), ("url".to_string(), None));
        assert_eq!(
            parse_arg_ref("url#host").unwrap(),
            ("url".to_string(), Some(Derive::Host))
        );
        assert!(parse_arg_ref("url#path").is_err());
        assert!(parse_arg_ref("#host").is_err());
        // A `sum` takes no derivation.
        let cap = Capability::new("bank", "send").with_limits(Limits {
            sum: Some(ArgLimit::new("amount", 1).derived(Derive::Host)),
            ..Limits::default()
        });
        assert!(cap.validate_limits().is_err());
    }

    /// SR-56: WHATWG and common HTTP clients disagree on where the host of
    /// `https://a.example\@b.example/` ends (`a.example` here, `b.example` for Python's
    /// `urllib` and `httpx`), so such a value has no host to count; a limit refuses it and run
    /// usage counts it as a value with no host.
    #[test]
    fn a_url_parsers_disagree_on_has_no_host_sr56() {
        let h = |s: &str| Derive::Host.apply(&json!(s));
        for url in [
            "https://a.example\\@b.example/",
            "https://a.example\\.b.example/",
            "https://a.example/\\@b.example",
            "https://a.exa\tmple/",
            "https://a.example /",
            " https://a.example/",
            "https://a.example/\n",
            "https://a.exa\u{7f}mple/",
            "https://a.example\u{a0}/",
        ] {
            assert_eq!(h(url), None, "{url:?}");
        }
        // Userinfo is still dropped, and an encoded backslash is part of it on every parser.
        assert_eq!(
            h("https://a.example%5C@b.example/").as_deref(),
            Some("b.example")
        );
        let chain = root(vec![Capability::new("web", "get_webpage").with_limits(
            Limits {
                distinct: Some(ArgLimit::new("url", 1).derived(Derive::Host)),
                ..Limits::default()
            },
        )]);
        let call = ToolCall::new(
            "web",
            "get_webpage",
            json!({"url": "https://a.example\\@b.example/?q=secret"}),
        );
        assert_eq!(charges_for(&chain, &call).unwrap_err().arg, "url#host");
        let usage = usage_charges(&LeaseId::new("run"), &call, None, Some("url#host"));
        assert_eq!(
            usage[1].value.as_deref(),
            Some(canonical(&json!({"raw": "https://a.example\\@b.example/?q=secret"})).as_slice())
        );
    }

    /// SR-57: a list argument counts at most `MAX_COUNTED_VALUES` values per limit and call.
    #[test]
    fn a_call_counts_a_bounded_number_of_values_sr57() {
        let chain = root(vec![Capability::new("mail", "send").with_limits(
            Limits::default()
                .with_calls_per("to", 1)
                .with_distinct("cc", 1000),
        )]);
        let many: Vec<String> = (0..=MAX_COUNTED_VALUES)
            .map(|i| format!("u{i}@x"))
            .collect();
        let at_most: Vec<String> = many[..MAX_COUNTED_VALUES].to_vec();
        let call = |to: &[String], cc: &[String]| {
            ToolCall::new("mail", "send", json!({ "to": to, "cc": cc }))
        };
        let charges = charges_for(&chain, &call(&at_most, &at_most)).unwrap();
        assert_eq!(charges.len(), 2 * MAX_COUNTED_VALUES);
        for (to, cc, kind, arg) in [
            (&many, &at_most, LimitKind::CallsPer, "to"),
            (&at_most, &many, LimitKind::Distinct, "cc"),
        ] {
            let err = charges_for(&chain, &call(to, cc)).unwrap_err();
            assert_eq!((err.kind, err.arg.as_str()), (kind, arg));
            assert!(err.problem.contains("more than 256"), "{}", err.problem);
        }
        // Run usage never refuses: the oversized list is one destination.
        let usage = usage_charges(&LeaseId::new("run"), &call(&many, &[]), None, Some("to"));
        assert_eq!(usage.len(), 2);
        assert_eq!(
            usage[1].value.as_deref(),
            Some(canonical(&json!(many)).as_slice())
        );
        let hosts: Vec<String> = (0..=MAX_COUNTED_VALUES)
            .map(|i| format!("https://h{i}.example/"))
            .collect();
        let fetch = ToolCall::new("web", "get_webpage", json!({ "url": hosts }));
        assert_eq!(
            usage_charges(&LeaseId::new("run"), &fetch, None, Some("url#host")).len(),
            2
        );
    }

    /// SR-59: a limit's `arg` is shown by the console and the CLI and written to the log, and
    /// a child may add a limit on any name: control characters and `#` are refused.
    #[test]
    fn limit_arg_names_have_no_control_characters_or_hash_sr59() {
        for arg in ["to\u{1b}[2J", "to\n", "a\u{7}", "url#host", "#"] {
            for limits in [
                Limits::default().with_sum(arg, 1),
                Limits::default().with_calls_per(arg, 1),
                Limits::default().with_distinct(arg, 1),
            ] {
                let cap = Capability::new("mail", "send").with_limits(limits);
                assert!(cap.validate_limits().is_err(), "{arg:?}");
            }
        }
        let ok = Capability::new("mail", "send")
            .with_limits(Limits::default().with_calls_per("recipient_émail", 1));
        assert!(ok.validate_limits().is_ok());
    }

    /// SR-63: in run usage a value with no host counts as itself, wrapped as `{"raw": value}`
    /// so it collides with no host: two different unparseable URLs are two destinations, the
    /// same one twice is one.
    #[test]
    fn hostless_usage_values_are_destinations_of_their_own_sr63() {
        let run = LeaseId::new("run");
        let dest = |url: Value| {
            let call = ToolCall::new("web", "get_webpage", json!({ "url": url }));
            usage_charges(&run, &call, None, Some("url#host"))
                .into_iter()
                .skip(1)
                .map(|c| c.value.unwrap())
                .collect::<Vec<_>>()
        };
        let a = dest(json!("docs.example/page"));
        let b = dest(json!("evil.example/?d=secret"));
        assert_eq!(a.len(), 1);
        assert_ne!(a, b, "two hostless values must be two destinations");
        assert_eq!(a, dest(json!("docs.example/page")), "the same one is one");
        assert_eq!(
            dest(json!(["docs.example/page", "docs.example/page"])).len(),
            1
        );
        assert_eq!(
            dest(json!(["docs.example/page", "evil.example/?d=secret"])).len(),
            2
        );
        assert_eq!(a[0], canonical(&json!({"raw": "docs.example/page"})));
        // A hostless value never collides with a host, even one spelled like the raw value.
        assert_ne!(dest(json!("a.example")), dest(json!("https://a.example/")));
    }

    #[test]
    fn usage_destinations_may_be_hosts() {
        let chain_id = LeaseId::new("run-1");
        let call = ToolCall::new(
            "web",
            "get_webpage",
            json!({"url": ["https://a.example/1", "https://A.example/2", "not a url", "x:y"]}),
        );
        let c = usage_charges(&chain_id, &call, None, Some("url#host"));
        let values: Vec<_> = c.iter().skip(1).map(|c| c.value.clone().unwrap()).collect();
        // One host, and every value without one as itself, wrapped (SR-63).
        assert_eq!(
            values,
            vec![
                b"\"a.example\"".to_vec(),
                canonical(&json!({"raw": "not a url"})),
                canonical(&json!({"raw": "x:y"})),
            ]
        );
        // A destination the catalog would refuse counts nothing.
        assert_eq!(
            usage_charges(&chain_id, &call, None, Some("url#path")).len(),
            1
        );
    }

    #[test]
    fn amounts() {
        assert_eq!(amount_of(&json!(0)), Some(0));
        assert_eq!(amount_of(&json!(40)), Some(40));
        assert_eq!(amount_of(&json!(40.0)), Some(40));
        assert_eq!(amount_of(&json!(-1200)), None);
        assert_eq!(amount_of(&json!(0.5)), None);
        assert_eq!(amount_of(&json!("1500")), None);
        assert_eq!(amount_of(&json!(u64::MAX)), None);
        assert_eq!(amount_of(&json!(null)), None);
    }

    #[test]
    fn validation() {
        let cap = |l: Limits| Capability::new("bank", "send").with_limits(l);
        assert!(cap(Limits::default().with_calls(MAX_LIMIT))
            .validate_limits()
            .is_ok());
        assert!(cap(Limits::default().with_calls(MAX_LIMIT + 1))
            .validate_limits()
            .is_err());
        assert!(cap(Limits::default().with_sum("", 1))
            .validate_limits()
            .is_err());
        let prefixed = Capability::new("bank", "send")
            .with_constraint("amount", ArgConstraint::Prefix("1".into()))
            .with_limits(Limits::default().with_sum("amount", 10));
        assert!(prefixed.validate_limits().is_err());
        let pinned = Capability::new("bank", "send")
            .with_constraint("amount", ArgConstraint::Equals(json!(10)))
            .with_limits(Limits::default().with_sum("amount", 10));
        assert!(pinned.validate_limits().is_ok());
        let pinned_str = Capability::new("bank", "send")
            .with_constraint("amount", ArgConstraint::Equals(json!("10")))
            .with_limits(Limits::default().with_sum("amount", 10));
        assert!(pinned_str.validate_limits().is_err());
    }

    #[test]
    fn usage_charges_key_by_run_and_tool() {
        let chain_id = LeaseId::new("run-1");
        let call = ToolCall::new(
            "banking",
            "send_money",
            json!({"recipient": ["A", "B", "A"], "amount": 40}),
        );
        let c = usage_charges(&chain_id, &call, Some("amount"), Some("recipient"));
        assert_eq!(c.len(), 4, "calls, amount and two distinct destinations");
        assert!(c
            .iter()
            .all(|c| c.usage && c.lease == chain_id && c.max == MAX_LIMIT));
        assert!(c
            .iter()
            .all(|c| c.arg.as_deref() == Some("banking/send_money")));
        assert_eq!((c[0].kind, c[0].amount), (LimitKind::Calls, 1));
        assert_eq!((c[1].kind, c[1].amount), (LimitKind::Sum, 40));
        assert_eq!(c[2].kind, LimitKind::CallsPer);
        assert_ne!(c[2].value, c[3].value);

        // No catalog fields: only the call count.
        assert_eq!(usage_charges(&chain_id, &call, None, None).len(), 1);
        // An amount that is not one adds 0; a missing destination adds no counter.
        let odd = ToolCall::new("banking", "send_money", json!({"amount": "1500"}));
        let c = usage_charges(&chain_id, &odd, Some("amount"), Some("recipient"));
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].amount, 0);
        let negative = ToolCall::new("banking", "send_money", json!({"amount": -1200}));
        assert_eq!(
            usage_charges(&chain_id, &negative, Some("amount"), None)[1].amount,
            0
        );
    }
}
