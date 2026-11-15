//! Shared pieces of the capability targets `capability_prepared` and
//! `capability_attenuate_root`: generators over small alphabets (so patterns, values and limits
//! collide), and a reference attenuation written from the definitions with only the pairwise
//! implication.
//!
//! The core picks between two implementations by size: two small constraints, capabilities
//! and sets are compared pair by pair (`implies_direct`, `covers_calls_direct`,
//! `attenuate_indexed_direct`), anything larger through `capability::prepared` (canonical keys
//! in hash sets, summaries of `one_of` lists). Both are private; from outside they are reached
//! by size alone, so the reference here never hands the core a `one_of` of more than one value
//! on either side ([`implies_ref`] splits lists into their values), and [`padded`] adds to a
//! parent set one capability that covers nothing but is too large for the pairwise path, which
//! sends the same comparison through the prepared one.

use std::collections::BTreeMap;

use arbitrary::{Result, Unstructured};
use attenuo_core::{
    ArgConstraint, ArgLimit, AttenuationError, Capability, CapabilitySet, Derive, Limits,
};
use serde_json::Value;

/// Server and tool patterns.
pub const NAMES: &[&str] = &[
    "*", "a*", "ab*", "ab", "abc", "a", "b", "", "r/*", "r/", "r/x", "r", "A", "a/b", "*a",
];

/// Strings that read as paths (and some that `path_prefix` refuses), for values, prefixes and
/// path prefixes alike.
pub const PATHS: &[&str] = &[
    "/",
    "/w",
    "/w/",
    "/w/a",
    "/w/a/",
    "/w/a/b",
    "/w-a",
    "w",
    "w/",
    "w/a",
    "w/a/",
    "/w/../a",
    "/w//a",
    "/w/%2e%2e",
    "",
];

/// Other strings: prefixes of each other, and one character in two normal forms.
pub const STRS: &[&str] = &[
    "a", "ab", "abc", "b", "acme/", "acme/x", "é", "e\u{301}", "a\u{0}",
];

fn string(u: &mut Unstructured<'_>) -> Result<String> {
    Ok(if u.arbitrary()? {
        (*u.choose(PATHS)?).to_string()
    } else {
        (*u.choose(STRS)?).to_string()
    })
}

/// Argument names of constraints and limits.
pub const ARGS: &[&str] = &["x", "y"];

/// The server of [`padding`]. A parent pattern without `*` covers only a child pattern equal
/// to it, so the padding covers a generated capability only if that capability has this
/// server, which [`uses_pad`] reports so a target can skip the input.
pub const PAD_SERVER: &str = "zz-pad";

/// One more than the longest `one_of` the core compares pairwise (`SMALL_LIST` in
/// `capability.rs`). Longer lists, and any capability or set holding one, take the prepared
/// path. If the core's figure grows, lists between the two take the prepared path on both
/// sides of a comparison here, which weakens the comparison but does not make it wrong.
pub const LONG_LIST: usize = 9;

pub fn name(u: &mut Unstructured<'_>) -> Result<String> {
    if u.ratio(1u8, 10u8)? {
        return u.arbitrary();
    }
    Ok((*u.choose(NAMES)?).to_string())
}

/// A value from a small alphabet: strings and paths, integers in several spellings that are
/// equal as values, floats around the integer limits, and the odd structured value.
pub fn value(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 | 1 => Value::String(string(u)?),
        2 => Value::from(u.int_in_range(-1i64..=3)?),
        3 => u
            .choose(&[
                serde_json::json!(1.0),
                serde_json::json!(-0.0),
                serde_json::json!(2.0),
                serde_json::json!(0.5),
                serde_json::json!(1e16),
                serde_json::json!(10_000_000_000_000_000u64),
                serde_json::json!(9_007_199_254_740_993u64),
                serde_json::json!(9_007_199_254_740_992.0),
                serde_json::json!(i64::MAX),
                serde_json::json!(u64::MAX),
                serde_json::json!(922_337_203_685_477.0),
                serde_json::json!(922_337_203_685_478i64),
            ])?
            .clone(),
        4 => Value::Null,
        5 => Value::Bool(u.arbitrary()?),
        6 => serde_json::json!([u.int_in_range(0i64..=1)?, {"k": u.int_in_range(0i64..=1)?}]),
        _ => crate::json_value(u, 2)?,
    })
}

fn values(u: &mut Unstructured<'_>, max: usize) -> Result<Vec<Value>> {
    let n = if u.ratio(1u8, 3u8)? {
        u.int_in_range(LONG_LIST..=max.max(LONG_LIST))?
    } else {
        u.int_in_range(0..=3)?
    };
    // Often of one kind only (paths, other strings, small integers), which is where the
    // prepared implication summarises a list instead of looking its values up.
    let kind = u.int_in_range(0u8..=3)?;
    let mut out: Vec<Value> = Vec::with_capacity(n);
    for _ in 0..n {
        // Repeats, so that a long list often has few distinct values.
        if !out.is_empty() && u.ratio(1u8, 3u8)? {
            let i = u.choose_index(out.len())?;
            out.push(out[i].clone());
            continue;
        }
        out.push(match kind {
            0 => Value::String((*u.choose(PATHS)?).to_string()),
            1 => Value::String((*u.choose(STRS)?).to_string()),
            2 => Value::from(u.int_in_range(-1i64..=3)?),
            _ => value(u)?,
        });
    }
    Ok(out)
}

/// A constraint, built unchecked, so inverted and unbounded ranges and malformed paths
/// (which deserialisation refuses) are covered too. A `one_of` is sometimes longer than the
/// pairwise path takes, up to `max_list` values.
pub fn constraint(u: &mut Unstructured<'_>, max_list: usize) -> Result<ArgConstraint> {
    Ok(match u.int_in_range(0u8..=5)? {
        0 => ArgConstraint::Equals(value(u)?),
        1 | 2 => ArgConstraint::OneOf(values(u, max_list)?),
        3 => ArgConstraint::Prefix(string(u)?),
        4 => ArgConstraint::PathPrefix((*u.choose(PATHS)?).to_string()),
        _ => ArgConstraint::Range {
            min: bound(u)?,
            max: bound(u)?,
        },
    })
}

fn bound(u: &mut Unstructured<'_>) -> Result<Option<i64>> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 => None,
        1 => Some(*u.choose(&[i64::MIN, i64::MAX, 922_337_203_685_478])?),
        _ => Some(u.int_in_range(-2i64..=3)?),
    })
}

fn arg_limit(u: &mut Unstructured<'_>) -> Result<ArgLimit> {
    let l = ArgLimit::new(*u.choose(ARGS)?, u.int_in_range(0u64..=3)?);
    Ok(if u.ratio(1u8, 6u8)? {
        l.derived(Derive::Host)
    } else {
        l
    })
}

/// Limits with small figures on the two arguments, often none.
pub fn limits(u: &mut Unstructured<'_>) -> Result<Limits> {
    let mut l = Limits::default();
    if u.ratio(1u8, 2u8)? {
        return Ok(l);
    }
    if u.arbitrary()? {
        l.calls = Some(u.int_in_range(0u64..=3)?);
    }
    if u.arbitrary()? {
        l.sum = Some(arg_limit(u)?);
    }
    if u.ratio(1u8, 3u8)? {
        l.calls_per = Some(arg_limit(u)?);
    }
    if u.ratio(1u8, 3u8)? {
        l.distinct = Some(arg_limit(u)?);
    }
    Ok(l)
}

pub fn capability(u: &mut Unstructured<'_>, max_list: usize) -> Result<Capability> {
    let mut c = Capability::new(name(u)?, name(u)?);
    for _ in 0..u.int_in_range(0usize..=2)? {
        let arg = (*u.choose(ARGS)?).to_string();
        c.constraints.insert(arg, constraint(u, max_list)?);
    }
    c.limits = limits(u)?;
    Ok(c)
}

/// The capabilities of a set as a list, before the set orders and deduplicates them, so a
/// target can build the same set from several orders.
pub fn caps(u: &mut Unstructured<'_>, max_caps: usize, max_list: usize) -> Result<Vec<Capability>> {
    let n = u.int_in_range(0..=max_caps)?;
    let mut out: Vec<Capability> = Vec::with_capacity(n);
    for _ in 0..n {
        // Sometimes a copy of an earlier one with other limits or one constraint changed:
        // the shapes that share a parent, or that are equal after clamping.
        if !out.is_empty() && u.ratio(1u8, 3u8)? {
            let mut c = out[u.choose_index(out.len())?].clone();
            if u.arbitrary()? {
                c.limits = limits(u)?;
            } else {
                c.constraints
                    .insert((*u.choose(ARGS)?).to_string(), constraint(u, max_list)?);
            }
            out.push(c);
        } else {
            out.push(capability(u, max_list)?);
        }
    }
    Ok(out)
}

/// The capability [`padded`] adds: on [`PAD_SERVER`] only, with a `one_of` longer than the
/// pairwise path takes, so a set holding it is compared through the prepared path.
pub fn padding() -> Capability {
    Capability::new(PAD_SERVER, "*").with_constraint(
        "x",
        ArgConstraint::OneOf((0..LONG_LIST as i64).map(Value::from).collect()),
    )
}

/// `set` with [`padding`] added.
pub fn padded(set: &CapabilitySet) -> CapabilitySet {
    let mut out = set.clone();
    out.insert(padding());
    out
}

/// Does a capability of `set` have the server [`PAD_SERVER`], which [`padding`] covers?
pub fn uses_pad(set: &CapabilitySet) -> bool {
    set.iter().any(|c| c.server == PAD_SERVER)
}

/// `x.implies(y)` from the pairwise definition, never giving the core a `one_of` of more than
/// one value: a list on the child side implies `y` when each of its values does (an empty
/// list implies everything), and a constraint that is not a list implies a list when no value
/// satisfies it or it implies one of the list's values. That is the definition's own reading
/// of every arm with a list in it (`implies_direct`), and each call left to the core is
/// between two constraints without a list, which the pairwise code answers.
pub fn implies_ref(x: &ArgConstraint, y: &ArgConstraint) -> bool {
    match (x, y) {
        (ArgConstraint::OneOf(xs), _) => xs
            .iter()
            .all(|a| implies_ref(&ArgConstraint::Equals(a.clone()), y)),
        (_, ArgConstraint::OneOf(ys)) => {
            // `x` implies the empty list exactly when no value satisfies `x`.
            x.implies(&ArgConstraint::OneOf(Vec::new()))
                || ys
                    .iter()
                    .any(|b| x.implies(&ArgConstraint::Equals(b.clone())))
        }
        _ => x.implies(y),
    }
}

/// `p.covers_calls(c)` with [`implies_ref`]: the patterns (compared by the core on the two
/// capabilities without constraints, which is pairwise), then every constraint of `p` implied
/// by `c`'s constraint on the same argument.
pub fn covers_calls_ref(p: &Capability, c: &Capability) -> bool {
    Capability::new(&p.server, &p.tool).covers_calls(&Capability::new(&c.server, &c.tool))
        && p.constraints
            .iter()
            .all(|(arg, pc)| c.constraints.get(arg).is_some_and(|cc| implies_ref(cc, pc)))
}

pub fn covers_ref(p: &Capability, c: &Capability) -> bool {
    covers_calls_ref(p, c) && c.limits.narrows(&p.limits)
}

pub fn set_covers_ref(parent: &CapabilitySet, child: &CapabilitySet) -> bool {
    child
        .iter()
        .all(|c| parent.iter().any(|p| covers_ref(p, c)))
}

/// The parent `attenuate` takes for `c`, by index in `parent`'s canonical order: the first
/// that covers `c` with its limits, else the first that covers its calls.
pub fn parent_of_ref(parent: &CapabilitySet, c: &Capability) -> Option<usize> {
    parent
        .iter()
        .position(|p| covers_ref(p, c))
        .or_else(|| parent.iter().position(|p| covers_calls_ref(p, c)))
}

/// `parent.attenuate(requested)` step by step, from its documentation, with nothing spent:
/// per requested capability in canonical order, its parent's index, the request and the
/// clamped capability.
pub fn attenuate_indexed_ref<'r>(
    parent: &CapabilitySet,
    requested: &'r CapabilitySet,
) -> std::result::Result<Vec<(usize, &'r Capability, Capability)>, AttenuationError> {
    if requested.is_empty() {
        return Err(AttenuationError::Empty);
    }
    requested.validate_size()?;
    let parents: Vec<&Capability> = parent.iter().collect();
    let mut out = Vec::new();
    for c in requested.iter() {
        let not_covered = || AttenuationError::NotCovered {
            requested: c.display(),
        };
        let index = parent_of_ref(parent, c).ok_or_else(not_covered)?;
        let mut child = c.clone();
        child.limits = Limits::clamp_to(&c.limits, &parents[index].limits);
        if !covers_ref(parents[index], &child) {
            return Err(not_covered());
        }
        out.push((index, c, child));
    }
    Ok(out)
}

pub fn attenuate_ref(
    parent: &CapabilitySet,
    requested: &CapabilitySet,
) -> std::result::Result<CapabilitySet, AttenuationError> {
    Ok(attenuate_indexed_ref(parent, requested)?
        .into_iter()
        .map(|(_, _, child)| child)
        .collect())
}

/// The indices, in `parent`'s canonical order, of its limited capabilities (limits not empty)
/// that cover the calls of `c`: the grant capabilities over `c` at hop 0 (SR-128).
pub fn limited_over_ref(parent: &CapabilitySet, c: &Capability) -> Vec<usize> {
    parent
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.limits.is_empty() && covers_calls_ref(p, c))
        .map(|(i, _)| i)
        .collect()
}

/// `own` lowered to every one of `parents` at hop 0, kind by kind, written from the rule
/// `Limits::clamp_to_all` documents without calling it, or `None` when one `Limits` cannot
/// carry them (the same kind on different arguments):
///
/// - `calls`: the least of `own`'s and the parents'.
/// - `sum`: `own`'s if it has one, else the first parent's; refused when another (own or
///   parent) is on another argument; the least `max` of all.
/// - `calls_per` and `distinct`, per kind: a parent's is *needed* unless the `calls` above is
///   at most its `max`. With `own`'s: refused when a needed one counts another target
///   (argument and derivation); the least `max` of `own`'s and every parent's on its target.
///   Without: none when nothing is needed; refused when the needed ones count different
///   targets; else the first needed one, with the least `max` of every parent's on its target.
pub fn clamp_to_all_ref(own: &Limits, parents: &[&Limits]) -> Option<Limits> {
    let calls = std::iter::once(own.calls)
        .chain(parents.iter().map(|p| p.calls))
        .flatten()
        .min();
    let sums: Vec<&ArgLimit> = own
        .sum
        .iter()
        .chain(parents.iter().filter_map(|p| p.sum.as_ref()))
        .collect();
    let sum = match sums.first() {
        None => None,
        Some(first) => {
            if sums.iter().any(|s| s.arg != first.arg) {
                return None;
            }
            let mut out = (*first).clone();
            out.max = sums.iter().map(|s| s.max).min().unwrap();
            Some(out)
        }
    };
    let target = |l: &ArgLimit| (l.arg.clone(), l.derive);
    let per_value = |own: &Option<ArgLimit>,
                     of: &dyn Fn(&Limits) -> Option<&ArgLimit>|
     -> Option<Option<ArgLimit>> {
        let all: Vec<&ArgLimit> = parents.iter().filter_map(|p| of(p)).collect();
        let needed: Vec<&ArgLimit> = all
            .iter()
            .copied()
            .filter(|p| !calls.is_some_and(|c| c <= p.max))
            .collect();
        let base = match own {
            Some(o) => o.clone(),
            None => match needed.first() {
                None => return Some(None),
                Some(n) => (*n).clone(),
            },
        };
        if needed.iter().any(|n| target(n) != target(&base)) {
            return None;
        }
        let mut out = base.clone();
        out.max = all
            .iter()
            .filter(|p| target(p) == target(&base))
            .map(|p| p.max)
            .chain([base.max])
            .min()
            .unwrap();
        Some(Some(out))
    };
    let calls_per = per_value(&own.calls_per, &|l: &Limits| l.calls_per.as_ref())?;
    let distinct = per_value(&own.distinct, &|l: &Limits| l.distinct.as_ref())?;
    Some(Limits {
        calls,
        sum,
        calls_per,
        distinct,
    })
}

/// `parent.attenuate_root(requested)` from its documentation (SR-121, SR-128): `attenuate`
/// first; then, per requested capability in canonical order, its capability in the result is
/// the request with its limits lowered to those of every limited grant capability over it
/// ([`limited_over_ref`], [`clamp_to_all_ref`]; `attenuate`'s when there is none), a
/// `LimitConflict` when one capability cannot carry them, and a `LimitSplit` naming the first
/// request under a limited grant capability and the first later one under it whose result
/// differs.
pub fn attenuate_root_ref(
    parent: &CapabilitySet,
    requested: &CapabilitySet,
) -> std::result::Result<CapabilitySet, AttenuationError> {
    let steps = attenuate_indexed_ref(parent, requested)?;
    let parents: Vec<&Capability> = parent.iter().collect();
    let mut first: BTreeMap<usize, (&Capability, Capability)> = BTreeMap::new();
    let mut out = Vec::new();
    for (_, req, child) in steps {
        let over = limited_over_ref(parent, req);
        let child = if over.is_empty() {
            child
        } else {
            let limits: Vec<&Limits> = over.iter().map(|&i| &parents[i].limits).collect();
            let Some(combined) = clamp_to_all_ref(&req.limits, &limits) else {
                return Err(AttenuationError::LimitConflict {
                    requested: req.display(),
                });
            };
            Capability {
                limits: combined,
                ..req.clone()
            }
        };
        for i in over {
            match first.get(&i) {
                Some((req0, child0)) if *child0 != child => {
                    return Err(AttenuationError::LimitSplit {
                        first: req0.display(),
                        second: req.display(),
                    })
                }
                Some(_) => {}
                None => {
                    first.insert(i, (req, child.clone()));
                }
            }
        }
        out.push(child);
    }
    Ok(out.into_iter().collect())
}
