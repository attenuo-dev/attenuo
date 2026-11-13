//! Property tests for the attenuation invariants: capabilities only narrow along a chain.
//!
//! These check the *soundness* direction (coverage never lets a child permit something the
//! parent does not), plus the structural guarantees of `DelegationChain`.

use std::collections::BTreeMap;

use attenuo_core::{
    AgentId, ArgConstraint, ArgLimit, AttenuationError, Capability, CapabilitySet, DelegationChain,
    Derive, LeaseId, Limits, OriginatingUser, ToolCall,
};
use proptest::prelude::*;
use serde_json::{json, Value};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

mod proptest_seed;
mod strategies;
use proptest_seed::proptest_config;
use strategies::{
    arg_constraint, name, path_constraint, path_string, range, related_path_constraints,
    small_value,
};

const MAX_DEPTH: usize = 8;
const ARGS: &[&str] = &["x", "y"];

fn t0() -> OffsetDateTime {
    datetime!(2026-10-22 21:00 UTC)
}

/// 512 cases, or `PROPTEST_CASES` when set (for longer soak runs). `range()` rejects about
/// one draw in three and some properties `prop_assume!` their way to a case, so both reject
/// allowances grow with the case count.
fn config() -> ProptestConfig {
    let config = proptest_config(512);
    ProptestConfig {
        max_local_rejects: config.cases.saturating_mul(4).max(65_536),
        max_global_rejects: config.cases.saturating_mul(4).max(1024),
        ..config
    }
}

// ---------------------------------------------------------------- strategies

/// Limits over a small range so that equal and nested figures are common. `sum` counts `n`,
/// which no constraint names, so every generated capability has well-formed limits.
fn limits() -> impl Strategy<Value = Limits> {
    (
        prop::option::of(0u64..4),
        prop::option::of(0u64..4),
        prop::option::of((prop::sample::select(ARGS), 0u64..4)),
        prop::option::of((prop::sample::select(ARGS), 0u64..4, any::<bool>())),
    )
        .prop_map(|(calls, sum, per, distinct)| Limits {
            calls,
            sum: sum.map(|max| ArgLimit::new("n", max)),
            calls_per: per.map(|(arg, max)| ArgLimit::new(arg, max)),
            distinct: distinct.map(|(arg, max, host)| {
                let l = ArgLimit::new(arg, max);
                if host {
                    l.derived(Derive::Host)
                } else {
                    l
                }
            }),
        })
}

fn capability() -> impl Strategy<Value = Capability> {
    (
        name(),
        name(),
        prop::collection::btree_map(
            prop::sample::select(ARGS).prop_map(str::to_owned),
            arg_constraint(),
            0..=2,
        ),
        any::<bool>(),
        prop_oneof![2 => Just(Limits::default()), 1 => limits()],
    )
        .prop_map(|(server, tool, mut constraints, with_z, limits)| {
            // up to 3 constraints: a third on an arg outside the shared pool
            if with_z {
                constraints.insert("z".into(), ArgConstraint::Prefix("a".into()));
            }
            Capability {
                server,
                tool,
                constraints,
                limits,
            }
        })
}

fn capability_set() -> impl Strategy<Value = CapabilitySet> {
    prop::collection::vec(capability(), 1..=4).prop_map(CapabilitySet::from_iter)
}

fn tool_call() -> impl Strategy<Value = ToolCall> {
    (
        name(),
        name(),
        prop::collection::btree_map(
            prop::sample::select(&["x", "y", "z"][..]).prop_map(str::to_owned),
            small_value(),
            0..=3,
        ),
    )
        .prop_map(|(server, tool, arguments)| ToolCall {
            server,
            tool,
            arguments,
            session_id: None,
            dpop_bound: false,
        })
}

fn user() -> OriginatingUser {
    OriginatingUser {
        subject: "user:p".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: datetime!(2026-10-22 20:00 UTC),
        attributes: BTreeMap::new(),
    }
}

#[derive(Debug, Clone)]
struct HopSpec {
    random: CapabilitySet,
    use_random: bool,
    mask: Vec<bool>,
    narrow: bool,
    ttl_mins: i64,
    dt_secs: i64,
}

fn hop_spec() -> impl Strategy<Value = HopSpec> {
    (
        capability_set(),
        any::<bool>(),
        prop::collection::vec(any::<bool>(), 4),
        any::<bool>(),
        1i64..180,
        0i64..600,
    )
        .prop_map(
            |(random, use_random, mask, narrow, ttl_mins, dt_secs)| HopSpec {
                random,
                use_random,
                mask,
                narrow,
                ttl_mins,
                dt_secs,
            },
        )
}

fn subset_of(parent: &CapabilitySet, mask: &[bool]) -> Vec<Capability> {
    let mut picked: Vec<Capability> = parent
        .iter()
        .enumerate()
        .filter(|(j, _)| mask[j % mask.len()])
        .map(|(_, c)| c.clone())
        .collect();
    if picked.is_empty() {
        picked.push(parent.iter().next().expect("non-empty").clone());
    }
    picked
}

/// A chain of 1-5 hops built only through `root` + `extend`. Hops whose request is rejected
/// (random requests often are) are skipped, so the result is always a valid chain.
fn chain() -> impl Strategy<Value = DelegationChain> {
    (
        capability_set(),
        10i64..240,
        prop::collection::vec(hop_spec(), 0..5),
    )
        .prop_map(|(root_caps, ttl, specs)| {
            let mut chain = DelegationChain::root(
                user(),
                AgentId::new("agent0"),
                root_caps,
                t0(),
                Duration::minutes(ttl),
                LeaseId::new("l0"),
            )
            .expect("non-empty root");
            let mut now = t0();
            for (i, spec) in specs.into_iter().enumerate() {
                if chain.depth() >= 5 {
                    break;
                }
                now += Duration::seconds(spec.dt_secs);
                let parent = &chain.hops.last().unwrap().capabilities;
                let requested = if spec.use_random {
                    spec.random
                } else {
                    let mut picked = subset_of(parent, &spec.mask);
                    if spec.narrow {
                        picked = picked
                            .into_iter()
                            .map(|c| c.with_constraint("w", ArgConstraint::Equals(json!(1))))
                            .collect();
                    }
                    CapabilitySet::from_iter(picked)
                };
                if let Ok(next) = chain.extend(
                    AgentId::new(format!("agent{}", i + 1)),
                    requested,
                    now,
                    Duration::minutes(spec.ttl_mins),
                    LeaseId::new(format!("l{}", i + 1)),
                    MAX_DEPTH,
                ) {
                    chain = next;
                }
            }
            chain
        })
}

/// Values every constraint test is evaluated on, plus generated extras.
fn value_pool() -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(small_value(), 0..12).prop_map(|mut pool| {
        for s in ["", "a", "b", "aa", "ab", "ba", "bb", "abb", "aab", "abab"] {
            pool.push(json!(s));
        }
        for s in [
            "/",
            "/a",
            "/a/",
            "/a/b",
            "/a/b/",
            "/ab",
            "/a-",
            "a/",
            "a/b",
            "/a/..",
            "/a/../b",
            "/a/./b",
            "/a//b",
            "/a\\b",
            "/a/%2e%2e",
            "/a%2Fb",
        ] {
            pool.push(json!(s));
        }
        for n in -2..6 {
            pool.push(json!(n));
        }
        for f in [1.0, 2.0, 0.5, 2.5] {
            pool.push(json!(f));
        }
        pool.push(json!("1"));
        pool.push(Value::Null);
        pool.push(json!(true));
        pool
    })
}

/// Is `got` what `attenuate` may return for a covered `requested`? It is `requested`, except
/// that a `calls_per` or `distinct` may have its `max` lowered on the same argument and
/// derivation (to the parent's figure, by `Limits::clamp_to`). `covers` accepts such a request
/// because its own `calls` is no larger than the parent's `max`, and that `calls` must also be
/// no larger than the lowered `max`: the per-value bound in force, `min(calls, max)`, is the
/// same before and after. Every other field must be equal.
fn effect_free_clamp(requested: &Capability, got: &Capability) -> bool {
    let (r, g) = (&requested.limits, &got.limits);
    let per_value = |r: &Option<ArgLimit>, g: &Option<ArgLimit>| match (r, g) {
        (Some(r), Some(g)) if r != g => {
            r.arg == g.arg
                && r.derive == g.derive
                && g.max < r.max
                && requested.limits.calls.is_some_and(|n| n <= g.max)
        }
        _ => r == g,
    };
    requested.server == got.server
        && requested.tool == got.tool
        && requested.constraints == got.constraints
        && r.calls == g.calls
        && r.sum == g.sum
        && per_value(&r.calls_per, &g.calls_per)
        && per_value(&r.distinct, &g.distinct)
}

fn last_expiry(c: &DelegationChain) -> OffsetDateTime {
    c.hops.last().unwrap().expires_at
}

// ---------------------------------------------------------------- properties

proptest! {
    #![proptest_config(config())]

    /// 1. covers is sound with respect to permits.
    #[test]
    fn coverage_is_sound_for_capabilities(
        parent in capability(),
        child in capability(),
        calls in prop::collection::vec(tool_call(), 1..24),
    ) {
        if parent.covers(&child) {
            for call in &calls {
                prop_assert!(!child.permits(call) || parent.permits(call),
                    "child permits {call:?} but parent does not");
            }
        }
    }

    #[test]
    fn coverage_is_sound_for_sets(
        parent in capability_set(),
        child in capability_set(),
        calls in prop::collection::vec(tool_call(), 1..24),
    ) {
        if parent.covers(&child) {
            for call in &calls {
                prop_assert!(!child.permits(call) || parent.permits(call),
                    "child permits {call:?} but parent does not");
            }
        }
    }

    /// Same, but biased towards covered pairs by deriving the child from the parent.
    #[test]
    fn coverage_is_sound_for_narrowed_children(
        parent in capability(),
        extra in arg_constraint(),
        tool in name(),
        calls in prop::collection::vec(tool_call(), 1..24),
    ) {
        let mut child = parent.clone();
        child.tool = tool;
        child.constraints.insert("x".into(), extra);
        if parent.covers(&child) {
            for call in &calls {
                prop_assert!(!child.permits(call) || parent.permits(call));
            }
        }
    }

    /// 2. implies is sound with respect to satisfied_by.
    #[test]
    fn implication_is_sound(a in arg_constraint(), b in arg_constraint(), pool in value_pool()) {
        if a.implies(&b) {
            for v in &pool {
                prop_assert!(!a.satisfied_by(v) || b.satisfied_by(v),
                    "{v} satisfies {a:?} but not {b:?}");
            }
        }
    }

    /// 2b. The same for string constraints over paths, with each constraint's own string and
    /// its continuations in the pool: a path prefix admits its base, so a wrong `implies`
    /// against a string prefix or another path prefix shows on the base or just below it.
    #[test]
    fn path_implication_is_sound(
        (a, b) in prop_oneof![
            (path_constraint(), path_constraint()),
            related_path_constraints(),
        ],
        extra in prop::collection::vec(path_string(), 0..12),
    ) {
        if a.implies(&b) {
            let mut pool: Vec<String> = extra;
            for c in [&a, &b] {
                if let ArgConstraint::Prefix(p) | ArgConstraint::PathPrefix(p) = c {
                    for tail in ["", "/", "a", "/a", "/a/", "-", "/..", "../a"] {
                        pool.push(format!("{p}{tail}"));
                    }
                    pool.push(p.trim_end_matches('/').to_string());
                }
            }
            for v in pool.iter().map(|s| json!(s)) {
                prop_assert!(!a.satisfied_by(&v) || b.satisfied_by(&v),
                    "{v} satisfies {a:?} but not {b:?}");
            }
        }
    }

    /// 2c. A path prefix is always within the string prefix of the same text, and a string
    /// prefix is never within a path prefix.
    #[test]
    fn path_prefix_narrows_the_string_prefix_of_its_text(p in path_string(), q in path_string()) {
        prop_assert!(ArgConstraint::PathPrefix(p.clone()).implies(&ArgConstraint::Prefix(p.clone())));
        prop_assert!(!ArgConstraint::Prefix(q).implies(&ArgConstraint::PathPrefix(p)));
    }

    /// 3. Reflexivity.
    #[test]
    fn covers_is_reflexive_for_capabilities(c in capability()) {
        prop_assert!(c.covers(&c), "{c:?} does not cover itself");
    }

    #[test]
    fn covers_is_reflexive_for_sets(s in capability_set()) {
        prop_assert!(s.covers(&s), "{s:?} does not cover itself");
    }

    #[test]
    fn constraint_implies_is_reflexive(a in arg_constraint()) {
        prop_assert!(a.implies(&a), "{a:?} does not imply itself");
    }

    /// 3. Transitivity.
    #[test]
    fn covers_is_transitive_for_capabilities(
        a in capability(), b in capability(), c in capability(),
    ) {
        if a.covers(&b) && b.covers(&c) {
            prop_assert!(a.covers(&c));
        }
    }

    #[test]
    fn covers_is_transitive_for_sets(
        a in capability_set(), b in capability_set(), c in capability_set(),
    ) {
        if a.covers(&b) && b.covers(&c) {
            prop_assert!(a.covers(&c));
        }
    }

    #[test]
    fn covers_is_transitive_along_chains(chain in chain()) {
        for w in chain.hops.windows(3) {
            prop_assert!(w[0].capabilities.covers(&w[2].capabilities));
        }
    }

    /// Ranges: tightening a bound narrows (the result implies the original and the original
    /// covers a capability carrying it); loosening a bound widens (refused), and a value just
    /// past the original bound is the witness.
    #[test]
    fn range_tightening_narrows_and_loosening_widens(
        r in range(),
        by in 1i64..3,
        side in any::<bool>(),
    ) {
        let ArgConstraint::Range { min, max } = r.clone() else { unreachable!() };
        let parent = Capability::new("bank", "send").with_constraint("amount", r.clone());
        // Tighten one side: raise min or lower max, if the range stays non-empty.
        let tighter = if side {
            ArgConstraint::range(Some(min.unwrap_or(-10) + by), max)
        } else {
            ArgConstraint::range(min, Some(max.unwrap_or(10) - by))
        };
        if let Ok(t) = tighter {
            prop_assert!(t.implies(&r), "{t:?} should imply {r:?}");
            let child = Capability::new("bank", "send").with_constraint("amount", t);
            prop_assert!(parent.covers(&child));
        }
        // Loosen one side that has a bound: the value just past it is admitted by the child,
        // refused by the parent, and the child is not covered.
        let (looser, witness) = match (side, min, max) {
            (true, Some(lo), _) | (false, Some(lo), None) => {
                (ArgConstraint::range(Some(lo - by), max).unwrap(), lo - 1)
            }
            (_, _, Some(hi)) => (ArgConstraint::range(min, Some(hi + by)).unwrap(), hi + 1),
            (_, None, None) => unreachable!("a checked range has a bound"),
        };
        prop_assert!(!looser.implies(&r), "{looser:?} must not imply {r:?}");
        prop_assert!(looser.satisfied_by(&json!(witness)) && !r.satisfied_by(&json!(witness)));
        let child = Capability::new("bank", "send").with_constraint("amount", looser);
        let set = CapabilitySet::from_iter([parent]);
        prop_assert!(matches!(
            set.attenuate(&CapabilitySet::from_iter([child])),
            Err(AttenuationError::NotCovered { .. })
        ), "a loosened range must be refused");
    }

    /// Range implication is exact, not only sound: `a` implies `b` exactly when every integer
    /// `a` admits is admitted by `b`.
    #[test]
    fn range_implication_matches_integer_containment(a in range(), b in range()) {
        let in_a = |n: i64| a.satisfied_by(&json!(n));
        let in_b = |n: i64| b.satisfied_by(&json!(n));
        // Bounds are in -1..4, so the window -3..=6 shows every difference between finite
        // bounds; a missing bound reaches the end of i64, which the two extremes check.
        let window_subset = (-3i64..=6).all(|n| !in_a(n) || in_b(n));
        let ends_subset = [i64::MIN, i64::MAX].iter().all(|&n| !in_a(n) || in_b(n));
        prop_assert_eq!(a.implies(&b), window_subset && ends_subset, "{:?} vs {:?}", a, b);
    }

    /// 4. Attenuation never widens along a chain built by `extend`.
    #[test]
    fn attenuation_never_widens(
        chain in chain(),
        calls in prop::collection::vec(tool_call(), 1..24),
    ) {
        for i in 1..chain.hops.len() {
            let (parent, hop) = (&chain.hops[i - 1], &chain.hops[i]);
            prop_assert!(hop.expires_at <= parent.expires_at);
            for call in &calls {
                prop_assert!(
                    !hop.capabilities.permits(call) || parent.capabilities.permits(call),
                    "hop {i} permits {call:?} but hop {} does not", i - 1
                );
            }
        }
    }

    /// 5a. Every chain produced by root/extend validates at any time before the last expiry.
    #[test]
    fn built_chains_validate(chain in chain(), frac in 0.0f64..1.0) {
        let span = (last_expiry(&chain) - t0()).whole_seconds();
        let now = t0() + Duration::seconds((span as f64 * frac) as i64);
        prop_assert!(now < last_expiry(&chain));
        prop_assert_eq!(chain.validate_at(now, MAX_DEPTH), Ok(()));
    }

    /// 5b. Replacing a hop's capabilities with a set the parent does not cover is rejected.
    #[test]
    fn widened_hop_is_rejected(
        chain in chain(),
        which in any::<prop::sample::Index>(),
        replacement in capability_set(),
    ) {
        prop_assume!(chain.hops.len() > 1);
        let i = 1 + which.index(chain.hops.len() - 1);
        let mut tampered = chain.clone();
        let parent_covers = tampered.hops[i - 1].capabilities.covers(&replacement);
        tampered.hops[i].capabilities = replacement;
        let result = tampered.validate_at(t0(), MAX_DEPTH);
        if !parent_covers {
            prop_assert!(result.is_err(), "uncovered replacement at hop {i} was accepted");
        } else {
            // a covered, non-empty replacement keeps the chain valid at the hop itself,
            // but a later hop may no longer be covered by it
            prop_assert!(i + 1 < tampered.hops.len() || result.is_ok());
        }
    }

    /// 5c. Moving a hop's expiry past its parent's is rejected.
    #[test]
    fn extended_expiry_is_rejected(
        chain in chain(),
        which in any::<prop::sample::Index>(),
        extra_secs in 1i64..100_000,
    ) {
        prop_assume!(chain.hops.len() > 1);
        let i = 1 + which.index(chain.hops.len() - 1);
        let mut tampered = chain.clone();
        tampered.hops[i].expires_at =
            tampered.hops[i - 1].expires_at + Duration::seconds(extra_secs);
        prop_assert!(tampered.validate_at(t0(), MAX_DEPTH).is_err());
    }

    /// 5d (SR-16). Copying one hop's lease or agent id onto another hop is rejected, and so is
    /// moving a hop's `issued_at` before its parent's.
    #[test]
    fn repeated_ids_and_reordered_issuance_are_rejected(
        chain in chain(),
        a in any::<prop::sample::Index>(),
        b in any::<prop::sample::Index>(),
        back_secs in 1i64..100_000,
    ) {
        prop_assume!(chain.hops.len() > 1);
        let n = chain.hops.len();
        let (i, j) = (a.index(n), b.index(n));
        prop_assume!(i != j);
        let mut lease = chain.clone();
        lease.hops[j].lease = chain.hops[i].lease.clone();
        prop_assert!(lease.validate_at(t0(), MAX_DEPTH).is_err());
        let mut agent = chain.clone();
        agent.hops[j].agent = chain.hops[i].agent.clone();
        prop_assert!(agent.validate_at(t0(), MAX_DEPTH).is_err());
        let k = 1 + a.index(n - 1);
        let mut early = chain.clone();
        early.hops[k].issued_at = chain.hops[k - 1].issued_at - Duration::seconds(back_secs);
        prop_assert!(early.validate_at(t0(), MAX_DEPTH).is_err());
    }

    /// 6. attenuate returns a covered request unchanged, and anything else it returns differs
    /// from the request only in limits clamped to the parent's (ADR-0010) and is covered.
    #[test]
    fn attenuate_iff_covered_and_nonempty(
        parent in capability_set(),
        requested in capability_set(),
    ) {
        let covered = parent.covers(&requested) && !requested.is_empty();
        match parent.attenuate(&requested) {
            Ok(got) => {
                prop_assert!(parent.covers(&got));
                if covered {
                    // A covered request comes back as it was, up to the one clamp that
                    // changes no figure in effect (see `effect_free_clamp`).
                    prop_assert!(got.len() <= requested.len());
                    for c in requested.iter() {
                        prop_assert!(got.iter().any(|g| effect_free_clamp(c, g)),
                            "{c:?} has no counterpart in {got:?}");
                    }
                    for g in got.iter() {
                        prop_assert!(requested.iter().any(|c| effect_free_clamp(c, g)),
                            "{g:?} was not requested");
                    }
                } else {
                    // Only limits changed: the calls the request names are all still there.
                    for c in requested.iter() {
                        prop_assert!(got.iter().any(|g| g.covers_calls(c) && c.covers_calls(g)));
                    }
                }
            }
            Err(_) => prop_assert!(!covered),
        }
    }

    /// ADR-0010: when a parent covers a child, every limit of the parent appears in the child
    /// with a max no larger (or, for `calls_per`, is implied by the child's `calls`).
    #[test]
    fn child_limit_never_exceeds_parent_limit(parent in capability(), child in capability()) {
        if parent.covers(&child) {
            let (p, c) = (&parent.limits, &child.limits);
            if let Some(pm) = p.calls {
                prop_assert!(c.calls.is_some_and(|cm| cm <= pm));
            }
            if let Some(ps) = &p.sum {
                prop_assert!(c.sum.as_ref().is_some_and(|cs| cs.arg == ps.arg && cs.max <= ps.max));
            }
            if let Some(pp) = &p.calls_per {
                let same = c.calls_per.as_ref().is_some_and(|cp| cp.arg == pp.arg && cp.max <= pp.max);
                prop_assert!(same || c.calls.is_some_and(|cm| cm <= pp.max));
            }
            if let Some(pd) = &p.distinct {
                let same = c.distinct.as_ref().is_some_and(|cd| {
                    cd.arg == pd.arg && cd.derive == pd.derive && cd.max <= pd.max
                });
                prop_assert!(same || c.calls.is_some_and(|cm| cm <= pd.max));
            }
        }
    }

    /// ADR-0010: clamping at exchange never yields a figure above what the parent has left.
    #[test]
    fn exchange_clamps_child_budget_to_parent_remaining(
        parent in capability(),
        requested in capability_set(),
        left in 0u64..4,
    ) {
        let parent_set = CapabilitySet::from_iter([parent.clone()]);
        if let Ok(got) = parent_set.attenuate_with(&requested, |i, _, max| {
            assert_eq!(i, 0);
            Some(left.min(max))
        }) {
            prop_assert!(parent_set.covers(&got));
            for g in got.iter() {
                if parent.limits.calls.is_some() {
                    prop_assert!(g.limits.calls.is_some_and(|c| c <= left));
                }
                if parent.limits.sum.is_some() {
                    prop_assert!(g.limits.sum.as_ref().is_some_and(|s| s.max <= left));
                }
            }
        }
    }

    #[test]
    fn attenuate_empty_request_fails(parent in capability_set()) {
        prop_assert_eq!(
            parent.attenuate(&CapabilitySet::new()),
            Err(AttenuationError::Empty)
        );
    }

    /// Liveness companion to the above: a subset of the parent is always accepted.
    #[test]
    fn attenuate_subset_of_parent_succeeds(
        parent in capability_set(),
        mask in prop::collection::vec(any::<bool>(), 4),
    ) {
        let requested = CapabilitySet::from_iter(subset_of(&parent, &mask));
        prop_assert!(parent.attenuate(&requested).is_ok());
    }

    /// 7. Serde round trip preserves the digest (and the chain).
    #[test]
    fn digest_survives_serde_round_trip(chain in chain()) {
        let s = serde_json::to_string(&chain).unwrap();
        let back: DelegationChain = serde_json::from_str(&s).unwrap();
        prop_assert_eq!(back.digest(), chain.digest());
        prop_assert_eq!(back, chain);
    }
}

// ---------------------------------------------------------------- regressions

/// The case `attenuate_iff_covered_and_nonempty` once failed on: a request whose `calls: 0`
/// meets the parent's `calls_per`/`distinct` of 0 (RFC 0001 section 3, rule 3) while its own
/// figure on the same argument is 1. It is covered, so `attenuate` accepts it, and lowers the
/// child's figure to the parent's. That changes nothing in effect (no call is allowed either
/// way), so the oracle must accept the lowered result and still refuse any other difference.
#[test]
fn covered_request_with_calls_below_parent_per_value_limit_is_clamped_without_effect() {
    for (parent_limits, requested_limits, expected_limits) in [
        (
            Limits::default().with_calls_per("y", 0),
            Limits::default().with_calls(0).with_calls_per("y", 1),
            Limits::default().with_calls(0).with_calls_per("y", 0),
        ),
        (
            Limits::default().with_distinct("y", 0),
            Limits::default().with_calls(0).with_distinct("y", 1),
            Limits::default().with_calls(0).with_distinct("y", 0),
        ),
    ] {
        let parent = CapabilitySet::from_iter([Capability {
            limits: parent_limits,
            ..Capability::new("*", "*")
        }]);
        let requested_cap = Capability {
            limits: requested_limits,
            ..Capability::new("a", "a")
        };
        let requested = CapabilitySet::from_iter([requested_cap.clone()]);
        assert!(parent.covers(&requested));
        let got = parent.attenuate(&requested).expect("covered, so accepted");
        let got_cap = got.iter().next().unwrap().clone();
        assert_eq!(got_cap.limits, expected_limits);
        assert!(effect_free_clamp(&requested_cap, &got_cap));

        // The oracle stays strict: a lowered figure the request's `calls` does not bound
        // (`calls: 1` with the figure going from 1 to 0 refuses a call that was allowed), a
        // changed `calls`, or a raised figure are all differences it refuses.
        let (mut loose, mut loose_got) = (requested_cap.clone(), got_cap.clone());
        loose.limits.calls = Some(1);
        loose_got.limits.calls = Some(1);
        assert!(!effect_free_clamp(&loose, &loose_got));
        let mut raised = got_cap.clone();
        raised.limits.calls = None;
        assert!(!effect_free_clamp(&requested_cap, &raised));
        assert!(!effect_free_clamp(&got_cap, &requested_cap));
    }
}
