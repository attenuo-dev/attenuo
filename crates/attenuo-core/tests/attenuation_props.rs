//! Property tests for the attenuation invariants: capabilities only narrow along a chain.
//!
//! These check the *soundness* direction (coverage never lets a child permit something the
//! parent does not), plus the structural guarantees of `DelegationChain`.

use std::collections::BTreeMap;

use attenuo_core::{
    AgentId, ArgConstraint, ArgLimit, AttenuationError, Capability, CapabilitySet, DelegationChain,
    LeaseId, Limits, OriginatingUser, ToolCall,
};
use proptest::prelude::*;
use serde_json::{json, Value};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const MAX_DEPTH: usize = 8;
const NAMES: &[&str] = &["a", "ab", "abc", "b", "*", "a*", "ab*", "b*"];
const ARGS: &[&str] = &["x", "y"];

fn t0() -> OffsetDateTime {
    datetime!(2026-10-22 21:00 UTC)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------- strategies

fn small_string() -> impl Strategy<Value = String> {
    "[ab]{0,3}"
}

fn small_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        small_string().prop_map(Value::String),
        (0i64..3).prop_map(|n| json!(n)),
    ]
}

fn arg_constraint() -> impl Strategy<Value = ArgConstraint> {
    prop_oneof![
        small_value().prop_map(ArgConstraint::Equals),
        prop::collection::vec(small_value(), 0..4).prop_map(ArgConstraint::OneOf),
        "[ab]{0,2}".prop_map(ArgConstraint::Prefix),
    ]
}

/// Limits over a small range so that equal and nested figures are common. `sum` counts `n`,
/// which no constraint names, so every generated capability has well-formed limits.
fn limits() -> impl Strategy<Value = Limits> {
    (
        prop::option::of(0u64..4),
        prop::option::of(0u64..4),
        prop::option::of((prop::sample::select(ARGS), 0u64..4)),
    )
        .prop_map(|(calls, sum, per)| Limits {
            calls,
            sum: sum.map(|max| ArgLimit::new("n", max)),
            calls_per: per.map(|(arg, max)| ArgLimit::new(arg, max)),
        })
}

fn name() -> impl Strategy<Value = String> {
    prop::sample::select(NAMES).prop_map(str::to_owned)
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
        for n in 0..3 {
            pool.push(json!(n));
        }
        pool.push(Value::Null);
        pool.push(json!(true));
        pool
    })
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
                    prop_assert_eq!(got, requested);
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
