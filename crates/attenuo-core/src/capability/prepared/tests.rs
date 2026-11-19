//! The prepared implication against the pairwise definition (SR-123): every answer of
//! [`ArgConstraint::implies`], [`Capability::covers_calls`], [`CapabilitySet::covers`] and
//! attenuation is compared with the implementation from before the fix, kept as
//! `implies_direct`, `covers_calls_direct`, `covers_direct` and `attenuate_indexed_direct`.
//! The values are drawn so that the cases where a canonical key could part from
//! [`value_eq`] are common: `1`, `1.0`, `1e0` and `-0.0`; integers beyond 2^53 and the floats
//! nearest them; strings that differ only in Unicode normalisation, escapes or a code point
//! above the BMP; strings that spell numbers; nested arrays and objects whose members come in
//! either order.

use proptest::prelude::*;
use serde_json::{json, Map, Value};

#[path = "../../../tests/proptest_seed/mod.rs"]
#[allow(dead_code, unreachable_pub)]
mod proptest_seed;

use super::super::{ArgConstraint, Capability, CapabilitySet, LimitKind};
use super::{Prepared, PreparedCap};

/// The prepared implication alone, whatever the sizes ([`ArgConstraint::implies`] compares
/// small constraints directly).
fn implies(a: &ArgConstraint, b: &ArgConstraint) -> bool {
    Prepared::new(a).implies(&Prepared::new(b))
}
use crate::jcs::{to_vec, value_eq, value_key};
use crate::limits::{ArgLimit, Limits};

/// Numbers that are equal under another spelling, or nearly equal: `1` and `1.0` (and `1e0`,
/// which parses to the same float), both zeros, `10^16` and `1e16` (the same canonical form),
/// `2^53 + 1` and the float `2^53` (different), the ends of both integer types.
fn number() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => (-2i64..4).prop_map(|n| json!(n)),
        2 => prop::sample::select(&[1.0f64, -0.0, 0.0, 0.5, 2.0, 1e16, 9_007_199_254_740_992.0,
            1e21, 1e-7, 922_337_203_685_477.0, -1.0][..]).prop_map(|f| json!(f)),
        2 => prop::sample::select(&[10_000_000_000_000_000u64, 9_007_199_254_740_993,
            9_007_199_254_740_992, u64::MAX, 922_337_203_685_477, 922_337_203_685_478][..])
            .prop_map(|n| json!(n)),
        1 => prop::sample::select(&[i64::MIN, -9_007_199_254_740_993][..]).prop_map(|n| json!(n)),
        1 => prop::sample::select(&["1", "1.0", "1e0", "-0", "1E+0"][..])
            .prop_map(|s| serde_json::from_str::<Value>(s).unwrap()),
    ]
}

/// Strings that collide in ways a key could get wrong: NFC and NFD forms of `é`, a character
/// above the BMP (which sorts differently as UTF-16 than as UTF-8), escapes, a digit, paths.
fn string() -> impl Strategy<Value = String> {
    let piece = prop::sample::select(
        &[
            "",
            "a",
            "b",
            "/",
            "/w",
            "w",
            "1",
            "\u{e9}",
            "e\u{301}",
            "\u{1F600}",
            "\u{ffff}",
            "\"",
            "\\",
            "\n",
            "\u{0}",
            "..",
            "%2e",
        ][..],
    );
    prop::collection::vec(piece, 0..3).prop_map(|p| p.concat())
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => number(),
        3 => string().prop_map(Value::String),
        1 => Just(Value::Null),
        1 => any::<bool>().prop_map(Value::Bool),
    ]
}

/// A JSON value: leaves, and arrays and objects of up to three members, nested, an object's
/// members in the order drawn (the map keeps insertion order), so equal objects with members
/// in another order are common.
fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(3, 12, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..3).prop_map(Value::Array),
            (
                prop::collection::vec((string(), inner), 0..3),
                any::<bool>()
            )
                .prop_map(|(members, reverse)| {
                    let mut members = members;
                    if reverse {
                        members.reverse();
                    }
                    Value::Object(members.into_iter().collect::<Map<String, Value>>())
                }),
        ]
    })
}

/// A path-like string, for `prefix` and `path_prefix` on either side.
fn path() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(&["/", "/", "w", "a", "b", "ab", ".", "..", "%2e", "\\", "-"][..]),
        0..5,
    )
    .prop_map(|parts| parts.concat())
}

fn list(item: BoxedStrategy<Value>) -> impl Strategy<Value = Vec<Value>> {
    prop::collection::vec(item, 0..6)
}

/// A constraint whose values come from `item`, of every kind, ranges unchecked (so inverted
/// and unbounded ones are drawn) and `path_prefix` unchecked (so malformed bases are drawn).
fn constraint_over(item: BoxedStrategy<Value>) -> impl Strategy<Value = ArgConstraint> {
    let bound = prop_oneof![
        3 => (-2i64..4).prop_map(Some),
        1 => Just(None),
        1 => prop::sample::select(&[922_337_203_685_477i64, 922_337_203_685_478,
            10_000_000_000_000_000, i64::MIN, i64::MAX][..]).prop_map(Some),
    ];
    prop_oneof![
        3 => item.clone().prop_map(ArgConstraint::Equals),
        5 => list(item.clone()).prop_map(ArgConstraint::OneOf),
        1 => string().prop_map(ArgConstraint::Prefix),
        1 => path().prop_map(ArgConstraint::Prefix),
        2 => path().prop_map(ArgConstraint::PathPrefix),
        // A prefix or a base taken from the pool, so that it often admits the other side.
        2 => (item.clone(), any::<bool>(), 0usize..3).prop_map(|(v, path, cut)| {
            // The pool's string, or that string without its last `cut` characters.
            let full = v.as_str().unwrap_or("/w");
            let keep = full.chars().count().saturating_sub(cut);
            let s: String = full.chars().take(keep).collect();
            if path { ArgConstraint::PathPrefix(s) } else { ArgConstraint::Prefix(s) }
        }),
        2 => (bound.clone(), bound).prop_map(|(min, max)| ArgConstraint::Range { min, max }),
    ]
}

/// Values of every shape, or only paths, or only integers: the last two make `one_of`
/// lists that a `path_prefix` or a `range` can admit whole, so those arms get both answers.
fn item() -> BoxedStrategy<Value> {
    prop_oneof![
        2 => value(),
        1 => path().prop_map(Value::String),
        1 => prop_oneof![3 => (-2i64..4).prop_map(|n| json!(n)), 1 => number()],
    ]
    .boxed()
}

fn constraint() -> impl Strategy<Value = ArgConstraint> {
    constraint_over(item())
}

/// Two constraints over one pool of values, so that the child's values are often all, or all
/// but one, in the parent's list.
fn related() -> impl Strategy<Value = (ArgConstraint, ArgConstraint)> {
    prop::collection::vec(item(), 1..6).prop_flat_map(|pool| {
        let pick = prop::sample::select(pool).boxed();
        (constraint_over(pick.clone()), constraint_over(pick))
    })
}

fn config() -> ProptestConfig {
    proptest_seed::proptest_config(4096)
}

const ARGS: &[&str] = &["x", "y"];

fn limits() -> impl Strategy<Value = Limits> {
    (prop::option::of(0u64..3), prop::option::of(0u64..3)).prop_map(|(calls, sum)| Limits {
        calls,
        sum: sum.map(|max| ArgLimit::new("n", max)),
        ..Limits::default()
    })
}

fn capability(pool: Vec<Value>) -> impl Strategy<Value = Capability> {
    let pick = prop::sample::select(pool).boxed();
    (
        prop::sample::select(&["s", "*", "s*"][..]),
        prop::sample::select(&["t", "*", "t*", "u"][..]),
        prop::collection::btree_map(
            prop::sample::select(ARGS).prop_map(str::to_owned),
            constraint_over(pick),
            0..=2,
        ),
        prop_oneof![2 => Just(Limits::default()), 1 => limits()],
    )
        .prop_map(|(server, tool, constraints, limits)| Capability {
            server: server.into(),
            tool: tool.into(),
            constraints,
            limits,
        })
}

/// A parent and a requested set over one pool of values.
fn sets() -> impl Strategy<Value = (CapabilitySet, CapabilitySet)> {
    prop::collection::vec(item(), 1..5).prop_flat_map(|pool| {
        let set = |pool: Vec<Value>| {
            prop::collection::vec(capability(pool), 0..5).prop_map(CapabilitySet::from_iter)
        };
        (set(pool.clone()), set(pool))
    })
}

proptest! {
    #![proptest_config(config())]

    /// A key is the value's canonical encoding, and keys are equal exactly when values are.
    #[test]
    fn value_key_is_value_eq(a in value(), b in value()) {
        prop_assert_eq!(value_key(&a), to_vec(&a).unwrap());
        prop_assert_eq!(value_key(&a) == value_key(&b), value_eq(&a, &b), "{} vs {}", a, b);
        prop_assert!(value_eq(&a, &a));
    }

    /// Equal objects in another member order, and a number in another spelling, have one key.
    #[test]
    fn value_key_ignores_member_order(a in value()) {
        let reordered = reorder(&a);
        prop_assert!(value_eq(&a, &reordered));
        prop_assert_eq!(value_key(&a), value_key(&reordered));
    }

    #[test]
    fn canonical_is_the_jcs_encoding(c in constraint()) {
        prop_assert_eq!(c.canonical(), to_vec(&c).unwrap());
    }

    #[test]
    fn implies_is_the_pairwise_implication(a in constraint(), b in constraint()) {
        prop_assert_eq!(implies(&a, &b), a.implies_direct(&b), "{:?} => {:?}", a, b);
        prop_assert_eq!(a.implies(&b), a.implies_direct(&b), "{:?} => {:?}", a, b);
    }

    #[test]
    fn implies_is_the_pairwise_implication_on_related_lists((a, b) in related()) {
        prop_assert_eq!(implies(&a, &b), a.implies_direct(&b), "{:?} => {:?}", a, b);
        prop_assert_eq!(a.implies(&b), a.implies_direct(&b), "{:?} => {:?}", a, b);
        prop_assert_eq!(implies(&b, &a), b.implies_direct(&a), "{:?} => {:?}", b, a);
    }

    #[test]
    fn set_checks_are_the_pairwise_checks((parent, requested) in sets()) {
        for p in parent.iter() {
            for c in requested.iter() {
                prop_assert_eq!(
                    PreparedCap::new(p).covers_calls(&PreparedCap::new(c)),
                    p.covers_calls_direct(c)
                );
                prop_assert_eq!(p.covers_calls(c), p.covers_calls_direct(c));
                prop_assert_eq!(
                    p.covers(c),
                    p.covers_calls_direct(c) && c.limits.narrows(&p.limits)
                );
            }
        }
        prop_assert_eq!(parent.covers_prepared(&requested), parent.covers_direct(&requested));
        prop_assert_eq!(requested.covers_prepared(&parent), requested.covers_direct(&parent));
        prop_assert_eq!(parent.covers(&requested), parent.covers_direct(&requested));
        let covered: Vec<&Capability> = requested
            .iter()
            .filter(|c| parent.covers_direct(&CapabilitySet::from_iter([(*c).clone()])))
            .collect();
        prop_assert_eq!(parent.covered(&requested), covered);
        let each: Vec<_> = requested
            .iter()
            .map(|c| {
                let one = CapabilitySet::from_iter([c.clone()]);
                parent
                    .attenuate_indexed_direct(&one, |_, _, _| None)
                    .map(|mut v| v.remove(0).2)
            })
            .collect();
        prop_assert_eq!(parent.attenuate_each(requested.iter()), each);
        prop_assert_eq!(requested.covers(&parent), requested.covers_direct(&parent));
        let none = |_: usize, _: LimitKind, _: u64| None;
        prop_assert_eq!(
            parent.attenuate_indexed_prepared(&requested, none),
            parent.attenuate_indexed_direct(&requested, none)
        );
        // With something spent on every limited parent, as at an exchange.
        let spent = |i: usize, _: LimitKind, max: u64| Some(max.saturating_sub(1 + i as u64 % 2));
        prop_assert_eq!(
            parent.attenuate_indexed_prepared(&requested, spent),
            parent.attenuate_indexed_direct(&requested, spent)
        );
        prop_assert_eq!(
            requested.attenuate_indexed_prepared(&parent, none),
            requested.attenuate_indexed_direct(&parent, none)
        );
        prop_assert_eq!(
            parent.attenuate_indexed(&requested, none),
            parent.attenuate_indexed_direct(&requested, none)
        );
    }
}

proptest! {
    #![proptest_config(config())]

    /// A set built from precomputed sort keys is the set `BTreeSet` builds, member for member
    /// and in how each is written (of equal capabilities, `1` and `1.0`, the one it keeps):
    /// collected (the last kept) and read from JSON (the first kept).
    #[test]
    fn sets_are_built_as_btreeset_builds_them(
        caps in prop::collection::vec(item(), 1..4)
            .prop_flat_map(|pool| prop::collection::vec(capability(pool), 0..8))
    ) {
        let mut caps = caps;
        // Equal capabilities written differently, next to each other and apart.
        if let Some(c) = caps.first().cloned() {
            caps.push(Capability { constraints: c.constraints.iter()
                .map(|(k, v)| (k.clone(), respell(v))).collect(), ..c });
        }
        let collected: std::collections::BTreeSet<Capability> = caps.iter().cloned().collect();
        let ours = CapabilitySet::from_iter(caps.iter().cloned());
        prop_assert_eq!(
            serde_json::to_string(&ours).unwrap(),
            serde_json::to_string(&collected).unwrap()
        );
        // Unchecked ranges and paths are drawn too; those do not read back.
        let json = serde_json::to_string(&caps).unwrap();
        let read = serde_json::from_str::<std::collections::BTreeSet<Capability>>(&json);
        let ours = serde_json::from_str::<CapabilitySet>(&json);
        prop_assert_eq!(read.is_ok(), ours.is_ok());
        let (Ok(read), Ok(ours)) = (read, ours) else {
            return Ok(());
        };
        prop_assert_eq!(
            serde_json::to_string(&ours).unwrap(),
            serde_json::to_string(&read).unwrap()
        );
    }
}

/// `c` with its values written another way where JSON allows ([`reorder`]).
fn respell(c: &ArgConstraint) -> ArgConstraint {
    match c {
        ArgConstraint::Equals(v) => ArgConstraint::Equals(reorder(v)),
        ArgConstraint::OneOf(vs) => ArgConstraint::OneOf(vs.iter().map(reorder).collect()),
        other => other.clone(),
    }
}

/// `v` with every object's members in reverse order and every whole float written as the
/// integer (and back), recursively.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "only whole numbers below 2^53 are converted, which both types hold exactly"
)]
fn reorder(v: &Value) -> Value {
    match v {
        Value::Array(items) => Value::Array(items.iter().map(reorder).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .rev()
                .map(|(k, v)| (k.clone(), reorder(v)))
                .collect(),
        ),
        Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) if i.unsigned_abs() < 1 << 53 => json!(i as f64),
            (None, Some(f)) if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 => {
                json!(f as i64)
            }
            _ => v.clone(),
        },
        _ => v.clone(),
    }
}

#[test]
fn keys_agree_with_value_eq_on_the_known_cases() {
    let parse = |s: &str| serde_json::from_str::<Value>(s).unwrap();
    let equal = [
        (parse("1"), parse("1.0")),
        (parse("1"), parse("1e0")),
        (parse("0"), parse("-0.0")),
        (parse("10000000000000000"), parse("1e16")),
        (
            parse(r#"{"a":1,"b":[2,{"c":3,"d":4}]}"#),
            parse(r#"{"b":[2.0,{"d":4,"c":3}],"a":1}"#),
        ),
    ];
    for (a, b) in &equal {
        assert!(value_eq(a, b), "{a} = {b}");
        assert_eq!(value_key(a), value_key(b), "{a} = {b}");
    }
    let different = [
        (parse("9007199254740993"), parse("9007199254740992.0")),
        (parse("1"), parse(r#""1""#)),
        (json!("\u{e9}"), json!("e\u{301}")),
        (parse("[1,2]"), parse("[2,1]")),
        (parse(r#"{"a":1}"#), parse(r#"{"a":1,"b":null}"#)),
        (parse("null"), parse("false")),
        (parse("[]"), parse("{}")),
        (parse(r#"["a,b"]"#), parse(r#"["a","b"]"#)),
    ];
    for (a, b) in &different {
        assert!(!value_eq(a, b), "{a} != {b}");
        assert_ne!(value_key(a), value_key(b), "{a} != {b}");
    }
}

/// Each summary arm on lists where the answer turns on one value, both ways.
#[test]
fn summaries_give_the_pairwise_answer() {
    let one_of = |vs: &[Value]| ArgConstraint::OneOf(vs.to_vec());
    let cases = [
        (
            one_of(&[json!("ab"), json!("abc")]),
            ArgConstraint::Prefix("ab".into()),
        ),
        (
            one_of(&[json!("ab"), json!("a")]),
            ArgConstraint::Prefix("ab".into()),
        ),
        (
            one_of(&[json!("ab"), json!(1)]),
            ArgConstraint::Prefix("".into()),
        ),
        (
            one_of(&[json!("\u{e9}"), json!("\u{ea}")]),
            ArgConstraint::Prefix("\u{e9}".into()),
        ),
        (
            one_of(&[json!("/w/a"), json!("/w/b/")]),
            ArgConstraint::PathPrefix("/w".into()),
        ),
        (
            one_of(&[json!("/w/a"), json!("/w")]),
            ArgConstraint::PathPrefix("/w/".into()),
        ),
        (
            one_of(&[json!("/w/"), json!("/w/a")]),
            ArgConstraint::PathPrefix("/w/".into()),
        ),
        (
            one_of(&[json!("/w/a"), json!("w/a")]),
            ArgConstraint::PathPrefix("/w".into()),
        ),
        (
            one_of(&[json!("/w-x"), json!("/w/a")]),
            ArgConstraint::PathPrefix("/w".into()),
        ),
        (
            one_of(&[json!("/w/a")]),
            ArgConstraint::PathPrefix("/w/../x".into()),
        ),
        (
            one_of(&[json!(0), json!(7.0)]),
            ArgConstraint::Range {
                min: Some(0),
                max: Some(7),
            },
        ),
        (
            one_of(&[json!(0), json!(8)]),
            ArgConstraint::Range {
                min: Some(0),
                max: Some(7),
            },
        ),
        (
            one_of(&[json!(1), json!(10_000_000_000_000_000u64)]),
            ArgConstraint::Range {
                min: None,
                max: None,
            },
        ),
        (
            one_of(&[json!(1), json!(1.0)]),
            ArgConstraint::Equals(json!(1)),
        ),
        (
            one_of(&[json!(1), json!(2)]),
            ArgConstraint::Equals(json!(1)),
        ),
        (
            one_of(&[json!(1.0), json!({"a": [1]})]),
            one_of(&[json!({"a": [1.0]}), json!(1)]),
        ),
        (
            one_of(&[json!(1), json!(1), json!(2)]),
            one_of(&[json!(1.0), json!(3)]),
        ),
        (
            ArgConstraint::Range {
                min: Some(5),
                max: Some(5),
            },
            one_of(&[json!(5.0)]),
        ),
        (
            ArgConstraint::Equals(json!({"b": 1, "a": 2})),
            one_of(&[json!({"a": 2, "b": 1.0})]),
        ),
    ];
    for (a, b) in &cases {
        assert_eq!(implies(a, b), a.implies_direct(b), "{a:?} => {b:?}");
        assert_eq!(implies(b, a), b.implies_direct(a), "{b:?} => {a:?}");
    }
}

/// The work of the `bounds` bench's worst case, counted rather than timed (SR-123): one
/// requested capability whose 1,024-value `one_of` is in none of `k` parents' 1,024-value
/// lists, each lacking only one of its values. Before the fix that was about
/// `3 * k * 1024 * 1024 / 2` value comparisons (17.7 s at `k` = 400); now each value's key is
/// written once per side and each child value is looked up at most once per parent.
#[test]
fn the_work_of_an_attenuation_is_linear_in_the_lists_sr123() {
    use super::count;
    let n = crate::MAX_ONE_OF_VALUES;
    let values = |last: Value| -> Vec<Value> {
        let mut v: Vec<Value> = (0..n).map(|i| json!(i)).collect();
        v[n - 1] = last;
        v
    };
    let request = CapabilitySet::from_iter([Capability::new("s", "t")
        .with_constraint("a", ArgConstraint::OneOf(values(json!("absent"))))]);
    for k in [1u64, 64] {
        let parent: CapabilitySet = (0..k)
            .map(|j| {
                Capability::new("s", "t")
                    .with_constraint("a", ArgConstraint::OneOf(values(json!(format!("p{j}")))))
            })
            .collect();
        let (result, keys, lookups) = count::of(|| parent.attenuate(&request));
        assert!(result.is_err());
        let n = n as u64;
        assert_eq!(keys, n * (k + 1), "k = {k}: each list's keys written once");
        assert!(lookups <= n * k, "k = {k}: {lookups} lookups");
        // And the same answer as the pairwise implementation.
        assert_eq!(
            parent.attenuate_indexed(&request, |_, _, _| None),
            parent.attenuate_indexed_direct(&request, |_, _, _| None)
        );
    }
    // Two lists of 1,024: at most 1,024 lookups, where the pairwise test made up to 1,048,576
    // comparisons.
    let a = ArgConstraint::OneOf(values(json!("absent")));
    let b = ArgConstraint::OneOf(values(json!("other")));
    let (implied, keys, lookups) = count::of(|| a.implies(&b));
    assert!(!implied);
    assert_eq!(keys, 2 * n as u64);
    assert!(lookups <= n as u64);
}
