//! The prepared implication of SR-123 (`capability/prepared.rs`: canonical keys in hash sets
//! and summaries of `one_of` lists) against the pairwise code it replaces, differentially.
//! Both are private; the core takes the pairwise path for small inputs and the prepared one
//! for larger ones, so this target asks the same question both ways through the public API
//! (`attenuo_fuzz::caps` has the reference and why it only ever reaches the pairwise path).
//!
//! Properties beyond "no panic":
//!
//! - `ArgConstraint::implies` with a `one_of` longer than the pairwise path takes, on either
//!   side, gives the answer of the pairwise implication applied value by value (`implies_ref`);
//! - for generated parent and child sets, `CapabilitySet::covers`, `covered`, `attenuate`,
//!   `attenuate_each`, `attenuate_root` and `attenuate_root_each` give the reference's answers, and the same answers
//!   again with the parent padded by one capability that covers nothing but is too large for
//!   the pairwise path (so a small pair is compared both ways);
//! - `jcs::value_key(a) == jcs::value_key(b)` exactly when `jcs::value_eq(a, b)`, for values
//!   parsed by `serde_json` from generated text: numbers in different spellings, nested
//!   values, escaped and unescaped unicode (NFC and NFD), duplicate object keys; the key is
//!   the bytes `jcs::to_vec` writes, and reading it back gives an equal value with the same
//!   key; an `equals` and a long `one_of` of such values imply each other exactly when the
//!   values are equal;
//! - `CapabilitySet::validate_size` refuses exactly when one of the documented counts is over
//!   its bound (capabilities over `MAX_CAPABILITIES`, a `one_of` over `MAX_ONE_OF_VALUES`,
//!   constraints over `MAX_CONSTRAINTS`, `one_of` values over `MAX_ONE_OF_VALUES_TOTAL`, in
//!   that order), and `attenuate`, `attenuate_root` and `attenuate_with` refuse such a request
//!   with that error before comparing anything.
#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_core::capability::{
    MAX_CAPABILITIES, MAX_CONSTRAINTS, MAX_ONE_OF_VALUES, MAX_ONE_OF_VALUES_TOTAL,
};
use attenuo_core::{jcs, ArgConstraint, AttenuationError, Capability, CapabilitySet, SizeError};
use attenuo_fuzz::caps::{
    attenuate_ref, attenuate_root_ref, capability, caps, constraint, covers_ref, implies_ref,
    padded, set_covers_ref, uses_pad, LONG_LIST,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// Spellings of numbers, grouped by the value a reader would expect them to have, so that two
/// texts often spell one number two ways (and the integer and float edges sit side by side).
const NUMBERS: &[&[&str]] = &[
    &[
        "1",
        "1.0",
        "1e0",
        "1E+0",
        "10e-1",
        "0.1e1",
        "1.00000000000000000001",
    ],
    &["0", "-0", "0.0", "-0.0", "0e5", "-0E-3"],
    &["2", "2.0", "2e0", "20e-1"],
    &["-1", "-1.0", "-1e0"],
    &["0.5", "5e-1", "0.50"],
    &["0.1", "1e-1", "100e-3"],
    &[
        "9007199254740992",
        "9007199254740992.0",
        "9.007199254740992e15",
    ],
    &["9007199254740993", "9007199254740993.0"],
    &["10000000000000000", "1e16", "1E16", "10000000000000000.0"],
    &["922337203685477", "922337203685477.0"],
    &["922337203685478", "922337203685478.0"],
    &[
        "9223372036854775807",
        "9223372036854775807.0",
        "9.223372036854776e18",
    ],
    &[
        "-9223372036854775808",
        "-9223372036854775808.0",
        "-9.223372036854776e18",
    ],
    &["-9223372036854775809"],
    &[
        "18446744073709551615",
        "18446744073709551615.0",
        "1.8446744073709552e19",
    ],
    &["18446744073709551616", "1.8446744073709552e19"],
    &["1e21", "1E21", "1000000000000000000000"],
    &["1.7976931348623157e308", "17976931348623157e292"],
    &["5e-324", "4.9e-324", "4.94065645841246544e-324"],
    &["123456789012345678901234567890", "1.2345678901234568e29"],
];

/// String literals, as JSON text: one string escaped and unescaped, NFC and NFD, characters
/// whose escapes differ in case, and a pair that is one character in UTF-16 escapes.
const STRINGS: &[&[&str]] = &[
    &[r#""a""#, r#""a""#],
    &[r#""é""#, r#""é""#, r#""é""#],
    &[r#""é""#, r#""é""#],
    &[r#""""#],
    &[r#""/""#, r#""\/""#],
    &[r#""\"""#, r#"""""#],
    &[r#""😀""#, r#""😀""#, r#""😀""#],
    &[r#""\u0000""#],
    &["\"\u{2028}\"", r#"" ""#],
    &[r#""﻿""#, "\"\u{feff}\""],
    &[r#""1""#],
    &[r#""\ud800""#],
];

/// Object member names: a few, so duplicates are common, ordered differently in UTF-8 and
/// UTF-16 (U+FFFF and U+10000).
const KEYS: &[&str] = &[
    r#""k""#,
    r#""k""#,
    r#""j""#,
    r#""""#,
    "\"\u{ffff}\"",
    r#""𐀀""#,
];

/// A JSON value with every leaf a choice of group and spelling, so it can be written again
/// with other spellings of the same leaves.
#[derive(Debug, Clone)]
enum Tree {
    Number(usize, usize),
    Str(usize, usize),
    Lit(usize),
    Array(Vec<Tree>),
    Object(Vec<(usize, Tree)>),
}

fn tree(u: &mut Unstructured<'_>, depth: u32) -> Result<Tree> {
    let pick = if depth == 0 {
        u.int_in_range(0u8..=2)?
    } else {
        u.int_in_range(0u8..=4)?
    };
    Ok(match pick {
        0 => Tree::Number(u.choose_index(NUMBERS.len())?, u.arbitrary()?),
        1 => Tree::Str(u.choose_index(STRINGS.len())?, u.arbitrary()?),
        2 => Tree::Lit(u.int_in_range(0..=2)?),
        3 => Tree::Array(
            (0..u.int_in_range(0..=3)?)
                .map(|_| tree(u, depth - 1))
                .collect::<Result<_>>()?,
        ),
        _ => Tree::Object(
            (0..u.int_in_range(0..=3)?)
                .map(|_| Ok((u.choose_index(KEYS.len())?, tree(u, depth - 1)?)))
                .collect::<Result<_>>()?,
        ),
    })
}

/// `t` written as JSON text, with each leaf's spelling `(chosen + shift) % spellings`.
fn write(t: &Tree, shift: usize, out: &mut String) {
    match t {
        Tree::Number(g, s) => {
            out.push_str(NUMBERS[*g][(s % NUMBERS[*g].len() + shift) % NUMBERS[*g].len()])
        }
        Tree::Str(g, s) => {
            out.push_str(STRINGS[*g][(s % STRINGS[*g].len() + shift) % STRINGS[*g].len()])
        }
        Tree::Lit(i) => out.push_str(["null", "true", "false"][*i]),
        Tree::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, shift, out);
            }
            out.push(']');
        }
        Tree::Object(members) => {
            out.push('{');
            for (i, (k, v)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(KEYS[(k % KEYS.len() + shift) % KEYS.len()]);
                out.push(':');
                write(v, shift, out);
            }
            out.push('}');
        }
    }
}

fn parse(t: &Tree, shift: usize) -> Option<Value> {
    let mut s = String::new();
    write(t, shift, &mut s);
    serde_json::from_str(&s).ok()
}

fn check_values(a: &Value, b: &Value) {
    let (ka, kb) = (jcs::value_key(a), jcs::value_key(b));
    assert_eq!(
        ka == kb,
        jcs::value_eq(a, b),
        "value_key and value_eq disagree on {a} and {b}"
    );
    assert_eq!(jcs::value_eq(a, b), jcs::value_eq(b, a));
    for (v, k) in [(a, &ka), (b, &kb)] {
        assert!(jcs::value_eq(v, v));
        if let Ok(bytes) = jcs::to_vec(v) {
            assert_eq!(&bytes, k, "value_key is not to_vec for {v}");
        }
        let back: Value = serde_json::from_slice(k).expect("a canonical key is JSON");
        assert!(
            jcs::value_eq(v, &back),
            "{v} read back from its key is {back}"
        );
        assert_eq!(&jcs::value_key(&back), k);
    }
    // Through the prepared implication: a list long enough for the prepared path, of one
    // value repeated.
    let eq = jcs::value_eq(a, b);
    let long = |v: &Value| ArgConstraint::OneOf(vec![v.clone(); LONG_LIST]);
    let one = |v: &Value| ArgConstraint::Equals(v.clone());
    assert_eq!(one(a).implies(&long(b)), eq);
    assert_eq!(long(a).implies(&one(b)), eq);
    assert_eq!(long(a).implies(&long(b)), eq);
    assert_eq!(one(a).implies(&one(b)), eq);
}

/// Requests around the whole-request bounds, built cheaply (one-argument names, one value
/// repeated), with the error `validate_size` must give, in its documented order.
fn check_bounds(u: &mut Unstructured<'_>) -> Result<()> {
    fn near(u: &mut Unstructured<'_>, bound: usize) -> Result<usize> {
        Ok(if u.ratio(1u8, 4u8)? {
            u.int_in_range(0..=bound + 8)?
        } else {
            bound - 2 + u.int_in_range(0..=4)?
        })
    }
    let n_caps = if u.arbitrary()? {
        near(u, MAX_CAPABILITIES)?
    } else {
        u.int_in_range(1..=4)?
    };
    // Constraints and one_of values, spread over the first few capabilities.
    let n_constraints = if u.arbitrary()? {
        near(u, MAX_CONSTRAINTS)?
    } else {
        u.int_in_range(0..=4)?
    };
    let longest = if u.arbitrary()? {
        near(u, MAX_ONE_OF_VALUES)?
    } else {
        u.int_in_range(0..=4)?
    };
    let rest = if u.arbitrary()? {
        near(u, MAX_ONE_OF_VALUES_TOTAL)?.saturating_sub(longest)
    } else {
        u.int_in_range(0..=4)?
    };
    let n_caps = n_caps.max(1);
    let spread = u.int_in_range(1..=n_caps.min(4))?;
    let mut caps: Vec<Capability> = (0..n_caps)
        .map(|i| Capability::new("s", format!("t{i}")))
        .collect();
    for i in 0..n_constraints {
        caps[i % spread]
            .constraints
            .insert(format!("a{i}"), ArgConstraint::Equals(Value::from(0)));
    }
    let mut lists = 0;
    let mut values = 0;
    let mut longest_seen = 0;
    for (len, at) in [(longest, 0usize), (rest, 1usize)] {
        if len == 0 {
            continue;
        }
        let c = &mut caps[at % spread];
        let arg = format!("list{at}");
        if c.constraints
            .insert(arg, ArgConstraint::OneOf(vec![Value::from(0); len]))
            .is_none()
        {
            lists += 1;
        }
        values += len;
        longest_seen = longest_seen.max(len);
    }
    let set: CapabilitySet = caps.into_iter().collect();
    assert_eq!(set.len(), n_caps);
    let total_constraints = n_constraints + lists;
    let expected = if n_caps > MAX_CAPABILITIES {
        Some("caps")
    } else if longest_seen > MAX_ONE_OF_VALUES {
        Some("one_of")
    } else if total_constraints > MAX_CONSTRAINTS {
        Some("constraints")
    } else if values > MAX_ONE_OF_VALUES_TOTAL {
        Some("values")
    } else {
        None
    };
    let got = set.validate_size();
    let kind = got.as_ref().err().map(|e| match e {
        SizeError::TooManyCapabilities { count, max } => {
            assert_eq!((*count, *max), (n_caps, MAX_CAPABILITIES));
            "caps"
        }
        SizeError::OneOfTooLong { count, max, .. } => {
            assert_eq!((*count, *max), (longest_seen, MAX_ONE_OF_VALUES));
            "one_of"
        }
        SizeError::TooManyConstraints { count, max } => {
            assert_eq!((*count, *max), (total_constraints, MAX_CONSTRAINTS));
            "constraints"
        }
        SizeError::TooManyOneOfValues { count, max } => {
            assert_eq!((*count, *max), (values, MAX_ONE_OF_VALUES_TOTAL));
            "values"
        }
    });
    assert_eq!(
        kind, expected,
        "validate_size: {got:?} for {n_caps} capabilities, {total_constraints} constraints, \
         longest one_of {longest_seen}, {values} values"
    );
    // Every attenuation refuses an oversized request with that error first, whatever the
    // parent; a request within the bounds under `*:*` is attenuated to itself.
    let parent: CapabilitySet = [Capability::new("*", "*")].into_iter().collect();
    let empty = CapabilitySet::new();
    for p in [&parent, &empty] {
        let results = [
            p.attenuate(&set),
            p.attenuate_root(&set),
            p.attenuate_with(&set, |_, _, _| Some(0)),
        ];
        for r in results {
            match (&got, r) {
                (Err(e), Err(AttenuationError::TooLarge(f))) => assert_eq!(e, &f),
                (Err(e), other) => panic!("oversized ({e}) request answered {other:?}"),
                (Ok(()), Err(AttenuationError::TooLarge(f))) => {
                    panic!("request within the bounds refused: {f}")
                }
                (Ok(()), Ok(out)) => assert!(std::ptr::eq(p, &parent) && out == set),
                (Ok(()), Err(e)) => assert!(std::ptr::eq(p, &empty), "{e}"),
            }
        }
    }
    Ok(())
}

fn check_sets(parent: &CapabilitySet, child: &CapabilitySet) {
    if uses_pad(child) {
        return;
    }
    let covers = set_covers_ref(parent, child);
    let attenuated = attenuate_ref(parent, child);
    let root = attenuate_root_ref(parent, child);
    let covered: Vec<&Capability> = child
        .iter()
        .filter(|c| parent.iter().any(|p| covers_ref(p, c)))
        .collect();
    let each: Vec<_> = child
        .iter()
        .map(|c| {
            let one: CapabilitySet = [c.clone()].into_iter().collect();
            attenuate_ref(parent, &one).map(|s| s.0.into_iter().next().expect("one"))
        })
        .collect();
    let root_each: Vec<_> = child
        .iter()
        .map(|c| {
            let one: CapabilitySet = [c.clone()].into_iter().collect();
            attenuate_root_ref(parent, &one).map(|s| s.0.into_iter().next().expect("one"))
        })
        .collect();
    for p in [parent.clone(), padded(parent)] {
        assert_eq!(p.covers(child), covers, "covers: {p:?} over {child:?}");
        assert_eq!(p.covered(child), covered, "covered: {p:?} over {child:?}");
        assert_eq!(
            p.attenuate(child),
            attenuated,
            "attenuate: {p:?} over {child:?}"
        );
        assert_eq!(
            p.attenuate_each(child.iter()),
            each,
            "attenuate_each: {p:?}"
        );
        assert_eq!(
            p.attenuate_root(child),
            root,
            "attenuate_root: {p:?} over {child:?}"
        );
        assert_eq!(
            p.attenuate_root_each(child.iter()),
            root_each,
            "attenuate_root_each: {p:?}"
        );
    }
    // Per capability, the prepared and the pairwise answers of `covers` agree (a capability
    // with a long list is prepared; the reference never is).
    for p in parent.iter() {
        for c in child.iter() {
            assert_eq!(p.covers(c), covers_ref(p, c), "{p:?} over {c:?}");
        }
    }
}

#[derive(Debug)]
enum Input {
    Implies(Vec<ArgConstraint>),
    Values(Tree, Tree, usize),
    Sets(CapabilitySet, CapabilitySet),
    Bounds(Vec<u8>),
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(match u.int_in_range(0u8..=5)? {
            0 | 1 => {
                let n = u.int_in_range(2..=4)?;
                Input::Implies((0..n).map(|_| constraint(u, 24)).collect::<Result<_>>()?)
            }
            2 => {
                let a = tree(u, 3)?;
                // Often the same tree spelled otherwise, so equal values are common.
                let b = if u.arbitrary()? {
                    a.clone()
                } else {
                    tree(u, 3)?
                };
                Input::Values(a, b, u.int_in_range(0..=7)?)
            }
            3 | 4 => {
                let parent = caps(u, 4, 16)?.into_iter().collect();
                let child = if u.arbitrary()? {
                    caps(u, 4, 16)?.into_iter().collect()
                } else {
                    // Narrowed copies of the parent's capabilities: what gets covered.
                    let p: Vec<Capability> = parent_iter(&parent);
                    let mut out = Vec::new();
                    for c in p {
                        if u.arbitrary()? {
                            let mut c = c;
                            if u.arbitrary()? {
                                c.constraints.insert(
                                    (*u.choose(attenuo_fuzz::caps::ARGS)?).to_string(),
                                    constraint(u, 16)?,
                                );
                            }
                            out.push(c);
                        }
                    }
                    if u.arbitrary()? {
                        out.push(capability(u, 16)?);
                    }
                    out.into_iter().collect()
                };
                Input::Sets(parent, child)
            }
            _ => Input::Bounds(u.arbitrary()?),
        })
    }
}

fn parent_iter(s: &CapabilitySet) -> Vec<Capability> {
    s.iter().cloned().collect()
}

fuzz_target!(|input: Input| {
    match input {
        Input::Implies(cs) => {
            for x in &cs {
                for y in &cs {
                    assert_eq!(x.implies(y), implies_ref(x, y), "{x:?} implies {y:?}");
                }
                assert!(x.implies(x), "not reflexive: {x:?}");
            }
        }
        Input::Values(a, b, shift) => {
            let (Some(a), Some(b)) = (parse(&a, 0), parse(&b, shift)) else {
                return;
            };
            check_values(&a, &b);
        }
        Input::Sets(parent, child) => {
            check_sets(&parent, &child);
            check_sets(&child, &parent);
        }
        Input::Bounds(bytes) => {
            let _ = check_bounds(&mut Unstructured::new(&bytes));
        }
    }
});
