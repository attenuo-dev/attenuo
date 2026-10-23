//! Capability coverage and attenuation, differentially: whenever `parent.covers(child)`, every
//! call `child` permits must be permitted by `parent` ("attenuated ⊆ parent"). Also checks that
//! `attenuate` agrees with `covers`, and that coverage is reflexive and transitive. Names and
//! values come from small alphabets so patterns, prefixes and constraints collide often.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use attenuo_core::{ArgConstraint, Capability, CapabilitySet, ToolCall};
use serde_json::Value;

const NAMES: &[&str] = &[
    "*", "a*", "ab*", "ab", "abc", "a", "b", "", "r/*", "r/", "r/x", "r", "A", "a/b", "*a",
];
const STRS: &[&str] = &["", "a", "ab", "abc", "b", "acme/", "acme/x", "é", "a\u{0}"];

fn name(u: &mut Unstructured<'_>) -> Result<String> {
    if u.ratio(1u8, 8u8)? {
        return u.arbitrary();
    }
    Ok((*u.choose(NAMES)?).to_string())
}

fn value(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=5)? {
        0 => Value::String((*u.choose(STRS)?).to_string()),
        1 => Value::from(u.int_in_range(-1i64..=2)?),
        2 => serde_json::json!(1.0),
        3 => Value::Null,
        4 => Value::Bool(u.arbitrary()?),
        _ => attenuo_fuzz::json_value(u, 2)?,
    })
}

fn constraint(u: &mut Unstructured<'_>) -> Result<ArgConstraint> {
    Ok(match u.int_in_range(0u8..=2)? {
        0 => ArgConstraint::Equals(value(u)?),
        1 => {
            let n = u.int_in_range(0usize..=3)?;
            ArgConstraint::OneOf((0..n).map(|_| value(u)).collect::<Result<_>>()?)
        }
        _ => ArgConstraint::Prefix((*u.choose(STRS)?).to_string()),
    })
}

fn capability(u: &mut Unstructured<'_>) -> Result<Capability> {
    let mut c = Capability::new(name(u)?, name(u)?);
    for _ in 0..u.int_in_range(0usize..=2)? {
        let arg = (*u.choose(&["x", "y"])?).to_string();
        c.constraints.insert(arg, constraint(u)?);
    }
    Ok(c)
}

fn set(u: &mut Unstructured<'_>) -> Result<CapabilitySet> {
    let n = u.int_in_range(0usize..=3)?;
    (0..n).map(|_| capability(u)).collect()
}

fn call(u: &mut Unstructured<'_>) -> Result<ToolCall> {
    let server = name(u)?;
    let tool = name(u)?;
    let mut args = BTreeMap::new();
    for arg in ["x", "y"] {
        if u.arbitrary()? {
            args.insert(arg.to_string(), value(u)?);
        }
    }
    let mut c = ToolCall::new(server, tool, Value::Null);
    c.arguments = args;
    Ok(c)
}

#[derive(Debug)]
struct Input {
    a: CapabilitySet,
    b: CapabilitySet,
    c: CapabilitySet,
    calls: Vec<ToolCall>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let a = set(u)?;
        let b = set(u)?;
        let c = set(u)?;
        let n = u.int_in_range(1usize..=8)?;
        let calls = (0..n).map(|_| call(u)).collect::<Result<_>>()?;
        Ok(Input { a, b, c, calls })
    }
}

fn check_pair(parent: &CapabilitySet, child: &CapabilitySet, calls: &[ToolCall]) {
    let covers = parent.covers(child);
    match parent.attenuate(child) {
        Ok(got) => {
            assert!(covers, "attenuate accepted what covers rejects");
            assert_eq!(&got, child);
        }
        Err(_) => assert!(!covers || child.is_empty()),
    }
    if covers {
        for call in calls {
            if child.permits(call) {
                assert!(
                    parent.permits(call),
                    "widening: child {child:?} permits {call:?}, parent {parent:?} does not"
                );
            }
        }
        // Per capability, too: each child capability is covered by a single parent one, which
        // must permit every call it permits.
        for cc in child.iter() {
            let p = parent.iter().find(|p| p.covers(cc)).expect("covered");
            for call in calls {
                if cc.permits(call) {
                    assert!(p.permits(call));
                }
            }
        }
    }
    let _ = child.iter().map(Capability::display).count();
}

fuzz_target!(|input: Input| {
    let Input { a, b, c, calls } = input;
    // Reflexive.
    assert!(a.covers(&a));
    for cap in a.iter() {
        assert!(cap.covers(cap), "capability does not cover itself: {cap:?}");
    }
    check_pair(&a, &b, &calls);
    check_pair(&b, &a, &calls);
    check_pair(&b, &c, &calls);
    // Transitive.
    if a.covers(&b) && b.covers(&c) {
        assert!(a.covers(&c), "covers is not transitive: {a:?} {b:?} {c:?}");
        check_pair(&a, &c, &calls);
    }
});
