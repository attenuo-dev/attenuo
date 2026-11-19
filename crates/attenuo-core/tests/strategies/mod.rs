//! Strategies shared by the property tests of this crate (`attenuation_props.rs`) and the
//! differential test against the Lean model (`lean_differential.rs`): small values, string and
//! path constraints, ranges and name patterns drawn so that equal, nested and nearly-equal
//! inputs are common.

use attenuo_core::ArgConstraint;
use proptest::prelude::*;
use serde_json::{json, Value};

/// Server and tool names and patterns: exact names, `*` and `prefix*` globs over a few letters.
pub const NAMES: &[&str] = &["a", "ab", "abc", "b", "*", "a*", "ab*", "b*"];

pub fn small_string() -> impl Strategy<Value = String> {
    "[ab]{0,3}"
}

/// A short string from path pieces, so that segment boundaries, trailing slashes, dot
/// segments, `//`, backslashes and percent escapes collide often.
pub fn path_string() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(&["/", "/", "a", "b", "ab", ".", "..", "%2e", "%2F", "\\", "-"][..]),
        0..6,
    )
    .prop_map(|parts| parts.concat())
}

pub fn small_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => small_string().prop_map(Value::String),
        2 => path_string().prop_map(Value::String),
        3 => (-1i64..4).prop_map(|n| json!(n)),
        // Whole floats are the integer they spell; fractions are no integer at all.
        1 => prop::sample::select(&[1.0f64, 2.0, 0.5, 2.5][..]).prop_map(|f| json!(f)),
    ]
}

/// A checked `range` with small bounds, either side possibly missing, so nested, equal and
/// single-integer ranges are common.
pub fn range() -> impl Strategy<Value = ArgConstraint> {
    (prop::option::of(-1i64..4), prop::option::of(-1i64..4))
        .prop_filter_map("a range needs a bound and min <= max", |(min, max)| {
            ArgConstraint::range(min, max).ok()
        })
}

/// String constraints over paths only: `prefix`, `path_prefix` and string `equals`/`one_of`.
pub fn path_constraint() -> impl Strategy<Value = ArgConstraint> {
    prop_oneof![
        path_string().prop_map(|s| ArgConstraint::Equals(json!(s))),
        prop::collection::vec(path_string().prop_map(Value::String), 0..3)
            .prop_map(ArgConstraint::OneOf),
        path_string().prop_map(ArgConstraint::Prefix),
        // Unchecked, so malformed bases (which admit nothing) are drawn too.
        path_string().prop_map(ArgConstraint::PathPrefix),
    ]
}

/// A string constraint of either path kind on `s`.
pub fn path_kind(s: String, kind: u8) -> ArgConstraint {
    match kind {
        0 => ArgConstraint::Prefix(s),
        1 => ArgConstraint::PathPrefix(s),
        _ => ArgConstraint::Equals(json!(s)),
    }
}

/// Two path constraints on one stem with different short tails (`/w` and `/w/`, `/w/a` and
/// `/w-`), so that nearly-equal bases, where a wrong rule would show, are common.
pub fn related_path_constraints() -> impl Strategy<Value = (ArgConstraint, ArgConstraint)> {
    const TAILS: &[&str] = &["", "", "/", "a", "/a", "/a/", "-", "/.."];
    (
        path_string(),
        prop::sample::select(TAILS),
        prop::sample::select(TAILS),
        0u8..3,
        0u8..3,
    )
        .prop_map(|(stem, t1, t2, k1, k2)| {
            (
                path_kind(format!("{stem}{t1}"), k1),
                path_kind(format!("{stem}{t2}"), k2),
            )
        })
}

pub fn arg_constraint() -> impl Strategy<Value = ArgConstraint> {
    prop_oneof![
        2 => small_value().prop_map(ArgConstraint::Equals),
        2 => prop::collection::vec(small_value(), 0..4).prop_map(ArgConstraint::OneOf),
        2 => "[ab]{0,2}".prop_map(ArgConstraint::Prefix),
        1 => path_string().prop_map(ArgConstraint::Prefix),
        // Checked, as a token can only carry; `path_constraint` draws malformed ones too.
        2 => path_string().prop_filter_map("a path_prefix needs a plain path", |p| {
            ArgConstraint::path_prefix(p).ok()
        }),
        2 => range(),
    ]
}

pub fn name() -> impl Strategy<Value = String> {
    prop::sample::select(NAMES).prop_map(str::to_owned)
}
