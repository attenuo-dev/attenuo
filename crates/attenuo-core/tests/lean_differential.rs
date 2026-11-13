//! Differential test against the Lean model of the covering rule (`proofs/lean/`).
//!
//! Generates cases for the functions the model defines (`satisfied_by`, `implies`,
//! `pattern_matches`, pattern covering, `Capability::permits` and `covers`,
//! `CapabilitySet::permits`, `covers` and `attenuate`), evaluates each with the Rust code and
//! writes the case and Rust's answer to a file, one per line, in the format
//! `proofs/lean/Attenuo/Cases.lean` reads. `scripts/check-lean-differential.sh` runs this test,
//! then the Lean model on the file, and fails on any case where the two answers differ. This
//! test alone needs no Lean: it checks only that the cases it meant to draw were drawn.
//!
//! The file is written to `$ATTENUO_LEAN_CASES` when set, else to `lean-differential/cases.txt`
//! under Cargo's test scratch directory. The seed is fixed, so the file is the same on every
//! run.
//!
//! The cases stay inside what the model represents, by construction:
//!
//! - JSON values are `null`, booleans, strings, integers (`i64` and `u64`) and finite floats.
//!   Arrays and objects are not drawn (`encode_value` refuses them).
//! - Limits hold `calls` only (`encode_limits` refuses the others).
//! - Server and tool patterns of capabilities are valid patterns (`names.rs`); a pattern that
//!   is not is refused by `encode_pattern`. Call names may be invalid: the model takes the
//!   result of `ToolCall::check_names` as an input, and the case carries it.
//!
//! Strings may hold any code point, the lookalike separators of `LOOKALIKE_SEPARATORS` among
//! them: both sides compare code points and neither normalises Unicode.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use attenuo_core::capability::pattern_matches;
use attenuo_core::jcs::format_f64;
use attenuo_core::names::{check_call_pattern, check_server_pattern};
use attenuo_core::{ArgConstraint, AttenuationError, Capability, CapabilitySet, Limits, ToolCall};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, RngSeed, TestRunner};
use serde_json::{json, Value};

mod strategies;
use strategies::{
    arg_constraint, name, path_constraint, path_string, range, related_path_constraints,
    small_value, NAMES,
};

/// The seed of every draw: the case file is the same on every run.
const SEED: u64 = 20_261_113;

/// Cases per function.
const SAT: usize = 4000;
const IMPLIES: usize = 7000;
const PMATCH: usize = 2000;
const PCOVERS: usize = 2000;
const CPERMITS: usize = 3000;
const CCOVERS: usize = 4000;
const SPERMITS: usize = 2500;
const SCOVERS: usize = 3000;
const ATTEN: usize = 4000;

/// `WHOLE_FLOAT_MAX` of `capability.rs`.
const WFM: i64 = 922_337_203_685_477;

const ARGS: &[&str] = &["x", "y"];

// ---------------------------------------------------------------- drawing

/// A small deterministic generator (SplitMix64) for the choices the strategies do not make.
struct Gen {
    state: u64,
    runner: TestRunner,
    /// Draws replaced because they fell outside the model, by reason.
    excluded: BTreeMap<&'static str, usize>,
}

impl Gen {
    fn new(seed: u64) -> Self {
        // The runner only draws here, so its reject count runs over every draw of the test:
        // `range()` and the checked `path_prefix` filter many out.
        let runner = TestRunner::new(Config {
            rng_seed: RngSeed::Fixed(seed),
            failure_persistence: None,
            max_local_rejects: u32::MAX,
            ..Config::default()
        });
        Gen {
            state: seed,
            runner,
            excluded: BTreeMap::new(),
        }
    }

    fn u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `n` (`n > 0`).
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.u64() % n as u64).expect("below a usize")
    }

    fn chance(&mut self, num: usize, den: usize) -> bool {
        self.below(den) < num
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn exclude(&mut self, reason: &'static str) {
        *self.excluded.entry(reason).or_default() += 1;
    }

    /// One value of a proptest strategy, from the shared strategies of the property tests.
    fn draw<S: Strategy>(&mut self, s: S) -> S::Value {
        s.new_tree(&mut self.runner)
            .expect("a strategy draws a value")
            .current()
    }
}

// ---------------------------------------------------------------- values

/// Integers around the edges the code cares about: `i64` and `u64` bounds, `WHOLE_FLOAT_MAX`,
/// `2^53` and integers whose nearest double is or is not written with their digits.
fn edge_ints() -> Vec<Value> {
    let mut v: Vec<Value> = [
        0,
        1,
        -1,
        5,
        i64::MIN,
        i64::MIN + 1,
        i64::MAX,
        i64::MAX - 1,
        WFM,
        WFM + 1,
        -WFM,
        -WFM - 1,
        (1 << 53) - 1,
        1 << 53,
        (1 << 53) + 1,
        (1 << 53) + 2,
        -(1 << 53) - 1,
        10_000_000_000_000_000,
        10_000_000_000_000_001,
        100_000_000_000_000_000,
        1 << 60,
        1_152_921_504_606_847_000,
        9_223_372_036_854_775_000,
        -9_223_372_036_854_775_000,
    ]
    .into_iter()
    .map(Value::from)
    .collect();
    for u in [i64::MAX as u64 + 1, u64::MAX, 10_000_000_000_000_000_000] {
        v.push(Value::from(u));
    }
    v
}

/// Floats: whole and fractional, at the `as_long` and `2^53` edges, beyond `10^21`, signed
/// zeros and the extremes of `f64`.
fn edge_floats() -> Vec<f64> {
    vec![
        5.0,
        -5.0,
        0.0,
        -0.0,
        0.5,
        -2.5,
        0.1,
        1.5,
        WFM as f64,
        (WFM + 1) as f64,
        -(WFM as f64),
        9_007_199_254_740_992.0,
        1e16,
        1e17,
        1_152_921_504_606_846_976.0,
        9.2e18,
        9.223_372_036_854_776e18,
        -9.223_372_036_854_776e18,
        1.844_674_407_370_955_2e19,
        1e20,
        1e21,
        1e22,
        1e300,
        f64::MAX,
        f64::MIN_POSITIVE,
        5e-324,
    ]
}

/// Strings `path_prefix` refuses or nearly refuses, outside the shared path pieces:
/// lookalike separators, double-encoded escapes, control characters (C0 and C1), non-ASCII
/// letters and spaces.
const EDGE_STRINGS: &[&str] = &[
    "",
    " ",
    "/a\u{ff0f}b",
    "/a/\u{2024}\u{2024}/b",
    "/a/\u{2215}",
    "/a/%252e",
    "/a/%252",
    "/a/%2E",
    "/a/%5C",
    "/a/\t",
    "/a/\u{7f}",
    "/a/\u{85}",
    "/a/\u{a0}",
    "/é/x",
    "é",
    "a b",
    "/a b/c",
    "\\",
    "/",
    "//",
    "a",
    "a/",
    "/a",
    "/a/",
];

/// An integer whose nearest double is written with its digits, so a float equals it: the
/// canonical text of a random large double, read as an integer.
fn int_with_float_twin(g: &mut Gen) -> Value {
    let exp = 49 + g.below(14) as i32;
    let f = (1.0 + (g.u64() >> 11) as f64 / (1u64 << 53) as f64) * 2f64.powi(exp);
    let f = if g.chance(1, 4) { -f } else { f };
    let text = format_f64(f.trunc()).expect("finite");
    match text.parse::<i64>() {
        Ok(n) => Value::from(n),
        Err(_) => Value::from(f.trunc()),
    }
}

fn value(g: &mut Gen) -> Value {
    match g.below(12) {
        0..=4 => g.draw(small_value()),
        5 => Value::String(g.draw(path_string())),
        6 => Value::String((*g.pick(EDGE_STRINGS)).to_owned()),
        7 => g.pick(&edge_ints()).clone(),
        8 => Value::from(*g.pick(&edge_floats())),
        9 => int_with_float_twin(g),
        10 => {
            let n = g.pick(&edge_ints()).as_i64().unwrap_or(0);
            Value::from(n.saturating_add(g.below(5) as i64 - 2))
        }
        _ => g.pick(&[Value::Null, json!(true), json!(false)]).clone(),
    }
}

/// A value canonically equal to `v` in another spelling (`5` and `5.0`), or `v` itself.
fn twin(v: &Value) -> Value {
    if let Some(n) = v.as_i64() {
        let f = n as f64;
        if format_f64(f).as_deref() == Some(n.to_string().as_str()) {
            return Value::from(f);
        }
    } else if let Some(f) = v.as_f64().filter(|_| v.is_f64()) {
        if let Some(n) = format_f64(f).and_then(|t| t.parse::<i64>().ok()) {
            return Value::from(n);
        }
    }
    v.clone()
}

/// A value next to `v`: an integer one off, a string with a character more or less.
fn neighbour(g: &mut Gen, v: &Value) -> Value {
    match v {
        Value::Number(n) => match n.as_i64() {
            Some(i) => Value::from(i.saturating_add(if g.chance(1, 2) { 1 } else { -1 })),
            None => Value::from(n.as_f64().unwrap_or(0.0) + 0.5),
        },
        Value::String(s) => {
            let mut s = s.clone();
            if g.chance(1, 2) || s.is_empty() {
                s.push(*g.pick(&['a', '/', '-']));
            } else {
                s.pop();
            }
            Value::String(s)
        }
        _ => value(g),
    }
}

/// A value meant to sit at the edge of what `c` admits: inside, just outside, or another
/// spelling of an admitted value.
fn value_for(g: &mut Gen, c: &ArgConstraint) -> Value {
    if g.chance(1, 5) {
        return value(g);
    }
    match c {
        ArgConstraint::Equals(v) => match g.below(3) {
            0 => v.clone(),
            1 => twin(v),
            _ => neighbour(g, v),
        },
        ArgConstraint::OneOf(vs) if !vs.is_empty() => {
            let v = g.pick(vs).clone();
            match g.below(3) {
                0 => v,
                1 => twin(&v),
                _ => neighbour(g, &v),
            }
        }
        ArgConstraint::OneOf(_) => value(g),
        ArgConstraint::Prefix(p) | ArgConstraint::PathPrefix(p) => {
            let tail = *g.pick(&[
                "", "", "a", "/", "/a", "/a/", "-", "/..", "/../x", "//x", "/%2e", "\u{ff0f}",
            ]);
            let mut s = format!("{p}{tail}");
            if g.chance(1, 6) {
                s.pop();
            }
            Value::String(s)
        }
        ArgConstraint::Range { min, max } => {
            let lo = min.unwrap_or(i64::MIN);
            let hi = max.unwrap_or(i64::MAX);
            let n = match g.below(6) {
                0 => lo,
                1 => hi,
                2 => lo.saturating_sub(1),
                3 => hi.saturating_add(1),
                4 => lo / 2 + hi / 2,
                _ => lo.saturating_add(g.below(3) as i64),
            };
            if g.chance(1, 3) {
                twin(&Value::from(n))
            } else {
                Value::from(n)
            }
        }
    }
}

// ---------------------------------------------------------------- constraints

fn edge_constraint(g: &mut Gen) -> ArgConstraint {
    let big = || -> Vec<i64> { vec![i64::MIN, i64::MAX, WFM, WFM + 1, -WFM - 1, 1 << 53, 0] };
    match g.below(10) {
        // Unchecked ranges: inverted, unbounded, at the ends of i64.
        0 => {
            let a = *g.pick(&big());
            let b = *g.pick(&big());
            ArgConstraint::Range {
                min: g.chance(3, 4).then_some(a),
                max: g.chance(3, 4).then_some(b),
            }
        }
        1 => ArgConstraint::Range {
            min: Some(5),
            max: Some(3),
        },
        2 => ArgConstraint::OneOf(Vec::new()),
        3 => ArgConstraint::Equals(value(g)),
        4 => ArgConstraint::OneOf((0..g.below(4)).map(|_| value(g)).collect()),
        5 => ArgConstraint::Prefix((*g.pick(EDGE_STRINGS)).to_owned()),
        6 => ArgConstraint::PathPrefix((*g.pick(EDGE_STRINGS)).to_owned()),
        7 => {
            let n = g.pick(&edge_ints()).as_i64().unwrap_or(7);
            ArgConstraint::Range {
                min: Some(n.saturating_sub(g.below(3) as i64)),
                max: Some(n.saturating_add(g.below(3) as i64)),
            }
        }
        8 => ArgConstraint::Equals(int_with_float_twin(g)),
        _ => ArgConstraint::Equals(Value::from(*g.pick(&edge_floats()))),
    }
}

fn constraint(g: &mut Gen) -> ArgConstraint {
    match g.below(8) {
        0..=3 => g.draw(arg_constraint()),
        4 => g.draw(path_constraint()),
        5 => g.draw(range()),
        _ => edge_constraint(g),
    }
}

/// A path that extends `p` by a segment or a trailing `/`.
fn extend_path(g: &mut Gen, p: &str) -> String {
    let sep = if p.ends_with('/') { "" } else { "/" };
    match g.below(4) {
        0 => format!("{p}{sep}a"),
        1 => format!("{p}{sep}b/c"),
        2 => format!("{p}{sep}"),
        _ => p.to_owned(),
    }
}

/// A constraint meant to imply `c`: the kind of child a delegation draws.
fn narrow(g: &mut Gen, c: &ArgConstraint) -> ArgConstraint {
    match c {
        ArgConstraint::Equals(v) => match g.below(3) {
            0 => ArgConstraint::Equals(v.clone()),
            1 => ArgConstraint::Equals(twin(v)),
            _ => match v.as_i64() {
                Some(n) => ArgConstraint::Range {
                    min: Some(n),
                    max: Some(n),
                },
                None => ArgConstraint::OneOf(vec![v.clone(), twin(v)]),
            },
        },
        ArgConstraint::OneOf(vs) if !vs.is_empty() => match g.below(3) {
            0 => ArgConstraint::Equals(twin(g.pick(vs))),
            1 => ArgConstraint::OneOf(vs.iter().filter(|_| g.chance(1, 2)).cloned().collect()),
            _ => ArgConstraint::OneOf(vs.iter().map(twin).collect()),
        },
        ArgConstraint::OneOf(_) => ArgConstraint::OneOf(Vec::new()),
        ArgConstraint::Prefix(p) => {
            let tail = *g.pick(&["", "a", "/", "/a", "ab"]);
            let q = format!("{p}{tail}");
            match g.below(4) {
                0 => ArgConstraint::Prefix(q),
                1 => ArgConstraint::Equals(Value::String(q)),
                2 => ArgConstraint::PathPrefix(q),
                _ => ArgConstraint::OneOf(vec![Value::String(q), Value::String(format!("{p}b"))]),
            }
        }
        ArgConstraint::PathPrefix(p) => {
            let q = extend_path(g, p);
            match g.below(4) {
                0 | 1 => ArgConstraint::PathPrefix(q),
                2 => ArgConstraint::Equals(Value::String(q)),
                _ => ArgConstraint::OneOf(vec![Value::String(q), Value::String(p.clone())]),
            }
        }
        ArgConstraint::Range { min, max } => {
            let lo = min.unwrap_or(i64::MIN);
            let hi = max.unwrap_or(i64::MAX);
            let a = lo.saturating_add(g.below(3) as i64);
            let b = hi.saturating_sub(g.below(3) as i64);
            match g.below(4) {
                0 => ArgConstraint::Range {
                    min: Some(a),
                    max: Some(b),
                },
                1 => ArgConstraint::Range {
                    min: Some(a),
                    max: Some(a),
                },
                2 => ArgConstraint::Equals(twin(&Value::from(a))),
                _ => ArgConstraint::OneOf(vec![Value::from(a), twin(&Value::from(b))]),
            }
        }
    }
}

/// A constraint just wider than `c`, or of a neighbouring kind: a near miss.
fn widen(g: &mut Gen, c: &ArgConstraint) -> ArgConstraint {
    match c {
        ArgConstraint::Equals(v) => match g.below(2) {
            0 => ArgConstraint::Equals(neighbour(g, v)),
            _ => ArgConstraint::OneOf(vec![v.clone(), neighbour(g, v)]),
        },
        ArgConstraint::OneOf(vs) => {
            let mut vs = vs.clone();
            vs.push(value(g));
            ArgConstraint::OneOf(vs)
        }
        ArgConstraint::Prefix(p) => {
            let mut q = p.clone();
            q.pop();
            match g.below(3) {
                0 => ArgConstraint::Prefix(q),
                1 => ArgConstraint::PathPrefix(p.clone()),
                _ => ArgConstraint::Prefix(format!("{p}-")),
            }
        }
        ArgConstraint::PathPrefix(p) => match g.below(4) {
            0 => ArgConstraint::Prefix(p.clone()),
            1 => ArgConstraint::PathPrefix(format!("{p}-")),
            2 => ArgConstraint::PathPrefix(
                p.trim_end_matches('/')
                    .rsplit_once('/')
                    .map_or("/", |(a, _)| a)
                    .to_owned(),
            ),
            _ => ArgConstraint::Equals(Value::String(format!("{p}/../x"))),
        },
        ArgConstraint::Range { min, max } => match g.below(3) {
            0 => ArgConstraint::Range {
                min: min.map(|m| m.saturating_sub(1)),
                max: *max,
            },
            1 => ArgConstraint::Range {
                min: *min,
                max: max.map(|m| m.saturating_add(1)),
            },
            _ => {
                ArgConstraint::Equals(Value::from(min.unwrap_or(i64::MIN).saturating_sub(1) as f64))
            }
        },
    }
}

// ---------------------------------------------------------------- patterns and capabilities

/// Valid server and tool patterns, the shared pool plus a few longer and method-like ones.
const MORE_PATTERNS: &[&str] = &["abc*", "a.b", "a-b*", "ba", "abd", "res*"];
const CALL_PATTERNS: &[&str] = &["res/read", "res/*", "res/re*"];
/// Names a call may carry, some invalid (the case carries `check_names`).
const CALL_NAMES: &[&str] = &[
    "a", "ab", "abc", "abd", "b", "ba", "a.b", "a-b", "res", "res/read", "", "*", "a*", "a b",
    "a/", "é",
];

fn pattern(g: &mut Gen, call: bool) -> String {
    match g.below(if call { 6 } else { 5 }) {
        0..=2 => g.draw(name()),
        3 | 4 => (*g.pick(MORE_PATTERNS)).to_owned(),
        _ => (*g.pick(CALL_PATTERNS)).to_owned(),
    }
}

fn valid_pattern(p: &str, call: bool) -> bool {
    if call {
        check_call_pattern(p).is_ok()
    } else {
        check_server_pattern(p).is_ok()
    }
}

/// A pattern meant to be covered by `p`. A narrowed pattern `names.rs` refuses (`res/` from
/// `res/*`) is outside the model: it is counted and replaced by `p`.
fn narrow_pattern(g: &mut Gen, p: &str, call: bool) -> String {
    if g.chance(1, 4) {
        return pattern(g, call);
    }
    let q = narrow_pattern_text(g, p);
    if valid_pattern(&q, call) {
        q
    } else {
        g.exclude("pattern refused by names.rs");
        p.to_owned()
    }
}

fn narrow_pattern_text(g: &mut Gen, p: &str) -> String {
    match p.strip_suffix('*') {
        Some(stem) => match g.below(3) {
            0 => format!("{stem}{}*", g.pick(&["", "a", "b"])),
            1 => format!("{stem}{}", g.pick(&["a", "b", "c"])),
            _ if !stem.is_empty() => stem.to_owned(),
            _ => "a".to_owned(),
        },
        None => p.to_owned(),
    }
}

fn limits(g: &mut Gen) -> Limits {
    Limits {
        calls: g.chance(1, 3).then(|| g.below(4) as u64),
        ..Limits::default()
    }
}

fn capability(g: &mut Gen) -> Capability {
    let mut constraints = BTreeMap::new();
    for arg in ARGS {
        if g.chance(1, 2) {
            constraints.insert((*arg).to_owned(), constraint(g));
        }
    }
    Capability {
        server: pattern(g, false),
        tool: pattern(g, true),
        constraints,
        limits: limits(g),
    }
}

/// A capability meant to be covered by `p`, with some near misses: a dropped or widened
/// constraint, a wider pattern, a larger `calls`.
fn narrow_capability(g: &mut Gen, p: &Capability) -> Capability {
    let mut constraints = BTreeMap::new();
    for (arg, c) in &p.constraints {
        match g.below(12) {
            0 => {}
            1 => {
                constraints.insert(arg.clone(), widen(g, c));
            }
            2 => {
                constraints.insert(arg.clone(), c.clone());
            }
            _ => {
                constraints.insert(arg.clone(), narrow(g, c));
            }
        }
    }
    if g.chance(1, 4) {
        constraints.insert("z".to_owned(), constraint(g));
    }
    let calls = match g.below(6) {
        0 => None,
        1 => p.limits.calls.map(|c| c + 1),
        2 => Some(g.below(4) as u64),
        _ => p.limits.calls.map(|c| c.saturating_sub(g.below(2) as u64)),
    };
    let server = if g.chance(1, 10) {
        pattern(g, false)
    } else {
        narrow_pattern(g, &p.server, false)
    };
    let tool = if g.chance(1, 10) {
        pattern(g, true)
    } else {
        narrow_pattern(g, &p.tool, true)
    };
    Capability {
        server,
        tool,
        constraints,
        limits: Limits {
            calls,
            ..Limits::default()
        },
    }
}

fn capability_set(g: &mut Gen) -> CapabilitySet {
    (0..1 + g.below(3)).map(|_| capability(g)).collect()
}

/// A set meant to be covered by `p`: members narrowed from members of `p`, sometimes with one
/// unrelated capability.
fn narrow_set(g: &mut Gen, p: &CapabilitySet) -> CapabilitySet {
    let parents: Vec<&Capability> = p.iter().collect();
    let mut out: CapabilitySet = (0..1 + g.below(3))
        .map(|_| {
            let parent = *g.pick(&parents);
            narrow_capability(g, parent)
        })
        .collect();
    if g.chance(1, 8) {
        out.insert(capability(g));
    }
    out
}

/// A name a pattern matches, or nearly matches.
fn name_for(g: &mut Gen, pattern: &str) -> String {
    if g.chance(1, 4) {
        return (*g.pick(CALL_NAMES)).to_owned();
    }
    match pattern.strip_suffix('*') {
        Some(stem) => format!("{stem}{}", g.pick(&["", "a", "b", "/x"])),
        None => {
            let mut s = pattern.to_owned();
            if g.chance(1, 4) {
                s.push('a');
            }
            s
        }
    }
}

/// A call meant to be permitted by `c`, with arguments at the edges of its constraints.
fn call_for(g: &mut Gen, c: &Capability) -> ToolCall {
    let mut arguments = BTreeMap::new();
    for (arg, k) in &c.constraints {
        if !g.chance(1, 10) {
            arguments.insert(arg.clone(), value_for(g, k));
        }
    }
    if g.chance(1, 3) {
        arguments.insert("w".to_owned(), value(g));
    }
    ToolCall {
        server: name_for(g, &c.server),
        tool: name_for(g, &c.tool),
        arguments,
        session_id: None,
        dpop_bound: false,
    }
}

// ---------------------------------------------------------------- encoding

/// A string token: `s:` and the string, `\` written `\\`, a space `\s`, and any character
/// outside printable ASCII `\x` with six hex digits.
fn encode_str(s: &str) -> String {
    let mut out = String::from("s:");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push_str("\\s"),
            '!'..='~' => out.push(c),
            _ => write!(out, "\\x{:06x}", u32::from(c)).expect("write to a String"),
        }
    }
    out
}

fn encode_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                format!("i:{i}")
            } else if let Some(u) = n.as_u64() {
                format!("i:{u}")
            } else {
                let f = n.as_f64().expect("a number is an i64, a u64 or an f64");
                assert!(f.is_finite(), "serde_json holds finite floats only");
                format!("f:{}:{f:?}", f.to_bits())
            }
        }
        Value::String(s) => encode_str(s),
        Value::Array(_) | Value::Object(_) => {
            panic!("arrays and objects are outside the model and never drawn: {v}")
        }
    }
}

fn encode_bound(b: Option<i64>) -> String {
    b.map_or_else(|| "-".to_owned(), |n| n.to_string())
}

fn encode_constraint(c: &ArgConstraint) -> String {
    match c {
        ArgConstraint::Equals(v) => format!("eq {}", encode_value(v)),
        ArgConstraint::OneOf(vs) => {
            let mut s = format!("oneof {}", vs.len());
            for v in vs {
                s.push(' ');
                s.push_str(&encode_value(v));
            }
            s
        }
        ArgConstraint::Prefix(p) => format!("prefix {}", encode_str(p)),
        ArgConstraint::PathPrefix(p) => format!("pathprefix {}", encode_str(p)),
        ArgConstraint::Range { min, max } => {
            format!("range {} {}", encode_bound(*min), encode_bound(*max))
        }
    }
}

fn encode_limits(l: &Limits) -> String {
    assert!(
        l.sum.is_none() && l.calls_per.is_none() && l.distinct.is_none(),
        "only `calls` limits are in the model"
    );
    l.calls
        .map_or_else(|| "-".to_owned(), |n| format!("calls:{n}"))
}

/// A capability's server or tool pattern; one `names.rs` refuses is outside the model.
fn encode_pattern(p: &str, call: bool) -> String {
    assert!(
        valid_pattern(p, call),
        "pattern {p:?} is not valid and outside the model"
    );
    encode_str(p)
}

fn encode_capability(c: &Capability) -> String {
    let mut s = format!(
        "cap {} {} {} {}",
        encode_pattern(&c.server, false),
        encode_pattern(&c.tool, true),
        encode_limits(&c.limits),
        c.constraints.len()
    );
    for (arg, k) in &c.constraints {
        write!(s, " {} {}", encode_str(arg), encode_constraint(k)).expect("write to a String");
    }
    s
}

fn encode_set(set: &CapabilitySet) -> String {
    let mut s = format!("set {}", set.len());
    for c in set.iter() {
        s.push(' ');
        s.push_str(&encode_capability(c));
    }
    s
}

fn encode_call(c: &ToolCall) -> String {
    let mut s = format!(
        "call {} {} {} {}",
        encode_str(&c.server),
        encode_str(&c.tool),
        u8::from(c.check_names().is_ok()),
        c.arguments.len()
    );
    for (arg, v) in &c.arguments {
        write!(s, " {} {}", encode_str(arg), encode_value(v)).expect("write to a String");
    }
    s
}

// ---------------------------------------------------------------- cases

struct Cases {
    out: String,
    excluded: BTreeMap<&'static str, usize>,
    counts: BTreeMap<&'static str, usize>,
    answers: BTreeMap<(&'static str, String), usize>,
}

impl Cases {
    fn push(&mut self, func: &'static str, args: &str, answer: &str) {
        writeln!(self.out, "{func} {args} = {answer}").expect("write to a String");
        *self.counts.entry(func).or_default() += 1;
        *self.answers.entry((func, answer.to_owned())).or_default() += 1;
    }
}

fn answer(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

/// `pattern_covers` is private; `covers_calls` of two capabilities with no constraints and a
/// tool pattern of `*` is exactly `pattern_covers` of their server patterns.
fn pattern_covers(parent: &str, child: &str) -> bool {
    Capability::new(parent, "*").covers_calls(&Capability::new(child, "*"))
}

fn generate() -> Cases {
    let mut g = Gen::new(SEED);
    let mut cases = Cases {
        out: String::new(),
        excluded: BTreeMap::new(),
        counts: BTreeMap::new(),
        answers: BTreeMap::new(),
    };

    for _ in 0..SAT {
        let c = constraint(&mut g);
        let v = value_for(&mut g, &c);
        let args = format!("{} {}", encode_constraint(&c), encode_value(&v));
        cases.push("sat", &args, answer(c.satisfied_by(&v)));
    }

    for i in 0..IMPLIES {
        let (c, d) = match i % 7 {
            0 => {
                let d = constraint(&mut g);
                (narrow(&mut g, &d), d)
            }
            1 => {
                let d = constraint(&mut g);
                (widen(&mut g, &d), d)
            }
            2 => {
                let c = constraint(&mut g);
                let d = narrow(&mut g, &c);
                (c, d)
            }
            3 => g.draw(related_path_constraints()),
            4 => (edge_constraint(&mut g), edge_constraint(&mut g)),
            // `equals` a large integer under a range: implied only when no float equals it
            // (SR-71), which is where `hasFloat` in the model must agree with `format_f64`.
            5 => {
                let n = int_with_float_twin(&mut g);
                let n = match n.as_i64() {
                    Some(i) => Value::from(i.saturating_add(g.below(3) as i64 - 1)),
                    None => n,
                };
                let wide = ArgConstraint::Range {
                    min: g.chance(1, 2).then_some(i64::MIN),
                    max: Some(i64::MAX),
                };
                (ArgConstraint::Equals(n), wide)
            }
            _ => (constraint(&mut g), constraint(&mut g)),
        };
        let args = format!("{} {}", encode_constraint(&c), encode_constraint(&d));
        cases.push("implies", &args, answer(c.implies(&d)));
    }

    let call_pattern_pool: Vec<&str> = NAMES
        .iter()
        .chain(MORE_PATTERNS)
        .chain(CALL_PATTERNS)
        .copied()
        .collect();
    for _ in 0..PMATCH {
        let p = *g.pick(&call_pattern_pool);
        let n = name_for(&mut g, p);
        let args = format!("{} {}", encode_pattern(p, true), encode_str(&n));
        cases.push("pmatch", &args, answer(pattern_matches(p, &n)));
    }

    for _ in 0..PCOVERS {
        let p = pattern(&mut g, false);
        let c = narrow_pattern(&mut g, &p, false);
        let args = format!(
            "{} {}",
            encode_pattern(&p, false),
            encode_pattern(&c, false)
        );
        cases.push("pcovers", &args, answer(pattern_covers(&p, &c)));
    }

    for _ in 0..CPERMITS {
        let c = capability(&mut g);
        let call = call_for(&mut g, &c);
        let args = format!("{} {}", encode_capability(&c), encode_call(&call));
        cases.push("cpermits", &args, answer(c.permits(&call)));
    }

    for i in 0..CCOVERS {
        let p = capability(&mut g);
        let c = if i % 5 == 0 {
            capability(&mut g)
        } else {
            narrow_capability(&mut g, &p)
        };
        let args = format!("{} {}", encode_capability(&p), encode_capability(&c));
        cases.push("ccovers", &args, answer(p.covers(&c)));
    }

    for _ in 0..SPERMITS {
        let s = capability_set(&mut g);
        let member = s.iter().nth(g.below(s.len())).expect("a member").clone();
        let call = call_for(&mut g, &member);
        let args = format!("{} {}", encode_set(&s), encode_call(&call));
        cases.push("spermits", &args, answer(s.permits(&call)));
    }

    for i in 0..SCOVERS {
        let p = capability_set(&mut g);
        let c = if i % 5 == 0 {
            capability_set(&mut g)
        } else {
            narrow_set(&mut g, &p)
        };
        let args = format!("{} {}", encode_set(&p), encode_set(&c));
        cases.push("scovers", &args, answer(p.covers(&c)));
    }

    for i in 0..ATTEN {
        let p = capability_set(&mut g);
        let r = match i % 10 {
            0 => CapabilitySet::new(),
            1 => capability_set(&mut g),
            2 => p.clone(),
            _ => narrow_set(&mut g, &p),
        };
        let (result, ans) = match p.attenuate(&r) {
            Ok(out) => (encode_set(&out), "ok"),
            Err(AttenuationError::Empty) => ("-".to_owned(), "err:empty"),
            Err(AttenuationError::NotCovered { .. }) => ("-".to_owned(), "err:not-covered"),
        };
        let args = format!("{} {} {result}", encode_set(&p), encode_set(&r));
        cases.push("atten", &args, ans);
    }

    cases.excluded = g.excluded;
    cases
}

#[test]
fn writes_the_differential_cases() {
    let cases = generate();
    let path = std::env::var_os("ATTENUO_LEAN_CASES").map_or_else(
        || std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("lean-differential/cases.txt"),
        std::path::PathBuf::from,
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).expect("create the case directory");
    }
    std::fs::write(&path, &cases.out).expect("write the case file");
    println!(
        "{} cases written to {}",
        cases.out.lines().count(),
        path.display()
    );
    for ((func, ans), n) in &cases.answers {
        println!("{func:>9} {ans:<16} {n}");
    }
    for (reason, n) in &cases.excluded {
        println!("replaced as outside the model: {reason}: {n}");
    }

    let expected = [
        ("sat", SAT),
        ("implies", IMPLIES),
        ("pmatch", PMATCH),
        ("pcovers", PCOVERS),
        ("cpermits", CPERMITS),
        ("ccovers", CCOVERS),
        ("spermits", SPERMITS),
        ("scovers", SCOVERS),
        ("atten", ATTEN),
    ];
    for (func, n) in expected {
        assert_eq!(cases.counts.get(func), Some(&n), "{func}");
    }
    // Every boolean function is drawn on both sides of its answer often enough to matter, and
    // `attenuate` succeeds and fails both ways.
    for (func, n) in expected {
        if func == "atten" {
            continue;
        }
        for ans in ["true", "false"] {
            let got = cases
                .answers
                .get(&(func, ans.to_owned()))
                .copied()
                .unwrap_or(0);
            assert!(
                got * 10 >= n,
                "{func}: only {got} of {n} cases answer {ans}"
            );
        }
    }
    for ans in ["ok", "err:empty", "err:not-covered"] {
        let got = cases
            .answers
            .get(&("atten", ans.to_owned()))
            .copied()
            .unwrap_or(0);
        assert!(got * 20 >= ATTEN, "atten: only {got} cases answer {ans}");
    }
}

#[test]
fn the_cases_are_the_same_on_every_run() {
    assert_eq!(generate().out, generate().out);
}

#[test]
fn strings_are_escaped_into_single_tokens() {
    assert_eq!(encode_str("/a b\\c"), "s:/a\\sb\\\\c");
    assert_eq!(encode_str("/a\u{ff0f}\t"), "s:/a\\x00ff0f\\x000009");
    assert_eq!(encode_str(""), "s:");
    let tokens: BTreeSet<&str> = ["null", "true", "false"].into_iter().collect();
    for v in [Value::Null, json!(true), json!(false)] {
        assert!(tokens.contains(encode_value(&v).as_str()));
    }
    assert_eq!(encode_value(&json!(5)), "i:5");
    assert_eq!(encode_value(&json!(u64::MAX)), "i:18446744073709551615");
    assert_eq!(
        encode_value(&json!(5.0)),
        format!("f:{}:5.0", 5.0f64.to_bits())
    );
}
