//! Property tests for run limits and the canonical JSON their counted values are keyed by
//! (fuzzing round 2, `docs/research/fuzzing-2026-10-24-round2.md`): the cases of the
//! `limits_charges` fuzz target that run without a nightly toolchain.
//!
//! - `clamp_to` is idempotent, never widens a child that already narrows, and narrows the
//!   parent whenever the two count the same arguments;
//! - a limit counts every distinct value of a call once, at most `MAX_COUNTED_VALUES`, and a
//!   `sum` charge is exactly the argument's amount;
//! - a derived host is a fixpoint: counting it again gives the same host (FZ2-1);
//! - a derived host and the injection suite's host entity of the same token are the same
//!   host whenever both exist, outside the input classes on which the two grammars are known
//!   to differ (`Derive::Host` lists them);
//! - canonical JSON is a fixpoint, and `jcs::value_eq` agrees with byte equality of the
//!   canonical forms.

use std::collections::{BTreeMap, BTreeSet};

use attenuo_core::fingerprint::{entities, normalise};
use attenuo_core::limits::{amount_of, charges_for, usage_charges, MAX_COUNTED_VALUES, MAX_LIMIT};
use attenuo_core::{
    jcs, AgentId, ArgLimit, Capability, CapabilitySet, DelegationChain, Derive, LeaseId, LimitKind,
    Limits, OriginatingUser, ToolCall,
};
use proptest::prelude::*;
use serde_json::{json, Value};
use time::macros::datetime;
use time::Duration;

mod proptest_seed;
use proptest_seed::proptest_config;

const ARGS: &[&str] = &["to", "url"];

// ---------------------------------------------------------------- strategies

fn max() -> impl Strategy<Value = u64> {
    prop_oneof![4 => 0u64..4, 1 => Just(MAX_LIMIT)]
}

fn arg_limit() -> impl Strategy<Value = ArgLimit> {
    (prop::sample::select(ARGS), max(), any::<bool>()).prop_map(|(arg, max, host)| {
        let l = ArgLimit::new(arg, max);
        if host {
            l.derived(Derive::Host)
        } else {
            l
        }
    })
}

fn limits() -> impl Strategy<Value = Limits> {
    (
        prop::option::of(max()),
        prop::option::of(max()),
        prop::option::of(arg_limit()),
        prop::option::of(arg_limit()),
    )
        .prop_map(|(calls, sum, calls_per, distinct)| Limits {
            calls,
            sum: sum.map(|m| ArgLimit::new("amount", m)),
            calls_per,
            distinct,
        })
}

/// Hosts and URL spellings, including the ones WHATWG normalises (case, dots, ports, user
/// info, IDNA, IP notations).
fn url() -> impl Strategy<Value = String> {
    let host = prop_oneof![
        Just("a.example".to_string()),
        Just("A.EXAMPLE".to_string()),
        Just("b.example".to_string()),
        Just("127.0.0.1".to_string()),
        Just("0x7f.1".to_string()),
        Just("[::1]".to_string()),
        Just("βόλος.example".to_string()),
        Just("xn--nxasmm1c.example".to_string()),
        "[a-z]{1,3}(\\.[a-z]{1,3}){0,2}",
    ];
    (
        prop::sample::select(&["https://", "http://", "HTTPS://", "wss://", "ftp://", ""][..]),
        prop::option::of(Just("user:pw@")),
        host,
        prop::sample::select(&["", ".", "..", "..."][..]),
        prop::sample::select(&["", ":443", ":8080"][..]),
        prop::sample::select(&["/", "/x?y=1", "#f", ""][..]),
    )
        .prop_map(|(scheme, user, host, dots, port, path)| {
            format!("{scheme}{}{host}{dots}{port}{path}", user.unwrap_or(""))
        })
}

/// One token in the shapes on which a URL grammar and a host-entity grammar may disagree:
/// with or without a scheme, user info, IP and IDNA hosts, percent escapes, trailing dots,
/// ports, and a second URL in the path or query. Also short strings of URL punctuation.
fn host_token() -> impl Strategy<Value = String> {
    let label = "[a-zA-Z0-9][a-zA-Z0-9-]{0,4}";
    let host = prop_oneof![
        6 => (prop::collection::vec(label, 1..4), "[a-zA-Z]{2,4}|[0-9]{1,3}|x[a-z]")
            .prop_map(|(ls, tld)| format!("{}.{tld}", ls.join("."))),
        1 => prop::sample::select(&[
            "localhost", "127.0.0.1", "0x7f.1", "127.1", "[::1]", "[::ffff:1.2.3.4]",
            "a.ex%61mple", "%61.example", "βόλος.example", "ａ.example", "xn--nxasmq6b.example",
            "www.true-informations.com", "a-.example", "a.example.com.pdf", "1.2.3",
        ][..]).prop_map(str::to_string),
    ];
    let structured = (
        prop::sample::select(
            &[
                "", "", "", "http://", "https://", "HTTP://", "ws://", "ftp://",
            ][..],
        ),
        prop::sample::select(&["", "", "", "u@", "u:p@", "good.example@", "a.example:80@"][..]),
        host,
        prop::sample::select(&["", "", ".", ".."][..]),
        prop::sample::select(&["", "", ":", ":80", ":8080", ":99999", ":x"][..]),
        prop::sample::select(
            &[
                "",
                "",
                "/",
                "/x/y",
                "?q=1",
                "#f",
                "/?r=https://b.example/",
                "/x/http://c.example",
                "?@evil.example",
                "#@evil.example",
            ][..],
        ),
    )
        .prop_map(|(scheme, user, host, dots, port, tail)| {
            format!("{scheme}{user}{host}{dots}{port}{tail}")
        });
    prop_oneof![
        8 => structured,
        1 => "[a-z0-9.:/?#@%-]{0,16}",
    ]
}

/// The host entity of one token, as the injection suite's matcher takes it: the host of the
/// token's `http(s)://` URL, or else its bare host (`fingerprint::entities`). The token must
/// not contain characters the entity tokeniser splits on.
fn fingerprint_host(token: &str) -> Option<String> {
    let found = entities(&normalise(token));
    if found.first().is_some_and(|e| e.contains("://")) {
        return found.get(1).filter(|h| !h.contains("://")).cloned();
    }
    // A bare host is the one entity with a dot and no `/`, `\` or `@` (paths, emails and
    // digit runs have one of those or no dot).
    found
        .into_iter()
        .find(|e| e.contains('.') && !e.contains(['/', '\\', '@']))
}

/// The input classes on which the two host grammars are known to differ, listed in the
/// `Derive::Host` documentation and in `docs/design/read-side-exfiltration.md` section 3. The
/// property does not force them to agree.
fn grammars_differ_on(token: &str, derived: &str, entity: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    // Percent escapes and non-ASCII: WHATWG decodes them and maps the host through IDNA; the
    // entity keeps the spelling (or, NFKC-normalised, may differ from IDNA's mapping).
    lower.contains('%') || !token.is_ascii()
        // IPv6 literals: the entity tokeniser splits on `[` and `]`.
        || token.contains(['[', ']'])
        // IPv4 in hex, octal or short form: WHATWG rewrites it to dotted decimal.
        || derived.parse::<std::net::Ipv4Addr>().is_ok()
        // Trailing dots in a full URL: the entity keeps them.
        || entity.ends_with('.')
        // A second URL after the token's start: the entity takes the embedded URL's host.
        || lower
            .match_indices("http://")
            .chain(lower.match_indices("https://"))
            .any(|(at, _)| at > 0)
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<u64>().prop_map(|n| json!(n)),
        any::<f64>().prop_map(|f| serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null)),
        prop::sample::select(&[0.5f64, 1.0, -0.0, 1e21, 1e-7, 9007199254740993.0][..])
            .prop_map(|f| json!(f)),
        url().prop_map(Value::String),
        "[a\u{0}\u{1f}\"\\\\é\u{301}]{0,4}".prop_map(Value::String),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[ab]{0,2}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// A value and a near copy: a number respelled, list elements reordered or doubled, object
/// members reordered.
fn value_pair() -> impl Strategy<Value = (Value, Value)> {
    (value(), any::<u8>()).prop_map(|(v, k)| {
        let w = match (&v, k % 4) {
            (Value::Number(n), 0) => n
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            (Value::Array(a), 1) => Value::Array(a.iter().rev().cloned().collect()),
            (Value::Array(a), 2) => Value::Array(a.iter().chain(a.iter()).cloned().collect()),
            (Value::Object(m), _) => Value::Object(
                m.iter()
                    .rev()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            _ => v.clone(),
        };
        (v, w)
    })
}

fn argument() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => url().prop_map(Value::String),
        2 => prop::collection::vec(url().prop_map(Value::String), 0..6).prop_map(Value::Array),
        1 => (MAX_COUNTED_VALUES - 1..=MAX_COUNTED_VALUES + 1).prop_map(|n| Value::Array(
            (0..n).map(|i| json!(format!("https://h{}.example/", i % 300))).collect()
        )),
        2 => leaf(),
        1 => value(),
    ]
}

fn chain(caps: Vec<Capability>) -> DelegationChain {
    DelegationChain::root(
        OriginatingUser {
            subject: "user:p".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: datetime!(2026-10-24 08:00 UTC),
            attributes: BTreeMap::new(),
        },
        AgentId::new("agent:a"),
        CapabilitySet::from_iter(caps),
        datetime!(2026-10-24 09:00 UTC),
        Duration::minutes(10),
        LeaseId::new("lease-root"),
    )
    .expect("root chain")
}

fn canonical(v: &Value) -> Vec<u8> {
    jcs::to_vec(v).expect("canonical form")
}

fn same_targets(child: &Limits, parent: &Limits) -> bool {
    let same = |c: &Option<ArgLimit>, p: &Option<ArgLimit>| match (c, p) {
        (Some(c), Some(p)) => c.arg == p.arg && c.derive == p.derive,
        _ => true,
    };
    same(&child.sum, &parent.sum)
        && same(&child.calls_per, &parent.calls_per)
        && same(&child.distinct, &parent.distinct)
}

// ---------------------------------------------------------------- properties

proptest! {
    #![proptest_config(proptest_config(1024))]

    #[test]
    fn clamping_is_idempotent_and_narrows(child in limits(), parent in limits()) {
        let clamped = Limits::clamp_to(&child, &parent);
        prop_assert_eq!(Limits::clamp_to(&clamped, &parent), clamped.clone());
        if child.narrows(&parent) {
            prop_assert!(clamped.narrows(&child) && clamped.narrows(&parent));
        }
        if same_targets(&child, &parent) {
            prop_assert!(clamped.narrows(&parent), "{:?} -> {:?} under {:?}", child, clamped, parent);
        }
    }

    #[test]
    fn charges_count_each_value_once_and_bounded(
        l in limits(),
        to in argument(),
        url_arg in argument(),
        amount in leaf(),
    ) {
        let chain = chain(vec![Capability::new("mail", "send").with_limits(l.clone())]);
        let call = ToolCall::new("mail", "send", json!({"to": to, "url": url_arg, "amount": amount}));
        if let Ok(charges) = charges_for(&chain, &call) {
            let mut seen: BTreeMap<LimitKind, BTreeSet<Vec<u8>>> = BTreeMap::new();
            for c in &charges {
                match c.kind {
                    LimitKind::Sum => {
                        prop_assert_eq!(Some(c.amount), amount_of(&call.arguments["amount"]));
                    }
                    LimitKind::CallsPer | LimitKind::Distinct => {
                        let v = c.value.clone().expect("a value");
                        let back: Value = serde_json::from_slice(&v).unwrap();
                        prop_assert_eq!(canonical(&back), v.clone());
                        let set = seen.entry(c.kind).or_default();
                        prop_assert!(set.insert(v), "a value counted twice");
                        prop_assert!(set.len() <= MAX_COUNTED_VALUES);
                    }
                    LimitKind::Calls => prop_assert_eq!(c.amount, 1),
                }
            }
        }
        let usage = usage_charges(&LeaseId::new("run"), &call, Some("amount"), Some("url#host"));
        let dests: Vec<_> = usage.iter().filter_map(|c| c.value.clone()).collect();
        prop_assert!(dests.len() <= MAX_COUNTED_VALUES);
        prop_assert_eq!(dests.iter().collect::<BTreeSet<_>>().len(), dests.len());
    }

    #[test]
    fn a_derived_host_is_a_fixpoint(u in url()) {
        if let Some(host) = Derive::Host.apply(&json!(u)) {
            prop_assert!(!host.is_empty() && !host.ends_with('.'));
            prop_assert_eq!(host.clone(), host.to_ascii_lowercase());
            let again = Derive::Host.apply(&json!(format!("https://{host}/")));
            prop_assert_eq!(again, Some(host));
        }
    }

    /// The two host grammars (`Derive::Host` for limits and destinations, the host entities of
    /// `fingerprint` for argument taint) name the same host for a token whenever both name one,
    /// outside the classes `grammars_differ_on` excludes.
    #[test]
    fn derived_host_agrees_with_the_fingerprint_host(token in host_token()) {
        let derived = Derive::Host.apply(&json!(token));
        let entity = fingerprint_host(&token);
        if let (Some(d), Some(e)) = (derived, entity) {
            if !grammars_differ_on(&token, &d, &e) {
                prop_assert_eq!(d, e, "token {:?}", token);
            }
        }
    }

    #[test]
    fn canonical_json_is_a_fixpoint_and_matches_value_eq((a, b) in value_pair(), c in value()) {
        let (ca, cb, cc) = (canonical(&a), canonical(&b), canonical(&c));
        let back: Value = serde_json::from_slice(&ca).unwrap();
        prop_assert_eq!(canonical(&back), ca.clone());
        prop_assert_eq!(jcs::value_eq(&a, &b), ca == cb);
        prop_assert_eq!(jcs::value_eq(&a, &c), ca == cc);
    }
}
