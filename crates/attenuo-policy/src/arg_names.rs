//! Argument names that differ only in case from a name the decision reads (SR-133's remainder).
//!
//! JSON member names are case-sensitive, and every stage of the decision reads an argument by
//! its exact name: a capability constraint or a run limit on `path`, a catalog input type, a
//! `decimal` input, an outbound input (and its `#host`), `amount` and `destination`, and a
//! Cedar policy that reads `context.input.path` or tests `context.untrusted_args` for
//! `"path"`. An upstream that matches member names without regard to case (Go's
//! `encoding/json` decoding the arguments into a struct) reads an argument `Path` as its field
//! `path`. SR-133's fix refuses `path` and `Path` together; with `Path` alone, every check
//! written as "if `path` is present, it must satisfy X" saw no `path` and passed.
//!
//! So a call is refused (`argument_case_mismatch`, before the capability stage) when a
//! top-level argument name is not one the decision knows for the tool but differs only in case
//! from one it does ([`check`]). The names the decision knows for a call are:
//!
//! - the tool's catalog entry: `inputs`, `amount`, `destination` and `outbound` (without
//!   `#host`) ([`ToolAttrs::argument_names`]);
//! - every constraint and every `sum`, `calls_per` and `distinct` limit of every capability, at
//!   any hop of the chain, whose server and tool patterns match the call;
//! - every name a loaded policy reads under `context.input` or compares with
//!   `context.untrusted_args`, whatever action the policy is for ([`PolicyArgNames`]). Cedar's
//!   strict validation does not bound these by the catalog: a read guarded by `has` of an
//!   undeclared name loads (with a "policy is impossible" warning) and runs, since evaluation is
//!   schema-free. Only a read the policy's text names is collected: an attribute chain from
//!   `context` (`context.input.path`, `context.input["path"]`, `context has input.path`) and a
//!   string literal on the other side of a comparison or a set method with
//!   `context.untrusted_args` itself. A whole-record comparison, a read through an expression
//!   that yields the record or the set (a conditional, a record literal), and a name computed at
//!   evaluation time are not (SR-138; the threat model says so).
//!
//! An exact name the tool's own entry or capabilities know passes even when a policy for
//! another tool reads a name that differs from it only in case; a name that matches none
//! passes as before. Names below the top level of `arguments` are not looked at: nothing in
//! the decision reads one by name (the catalog types no record input, so no policy can
//! validate a read of one; `equals` and `one_of` compare a whole value, member names exactly;
//! `prefix`, `path_prefix`, `range`, `#host` and `sum` read only strings and numbers).

use std::collections::{BTreeSet, HashMap};

use attenuo_core::capability::pattern_matches;
use attenuo_core::{DelegationChain, ToolCall};
use cedar_policy::PolicySet;
use serde_json::Value;

use crate::catalog::ToolAttrs;

/// A name with case folded: two names with one key are one name to a decoder that matches
/// names without regard to case. Go's `encoding/json` joins two names that are equal rune by
/// rune under Unicode simple case folding (`ſ` with `s`, the Kelvin sign with `k`, `ẞ` with
/// `ß`); lower, upper, then lower case gives each such pair one key, as the proxy's SR-133
/// check does (SR-137: upper then lower case alone gave `ẞ` and `ß` two keys). Full case
/// mapping also joins `ß` with `ss` and a ligature with its letters, which Go does not; that
/// can only refuse more.
pub(crate) fn fold(name: &str) -> String {
    name.to_lowercase().to_uppercase().to_lowercase()
}

/// The argument names the loaded policies read, by folded name: every `context.input.<name>`
/// (or `context.input has <name>`, `context.input["<name>"]`), and every string literal on the
/// other side of a comparison or a set method with `context.untrusted_args`
/// (`context.untrusted_args.contains("path")`). Collected once per load from Cedar's JSON form.
#[derive(Debug, Clone, Default)]
pub(crate) struct PolicyArgNames {
    by_fold: HashMap<String, BTreeSet<String>>,
}

impl PolicyArgNames {
    /// The names `policies` read.
    ///
    /// # Errors
    ///
    /// The set cannot be rendered as JSON, so the names it reads cannot be known; the load
    /// is refused rather than decided without them.
    pub(crate) fn of(policies: &PolicySet) -> Result<Self, String> {
        let v = policies
            .clone()
            .to_json()
            .map_err(|e| format!("cannot read which argument names the policies use: {e}"))?;
        let mut names = BTreeSet::new();
        collect(&v, &mut names);
        let mut by_fold: HashMap<String, BTreeSet<String>> = HashMap::new();
        for n in names {
            by_fold.entry(fold(&n)).or_default().insert(n);
        }
        Ok(Self { by_fold })
    }

    fn with_fold(&self, folded: &str) -> impl Iterator<Item = &str> {
        self.by_fold
            .get(folded)
            .into_iter()
            .flatten()
            .map(String::as_str)
    }
}

/// Collect the names read under `context.input`, and the string literals compared with
/// `context.untrusted_args`, from Cedar's JSON (EST) form.
fn collect(v: &Value, out: &mut BTreeSet<String>) {
    if let Some(path) = crate::usage::context_path(v) {
        if let [Some(input), Some(name), ..] = path.as_slice() {
            if input == "input" {
                out.insert(name.clone());
            }
        }
        return;
    }
    match v {
        Value::Object(map) => {
            for inner in map.values() {
                if let (Some(l), Some(r)) = (inner.get("left"), inner.get("right")) {
                    for (side, other) in [(l, r), (r, l)] {
                        if is_untrusted_args(side) {
                            strings(other, out);
                        }
                    }
                }
            }
            map.values().for_each(|x| collect(x, out));
        }
        Value::Array(items) => items.iter().for_each(|x| collect(x, out)),
        _ => {}
    }
}

fn is_untrusted_args(v: &Value) -> bool {
    crate::usage::context_path(v)
        .is_some_and(|p| p.len() == 1 && p[0].as_deref() == Some("untrusted_args"))
}

/// Every string literal in an expression (`"path"`, `["path", "url"]`).
fn strings(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("Value") {
                out.insert(s.clone());
            }
            map.values().for_each(|x| strings(x, out));
        }
        Value::Array(items) => items.iter().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// Refuse a call with a top-level argument name that is not one the decision knows for the
/// tool but differs only in case from one it does (see the module docs). `entry` is the tool's
/// catalog entry, `None` when the catalog has none. Returns the diagnostic, which names the
/// two names (never a value).
pub(crate) fn check(
    call: &ToolCall,
    chain: &DelegationChain,
    entry: Option<&ToolAttrs>,
    policies: &PolicyArgNames,
) -> Result<(), String> {
    if call.arguments.is_empty() {
        return Ok(());
    }
    // The names this tool's own entry and capabilities read.
    let mut own: BTreeSet<&str> = BTreeSet::new();
    if let Some(attrs) = entry {
        own.extend(attrs.argument_names());
    }
    for hop in &chain.hops {
        for cap in hop.capabilities.iter() {
            if !(pattern_matches(&cap.server, &call.server)
                && pattern_matches(&cap.tool, &call.tool))
            {
                continue;
            }
            own.extend(cap.constraints.keys().map(String::as_str));
            let l = &cap.limits;
            own.extend(
                [&l.sum, &l.calls_per, &l.distinct]
                    .into_iter()
                    .flatten()
                    .map(|a| a.arg.as_str()),
            );
        }
    }
    let mut own_by_fold: HashMap<String, Vec<&str>> = HashMap::new();
    for n in &own {
        own_by_fold.entry(fold(n)).or_default().push(n);
    }
    for name in call.arguments.keys() {
        let folded = fold(name);
        let own_variants = own_by_fold.get(&folded).map(Vec::as_slice).unwrap_or(&[]);
        // An exact name of the tool's own, with no other name of its own in another case.
        if own_variants == [name.as_str()] {
            continue;
        }
        let other = own_variants
            .iter()
            .copied()
            .chain(policies.with_fold(&folded))
            .find(|k| *k != name);
        if let Some(known) = other {
            return Err(format!(
                "argument {name:?} differs only in case from {known:?}, a name the decision \
                 reads for {}:{}; send it as the tool declares it",
                call.server, call.tool
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn collected(src: &str) -> BTreeSet<String> {
        let set = PolicySet::from_str(src).unwrap_or_else(|e| panic!("{src}: {e}"));
        let names = PolicyArgNames::of(&set).unwrap();
        names.by_fold.into_values().flatten().collect()
    }

    /// Pass 20, 1a: every Cedar expression form that can read `context.input` or
    /// `context.untrusted_args`, and whether the name it reads is collected. A `false` row is a
    /// form whose name cannot be known from the text (a name computed at evaluation time) or
    /// that reaches the record through another expression; the threat model names them.
    #[test]
    fn every_expression_form_is_collected_or_named_as_a_limit_sr138() {
        let when = |cond: &str| format!("forbid(principal, action, resource) when {{ {cond} }};");
        let rows: &[(&str, &str, &[&str])] = &[
            // context.input: attribute access, has, index with a string.
            ("attribute", "context.input.path == \"x\"", &["path"]),
            ("has", "context.input has path", &["path"]),
            ("has with a string", "context.input has \"path\"", &["path"]),
            ("index", "context.input[\"path\"] == \"x\"", &["path"]),
            (
                "index on context",
                "context[\"input\"][\"path\"] == \"x\"",
                &["path"],
            ),
            ("has on a path", "context has input.path", &["path"]),
            ("negated has", "!(context.input has path)", &["path"]),
            ("like", "context.input.path like \"/etc/*\"", &["path"]),
            ("in", "context.input.dir in Dir::\"etc\"", &["dir"]),
            (
                "contains on a member",
                "context.input.tags.contains(\"a\")",
                &["tags"],
            ),
            (
                "containsAll on a member",
                "context.input.tags.containsAll([\"a\"])",
                &["tags"],
            ),
            (
                "containsAny on a member",
                "[\"a\"].containsAny(context.input.tags)",
                &["tags"],
            ),
            (
                "extension call",
                "decimal(context.input.price) > decimal(\"1.0\")",
                &["price"],
            ),
            ("ip", "ip(context.input.host).isLoopback()", &["host"]),
            (
                "member against member",
                "context.input.a == context.input.B",
                &["B", "a"],
            ),
            (
                "if/then/else",
                "if context.input has path then context.input.path == \"x\" else false",
                &["path"],
            ),
            // context.untrusted_args: comparison and every set method, both ways round.
            (
                "untrusted ==",
                "context.untrusted_args == [\"path\"]",
                &["path"],
            ),
            (
                "untrusted !=",
                "[\"path\"] != context.untrusted_args",
                &["path"],
            ),
            (
                "untrusted contains",
                "context.untrusted_args.contains(\"path\")",
                &["path"],
            ),
            (
                "untrusted containsAll",
                "context.untrusted_args.containsAll([\"path\", \"url\"])",
                &["path", "url"],
            ),
            (
                "untrusted containsAny reversed",
                "[\"url\"].containsAny(context.untrusted_args)",
                &["url"],
            ),
            (
                "untrusted in",
                "\"path\" in context.untrusted_args",
                &["path"],
            ),
            (
                "untrusted with a conditional name",
                "context.untrusted_args.contains(if principal has x then \"path\" else \"url\")",
                &["path", "url"],
            ),
            ("untrusted isEmpty", "context.untrusted_args.isEmpty()", &[]),
            // Not collected: the limits the threat model names.
            (
                "whole record",
                "context.input == {\"path\": \"/etc/passwd\"}",
                &[],
            ),
            (
                "record through a conditional",
                "(if principal has x then context.input else context.input) has path",
                &[],
            ),
            (
                "record through a record literal",
                "{\"r\": context.input}.r has path",
                &[],
            ),
            (
                "untrusted through a conditional",
                "(if principal has x then context.untrusted_args else []).contains(\"path\")",
                &[],
            ),
            (
                "computed name",
                "context.untrusted_args.contains(principal.watched_arg)",
                &[],
            ),
        ];
        for (form, cond, want) in rows {
            let got = collected(&when(cond));
            let want: BTreeSet<String> = want.iter().map(|s| s.to_string()).collect();
            assert_eq!(got, want, "{form}: {cond}");
        }
        // A template's body is read like a static policy's, linked or not.
        let template = r#"@id("t")
            forbid(principal == ?principal, action, resource) when { context.input has path };"#;
        assert_eq!(collected(template), BTreeSet::from(["path".to_string()]));
        let mut set = PolicySet::new();
        set.add_template(
            cedar_policy::Template::parse(Some(cedar_policy::PolicyId::new("t")), template)
                .unwrap(),
        )
        .unwrap();
        set.link(
            cedar_policy::PolicyId::new("t"),
            cedar_policy::PolicyId::new("t1"),
            HashMap::from([(
                cedar_policy::SlotId::principal(),
                cedar_policy::EntityUid::from_str("User::\"a\"").unwrap(),
            )]),
        )
        .unwrap();
        let names = PolicyArgNames::of(&set).unwrap();
        assert_eq!(names.with_fold("path").collect::<Vec<_>>(), ["path"]);
    }

    /// Pass 20, 1b: Go's `encoding/json` matches a member to a field whose name has the same
    /// key under `foldName`: ASCII letters upper-cased, every other rune replaced by the
    /// smallest rune of its `unicode.SimpleFold` orbit, so two names match when they are equal
    /// rune by rune under simple case folding. Each group is one such orbit (or a name built
    /// from them) and must give one key here. Upper then lower case alone gave `ß` the key
    /// `ss` and `ẞ` the key `ß`, which Go joins (SR-137).
    #[test]
    fn the_fold_joins_every_name_go_joins_sr137() {
        for group in [
            &["straße", "straẞe", "STRAẞE", "STRAßE"][..],
            &["ask", "a\u{17f}k", "ASK"],
            &["key", "\u{212a}ey", "KEY"],
            &["\u{e5}", "\u{c5}", "\u{212b}"],
            &["\u{3c9}", "\u{3a9}", "\u{2126}"],
            &["\u{3c3}", "\u{3c2}", "\u{3a3}"],
            &["\u{3b1}\u{3c2}", "\u{3b1}\u{3c3}", "\u{391}\u{3a3}"],
            &["\u{3c3}\u{3b1}", "\u{3c2}\u{3b1}"],
            &["\u{1c6}", "\u{1c5}", "\u{1c4}"],
            &["\u{1fb3}", "\u{1fbc}"],
            &["\u{3b8}", "\u{3d1}", "\u{3f4}", "\u{398}"],
            &["\u{3b9}", "\u{345}", "\u{1fbe}", "\u{399}"],
            &["\u{b5}", "\u{3bc}", "\u{39c}"],
            &["\u{1e61}", "\u{1e9b}", "\u{1e60}"],
            &["\u{432}", "\u{1c80}", "\u{412}"],
        ] {
            let keys: BTreeSet<String> = group.iter().map(|n| fold(n)).collect();
            assert_eq!(keys.len(), 1, "{group:?} gave {keys:?}");
        }
        // Where the fold joins more than Go does, it can only refuse more: full case mapping
        // makes `ß` one with `ss` and a ligature one with its letters, and the dotless `ı`
        // upper-cases to `I`. Go keeps each of these apart; so does the fold with `İ`.
        for (a, b, joined) in [
            ("stra\u{df}e", "strasse", true),
            ("\u{fb01}le", "file", true),
            ("\u{131}d", "id", true),
            ("\u{130}d", "id", false),
            ("path", "pat", false),
        ] {
            assert_eq!(fold(a) == fold(b), joined, "{a} {b}");
        }
    }
}
