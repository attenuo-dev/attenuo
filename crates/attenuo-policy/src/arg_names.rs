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
//!   schema-free.
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
/// names without regard to case. Upper then lower case, so that the folds Go's
/// `encoding/json` makes (`ſ` to `s`, the Kelvin sign to `k`) give one key too, as the
/// proxy's SR-133 check does; `ß` and `ss` also give one key, which can only refuse more.
pub(crate) fn fold(name: &str) -> String {
    name.to_uppercase().to_lowercase()
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
