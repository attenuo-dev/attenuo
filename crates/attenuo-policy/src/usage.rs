//! Whether run usage (`context.usage`, run-limits design section 3.5) can matter to a loaded
//! policy set, decided once per load.
//!
//! The server keeps run usage in the lease store: every allowed call of a destructive tool
//! pays one write transaction for it. When nothing can read the figures, that write is pure
//! cost, so the engine decides at build and at every reload whether usage is *tracked*
//! ([`crate::PolicyEngine::tracks_usage`]). It is, when any of these holds:
//!
//! - some loaded policy (or template) reads `context.usage`: [`policies_read_usage`];
//! - the catalog declares `amount` or `destination` for some tool, which only exists to feed
//!   `context.usage` (an operator who names them means to read them, perhaps in a policy
//!   loaded later);
//! - `[policy] track_usage = true` ([`TrackUsage::Always`]).
//!
//! The policy check is a walk of Cedar's JSON form of each policy, conservative in the safe
//! direction: `context.usage`, `context["usage"]` and `context has usage` count, and so does
//! any use of `context` other than reading or testing one named attribute (for example
//! `context == {...}`), which could observe the record whole. A policy set that cannot be
//! rendered as JSON counts as reading usage. Untracked usage is not a weaker policy: no loaded
//! policy can tell the zeros it then sees from real figures.

use attenuo_core::WindowKind;
use cedar_policy::PolicySet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// `[policy] track_usage`: whether the server keeps run usage (`context.usage`) for calls to
/// destructive tools.
///
/// In TOML: `"auto"` (the default) or `true`. `false` is refused: usage a policy reads must be
/// kept, so the only choice is whether to keep it when nothing reads it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TrackUsage {
    /// Keep usage only when it can matter: some loaded policy reads `context.usage`, or the
    /// catalog declares `amount` or `destination` for some tool. Re-decided on every reload.
    #[default]
    Auto,
    /// Always keep usage for destructive tools, as before the elision (for example to watch
    /// the counters from the console before writing a policy over them).
    Always,
}

impl Serialize for TrackUsage {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Auto => s.serialize_str("auto"),
            Self::Always => s.serialize_bool(true),
        }
    }
}

impl<'de> Deserialize<'de> for TrackUsage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Bool(bool),
            Str(String),
        }
        match Repr::deserialize(d)? {
            Repr::Bool(true) => Ok(Self::Always),
            Repr::Str(s) if s == "auto" => Ok(Self::Auto),
            Repr::Bool(false) => Err(serde::de::Error::custom(
                "track_usage = false is not supported: usage is kept whenever a policy reads \
                 `context.usage`; use \"auto\" (the default) or true",
            )),
            Repr::Str(s) => Err(serde::de::Error::custom(format!(
                "track_usage: expected \"auto\" or true, got {s:?}"
            ))),
        }
    }
}

/// Whether any policy or template in `policies` may read `context.usage` (see the module
/// docs for what counts). `true` when the set cannot be rendered as JSON.
pub fn policies_read_usage(policies: &PolicySet) -> bool {
    policies_read_context_attr(policies, "usage")
}

/// Whether any policy or template in `policies` may read the context member `attr`, by the
/// same conservative walk as [`policies_read_usage`]. `true` when the set cannot be rendered
/// as JSON.
pub(crate) fn policies_read_context_attr(policies: &PolicySet, attr: &str) -> bool {
    match policies.clone().to_json() {
        Ok(v) => reads_attr(&v, attr),
        Err(_) => true,
    }
}

/// The per-user window kinds (run limits phase 3) some policy or template in `policies` may
/// read as `context.usage.user_window.<kind>`, shortest first. The walk errs towards keeping
/// a kind, as [`policies_read_usage`] does: a use of `context`, `context.usage` or
/// `context.usage.user_window` as a whole (or a `has` test on one) counts for every kind, and
/// so does a set that cannot be rendered as JSON. A kind no loaded policy reads is not kept:
/// the server charges and reads nothing for it, and Cedar sees it as zero.
pub fn policies_read_user_window(policies: &PolicySet) -> Vec<WindowKind> {
    let mut kinds = [false; 2];
    match policies.clone().to_json() {
        Ok(v) => window_reads(&v, &mut kinds),
        Err(_) => kinds = [true; 2],
    }
    WindowKind::ALL
        .into_iter()
        .zip(kinds)
        .filter_map(|(k, read)| read.then_some(k))
        .collect()
}

/// The attribute path of an access chain on `context` (`context.a.b` is `["a", "b"]`), or
/// `None` when `v` is not one. An access whose attribute has an unexpected shape ends the
/// path with `None` in it, which reads as "anything".
pub(crate) fn context_path(v: &Value) -> Option<Vec<Option<String>>> {
    if is_context(v) {
        return Some(Vec::new());
    }
    let map = v.as_object().filter(|m| m.len() == 1)?;
    let inner = [".", "has"].into_iter().find_map(|op| map.get(op))?;
    let mut path = context_path(inner.get("left")?)?;
    match inner.get("attr") {
        Some(Value::String(a)) => path.push(Some(a.clone())),
        Some(Value::Array(items)) => {
            path.extend(items.iter().map(|a| a.as_str().map(str::to_string)))
        }
        _ => path.push(None),
    }
    Some(path)
}

fn window_reads(v: &Value, kinds: &mut [bool; 2]) {
    if let Some(path) = context_path(v) {
        let at = |i: usize| path.get(i).map(Option::as_deref);
        let all = match (at(0), at(1), at(2)) {
            // `context` whole, or an unreadable step: could observe anything.
            (None, ..) | (Some(None), ..) => true,
            (Some(Some(a)), ..) if a != "usage" => false,
            (Some(Some(_)), None, _) | (Some(Some(_)), Some(None), _) => true,
            (Some(Some(_)), Some(Some(b)), _) if b != "user_window" => false,
            (_, _, None) | (_, _, Some(None)) => true,
            (_, _, Some(Some(kind))) => {
                match WindowKind::parse(kind) {
                    Some(k) => {
                        kinds[WindowKind::ALL.iter().position(|x| *x == k).unwrap_or(0)] = true
                    }
                    // A kind the schema does not declare cannot validate; keep both to be safe.
                    None => *kinds = [true; 2],
                }
                false
            }
        };
        if all {
            *kinds = [true; 2];
        }
        return;
    }
    match v {
        Value::Object(map) => map.values().for_each(|x| window_reads(x, kinds)),
        Value::Array(items) => items.iter().for_each(|x| window_reads(x, kinds)),
        _ => {}
    }
}

fn is_context(v: &Value) -> bool {
    v.get("Var").and_then(Value::as_str) == Some("context")
}

/// Walk Cedar's JSON (EST) form: an attribute access or `has` test on `context` reads `name`
/// when it names it; any other appearance of the `context` variable counts too.
fn reads_attr(v: &Value, name: &str) -> bool {
    match v {
        Value::Object(map) => {
            for op in [".", "has"] {
                if let Some(inner) = map.get(op).filter(|_| map.len() == 1) {
                    if inner.get("left").is_some_and(is_context) {
                        let attr = match inner.get("attr") {
                            Some(Value::String(a)) => Some(a.as_str()),
                            Some(Value::Array(path)) => path.first().and_then(Value::as_str),
                            _ => None,
                        };
                        // An unexpected shape is a read, to be safe.
                        return attr.is_none_or(|a| a == name);
                    }
                }
            }
            is_context(v) || map.values().any(|x| reads_attr(x, name))
        }
        Value::Array(items) => items.iter().any(|x| reads_attr(x, name)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn reads(text: &str) -> bool {
        policies_read_usage(&PolicySet::from_str(text).unwrap())
    }

    #[test]
    fn finds_reads_of_context_usage() {
        assert!(!reads("permit(principal, action, resource);"));
        assert!(!reads(
            "forbid(principal, action, resource) when { context.input has amount && \
             context.input.amount > 5 && context.budget.limited && resource.destructive };"
        ));
        assert!(reads(
            "forbid(principal, action, resource) when { context.usage.calls >= 1 };"
        ));
        assert!(reads(
            r#"forbid(principal, action, resource) when { context["usage"].amount > 9 };"#
        ));
        assert!(reads(
            "forbid(principal, action, resource) when { context has usage };"
        ));
        assert!(reads(
            "permit(principal, action, resource) unless { context.usage.destination_seen };"
        ));
        // A whole-record use could observe usage.
        assert!(reads(
            "forbid(principal, action, resource) when { context == {} };"
        ));
        // Templates count too.
        assert!(reads(
            "permit(principal == ?principal, action, resource) when { context.usage.calls < 3 };"
        ));
        // `usage` elsewhere is not a read of `context.usage`.
        assert!(!reads(
            r#"forbid(principal, action, resource) when { context.input has usage && context.input.usage == "usage" };"#
        ));
    }

    fn windows(text: &str) -> Vec<&'static str> {
        policies_read_user_window(&PolicySet::from_str(text).unwrap())
            .into_iter()
            .map(|k| k.as_str())
            .collect()
    }

    #[test]
    fn finds_the_window_kinds_policies_read() {
        let none: Vec<&str> = Vec::new();
        assert_eq!(windows("permit(principal, action, resource);"), none);
        // Run usage alone keeps no window.
        assert_eq!(
            windows("forbid(principal, action, resource) when { context.usage.amount > 5 };"),
            none
        );
        assert_eq!(
            windows(
                "forbid(principal, action, resource) when { \
                 context.usage.user_window.day.amount + 1 > 5000 };"
            ),
            vec!["day"]
        );
        assert_eq!(
            windows(
                r#"forbid(principal, action, resource) when { context["usage"]["user_window"]["hour"].calls > 3 };"#
            ),
            vec!["hour"]
        );
        assert_eq!(
            windows(
                "forbid(principal, action, resource) when { context.usage.user_window.hour.calls > 3 \
                 || context.usage.user_window.day.calls > 30 };"
            ),
            vec!["hour", "day"]
        );
        // Whole records count for every kind.
        for whole in [
            "forbid(principal, action, resource) when { context.usage.user_window == {} };",
            "forbid(principal, action, resource) when { context.usage == {} };",
            "forbid(principal, action, resource) when { context == {} };",
            "forbid(principal, action, resource) when { context.usage has user_window };",
        ] {
            assert_eq!(windows(whole), vec!["hour", "day"], "{whole}");
        }
        // Templates count too.
        assert_eq!(
            windows(
                "permit(principal == ?principal, action, resource) when { \
                 context.usage.user_window.day.calls < 3 };"
            ),
            vec!["day"]
        );
        // `user_window` elsewhere is not a read.
        assert_eq!(
            windows(
                r#"forbid(principal, action, resource) when { context.input has user_window && context.input.user_window == "day" };"#
            ),
            none
        );
    }

    #[test]
    fn track_usage_parses_auto_and_true_only() {
        #[derive(Deserialize)]
        struct T {
            t: TrackUsage,
        }
        let p = |s: &str| toml::from_str::<T>(s).map(|t| t.t);
        assert_eq!(p("t = \"auto\"").unwrap(), TrackUsage::Auto);
        assert_eq!(p("t = true").unwrap(), TrackUsage::Always);
        assert!(p("t = false").is_err());
        assert!(p("t = \"always\"").is_err());
    }
}
