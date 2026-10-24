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
    match policies.clone().to_json() {
        Ok(v) => reads_usage(&v),
        Err(_) => true,
    }
}

fn is_context(v: &Value) -> bool {
    v.get("Var").and_then(Value::as_str) == Some("context")
}

/// Walk Cedar's JSON (EST) form: an attribute access or `has` test on `context` reads usage
/// when it names `usage`; any other appearance of the `context` variable counts too.
fn reads_usage(v: &Value) -> bool {
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
                        return attr.is_none_or(|a| a == "usage");
                    }
                }
            }
            is_context(v) || map.values().any(reads_usage)
        }
        Value::Array(items) => items.iter().any(reads_usage),
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
