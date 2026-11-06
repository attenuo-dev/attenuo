//! The tool names each upstream has listed (SR-25).
//!
//! Names are compared case-sensitively and never normalized ([`attenuo_core::names`]). An
//! upstream that resolves `tools/call` names case-insensitively (or after any other folding)
//! would run `delete_repo` for a call to `Delete_Repo`, which no rule keyed on `delete_repo`
//! sees. So, with [`ProxyConfig::require_listed_tools`](crate::ProxyConfig::require_listed_tools)
//! on, a `tools/call` is only screened further if its exact name appeared in a `tools/list`
//! result from that upstream, or is in the authorizer's tool catalog
//! ([`Authorizer::knows_tool`](crate::Authorizer::knows_tool)).
//!
//! The names come from every `tools/list` result that passes through the proxy, before it is
//! filtered for the caller, across all sessions and pages: this is about spelling, not about
//! permission, which the policy decides afterwards. Names that are not valid tool names are
//! not recorded. Each upstream's set is bounded by [`MAX_LISTED_TOOLS`]; past it, new names
//! are ignored (a misbehaving upstream can only lock its own new tools out).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Most tool names remembered per upstream.
pub const MAX_LISTED_TOOLS: usize = 10_000;

/// Upstream name to the set of tool names it has listed.
#[derive(Default)]
pub struct ListedTools {
    by_server: Mutex<HashMap<String, HashSet<String>>>,
}

impl ListedTools {
    /// An empty record: no upstream has listed anything yet.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HashSet<String>>> {
        self.by_server.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Remember the names `server` listed. Invalid tool names are skipped.
    pub fn record<'a>(&self, server: &str, names: impl IntoIterator<Item = &'a str>) {
        let mut map = self.lock();
        let set = map.entry(server.to_owned()).or_default();
        let mut dropped = 0usize;
        for name in names {
            if attenuo_core::names::check_tool_name(name).is_err() {
                continue;
            }
            if set.len() >= MAX_LISTED_TOOLS && !set.contains(name) {
                dropped += 1;
                continue;
            }
            set.insert(name.to_owned());
        }
        if dropped > 0 {
            tracing::warn!(
                server,
                dropped,
                "upstream listed more tools than the proxy remembers; new names ignored"
            );
        }
    }

    /// Has `server` listed exactly `tool`?
    pub fn contains(&self, server: &str, tool: &str) -> bool {
        self.lock().get(server).is_some_and(|s| s.contains(tool))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_names_only() {
        let l = ListedTools::new();
        l.record("github", ["delete_repo", "read file", "read_file"]);
        assert!(l.contains("github", "delete_repo"));
        assert!(!l.contains("github", "Delete_Repo"));
        assert!(
            !l.contains("github", "read file"),
            "invalid names are not kept"
        );
        assert!(!l.contains("gitlab", "delete_repo"));
    }

    #[test]
    fn bounded_per_server() {
        let l = ListedTools::new();
        let names: Vec<String> = (0..MAX_LISTED_TOOLS + 5).map(|i| format!("t{i}")).collect();
        l.record("s", names.iter().map(String::as_str));
        assert!(l.contains("s", "t0"));
        assert!(!l.contains("s", &format!("t{}", MAX_LISTED_TOOLS + 1)));
        // Names already known can be listed again.
        l.record("s", ["t0"]);
        assert!(l.contains("s", "t0"));
    }
}
