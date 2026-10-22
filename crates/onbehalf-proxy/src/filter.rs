//! `tools/list` filtering.
//!
//! [`onbehalf_core::CapabilitySet::permits`] answers "is this concrete call allowed", and a
//! capability with an argument constraint denies a call that lacks that argument. That is the
//! right answer for `tools/call`, but the wrong question for `tools/list`: a tool the caller may
//! call *with the right arguments* must still be listed. So the proxy asks a weaker question,
//! "could any capability ever permit a call to this tool", which ignores constraints and looks
//! only at the server and tool name patterns.

use onbehalf_core::CapabilitySet;
use serde_json::Value;

/// Name pattern matching as `onbehalf-core` defines it: exact, `*`, or `prefix*`.
pub fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// Could some capability in `caps` permit a call to `tool` on `server`, for *some* arguments?
pub fn could_permit_tool(caps: &CapabilitySet, server: &str, tool: &str) -> bool {
    caps.iter()
        .any(|c| pattern_matches(&c.server, server) && pattern_matches(&c.tool, tool))
}

/// Filter a `tools/list` *result* object in place, keeping only tools that
/// [`could_permit_tool`]. Returns the number of tools removed. Results without a `tools` array
/// are left untouched.
pub fn filter_tools_result(result: &mut Value, caps: &CapabilitySet, server: &str) -> usize {
    let Some(tools) = result.get_mut("tools").and_then(Value::as_array_mut) else {
        return 0;
    };
    let before = tools.len();
    tools.retain(|t| {
        t.get("name")
            .and_then(Value::as_str)
            .map(|name| could_permit_tool(caps, server, name))
            .unwrap_or(false)
    });
    before - tools.len()
}

/// Filter a whole JSON-RPC `tools/list` response (`{"jsonrpc","id","result":{...}}`) in place.
pub fn filter_tools_response(response: &mut Value, caps: &CapabilitySet, server: &str) -> usize {
    match response.get_mut("result") {
        Some(result) => filter_tools_result(result, caps, server),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onbehalf_core::{ArgConstraint, Capability};
    use serde_json::json;

    fn caps() -> CapabilitySet {
        CapabilitySet::from_iter([
            Capability::new("github", "read_*"),
            Capability::new("github", "create_issue")
                .with_constraint("repo", ArgConstraint::Prefix("acme/".into())),
            Capability::new("slack*", "*"),
        ])
    }

    #[test]
    fn constrained_tool_is_still_listed() {
        let c = caps();
        assert!(could_permit_tool(&c, "github", "read_file"));
        assert!(could_permit_tool(&c, "github", "create_issue"));
        assert!(!could_permit_tool(&c, "github", "delete_repo"));
        assert!(could_permit_tool(&c, "slack-eu", "post_message"));
        assert!(!could_permit_tool(&c, "jira", "read_file"));
    }

    #[test]
    fn filters_tools_array_and_counts_removed() {
        let mut resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "tools": [
                {"name": "read_file"}, {"name": "create_issue"},
                {"name": "delete_repo"}, {"description": "nameless"}
            ], "nextCursor": "abc" }
        });
        let removed = filter_tools_response(&mut resp, &caps(), "github");
        assert_eq!(removed, 2);
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["read_file", "create_issue"]);
        assert_eq!(resp["result"]["nextCursor"], "abc");
    }

    #[test]
    fn error_responses_are_untouched() {
        let mut resp = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"x"}});
        let before = resp.clone();
        assert_eq!(filter_tools_response(&mut resp, &caps(), "github"), 0);
        assert_eq!(resp, before);
    }
}
