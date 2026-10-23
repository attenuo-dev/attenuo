//! Filtering of list results: `tools/list`, `resources/list`, `resources/templates/list` and
//! `prompts/list`.
//!
//! [`onbehalf_core::CapabilitySet::permits`] answers "is this concrete call allowed", and a
//! capability with an argument constraint denies a call that lacks that argument. That is the
//! right answer for `tools/call`, but the wrong question for `tools/list`: a tool the caller may
//! call *with the right arguments* must still be listed. So the proxy asks a weaker question,
//! "could any capability ever permit a call to this tool", which ignores constraints and looks
//! only at the server and tool name patterns.

use onbehalf_core::{Capability, CapabilitySet};
use serde_json::Value;

use crate::jsonrpc::{
    METHOD_PROMPTS_GET, METHOD_PROMPTS_LIST, METHOD_RESOURCES_LIST, METHOD_RESOURCES_READ,
    METHOD_RESOURCES_TEMPLATES_LIST, METHOD_TOOLS_LIST,
};

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

/// The four MCP list methods whose results the proxy filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Tools,
    Resources,
    ResourceTemplates,
    Prompts,
}

impl ListKind {
    pub const ALL: [ListKind; 4] = [
        ListKind::Tools,
        ListKind::Resources,
        ListKind::ResourceTemplates,
        ListKind::Prompts,
    ];

    /// The list kind a request method asks for, if it is one of the four list methods.
    pub fn from_method(method: &str) -> Option<ListKind> {
        match method {
            METHOD_TOOLS_LIST => Some(ListKind::Tools),
            METHOD_RESOURCES_LIST => Some(ListKind::Resources),
            METHOD_RESOURCES_TEMPLATES_LIST => Some(ListKind::ResourceTemplates),
            METHOD_PROMPTS_LIST => Some(ListKind::Prompts),
            _ => None,
        }
    }

    /// The member of the result object that holds the entries.
    pub fn array_key(self) -> &'static str {
        match self {
            ListKind::Tools => "tools",
            ListKind::Resources => "resources",
            ListKind::ResourceTemplates => "resourceTemplates",
            ListKind::Prompts => "prompts",
        }
    }

    /// The member of one entry that identifies it in the matching request mapping.
    fn key_field(self) -> &'static str {
        match self {
            ListKind::Tools | ListKind::Prompts => "name",
            ListKind::Resources => "uri",
            ListKind::ResourceTemplates => "uriTemplate",
        }
    }
}

/// Does `cap` match `server` and `tool`, and would its constraint on `arg` (if any) accept
/// `value`? Constraints on other arguments are ignored: a list entry cannot know them.
fn could_permit_with(cap: &Capability, server: &str, tool: &str, arg: &str, value: &str) -> bool {
    pattern_matches(&cap.server, server)
        && pattern_matches(&cap.tool, tool)
        && cap
            .constraints
            .get(arg)
            .map(|c| c.satisfied_by(&Value::String(value.to_owned())))
            .unwrap_or(true)
}

/// Could some capability permit `resources/read` of `uri` on `server`? Mirrors the request
/// mapping (`tool = "resources/read"`, `arguments = {"uri": uri}`): a `uri` constraint is
/// checked against the concrete URI, other constraints are ignored.
pub fn could_permit_resource(caps: &CapabilitySet, server: &str, uri: &str) -> bool {
    caps.iter()
        .any(|c| could_permit_with(c, server, METHOD_RESOURCES_READ, "uri", uri))
}

/// Could some capability permit `resources/read` on `server` for *some* URI? Used for
/// resource templates, whose `uriTemplate` is not a URI: constraints are ignored, as for tools.
pub fn could_permit_resource_template(caps: &CapabilitySet, server: &str) -> bool {
    could_permit_tool(caps, server, METHOD_RESOURCES_READ)
}

/// Could some capability permit `prompts/get` of prompt `name` on `server`? Mirrors the request
/// mapping (`tool = "prompts/get"`, `arguments = {"name": name, "arguments": ...}`): a `name`
/// constraint is checked against the prompt name, other constraints are ignored.
pub fn could_permit_prompt(caps: &CapabilitySet, server: &str, name: &str) -> bool {
    caps.iter()
        .any(|c| could_permit_with(c, server, METHOD_PROMPTS_GET, "name", name))
}

/// Filter the list `result` object of `kind` in place, keeping only entries the chain could
/// ever be permitted to use. An entry without its identifying string member is dropped (it
/// could not be requested by name either). `nextCursor` and every other member are left alone.
/// Returns the number of entries removed. A result without the array is left untouched.
pub fn filter_list_result(
    kind: ListKind,
    result: &mut Value,
    caps: &CapabilitySet,
    server: &str,
) -> usize {
    let Some(entries) = result
        .get_mut(kind.array_key())
        .and_then(Value::as_array_mut)
    else {
        return 0;
    };
    let before = entries.len();
    entries.retain(|e| {
        let Some(key) = e.get(kind.key_field()).and_then(Value::as_str) else {
            return false;
        };
        match kind {
            ListKind::Tools => could_permit_tool(caps, server, key),
            ListKind::Resources => could_permit_resource(caps, server, key),
            ListKind::ResourceTemplates => could_permit_resource_template(caps, server),
            ListKind::Prompts => could_permit_prompt(caps, server, key),
        }
    });
    before - entries.len()
}

/// Filter a whole JSON-RPC list response in place. Error responses are untouched.
pub fn filter_list_response(
    kind: ListKind,
    response: &mut Value,
    caps: &CapabilitySet,
    server: &str,
) -> usize {
    match response.get_mut("result") {
        Some(result) => filter_list_result(kind, result, caps, server),
        None => 0,
    }
}

/// Does a response `id` answer the request `id`? Numbers compare by value, not by spelling:
/// an upstream in JavaScript (or anything that parses ids into a double) answers a request
/// with `"id": 1.0` as `"id": 1`, and `9007199254740993` as `9007199254740992`. Comparing
/// the JSON values exactly let such an answer to a `tools/list` reach the client unfiltered
/// (found by the `proxy_jsonrpc` fuzz target). A fractional or huge id can also come back
/// spelled differently, and `serde_json` may parse the two spellings a unit in the last place
/// apart, so doubles match within a few ULPs. Ids that collide this way are both filtered,
/// which can only remove entries.
fn same_id(request: &Value, response: &Value) -> bool {
    match (request, response) {
        (Value::Number(a), Value::Number(b)) => {
            a == b
                || match (a.as_f64(), b.as_f64()) {
                    (Some(x), Some(y)) => {
                        x == y || (x - y).abs() <= 4.0 * f64::EPSILON * x.abs().max(y.abs())
                    }
                    _ => false,
                }
        }
        // JSON-RPC ids are strings, numbers or null, but nothing stops a client from sending
        // an array or object; their numbers drift the same way.
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same_id(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, x)| b.get(k).is_some_and(|y| same_id(x, y)))
        }
        _ => request == response,
    }
}

/// The list requests of one HTTP request whose responses must be filtered, and what to filter
/// them with.
///
/// A message is only ever treated as a *response* when it has no `method`: a request or
/// notification that carries a `result` (a client trying to smuggle one, or an upstream
/// server-initiated request that reuses an id) is not a result, and is left alone.
pub struct ListFilter<'a> {
    pending: &'a [(Value, ListKind)],
    caps: &'a CapabilitySet,
    server: &'a str,
}

impl<'a> ListFilter<'a> {
    pub fn new(pending: &'a [(Value, ListKind)], caps: &'a CapabilitySet, server: &'a str) -> Self {
        Self {
            pending,
            caps,
            server,
        }
    }

    /// Filter one JSON-RPC message in place if it answers a pending list request; returns the
    /// number of entries removed.
    pub fn apply_message(&self, msg: &mut Value) -> usize {
        if msg.get("method").is_some() {
            return 0;
        }
        let Some(id) = msg.get("id") else {
            return 0;
        };
        let kinds: Vec<ListKind> = self
            .pending
            .iter()
            .filter(|(pid, _)| same_id(pid, id))
            .map(|(_, k)| *k)
            .collect();
        kinds
            .into_iter()
            .map(|k| filter_list_response(k, msg, self.caps, self.server))
            .sum()
    }

    /// The tool names in every `tools/list` result in `body` (a message or a batch) that
    /// answers a pending `tools/list` request, unfiltered. Matching is the same as for
    /// [`apply`](Self::apply). Call it before filtering.
    pub fn listed_tool_names(&self, body: &Value) -> Vec<String> {
        let messages: Vec<&Value> = match body {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        let mut names = Vec::new();
        for msg in messages {
            if msg.get("method").is_some() {
                continue;
            }
            let Some(id) = msg.get("id") else {
                continue;
            };
            let is_tools = self
                .pending
                .iter()
                .any(|(pid, k)| same_id(pid, id) && *k == ListKind::Tools);
            if !is_tools {
                continue;
            }
            if let Some(tools) = msg
                .get("result")
                .and_then(|r| r.get("tools"))
                .and_then(Value::as_array)
            {
                names.extend(
                    tools
                        .iter()
                        .filter_map(|t| t.get("name").and_then(Value::as_str))
                        .map(str::to_owned),
                );
            }
        }
        names
    }

    /// Filter a JSON body: a single message or a batch.
    pub fn apply(&self, body: &mut Value) -> usize {
        match body {
            Value::Array(items) => items.iter_mut().map(|m| self.apply_message(m)).sum(),
            other => self.apply_message(other),
        }
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

    fn res_caps() -> CapabilitySet {
        CapabilitySet::from_iter([
            Capability::new("github", "resources/read")
                .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into())),
            Capability::new("github", "prompts/get")
                .with_constraint("name", ArgConstraint::Equals(json!("deploy"))),
        ])
    }

    #[test]
    fn resources_are_matched_on_the_uri_constraint() {
        let c = res_caps();
        assert!(could_permit_resource(&c, "github", "file:///public/a"));
        assert!(!could_permit_resource(&c, "github", "file:///secret/a"));
        assert!(!could_permit_resource(&c, "gitlab", "file:///public/a"));
        assert!(could_permit_resource_template(&c, "github"));
        assert!(!could_permit_resource_template(&c, "gitlab"));
    }

    #[test]
    fn prompts_are_matched_on_the_name_constraint() {
        let c = res_caps();
        assert!(could_permit_prompt(&c, "github", "deploy"));
        assert!(!could_permit_prompt(&c, "github", "review"));
    }

    #[test]
    fn filter_list_result_per_kind_keeps_other_members() {
        let c = res_caps();
        let mut r = json!({"resources": [
            {"uri": "file:///public/a"}, {"uri": "file:///secret/b"}, {"name": "no uri"}
        ], "nextCursor": "n"});
        assert_eq!(
            filter_list_result(ListKind::Resources, &mut r, &c, "github"),
            2
        );
        assert_eq!(r["resources"], json!([{"uri": "file:///public/a"}]));
        assert_eq!(r["nextCursor"], "n");

        let mut t = json!({"resourceTemplates": [{"uriTemplate": "x://{a}"}]});
        assert_eq!(
            filter_list_result(ListKind::ResourceTemplates, &mut t, &c, "gitlab"),
            1
        );
        assert_eq!(t["resourceTemplates"], json!([]));

        // wrong array key for the kind: untouched
        let mut p = json!({"prompts": [{"name": "x"}]});
        assert_eq!(filter_list_result(ListKind::Tools, &mut p, &c, "github"), 0);
    }

    #[test]
    fn list_kind_from_method() {
        assert_eq!(
            ListKind::from_method("prompts/list"),
            Some(ListKind::Prompts)
        );
        assert_eq!(ListKind::from_method("prompts/get"), None);
        for k in ListKind::ALL {
            assert!(!k.array_key().is_empty());
        }
    }

    #[test]
    fn list_filter_only_touches_responses_to_pending_ids() {
        let c = res_caps();
        let pending = vec![(json!(1), ListKind::Resources)];
        let f = ListFilter::new(&pending, &c, "github");
        let entries = json!([{"uri": "file:///secret/b"}]);

        // answers id 1: filtered
        let mut m = json!({"jsonrpc":"2.0","id":1,"result":{"resources": entries}});
        assert_eq!(f.apply_message(&mut m), 1);
        // another id: untouched
        let mut m = json!({"jsonrpc":"2.0","id":2,"result":{"resources": entries}});
        assert_eq!(f.apply_message(&mut m), 0);
        assert_eq!(m["result"]["resources"], entries);
        // has a method, so it is a request or notification, never a result
        let mut m = json!({"jsonrpc":"2.0","id":1,"method":"notifications/x",
                           "result":{"resources": entries}});
        assert_eq!(f.apply_message(&mut m), 0);
        assert_eq!(m["result"]["resources"], entries);
        // batch
        let mut b = json!([
            {"jsonrpc":"2.0","id":3,"result":{}},
            {"jsonrpc":"2.0","id":1,"result":{"resources": entries}}
        ]);
        assert_eq!(f.apply(&mut b), 1);
    }

    /// Found by the `proxy_jsonrpc` fuzz target: a `tools/list` sent with `"id": 1.0` and
    /// answered by a JavaScript upstream with `"id": 1` passed through unfiltered.
    #[test]
    fn list_filter_matches_numeric_ids_by_value() {
        let c = caps();
        let tools = json!([{"name": "read_file"}, {"name": "delete_repo"}]);
        for (sent, answered) in [
            (json!(1.0), json!(1)),
            (json!(1), json!(1.0)),
            (json!(-0.0), json!(0)),
            (
                json!(1.866_909_276_318_353e230),
                json!(1.866_909_276_318_354e230),
            ),
            (
                json!(9_007_199_254_740_993u64),
                json!(9_007_199_254_740_992u64),
            ),
        ] {
            let pending = vec![(sent.clone(), ListKind::Tools)];
            let f = ListFilter::new(&pending, &c, "github");
            let mut m = json!({"jsonrpc":"2.0","id":answered,"result":{"tools": tools}});
            assert_eq!(f.listed_tool_names(&m).len(), 2, "{sent} / {answered}");
            assert_eq!(f.apply_message(&mut m), 1, "{sent} / {answered}");
            assert_eq!(m["result"]["tools"], json!([{"name": "read_file"}]));
        }
        // A string id is still not a number.
        let pending = vec![(json!("1"), ListKind::Tools)];
        let f = ListFilter::new(&pending, &c, "github");
        let mut m = json!({"jsonrpc":"2.0","id":1,"result":{"tools": tools}});
        assert_eq!(f.apply_message(&mut m), 0);
    }
}
