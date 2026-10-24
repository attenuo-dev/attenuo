//! Human-readable rendering of chains, capabilities and times.

use attenuo_core::{ArgConstraint, Capability, CapabilitySet, DelegationChain};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub fn fmt_time(t: OffsetDateTime) -> String {
    let t = t.replace_nanosecond(0).unwrap_or(t);
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

/// "in 14m 30s" or "expired 2m 5s ago".
pub fn fmt_relative(t: OffsetDateTime, now: OffsetDateTime) -> String {
    let secs = (t - now).whole_seconds();
    let span = fmt_span(secs.unsigned_abs());
    if secs >= 0 {
        format!("in {span}")
    } else {
        format!("expired {span} ago")
    }
}

fn fmt_span(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m {s}s"),
        _ => format!("{h}h {m}m"),
    }
}

fn fmt_constraint(arg: &str, c: &ArgConstraint) -> String {
    match c {
        ArgConstraint::Equals(v) => format!("{arg} == {v}"),
        ArgConstraint::OneOf(vs) => {
            let items: Vec<String> = vs.iter().map(|v| v.to_string()).collect();
            format!("{arg} in [{}]", items.join(", "))
        }
        ArgConstraint::Prefix(p) => format!("{arg} starts with {p:?}"),
    }
}

/// `github:read_file`, or `github:create_issue {repo starts with "acme/"}`, with run limits
/// (ADR-0010) after them: `banking:send_money [calls <= 1, sum(amount) <= 10]`.
pub fn fmt_capability(c: &Capability) -> String {
    let mut out = format!("{}:{}", c.server, c.tool);
    if !c.constraints.is_empty() {
        let cs: Vec<String> = c
            .constraints
            .iter()
            .map(|(arg, con)| fmt_constraint(arg, con))
            .collect();
        out.push_str(&format!(" {{{}}}", cs.join(", ")));
    }
    let l = &c.limits;
    let mut ls = Vec::new();
    if let Some(n) = l.calls {
        ls.push(format!("calls <= {n}"));
    }
    if let Some(s) = &l.sum {
        ls.push(format!("sum({}) <= {}", s.arg, s.max));
    }
    if let Some(p) = &l.calls_per {
        ls.push(format!("calls per {} <= {}", p.arg, p.max));
    }
    if !ls.is_empty() {
        out.push_str(&format!(" [{}]", ls.join(", ")));
    }
    out
}

pub fn fmt_capabilities(set: &CapabilitySet) -> String {
    if set.is_empty() {
        return "(none)".to_string();
    }
    set.0
        .iter()
        .map(fmt_capability)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Draw the chain as a tree: the user at the root, then one level per agent, each with its
/// capabilities, expiry and lease. The last hop is the agent that holds the token.
pub fn render_chain_tree(chain: &DelegationChain, now: OffsetDateTime) -> String {
    let user = &chain.originating_user;
    let mut out = format!("user {}  (issuer {})\n", user.subject, user.issuer);
    out.push_str(&format!(
        "  authenticated {}\n",
        fmt_time(user.authenticated_at)
    ));
    if !user.attributes.is_empty() {
        let attrs: Vec<String> = user
            .attributes
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        out.push_str(&format!("  attributes {}\n", attrs.join(", ")));
    }
    let last = chain.hops.len().saturating_sub(1);
    for (i, hop) in chain.hops.iter().enumerate() {
        let pad = "   ".repeat(i);
        let acting = if i == last {
            "  <- holds this token"
        } else {
            ""
        };
        out.push_str(&format!("{pad}└─ agent {}{acting}\n", hop.agent));
        out.push_str(&format!(
            "{pad}     can   {}\n",
            fmt_capabilities(&hop.capabilities)
        ));
        out.push_str(&format!(
            "{pad}     until {} ({})\n",
            fmt_time(hop.expires_at),
            fmt_relative(hop.expires_at, now)
        ));
        out.push_str(&format!("{pad}     lease {}\n", hop.lease.0));
    }
    out
}

// -- admin API answers --
//
// These read the server's JSON as `Value` rather than typed structs: a field the server adds
// later should not break an older CLI, and a missing one prints as `-`.

/// `v[key]` as text, `-` when absent or not a string.
fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("-")
}

/// The strings of a JSON array.
fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// One line per audit entry.
pub fn fmt_audit_entry(e: &Value) -> String {
    let r = &e["record"];
    let agents = strs(&r["agents"]);
    // Admin actions have no delegation chain, so no agents.
    let who = if agents.is_empty() {
        "by".to_string()
    } else {
        format!("{} for", agents.join(" > "))
    };
    format!(
        "#{:<4} {}  {:<5} {}/{}  {} {}  reason={}  id={}",
        e["seq"].as_u64().unwrap_or(0),
        s(r, "at"),
        s(r, "decision").to_uppercase(),
        s(r, "server"),
        s(r, "tool"),
        who,
        s(r, "originating_subject"),
        s(r, "reason"),
        s(r, "id"),
    )
}

/// A lease's state as the registry sees it now: `active, expires ...`, `REVOKED ...`,
/// `expired ...`, or `unknown` for a lease the registry does not hold.
fn fmt_lease_state(l: &Value) -> String {
    if l["known"] == false {
        return "unknown to the lease registry".to_string();
    }
    if !l["revoked_at"].is_null() {
        return format!(
            "REVOKED {} ({})",
            s(l, "revoked_at"),
            l["revoke_reason"].as_str().unwrap_or("no reason")
        );
    }
    if l["active"] == true {
        format!("active, expires {}", s(l, "expires_at"))
    } else {
        format!("expired {}", s(l, "expires_at"))
    }
}

/// `audit show`: the entry line, then the record's details and its context
/// (`{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}`).
pub fn render_entry_view(v: &Value) -> String {
    let e = &v["entry"];
    let r = &e["record"];
    let mut out = format!("{}\n", fmt_audit_entry(e));
    out.push_str(&format!("kind        {}\n", s(r, "kind")));
    if let Some(chain) = r["chain_id"].as_str() {
        out.push_str(&format!("chain       {chain}\n"));
    }
    let policies = strs(&r["policy_ids"]);
    if !policies.is_empty() {
        out.push_str(&format!("policies    {}\n", policies.join(", ")));
    }
    if r["dpop_bound"] == true {
        out.push_str("dpop        bound\n");
    }
    out.push_str(&format!("hash        {}\n", s(e, "entry_hash")));
    out.push_str(&format!("prev hash   {}\n", s(e, "prev_hash")));
    let leases = v["lease_states"].as_array().cloned().unwrap_or_default();
    if leases.is_empty() {
        out.push_str("leases      (none)\n");
    } else {
        out.push_str("leases      (root first, as the registry sees them now)\n");
        for l in &leases {
            out.push_str(&format!("  {}  {}\n", s(l, "lease_id"), fmt_lease_state(l)));
        }
    }
    let cp = &v["covered_by_checkpoint"];
    if cp.is_null() {
        out.push_str(
            "checkpoint  none yet: the entry is newer than every checkpoint, only the hash chain covers it\n",
        );
    } else {
        out.push_str(&format!(
            "checkpoint  seq {} at {} (kid {}); `audit verify` checks its signature\n",
            cp["seq"],
            s(cp, "at"),
            s(cp, "kid")
        ));
    }
    match v["policy_reloaded_after"].as_u64() {
        Some(seq) => out.push_str(&format!(
            "policy      reloaded at seq {seq}, after this entry: the policy in force now may not be the one that decided\n"
        )),
        None => out.push_str("policy      not reloaded since this entry\n"),
    }
    out
}

/// `audit checkpoints`: one line per stored checkpoint, newest first, and how to page on.
pub fn render_checkpoints(v: &Value) -> String {
    let cps = v["checkpoints"].as_array().cloned().unwrap_or_default();
    if cps.is_empty() {
        return "no checkpoints stored\n".to_string();
    }
    let mut out = String::new();
    for c in &cps {
        out.push_str(&format!(
            "seq {:<6} {}  kid {}  head {}\n",
            c["seq"],
            s(c, "at"),
            s(c, "kid"),
            s(c, "head_hash")
        ));
    }
    if let Some(prev) = v["prev"].as_u64() {
        out.push_str(&format!("older: audit checkpoints --before {prev}\n"));
    }
    out
}

/// One lease of a tree: id, agent, state and the audit seq that issued it.
fn fmt_tree_node(n: &Value) -> String {
    let issued = n["issued_seq"]
        .as_u64()
        .map(|seq| format!("  issued #{seq}"))
        .unwrap_or_default();
    format!(
        "{}  {}  {}{issued}",
        s(n, "lease_id"),
        n["agent"].as_str().unwrap_or("(agent unknown)"),
        fmt_lease_state(n)
    )
}

/// `lease tree`: the ancestors nearest first, then the lease and its descendants drawn as a
/// tree, then what a revoke would change.
pub fn render_lease_tree(v: &Value) -> String {
    let nodes = v["nodes"].as_array().cloned().unwrap_or_default();
    let mut out = String::new();
    let ancestors = v["ancestors"].as_array().cloned().unwrap_or_default();
    if ancestors.is_empty() {
        out.push_str("root lease (no ancestors)\n");
    } else {
        out.push_str(&format!(
            "ancestors (nearest first, chain root {})\n",
            s(v, "root")
        ));
        for a in &ancestors {
            out.push_str(&format!("  {}\n", fmt_tree_node(a)));
        }
    }
    // Breadth-first order puts every parent before its children, so a parent-to-children
    // map drawn from the first node reaches every listed lease.
    let mut children: std::collections::BTreeMap<&str, Vec<&Value>> = Default::default();
    for n in nodes.iter().skip(1) {
        children.entry(s(n, "parent")).or_default().push(n);
    }
    fn draw(
        out: &mut String,
        n: &Value,
        prefix: &str,
        children: &std::collections::BTreeMap<&str, Vec<&Value>>,
    ) {
        let kids = children.get(s(n, "lease_id")).cloned().unwrap_or_default();
        for (i, k) in kids.iter().enumerate() {
            let last = i + 1 == kids.len();
            out.push_str(&format!(
                "{prefix}{}{}\n",
                if last { "└─ " } else { "├─ " },
                fmt_tree_node(k)
            ));
            let deeper = format!("{prefix}{}", if last { "   " } else { "│  " });
            draw(out, k, &deeper, children);
        }
    }
    if let Some(first) = nodes.first() {
        out.push_str(&format!("{}\n", fmt_tree_node(first)));
        draw(&mut out, first, "", &children);
    }
    out.push_str(&format!(
        "would revoke {} lease(s) if revoked now\n",
        v["would_revoke"]
    ));
    if v["truncated"] == true {
        out.push_str(&format!(
            "truncated: only {} leases listed (raise --max-nodes); `would revoke` counts the whole subtree\n",
            nodes.len()
        ));
    }
    out
}

/// `approval list`: one line per approval, newest first.
pub fn render_approvals(v: &Value) -> String {
    let list = v["approvals"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        return "no approvals\n".to_string();
    }
    let mut out = String::new();
    for a in &list {
        let state = if a["expired"] == true && matches!(s(a, "state"), "pending" | "granted") {
            format!("{} (expired)", s(a, "state"))
        } else {
            s(a, "state").to_string()
        };
        out.push_str(&format!(
            "{}  {:<18} {}/{}  run {}  expires {}\n",
            s(a, "approval_id"),
            state,
            s(&a["call"], "server"),
            s(&a["call"], "tool"),
            s(a, "chain_id"),
            s(a, "expires_at"),
        ));
    }
    out
}

/// `approval show` (and the answer to `grant` / `decline`): the exact call the approval is
/// for, the run's labels, and its state.
pub fn render_approval(a: &Value) -> String {
    let mut out = format!(
        "approval   {}\nstate      {}{}\ncall       {}/{}\narguments  {}\ncall hash  {}\n",
        s(a, "approval_id"),
        s(a, "state"),
        if a["expired"] == true {
            " (expired)"
        } else {
            ""
        },
        s(&a["call"], "server"),
        s(&a["call"], "tool"),
        a["call"]["arguments"],
        s(a, "call_hash"),
    );
    out.push_str(&format!(
        "user       {} ({})\nagents     {}\nrun        {}\nlease      {}\n",
        s(a, "subject"),
        s(a, "issuer"),
        strs(&a["agents"]).join(" > "),
        s(a, "chain_id"),
        s(a, "lease"),
    ));
    let labels = a["labels"].as_array().cloned().unwrap_or_default();
    if labels.is_empty() {
        out.push_str("labels     none\n");
    } else {
        for (i, l) in labels.iter().enumerate() {
            out.push_str(&format!(
                "{}{} (audit seq {})\n",
                if i == 0 { "labels     " } else { "           " },
                s(l, "source"),
                l["seq"],
            ));
        }
    }
    out.push_str(&format!(
        "created    {}\nexpires    {}\n",
        s(a, "created_at"),
        s(a, "expires_at")
    ));
    if a["approver"].is_object() {
        out.push_str(&format!(
            "decided    {} by {} ({}, {})\n",
            s(a, "decided_at"),
            s(&a["approver"], "subject"),
            s(&a["approver"], "by"),
            s(&a["approver"], "method"),
        ));
    }
    if a["consumed_by"].is_string() {
        out.push_str(&format!("used by    decision {}\n", s(a, "consumed_by")));
    }
    out
}

/// `policy show`: what the server has loaded, then each policy's text.
pub fn render_policies(v: &Value) -> String {
    let ids = strs(&v["policy_ids"]);
    let mut out = format!(
        "path       {}\nsha256     {}\nloaded at  {}\npolicies   {}: {}\n",
        v["path"].as_str().unwrap_or("(no policy file configured)"),
        s(v, "sha256"),
        s(v, "loaded_at"),
        ids.len(),
        ids.join(", ")
    );
    for w in strs(&v["warnings"]) {
        out.push_str(&format!("warning: {w}\n"));
    }
    for p in v["policies"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "\n// {}\n{}\n",
            s(p, "id"),
            s(p, "text").trim_end()
        ));
    }
    out
}

/// `policy check`: the lint issues as `path:line:col: severity[stage] (id): message`, as
/// `policy lint` prints them, then whether a reload would succeed.
pub fn render_policy_check(v: &Value) -> String {
    let path = s(v, "path");
    let mut out = String::new();
    for i in v["issues"].as_array().into_iter().flatten() {
        let loc = match (i["line"].as_u64(), i["column"].as_u64()) {
            (Some(l), Some(c)) => format!("{path}:{l}:{c}"),
            _ => path.to_string(),
        };
        let id = i["policy_id"]
            .as_str()
            .map(|p| format!(" ({p})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "{loc}: {}[{}]{id}: {}\n",
            s(i, "severity"),
            s(i, "stage"),
            s(i, "message")
        ));
    }
    let n = strs(&v["policy_ids"]).len();
    out.push_str(&format!(
        "{path}: {n} polic{}, {} error(s), {} warning(s)\n",
        if n == 1 { "y" } else { "ies" },
        v["error_count"],
        v["warning_count"]
    ));
    let differs = if v["differs_from_loaded"] == true {
        "differs from the loaded policy set"
    } else {
        "same as the loaded policy set"
    };
    out.push_str(&format!("on disk sha256 {} ({differs})\n", s(v, "sha256")));
    out.push_str(if v["ok"] == true {
        "a reload would succeed\n"
    } else {
        "a reload would FAIL: the server keeps the loaded set\n"
    });
    out
}

/// `policy evaluate`: the decision, its reason and policies, and what the dry run left out.
pub fn render_evaluation(v: &Value) -> String {
    let mut out = format!("{}  {}\n", s(v, "decision").to_uppercase(), s(v, "reason"));
    let pols = strs(&v["policy_ids"]);
    if !pols.is_empty() {
        out.push_str(&format!("policies     {}\n", pols.join(", ")));
    }
    let source = match s(v, "chain_source") {
        "token" if v["token_expired"] == true => {
            "token (expired; verified as of its last valid second)"
        }
        "token" => "token",
        "admin_supplied" => "admin supplied (shape checked only, not shown to be issued here)",
        other => other,
    };
    out.push_str(&format!("chain from   {source}\n"));
    out.push_str(&format!(
        "lease check  {} (dry run: nothing audited)\n",
        s(v, "lease_check")
    ));
    for d in v["diagnostics"].as_array().into_iter().flatten() {
        match d.as_str() {
            Some(text) => out.push_str(&format!("diagnostic: {text}\n")),
            None => out.push_str(&format!("diagnostic: {d}\n")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_core::{AgentId, LeaseId, OriginatingUser};
    use serde_json::json;
    use time::macros::datetime;
    use time::Duration;

    fn chain() -> DelegationChain {
        let t0 = datetime!(2026-10-22 09:00:00 UTC);
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert("mfa".to_string(), json!(false));
        let user = OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: t0,
            attributes,
        };
        let root = DelegationChain::root(
            user,
            AgentId::new("planner"),
            CapabilitySet::from_iter([Capability::new("github", "*")]),
            t0,
            Duration::minutes(15),
            LeaseId::new("L-root"),
        )
        .unwrap();
        root.extend(
            AgentId::new("coder"),
            CapabilitySet::from_iter([Capability::new("github", "read_file")
                .with_constraint("repo", ArgConstraint::Prefix("alice/public-".into()))]),
            t0,
            Duration::minutes(5),
            LeaseId::new("L-child"),
            8,
        )
        .unwrap()
    }

    #[test]
    fn tree_shows_user_then_each_agent_nested() {
        let now = datetime!(2026-10-22 09:01:00 UTC);
        let text = render_chain_tree(&chain(), now);
        let expected = "\
user alice  (issuer https://idp.example)
  authenticated 2026-10-22T09:00:00Z
  attributes mfa=false
└─ agent planner
     can   github:*
     until 2026-10-22T09:15:00Z (in 14m 0s)
     lease L-root
   └─ agent coder  <- holds this token
        can   github:read_file {repo starts with \"alice/public-\"}
        until 2026-10-22T09:05:00Z (in 4m 0s)
        lease L-child
";
        assert_eq!(text, expected);
    }

    #[test]
    fn tree_marks_expired_hops() {
        let now = datetime!(2026-10-22 09:10:00 UTC);
        let text = render_chain_tree(&chain(), now);
        assert!(text.contains("(expired 5m 0s ago)"), "{text}");
        assert!(text.contains("(in 5m 0s)"), "{text}");
    }

    #[test]
    fn relative_spans() {
        let now = datetime!(2026-10-22 09:00:00 UTC);
        assert_eq!(fmt_relative(now + Duration::seconds(7), now), "in 7s");
        assert_eq!(fmt_relative(now + Duration::hours(2), now), "in 2h 0m");
        assert_eq!(
            fmt_relative(now - Duration::seconds(90), now),
            "expired 1m 30s ago"
        );
    }

    #[test]
    fn capability_forms() {
        let c = Capability::new("github", "x")
            .with_constraint("n", ArgConstraint::Equals(json!(1)))
            .with_constraint("r", ArgConstraint::OneOf(vec![json!("a"), json!("b")]));
        assert_eq!(fmt_capability(&c), "github:x {n == 1, r in [\"a\", \"b\"]}");
        assert_eq!(fmt_capabilities(&CapabilitySet::new()), "(none)");
        let limited = Capability::new("banking", "send_money").with_limits(
            attenuo_core::Limits::default()
                .with_calls(1)
                .with_sum("amount", 10)
                .with_calls_per("recipient", 1),
        );
        assert_eq!(
            fmt_capability(&limited),
            "banking:send_money [calls <= 1, sum(amount) <= 10, calls per recipient <= 1]"
        );
    }

    fn node(id: &str, parent: Option<&str>, agent: &str, revoked: bool) -> Value {
        json!({"lease_id": id, "parent": parent, "agent": agent, "active": !revoked,
               "expires_at": "2026-10-23T10:00:00Z",
               "revoked_at": if revoked { json!("2026-10-23T09:30:00Z") } else { json!(null) },
               "revoke_reason": if revoked { json!("rotated") } else { json!(null) },
               "issued_seq": 3})
    }

    #[test]
    fn lease_tree_draws_siblings_and_marks_state() {
        let v = json!({
            "root": "R",
            "ancestors": [node("R", None, "planner", false)],
            "nodes": [
                node("A", Some("R"), "coder", false),
                node("B", Some("A"), "reviewer", true),
                node("C", Some("A"), "tester", false),
                node("D", Some("B"), "linter", false),
            ],
            "would_revoke": 3,
            "truncated": true,
        });
        let expected = "\
ancestors (nearest first, chain root R)
  R  planner  active, expires 2026-10-23T10:00:00Z  issued #3
A  coder  active, expires 2026-10-23T10:00:00Z  issued #3
├─ B  reviewer  REVOKED 2026-10-23T09:30:00Z (rotated)  issued #3
│  └─ D  linter  active, expires 2026-10-23T10:00:00Z  issued #3
└─ C  tester  active, expires 2026-10-23T10:00:00Z  issued #3
would revoke 3 lease(s) if revoked now
truncated: only 4 leases listed (raise --max-nodes); `would revoke` counts the whole subtree
";
        assert_eq!(render_lease_tree(&v), expected);
    }

    #[test]
    fn entry_view_names_unknown_leases_and_missing_checkpoint() {
        let v = json!({
            "entry": {"seq": 4, "entry_hash": "h4", "prev_hash": "h3",
                      "record": {"kind": "admin", "decision": "allow", "agents": []}},
            "lease_states": [{"lease_id": "L", "known": false, "active": false}],
            "covered_by_checkpoint": null,
            "policy_reloaded_after": 9,
        });
        let text = render_entry_view(&v);
        assert!(
            text.contains("  L  unknown to the lease registry\n"),
            "{text}"
        );
        assert!(text.contains("checkpoint  none yet"), "{text}");
        assert!(
            text.contains("reloaded at seq 9, after this entry"),
            "{text}"
        );
        assert!(
            !text.contains("\nchain "),
            "admin records have no chain: {text}"
        );
    }

    #[test]
    fn empty_checkpoints_and_expired_evaluation() {
        assert_eq!(
            render_checkpoints(&json!({"checkpoints": [], "prev": null})),
            "no checkpoints stored\n"
        );
        let text = render_evaluation(&json!({
            "decision": "deny", "reason": "policy_deny", "policy_ids": [],
            "diagnostics": ["no policy matched"], "lease_check": "skipped",
            "chain_source": "token", "token_expired": true}));
        assert!(text.starts_with("DENY  policy_deny\n"), "{text}");
        assert!(text.contains("token (expired"), "{text}");
        assert!(text.contains("diagnostic: no policy matched"), "{text}");
    }

    fn approval() -> Value {
        json!({
            "approval_id": "a-1", "state": "granted", "expired": false, "chain_id": "l1",
            "lease": "l2", "call_hash": "ab12",
            "call": {"server": "github", "tool": "delete_repo", "arguments": {"repo": "a/b"}},
            "labels": [{"source": "github/read_web", "seq": 3}],
            "decision_id": "d-1", "subject": "alice", "issuer": "https://idp.example",
            "agents": ["planner", "coder"], "created_at": "2026-10-24T09:00:00Z",
            "expires_at": "2026-10-24T09:02:00Z", "decided_at": "2026-10-24T09:00:30Z",
            "approver": {"subject": "alice", "method": "id_token", "by": "user"},
        })
    }

    #[test]
    fn approval_view_shows_the_exact_call_and_its_labels() {
        let text = render_approval(&approval());
        assert!(text.contains("call       github/delete_repo\n"), "{text}");
        assert!(text.contains(r#"arguments  {"repo":"a/b"}"#), "{text}");
        assert!(
            text.contains("labels     github/read_web (audit seq 3)\n"),
            "{text}"
        );
        assert!(text.contains("agents     planner > coder\n"), "{text}");
        assert!(text.contains("by alice (user, id_token)"), "{text}");
        assert!(!text.contains("used by"), "{text}");
        let mut a = approval();
        a["labels"] = json!([]);
        a["consumed_by"] = json!("d-2");
        a["expired"] = json!(true);
        let text = render_approval(&a);
        assert!(text.contains("labels     none\n"), "{text}");
        assert!(text.contains("used by    decision d-2\n"), "{text}");
        assert!(text.contains("state      granted (expired)\n"), "{text}");
    }

    #[test]
    fn approval_list_has_one_line_each() {
        assert_eq!(
            render_approvals(&json!({"approvals": []})),
            "no approvals\n"
        );
        let mut expired = approval();
        expired["state"] = json!("pending");
        expired["expired"] = json!(true);
        let text = render_approvals(&json!({"approvals": [approval(), expired]}));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].starts_with("a-1  granted"), "{text}");
        assert!(lines[0].contains("github/delete_repo  run l1"), "{text}");
        assert!(lines[1].contains("pending (expired)"), "{text}");
    }
}
