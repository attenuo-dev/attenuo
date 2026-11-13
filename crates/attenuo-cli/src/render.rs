//! Human-readable rendering of chains, capabilities and times.

use attenuo_core::{ArgConstraint, Capability, CapabilitySet, DelegationChain};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub(crate) fn fmt_time(t: OffsetDateTime) -> String {
    let t = t.replace_nanosecond(0).unwrap_or(t);
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

/// "in 14m 30s" or "expired 2m 5s ago".
pub(crate) fn fmt_relative(t: OffsetDateTime, now: OffsetDateTime) -> String {
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

/// `s` with its control characters escaped (`\u{1b}`) and everything else as it is, for text
/// that a child or a caller chose and a terminal would otherwise act on (SR-59, SR-72).
fn escape_controls(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().collect()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn fmt_constraint(arg: &str, c: &ArgConstraint) -> String {
    // A child names the arguments of the constraints it adds (SR-72).
    let arg = escape_controls(arg);
    match c {
        ArgConstraint::Equals(v) => format!("{arg} == {v}"),
        ArgConstraint::OneOf(vs) => {
            let items: Vec<String> = vs.iter().map(|v| v.to_string()).collect();
            format!("{arg} in [{}]", items.join(", "))
        }
        ArgConstraint::Prefix(p) => format!("{arg} starts with {p:?}"),
        ArgConstraint::PathPrefix(p) => format!("{arg} is a path under {p:?}"),
        ArgConstraint::Range { min, max } => match (min, max) {
            (Some(lo), Some(hi)) => format!("{lo} <= {arg} <= {hi}"),
            (Some(lo), None) => format!("{arg} >= {lo}"),
            (None, Some(hi)) => format!("{arg} <= {hi}"),
            (None, None) => format!("{arg} is an integer"),
        },
    }
}

/// `github:read_file`, or `github:create_issue {repo starts with "acme/"}`, with run limits
/// (ADR-0010) after them: `banking:send_money [calls <= 1, sum(amount) <= 10]`.
pub(crate) fn fmt_capability(c: &Capability) -> String {
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
        ls.push(format!("calls per {} <= {}", p.counted(), p.max));
    }
    if let Some(d) = &l.distinct {
        ls.push(format!("distinct {} <= {}", d.counted(), d.max));
    }
    if !ls.is_empty() {
        out.push_str(&format!(" [{}]", ls.join(", ")));
    }
    out
}

pub(crate) fn fmt_capabilities(set: &CapabilitySet) -> String {
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
pub(crate) fn render_chain_tree(chain: &DelegationChain, now: OffsetDateTime) -> String {
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

/// The `may_act` line of `token inspect`: who may exchange the token next (RFC 8693 §4.4).
/// Absent means any authenticated agent may; an empty list, none. Agent ids are printed with
/// control characters escaped, since they come from the token.
pub(crate) fn fmt_may_act(may_act: Option<&attenuo_token::MayAct>) -> String {
    match may_act {
        None => "may_act (absent): any authenticated agent may exchange this token".into(),
        Some(m) if m.sub.is_empty() => "may_act []: no agent may exchange this token".into(),
        Some(m) => {
            let agents: Vec<String> = m.sub.iter().map(|a| a.escape_debug().to_string()).collect();
            format!(
                "may_act {}: only {} may exchange this token",
                agents.join(", "),
                if agents.len() == 1 {
                    "this agent"
                } else {
                    "these agents"
                }
            )
        }
    }
}

/// `token inspect`'s key line: the header `kid` (the key that signed the token) and `ou_kid`
/// (the key that made the originating-user signature `ou_sig` at the root, which differs after
/// a key rotation), each only when present and with control characters escaped. `None` when
/// neither is there.
pub(crate) fn fmt_kids(kid: Option<&str>, ou_kid: Option<&str>) -> Option<String> {
    let parts: Vec<String> = [("kid", kid), ("ou_kid", ou_kid)]
        .into_iter()
        .filter_map(|(name, v)| {
            v.filter(|v| !v.is_empty())
                .map(|v| format!("{name} {}", v.escape_debug()))
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("   "))
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
///
/// Decisions, token issuance, lease and admin records print `ALLOW`/`DENY` and the reason as
/// they always did (the latter three name themselves in `server/tool`, e.g.
/// `attenuo/token.exchange`). The records that are not decisions but would read like one,
/// `tool_result`, `approval_request` and `approval_grant`, print their kind in place of
/// `ALLOW`/`DENY` and the details that matter for that kind.
pub(crate) fn fmt_audit_entry(e: &Value) -> String {
    let r = &e["record"];
    let agents = strs(&r["agents"]);
    // Admin actions have no delegation chain, so no agents.
    let who = if agents.is_empty() {
        "by".to_string()
    } else {
        format!("{} for", agents.join(" > "))
    };
    let seq = e["seq"].as_u64().unwrap_or(0);
    let kind = r["kind"].as_str().unwrap_or("decision");
    let detail = match kind {
        "tool_result" => {
            let res = &r["result"];
            let mut d = format!(
                "decision={}  label={} size={}",
                s(r, "decision_id"),
                s(res, "label"),
                res["size"]
                    .as_u64()
                    .map_or("-".to_string(), |n| n.to_string()),
            );
            if res["error"] == true {
                d.push_str(" error");
            }
            d
        }
        "approval_request" => {
            let a = &r["approval"];
            format!(
                "decision={}  approval={} expires={}",
                s(r, "decision_id"),
                s(a, "id"),
                s(a, "expires_at")
            )
        }
        "approval_grant" => {
            let a = &r["approval"];
            format!(
                "decision={}  approval={} outcome={} by={}",
                s(r, "decision_id"),
                s(a, "id"),
                s(a, "outcome"),
                s(a, "by")
            )
        }
        _ => String::new(),
    };
    if detail.is_empty() {
        return format!(
            "#{:<4} {}  {:<5} {}/{}  {} {}  reason={}  id={}",
            seq,
            s(r, "at"),
            s(r, "decision").to_uppercase(),
            s(r, "server"),
            s(r, "tool"),
            who,
            s(r, "originating_subject"),
            s(r, "reason"),
            s(r, "id"),
        );
    }
    format!(
        "#{:<4} {}  {}  {}/{}  {} {}  {}  id={}",
        seq,
        s(r, "at"),
        kind,
        s(r, "server"),
        s(r, "tool"),
        who,
        s(r, "originating_subject"),
        detail,
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
pub(crate) fn render_entry_view(v: &Value) -> String {
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

/// The options a listing was given that its next page needs again (`--limit`, filters), as
/// ` --name value` each, values quoted for a POSIX shell when they need it, for the hint that
/// names the next page's command. Options without a value are left out.
pub(crate) fn repeat_flags(flags: &[(&str, Option<String>)]) -> String {
    let mut out = String::new();
    for (name, value) in flags {
        if let Some(v) = value {
            out.push_str(&format!(" {name} {}", shell_word(v)));
        }
    }
    out
}

/// `s` as one POSIX shell word: as it is when it has only safe characters, else in single
/// quotes.
fn shell_word(s: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_.:/@%+=,".contains(c);
    if !s.is_empty() && s.chars().all(safe) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// `audit checkpoints`: one line per stored checkpoint, newest first, and how to page on.
/// `flags` are the options to repeat on the next page ([`repeat_flags`]).
pub(crate) fn render_checkpoints(v: &Value, flags: &str) -> String {
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
    if let Some(next) = v["next_cursor"].as_str() {
        out.push_str(&format!(
            "older: audit checkpoints{flags} --cursor {next}\n"
        ));
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

/// A JSON number as text, `-` when absent or null.
fn num(v: &Value) -> String {
    if v.is_null() {
        "-".to_string()
    } else {
        v.to_string()
    }
}

/// The lines a lease tree node's `budget` adds under it: `limits not recorded` for a lease
/// issued by a server that did not keep its limits, then one `limit` line per limit
/// (`<server>/<tool> <kind> [<arg>] <used>/<max> (<remaining> left)`, with the number of
/// values seen for `calls_per`), then one `usage` line per destructive tool on a run's root
/// lease. Nothing for a `null` budget.
pub(crate) fn fmt_budget(b: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if b.is_null() {
        return out;
    }
    if b["recorded"] == false {
        out.push("limits not recorded".to_string());
    }
    for l in b["limits"].as_array().into_iter().flatten() {
        let target = match (l["server"].as_str(), l["tool"].as_str()) {
            (Some(server), Some(tool)) => format!("{server}/{tool}"),
            _ => format!("cap {}", num(&l["cap"])),
        };
        let mut line = format!("limit {target} {}", s(l, "kind"));
        if let Some(arg) = l["arg"].as_str() {
            // A child chooses the names of the limits it adds: escape control characters so
            // a name cannot drive the terminal (SR-59; tokens with one are refused since).
            line.push_str(&format!(" {}", arg.escape_debug()));
        }
        let values = (l["kind"] == "calls_per").then(|| format!("{} values", num(&l["values"])));
        if l["max"].is_null() {
            line.push_str(&format!(" {} used", num(&l["used"])));
            if let Some(v) = values {
                line.push_str(&format!(" ({v})"));
            }
        } else {
            let mut paren = format!("{} left", num(&l["remaining"]));
            if let Some(v) = values {
                paren.push_str(&format!(", {v}"));
            }
            line.push_str(&format!(
                " {}/{} ({paren})",
                num(&l["used"]),
                num(&l["max"])
            ));
        }
        out.push(line);
    }
    for u in b["usage"].as_array().into_iter().flatten() {
        out.push(format!(
            "usage {}: {} calls, amount {}, {} destinations",
            s(u, "tool"),
            num(&u["calls"]),
            num(&u["amount"]),
            num(&u["destinations"])
        ));
    }
    out
}

type Children<'a> = std::collections::BTreeMap<&'a str, Vec<&'a Value>>;

/// The budget lines of tree node `n`, whose children are drawn below it at `deeper`; a `│`
/// keeps the line down to its first child unbroken.
fn tree_budget(out: &mut String, n: &Value, deeper: &str, children: &Children) {
    let has_kids = children.contains_key(s(n, "lease_id"));
    for line in fmt_budget(&n["budget"]) {
        out.push_str(&format!(
            "{deeper}{}{line}\n",
            if has_kids { "│    " } else { "     " }
        ));
    }
}

/// `lease tree`: the ancestors nearest first, then the lease and its descendants drawn as a
/// tree, then what a revoke would change. Each lease with a `budget` has its limit and usage
/// lines under it, indented to stay inside its branch.
pub(crate) fn render_lease_tree(v: &Value) -> String {
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
            for line in fmt_budget(&a["budget"]) {
                out.push_str(&format!("       {line}\n"));
            }
        }
    }
    // Breadth-first order puts every parent before its children, so a parent-to-children
    // map drawn from the first node reaches every listed lease.
    let mut children: Children = Default::default();
    for n in nodes.iter().skip(1) {
        children.entry(s(n, "parent")).or_default().push(n);
    }
    fn draw(out: &mut String, n: &Value, prefix: &str, children: &Children) {
        let kids = children.get(s(n, "lease_id")).cloned().unwrap_or_default();
        for (i, k) in kids.iter().enumerate() {
            let last = i + 1 == kids.len();
            out.push_str(&format!(
                "{prefix}{}{}\n",
                if last { "└─ " } else { "├─ " },
                fmt_tree_node(k)
            ));
            let deeper = format!("{prefix}{}", if last { "   " } else { "│  " });
            tree_budget(out, k, &deeper, children);
            draw(out, k, &deeper, children);
        }
    }
    if let Some(first) = nodes.first() {
        out.push_str(&format!("{}\n", fmt_tree_node(first)));
        tree_budget(&mut out, first, "", &children);
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

/// `budget refund`: what was given back and the audit record that says so.
pub(crate) fn render_refund(v: &Value) -> String {
    let audit = match v["audit_id"].as_str() {
        Some(id) => id.to_string(),
        None => "- (the refund stands, but its audit record was not written; see the server log)"
            .to_string(),
    };
    format!(
        "decision  {}\nrefunded  {} limit counter(s)\nreason    {}\naudit     {audit}\n",
        s(v, "decision_id"),
        num(&v["refunded"]),
        s(v, "reason"),
    )
}

/// `lease revoke --user/--chain-id/--session [--preview]`: the selector (for a session, its
/// audit tag and the chains it resolved to), the counts, then one line per revoked lease (the
/// matches first, then the cascade), and the audit record.
pub(crate) fn render_selector_revocation(v: &Value) -> String {
    let preview = v["preview"].as_bool().unwrap_or(false);
    let sel = &v["selector"];
    let session = sel["session_tag"].as_str();
    let selector = match (session, sel.as_object().and_then(|o| o.iter().next())) {
        (Some(tag), _) => format!("session {tag}"),
        (None, Some((k, val))) => format!("{k} {}", val.as_str().unwrap_or("-")),
        (None, None) => "-".to_string(),
    };
    let mut out = String::new();
    if preview {
        out.push_str("preview: nothing was changed\n");
    }
    out.push_str(&format!("selector  {selector}\n"));
    if session.is_some() {
        let chains: Vec<&str> = sel["chain_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if chains.is_empty() {
            out.push_str("chains    none recorded for this session\n");
        } else {
            out.push_str(&format!("chains    {}\n", chains.join(", ")));
        }
    }
    out.push_str(&format!(
        "matched   {} lease(s)\n",
        num(&v["matched_count"])
    ));
    let verb = if preview { "would revoke" } else { "revoked" };
    out.push_str(&format!("{verb} {} lease(s)\n", num(&v["revoked_count"])));
    for id in v["revoked"].as_array().into_iter().flatten() {
        out.push_str(&format!("  {}\n", id.as_str().unwrap_or("-")));
    }
    if v["truncated"].as_bool().unwrap_or(false) {
        out.push_str("  (list cut short; the counts are complete, see --json)\n");
    }
    if !preview {
        out.push_str(&format!("reason    {}\n", s(v, "reason")));
        let audit = match v["audit_id"].as_str() {
            Some(id) => id.to_string(),
            None => "- (the revocation stands, but its audit record was not written; see the \
                     server log)"
                .to_string(),
        };
        out.push_str(&format!("audit     {audit}\n"));
    }
    out
}

/// `approval list`: one line per approval, newest first. `flags` are the filters and
/// `--limit` to repeat on the next page ([`repeat_flags`]).
pub(crate) fn render_approvals(v: &Value, flags: &str) -> String {
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
    if let Some(next) = v["next_cursor"].as_str() {
        out.push_str(&format!(
            "more: approval list{flags} --cursor {next}, or --all\n"
        ));
    }
    out
}

/// `approval show` (and the answer to `grant` / `decline`): the exact call the approval is
/// for, the run's labels, and its state.
pub(crate) fn render_approval(a: &Value) -> String {
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
pub(crate) fn render_policies(v: &Value) -> String {
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
pub(crate) fn render_policy_check(v: &Value) -> String {
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
pub(crate) fn render_evaluation(v: &Value) -> String {
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
            Some(text) => out.push_str(&format!("diagnostic: {}\n", escape_controls(text))),
            None => out.push_str(&format!("diagnostic: {d}\n")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    /// An entry as `GET /admin/audit` returns it, with `extra` merged into the record.
    fn entry(seq: u64, kind: &str, extra: Value) -> Value {
        let mut record = json!({
            "id": "rec1", "at": "2026-10-24T10:00:00Z", "kind": kind, "decision": "allow",
            "reason": "r", "originating_subject": "alice", "agents": ["planner", "coder"],
            "server": "github", "tool": "read_file"});
        for (k, v) in extra.as_object().unwrap() {
            record[k] = v.clone();
        }
        json!({"seq": seq, "record": record})
    }

    #[test]
    fn decision_line_is_unchanged_with_or_without_a_kind() {
        let want = "#4    2026-10-24T10:00:00Z  ALLOW github/read_file  planner > coder for alice  reason=policy_allow  id=rec1";
        let with = entry(4, "decision", json!({"reason": "policy_allow"}));
        assert_eq!(fmt_audit_entry(&with), want);
        let mut without = with.clone();
        without["record"].as_object_mut().unwrap().remove("kind");
        assert_eq!(fmt_audit_entry(&without), want);
    }

    #[test]
    fn tool_result_line_names_kind_decision_label_and_size() {
        let e = entry(
            5,
            "tool_result",
            json!({"reason": "tool_result", "decision_id": "dec1",
                   "result": {"digest": "ab", "size": 149, "label": "untrusted", "fingerprints": 0}}),
        );
        assert_eq!(
            fmt_audit_entry(&e),
            "#5    2026-10-24T10:00:00Z  tool_result  github/read_file  planner > coder for alice  decision=dec1  label=untrusted size=149  id=rec1"
        );
        let mut err = e.clone();
        err["record"]["result"]["error"] = json!(true);
        assert!(fmt_audit_entry(&err).contains("size=149 error  id="));
    }

    #[test]
    fn approval_request_line_names_approval_and_expiry() {
        let e = entry(
            6,
            "approval_request",
            json!({"decision": "deny", "reason": "approval_requested", "decision_id": "dec2",
                   "approval": {"id": "ap1", "expires_at": "2026-10-24T10:02:00Z"}}),
        );
        assert_eq!(
            fmt_audit_entry(&e),
            "#6    2026-10-24T10:00:00Z  approval_request  github/read_file  planner > coder for alice  decision=dec2  approval=ap1 expires=2026-10-24T10:02:00Z  id=rec1"
        );
    }

    #[test]
    fn approval_grant_line_names_outcome_and_approver() {
        let e = entry(
            7,
            "approval_grant",
            json!({"reason": "approval_granted", "decision_id": "dec2",
                   "approval": {"id": "ap1", "by": "operator", "outcome": "grant"}}),
        );
        assert_eq!(
            fmt_audit_entry(&e),
            "#7    2026-10-24T10:00:00Z  approval_grant  github/read_file  planner > coder for alice  decision=dec2  approval=ap1 outcome=grant by=operator  id=rec1"
        );
        let mut declined = e.clone();
        declined["record"]["approval"]["outcome"] = json!("decline");
        declined["record"]["approval"]["by"] = json!("user");
        assert!(fmt_audit_entry(&declined).contains("outcome=decline by=user"));
    }

    #[test]
    fn exchange_admin_and_lease_rows_keep_their_look() {
        for (kind, tool) in [
            ("exchange", "token.exchange"),
            ("root_token", "token.root"),
            ("lease_renew", "lease.renew"),
            ("lease_revoke", "admin.lease.revoke"),
            ("admin", "admin.policy.reload"),
        ] {
            let e = entry(
                1,
                kind,
                json!({"server": "attenuo", "tool": tool, "reason": "admin_action", "agents": []}),
            );
            assert_eq!(
                fmt_audit_entry(&e),
                format!("#1    2026-10-24T10:00:00Z  ALLOW attenuo/{tool}  by alice  reason=admin_action  id=rec1")
            );
        }
    }

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
    fn may_act_line_says_who_may_exchange() {
        use attenuo_token::MayAct;
        assert_eq!(
            fmt_may_act(None),
            "may_act (absent): any authenticated agent may exchange this token"
        );
        assert_eq!(
            fmt_may_act(Some(&MayAct::new(Vec::<String>::new()))),
            "may_act []: no agent may exchange this token"
        );
        assert_eq!(
            fmt_may_act(Some(&MayAct::new(["coder"]))),
            "may_act coder: only this agent may exchange this token"
        );
        assert_eq!(
            fmt_may_act(Some(&MayAct::new(["coder", "reviewer"]))),
            "may_act coder, reviewer: only these agents may exchange this token"
        );
        // An agent id with a terminal escape in it is printed escaped.
        let line = fmt_may_act(Some(&MayAct::new(["evil\u{1b}[2J"])));
        assert!(!line.chars().any(char::is_control), "{line}");
        assert!(line.contains("evil\\u{1b}[2J"), "{line}");
    }

    #[test]
    fn key_line_shows_the_kids_that_are_present() {
        assert_eq!(
            fmt_kids(Some("k1"), Some("k0")).as_deref(),
            Some("kid k1   ou_kid k0")
        );
        assert_eq!(fmt_kids(None, Some("k0")).as_deref(), Some("ou_kid k0"));
        assert_eq!(fmt_kids(Some("k1"), Some("")).as_deref(), Some("kid k1"));
        assert_eq!(fmt_kids(None, None), None);
        let line = fmt_kids(Some("evil\u{1b}[2J"), None).unwrap();
        assert!(!line.chars().any(char::is_control), "{line}");
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
        let paths = Capability::new("fs", "read_file")
            .with_constraint("path", ArgConstraint::path_prefix("/workspace/").unwrap())
            .with_constraint("root", ArgConstraint::Prefix("/workspace/".into()));
        assert_eq!(
            fmt_capability(&paths),
            "fs:read_file {path is a path under \"/workspace/\", root starts with \"/workspace/\"}"
        );
        let range = |min, max| ArgConstraint::range(min, max).unwrap();
        let ranged = Capability::new("bank", "send_money")
            .with_constraint("amount", range(Some(0), Some(2000)))
            .with_constraint("fee", range(None, Some(5)))
            .with_constraint("n", range(Some(-1), None));
        assert_eq!(
            fmt_capability(&ranged),
            "bank:send_money {0 <= amount <= 2000, fee <= 5, n >= -1}"
        );
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
        let mut hosts = attenuo_core::Limits::default().with_distinct("url", 2);
        hosts.distinct = hosts
            .distinct
            .map(|d| d.derived(attenuo_core::Derive::Host));
        assert_eq!(
            fmt_capability(&Capability::new("web", "get_webpage").with_limits(hosts)),
            "web:get_webpage [distinct url#host <= 2]"
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

    fn limit(
        server: &str,
        tool: &str,
        kind: &str,
        arg: Option<&str>,
        max: u64,
        used: u64,
    ) -> Value {
        json!({"cap": 0, "server": server, "tool": tool, "kind": kind, "arg": arg,
               "max": max, "used": used, "remaining": max - used})
    }

    #[test]
    fn budget_lines_for_every_limit_kind_and_usage() {
        let mut per = limit("bank", "send_money", "calls_per", Some("to"), 3, 2);
        per["values"] = json!(4);
        let b = json!({"recorded": true, "limits": [
            limit("bank", "send_money", "calls", None, 5, 1),
            limit("bank", "send_money", "sum", Some("amount"), 100, 30),
            per,
            limit("web", "get_webpage", "distinct", Some("url#host"), 2, 2),
        ], "usage": [
            {"tool": "bank/send_money", "calls": 2, "amount": 30, "destinations": 1},
        ]});
        assert_eq!(
            fmt_budget(&b),
            [
                "limit bank/send_money calls 1/5 (4 left)",
                "limit bank/send_money sum amount 30/100 (70 left)",
                "limit bank/send_money calls_per to 2/3 (1 left, 4 values)",
                "limit web/get_webpage distinct url#host 2/2 (0 left)",
                "usage bank/send_money: 2 calls, amount 30, 1 destinations",
            ]
        );
        assert!(fmt_budget(&Value::Null).is_empty());
        // Usage alone (a root lease with no token limits) is still shown.
        let usage_only = json!({"recorded": true, "limits": [], "usage": [
            {"tool": "github/create_issue", "calls": 1, "amount": 0, "destinations": 0}]});
        assert_eq!(
            fmt_budget(&usage_only),
            ["usage github/create_issue: 1 calls, amount 0, 0 destinations"]
        );
    }

    /// SR-59: a limit name with a terminal escape in it is printed escaped.
    #[test]
    fn budget_lines_escape_control_characters_sr59() {
        let b = json!({"recorded": true, "limits": [
            limit("mail", "send", "calls_per", Some("to\u{1b}[2J\u{1b}]0;x\u{7}"), 3, 0),
        ], "usage": []});
        let lines = fmt_budget(&b);
        assert!(!lines[0].chars().any(char::is_control), "{lines:?}");
        assert!(lines[0].contains(r"to\u{1b}[2J"), "{lines:?}");
    }

    /// SR-72: a child chooses the argument names of the constraints it adds, and they reach
    /// `token inspect`, `lease tree` and the dry run's `capability_denied` diagnostic.
    #[test]
    fn constraint_names_and_diagnostics_escape_control_characters_sr72() {
        let evil = "amount\u{1b}[2J\u{1b}]0;x\u{7}";
        let c = Capability::new("bank", "send_money")
            .with_constraint(evil, ArgConstraint::range(None, Some(5)).unwrap());
        let text = fmt_capability(&c);
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert!(text.contains(r"amount\u{1b}[2J"), "{text}");
        let text = render_evaluation(&json!({
            "decision": "deny", "reason": "capability_denied", "policy_ids": [],
            "diagnostics": [format!("bank:send_money: argument `{evil}` is absent; \"acme/\"")],
            "lease_check": "skipped", "chain_source": "token"}));
        assert!(
            !text
                .trim_end()
                .lines()
                .any(|l| l.chars().any(char::is_control)),
            "{text:?}"
        );
        assert!(text.contains(r"argument `amount\u{1b}[2J"), "{text}");
        assert!(
            text.contains("; \"acme/\""),
            "quotes stay as they are: {text}"
        );
    }

    #[test]
    fn budget_lines_when_the_limits_were_not_recorded() {
        // An older server kept the counters but not the hop's limits: no server, tool or max.
        let b = json!({"recorded": false, "usage": [], "limits": [
            {"cap": 0, "server": null, "tool": null, "kind": "calls", "arg": null,
             "max": null, "used": 2, "remaining": null},
            {"cap": 1, "server": null, "tool": null, "kind": "calls_per", "arg": "to",
             "max": null, "used": 1, "remaining": null, "values": 3},
        ]});
        assert_eq!(
            fmt_budget(&b),
            [
                "limits not recorded",
                "limit cap 0 calls 2 used",
                "limit cap 1 calls_per to 1 used (3 values)",
            ]
        );
    }

    #[test]
    fn lease_tree_puts_budgets_under_their_lease() {
        let mut root = node("R", None, "planner", false);
        root["budget"] = json!({"recorded": true, "limits": [], "usage": [
            {"tool": "bank/send_money", "calls": 1, "amount": 10, "destinations": 1}]});
        let mut a = node("A", Some("R"), "coder", false);
        a["budget"] = json!({"recorded": true, "usage": [], "limits": [
            limit("bank", "send_money", "calls", None, 2, 1)]});
        let mut b = node("B", Some("A"), "reviewer", false);
        b["budget"] = json!({"recorded": false, "usage": [], "limits": []});
        let mut c = node("C", Some("A"), "tester", false);
        c["budget"] = json!({"recorded": true, "usage": [], "limits": [
            limit("web", "get_webpage", "distinct", Some("url#host"), 2, 1)]});
        let v = json!({
            "root": "R",
            "ancestors": [root],
            "nodes": [a, b, c, node("D", Some("B"), "linter", false)],
            "would_revoke": 4,
            "truncated": false,
        });
        let expected = "\
ancestors (nearest first, chain root R)
  R  planner  active, expires 2026-10-23T10:00:00Z  issued #3
       usage bank/send_money: 1 calls, amount 10, 1 destinations
A  coder  active, expires 2026-10-23T10:00:00Z  issued #3
│    limit bank/send_money calls 1/2 (1 left)
├─ B  reviewer  active, expires 2026-10-23T10:00:00Z  issued #3
│  │    limits not recorded
│  └─ D  linter  active, expires 2026-10-23T10:00:00Z  issued #3
└─ C  tester  active, expires 2026-10-23T10:00:00Z  issued #3
        limit web/get_webpage distinct url#host 1/2 (1 left)
would revoke 4 lease(s) if revoked now
";
        assert_eq!(render_lease_tree(&v), expected);
    }

    #[test]
    fn selector_revocation_lists_the_revoked_leases() {
        let v = json!({"selector": {"user": "alice"}, "preview": false,
                       "matched": ["L1"], "revoked": ["L1", "L2"], "matched_count": 1,
                       "revoked_count": 2, "truncated": false, "reason": "stolen",
                       "audit_id": "A9"});
        assert_eq!(
            render_selector_revocation(&v),
            "selector  user alice\nmatched   1 lease(s)\nrevoked 2 lease(s)\n  L1\n  L2\n\
             reason    stolen\naudit     A9\n"
        );
        let p = json!({"selector": {"chain_id": "L0"}, "preview": true, "matched": [],
                       "revoked": [], "matched_count": 0, "revoked_count": 0,
                       "truncated": true, "reason": null, "audit_id": null});
        let text = render_selector_revocation(&p);
        assert!(text.starts_with("preview: nothing was changed\n"), "{text}");
        assert!(text.contains("selector  chain_id L0\n"), "{text}");
        assert!(text.contains("would revoke 0 lease(s)\n"), "{text}");
        assert!(text.contains("list cut short"), "{text}");
        assert!(!text.contains("audit"), "{text}");

        let v = json!({"selector": {"session_tag": "0a1b2c3d4e5f", "chain_ids": ["L0"]},
                       "preview": true, "matched": ["L0", "L1"], "revoked": ["L0", "L1"],
                       "matched_count": 2, "revoked_count": 2, "truncated": false,
                       "reason": null, "audit_id": null});
        assert_eq!(
            render_selector_revocation(&v),
            "preview: nothing was changed\nselector  session 0a1b2c3d4e5f\nchains    L0\n\
             matched   2 lease(s)\nwould revoke 2 lease(s)\n  L0\n  L1\n"
        );
        let v = json!({"selector": {"session_tag": "0a1b2c3d4e5f", "chain_ids": []},
                       "preview": true, "matched": [], "revoked": [], "matched_count": 0,
                       "revoked_count": 0, "truncated": false});
        let text = render_selector_revocation(&v);
        assert!(
            text.contains("chains    none recorded for this session\n"),
            "{text}"
        );
    }

    #[test]
    fn refund_answer_names_decision_count_and_audit_record() {
        let v = json!({"decision_id": "D1", "refunded": 2, "reason": "upstream timed out",
                       "audit_id": "A9"});
        assert_eq!(
            render_refund(&v),
            "decision  D1\nrefunded  2 limit counter(s)\nreason    upstream timed out\naudit     A9\n"
        );
        let unaudited = json!({"decision_id": "D1", "refunded": 0, "reason": "r",
                               "audit_id": null});
        let text = render_refund(&unaudited);
        assert!(text.contains("refunded  0 limit counter(s)"), "{text}");
        assert!(text.contains("audit     - (the refund stands"), "{text}");
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
            render_checkpoints(&json!({"checkpoints": [], "prev": null}), ""),
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
            render_approvals(&json!({"approvals": []}), ""),
            "no approvals\n"
        );
        let mut expired = approval();
        expired["state"] = json!("pending");
        expired["expired"] = json!(true);
        let text = render_approvals(&json!({"approvals": [approval(), expired]}), "");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].starts_with("a-1  granted"), "{text}");
        assert!(lines[0].contains("github/delete_repo  run l1"), "{text}");
        assert!(lines[1].contains("pending (expired)"), "{text}");
    }

    #[test]
    fn next_page_hints_repeat_the_limit_and_filters() {
        let flags = repeat_flags(&[
            ("--chain-id", Some("l1".into())),
            ("--state", None),
            ("--limit", Some("5".into())),
        ]);
        assert_eq!(flags, " --chain-id l1 --limit 5");
        let page = json!({"approvals": [approval()], "next_cursor": "AQID"});
        assert!(
            render_approvals(&page, &flags)
                .ends_with("more: approval list --chain-id l1 --limit 5 --cursor AQID, or --all\n"),
            "{}",
            render_approvals(&page, &flags)
        );
        let cps = json!({"checkpoints": [{"seq": 9, "at": "t", "kid": "k", "head_hash": "h"}],
                         "next_cursor": "AQIC"});
        let text = render_checkpoints(&cps, &repeat_flags(&[("--limit", Some("3".into()))]));
        assert!(
            text.ends_with("older: audit checkpoints --limit 3 --cursor AQIC\n"),
            "{text}"
        );
        assert_eq!(
            repeat_flags(&[("--x", Some("it's a b".into()))]),
            r" --x 'it'\''s a b'"
        );
        assert_eq!(repeat_flags(&[("--x", Some(String::new()))]), " --x ''");
    }
}
