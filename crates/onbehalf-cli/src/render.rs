//! Human-readable rendering of chains, capabilities and times.

use onbehalf_core::{ArgConstraint, Capability, CapabilitySet, DelegationChain};
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

/// `github:read_file`, or `github:create_issue {repo starts with "acme/"}`.
pub fn fmt_capability(c: &Capability) -> String {
    let base = format!("{}:{}", c.server, c.tool);
    if c.constraints.is_empty() {
        return base;
    }
    let cs: Vec<String> = c
        .constraints
        .iter()
        .map(|(arg, con)| fmt_constraint(arg, con))
        .collect();
    format!("{base} {{{}}}", cs.join(", "))
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

#[cfg(test)]
mod tests {
    use super::*;
    use onbehalf_core::{AgentId, LeaseId, OriginatingUser};
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
    }
}
