//! `[idps.id_jag_ceiling]`: an ID-JAG's `resource`, `scope` and `authorization_details`
//! claims as a ceiling under `[[root_grants]]` (draft-ietf-oauth-identity-assertion-authz-grant
//! -06 §4.4.1).
//!
//! Opt-in per `[[idps]]` entry. With the table absent, [`super::intake`] does not call into this
//! module and the claims are ignored, as before.
//!
//! # What each claim names
//!
//! Every claim is turned into a set of capabilities, the most the ID-JAG allows by that claim:
//!
//! | Claim | Names |
//! |---|---|
//! | `authorization_details` | the `capabilities` of every entry whose `type` is `attenuo_capabilities` ([`AUTHORIZATION_DETAILS_TYPE`]), each read strictly ([`CapabilityConfig`]: an unknown member, or a name that is not valid, makes that capability name nothing). An entry of any other `type` names nothing, and so does the whole claim when its entries hold more than [`MAX_CLAIM_CAPABILITIES`] capabilities |
//! | `resource` (string or array of strings) | `<server>:*` for every server that `resources` maps the value to. An unmapped value names nothing |
//! | `scope` (space-separated string) | the capabilities that `scopes` maps each token to. An unmapped token names nothing |
//!
//! A claim of the wrong JSON type names nothing. A claim that is absent or `null` is not used.
//!
//! # How the ceiling is formed
//!
//! Start from the root grant's capabilities `G`. For each claim present, in the order
//! `resource`, `scope`, `authorization_details`, replace `G` by [`meet`]`(G, named)`. Every
//! step can only narrow, so the result is `⊑` the root grant and `⊑` every claim used. The
//! request is then attenuated against the result as against a root grant.
//!
//! [`meet`] is not the greatest lower bound: it keeps a capability of one side when a single
//! capability of the other side covers it (after clamping limits), the same conservative rule
//! as [`CapabilitySet::covers`]. Two capabilities that only overlap (`github:read_*` and
//! `github:*_file`) give nothing, rather than a new capability built from both.

use std::collections::BTreeMap;

use attenuo_core::{Capability, CapabilitySet};
use attenuo_token::AUTHORIZATION_DETAILS_TYPE;
use serde_json::{Map, Value};

use crate::config::{check_server_name, CapSpec, CapabilityConfig, IdJagCeilingConfig};

/// The claims a ceiling reads, in the order they are applied.
pub(crate) const CEILING_CLAIMS: [&str; 3] = ["resource", "scope", "authorization_details"];

/// The most capabilities an `authorization_details` claim may name, over all its
/// `attenuo_capabilities` entries. A claim naming more names nothing, so the request is refused
/// (`id_jag_ceiling_empty`): the request is attenuated against the ceiling, which costs the
/// product of the two sizes, before any of it reaches the blocking pool (SR-123).
pub(crate) const MAX_CLAIM_CAPABILITIES: usize = 256;

/// A checked `[idps.id_jag_ceiling]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdJagCeiling {
    resources: BTreeMap<String, CapabilitySet>,
    scopes: BTreeMap<String, CapabilitySet>,
}

/// The ceiling for one ID-JAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Applied {
    /// What the root token may carry at most: `⊑` the root grant and every claim in `claims`.
    pub capabilities: CapabilitySet,
    /// The claims that were present and narrowed it, in [`CEILING_CLAIMS`] order.
    pub claims: Vec<&'static str>,
}

impl IdJagCeiling {
    /// Check the table: every resource maps to at least one valid server name, every scope
    /// token is non-empty without whitespace and maps to at least one valid capability (names and limits).
    ///
    /// # Errors
    ///
    /// A message naming the first entry that breaks a rule.
    pub(crate) fn from_config(cfg: &IdJagCeilingConfig) -> Result<Self, String> {
        let mut resources = BTreeMap::new();
        for (resource, servers) in &cfg.resources {
            if resource.trim().is_empty() {
                return Err("id_jag_ceiling.resources: a resource identifier is empty".into());
            }
            if servers.is_empty() {
                return Err(format!(
                    "id_jag_ceiling.resources: `{resource}` maps to no server; name one or remove it"
                ));
            }
            let mut set = CapabilitySet::new();
            for server in servers {
                check_server_name(server)
                    .map_err(|e| format!("id_jag_ceiling.resources `{resource}`: {e}"))?;
                set.insert(Capability::new(server.clone(), "*"));
            }
            resources.insert(resource.clone(), set);
        }
        let mut scopes = BTreeMap::new();
        for (scope, specs) in &cfg.scopes {
            if scope.is_empty() || scope.chars().any(char::is_whitespace) {
                return Err(format!(
                    "id_jag_ceiling.scopes: {scope:?} is not a scope token (empty, or with whitespace)"
                ));
            }
            if specs.is_empty() {
                return Err(format!(
                    "id_jag_ceiling.scopes: `{scope}` maps to no capability; name one or remove it"
                ));
            }
            let mut set = CapabilitySet::new();
            for spec in specs {
                let cap = CapSpec::to_capability(spec)
                    .map_err(|e| format!("id_jag_ceiling.scopes `{scope}`: {e}"))?;
                cap.validate()
                    .map_err(|e| format!("id_jag_ceiling.scopes `{scope}`: {e}"))?;
                // As for an `authorization_details` capability: limits no token may carry
                // would otherwise fail every intake that keeps this capability (SR-125).
                cap.validate_limits()
                    .map_err(|e| format!("id_jag_ceiling.scopes `{scope}`: {e}"))?;
                cap.validate_size()
                    .map_err(|e| format!("id_jag_ceiling.scopes `{scope}`: {e}"))?;
                if cap.server != "*" {
                    check_server_name(&cap.server)
                        .map_err(|e| format!("id_jag_ceiling.scopes `{scope}`: {e}"))?;
                }
                set.insert(cap);
            }
            set.validate_size()
                .map_err(|e| format!("id_jag_ceiling.scopes `{scope}`: {e}"))?;
            scopes.insert(scope.clone(), set);
        }
        Ok(Self { resources, scopes })
    }

    /// The ceiling for an ID-JAG with these verified `claims`, under the root grant's
    /// capabilities `grant`. See the module docs.
    pub(crate) fn apply(&self, grant: &CapabilitySet, claims: &Map<String, Value>) -> Applied {
        let mut capabilities = grant.clone();
        let mut used = Vec::new();
        for name in CEILING_CLAIMS {
            let Some(value) = claims.get(name).filter(|v| !v.is_null()) else {
                continue;
            };
            let named = match name {
                "resource" => self.named_by_resource(value),
                "scope" => self.named_by_scope(value),
                _ => named_by_details(value),
            };
            capabilities = meet(&capabilities, &named);
            used.push(name);
        }
        Applied {
            capabilities,
            claims: used,
        }
    }

    fn named_by_resource(&self, value: &Value) -> CapabilitySet {
        let values: Vec<&str> = match value {
            Value::String(s) => vec![s.as_str()],
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        values
            .into_iter()
            .filter_map(|v| self.resources.get(v))
            .flat_map(|set| set.iter().cloned())
            .collect()
    }

    fn named_by_scope(&self, value: &Value) -> CapabilitySet {
        value
            .as_str()
            .unwrap_or("")
            .split_ascii_whitespace()
            .filter_map(|token| self.scopes.get(token))
            .flat_map(|set| set.iter().cloned())
            .collect()
    }
}

/// The capabilities of the `attenuo_capabilities` entries of an `authorization_details` claim.
/// Nothing when they hold more than [`MAX_CLAIM_CAPABILITIES`] capability objects (SR-123).
fn named_by_details(value: &Value) -> CapabilitySet {
    let Some(entries) = value.as_array() else {
        return CapabilitySet::new();
    };
    let objects: Vec<&Value> = entries
        .iter()
        .filter(|e| e.get("type").and_then(Value::as_str) == Some(AUTHORIZATION_DETAILS_TYPE))
        .filter_map(|e| e.get("capabilities").and_then(Value::as_array))
        .flatten()
        .collect();
    if objects.len() > MAX_CLAIM_CAPABILITIES {
        tracing::warn!(
            named = objects.len(),
            max = MAX_CLAIM_CAPABILITIES,
            "ID-JAG authorization_details names more capabilities than the ceiling reads; \
             it names nothing"
        );
        return CapabilitySet::new();
    }
    objects
        .into_iter()
        .filter_map(|c| serde_json::from_value::<CapabilityConfig>(c.clone()).ok())
        .map(Capability::from)
        // A `one_of` over the bound names nothing, as any capability no token may carry (SR-123).
        .filter(|c| {
            c.validate().is_ok() && c.validate_limits().is_ok() && c.validate_size().is_ok()
        })
        .collect()
}

/// A set `⊑ a` and `⊑ b`, from the existing `⊑` ([`Capability::covers`]) and attenuation
/// ([`CapabilitySet::attenuate`]):
///
/// - each capability of `a` that a single capability of `b` covers, unchanged;
/// - each capability of `b` that `a` can be attenuated to (with limits clamped to the
///   covering capability of `a`, as at a delegation hop), when the result is still covered
///   by that capability of `b`.
///
/// Sound, not complete: see the module docs. Empty when nothing on either side is covered by a
/// single capability of the other.
pub(crate) fn meet(a: &CapabilitySet, b: &CapabilitySet) -> CapabilitySet {
    let mut out = CapabilitySet::new();
    for x in a.iter() {
        if b.iter().any(|y| y.covers(x)) {
            out.insert(x.clone());
        }
    }
    for y in b.iter() {
        let one: CapabilitySet = std::iter::once(y.clone()).collect();
        if let Ok(narrowed) = a.attenuate(&one) {
            for n in narrowed.iter() {
                if y.covers(n) {
                    out.insert(n.clone());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_core::{ArgConstraint, Limits};
    use serde_json::json;

    fn set(caps: &[&str]) -> CapabilitySet {
        caps.iter()
            .map(|c| {
                let (s, t) = c.split_once(':').unwrap();
                Capability::new(s, t)
            })
            .collect()
    }

    fn ceiling() -> IdJagCeiling {
        let cfg: IdJagCeilingConfig = toml::from_str(
            r#"
            resources = { "https://mcp.example/github" = ["github"], "https://mcp.example/chat" = ["slack"] }
            scopes = { "repo.read" = ["github:read_file", "github:list_*"], "chat" = ["slack:post_message"] }
            "#,
        )
        .unwrap();
        IdJagCeiling::from_config(&cfg).unwrap()
    }

    fn claims(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    /// Every capability of the result is covered by one of `outer`.
    fn within(result: &CapabilitySet, outer: &CapabilitySet) -> bool {
        outer.covers(result)
    }

    #[test]
    fn meet_keeps_the_narrower_side_and_never_widens() {
        let g = set(&["github:*"]);
        let r = meet(&g, &set(&["github:read_file", "slack:*"]));
        assert_eq!(r, set(&["github:read_file"]));
        let r = meet(&set(&["github:read_file"]), &set(&["github:*", "jira:*"]));
        assert_eq!(r, set(&["github:read_file"]));
        // Disjoint: nothing.
        assert!(meet(&g, &set(&["slack:*"])).is_empty());
        // Only overlapping patterns: nothing (not the greatest lower bound).
        assert!(meet(&set(&["github:read_*"]), &set(&["github:*_file"])).is_empty());
        // Wider on the claim side adds nothing beyond the grant.
        let r = meet(&set(&["github:read_file"]), &set(&["*:*"]));
        assert_eq!(r, set(&["github:read_file"]));
        assert!(meet(&CapabilitySet::new(), &g).is_empty());
        assert!(meet(&g, &CapabilitySet::new()).is_empty());
    }

    #[test]
    fn meet_respects_constraints_and_limits() {
        let pinned = Capability::new("github", "read_file")
            .with_constraint("repo", ArgConstraint::Prefix("acme/".into()));
        let grant: CapabilitySet = [pinned.clone()].into_iter().collect();
        // The claim names the tool without the constraint: the grant's constrained one stays.
        assert_eq!(meet(&grant, &set(&["github:read_file"])), grant);
        // The claim is narrower: it is taken.
        let narrower = Capability::new("github", "read_file")
            .with_constraint("repo", ArgConstraint::Prefix("acme/api".into()));
        let claim: CapabilitySet = [narrower.clone()].into_iter().collect();
        assert_eq!(meet(&grant, &claim), claim);
        // A claim outside the constraint gives nothing.
        let other = Capability::new("github", "read_file")
            .with_constraint("repo", ArgConstraint::Prefix("evil/".into()));
        assert!(meet(&grant, &[other].into_iter().collect()).is_empty());

        // Limits: a claim without limits under a limited grant gets the grant's limits.
        let limited: CapabilitySet =
            [Capability::new("github", "*").with_limits(Limits::default().with_calls(10))]
                .into_iter()
                .collect();
        let r = meet(&limited, &set(&["github:read_file"]));
        assert_eq!(r.len(), 1);
        let only = r.iter().next().unwrap();
        assert_eq!(only.limits.calls, Some(10));
        assert!(within(&r, &limited));
        assert!(within(&r, &set(&["github:read_file"])));
        // A claim with a lower limit keeps it.
        let lower: CapabilitySet =
            [Capability::new("github", "read_file").with_limits(Limits::default().with_calls(3))]
                .into_iter()
                .collect();
        let r = meet(&limited, &lower);
        assert_eq!(r.iter().next().unwrap().limits.calls, Some(3));
    }

    #[test]
    fn each_claim_narrows_and_absent_claims_do_not() {
        let c = ceiling();
        let grant = set(&["github:*", "slack:*", "jira:*"]);

        // No claim: the grant as it is.
        let a = c.apply(&grant, &claims(json!({"sub": "alice"})));
        assert_eq!(a.capabilities, grant);
        assert!(a.claims.is_empty());
        // null is the same as absent.
        let a = c.apply(&grant, &claims(json!({"scope": null})));
        assert_eq!(a.capabilities, grant);

        // resource, as a string and as an array.
        let a = c.apply(
            &grant,
            &claims(json!({"resource": "https://mcp.example/github"})),
        );
        assert_eq!(a.capabilities, set(&["github:*"]));
        assert_eq!(a.claims, ["resource"]);
        let a = c.apply(
            &grant,
            &claims(
                json!({"resource": ["https://mcp.example/github", "https://mcp.example/chat"]}),
            ),
        );
        assert_eq!(a.capabilities, set(&["github:*", "slack:*"]));

        // scope.
        let a = c.apply(&grant, &claims(json!({"scope": "repo.read"})));
        assert_eq!(a.capabilities, set(&["github:list_*", "github:read_file"]));
        assert_eq!(a.claims, ["scope"]);

        // authorization_details of attenuo's own type.
        let a = c.apply(
            &grant,
            &claims(json!({"authorization_details": [{
                "type": AUTHORIZATION_DETAILS_TYPE,
                "capabilities": [{"server": "jira", "tool": "create_issue"}],
            }]})),
        );
        assert_eq!(a.capabilities, set(&["jira:create_issue"]));
        assert_eq!(a.claims, ["authorization_details"]);

        // All three: the intersection of each.
        let a = c.apply(
            &grant,
            &claims(json!({
                "resource": "https://mcp.example/github",
                "scope": "repo.read chat",
                "authorization_details": [{
                    "type": AUTHORIZATION_DETAILS_TYPE,
                    "capabilities": [{"server": "github", "tool": "read_file"}, {"server": "slack", "tool": "*"}],
                }],
            })),
        );
        assert_eq!(a.capabilities, set(&["github:read_file"]));
        assert_eq!(a.claims, ["resource", "scope", "authorization_details"]);
    }

    #[test]
    fn unmapped_or_unknown_names_nothing() {
        let c = ceiling();
        let grant = set(&["github:*", "slack:*"]);
        let empty = |v: Value| c.apply(&grant, &claims(v)).capabilities.is_empty();
        assert!(empty(json!({"resource": "https://mcp.example/unknown"})));
        // Not normalised: a trailing slash is another identifier.
        assert!(empty(json!({"resource": "https://mcp.example/github/"})));
        assert!(empty(json!({"resource": 7})));
        assert!(empty(json!({"scope": "admin"})));
        assert!(empty(json!({"scope": ["repo.read"]})));
        assert!(empty(json!({"scope": ""})));
        assert!(empty(json!({"authorization_details": [
            {"type": "payment_initiation", "capabilities": [{"server": "github", "tool": "*"}]}
        ]})));
        assert!(empty(
            json!({"authorization_details": {"type": AUTHORIZATION_DETAILS_TYPE}})
        ));
        // A misspelt member does not drop the constraint silently: the capability names nothing.
        assert!(empty(json!({"authorization_details": [{
            "type": AUTHORIZATION_DETAILS_TYPE,
            "capabilities": [{"server": "github", "tool": "*", "constraint": {}}],
        }]})));
        // An invalid name names nothing.
        assert!(empty(json!({"authorization_details": [{
            "type": AUTHORIZATION_DETAILS_TYPE,
            "capabilities": [{"server": "git/hub", "tool": "*"}],
        }]})));
        // An unmapped token next to a mapped one: the mapped one alone counts.
        let a = c.apply(&grant, &claims(json!({"scope": "admin chat"})));
        assert_eq!(a.capabilities, set(&["slack:post_message"]));
        // A claim naming something the grant does not give adds nothing.
        let a = c.apply(
            &set(&["github:read_file"]),
            &claims(json!({"scope": "chat repo.read"})),
        );
        assert_eq!(a.capabilities, set(&["github:read_file"]));
    }

    #[test]
    fn config_is_checked() {
        let bad = |toml_text: &str| {
            let cfg: IdJagCeilingConfig = toml::from_str(toml_text).unwrap();
            IdJagCeiling::from_config(&cfg).unwrap_err()
        };
        assert!(bad(r#"resources = { "r" = [] }"#).contains("maps to no server"));
        assert!(bad(r#"resources = { "" = ["github"] }"#).contains("empty"));
        assert!(bad(r#"resources = { "r" = ["git/hub"] }"#).contains("resources `r`"));
        assert!(bad(r#"resources = { "r" = ["attenuo"] }"#).contains("reserved"));
        assert!(bad(r#"scopes = { "a b" = ["github:*"] }"#).contains("not a scope token"));
        assert!(bad(r#"scopes = { "s" = [] }"#).contains("maps to no capability"));
        assert!(bad(r#"scopes = { "s" = ["nocolon"] }"#).contains("server:tool"));
        // SR-125: a scope capability whose limits no token may carry refuses to start, as an
        // `authorization_details` one names nothing, instead of failing every intake later.
        assert!(bad(
            r#"scopes = { "s" = [{ server = "github", tool = "*", limits = { sum = { arg = "", max = 1 } } }] }"#
        )
        .contains("scopes `s`"));
        assert!(bad(
            r#"scopes = { "s" = [{ server = "github", tool = "*", limits = { sum = { arg = "n", max = 1, derive = "host" } } }] }"#
        )
        .contains("derive"));
        // SR-123: a `one_of` over the bound, or a scope naming more capabilities than a token
        // may hold, refuses to start.
        let values: Vec<String> = (0..=attenuo_core::MAX_ONE_OF_VALUES)
            .map(|i| i.to_string())
            .collect();
        assert!(bad(&format!(
            r#"scopes = {{ "s" = [{{ server = "github", tool = "*", constraints = {{ repo = {{ op = "one_of", value = [{}] }} }} }}] }}"#,
            values.join(", ")
        ))
        .contains("1025 values"));
        let tools: Vec<String> = (0..=attenuo_core::MAX_CAPABILITIES)
            .map(|i| format!("\"github:t{i}\""))
            .collect();
        assert!(
            bad(&format!(r#"scopes = {{ "s" = [{}] }}"#, tools.join(", ")))
                .contains("1025 capabilities")
        );
        // An empty table is accepted: only authorization_details can then name anything.
        let cfg: IdJagCeilingConfig = toml::from_str("").unwrap();
        IdJagCeiling::from_config(&cfg).unwrap();
        assert!(toml::from_str::<IdJagCeilingConfig>("resource = {}").is_err());
    }

    /// SR-123: the request is attenuated against the ceiling, which costs the product of the
    /// two sizes, on the request's own task. An `authorization_details` claim naming more
    /// capabilities than [`MAX_CLAIM_CAPABILITIES`] names nothing (fails closed), so the
    /// ceiling stays within the root grant's size plus that bound.
    #[test]
    fn a_claim_naming_too_many_capabilities_names_nothing_sr123() {
        let c = ceiling();
        let grant = set(&["github:*"]);
        let details = |n: usize| {
            let caps: Vec<Value> = (0..n)
                .map(|i| json!({"server": "github", "tool": format!("t{i}")}))
                .collect();
            claims(json!({"authorization_details": [
                {"type": AUTHORIZATION_DETAILS_TYPE, "capabilities": caps[..n / 2]},
                {"type": "payment_initiation"},
                {"type": AUTHORIZATION_DETAILS_TYPE, "capabilities": caps[n / 2..]},
            ]}))
        };
        let at = c.apply(&grant, &details(MAX_CLAIM_CAPABILITIES));
        assert_eq!(at.capabilities.len(), MAX_CLAIM_CAPABILITIES);
        let over = c.apply(&grant, &details(MAX_CLAIM_CAPABILITIES + 1));
        assert!(over.capabilities.is_empty());
        assert_eq!(over.claims, ["authorization_details"]);
    }

    /// SR-123: an `authorization_details` capability with a `one_of` over
    /// [`attenuo_core::MAX_ONE_OF_VALUES`] names nothing, so it cannot make the ceiling's
    /// comparisons costly; one at the bound is kept.
    #[test]
    fn a_claim_with_a_long_one_of_names_nothing_sr123() {
        let c = ceiling();
        let grant = set(&["github:*"]);
        let details = |n: usize| {
            claims(
                json!({"authorization_details": [{"type": AUTHORIZATION_DETAILS_TYPE,
                "capabilities": [{"server": "github", "tool": "read_file", "constraints":
                    {"repo": {"op": "one_of", "value": (0..n).collect::<Vec<_>>()}}}]}]}),
            )
        };
        assert_eq!(
            c.apply(&grant, &details(attenuo_core::MAX_ONE_OF_VALUES))
                .capabilities
                .len(),
            1
        );
        assert!(c
            .apply(&grant, &details(attenuo_core::MAX_ONE_OF_VALUES + 1))
            .capabilities
            .is_empty());
    }

    /// The claims hold for a spread of grants and claims with globs, constraints and limits:
    /// the result is covered by the grant and by what each claim names, and the request
    /// attenuated against it too.
    #[test]
    fn the_result_is_within_the_grant_and_every_claim() {
        let limited = |cap: Capability, l: Limits| cap.with_limits(l);
        let pin =
            |cap: Capability, p: &str| cap.with_constraint("repo", ArgConstraint::Prefix(p.into()));
        let caps = vec![
            Capability::new("*", "*"),
            Capability::new("github", "*"),
            Capability::new("github", "read_*"),
            Capability::new("github", "read_file"),
            pin(Capability::new("github", "read_file"), "acme/"),
            pin(Capability::new("github", "*"), "acme/api"),
            limited(
                Capability::new("github", "*"),
                Limits::default().with_calls(5),
            ),
            limited(
                Capability::new("github", "read_file"),
                Limits::default().with_calls(2),
            ),
            limited(
                Capability::new("github", "read_file"),
                Limits {
                    distinct: Some(attenuo_core::ArgLimit::new("repo", 1)),
                    ..Limits::default()
                },
            ),
            limited(
                Capability::new("github", "read_file"),
                Limits {
                    sum: Some(attenuo_core::ArgLimit::new("bytes", 100)),
                    ..Limits::default()
                },
            ),
            Capability::new("slack", "post_message"),
        ];
        let sets: Vec<CapabilitySet> = (0..caps.len())
            .flat_map(|i| {
                (i..caps.len()).map({
                    let caps = &caps;
                    move |j| [caps[i].clone(), caps[j].clone()].into_iter().collect()
                })
            })
            .collect();
        let mut kept = 0;
        for g in &sets {
            for b in &sets {
                let m = meet(g, b);
                assert!(g.covers(&m), "{g:?} {b:?} -> {m:?}");
                assert!(b.covers(&m), "{g:?} {b:?} -> {m:?}");
                if m.is_empty() {
                    continue;
                }
                kept += 1;
                for r in &sets {
                    if let Ok(t) = g.attenuate(r).and_then(|t| m.attenuate(&t)) {
                        assert!(g.covers(&t) && b.covers(&t) && m.covers(&t));
                    }
                }
            }
        }
        assert!(kept > 100, "{kept}");
    }
}
