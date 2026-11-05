//! The list screen (ADR-0011): Cedar partial evaluation of the shipped starter policy
//! (`policies/default.cedar`) for a 200-tool catalog, with every call-time context member
//! unknown (`input`, `session`, `args_contain_untrusted`, `untrusted_args`, `approval`,
//! `budget`, `usage`, `now_unix`, `session_id`), next to `policy_stage`.
//!
//! Rows, all for one `tools/list` of 200 tools on server `github`, chains of 1 and 3 hops,
//! a user without MFA:
//!
//! - `screen/<n>_hop`: `PolicyEngine::screen_tools_uncached`, what a chain's first list costs
//!   (per-list parts, then per tool: tool entities, partial request, partial evaluation).
//! - `screen_approval/<n>_hop`: the same with an `@obligation("approval")` forbid added, so the
//!   screen evaluates the relaxed set.
//! - `prepare/<n>_hop` and `partial_eval/<n>_hop`: the two halves of `screen`, timed apart.
//! - `concrete_eval/<n>_hop`: for comparison, the concrete evaluation of one prepared call
//!   per tool (`policy_stage`'s `evaluate`, 200 times).
//!
//! ```text
//! cargo bench -p attenuo-policy --bench list_screen -- --warm-up-time 1 --measurement-time 3
//! ```

use std::hint::black_box;

use attenuo_core::chain::DEFAULT_MAX_DEPTH;
use attenuo_core::{
    AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser, ToolCall,
};
use attenuo_policy::bench_support;
use attenuo_policy::{
    ArgType, ListScreen, PolicyEngine, PolicyEngineBuilder, ToolAttrs, ToolCatalog,
    DEFAULT_POLICIES,
};
use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const TOOLS: usize = 200;

const APPROVAL: &str = r#"
@id("approve_destructive_when_tainted")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
"#;

fn now() -> OffsetDateTime {
    datetime!(2026-11-05 06:00 UTC)
}

/// `create_issue`, `delete_repo` (sensitive) and 198 more: a third read-only (listed), a third
/// neither (no permit: hidden), a third read-only and sensitive (hidden without MFA).
fn catalog() -> (ToolCatalog, Vec<String>) {
    let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
    let mut catalog = ToolCatalog::new()
        .with("github", "create_issue", repo())
        .with("github", "delete_repo", repo().sensitive(true));
    let mut names = vec!["create_issue".to_string(), "delete_repo".to_string()];
    for i in 0..TOOLS - 2 {
        let name = format!("tool_{i:03}");
        let attrs = match i % 3 {
            0 => repo().readonly(true),
            1 => repo(),
            _ => repo().readonly(true).sensitive(true),
        };
        catalog = catalog.with("github", &name, attrs);
        names.push(name);
    }
    (catalog, names)
}

fn engine(extra: &str) -> PolicyEngine {
    PolicyEngineBuilder::new()
        .with_catalog(catalog().0)
        .with_policies_str(DEFAULT_POLICIES)
        .with_policies_str(extra)
        .build()
        .expect("starter policy loads")
}

fn chain_of_depth(depth: usize) -> DelegationChain {
    let user = OriginatingUser {
        subject: "bench-user".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now() - Duration::minutes(5),
        attributes: Default::default(),
    };
    let caps = || CapabilitySet::from_iter([Capability::new("github", "*")]);
    let mut chain = DelegationChain::root(
        user,
        AgentId::new("bench-root"),
        caps(),
        now(),
        Duration::hours(1),
        LeaseId::new("l0"),
    )
    .expect("root chain");
    for i in 1..depth {
        chain = chain
            .extend(
                AgentId::new(format!("bench-a{i}")),
                caps(),
                now(),
                Duration::minutes(10),
                LeaseId::new(format!("l{i}")),
                DEFAULT_MAX_DEPTH,
            )
            .expect("extend");
    }
    chain
}

fn bench_screen(c: &mut Criterion) {
    let names = catalog().1;
    let plain = engine("");
    let approval = engine(APPROVAL);
    let mut group = c.benchmark_group("list_screen_partial");
    for depth in [1usize, 3] {
        let chain = chain_of_depth(depth);
        // What the screen says, so the rows time the intended work: create_issue and the
        // read-only tools kept, 66 tools no permit allows, 66 sensitive ones and delete_repo hidden.
        for engine in [&plain, &approval] {
            let verdicts = engine.screen_tools_uncached(&chain, "github", &names);
            let hidden = verdicts.iter().filter(|v| !v.keeps()).count();
            assert_eq!(hidden, 133, "hidden at {depth} hops");
            assert_eq!(verdicts[0], ListScreen::Keep, "create_issue");
            assert!(!verdicts[1].keeps(), "delete_repo without MFA");
        }

        group.bench_function(format!("screen/{depth}_hop"), |b| {
            b.iter(|| plain.screen_tools_uncached(black_box(&chain), "github", black_box(&names)))
        });
        group.bench_function(format!("screen_approval/{depth}_hop"), |b| {
            b.iter(|| {
                approval.screen_tools_uncached(black_box(&chain), "github", black_box(&names))
            })
        });
        group.bench_function(format!("prepare/{depth}_hop"), |b| {
            b.iter(|| bench_support::screen_prepare(&plain, black_box(&chain), "github", &names))
        });
        let prepared = bench_support::screen_prepare(&plain, &chain, "github", &names);
        assert_eq!(bench_support::screen_evaluate(&plain, &prepared), 133);
        group.bench_function(format!("partial_eval/{depth}_hop"), |b| {
            b.iter(|| bench_support::screen_evaluate(&plain, black_box(&prepared)))
        });
        let calls: Vec<_> = names
            .iter()
            .map(|t| {
                let call = ToolCall::new("github", t, json!({"repo": "acme/x"}));
                bench_support::prepare(&plain, &chain, &call, now())
            })
            .collect();
        group.bench_function(format!("concrete_eval/{depth}_hop"), |b| {
            b.iter(|| {
                calls
                    .iter()
                    .filter(|p| {
                        bench_support::evaluate(&plain, black_box(p))
                            .decision
                            .is_allow()
                    })
                    .count()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_screen);
criterion_main!(benches);
