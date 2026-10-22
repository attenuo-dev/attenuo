//! Cost of one `PolicyEngine::authorize` with the shipped default policies.
//!
//! Three calls on a 1-hop and a 4-hop chain: a read-only tool, `create_issue` (argument-level
//! rule) and the sensitive `delete_repo`. The chain's capabilities are wide so the capability
//! stage passes and the time goes to chain-to-Cedar translation and policy evaluation. The
//! default policy `forbid_deep_chains` rejects depth > 3, so every 4-hop case is a deny; the
//! cost of evaluating a deeper principal hierarchy is what is being compared, not the outcome.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use onbehalf_core::chain::DEFAULT_MAX_DEPTH;
use onbehalf_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, LeaseId, OriginatingUser,
    ToolCall,
};
use onbehalf_policy::{
    ArgType, PolicyEngine, PolicyEngineBuilder, ToolAttrs, ToolCatalog, DEFAULT_POLICIES,
};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    datetime!(2026-10-22 21:00 UTC)
}

fn engine() -> PolicyEngine {
    let catalog = ToolCatalog::new()
        .with(
            "github",
            "read_file",
            ToolAttrs::new()
                .readonly(true)
                .with_input("repo", ArgType::String)
                .with_input("path", ArgType::String),
        )
        .with(
            "github",
            "create_issue",
            ToolAttrs::new().with_input("repo", ArgType::String),
        )
        .with(
            "github",
            "delete_repo",
            ToolAttrs::new()
                .sensitive(true)
                .with_input("repo", ArgType::String),
        );
    PolicyEngineBuilder::new()
        .with_catalog(catalog)
        .with_policies_str(DEFAULT_POLICIES)
        .build()
        .expect("default policies load")
}

fn chain_of_depth(depth: usize) -> DelegationChain {
    let user = OriginatingUser {
        subject: "alice".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now() - Duration::minutes(5),
        attributes: BTreeMap::from([("mfa".to_string(), json!(true))]),
    };
    let wide = || CapabilitySet::from_iter([Capability::new("github", "*")]);
    let mut chain = DelegationChain::root(
        user,
        AgentId::new("root-agent"),
        wide(),
        now(),
        Duration::hours(1),
        LeaseId::new("l1"),
    )
    .expect("root chain");
    for i in 1..depth {
        chain = chain
            .extend(
                AgentId::new(format!("sub{i}")),
                wide(),
                now(),
                Duration::minutes(10),
                LeaseId::new(format!("l{}", i + 1)),
                DEFAULT_MAX_DEPTH,
            )
            .expect("extend");
    }
    assert_eq!(chain.depth(), depth);
    chain
}

fn bench_authorize(c: &mut Criterion) {
    let engine = engine();
    let calls = [
        (
            "read_file",
            ToolCall::new(
                "github",
                "read_file",
                json!({"repo": "alice/site", "path": "README.md"}),
            ),
            Decision::Allow,
        ),
        (
            "create_issue",
            ToolCall::new("github", "create_issue", json!({"repo": "acme/site"})),
            Decision::Allow,
        ),
        (
            "delete_repo",
            ToolCall::new("github", "delete_repo", json!({"repo": "alice/site"})),
            // Allowed by capability, no permit rule matches: Cedar default deny.
            Decision::Deny,
        ),
    ];

    let mut group = c.benchmark_group("authorize");
    for depth in [1usize, 4] {
        let chain = chain_of_depth(depth);
        for (name, call, at_depth_1) in &calls {
            // Sanity: the cases measure what the docs say they measure.
            let expected = if depth > 3 {
                &Decision::Deny
            } else {
                at_depth_1
            };
            assert_eq!(
                &engine.authorize(&chain, call, now()).decision,
                expected,
                "{name} at depth {depth}"
            );
            group.bench_function(format!("{name}/{depth}_hop"), |b| {
                b.iter(|| engine.authorize(black_box(&chain), black_box(call), now()))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_authorize);
criterion_main!(benches);
