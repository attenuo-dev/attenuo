//! The Cedar stage of one decision, split in two: preparing the request (entities, context,
//! `Request::new`) and evaluating it, plus `PolicyEngine::authorize` as a whole.
//!
//! Same policy and catalog as the server's `decide` bench and `onbehalf-bench` (the leak
//! demo's three policies, server `fake`), chains of 1 and 3 hops, the allowed `read_file`
//! call. `prepare` is `bench_support::prepare`, the translation the engine runs after the
//! capability and catalog stages. The engine caches the parts of the translation that depend
//! only on the chain and tool, so `authorize` and `prepare` measure a cache hit (every call
//! after an agent's first), and the `_uncached` rows empty the cache before each call, which
//! is what every call cost before the cache.
//!
//! ```text
//! cargo bench -p onbehalf-policy --bench policy_stage -- --warm-up-time 1 --measurement-time 3
//! ```

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use onbehalf_core::chain::DEFAULT_MAX_DEPTH;
use onbehalf_core::{
    AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser, ToolCall,
};
use onbehalf_policy::bench_support;
use onbehalf_policy::{ArgType, PolicyEngine, PolicyEngineBuilder, ToolAttrs, ToolCatalog};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const POLICY: &str = r#"
@id("read_file_public_repos_only")
permit(principal, action == Action::"fake/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("forbid_sensitive_without_mfa")
forbid(principal, action, resource)
when {
    resource.sensitive &&
    !(context.originating_user.attributes has mfa && context.originating_user.attributes.mfa == true)
};

@id("forbid_deep_chains")
forbid(principal, action, resource)
when { context.chain.depth > 3 };
"#;

fn now() -> OffsetDateTime {
    datetime!(2026-10-23 06:00 UTC)
}

fn engine() -> PolicyEngine {
    let catalog = ToolCatalog::new()
        .with(
            "fake",
            "read_file",
            ToolAttrs::new()
                .readonly(true)
                .with_input("repo", ArgType::String)
                .with_input("path", ArgType::String),
        )
        .with(
            "fake",
            "delete_repo",
            ToolAttrs::new()
                .sensitive(true)
                .with_input("repo", ArgType::String),
        );
    PolicyEngineBuilder::new()
        .with_catalog(catalog)
        .with_policies_str(POLICY)
        .build()
        .expect("bench policy loads")
}

fn chain_of_depth(depth: usize) -> DelegationChain {
    let user = OriginatingUser {
        subject: "bench-user".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now() - Duration::minutes(5),
        attributes: Default::default(),
    };
    let caps = || CapabilitySet::from_iter([Capability::new("fake", "read_file")]);
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
    assert_eq!(chain.depth(), depth);
    chain
}

fn bench_stage(c: &mut Criterion) {
    let engine = engine();
    let call = ToolCall::new(
        "fake",
        "read_file",
        json!({"repo": "alice/public-docs", "path": "README.md"}),
    );
    let mut group = c.benchmark_group("policy_stage");
    for depth in [1usize, 3] {
        let chain = chain_of_depth(depth);
        assert!(engine.authorize(&chain, &call, now()).decision.is_allow());

        group.bench_function(format!("authorize/{depth}_hop"), |b| {
            b.iter(|| engine.authorize(black_box(&chain), black_box(&call), now()))
        });
        group.bench_function(format!("authorize_uncached/{depth}_hop"), |b| {
            b.iter(|| {
                bench_support::clear_request_cache(&engine);
                engine.authorize(black_box(&chain), black_box(&call), now())
            })
        });
        group.bench_function(format!("prepare/{depth}_hop"), |b| {
            b.iter(|| bench_support::prepare(&engine, black_box(&chain), black_box(&call), now()))
        });
        group.bench_function(format!("prepare_uncached/{depth}_hop"), |b| {
            b.iter(|| {
                bench_support::clear_request_cache(&engine);
                bench_support::prepare(&engine, black_box(&chain), black_box(&call), now())
            })
        });
        let prepared = bench_support::prepare(&engine, &chain, &call, now());
        group.bench_function(format!("evaluate/{depth}_hop"), |b| {
            b.iter(|| bench_support::evaluate(&engine, black_box(&prepared)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_stage);
criterion_main!(benches);
