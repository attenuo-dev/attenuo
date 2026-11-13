//! Cost of a verified-token cache hit: `ServerAuthorizer::authenticate_request` with a token the
//! server has already verified, as the proxy calls it on every request after the first (an
//! unbound token, no DPoP proof, no run limits). A hit hashes the token, looks it up, re-runs
//! the chain's `validate_at(now)` and hands the proxy an owned copy of the chain.
//!
//! - `hit/{hops}`: chains of 1, 3 and 8 hops (8 is the default `[token] max_depth`). Every hop
//!   carries the same five capabilities with argument constraints and one run limit, about what
//!   a coding agent with GitHub and filesystem tools is granted. The 8-hop token is checked to be
//!   under `VERIFIED_TOKEN_MAX_BYTES`, so it is cached.
//! - `chain_clone/{hops}`: `DelegationChain::clone` of the same chains, the one copy a hit
//!   cannot avoid while `Authenticated` owns its chain.
//!
//! ```text
//! cargo bench -p attenuo-server --bench token_cache
//! ```

use std::hint::black_box;
use std::sync::Arc;

use attenuo_audit::{SqliteAudit, SqliteLeaseStore};
use attenuo_core::{
    AgentId, ArgConstraint, ArgLimit, Capability, CapabilitySet, Limits, OriginatingUser,
};
use attenuo_policy::PolicyEngineBuilder;
use attenuo_proxy::{Authorizer, RequestAuth};
use attenuo_server::authz::VERIFIED_TOKEN_MAX_BYTES;
use attenuo_server::{Pipeline, ServerAuthorizer, SharedPolicy};
use attenuo_token::{Issuer, IssuerConfig};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;
use time::{Duration, OffsetDateTime};

/// The default `[token] max_depth`.
const MAX_DEPTH: usize = 8;

fn caps() -> CapabilitySet {
    CapabilitySet::from_iter([
        Capability::new("github", "get_file_contents")
            .with_constraint("owner", ArgConstraint::Equals(json!("alice")))
            .with_constraint("repo", ArgConstraint::Prefix("public-".into())),
        Capability::new("github", "list_issues")
            .with_constraint("owner", ArgConstraint::Equals(json!("alice"))),
        Capability::new("github", "create_issue")
            .with_constraint("owner", ArgConstraint::Equals(json!("alice")))
            .with_constraint(
                "repo",
                ArgConstraint::OneOf(vec![json!("public-docs"), json!("public-site")]),
            )
            .with_limits(Limits {
                calls: Some(20),
                ..Limits::default()
            }),
        Capability::new("fs", "read_file").with_constraint(
            "path",
            ArgConstraint::path_prefix("/workspace/project/").expect("absolute path"),
        ),
        Capability::new("fs", "search_files")
            .with_constraint(
                "path",
                ArgConstraint::path_prefix("/workspace/project/").expect("absolute path"),
            )
            .with_limits(Limits {
                distinct: Some(ArgLimit::new("pattern", 50)),
                ..Limits::default()
            }),
    ])
}

/// A token of `hops` hops: the root, then `hops - 1` exchanges with the same capabilities.
fn token(issuer: &Issuer, hops: usize, now: OffsetDateTime) -> String {
    let user = OriginatingUser {
        subject: "user:alice".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now,
        attributes: [("mfa".to_string(), json!(true))].into_iter().collect(),
    };
    let mut issued = issuer
        .issue_root(user, AgentId::new("agent:planner"), caps(), None, now)
        .expect("root");
    for i in 1..hops {
        issued = issuer
            .exchange(
                &issued.token,
                AgentId::new(format!("agent:sub{i}")),
                caps(),
                None,
                now,
            )
            .expect("exchange");
    }
    issued.token
}

fn bench_token_cache(c: &mut Criterion) {
    let now = OffsetDateTime::now_utc();
    let issuer = Issuer::generate(IssuerConfig {
        issuer: "http://bench".into(),
        audience: "attenuo".into(),
        max_depth: MAX_DEPTH,
        default_ttl: Duration::hours(1),
    });
    let verifier = issuer.verifier();
    let engine = PolicyEngineBuilder::new()
        .with_policies_str("permit(principal, action, resource);")
        .build()
        .expect("policy loads");
    let pipeline = Arc::new(Pipeline::new(
        Arc::new(SharedPolicy::new(engine)),
        Arc::new(SqliteLeaseStore::open_in_memory().unwrap()),
        Arc::new(SqliteAudit::open_in_memory().unwrap()),
    ));
    let auth = ServerAuthorizer::new(verifier.clone(), pipeline);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("token_cache");
    for hops in [1usize, 3, MAX_DEPTH] {
        let tok = token(&issuer, hops, now);
        assert!(
            tok.len() <= VERIFIED_TOKEN_MAX_BYTES,
            "{hops} hops: {} bytes is not cached",
            tok.len()
        );
        let req = RequestAuth {
            token: &tok,
            dpop: None,
            method: "POST",
            path: "/mcp/github",
            host: Some("attenuo.example"),
        };
        // The first call verifies and fills the cache; every timed call is a hit.
        let first = rt.block_on(auth.authenticate_request(&req, now)).unwrap();
        assert_eq!(first.chain.hops.len(), hops);
        group.bench_with_input(BenchmarkId::new("hit", hops), &hops, |b, _| {
            b.iter(|| {
                rt.block_on(auth.authenticate_request(black_box(&req), now))
                    .unwrap()
            })
        });
        let chain = first.chain;
        group.bench_with_input(BenchmarkId::new("chain_clone", hops), &hops, |b, _| {
            b.iter(|| black_box(&chain).clone())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_token_cache);
criterion_main!(benches);
