//! Where the time of one proxied decision goes, stage by stage, in process.
//!
//! The end-to-end harness (`attenuo-bench`) measures the whole call through HTTP. This bench
//! splits the server's share of it into the stages the proxy runs for every `tools/call`:
//! token verification (`Verifier::verify`, and `ServerAuthorizer::authenticate` with its cache), the lease check (`Pipeline::check_leases`),
//! policy (`PolicyEngine::authorize`), building the `DecisionRecord`, the audit append, and
//! `Pipeline::decide` as a whole (leases, policy, record, append). Chains of 1 and 3 hops, the
//! `attenuo-bench` policy and catalog, SQLite stores in memory and in a temporary file
//! (`durability` normal and full, opened as the server opens them: WAL checkpoints in the
//! background).
//!
//! ```text
//! cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3
//! ```

use std::hint::black_box;
use std::sync::{Arc, RwLock};

use attenuo_audit::{
    AuditSink, Durability, LeaseStore, SqliteAudit, SqliteLeaseStore,
    DEFAULT_WAL_CHECKPOINT_INTERVAL,
};
use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DecisionRecord, OriginatingUser, ToolCall,
};
use attenuo_policy::{ArgType, PolicyEngine, PolicyEngineBuilder, ToolAttrs, ToolCatalog};
use attenuo_proxy::Authorizer;
use attenuo_server::{Pipeline, ServerAuthorizer};
use attenuo_token::{Issuer, IssuerConfig};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use serde_json::json;
use time::{Duration, OffsetDateTime};

/// The policy `attenuo-bench` runs (the leak demo's, server `fake`).
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

fn read_file() -> CapabilitySet {
    CapabilitySet::from_iter([Capability::new("fake", "read_file")])
}

/// A token with `depth` hops, its leases registered in `leases`.
fn token(issuer: &Issuer, leases: &dyn LeaseStore, depth: usize, now: OffsetDateTime) -> String {
    let user = OriginatingUser {
        subject: "bench-user".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now,
        attributes: Default::default(),
    };
    let mut issued = issuer
        .issue_root(user, AgentId::new("bench-root"), read_file(), None, now)
        .expect("root");
    let far = now + Duration::days(1);
    leases.register(&issued.lease, None, far).expect("lease");
    for i in 1..depth {
        let parent = issued.lease.clone();
        issued = issuer
            .exchange(
                &issued.token,
                AgentId::new(format!("bench-a{i}")),
                read_file(),
                None,
                now,
            )
            .expect("exchange");
        leases
            .register(&issued.lease, Some(&parent), far)
            .expect("lease");
    }
    issued.token
}

struct Store {
    name: &'static str,
    audit: Arc<SqliteAudit>,
    leases: Arc<SqliteLeaseStore>,
    _dir: Option<tempfile::TempDir>,
}

fn stores() -> Vec<Store> {
    let mut out = vec![Store {
        name: "memory",
        audit: Arc::new(SqliteAudit::open_in_memory().unwrap()),
        leases: Arc::new(SqliteLeaseStore::open_in_memory().unwrap()),
        _dir: None,
    }];
    for (name, durability) in [
        ("file", Durability::Normal),
        ("file_full", Durability::Full),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        // As the server opens them: WAL checkpoints in the background, not on the writer.
        let audit = SqliteAudit::open_with(&path, durability)
            .unwrap()
            .with_wal_checkpoints(DEFAULT_WAL_CHECKPOINT_INTERVAL)
            .unwrap();
        let leases = SqliteLeaseStore::open_with(&path, durability)
            .unwrap()
            .without_wal_autocheckpoint()
            .unwrap();
        out.push(Store {
            name,
            audit: Arc::new(audit),
            leases: Arc::new(leases),
            _dir: Some(dir),
        });
    }
    out
}

fn record(
    chain: &attenuo_core::DelegationChain,
    call: &ToolCall,
    now: OffsetDateTime,
) -> DecisionRecord {
    DecisionRecord::new(
        now,
        Decision::Allow,
        "allow",
        chain,
        call,
        vec!["read_file_public_repos_only".into()],
    )
}

fn bench_decide(c: &mut Criterion) {
    let now = OffsetDateTime::now_utc();
    let issuer = Issuer::generate(IssuerConfig {
        issuer: "http://bench".into(),
        audience: "attenuo".into(),
        max_depth: 8,
        default_ttl: Duration::hours(1),
    });
    let verifier = issuer.verifier();
    let policy = Arc::new(RwLock::new(engine()));
    let call = ToolCall::new(
        "fake",
        "read_file",
        json!({"repo": "alice/public-docs", "path": "README.md"}),
    );

    let mut group = c.benchmark_group("decide");
    for store in stores() {
        let pipeline = Arc::new(Pipeline::new(
            policy.clone(),
            store.leases.clone(),
            store.audit.clone(),
        ));
        let auth = ServerAuthorizer::new(verifier.clone(), pipeline.clone());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for depth in [1usize, 3] {
            let tok = token(&issuer, store.leases.as_ref(), depth, now);
            let chain = verifier.verify(&tok, now).expect("verifies").chain;
            assert!(pipeline.decide(&chain, &call, now).is_allow());
            let s = store.name;

            if s == "memory" {
                group.bench_function(format!("verify/{depth}_hop"), |b| {
                    b.iter(|| verifier.verify(black_box(&tok), now).unwrap())
                });
                // What the proxy calls: verification behind the server's verified-token cache.
                group.bench_function(format!("authenticate/{depth}_hop"), |b| {
                    b.iter(|| {
                        rt.block_on(auth.authenticate(black_box(&tok), now))
                            .unwrap()
                    })
                });
                group.bench_function(format!("policy/{depth}_hop"), |b| {
                    b.iter(|| {
                        policy
                            .read()
                            .unwrap()
                            .authorize(black_box(&chain), &call, now)
                    })
                });
                group.bench_function(format!("record/{depth}_hop"), |b| {
                    b.iter(|| record(black_box(&chain), &call, now))
                });
            }
            group.bench_function(format!("leases_{s}/{depth}_hop"), |b| {
                b.iter(|| pipeline.check_leases(black_box(&chain), now).unwrap())
            });
            group.bench_function(format!("append_{s}/{depth}_hop"), |b| {
                b.iter_batched(
                    || record(&chain, &call, now),
                    |r| store.audit.append(r).unwrap(),
                    BatchSize::SmallInput,
                )
            });
            group.bench_function(format!("decide_{s}/{depth}_hop"), |b| {
                b.iter(|| pipeline.decide(black_box(&chain), &call, now))
            });
        }
        assert!(store.audit.verify_chain().unwrap().ok);
    }
    group.finish();
}

criterion_group!(benches, bench_decide);
criterion_main!(benches);
