//! The latency and the write count of an allowed call that involves no approval (audit
//! finding A-4): `Pipeline::decide` of a read on a 1-hop chain with no run limits, on a
//! file store opened as the server opens it (`durability = "normal"`, WAL checkpoints in the
//! background, lease store and audit log on one file).
//!
//! Prints the median and p99 of the approval lookup alone (`LeaseStore::take_approval` with
//! no approval to take, one caller), then, for 1 caller and for 8 concurrent callers, the
//! median and p99 of one decision and the writes per decision (`SqliteLeaseStore::write_turns`: every write transaction on the
//! file, the decision's audit append included). Criterion reports means; a tail under write
//! contention needs the percentiles, so this bench times each call itself.
//!
//! ```text
//! cargo bench -p attenuo-server --bench allowed_call
//! ```

use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use attenuo_audit::{
    ApprovalStore, Durability, LeaseStore, SqliteAudit, SqliteLeaseStore,
    DEFAULT_WAL_CHECKPOINT_INTERVAL,
};
use attenuo_core::{AgentId, Capability, CapabilitySet, OriginatingUser, ToolCall};
use attenuo_policy::{ArgType, PolicyEngineBuilder, ToolAttrs, ToolCatalog};
use attenuo_server::{Pipeline, SharedPolicy};
use attenuo_token::{Issuer, IssuerConfig};
use serde_json::json;
use time::{Duration, OffsetDateTime};

const POLICY: &str = r#"
@id("read_file_public_repos_only")
permit(principal, action == Action::"fake/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };
"#;

/// Calls per caller, after a warm-up of the same size.
const CALLS: usize = 4000;

fn percentile(sorted: &[StdDuration], p: f64) -> StdDuration {
    let rank = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// `n` root chains (one run each) allowed to call `read_file`, their leases registered.
fn chains_for(
    issuer: &Issuer,
    verifier: &attenuo_token::Verifier,
    leases: &dyn LeaseStore,
    n: usize,
    now: OffsetDateTime,
) -> Vec<attenuo_core::DelegationChain> {
    (0..n)
        .map(|i| {
            let user = OriginatingUser {
                subject: format!("bench-user-{i}"),
                issuer: "https://idp.example".into(),
                authenticated_at: now,
                attributes: Default::default(),
            };
            let caps = CapabilitySet::from_iter([Capability::new("fake", "read_file")]);
            let issued = issuer
                .issue_root(user, AgentId::new("bench-root"), caps, None, now)
                .expect("root");
            leases
                .register(&issued.lease, None, now + Duration::days(1))
                .expect("lease");
            verifier.verify(&issued.token, now).expect("verifies").chain
        })
        .collect()
}

fn main() {
    // `cargo bench` passes `--bench`; `cargo test --benches` runs this once, briefly.
    let quick = !std::env::args().any(|a| a == "--bench");
    let calls = if quick { 50 } else { CALLS };
    let now = OffsetDateTime::now_utc();
    let issuer = Issuer::generate(IssuerConfig {
        issuer: "http://bench".into(),
        audience: "attenuo".into(),
        max_depth: 8,
        default_ttl: Duration::hours(1),
    });
    let verifier = issuer.verifier();
    let catalog = ToolCatalog::new().with(
        "fake",
        "read_file",
        ToolAttrs::new()
            .readonly(true)
            .with_input("repo", ArgType::String)
            .with_input("path", ArgType::String),
    );
    let engine = PolicyEngineBuilder::new()
        .with_catalog(catalog)
        .with_policies_str(POLICY)
        .build()
        .expect("bench policy loads");
    let policy = Arc::new(SharedPolicy::new(engine));
    let call = ToolCall::new(
        "fake",
        "read_file",
        json!({"repo": "alice/public-docs", "path": "README.md"}),
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let audit = SqliteAudit::open_with(&path, Durability::Normal)
        .unwrap()
        .with_wal_checkpoints(DEFAULT_WAL_CHECKPOINT_INTERVAL)
        .unwrap();
    let leases = Arc::new(
        SqliteLeaseStore::open_with(&path, Durability::Normal)
            .unwrap()
            .without_wal_autocheckpoint()
            .unwrap(),
    );
    let pipeline = Arc::new(Pipeline::new(policy, leases.clone(), Arc::new(audit)));

    {
        let chain = chains_for(&issuer, &verifier, leases.as_ref(), 1, now).remove(0);
        let chain_id = attenuo_core::LeaseId::new(attenuo_core::chain_id_of(&chain).unwrap());
        let lease = chain.hops.last().unwrap().lease.clone();
        let hash = call.call_hash();
        let lookup = || {
            let mut times = Vec::with_capacity(calls);
            for i in 0..calls {
                let t = Instant::now();
                let taken = leases
                    .take_approval(&chain_id, &lease, &hash, &format!("d{i}"), now)
                    .unwrap();
                times.push(t.elapsed());
                assert!(taken.is_none());
            }
            times
        };
        let _ = lookup();
        let before = leases.write_turns();
        let mut times = lookup();
        times.sort_unstable();
        println!(
            "take_approval_none: {} lookups, median {:.1} us, p99 {:.1} us, {:.2} writes per lookup",
            times.len(),
            percentile(&times, 0.5).as_secs_f64() * 1e6,
            percentile(&times, 0.99).as_secs_f64() * 1e6,
            (leases.write_turns() - before) as f64 / times.len() as f64,
        );
    }

    for callers in [1usize, 8] {
        // One run (one chain) per caller, as concurrent agents would have.
        let chains = chains_for(&issuer, &verifier, leases.as_ref(), callers, now);
        let run = || -> (Vec<StdDuration>, u64) {
            let before = leases.write_turns();
            let times = std::thread::scope(|s| {
                let handles: Vec<_> = chains
                    .iter()
                    .map(|chain| {
                        let (pipeline, call) = (&pipeline, &call);
                        s.spawn(move || {
                            let mut times = Vec::with_capacity(calls);
                            for _ in 0..calls {
                                let t = Instant::now();
                                let d = pipeline.decide(chain, call, now);
                                times.push(t.elapsed());
                                assert!(d.is_allow(), "{d:?}");
                            }
                            times
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect::<Vec<_>>()
            });
            (times, leases.write_turns() - before)
        };
        // Warm-up: statement caches, the WAL, the page cache.
        let _ = run();
        let (mut times, writes) = run();
        times.sort_unstable();
        let n = times.len();
        println!(
            "allowed_call/{callers}_caller: {n} decisions, median {:.1} us, p99 {:.1} us, \
             {:.2} writes per decision",
            percentile(&times, 0.5).as_secs_f64() * 1e6,
            percentile(&times, 0.99).as_secs_f64() * 1e6,
            writes as f64 / n as f64,
        );
    }
}
