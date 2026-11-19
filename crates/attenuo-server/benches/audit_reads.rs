//! Append latency while a long admin read of the audit log runs (audit finding A-1).
//!
//! `GET /admin/audit/verify` walks the whole chain, the export streams it in pages, and a
//! filtered search scans up to 50,000 seqs. This measures what each costs the decisions that
//! append meanwhile: a log of `AUDIT_READS_RECORDS` entries (default 50,000) in a temporary
//! file, opened as the server opens it (`durability = "normal"`, a signed checkpoint every
//! 1,000 entries, WAL checkpoints in the background), then `AUDIT_READS_APPENDS` appends
//! (default 2,000) from one thread, each timed, with:
//!
//! - `idle`: nothing else running (the baseline);
//! - `verify`: another thread running `verify_chain_signed` back to back;
//! - `export`: another thread reading the whole log with `range_filtered` in pages of 500,
//!   back to back, as `GET /admin/audit/export` does;
//! - `search`: another thread running a filtered `entries_matching` over the newest 50,000
//!   seqs that matches nothing, back to back, as a `GET /admin/audit` page with a filter does.
//!
//! A scenario stops after `AUDIT_READS_SECONDS` (default 10) even if not every append was
//! made: with the reads on the writer's connection an append can wait for a whole verify, and
//! the count of appends made in that time is itself the result.
//!
//! The appender sleeps `AUDIT_READS_GAP_US` microseconds (default 200) between appends, so the
//! reader is not starved of the connection by a tight loop and the latencies are those of a
//! decision arriving at a random moment. It prints p50, p99 and max append latency per
//! scenario, and how many reads completed and how long each took.
//!
//! ```text
//! cargo bench -p attenuo-server --bench audit_reads
//! AUDIT_READS_RECORDS=50000 AUDIT_READS_APPENDS=2000 cargo bench -p attenuo-server --bench audit_reads
//! ```
//!
//! Results are in `docs/design/performance.md`, "Long audit reads and the append path".

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use attenuo_audit::{
    AuditSink, CheckpointKeys, Durability, EntryFilter, Order, RecordFilter, SqliteAudit,
    DEFAULT_WAL_CHECKPOINT_INTERVAL,
};
use attenuo_core::chain::DEFAULT_MAX_DEPTH;
use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DecisionRecord, DelegationChain, LeaseId,
    OriginatingUser, ToolCall,
};
use attenuo_token::{Issuer, IssuerConfig};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::json;
use time::OffsetDateTime;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map(|v| {
            v.parse()
                .unwrap_or_else(|_| panic!("{name} must be a number"))
        })
        .unwrap_or(default)
}

fn chain() -> DelegationChain {
    let t0 = OffsetDateTime::now_utc();
    let user = OriginatingUser {
        subject: "user:bench".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: t0,
        attributes: Default::default(),
    };
    DelegationChain::root(
        user,
        AgentId::new("agent:planner"),
        CapabilitySet::from_iter(vec![Capability::new("github", "*")]),
        t0,
        time::Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap()
    .extend(
        AgentId::new("agent:coder"),
        CapabilitySet::from_iter(vec![Capability::new("github", "create_issue")]),
        t0,
        time::Duration::minutes(30),
        LeaseId::new("l2"),
        DEFAULT_MAX_DEPTH,
    )
    .unwrap()
}

fn record(chain: &DelegationChain, i: usize) -> DecisionRecord {
    let call = ToolCall::new(
        "github",
        "create_issue",
        json!({"repo": "acme/x", "title": format!("issue {i}")}),
    );
    DecisionRecord::new(
        OffsetDateTime::now_utc(),
        Decision::Allow,
        "policy_allow",
        chain,
        &call,
        vec!["permit_create_issue".into()],
    )
}

fn keys(issuer: &Issuer) -> CheckpointKeys {
    let keys: Vec<serde_json::Value> = issuer
        .trusted_public_keys()
        .into_iter()
        .map(|(kid, pem)| {
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = STANDARD.decode(b64).unwrap();
            json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                   "kid": kid, "x": URL_SAFE_NO_PAD.encode(&der[der.len() - 32..])})
        })
        .collect();
    CheckpointKeys::from_jwks(&json!({ "keys": keys })).unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reader {
    Idle,
    Verify,
    Export,
    Search,
}

impl Reader {
    fn name(self) -> &'static str {
        match self {
            Reader::Idle => "idle",
            Reader::Verify => "verify",
            Reader::Export => "export",
            Reader::Search => "search",
        }
    }
}

/// One full read of the kind `reader` runs. Returns the entries it checked or returned.
fn read_once(log: &SqliteAudit, keys: &CheckpointKeys, reader: Reader) -> u64 {
    match reader {
        Reader::Idle => 0,
        Reader::Verify => {
            let report = log.verify_chain_signed(keys).expect("verify runs");
            assert!(report.chain().ok, "the chain verifies");
            report.chain().entries
        }
        Reader::Export => {
            let head = log.head().unwrap().map_or(0, |h| h.seq);
            let (mut next, mut n) = (1, 0u64);
            while next <= head {
                let page = log
                    .range_filtered(next, head, &RecordFilter::default(), 500)
                    .unwrap();
                let Some(last) = page.last() else { break };
                next = last.seq + 1;
                n += page.len() as u64;
            }
            n
        }
        Reader::Search => {
            let head = log.head().unwrap().map_or(0, |h| h.seq);
            let filter = EntryFilter {
                subject: Some("user:nobody".into()),
                ..EntryFilter::default()
            };
            let lo = head.saturating_sub(49_999).max(1);
            log.entries_matching(lo, head, &filter, Order::Descending, 100)
                .unwrap()
                .len() as u64
        }
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn main() {
    // `cargo bench` passes `--bench`; a filter argument is not supported.
    let records = env_usize("AUDIT_READS_RECORDS", 50_000);
    let appends = env_usize("AUDIT_READS_APPENDS", 2_000);
    let gap = Duration::from_micros(env_usize("AUDIT_READS_GAP_US", 200) as u64);
    let cap = Duration::from_secs(env_usize("AUDIT_READS_SECONDS", 10) as u64);

    let issuer = Issuer::generate(IssuerConfig {
        issuer: "https://attenuo.bench".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    });
    let keys = Arc::new(keys(&issuer));
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        SqliteAudit::open_with(dir.path().join("audit.db"), Durability::Normal)
            .unwrap()
            .with_checkpointing(issuer.detached_signer(), 1000)
            .with_wal_checkpoints(DEFAULT_WAL_CHECKPOINT_INTERVAL)
            .unwrap(),
    );
    let c = chain();
    let filled = Instant::now();
    // Four appenders, so group commit fills the log quickly.
    std::thread::scope(|s| {
        for t in 0..4 {
            let (log, c) = (&log, &c);
            s.spawn(move || {
                for i in (t..records).step_by(4) {
                    log.append(record(c, i)).unwrap();
                }
            });
        }
    });
    println!(
        "audit_reads: {records} entries written in {:.1?}; {appends} timed appends per \
         scenario, {gap:?} apart",
        filled.elapsed()
    );
    println!(
        "{:<8} {:>8} {:>10} {:>10} {:>10} {:>7} {:>12}",
        "reader", "appends", "p50", "p99", "max", "reads", "read time"
    );

    for reader in [Reader::Idle, Reader::Verify, Reader::Export, Reader::Search] {
        let stop = Arc::new(AtomicBool::new(false));
        let start = Arc::new(Barrier::new(2));
        let reads = {
            let (log, keys, stop, start) = (
                Arc::clone(&log),
                Arc::clone(&keys),
                Arc::clone(&stop),
                Arc::clone(&start),
            );
            std::thread::spawn(move || {
                let mut times = Vec::new();
                start.wait();
                while reader != Reader::Idle && !stop.load(Ordering::Acquire) {
                    let t = Instant::now();
                    std::hint::black_box(read_once(&log, &keys, reader));
                    times.push(t.elapsed());
                }
                times
            })
        };
        start.wait();
        // Let the first read get going before the timed appends start.
        std::thread::sleep(Duration::from_millis(20));
        let mut lat = Vec::with_capacity(appends);
        let began = Instant::now();
        for i in 0..appends {
            if began.elapsed() > cap {
                break;
            }
            let r = record(&c, records + i);
            let t = Instant::now();
            log.append(r).unwrap();
            lat.push(t.elapsed());
            std::thread::sleep(gap);
        }
        stop.store(true, Ordering::Release);
        let read_times = reads.join().unwrap();
        lat.sort();
        let mean_read = if read_times.is_empty() {
            "-".to_string()
        } else {
            format!(
                "{:.1?}",
                read_times.iter().sum::<Duration>() / read_times.len() as u32
            )
        };
        println!(
            "{:<8} {:>8} {:>10.1?} {:>10.1?} {:>10.1?} {:>7} {:>12}",
            reader.name(),
            lat.len(),
            percentile(&lat, 0.50),
            percentile(&lat, 0.99),
            lat[lat.len() - 1],
            read_times.len(),
            mean_read
        );
    }
    let report = log.verify_chain_signed(&keys).unwrap();
    assert!(report.chain().ok, "the chain still verifies at the end");
}
