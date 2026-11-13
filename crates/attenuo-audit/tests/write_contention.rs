//! Measurement probe, not a test: lease-store writes interleaved with audit appends on one
//! SQLite file, from N threads, counting how often SQLite's busy handler runs. This is the
//! server's layout (`SqliteAudit` and `SqliteLeaseStore` opened on the same path, each with
//! its own connection), and the busy handler is what sleeps when the two connections want the
//! write lock at once. See `docs/design/performance.md`, "Write-lock contention between the
//! lease and audit connections".
//!
//! ```text
//! cargo test --release -p attenuo-audit --test write_contention -- --ignored --nocapture
//! PROBE_THREADS=1,4,8 PROBE_CALLS=1000 PROBE_ROUNDS=3 PROBE_MODE=sum   # the defaults
//! ```
//!
//! `PROBE_MODE=sum`: each call is a deferred `calls` + `sum` charge on two hops, then a synced
//! decision append, and every fourth call adds a run label (the pipeline's order for a limited
//! call that reads an untrusted result). `PROBE_MODE=calls`: a `calls` charge, then a plain
//! append. The probe replaces each connection's busy timeout with a handler that counts its
//! invocations and otherwise sleeps exactly as SQLite's default handler does (1, 2, 5, 10, 15,
//! 20, 25, 25, 25, 50, 50, 100 ms, up to the same 5 s).

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use attenuo_audit::{
    AuditSink, Durability, LeaseRegistry, RunLabel, RunLimits, RunState, SqliteAudit,
    SqliteLeaseStore, DEFAULT_WAL_CHECKPOINT_INTERVAL,
};
use attenuo_core::{Charge, Decision, LeaseId, LimitKind};
use common::{chain, record_for};
use time::OffsetDateTime;

static BUSY_CALLS: AtomicU64 = AtomicU64::new(0);
static BUSY_SLEPT_US: AtomicU64 = AtomicU64::new(0);

/// SQLite's `sqliteDefaultBusyCallback`, counted.
fn counting_busy_handler(count: i32) -> bool {
    const DELAYS: [u64; 12] = [1, 2, 5, 10, 15, 20, 25, 25, 25, 50, 50, 100];
    const TOTALS: [u64; 12] = [0, 1, 3, 8, 18, 33, 53, 78, 103, 128, 178, 228];
    const TIMEOUT_MS: u64 = 5_000;
    BUSY_CALLS.fetch_add(1, Ordering::Relaxed);
    let n = usize::try_from(count).unwrap_or(0);
    let (mut delay, prior) = if n < DELAYS.len() {
        (DELAYS[n], TOTALS[n])
    } else {
        (100, TOTALS[11] + (n as u64 - 11) * 100)
    };
    if prior + delay > TIMEOUT_MS {
        delay = TIMEOUT_MS.saturating_sub(prior);
        if delay == 0 {
            return false;
        }
    }
    let t = Instant::now();
    // SQLite's own busy-handler backoff, reproduced: the behaviour under test, not a wait.
    std::thread::sleep(Duration::from_millis(delay));
    BUSY_SLEPT_US.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
    true
}

fn env_list(name: &str, default: &str) -> Vec<usize> {
    std::env::var(name)
        .unwrap_or_else(|_| default.into())
        .split(',')
        .map(|s| s.trim().parse().expect("a number"))
        .collect()
}

fn charges(sum: bool) -> Vec<Charge> {
    let mut v = Vec::new();
    for (hop, lease) in ["l1", "l2"].iter().enumerate() {
        let mut c = Charge {
            hop,
            cap: 0,
            lease: LeaseId::new(*lease),
            kind: LimitKind::Calls,
            arg: None,
            value: None,
            amount: 1,
            max: u64::MAX >> 2,
            usage: false,
        };
        v.push(c.clone());
        if sum {
            c.kind = LimitKind::Sum;
            c.arg = Some("n".into());
            v.push(c);
        }
    }
    v
}

struct Run {
    latencies: Vec<Duration>,
    elapsed: Duration,
    busy: u64,
    slept: Duration,
}

fn run(threads: usize, calls: usize, sum: bool) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.db");
    // As the server opens them (`state.rs`): one file, two stores.
    let audit = SqliteAudit::open_with(&path, Durability::Normal)
        .unwrap()
        .with_wal_checkpoints(DEFAULT_WAL_CHECKPOINT_INTERVAL)
        .unwrap();
    let leases = SqliteLeaseStore::open_with(&path, Durability::Normal)
        .unwrap()
        .without_wal_autocheckpoint()
        .unwrap();
    audit
        .with_connection(|c| Ok(c.busy_handler(Some(counting_busy_handler))?))
        .unwrap();
    leases
        .with_connection(|c| Ok(c.busy_handler(Some(counting_busy_handler))?))
        .unwrap();
    let at = OffsetDateTime::now_utc() + time::Duration::hours(1);
    leases.register(&LeaseId::new("l1"), None, at).unwrap();
    leases
        .register(&LeaseId::new("l2"), Some(&LeaseId::new("l1")), at)
        .unwrap();
    let (audit, leases) = (Arc::new(audit), Arc::new(leases));
    let chain = Arc::new(chain("user:probe", ("l1", "l2")));
    let c = Arc::new(charges(sum));
    let barrier = Arc::new(Barrier::new(threads + 1));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let (audit, leases, chain, c, barrier) = (
                audit.clone(),
                leases.clone(),
                chain.clone(),
                c.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                let now = OffsetDateTime::now_utc();
                let mut lat = Vec::with_capacity(calls);
                barrier.wait();
                for i in 0..calls {
                    let id = format!("d{t}-{i}");
                    let started = Instant::now();
                    if sum {
                        let (_, owed) = leases.charge_sync_deferred(&id, &c, now).unwrap();
                        assert!(owed, "a sum charge on a shared file defers its sync");
                        let entry = audit
                            .append_synced(record_for(&chain, i, Decision::Allow))
                            .unwrap();
                        if i % 4 == 0 {
                            let label = RunLabel {
                                source: format!("probe/t{t}-{i}"),
                                decision_id: id,
                                seq: entry.seq,
                                at: now,
                            };
                            leases.add_label(&LeaseId::new("l1"), &label).unwrap();
                        }
                    } else {
                        leases.charge(&id, &c, now).unwrap();
                        audit
                            .append(record_for(&chain, i, Decision::Allow))
                            .unwrap();
                    }
                    lat.push(started.elapsed());
                }
                lat
            })
        })
        .collect();
    BUSY_CALLS.store(0, Ordering::Relaxed);
    BUSY_SLEPT_US.store(0, Ordering::Relaxed);
    barrier.wait();
    let started = Instant::now();
    let mut latencies = Vec::new();
    for h in handles {
        latencies.extend(h.join().unwrap());
    }
    let elapsed = started.elapsed();
    let busy = BUSY_CALLS.load(Ordering::Relaxed);
    let slept = Duration::from_micros(BUSY_SLEPT_US.load(Ordering::Relaxed));
    // Every charge counted, every append chained.
    let used = leases.budget_used(&c).unwrap();
    assert!(
        used.iter().all(|&u| u == (threads * calls) as u64),
        "{used:?}"
    );
    let report = audit.verify_chain().unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.entries, (threads * calls) as u64);
    Run {
        latencies,
        elapsed,
        busy,
        slept,
    }
}

#[test]
#[ignore = "measurement probe; run with --ignored --nocapture in release"]
fn write_contention_probe() {
    let threads = env_list("PROBE_THREADS", "1,4,8");
    let calls = env_list("PROBE_CALLS", "1000")[0];
    let rounds = env_list("PROBE_ROUNDS", "3")[0];
    let mode = std::env::var("PROBE_MODE").unwrap_or_else(|_| "sum".into());
    let sum = mode == "sum";
    println!("mode={mode} calls/thread={calls}  (busy = busy-handler invocations; per call)");
    for round in 0..rounds {
        for &n in &threads {
            let r = run(n, calls, sum);
            let mut v = r.latencies;
            v.sort();
            let total = v.len();
            let pct = |p: usize| v[(total * p / 100).min(total - 1)].as_micros();
            println!(
                "round {round} threads {n}: calls/s {:>6.0}  p50 {:>6} us  p99 {:>6} us  \
                 max {:>6} us  busy {:>6} ({:.3}/call)  slept {:>6} ms",
                total as f64 / r.elapsed.as_secs_f64(),
                pct(50),
                pct(99),
                v[total - 1].as_micros(),
                r.busy,
                r.busy as f64 / total as f64,
                r.slept.as_millis(),
            );
        }
    }
}
