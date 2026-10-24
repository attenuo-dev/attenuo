//! Measurement probe, not a test: where a single client's slow appends come from. One thread
//! makes the server's store calls for one allowed call (lease check, run labels read, decision
//! append, a pause standing in for the upstream round trip, result append) in a closed loop,
//! and times each append. Configurations (`PROBE_CONFIGS`, run in segments of `PROBE_CALLS`
//! calls, alternating when there are several):
//!
//! - `memory`: in-memory stores (no file, no WAL, no checkpointer): the floor;
//! - `file`: one file, as the server opens it (`durability = "normal"`, background WAL
//!   checkpointer, lease autocheckpoint off), no signed checkpoints;
//! - `file-nopresync`: as `file`, without the database-file sync before the checkpointer's
//!   locked pass (the behaviour before it was added);
//! - `parked`: as `file`, with the WAL checkpointer parked for each segment (no `PASSIVE` or
//!   `TRUNCATE` runs during it); the segment ends with an untimed `TRUNCATE`, so each one
//!   starts from an empty WAL and is short enough (800 calls, about 1,600 commits) that the
//!   WAL never reaches the writer's backstop;
//! - `signed`: as `file`, plus a signed audit checkpoint every 1,000 entries (the server's
//!   default `checkpoint_every`), whose commit is synced;
//! - `signed-nopresync`: as `signed`, without either sync ahead of time (the WAL before a
//!   signed checkpoint, the database file before the locked pass): the behaviour before;
//! - `signed-leadN`: as `signed`, with the WAL synced `N` entries before each signed
//!   checkpoint (`signed-lead0`: not at all).
//!
//! With several configurations in one process, each one's store sits idle while the others
//! run, so its checkpointer truncates the WAL and the next segment starts with a growing WAL
//! (`PROBE_RESET=truncate` does that on purpose). The server under steady load keeps a large
//! WAL that it overwrites, so for that case run one configuration per process and alternate
//! them from the shell. See `docs/design/performance.md`, "Single-client outliers".
//!
//! ```text
//! cargo test --release -p attenuo-audit --test single_client_outliers --no-run
//! for c in file-nopresync file signed-nopresync signed; do
//!   PROBE_CONFIGS=$c PROBE_ROUNDS=8 target/release/deps/single_client_outliers-* \
//!     --ignored --nocapture
//! done
//! ```

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use attenuo_audit::{
    AuditSink, Durability, LeaseStore, SqliteAudit, SqliteLeaseStore,
    DEFAULT_WAL_CHECKPOINT_INTERVAL,
};
use attenuo_core::{Decision, DecisionRecord, LeaseId};
use common::{chain, record_for};
use time::OffsetDateTime;

/// `checkpoint_every` of the `signed` configuration (the server's default).
const SIGN_EVERY: u64 = 1000;

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Stores {
    audit: SqliteAudit,
    leases: SqliteLeaseStore,
    _dir: Option<tempfile::TempDir>,
}

fn open(config: &str) -> Stores {
    if config == "memory" {
        return Stores {
            audit: SqliteAudit::open_in_memory().unwrap(),
            leases: SqliteLeaseStore::open_in_memory().unwrap(),
            _dir: None,
        };
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.db");
    let mut audit = SqliteAudit::open_with(&path, Durability::Normal).unwrap();
    if config.starts_with("signed") {
        let issuer = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: time::Duration::minutes(5),
        });
        audit = audit.with_checkpointing(issuer.detached_signer(), SIGN_EVERY);
    }
    let audit = audit
        .with_wal_checkpoints(DEFAULT_WAL_CHECKPOINT_INTERVAL)
        .unwrap();
    // The A/B of the database-file sync before the locked pass, on one build.
    if config.ends_with("-nopresync") {
        audit.set_wal_presync(false);
        audit.set_checkpoint_presync_lead(0);
    }
    if let Some(lead) = config.strip_prefix("signed-lead") {
        audit.set_checkpoint_presync_lead(lead.parse().unwrap());
    }
    let leases = SqliteLeaseStore::open_with(&path, Durability::Normal)
        .unwrap()
        .without_wal_autocheckpoint()
        .unwrap();
    Stores {
        audit,
        leases,
        _dir: Some(dir),
    }
}

#[derive(Default)]
struct Samples {
    decision: Vec<Duration>,
    result: Vec<Duration>,
    reads: Vec<Duration>,
    /// Start and length of every append over 1 ms.
    slow: Vec<(Instant, Duration)>,
    /// The appends that wrote a signed checkpoint (`signed` only).
    signed: Vec<Duration>,
}

/// Append one record and time it.
fn timed_append(stores: &Stores, record: DecisionRecord, out: &mut Samples) -> Duration {
    let t = Instant::now();
    let entry = stores.audit.append(record).unwrap();
    let took = t.elapsed();
    if took > Duration::from_millis(1) {
        out.slow.push((t, took));
    }
    if entry.seq.is_multiple_of(SIGN_EVERY) {
        out.signed.push(took);
    }
    took
}

fn segment(stores: &Stores, config: &str, calls: usize, gap: Duration, out: &mut Samples) {
    let chain = chain("user:probe", ("l1", "l2"));
    let ids = [LeaseId::new("l1"), LeaseId::new("l2")];
    let leases = [&ids[0], &ids[1]];
    if std::env::var("PROBE_RESET").as_deref() == Ok("truncate") {
        // Start from an empty WAL, untimed.
        stores.audit.checkpoint_wal().unwrap();
    }
    let parked = (config == "parked").then(|| stores.audit.park_wal_checkpointer());
    let now = OffsetDateTime::now_utc();
    for i in 0..calls {
        let t = Instant::now();
        assert!(stores.leases.check_all(&leases, now).unwrap().active);
        stores.leases.labels(leases[0]).unwrap();
        out.reads.push(t.elapsed());
        let took = timed_append(stores, record_for(&chain, i, Decision::Allow), out);
        out.decision.push(took);
        std::thread::sleep(gap);
        let took = timed_append(stores, record_for(&chain, i, Decision::Allow), out);
        out.result.push(took);
        std::thread::sleep(gap / 2);
    }
    if parked.is_some() {
        drop(parked);
        // Let the parked checkpointer finish its round here, untimed, not during the next
        // segment.
        stores.audit.checkpoint_wal().unwrap();
    }
}

fn summary(v: &mut [Duration]) -> String {
    v.sort();
    let n = v.len();
    let us = |d: Duration| d.as_micros();
    let pct = |p: f64| us(v[((n as f64 * p) as usize).min(n - 1)]);
    let over = |ms: u64| v.iter().filter(|d| **d > Duration::from_millis(ms)).count();
    format!(
        "n {n:>6}  p50 {:>5}  p90 {:>5}  p99 {:>5}  p99.9 {:>6}  max {:>6} us  >1ms {:>4}  >3ms {:>3}",
        pct(0.50),
        pct(0.90),
        pct(0.99),
        pct(0.999),
        us(v[n - 1]),
        over(1),
        over(3),
    )
}

#[test]
#[ignore = "measurement probe; run with --ignored --nocapture in release"]
fn single_client_outliers_probe() {
    let configs: Vec<String> = std::env::var("PROBE_CONFIGS")
        .unwrap_or_else(|_| "memory,file,file-nopresync,parked,signed,signed-nopresync".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    let calls: usize = env_or("PROBE_CALLS", 800);
    let rounds: usize = env_or("PROBE_ROUNDS", 10);
    let gap = Duration::from_micros(env_or("PROBE_GAP_US", 700));
    let stores: Vec<(String, Arc<Stores>)> = configs
        .iter()
        .map(|c| {
            let s = open(c);
            let at = OffsetDateTime::now_utc() + time::Duration::hours(10);
            s.leases.register(&LeaseId::new("l1"), None, at).unwrap();
            s.leases
                .register(&LeaseId::new("l2"), Some(&LeaseId::new("l1")), at)
                .unwrap();
            (c.clone(), Arc::new(s))
        })
        .collect();
    let mut samples: Vec<Samples> = configs.iter().map(|_| Samples::default()).collect();
    println!("calls/segment={calls} rounds={rounds} gap={gap:?}");
    for round in 0..rounds {
        // Alternate the order each round.
        let order: Vec<usize> = if round % 2 == 0 {
            (0..stores.len()).collect()
        } else {
            (0..stores.len()).rev().collect()
        };
        for i in order {
            let (c, s) = &stores[i];
            segment(s, c, calls, gap, &mut samples[i]);
        }
    }
    for ((c, s), out) in stores.iter().zip(&mut samples) {
        println!("{c:>7} decision append  {}", summary(&mut out.decision));
        println!("{c:>7} result append    {}", summary(&mut out.result));
        println!("{c:>7} lease+label read {}", summary(&mut out.reads));
        if c.starts_with("signed") {
            println!("{c:>7} signing append   {}", summary(&mut out.signed));
        }
        let t = s.audit.wal_timings();
        let mut took: Vec<Duration> = t.rounds.iter().map(|r| r.took).collect();
        took.sort();
        let complete = t.rounds.iter().filter(|r| r.last.complete()).count();
        let mut held: Vec<Duration> = t.locked_passes.iter().map(|(d, _)| *d).collect();
        held.sort();
        if !held.is_empty() {
            println!(
                "{c:>7} locked passes held the store lock: min {:?} median {:?} max {:?}",
                held[0],
                held[held.len() / 2],
                held[held.len() - 1]
            );
        }
        let truncated = t.rounds.iter().filter(|r| r.truncated).count();
        let frames: Vec<i64> = t.rounds.iter().map(|r| r.first.wal_frames).collect();
        println!(
            "{c:>7} rounds {}  took p50 {:?} max {:?}  complete {complete}  truncated {truncated}  \
             first-pass WAL frames min {} max {}  locked passes {}  backstops {}",
            t.rounds.len(),
            took.get(took.len() / 2).copied().unwrap_or_default(),
            took.last().copied().unwrap_or_default(),
            frames.iter().min().copied().unwrap_or(0),
            frames.iter().max().copied().unwrap_or(0),
            t.locked_passes.len(),
            t.backstops.len()
        );
        // Which slow appends started while a round was running (or within 1 ms after it).
        for ms in [1u64, 3] {
            let slow: Vec<_> = out
                .slow
                .iter()
                .filter(|(_, d)| *d > Duration::from_millis(ms))
                .collect();
            let during = slow
                .iter()
                .filter(|(at, d)| {
                    t.rounds.iter().any(|r| {
                        *at + *d >= r.started
                            && *at <= r.started + r.took + Duration::from_millis(1)
                    })
                })
                .count();
            let in_locked = slow
                .iter()
                .filter(|(at, d)| {
                    t.rounds.iter().filter_map(|r| r.locked).any(|(l, held)| {
                        *at + *d >= l && *at <= l + held + Duration::from_millis(1)
                    })
                })
                .count();
            println!(
                "{c:>7} appends over {ms} ms: {}, of which during a checkpoint round: {during}, \
                 during its locked pass: {in_locked}",
                slow.len()
            );
        }
        let report = s.audit.verify_chain().unwrap();
        assert!(report.ok, "{report:?}");
    }
}
