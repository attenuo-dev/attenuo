//! Exchange throughput, lease renewal load and open-loop arrivals.
//!
//! Three additions to the harness, all in this file so the proxied-call path in `lib.rs` is
//! untouched:
//!
//! - `exchange`: N closed-loop clients, each holding a token (a root, or a chain of three
//!   hops), exchange it for a child delegated to a fresh actor id on every request. The
//!   server allows one delegation per parent and actor, so ids come from [`ActorIds`], which
//!   never repeats. The server runs with `[token] require_actor_auth = false`, so the
//!   actor's client secret is not checked (one SHA-256 comparison per request is left out).
//! - `lease-renew`: M live leases (roots with 99 children each), every lease renewing at
//!   interval T through `POST /token/renew`. Latency is measured from the time a renewal was
//!   due, so a server that falls behind shows it. Then the time to revoke the root of a
//!   three-level tree with 100 descendant leases.
//! - `--open-loop RATE`: Poisson arrivals at a fixed rate instead of a fixed number of
//!   clients, on the existing proxied `tools/call` cell (top-level flag) and on `exchange`.
//!   Latency runs from the scheduled arrival, not from the send, so a slow server is not let
//!   off by the load generator waiting for it (coordinated omission).
//!
//! The server's CPU time over each measured window is read from `/proc/<pid>/stat`.
//! See `docs/design/performance.md` for the method and its limits.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Args, Subcommand};
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::process::Command as Spawn;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::{
    check_answer, command_output, default_bin_dir, find_bin, free_port, mint_chain, post_json,
    render_config, round1, wait_http, wait_tcp, AuditMode, Expect, Opts, Outcome, Proc, Stats,
    WorkDir, ADMIN_TOKEN, POLICY, UPSTREAM,
};

// ---------------------------------------------------------------------------------------
// Command line

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Token-exchange throughput: clients exchange their token to a fresh actor per request.
    Exchange(ExchangeArgs),
    /// Lease renewal load at M live leases, and the revoke-cascade time.
    LeaseRenew(LeaseArgs),
    /// What output labelling and run limits add to one proxied `tools/call`, and the cost of
    /// an approval round (see [`crate::hotpath`]).
    HotPath(crate::hotpath::HotPathArgs),
}

#[derive(Debug, Clone, Args)]
pub struct Common {
    /// Directory holding the `attenuo-server` binary (default: this executable's directory).
    #[arg(long)]
    pub bin_dir: Option<PathBuf>,
    /// Measured seconds per cell.
    #[arg(long, default_value_t = 10.0)]
    pub duration: f64,
    /// Warm-up seconds per cell, discarded.
    #[arg(long, default_value_t = 2.0)]
    pub warmup: f64,
    /// Audit store: `memory`, `file` or `file_full`. One server per mode.
    #[arg(long, value_delimiter = ',', value_enum, default_values_t = [AuditMode::Memory, AuditMode::File])]
    pub audit: Vec<AuditMode>,
    /// Merge the results into this JSON file (created if missing).
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Append the markdown tables to this file (created if missing).
    #[arg(long)]
    pub markdown: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ExchangeArgs {
    #[command(flatten)]
    pub common: Common,
    /// Closed-loop clients (ignored with `--open-loop`).
    #[arg(long, value_delimiter = ',', default_values_t = [1usize, 8])]
    pub clients: Vec<usize>,
    /// Hops in the token being exchanged: 1 is a root token, 3 a chain of three.
    #[arg(long, value_delimiter = ',', default_values_t = [1usize, 3])]
    pub depths: Vec<usize>,
    /// Open loop: Poisson arrivals at these rates (requests per second) instead of clients.
    #[arg(long, value_delimiter = ',')]
    pub open_loop: Vec<f64>,
}

#[derive(Debug, Clone, Args)]
pub struct LeaseArgs {
    #[command(flatten)]
    pub common: Common,
    /// Cells as `LEASES:INTERVAL_SECONDS`, comma separated. Leases are rounded up to a
    /// multiple of 100 (a root and 99 children per group).
    #[arg(long, value_delimiter = ',', default_value = "100:1,1000:1,5000:1")]
    pub cells: Vec<String>,
    /// Revoke-cascade repetitions per audit mode (a tree of depth 3 with 100 descendants).
    #[arg(long, default_value_t = 5)]
    pub cascade_runs: usize,
}

// ---------------------------------------------------------------------------------------
// Actor ids

/// Ids for actors that never repeat, within a run or across runs on one audit file.
#[derive(Debug, Clone)]
pub struct ActorIds {
    prefix: String,
}

impl ActorIds {
    /// `run` should differ between runs that share a server; use [`ActorIds::for_this_run`].
    pub fn new(run: &str) -> Self {
        Self {
            prefix: format!("xa-{run}"),
        }
    }

    pub fn for_this_run() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        Self::new(&format!(
            "{:x}{:x}",
            std::process::id() & 0xffff,
            nanos & 0xffff
        ))
    }

    /// The id of request `seq` of client `client`.
    pub fn id(&self, client: usize, seq: u64) -> String {
        format!("{}-{client}-{seq}", self.prefix)
    }
}

// ---------------------------------------------------------------------------------------
// Open-loop scheduler

/// Poisson arrival offsets from the start of a run: exponential gaps with mean `1 / rate`.
#[derive(Debug, Clone)]
pub struct Arrivals {
    state: u64,
    mean_gap_s: f64,
    at_s: f64,
}

impl Arrivals {
    pub fn poisson(rate: f64, seed: u64) -> Self {
        assert!(rate > 0.0 && rate.is_finite(), "rate must be positive");
        Self {
            state: seed,
            mean_gap_s: 1.0 / rate,
            at_s: 0.0,
        }
    }

    /// SplitMix64, mapped to the open interval (0, 1).
    fn unit(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        ((z >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }
}

impl Iterator for Arrivals {
    type Item = Duration;
    fn next(&mut self) -> Option<Duration> {
        self.at_s += -self.mean_gap_s * self.unit().ln();
        Some(Duration::from_secs_f64(self.at_s))
    }
}

fn new_hist() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 120_000_000_000, 3).expect("histogram bounds")
}

fn record(h: &mut Histogram<u64>, d: Duration) {
    let _ = h.record((d.as_nanos() as u64).max(1));
}

#[derive(Debug, Clone)]
pub struct OpenCfg {
    pub rate: f64,
    /// Time zero of the schedule.
    pub start: Instant,
    pub warmup: Duration,
    pub duration: Duration,
    /// Requests in flight at once; an arrival that finds all slots taken is shed and counted.
    pub max_inflight: usize,
    pub seed: u64,
}

#[derive(Debug)]
pub struct OpenOut {
    /// Arrivals scheduled inside the measured window.
    pub offered: u64,
    /// Of those, dropped because `max_inflight` requests were already running.
    pub shed: u64,
    /// Of those, answered correctly and finished before the window closed.
    pub done_in_window: u64,
    /// Of those, answered correctly at any time (after the drain).
    pub ok: u64,
    pub errors: u64,
    pub first_bad: Option<String>,
    /// From the scheduled arrival to the end of the response.
    pub latency: Histogram<u64>,
    /// From the moment the request was started to the end of the response.
    pub service: Histogram<u64>,
    /// From the scheduled arrival to the moment the scheduler dispatched it: the timer's
    /// resolution (tokio ticks at 1 ms) plus any time the scheduler task was starved.
    pub lag: Histogram<u64>,
}

/// Run `f(seq)` at Poisson arrival times. `f` is called on the scheduler task and returns the
/// future that is then spawned.
pub async fn run_open<F, Fut>(cfg: &OpenCfg, f: F) -> OpenOut
where
    F: Fn(u64) -> Fut,
    Fut: Future<Output = std::result::Result<(), String>> + Send + 'static,
{
    let end = cfg.warmup + cfg.duration;
    let slots = Arc::new(Semaphore::new(cfg.max_inflight));
    let mut tasks = JoinSet::new();
    let mut out = OpenOut {
        offered: 0,
        shed: 0,
        done_in_window: 0,
        ok: 0,
        errors: 0,
        first_bad: None,
        latency: new_hist(),
        service: new_hist(),
        lag: new_hist(),
    };
    let start = cfg.start;
    for (seq, off) in Arrivals::poisson(cfg.rate, cfg.seed).enumerate() {
        if off >= end {
            break;
        }
        tokio::time::sleep_until(start + off).await;
        let measured = off >= cfg.warmup;
        if measured {
            out.offered += 1;
            record(
                &mut out.lag,
                Instant::now().saturating_duration_since(start + off),
            );
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            if measured {
                out.shed += 1;
            }
            continue;
        };
        let fut = f(seq as u64);
        let scheduled = start + off;
        tasks.spawn(async move {
            let begun = Instant::now();
            let res = fut.await;
            let done = Instant::now();
            drop(permit);
            (
                measured,
                res,
                done.saturating_duration_since(scheduled),
                done.saturating_duration_since(begun),
                done.saturating_duration_since(start) <= end,
            )
        });
    }
    // Let stragglers finish so their latency counts; give up on a wedged server.
    while let Ok(Some(joined)) =
        tokio::time::timeout(Duration::from_secs(15), tasks.join_next()).await
    {
        let Ok((measured, res, latency, service, in_window)) = joined else {
            continue;
        };
        if !measured {
            continue;
        }
        match res {
            Ok(()) => {
                out.ok += 1;
                if in_window {
                    out.done_in_window += 1;
                }
                record(&mut out.latency, latency);
                record(&mut out.service, service);
            }
            Err(why) => {
                out.errors += 1;
                out.first_bad.get_or_insert(why);
            }
        }
    }
    out
}

#[derive(Debug)]
pub struct ClosedOut {
    pub ok: u64,
    pub errors: u64,
    pub first_bad: Option<String>,
    pub latency: Histogram<u64>,
}

/// `clients` closed-loop tasks, each calling `f(client, seq)` back to back.
pub async fn run_closed<F, Fut>(
    clients: usize,
    start: Instant,
    warmup: Duration,
    duration: Duration,
    f: F,
) -> ClosedOut
where
    F: Fn(usize, u64) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<(), String>> + Send + 'static,
{
    let f = Arc::new(f);
    let (warm_end, end) = (start + warmup, start + warmup + duration);
    let mut tasks = JoinSet::new();
    for client in 0..clients {
        let f = f.clone();
        tasks.spawn(async move {
            let mut out = ClosedOut {
                ok: 0,
                errors: 0,
                first_bad: None,
                latency: new_hist(),
            };
            tokio::time::sleep_until(start).await;
            let mut seq = 0u64;
            loop {
                let begun = Instant::now();
                if begun >= end {
                    break;
                }
                let res = f(client, seq).await;
                seq += 1;
                if begun < warm_end {
                    continue;
                }
                match res {
                    Ok(()) => {
                        out.ok += 1;
                        record(&mut out.latency, begun.elapsed());
                    }
                    Err(why) => {
                        out.errors += 1;
                        out.first_bad.get_or_insert(why);
                    }
                }
            }
            out
        });
    }
    let mut total = ClosedOut {
        ok: 0,
        errors: 0,
        first_bad: None,
        latency: new_hist(),
    };
    while let Some(Ok(o)) = tasks.join_next().await {
        total.ok += o.ok;
        total.errors += o.errors;
        total.first_bad = total.first_bad.or(o.first_bad);
        let _ = total.latency.add(&o.latency);
    }
    total
}

fn us(ns: f64) -> f64 {
    round1(ns / 1000.0)
}

fn stats_of(h: &Histogram<u64>, unexpected: u64, rate_count: u64, secs: f64) -> Stats {
    Stats {
        requests: h.len(),
        unexpected,
        seconds: secs,
        rps: round1(rate_count as f64 / secs),
        mean_us: us(h.mean()),
        p50_us: us(h.value_at_quantile(0.50) as f64),
        p90_us: us(h.value_at_quantile(0.90) as f64),
        p95_us: us(h.value_at_quantile(0.95) as f64),
        p99_us: us(h.value_at_quantile(0.99) as f64),
        max_us: us(h.max() as f64),
    }
}

// ---------------------------------------------------------------------------------------
// Server CPU from /proc

/// `utime + stime` in clock ticks from the text of `/proc/<pid>/stat`. The command name is in
/// parentheses and may contain spaces, so fields are counted from the last `)`.
pub fn parse_proc_stat_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // `rest` starts at field 3 (state); utime is field 14 and stime field 15.
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// `VmRSS` in kB from the text of `/proc/<pid>/status`.
pub fn parse_status_rss_kb(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn read_ticks(pid: u32) -> Option<u64> {
    parse_proc_stat_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn read_rss_mb(pid: u32) -> Option<f64> {
    let kb = parse_status_rss_kb(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)?;
    Some(round1(kb as f64 / 1024.0))
}

fn clk_tck() -> f64 {
    command_output("getconf", &["CLK_TCK"])
        .and_then(|s| s.parse().ok())
        .unwrap_or(100.0)
}

/// Server CPU over a measured window.
#[derive(Debug, Clone, Serialize)]
pub struct Cpu {
    pub seconds: f64,
    /// Share of one core, in percent, over the window.
    pub pct_of_core: f64,
    /// CPU microseconds per completed request.
    pub us_per_request: f64,
}

fn cpu_of(before: Option<u64>, after: Option<u64>, window_s: f64, requests: u64) -> Option<Cpu> {
    let secs = (after?.checked_sub(before?)?) as f64 / clk_tck();
    Some(Cpu {
        seconds: round1(secs * 100.0) / 100.0,
        pct_of_core: round1(secs / window_s * 100.0),
        us_per_request: if requests == 0 {
            0.0
        } else {
            round1(secs / requests as f64 * 1e6)
        },
    })
}

/// Read the server's CPU ticks when the warm-up ends and when the window closes.
fn sample_cpu(
    pid: u32,
    t0: Instant,
    t1: Instant,
) -> tokio::task::JoinHandle<(Option<u64>, Option<u64>)> {
    tokio::spawn(async move {
        tokio::time::sleep_until(t0).await;
        let a = read_ticks(pid);
        tokio::time::sleep_until(t1).await;
        (a, read_ticks(pid))
    })
}

// ---------------------------------------------------------------------------------------
// Servers

struct Env {
    work: WorkDir,
    server_bin: PathBuf,
    fake_bin: Option<PathBuf>,
    policy: PathBuf,
}

impl Env {
    fn new(bin_dir: &Option<PathBuf>, with_upstream: bool) -> Result<Self> {
        let bin_dir = match bin_dir {
            Some(d) => d.clone(),
            None => default_bin_dir()?,
        };
        let work = WorkDir::new()?;
        // Copy the binaries: a shared target dir may be rebuilt by another checkout mid-run.
        let server_bin = work.0.join("attenuo-server");
        std::fs::copy(find_bin(&bin_dir, "attenuo-server")?, &server_bin)?;
        let fake_bin = if with_upstream {
            let p = work.0.join("fake_mcp");
            std::fs::copy(find_bin(&bin_dir, "fake_mcp")?, &p)?;
            Some(p)
        } else {
            None
        };
        let policy = work.0.join("policy.cedar");
        std::fs::write(&policy, POLICY)?;
        Ok(Self {
            work,
            server_bin,
            fake_bin,
            policy,
        })
    }
}

struct Running {
    _server: Proc,
    _fake: Option<Proc>,
    pid: u32,
    base: String,
    http: reqwest::Client,
    label: &'static str,
    upstream_mcp: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ServerOpts {
    /// `[issuer] lease_interval_seconds`; the harness default (86400) when `None`.
    lease_interval: Option<u64>,
}

/// Spawn a binary this process has just copied. Another thread that copies a binary at the
/// same moment (the tests run in one process) can hold a write handle across a `fork`, which
/// makes `exec` fail with `ETXTBSY` until the child has exec'd; retry briefly.
async fn spawn_retrying(cmd: &mut Spawn) -> std::io::Result<tokio::process::Child> {
    let mut tries = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(26) && tries < 40 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            other => return other,
        }
    }
}

async fn start_server(env: &Env, mode: AuditMode, so: ServerOpts) -> Result<Running> {
    let label = mode.label();
    let (sqlite, durability) = mode.settings(&env.work.0);
    let (ob_port, up_port, metrics_port) = (free_port()?, free_port()?, free_port()?);
    let mut cfg = render_config(
        ob_port,
        up_port,
        &env.policy,
        &sqlite,
        durability,
        metrics_port,
    );
    // The actor id of an exchange is asserted, so every request can name a fresh one.
    cfg.push_str("\n[token]\nrequire_actor_auth = false\n");
    if let Some(s) = so.lease_interval {
        cfg = cfg.replace(
            "lease_interval_seconds = 86400",
            &format!("lease_interval_seconds = {s}"),
        );
    }
    let cfg_path = env.work.0.join(format!("config-{label}.toml"));
    std::fs::write(&cfg_path, cfg)?;
    let fake = match &env.fake_bin {
        Some(bin) => {
            let p = Proc {
                child: spawn_retrying(
                    Spawn::new(bin)
                        .args(["--port", &up_port.to_string()])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .kill_on_drop(true),
                )
                .await
                .context("start fake_mcp")?,
            };
            wait_tcp(up_port).await?;
            Some(p)
        }
        None => None,
    };
    let log_path = env.work.0.join(format!("server-{label}.log"));
    let server = Proc {
        child: spawn_retrying(
            Spawn::new(&env.server_bin)
                .arg("--config")
                .arg(&cfg_path)
                .env("RUST_LOG", "warn")
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(&log_path)?)
                .kill_on_drop(true),
        )
        .await
        .context("start attenuo-server")?,
    };
    let pid = server
        .child
        .id()
        .ok_or_else(|| anyhow!("server has no pid"))?;
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(512)
        .timeout(Duration::from_secs(30))
        .build()?;
    let base = format!("http://127.0.0.1:{ob_port}");
    if let Err(e) = wait_http(&http, &format!("{base}/healthz")).await {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        bail!("{e}; server log:\n{log}");
    }
    Ok(Running {
        _server: server,
        _fake: fake,
        pid,
        base,
        http,
        label,
        upstream_mcp: env
            .fake_bin
            .as_ref()
            .map(|_| format!("http://127.0.0.1:{up_port}/mcp")),
    })
}

fn dedup_modes(modes: &[AuditMode]) -> Vec<AuditMode> {
    let mut seen = Vec::new();
    for &m in modes {
        if !seen.contains(&m) {
            seen.push(m);
        }
    }
    seen
}

async fn audit_verify(run: &Running, at_least: u64) -> Result<Value> {
    let v: Value = run
        .http
        .get(format!("{}/admin/audit/verify", run.base))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await?
        .json()
        .await
        .context("audit verify")?;
    let ok = v["ok"].as_bool() == Some(true) && v["first_bad_seq"].is_null();
    let entries = v["entries"].as_u64().unwrap_or(0);
    eprintln!(
        "[{}] audit verify: ok={ok} entries={entries} (at least {at_least} expected)",
        run.label
    );
    ensure!(
        ok && entries >= at_least,
        "[{}] audit chain did not verify or is short ({v}); expected at least {at_least}",
        run.label
    );
    Ok(json!({"audit": run.label, "ok": ok, "entries": entries, "expected_at_least": at_least}))
}

// ---------------------------------------------------------------------------------------
// Requests

/// A token plus the lease of its last hop.
struct Issued {
    token: String,
    lease: String,
}

fn issued_of(v: &Value) -> Result<Issued> {
    Ok(Issued {
        token: v["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("no access_token in {v}"))?
            .to_string(),
        lease: v["lease"]
            .as_str()
            .ok_or_else(|| anyhow!("no lease in {v}"))?
            .to_string(),
    })
}

async fn mint_root(run: &Running) -> Result<Issued> {
    let v = post_json(
        &run.http,
        &format!("{}/admin/root-token", run.base),
        Some(ADMIN_TOKEN),
        &json!({
            "subject": "bench-user", "issuer": "https://idp.example", "agent": "bench-root",
            "capabilities": [format!("{UPSTREAM}:read_file")], "ttl_seconds": 3600,
        }),
    )
    .await
    .context("dev root mint")?;
    issued_of(&v)
}

fn exchange_body(parent: &str, actor: &str) -> Value {
    json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": parent,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "actor": actor,
        "requested_ttl_seconds": 3600,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": UPSTREAM, "tool": "read_file"}]}],
    })
}

/// One exchange as the measured workload sends it: only the status and the presence of a new
/// token are checked.
async fn exchange_once(
    http: &reqwest::Client,
    base: &str,
    parent: &str,
    actor: &str,
) -> std::result::Result<(), String> {
    let resp = http
        .post(format!("{base}/token"))
        .json(&exchange_body(parent, actor))
        .send()
        .await
        .map_err(|e| format!("request error: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("body error: {e}"))?;
    if status.is_success() && text.contains("\"access_token\"") {
        Ok(())
    } else {
        Err(format!("exchange answered {status}: {text}"))
    }
}

async fn exchange_issued(run: &Running, parent: &str, actor: &str) -> Result<Issued> {
    let v = post_json(
        &run.http,
        &format!("{}/token", run.base),
        None,
        &exchange_body(parent, actor),
    )
    .await
    .with_context(|| format!("exchange to {actor}"))?;
    issued_of(&v)
}

async fn renew_once(
    http: &reqwest::Client,
    base: &str,
    token: &str,
) -> std::result::Result<(), String> {
    let resp = http
        .post(format!("{base}/token/renew"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("request error: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("body error: {e}"))?;
    if status.is_success() && text.contains("\"expires_at\"") {
        Ok(())
    } else {
        Err(format!("renew answered {status}: {text}"))
    }
}

/// One proxied or direct `tools/call`, checked the way the closed-loop cell checks it.
async fn call_once(
    http: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    body: &str,
    expect: Expect,
) -> std::result::Result<(), String> {
    let mut req = http
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_string());
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("request error: {e}"))?;
    let status = resp.status().as_u16();
    let header = resp
        .headers()
        .get(super::DECISION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let text = resp.text().await.map_err(|e| format!("body error: {e}"))?;
    check_answer(expect, status, header.as_deref(), &text).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------------------
// One measured cell, closed or open loop

#[derive(Debug, Clone, Copy)]
enum Load {
    Closed(usize),
    Open(f64),
}

#[derive(Debug, Clone, Serialize)]
pub struct Measured {
    /// `closed` or `open`.
    pub load: &'static str,
    pub clients: Option<usize>,
    pub offered_rps: Option<f64>,
    /// Arrivals dropped because too many requests were already in flight (open loop).
    pub shed: u64,
    /// Latency: from send (closed) or from the scheduled arrival (open). `rps` is the achieved
    /// rate of correct answers.
    #[serde(flatten)]
    pub stats: Stats,
    pub cpu: Option<Cpu>,
    pub server_rss_mb: Option<f64>,
    /// Open loop only: p50 and p99 of the time from sending a request to its answer, without
    /// the time the arrival waited for the scheduler (see `dispatch_lag_*`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_p50_us: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_p99_us: Option<f64>,
    /// Open loop only: how late the scheduler dispatched arrivals (timer resolution is 1 ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch_lag_p50_us: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch_lag_p99_us: Option<f64>,
}

const OPEN_MAX_INFLIGHT: usize = 1024;

/// Run `f(slot, seq)` under `load` for warm-up plus duration and measure the server's CPU
/// over the measured window. `slots` is how many distinct tokens `f` can index for an open
/// loop; the closed loop indexes by client.
async fn measure<F, Fut>(
    run: &Running,
    load: Load,
    warmup: Duration,
    duration: Duration,
    slots: usize,
    f: F,
) -> Result<Measured>
where
    F: Fn(usize, u64) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<(), String>> + Send + 'static,
{
    let start = Instant::now() + Duration::from_millis(100);
    let cpu = sample_cpu(run.pid, start + warmup, start + warmup + duration);
    let secs = duration.as_secs_f64();
    let mut open_extra = (None, None, None, None);
    let (stats, shed, clients, offered) = match load {
        Load::Closed(n) => {
            let o = run_closed(n, start, warmup, duration, f).await;
            if let Some(bad) = &o.first_bad {
                eprintln!("  unexpected answer ({} total), first: {bad}", o.errors);
            }
            (stats_of(&o.latency, o.errors, o.ok, secs), 0, Some(n), None)
        }
        Load::Open(rate) => {
            let cfg = OpenCfg {
                rate,
                start,
                warmup,
                duration,
                max_inflight: OPEN_MAX_INFLIGHT,
                seed: 0x0b_e4a1f ^ rate.to_bits(),
            };
            let o = run_open(&cfg, |seq| f(seq as usize % slots.max(1), seq)).await;
            if let Some(bad) = &o.first_bad {
                eprintln!("  unexpected answer ({} total), first: {bad}", o.errors);
            }
            let q = |h: &Histogram<u64>, p: f64| Some(us(h.value_at_quantile(p) as f64));
            open_extra = (
                q(&o.service, 0.5),
                q(&o.service, 0.99),
                q(&o.lag, 0.5),
                q(&o.lag, 0.99),
            );
            (
                stats_of(&o.latency, o.errors, o.done_in_window, secs),
                o.shed,
                None,
                Some(rate),
            )
        }
    };
    let (a, b) = cpu.await?;
    Ok(Measured {
        load: if clients.is_some() { "closed" } else { "open" },
        clients,
        offered_rps: offered,
        shed,
        cpu: cpu_of(a, b, secs, stats.requests),
        server_rss_mb: read_rss_mb(run.pid),
        service_p50_us: open_extra.0,
        service_p99_us: open_extra.1,
        dispatch_lag_p50_us: open_extra.2,
        dispatch_lag_p99_us: open_extra.3,
        stats,
    })
}

fn ensure_clean(cell: &str, m: &Measured) -> Result<()> {
    ensure!(
        m.stats.unexpected == 0,
        "{cell}: {} answers were not what the scenario expects",
        m.stats.unexpected
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------
// exchange

#[derive(Debug, Clone, Serialize)]
pub struct ExchangeRow {
    pub audit: String,
    /// Hops in the token that is exchanged (the child has one more).
    pub parent_hops: usize,
    #[serde(flatten)]
    pub m: Measured,
}

async fn run_exchange(a: &ExchangeArgs) -> Result<()> {
    let c = &a.common;
    ensure!(c.duration > 0.0, "--duration must be positive");
    ensure!(
        !a.clients.contains(&0),
        "--clients values must be at least 1"
    );
    ensure!(
        a.open_loop.iter().all(|r| *r > 0.0),
        "--open-loop rates must be positive"
    );
    let (warm, dur) = (
        Duration::from_secs_f64(c.warmup),
        Duration::from_secs_f64(c.duration),
    );
    let env = Env::new(&c.bin_dir, false)?;
    let ids = ActorIds::for_this_run();
    let mut rows: Vec<ExchangeRow> = Vec::new();
    let mut checks: Vec<Value> = Vec::new();
    for mode in dedup_modes(&c.audit) {
        let run = start_server(&env, mode, ServerOpts::default()).await?;
        for &depth in &a.depths {
            let loads: Vec<Load> = if a.open_loop.is_empty() {
                a.clients.iter().map(|&n| Load::Closed(n)).collect()
            } else {
                a.open_loop.iter().map(|&r| Load::Open(r)).collect()
            };
            for load in loads {
                let slots = match load {
                    Load::Closed(n) => n,
                    Load::Open(_) => 16,
                };
                // Each client holds its own token, so closed-loop clients do not share a parent.
                let mut tokens = Vec::new();
                for _ in 0..slots {
                    tokens.push(Arc::new(mint_chain(&run.http, &run.base, depth).await?));
                }
                eprintln!("[{}] exchange of a {depth}-hop token, {load:?}", run.label);
                let (http, base, ids2) = (run.http.clone(), run.base.clone(), ids.clone());
                let m = measure(&run, load, warm, dur, slots, move |slot, seq| {
                    let (http, base, token) = (http.clone(), base.clone(), tokens[slot].clone());
                    let actor = ids2.id(slot, seq);
                    async move { exchange_once(&http, &base, &token, &actor).await }
                })
                .await?;
                ensure_clean(
                    &format!("[{}] exchange depth {depth} {load:?}", run.label),
                    &m,
                )?;
                rows.push(ExchangeRow {
                    audit: run.label.into(),
                    parent_hops: depth,
                    m,
                });
            }
        }
        let ok: u64 = rows
            .iter()
            .filter(|r| r.audit == run.label)
            .map(|r| r.m.stats.requests)
            .sum();
        checks.push(audit_verify(&run, ok).await?);
    }
    let md = render_exchange(&rows, &checks);
    println!("{md}");
    write_outputs(c, "exchange", serde_json::to_value(&rows)?, &md, checks)
}

fn load_cell(m: &Measured) -> String {
    match (m.clients, m.offered_rps) {
        (Some(n), _) => format!("{n} clients"),
        (_, Some(r)) => format!("open {r:.0}/s"),
        _ => "?".into(),
    }
}

fn cpu_cells(c: &Option<Cpu>) -> String {
    c.as_ref().map_or("n/a | n/a".into(), |c| {
        format!("{:.0}% | {}", c.pct_of_core, c.us_per_request)
    })
}

pub fn render_exchange(rows: &[ExchangeRow], checks: &[Value]) -> String {
    let mut s = String::from("### Token exchange (`POST /token`), fresh actor per request\n\n");
    s.push_str(
        "Closed-loop latency runs from send; open-loop latency from the scheduled arrival. \
         `CPU` is the server process over the measured window, in percent of one core and \
         microseconds per request. For open-loop rows `svc` is the time from send to answer and \
         `lag` the time the scheduler took to dispatch an arrival (tokio's timer ticks at 1 ms), \
         both of which the latency columns include.\n\n\
         | audit | hops in | load | req/s | p50 us | p99 us | max us | shed | server CPU | CPU us/req | svc p50 / p99 us | lag p50 us |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        let t = &r.m.stats;
        s.push_str(&format!(
            "| {} | {} | {} | {:.0} | {} | {} | {} | {} | {} | {} |\n",
            r.audit,
            r.parent_hops,
            load_cell(&r.m),
            t.rps,
            t.p50_us,
            t.p99_us,
            t.max_us,
            r.m.shed,
            cpu_cells(&r.m.cpu),
            svc_cells(&r.m)
        ));
    }
    s.push_str(&render_checks(checks));
    s
}

fn svc_cells(m: &Measured) -> String {
    match (m.service_p50_us, m.service_p99_us, m.dispatch_lag_p50_us) {
        (Some(a), Some(b), Some(l)) => format!("{a} / {b} | {l}"),
        _ => "n/a | n/a".into(),
    }
}

fn render_checks(checks: &[Value]) -> String {
    let mut s = String::from("\nAudit chain after the run:\n\n| audit | verified | entries | at least |\n|---|---|---|---|\n");
    for c in checks {
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            c["audit"].as_str().unwrap_or("?"),
            c["ok"],
            c["entries"],
            c["expected_at_least"]
        ));
    }
    s
}

// ---------------------------------------------------------------------------------------
// lease-renew

const GROUP: usize = 100;
const RENEW_INFLIGHT: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct LeaseRow {
    pub audit: String,
    pub leases: usize,
    pub roots: usize,
    pub interval_s: f64,
    pub offered_rps: f64,
    pub achieved_rps: f64,
    pub renewals: u64,
    pub errors: u64,
    /// Renewals that finished later than one interval after they were due.
    pub later_than_interval: u64,
    /// From the due time to the end of the response.
    pub p50_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
    /// From the start of the request to the end of the response.
    pub service_p50_us: f64,
    pub service_p99_us: f64,
    pub cpu: Option<Cpu>,
    /// Server CPU with the same leases live and no renewals, percent of one core.
    pub idle_cpu_pct: Option<f64>,
    pub rss_mb_before: Option<f64>,
    pub rss_mb_after: Option<f64>,
    pub setup_s: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CascadeRow {
    pub audit: String,
    pub run: usize,
    /// Hops of the deepest token in the tree.
    pub depth: usize,
    pub descendants: usize,
    pub revoked: u64,
    pub revoke_ms: f64,
    /// A descendant's renewal after the revoke was refused.
    pub descendant_refused: bool,
}

fn parse_cell(s: &str) -> Result<(usize, f64)> {
    let (m, t) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("cell `{s}` must be LEASES:INTERVAL_SECONDS"))?;
    let m: usize = m
        .trim()
        .parse()
        .with_context(|| format!("leases in `{s}`"))?;
    let t: f64 = t
        .trim()
        .parse()
        .with_context(|| format!("interval in `{s}`"))?;
    ensure!(
        m >= 1 && t > 0.0 && t.is_finite(),
        "cell `{s}`: leases and interval must be positive"
    );
    Ok((m, t))
}

/// `roots` roots, each with `GROUP - 1` children: every token is returned, roots first.
async fn make_leases(run: &Running, ids: &ActorIds, roots: usize) -> Result<Vec<String>> {
    let mut root_tokens = Vec::new();
    for _ in 0..roots {
        root_tokens.push(mint_root(run).await?.token);
    }
    let gate = Arc::new(Semaphore::new(32));
    let mut tasks = JoinSet::new();
    for (ri, root) in root_tokens.iter().enumerate() {
        for k in 0..GROUP - 1 {
            let (http, base, root, actor) = (
                run.http.clone(),
                run.base.clone(),
                root.clone(),
                ids.id(ri, k as u64),
            );
            let gate = gate.clone();
            tasks.spawn(async move {
                let _p = gate.acquire().await;
                let v = post_json(
                    &http,
                    &format!("{base}/token"),
                    None,
                    &exchange_body(&root, &actor),
                )
                .await
                .with_context(|| format!("exchange to {actor}"))?;
                issued_of(&v).map(|i| i.token)
            });
        }
    }
    let mut out = root_tokens;
    while let Some(r) = tasks.join_next().await {
        out.push(r??);
    }
    Ok(out)
}

async fn lease_cell(
    run: &Running,
    ids: &ActorIds,
    m: usize,
    interval_s: f64,
    warm: Duration,
    dur: Duration,
) -> Result<LeaseRow> {
    let roots = m.div_ceil(GROUP);
    let t_setup = std::time::Instant::now();
    let tokens = make_leases(run, ids, roots).await?;
    let setup_s = round1(t_setup.elapsed().as_secs_f64());
    let total = tokens.len();
    let rss_before = read_rss_mb(run.pid);

    // Same leases, nothing renewing.
    let idle_a = read_ticks(run.pid);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let idle_cpu_pct = cpu_of(idle_a, read_ticks(run.pid), 2.0, 0).map(|c| c.pct_of_core);

    let interval = Duration::from_secs_f64(interval_s);
    let start = Instant::now() + Duration::from_millis(200);
    let end = warm + dur;
    let cpu = sample_cpu(run.pid, start + warm, start + end);
    let gate = Arc::new(Semaphore::new(RENEW_INFLIGHT));
    let mut tasks = JoinSet::new();
    for (i, token) in tokens.into_iter().enumerate() {
        let (http, base, gate) = (run.http.clone(), run.base.clone(), gate.clone());
        // Spread the first renewals evenly over one interval.
        let phase = interval.mul_f64(i as f64 / total as f64);
        tasks.spawn(async move {
            let (mut lat, mut svc) = (new_hist(), new_hist());
            let (mut errors, mut late, mut done_in_window) = (0u64, 0u64, 0u64);
            let mut first_bad = None;
            let mut off = phase;
            while off < end {
                tokio::time::sleep_until(start + off).await;
                let permit = gate.acquire().await;
                let begun = Instant::now();
                let res = renew_once(&http, &base, &token).await;
                let done = Instant::now();
                drop(permit);
                if off >= warm {
                    match res {
                        Ok(()) => {
                            let l = done.saturating_duration_since(start + off);
                            record(&mut lat, l);
                            record(&mut svc, done.saturating_duration_since(begun));
                            if l > interval {
                                late += 1;
                            }
                            if done.saturating_duration_since(start) <= end {
                                done_in_window += 1;
                            }
                        }
                        Err(why) => {
                            errors += 1;
                            first_bad.get_or_insert(why);
                        }
                    }
                }
                off += interval;
            }
            (lat, svc, errors, late, done_in_window, first_bad)
        });
    }
    let (mut lat, mut svc) = (new_hist(), new_hist());
    let (mut errors, mut late, mut in_window) = (0u64, 0u64, 0u64);
    let mut first_bad: Option<String> = None;
    while let Some(r) = tasks.join_next().await {
        let (l, s, e, lt, w, fb) = r?;
        let _ = lat.add(&l);
        let _ = svc.add(&s);
        errors += e;
        late += lt;
        in_window += w;
        first_bad = first_bad.or(fb);
    }
    let (a, b) = cpu.await?;
    let secs = dur.as_secs_f64();
    if let Some(bad) = &first_bad {
        eprintln!("  renewal failed ({errors} total), first: {bad}");
    }
    ensure!(
        errors == 0,
        "lease-renew {m}: {errors} renewals failed; first: {}",
        first_bad.unwrap_or_default()
    );
    Ok(LeaseRow {
        audit: run.label.into(),
        leases: total,
        roots,
        interval_s,
        offered_rps: round1(total as f64 / interval_s),
        achieved_rps: round1(in_window as f64 / secs),
        renewals: lat.len(),
        errors,
        later_than_interval: late,
        p50_us: us(lat.value_at_quantile(0.5) as f64),
        p99_us: us(lat.value_at_quantile(0.99) as f64),
        max_us: us(lat.max() as f64),
        service_p50_us: us(svc.value_at_quantile(0.5) as f64),
        service_p99_us: us(svc.value_at_quantile(0.99) as f64),
        cpu: cpu_of(a, b, secs, lat.len()),
        idle_cpu_pct,
        rss_mb_before: rss_before,
        rss_mb_after: read_rss_mb(run.pid),
        setup_s,
    })
}

/// Build a tree of depth 3 with 100 descendants under one root (10 children, 9 under each),
/// revoke the root and time it.
async fn cascade_once(run: &Running, ids: &ActorIds, n: usize) -> Result<CascadeRow> {
    let root = mint_root(run).await?;
    let mut leaf = None;
    for c in 0..10usize {
        let child = exchange_issued(run, &root.token, &ids.id(1000 + n, c as u64)).await?;
        for g in 0..9usize {
            let gc =
                exchange_issued(run, &child.token, &ids.id(2000 + n * 10 + c, g as u64)).await?;
            leaf = Some(gc);
        }
    }
    let leaf = leaf.ok_or_else(|| anyhow!("no leaf"))?;
    let t = std::time::Instant::now();
    let v = post_json(
        &run.http,
        &format!("{}/admin/leases/{}/revoke", run.base, root.lease),
        Some(ADMIN_TOKEN),
        &json!({"reason": "bench cascade"}),
    )
    .await
    .context("revoke root")?;
    let revoke_ms = t.elapsed().as_secs_f64() * 1000.0;
    let revoked = v["revoked"].as_u64().unwrap_or(0);
    ensure!(
        revoked == 101,
        "revoking the root changed {revoked} leases, expected 101: {v}"
    );
    let refused = renew_once(&run.http, &run.base, &leaf.token).await.is_err();
    ensure!(refused, "a descendant could still renew after the revoke");
    Ok(CascadeRow {
        audit: run.label.into(),
        run: n,
        depth: 3,
        descendants: 100,
        revoked,
        revoke_ms: (revoke_ms * 100.0).round() / 100.0,
        descendant_refused: refused,
    })
}

async fn run_lease(a: &LeaseArgs) -> Result<()> {
    let c = &a.common;
    ensure!(c.duration > 0.0, "--duration must be positive");
    let cells: Vec<(usize, f64)> = a
        .cells
        .iter()
        .map(|s| parse_cell(s))
        .collect::<Result<_>>()?;
    let (warm, dur) = (
        Duration::from_secs_f64(c.warmup),
        Duration::from_secs_f64(c.duration),
    );
    let env = Env::new(&c.bin_dir, false)?;
    let ids = ActorIds::for_this_run();
    let (mut rows, mut cascades, mut checks) = (Vec::new(), Vec::new(), Vec::new());
    for mode in dedup_modes(&c.audit) {
        // A 300 s lease, as in the default config, so renewals really move the expiry.
        let run = start_server(
            &env,
            mode,
            ServerOpts {
                lease_interval: Some(300),
            },
        )
        .await?;
        for &(m, t) in &cells {
            eprintln!("[{}] {m} leases renewing every {t} s", run.label);
            rows.push(lease_cell(&run, &ids, m, t, warm, dur).await?);
        }
        for n in 0..a.cascade_runs {
            eprintln!("[{}] revoke cascade {n}", run.label);
            cascades.push(cascade_once(&run, &ids, n).await?);
        }
        let expected = rows
            .iter()
            .filter(|r| r.audit == run.label)
            .map(|r| r.renewals)
            .sum();
        checks.push(audit_verify(&run, expected).await?);
    }
    let md = render_lease(&rows, &cascades, &checks);
    println!("{md}");
    let value = json!({"renewals": rows, "cascade": cascades});
    write_outputs(c, "lease_renew", value, &md, checks)
}

fn opt(x: Option<f64>) -> String {
    x.map_or("n/a".into(), |v| format!("{v}"))
}

pub fn render_lease(rows: &[LeaseRow], cascades: &[CascadeRow], checks: &[Value]) -> String {
    let mut s = String::from("### Lease renewal (`POST /token/renew`)\n\n");
    s.push_str(
        "Each lease renews once per interval, first renewals spread evenly over the first \
         interval. Latency runs from the time the renewal was due (a server that falls behind \
         shows it); service time from the request being sent. `late` counts renewals that \
         finished more than one interval after they were due. Server CPU is over the measured \
         window; idle CPU is the same leases with nothing renewing.\n\n\
         | audit | leases | interval s | offered/s | achieved/s | p50 us | p99 us | max us | svc p50 | svc p99 | late | CPU % of core | CPU us/renewal | idle CPU % | RSS MB before/after |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        let (pct, per) = r
            .cpu
            .as_ref()
            .map_or((f64::NAN, f64::NAN), |c| (c.pct_of_core, c.us_per_request));
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.0} | {} | {} | {} / {} |\n",
            r.audit, r.leases, r.interval_s, r.offered_rps, r.achieved_rps, r.p50_us, r.p99_us,
            r.max_us, r.service_p50_us, r.service_p99_us, r.later_than_interval, pct, per,
            opt(r.idle_cpu_pct), opt(r.rss_mb_before), opt(r.rss_mb_after)
        ));
    }
    s.push_str("\n### Revoke cascade\n\nRoot of a tree of depth 3 (a root, 10 children, 9 grandchildren under each: 100 descendants), revoked through `POST /admin/leases/{id}/revoke`. The time includes the HTTP round trip and the admin audit record.\n\n| audit | runs | revoked leases | min ms | median ms | max ms |\n|---|---|---|---|---|---|\n");
    let mut modes: Vec<&str> = Vec::new();
    for c in cascades {
        if !modes.contains(&c.audit.as_str()) {
            modes.push(&c.audit);
        }
    }
    for m in modes {
        let mut v: Vec<f64> = cascades
            .iter()
            .filter(|c| c.audit == m)
            .map(|c| c.revoke_ms)
            .collect();
        v.sort_by(|a, b| a.total_cmp(b));
        s.push_str(&format!(
            "| {m} | {} | {} | {} | {} | {} |\n",
            v.len(),
            cascades
                .iter()
                .find(|c| c.audit == m)
                .map_or(0, |c| c.revoked),
            v[0],
            v[v.len() / 2],
            v[v.len() - 1]
        ));
    }
    s.push_str(&render_checks(checks));
    s
}

// ---------------------------------------------------------------------------------------
// Open-loop proxied call (the top-level `--open-loop` flag)

#[derive(Debug, Clone, Serialize)]
pub struct CallOpenRow {
    pub audit: String,
    /// `direct` (straight at the upstream) or the outcome through the proxy.
    pub path: String,
    pub hops: usize,
    #[serde(flatten)]
    pub m: Measured,
}

/// The existing proxied `tools/call` cell with Poisson arrivals at each `--open-loop` rate,
/// plus the same call straight at the upstream at the same rate.
pub async fn run_call_open(opts: &Opts) -> Result<()> {
    ensure!(opts.duration > 0.0, "--duration must be positive");
    ensure!(
        opts.open_loop.iter().all(|r| *r > 0.0),
        "--open-loop rates must be positive"
    );
    let (warm, dur) = (
        Duration::from_secs_f64(opts.warmup),
        Duration::from_secs_f64(opts.duration),
    );
    let env = Env::new(&opts.bin_dir, true)?;
    let mut rows: Vec<CallOpenRow> = Vec::new();
    let mut checks = Vec::new();
    for mode in dedup_modes(&opts.audit) {
        let run = start_server(&env, mode, ServerOpts::default()).await?;
        let upstream = run
            .upstream_mcp
            .clone()
            .ok_or_else(|| anyhow!("no upstream"))?;
        let mut sent = 0u64;
        for &rate in &opts.open_loop {
            eprintln!("[{}] direct, open loop {rate}/s", run.label);
            let (http, url) = (run.http.clone(), upstream.clone());
            let body = Arc::new(Outcome::Allow.body());
            let expect = Expect::Result {
                decision_header: false,
            };
            let m = measure(&run, Load::Open(rate), warm, dur, 1, move |_, _| {
                let (http, url, body) = (http.clone(), url.clone(), body.clone());
                async move { call_once(&http, &url, None, &body, expect).await }
            })
            .await?;
            // The server is not on this path; its CPU is not the cost of these calls.
            let m = Measured { cpu: None, ..m };
            ensure_clean(&format!("[{}] direct open {rate}", run.label), &m)?;
            rows.push(CallOpenRow {
                audit: run.label.into(),
                path: "direct".into(),
                hops: 0,
                m,
            });
        }
        for &depth in &opts.depths {
            let token = Arc::new(mint_chain(&run.http, &run.base, depth).await?);
            for &outcome in &opts.outcomes {
                for &rate in &opts.open_loop {
                    eprintln!(
                        "[{}] depth {depth} {}, open loop {rate}/s",
                        run.label,
                        outcome.label()
                    );
                    let url = format!("{}/mcp/{UPSTREAM}", run.base);
                    let (http, token, body) =
                        (run.http.clone(), token.clone(), Arc::new(outcome.body()));
                    let expect = outcome.expect();
                    let m = measure(&run, Load::Open(rate), warm, dur, 1, move |_, _| {
                        let (http, url, token, body) =
                            (http.clone(), url.clone(), token.clone(), body.clone());
                        async move { call_once(&http, &url, Some(&token), &body, expect).await }
                    })
                    .await?;
                    sent += m.stats.requests;
                    ensure_clean(
                        &format!(
                            "[{}] depth {depth} {} open {rate}",
                            run.label,
                            outcome.label()
                        ),
                        &m,
                    )?;
                    rows.push(CallOpenRow {
                        audit: run.label.into(),
                        path: outcome.label().into(),
                        hops: depth,
                        m,
                    });
                }
            }
        }
        checks.push(audit_verify(&run, sent).await?);
    }
    let md = render_call_open(&rows, &checks);
    println!("{md}");
    let common = Common {
        bin_dir: opts.bin_dir.clone(),
        duration: opts.duration,
        warmup: opts.warmup,
        audit: opts.audit.clone(),
        json: opts.json.clone(),
        markdown: opts.markdown.clone(),
    };
    write_outputs(
        &common,
        "call_open_loop",
        serde_json::to_value(&rows)?,
        &md,
        checks,
    )
}

pub fn render_call_open(rows: &[CallOpenRow], checks: &[Value]) -> String {
    let mut s = String::from("### Proxied `tools/call`, open loop (Poisson arrivals)\n\n");
    s.push_str(
        "Latency runs from the scheduled arrival. `achieved` counts correct answers that \
         arrived before the window closed.\n\n\
         | audit | path | hops | offered/s | achieved/s | p50 us | p99 us | max us | shed | server CPU | CPU us/req | svc p50 / p99 us | lag p50 us |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        let t = &r.m.stats;
        s.push_str(&format!(
            "| {} | {} | {} | {} | {:.0} | {} | {} | {} | {} | {} | {} |\n",
            r.audit,
            r.path,
            r.hops,
            opt(r.m.offered_rps),
            t.rps,
            t.p50_us,
            t.p99_us,
            t.max_us,
            r.m.shed,
            cpu_cells(&r.m.cpu),
            svc_cells(&r.m)
        ));
    }
    s.push_str(&render_checks(checks));
    s
}

// ---------------------------------------------------------------------------------------
// Output

fn meta_json(c: &Common) -> Value {
    let cpu_model = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
    });
    json!({
        "date_utc": command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]),
        "host": command_output("hostname", &[]),
        "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|s| s.trim().to_string()),
        "cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "cpu_model": cpu_model,
        "loadavg_at_end": std::fs::read_to_string("/proc/loadavg").ok().map(|s| s.trim().to_string()),
        "git_rev": command_output("git", &["rev-parse", "--short", "HEAD"]),
        "rustc": command_output("rustc", &["--version"]),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "duration_s": c.duration,
        "warmup_s": c.warmup,
        "cpu_clock_ticks_per_s": clk_tck(),
        "runs_per_cell": 1,
        "server_config": "[token] require_actor_auth = false; loopback; HTTP/1.1 keep-alive",
    })
}

/// Merge `rows` into `runs.<section>` of the JSON file and append `md` to the markdown file.
fn write_outputs(
    c: &Common,
    section: &str,
    rows: Value,
    md: &str,
    checks: Vec<Value>,
) -> Result<()> {
    if let Some(p) = &c.json {
        let mut doc: Value = std::fs::read(p)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| json!({"runs": {}}));
        let runs = doc["runs"]
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} has no `runs` object", p.display()))?;
        let entry = runs
            .entry(section)
            .or_insert_with(|| json!({"meta": Value::Null, "rows": []}));
        entry["meta"] = meta_json(c);
        merge_rows(&mut entry["rows"], rows);
        let ck = entry
            .as_object_mut()
            .unwrap()
            .entry("audit_checks")
            .or_insert_with(|| json!([]));
        if let Some(a) = ck.as_array_mut() {
            a.extend(checks);
        }
        std::fs::write(p, serde_json::to_string_pretty(&doc)?)?;
    }
    if let Some(p) = &c.markdown {
        append(p, md)?;
    }
    Ok(())
}

fn merge_rows(into: &mut Value, rows: Value) {
    match (into.as_array_mut(), rows) {
        (Some(a), Value::Array(r)) => a.extend(r),
        (_, Value::Object(new)) => {
            // `{name: [rows]}`: extend each named list.
            if !into.is_object() {
                *into = json!({});
            }
            for (k, v) in new {
                let slot = into
                    .as_object_mut()
                    .unwrap()
                    .entry(k)
                    .or_insert_with(|| json!([]));
                merge_rows(slot, v);
            }
        }
        (_, other) => *into = other,
    }
}

fn append(p: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    writeln!(f, "{text}")?;
    Ok(())
}

pub async fn run_command(cmd: &Command) -> Result<()> {
    match cmd {
        Command::Exchange(a) => run_exchange(a).await,
        Command::LeaseRenew(a) => run_lease(a).await,
        Command::HotPath(a) => crate::hotpath::run(a).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn actor_ids_never_repeat_and_stay_valid() {
        let ids = ActorIds::new("t1");
        let mut seen = HashSet::new();
        for client in 0..8 {
            for seq in 0..1000 {
                let id = ids.id(client, seq);
                assert!(seen.insert(id.clone()), "{id} repeated");
                assert!(id.len() <= 40, "{id}");
                assert!(
                    id.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                    "{id}"
                );
                assert!(!id.starts_with("bench-a") && id != "attenuo");
            }
        }
        // (client 1, seq 23) and (client 12, seq 3) must not collide.
        assert_ne!(ids.id(1, 23), ids.id(12, 3));
        assert_ne!(ActorIds::new("t2").id(0, 0), ids.id(0, 0));
    }

    #[test]
    fn actor_ids_differ_between_runs() {
        let a = ActorIds::for_this_run();
        std::thread::sleep(Duration::from_millis(2));
        let b = ActorIds::for_this_run();
        assert_ne!(a.id(0, 0), b.id(0, 0));
    }

    #[test]
    fn arrivals_are_increasing_with_the_requested_rate_and_exponential_gaps() {
        let rate = 500.0;
        let times: Vec<Duration> = Arrivals::poisson(rate, 42)
            .take_while(|t| *t < Duration::from_secs(20))
            .collect();
        assert!(times.windows(2).all(|w| w[0] < w[1]));
        let n = times.len() as f64;
        assert!(
            (n / 20.0 - rate).abs() / rate < 0.03,
            "{n} arrivals in 20 s"
        );
        let gaps: Vec<f64> = times
            .windows(2)
            .map(|w| (w[1] - w[0]).as_secs_f64())
            .collect();
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        assert!((mean * rate - 1.0).abs() < 0.03, "mean gap {mean}");
        // Exponential gaps have a coefficient of variation of 1 (a fixed pace would give 0).
        assert!(
            (var.sqrt() / mean - 1.0).abs() < 0.08,
            "cv {}",
            var.sqrt() / mean
        );
    }

    fn cfg(rate: f64, secs: u64, max_inflight: usize) -> OpenCfg {
        OpenCfg {
            rate,
            start: Instant::now(),
            warmup: Duration::ZERO,
            duration: Duration::from_secs(secs),
            max_inflight,
            seed: 7,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn open_loop_follows_the_schedule_on_a_fake_clock() {
        // The service takes exactly 5 ms of (paused) tokio time.
        let c = cfg(200.0, 10, 1000);
        let out = run_open(&c, |_| async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok(())
        })
        .await;
        assert!(
            (out.offered as f64 / 10.0 - 200.0).abs() < 12.0,
            "{} offered",
            out.offered
        );
        assert_eq!((out.shed, out.errors), (0, 0));
        assert_eq!(out.ok, out.offered);
        // Tokio's timer ticks at 1 ms, even paused: a wake-up is at most one tick late.
        assert!(
            out.lag.max() <= 1_100_000,
            "dispatch lag {} ns",
            out.lag.max()
        );
        // The service time is the 5 ms exactly; the latency from the scheduled arrival adds
        // the dispatch lag and nothing else, because nothing queues.
        let svc = out.service.value_at_quantile(0.5);
        assert!(
            (5_000_000..=5_100_000).contains(&svc),
            "service p50 {svc} ns"
        );
        let p50 = out.latency.value_at_quantile(0.5);
        assert!((5_000_000..=6_200_000).contains(&p50), "p50 {p50} ns");
        assert!(out.latency.max() <= 6_200_000);
    }

    #[tokio::test(start_paused = true)]
    async fn open_loop_does_not_wait_for_a_slow_request() {
        // The first request takes 2 s; the rest 1 ms. A closed loop would stall behind it.
        let c = cfg(100.0, 5, 1000);
        let out = run_open(&c, |seq| async move {
            let d = if seq == 0 { 2000 } else { 1 };
            tokio::time::sleep(Duration::from_millis(d)).await;
            Ok(())
        })
        .await;
        assert!(out.offered > 400, "{} offered", out.offered);
        assert_eq!(out.ok, out.offered);
        assert!(
            out.latency.value_at_quantile(0.5) < 2_000_000,
            "p50 stayed at the service time"
        );
        assert!(out.latency.max() >= 2_000_000_000);
    }

    #[tokio::test(start_paused = true)]
    async fn open_loop_sheds_when_the_server_cannot_keep_up() {
        // 1000/s offered, 100 ms service, 10 slots: capacity is 100/s.
        let c = cfg(1000.0, 5, 10);
        let out = run_open(&c, |_| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        })
        .await;
        assert_eq!(out.offered, out.shed + out.ok + out.errors);
        assert!(out.shed > out.ok * 5, "shed {} ok {}", out.shed, out.ok);
        assert!((out.ok as f64 / 5.0 - 100.0).abs() < 15.0, "{} ok", out.ok);
    }

    #[tokio::test(start_paused = true)]
    async fn open_loop_discards_the_warmup_and_reports_errors() {
        let mut c = cfg(100.0, 4, 100);
        c.warmup = Duration::from_secs(2);
        let out = run_open(&c, |seq| async move {
            if seq % 10 == 0 {
                Err("bad".into())
            } else {
                Ok(())
            }
        })
        .await;
        // Only the last 4 of the 6 scheduled seconds are measured.
        assert!((out.offered as f64 - 400.0).abs() < 60.0, "{}", out.offered);
        assert_eq!(out.offered, out.ok + out.errors);
        assert!(out.errors > 0);
        assert_eq!(out.first_bad.as_deref(), Some("bad"));
    }

    #[tokio::test(start_paused = true)]
    async fn closed_loop_runs_back_to_back_and_skips_the_warmup() {
        let out = run_closed(
            2,
            Instant::now(),
            Duration::from_secs(1),
            Duration::from_secs(3),
            |_, _| async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            },
        )
        .await;
        // 2 clients x 3 s / 10 ms
        assert!((out.ok as f64 - 600.0).abs() <= 4.0, "{}", out.ok);
        assert_eq!(out.errors, 0);
    }

    #[test]
    fn proc_stat_parsing_survives_a_command_name_with_spaces_and_parens() {
        let line = "1234 (attenuo (srv) x) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 75 0 0 20 0 9 0 5555 1000000 2000 18446744073709551615";
        assert_eq!(parse_proc_stat_ticks(line), Some(325));
        assert_eq!(parse_proc_stat_ticks("garbage"), None);
        assert_eq!(
            parse_status_rss_kb("Name:\tx\nVmRSS:\t  20480 kB\nThreads:\t3\n"),
            Some(20480)
        );
        assert_eq!(parse_status_rss_kb("Name:\tx\n"), None);
    }

    #[test]
    fn cpu_window_math() {
        let c = cpu_of(Some(100), Some(300), 10.0, 1000).unwrap();
        // 200 ticks at the assumed rate of 100 per second is 2 s over a 10 s window.
        if clk_tck() == 100.0 {
            assert_eq!(c.pct_of_core, 20.0);
            assert_eq!(c.us_per_request, 2000.0);
        }
        assert!(cpu_of(Some(5), Some(3), 1.0, 1).is_none());
        assert!(cpu_of(None, Some(3), 1.0, 1).is_none());
    }

    #[test]
    fn lease_cells_parse() {
        assert_eq!(parse_cell("5000:1").unwrap(), (5000, 1.0));
        assert_eq!(parse_cell(" 100 : 2.5 ").unwrap(), (100, 2.5));
        assert!(parse_cell("100").is_err());
        assert!(parse_cell("0:1").is_err());
        assert!(parse_cell("10:0").is_err());
    }

    #[test]
    fn json_rows_merge_across_runs() {
        let mut slot = json!([]);
        merge_rows(&mut slot, json!([{"a": 1}]));
        merge_rows(&mut slot, json!([{"a": 2}]));
        assert_eq!(slot.as_array().unwrap().len(), 2);
        let mut obj = json!([]);
        merge_rows(&mut obj, json!({"renewals": [1], "cascade": [2]}));
        merge_rows(&mut obj, json!({"renewals": [3], "cascade": []}));
        assert_eq!(obj["renewals"], json!([1, 3]));
        assert_eq!(obj["cascade"], json!([2]));
    }
}
