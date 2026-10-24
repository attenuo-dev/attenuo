//! What output labelling (ADR-0009) and run limits (ADR-0010) add to one proxied `tools/call`.
//!
//! `attenuo-bench hot-path` starts one server (with its own `fake_mcp`) per configuration, all
//! on the same kind of audit store, and drives the same two calls through each:
//!
//! - `read`: `read_file` on `alice/public-docs`, the call most of a run is made of;
//! - `destructive`: `create_issue` on the same repo (catalog `destructive`, the default for a
//!   tool that is not `readonly`), which Cedar allows in every configuration.
//!
//! Both bodies carry `n: 1` (declared `long` in the catalog everywhere), so the bodies are
//! byte for byte the same in every configuration. The configurations:
//!
//! | `--configs` | Catalog `output` | Extra policy | Token |
//! |---|---|---|---|
//! | `baseline` | `trusted` on both tools | none | no limits |
//! | `labels` | `untrusted` (the default) | a forbid on `context.session.tainted` that does not fire for these calls | no limits |
//! | `limits` | `trusted` | none | `calls` and `sum` (on `n`) on both capabilities, in both hops |
//! | `limits_calls` | `trusted` | none | `calls` only (no `sum`, so no `synchronous=FULL` charge) |
//! | `both` | as `labels` | as `labels` | as `limits` |
//! | `usage` | as `baseline` | none | no limits; `[policy] track_usage = true` |
//!
//! Run usage (`context.usage`) is kept only when it can matter: no policy here reads it and
//! no catalog entry names `amount` or `destination`, so in every configuration but `usage`
//! an allowed `destructive` call makes no usage write. `usage` forces it, so `usage` against
//! `baseline` is the cost of that write (one lease-store transaction per allowed destructive
//! call, as every such call paid between #59 and the elision).
//!
//! Every allowed call's answer is recorded since #42 (a `tool_result` append), trusted or not,
//! so `baseline` already has the result append; an untrusted answer adds the run-label write
//! and makes later decisions carry `labels.tainted_by`. The `read` cell runs before the
//! `destructive` one, so with labels on, every measured destructive call is on a tainted run.
//! With limits, every allowed call charges 4 counters (2 kinds in each of 2 hops) in one
//! store transaction between the policy stage and the audit append.
//!
//! Cells are interleaved: run 1 does every configuration's two cells, then run 2, and so on,
//! so slow drift on a shared host spreads over all configurations. Per cell the harness reads
//! `/metrics` when the warm-up ends and when the clients stop, and reports, besides
//! `attenuo_proxy_stage_seconds`, two derived means from histograms the server already has:
//! the decision time not in any decision stage (`attenuo_authorize_duration_seconds` minus
//! lease check, policy and audit append: the budget charge, building the record, approval
//! bookkeeping) and the mean `tool_result` append (`attenuo_audit_append_duration_seconds`
//! minus the decision appends of the `audit_append` stage). The run-label write has no timer;
//! it sits inside the `response` stage.
//!
//! `--approval-loops N` adds the approval round, timed as one sequence on a separate server
//! (untrusted `read_file`, an `@obligation("approval")` forbid on destructive calls in a
//! tainted run): the gated call (`-32008` with an `approval_id`), `POST
//! /admin/approvals/{id}` with `{"decision": "grant"}`, and the identical retry, allowed.
//!
//! ```text
//! cargo build --release -p attenuo-bench -p attenuo-server
//! cargo build --release -p attenuo-proxy --features testing --example fake_mcp
//! target/release/attenuo-bench hot-path --runs 5 --duration 10 --approval-loops 2000 \
//!     --json out.json --markdown out.md
//! ```
//!
//! See `docs/design/performance.md` ("Output labelling and run limits on the hot path").

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Args, ValueEnum};
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{
    command_output, default_bin_dir, drive, ensure_expected, find_bin, free_port, parse_stages,
    post_json, render_config, round1, stage_delta, wait_http, wait_tcp, AuditMode, Endpoints,
    Expect, Proc, StageHist, Stats, Target, WorkDir, ADMIN_TOKEN, AGENT_SECRET, POLICY, UPSTREAM,
};

/// One configuration of the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HotConfig {
    /// No output labels (both tools `output = "trusted"`), no limits.
    Baseline,
    /// Untrusted output: every answer labels the run; a session-aware forbid in the policy.
    Labels,
    /// `calls` and `sum` limits on both capabilities in both hops; trusted output.
    Limits,
    /// `calls` limits only (no `sum`, so the charge commits at the store's durability).
    #[value(name = "limits_calls")]
    LimitsCalls,
    /// Labels and limits together.
    Both,
    /// As `baseline`, with `[policy] track_usage = true`: every allowed destructive call
    /// charges the run-usage counters, which no policy here reads.
    Usage,
}

impl HotConfig {
    fn label(self) -> &'static str {
        match self {
            HotConfig::Baseline => "baseline",
            HotConfig::Labels => "labels",
            HotConfig::Limits => "limits",
            HotConfig::LimitsCalls => "limits_calls",
            HotConfig::Both => "both",
            HotConfig::Usage => "usage",
        }
    }
    fn labels(self) -> bool {
        matches!(self, HotConfig::Labels | HotConfig::Both)
    }
    /// The `limits` member each capability carries, if any.
    fn limits(self) -> Option<Value> {
        // Far above anything a run reaches, so no call is refused.
        let calls = 1_000_000_000_000u64;
        let sum = json!({"arg": "n", "max": 1_000_000_000_000_000u64});
        match self {
            HotConfig::Limits | HotConfig::Both => Some(json!({"calls": calls, "sum": sum})),
            HotConfig::LimitsCalls => Some(json!({"calls": calls})),
            HotConfig::Baseline | HotConfig::Labels | HotConfig::Usage => None,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct HotPathArgs {
    /// Directory holding `attenuo-server` and `fake_mcp` (default: this executable's directory).
    #[arg(long)]
    pub bin_dir: Option<PathBuf>,
    /// Measured seconds per cell.
    #[arg(long, default_value_t = 10.0)]
    pub duration: f64,
    /// Warm-up seconds per cell, discarded.
    #[arg(long, default_value_t = 2.0)]
    pub warmup: f64,
    /// Interleaved repetitions of every cell.
    #[arg(long, default_value_t = 5)]
    pub runs: usize,
    /// Configurations to measure.
    #[arg(long, value_delimiter = ',', value_enum,
          default_values_t = [HotConfig::Baseline, HotConfig::Labels, HotConfig::Limits, HotConfig::Both])]
    pub configs: Vec<HotConfig>,
    /// Audit and lease store for every configuration (`file` is SQLite, `durability = "normal"`).
    #[arg(long, value_enum, default_value_t = AuditMode::File)]
    pub audit: AuditMode,
    /// Hops in the token (2: the root and one exchange, so limits charge both hops).
    #[arg(long, default_value_t = 2)]
    pub depth: usize,
    /// Closed-loop clients per cell.
    #[arg(long, default_value_t = 1)]
    pub clients: usize,
    /// Approval rounds to time (gated call, grant, retry) after `--approval-warmup` rounds;
    /// 0 skips them.
    #[arg(long, default_value_t = 0)]
    pub approval_loops: usize,
    /// Approval rounds run first and discarded.
    #[arg(long, default_value_t = 100)]
    pub approval_warmup: usize,
    /// Write the results as JSON here.
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Write the markdown tables here.
    #[arg(long)]
    pub markdown: Option<PathBuf>,
}

/// The two calls every configuration measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Cell {
    Read,
    Destructive,
}

impl Cell {
    const ALL: [Cell; 2] = [Cell::Read, Cell::Destructive];
    fn label(self) -> &'static str {
        match self {
            Cell::Read => "read",
            Cell::Destructive => "destructive",
        }
    }
    fn body(self) -> String {
        let (name, args) = match self {
            Cell::Read => (
                "read_file",
                json!({"repo": "alice/public-docs", "path": "README.md", "n": 1}),
            ),
            Cell::Destructive => (
                "create_issue",
                json!({"repo": "alice/public-docs", "title": "bench", "n": 1}),
            ),
        };
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": name, "arguments": args}})
        .to_string()
    }
}

const PERMIT_CREATE_ISSUE: &str = r#"
@id("permit_create_issue_public")
permit(principal, action == Action::"fake/create_issue", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };
"#;

/// Reads the run's labels in Cedar and never fires for the benchmarked calls (public repo).
const LABELS_FORBID: &str = r#"
@id("forbid_private_writes_after_untrusted_read")
forbid(principal, action, resource)
when {
    resource.destructive && context.session.tainted &&
    context.input has repo && context.input.repo like "alice/private-*"
};
"#;

const APPROVAL_FORBID: &str = r#"
@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
"#;

/// The bench's server config with the catalog this module needs: an `n` argument on both
/// tools, `output = "trusted"` on both unless `untrusted`, and `track_usage = true` when
/// `track_usage`.
fn config_text(base: String, untrusted: bool, track_usage: bool) -> Result<String> {
    let output = if untrusted {
        ""
    } else {
        "output = \"trusted\"\n"
    };
    let mut s = base;
    for (from, to) in [
        (
            format!(
                "[policy.catalog.{UPSTREAM}.read_file]\nreadonly = true\n\
                 inputs = {{ repo = \"string\", path = \"string\" }}\n"
            ),
            format!(
                "[policy.catalog.{UPSTREAM}.read_file]\nreadonly = true\n{output}\
                 inputs = {{ repo = \"string\", path = \"string\", n = \"long\" }}\n"
            ),
        ),
        (
            format!(
                "[policy.catalog.{UPSTREAM}.create_issue]\n\
                 inputs = {{ repo = \"string\", title = \"string\" }}\n"
            ),
            format!(
                "[policy.catalog.{UPSTREAM}.create_issue]\n{output}\
                 inputs = {{ repo = \"string\", title = \"string\", n = \"long\" }}\n"
            ),
        ),
    ] {
        ensure!(
            s.contains(&from),
            "bench config template changed; cannot patch {from}"
        );
        s = s.replace(&from, &to);
    }
    if track_usage {
        ensure!(
            s.contains("\n[policy]\n"),
            "bench config template has no [policy]"
        );
        s = s.replacen("\n[policy]\n", "\n[policy]\ntrack_usage = true\n", 1);
    }
    Ok(s)
}

/// A token of `depth` hops carrying `read_file` and `create_issue`, each with `limits` when
/// given (the same figures in every hop).
async fn mint(
    http: &reqwest::Client,
    base: &str,
    depth: usize,
    limits: Option<&Value>,
) -> Result<String> {
    let caps: Vec<Value> = ["read_file", "create_issue"]
        .iter()
        .map(|tool| {
            let mut c = json!({"server": UPSTREAM, "tool": tool});
            if let Some(l) = limits {
                c["limits"] = l.clone();
            }
            c
        })
        .collect();
    let root = post_json(
        http,
        &format!("{base}/admin/root-token"),
        Some(ADMIN_TOKEN),
        &json!({
            "subject": "bench-user", "issuer": "https://idp.example", "agent": "bench-root",
            "capabilities": caps, "ttl_seconds": 3600,
        }),
    )
    .await
    .context("dev root mint")?;
    let mut token = root["access_token"]
        .as_str()
        .ok_or_else(|| anyhow!("root mint has no access_token: {root}"))?
        .to_string();
    for i in 1..depth {
        let actor = format!("bench-a{i}");
        let resp = post_json(
            http,
            &format!("{base}/token"),
            None,
            &json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor, "client_id": actor, "client_secret": AGENT_SECRET,
                "requested_ttl_seconds": 3600,
                "authorization_details": [{"type": "attenuo_capabilities", "capabilities": caps}],
            }),
        )
        .await
        .with_context(|| format!("exchange to {actor}"))?;
        token = resp["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("exchange has no access_token: {resp}"))?
            .to_string();
    }
    Ok(token)
}

/// A running server and its upstream.
struct Server {
    _fake: Proc,
    _server: Proc,
    ep: Endpoints,
    token: String,
    sent: u64,
}

#[allow(clippy::too_many_arguments)]
async fn start(
    work: &WorkDir,
    server_bin: &std::path::Path,
    fake_bin: &std::path::Path,
    http: &reqwest::Client,
    args: &HotPathArgs,
    label: &str,
    untrusted: bool,
    track_usage: bool,
    policy: &str,
    limits: Option<&Value>,
) -> Result<Server> {
    let dir = work.0.join(label);
    std::fs::create_dir_all(&dir)?;
    let policy_path = dir.join("policy.cedar");
    std::fs::write(&policy_path, policy)?;
    let (sqlite, durability) = args.audit.settings(&dir);
    let (ob_port, up_port, metrics_port) = (free_port()?, free_port()?, free_port()?);
    let cfg = config_text(
        render_config(
            ob_port,
            up_port,
            &policy_path,
            &sqlite,
            durability,
            metrics_port,
        ),
        untrusted,
        track_usage,
    )?;
    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, cfg)?;
    let fake = Proc {
        child: Command::new(fake_bin)
            .args(["--port", &up_port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("start fake_mcp")?,
    };
    let log_path = dir.join("server.log");
    let server = Proc {
        child: Command::new(server_bin)
            .arg("--config")
            .arg(&cfg_path)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log_path)?)
            .kill_on_drop(true)
            .spawn()
            .context("start attenuo-server")?,
    };
    wait_tcp(up_port).await?;
    let ep = Endpoints {
        attenuo: format!("http://127.0.0.1:{ob_port}"),
        upstream_mcp: format!("http://127.0.0.1:{up_port}/mcp"),
        metrics: Some(format!("http://127.0.0.1:{metrics_port}/metrics")),
    };
    if let Err(e) = wait_http(http, &format!("{}/healthz", ep.attenuo)).await {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        bail!("{e}; server log:\n{log}");
    }
    let token = mint(http, &ep.attenuo, args.depth, limits)
        .await
        .with_context(|| format!("[{label}] token"))?;
    Ok(Server {
        _fake: fake,
        _server: server,
        ep,
        token,
        sent: 0,
    })
}

/// `name value` from a Prometheus text exposition (an unlabelled sample), 0 when absent.
fn scalar(text: &str, name: &str) -> f64 {
    text.lines()
        .filter_map(|l| l.split_once(' '))
        .find(|(n, _)| *n == name)
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0.0)
}

/// Sums and counts over one window, for the derived means.
#[derive(Debug, Clone, Copy, Default, Serialize)]
struct Sums {
    authorize_sum: f64,
    authorize_count: f64,
    append_sum: f64,
    append_count: f64,
}

impl Sums {
    fn delta(before: &str, after: &str) -> Self {
        let d = |n: &str| (scalar(after, n) - scalar(before, n)).max(0.0);
        Sums {
            authorize_sum: d("attenuo_authorize_duration_seconds_sum"),
            authorize_count: d("attenuo_authorize_duration_seconds_count"),
            append_sum: d("attenuo_audit_append_duration_seconds_sum"),
            append_count: d("attenuo_audit_append_duration_seconds_count"),
        }
    }
    fn add(&mut self, o: &Sums) {
        self.authorize_sum += o.authorize_sum;
        self.authorize_count += o.authorize_count;
        self.append_sum += o.append_sum;
        self.append_count += o.append_count;
    }
}

/// Stage histograms by stage name.
type Stages = Vec<(String, StageHist)>;

fn merge(into: &mut Stages, add: &[(String, StageHist)]) {
    for (stage, h) in add {
        match into.iter_mut().find(|(s, _)| s == stage) {
            None => into.push((stage.clone(), h.clone())),
            Some((_, acc)) => {
                for (i, &(bound, n)) in h.buckets.iter().enumerate() {
                    match acc.buckets.get_mut(i) {
                        Some(b) if b.0 == bound => b.1 += n,
                        _ => acc.buckets.push((bound, n)),
                    }
                }
                acc.sum += h.sum;
                acc.count += h.count;
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct StageSummary {
    stage: String,
    count: u64,
    mean_us: f64,
    p50_us: f64,
    p90_us: f64,
    p95_us: f64,
}

fn stage_summaries(h: &[(String, StageHist)]) -> Vec<StageSummary> {
    let us = |s: Option<f64>| round1(s.unwrap_or(0.0) * 1e6);
    h.iter()
        .filter(|(_, h)| h.count > 0)
        .map(|(stage, h)| StageSummary {
            stage: stage.clone(),
            count: h.count,
            mean_us: us(Some(h.sum / h.count as f64)),
            p50_us: us(h.quantile(0.5)),
            p90_us: us(h.quantile(0.9)),
            p95_us: us(h.quantile(0.95)),
        })
        .collect()
}

/// Means derived from the server's histograms over a window (see the module docs).
#[derive(Debug, Clone, Serialize)]
struct Derived {
    /// `attenuo_authorize_duration_seconds` mean: the whole decision.
    decide_mean_us: f64,
    /// Decision time outside lease check, policy and audit append (charge, record, approval).
    decide_unstaged_mean_us: f64,
    /// Mean of the appends that are not decision records (the `tool_result` appends).
    result_append_mean_us: f64,
    result_appends: u64,
}

fn derived(stages: &[(String, StageHist)], s: &Sums) -> Derived {
    let sum_of = |name: &str| {
        stages
            .iter()
            .find(|(n, _)| n == name)
            .map_or((0.0, 0u64), |(_, h)| (h.sum, h.count))
    };
    let (lease, _) = sum_of("lease_check");
    let (policy, _) = sum_of("policy");
    let (append, append_n) = sum_of("audit_append");
    let n = s.authorize_count.max(1.0);
    let other_n = (s.append_count - append_n as f64).max(0.0);
    Derived {
        decide_mean_us: round1(s.authorize_sum / n * 1e6),
        decide_unstaged_mean_us: round1((s.authorize_sum - lease - policy - append) / n * 1e6),
        result_append_mean_us: if other_n > 0.0 {
            round1((s.append_sum - append) / other_n * 1e6)
        } else {
            0.0
        },
        result_appends: other_n as u64,
    }
}

#[derive(Debug, Clone, Serialize)]
struct CellRun {
    config: &'static str,
    cell: &'static str,
    run: usize,
    #[serde(flatten)]
    stats: Stats,
    derived: Derived,
}

#[derive(Debug, Clone, Serialize)]
struct CellSummary {
    config: &'static str,
    cell: &'static str,
    runs: usize,
    p50_median_us: f64,
    p50_min_us: f64,
    p50_max_us: f64,
    p95_median_us: f64,
    p99_median_us: f64,
    rps_median: f64,
    stages: Vec<StageSummary>,
    derived: Derived,
}

#[derive(Debug, Clone, Serialize)]
struct Step {
    step: &'static str,
    count: u64,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    mean_us: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ApprovalReport {
    rounds: usize,
    steps: Vec<Step>,
    stages: Vec<StageSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct HotReport {
    meta: Value,
    runs: Vec<CellRun>,
    summary: Vec<CellSummary>,
    /// Per configuration and call: counters charged and label sources in one decision record.
    checks: Vec<Value>,
    approval: Option<ApprovalReport>,
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    match v.len() {
        0 => 0.0,
        n if n % 2 == 1 => v[n / 2],
        n => round1((v[n / 2 - 1] + v[n / 2]) / 2.0),
    }
}

/// POST a JSON-RPC body through the proxy and return the parsed message.
async fn rpc(http: &reqwest::Client, url: &str, token: &str, body: &str) -> Result<Value> {
    let resp = http
        .post(url)
        .bearer_auth(token)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_string())
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    ensure!(status.is_success(), "HTTP {status}: {text}");
    super::rpc_message(&text).ok_or_else(|| anyhow!("no JSON-RPC message in {text}"))
}

/// One approval round: gated call, operator grant, identical retry. Times in nanoseconds.
async fn approval_round(
    http: &reqwest::Client,
    srv: &Server,
    url: &str,
    body: &str,
) -> Result<[u64; 3]> {
    let t0 = Instant::now();
    let gated = rpc(http, url, &srv.token, body).await?;
    let t1 = Instant::now();
    let code = gated.pointer("/error/code").and_then(Value::as_i64);
    let id = gated
        .pointer("/error/data/approval_id")
        .and_then(Value::as_str);
    let (Some(-32008), Some(id)) = (code, id) else {
        bail!("expected approval_required (-32008) with an approval_id, got {gated}");
    };
    let resp = http
        .post(format!("{}/admin/approvals/{id}", srv.ep.attenuo))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"decision": "grant"}))
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    ensure!(status.is_success(), "grant answered {status}: {text}");
    let t2 = Instant::now();
    let retry = rpc(http, url, &srv.token, body).await?;
    let t3 = Instant::now();
    ensure!(
        retry.get("result").is_some(),
        "granted retry was not allowed: {retry}"
    );
    let ns = |d: Duration| (d.as_nanos() as u64).max(1);
    Ok([ns(t1 - t0), ns(t2 - t1), ns(t3 - t2)])
}

async fn run_approvals(
    http: &reqwest::Client,
    srv: &mut Server,
    args: &HotPathArgs,
) -> Result<ApprovalReport> {
    let url = format!("{}/mcp/{UPSTREAM}", srv.ep.attenuo);
    // Taint the run first: one untrusted read.
    let read = rpc(http, &url, &srv.token, &Cell::Read.body()).await?;
    ensure!(read.get("result").is_some(), "taint read failed: {read}");
    let body = Cell::Destructive.body();
    for _ in 0..args.approval_warmup {
        approval_round(http, srv, &url, &body).await?;
    }
    let metrics = srv.ep.metrics.clone().unwrap_or_default();
    let before = super::scrape_metrics(http, &metrics).await?;
    let new_hist = || Histogram::<u64>::new_with_bounds(1, 120_000_000_000, 3);
    let mut hists = [new_hist()?, new_hist()?, new_hist()?, new_hist()?];
    for _ in 0..args.approval_loops {
        let t = approval_round(http, srv, &url, &body).await?;
        for (h, v) in hists.iter_mut().zip(t.iter().chain([&t.iter().sum()])) {
            h.record(*v)?;
        }
    }
    let after = super::scrape_metrics(http, &metrics).await?;
    srv.sent += 1 + 2 * (args.approval_warmup + args.approval_loops) as u64;
    let us = |ns: f64| round1(ns / 1000.0);
    let steps = ["gated_call", "grant", "retry", "round"]
        .iter()
        .zip(&hists)
        .map(|(step, h)| Step {
            step,
            count: h.len(),
            p50_us: us(h.value_at_quantile(0.5) as f64),
            p95_us: us(h.value_at_quantile(0.95) as f64),
            p99_us: us(h.value_at_quantile(0.99) as f64),
            mean_us: us(h.mean()),
        })
        .collect();
    Ok(ApprovalReport {
        rounds: args.approval_loops,
        steps,
        stages: stage_summaries(&stage_delta(&parse_stages(&before), &parse_stages(&after))),
    })
}

/// The first value under `key` anywhere in `v` (depth first).
fn find_key<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m
            .get(key)
            .or_else(|| m.values().find_map(|x| find_key(x, key))),
        Value::Array(a) => a.iter().find_map(|x| find_key(x, key)),
        _ => None,
    }
}

/// One more call of `cell`, and what its decision record says: how many counters it charged,
/// how many label sources it names, and whether it carries run usage. Checks that the
/// configuration does what it claims.
async fn probe(http: &reqwest::Client, srv: &mut Server, cell: Cell) -> Result<Value> {
    let resp = http
        .post(format!("{}/mcp/{UPSTREAM}", srv.ep.attenuo))
        .bearer_auth(&srv.token)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(cell.body())
        .send()
        .await?;
    srv.sent += 1;
    let id = resp
        .headers()
        .get(super::DECISION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.split(',').next())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow!("probe answer has no decision id"))?;
    let rec: Value = http
        .get(format!("{}/admin/audit/records/{id}", srv.ep.attenuo))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let len = |k: &str| {
        find_key(&rec, k)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    Ok(json!({
        "cell": cell.label(),
        "charged": len("charged"),
        "tainted_by": len("tainted_by"),
        "usage": find_key(&rec, "usage").is_some_and(|u| !u.is_null()),
    }))
}

async fn verify(http: &reqwest::Client, label: &str, srv: &Server) -> Result<()> {
    let v: Value = http
        .get(format!("{}/admin/audit/verify", srv.ep.attenuo))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await?
        .json()
        .await
        .context("audit verify")?;
    let entries = v["entries"].as_u64().unwrap_or(0);
    eprintln!(
        "[{label}] audit verify: ok={} entries={entries} (proxied calls sent {})",
        v["ok"], srv.sent
    );
    ensure!(
        v["ok"].as_bool() == Some(true) && v["first_bad_seq"].is_null() && entries >= srv.sent,
        "[{label}] audit chain did not verify or is short ({v}); proxied calls sent {}",
        srv.sent
    );
    Ok(())
}

fn render(r: &HotReport) -> String {
    let mut s = String::from(
        "### Configuration check\n\n\
         One extra call per configuration and call after the runs: counters its decision \
         charged, label sources (`labels.tainted_by`) and whether it carries run usage \
         (`usage`) in its record.\n\n\
         | config | call | counters charged | tainted_by | usage |\n|---|---|---|---|---|\n",
    );
    for c in &r.checks {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            c["config"].as_str().unwrap_or(""),
            c["cell"].as_str().unwrap_or(""),
            c["charged"],
            c["tainted_by"],
            c["usage"]
        ));
    }
    s.push_str(
        "\n### Client latency per configuration\n\n\
         Medians over the runs of each run's p50, p95 and p99 (closed loop), and the \
         lowest and highest p50 of the runs.\n\n\
         | config | call | runs | p50 us | p50 range | p95 us | p99 us | req/s |\n\
         |---|---|---|---|---|---|---|---|\n",
    );
    for x in &r.summary {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} to {} | {} | {} | {:.0} |\n",
            x.config,
            x.cell,
            x.runs,
            x.p50_median_us,
            x.p50_min_us,
            x.p50_max_us,
            x.p95_median_us,
            x.p99_median_us,
            x.rps_median
        ));
    }
    s.push_str(
        "\n### Server stages per configuration\n\n\
         `attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 \
         interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time \
         outside lease check, policy and audit append (the budget charge, among others); \
         `result append` is the mean `tool_result` append. Both are means derived from \
         `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.\n\n\
         | config | call | stage | count | mean us | p50 us | p95 us |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for x in &r.summary {
        for st in &x.stages {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                x.config, x.cell, st.stage, st.count, st.mean_us, st.p50_us, st.p95_us
            ));
        }
        let d = &x.derived;
        s.push_str(&format!(
            "| {} | {} | decide (whole, mean) | | {} | | |\n\
             | {} | {} | decide (unstaged, mean) | | {} | | |\n\
             | {} | {} | result append (mean) | {} | {} | | |\n",
            x.config,
            x.cell,
            d.decide_mean_us,
            x.config,
            x.cell,
            d.decide_unstaged_mean_us,
            x.config,
            x.cell,
            d.result_appends,
            d.result_append_mean_us
        ));
    }
    if let Some(a) = &r.approval {
        s.push_str(&format!(
            "\n### Approval round ({} rounds)\n\n\
             | step | count | p50 us | p95 us | p99 us | mean us |\n|---|---|---|---|---|---|\n",
            a.rounds
        ));
        for st in &a.steps {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                st.step, st.count, st.p50_us, st.p95_us, st.p99_us, st.mean_us
            ));
        }
        s.push_str(
            "\nServer stages over the measured rounds:\n\n\
             | stage | count | mean us | p50 us | p95 us |\n|---|---|---|---|---|\n",
        );
        for st in &a.stages {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                st.stage, st.count, st.mean_us, st.p50_us, st.p95_us
            ));
        }
    }
    s
}

/// Run `attenuo-bench hot-path`.
pub async fn run(args: &HotPathArgs) -> Result<()> {
    ensure!(args.duration > 0.0, "--duration must be positive");
    ensure!(args.runs > 0, "--runs must be at least 1");
    ensure!(args.clients > 0, "--clients must be at least 1");
    ensure!(
        (2..=8).contains(&args.depth),
        "--depth must be 2 to 8 (limits charge every hop)"
    );
    let mut configs = Vec::new();
    for &c in &args.configs {
        if !configs.contains(&c) {
            configs.push(c);
        }
    }
    let bin_dir = match &args.bin_dir {
        Some(d) => d.clone(),
        None => default_bin_dir()?,
    };
    let work = WorkDir::new()?;
    // Copies: a shared target dir may be rebuilt by another checkout mid-run.
    let server_bin = work.0.join("attenuo-server");
    let fake_bin = work.0.join("fake_mcp");
    std::fs::copy(find_bin(&bin_dir, "attenuo-server")?, &server_bin)?;
    std::fs::copy(find_bin(&bin_dir, "fake_mcp")?, &fake_bin)?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut servers = Vec::new();
    for &c in &configs {
        let mut policy = format!("{POLICY}{PERMIT_CREATE_ISSUE}");
        if c.labels() {
            policy.push_str(LABELS_FORBID);
        }
        let limits = c.limits();
        let srv = start(
            &work,
            &server_bin,
            &fake_bin,
            &http,
            args,
            c.label(),
            c.labels(),
            c == HotConfig::Usage,
            &policy,
            limits.as_ref(),
        )
        .await?;
        servers.push((c, srv));
    }

    let warmup = Duration::from_secs_f64(args.warmup);
    let duration = Duration::from_secs_f64(args.duration);
    let mut runs = Vec::new();
    let mut pooled: Vec<(HotConfig, Cell, Stages, Sums)> = Vec::new();
    for run in 1..=args.runs {
        for (c, srv) in servers.iter_mut() {
            for cell in Cell::ALL {
                let name = format!("[{}] run {run} {}", c.label(), cell.label());
                eprintln!("{name}");
                let target = Target {
                    url: format!("{}/mcp/{UPSTREAM}", srv.ep.attenuo),
                    token: Some(srv.token.clone()),
                    body: cell.body(),
                    expect: Expect::Result {
                        decision_header: true,
                    },
                };
                let metrics = srv.ep.metrics.clone();
                let out = drive(
                    &target,
                    args.clients,
                    warmup,
                    duration,
                    metrics.as_deref().map(|u| (&http, u)),
                )
                .await?;
                srv.sent += out.sent;
                ensure_expected(&name, &out)?;
                let stages = out.stages.clone().unwrap_or_default();
                let sums = out
                    .metrics_raw
                    .as_ref()
                    .map(|(b, a)| Sums::delta(b, a))
                    .unwrap_or_default();
                runs.push(CellRun {
                    config: c.label(),
                    cell: cell.label(),
                    run,
                    stats: out.stats.clone(),
                    derived: derived(&stages, &sums),
                });
                match pooled.iter_mut().find(|p| p.0 == *c && p.1 == cell) {
                    Some(p) => {
                        merge(&mut p.2, &stages);
                        p.3.add(&sums);
                    }
                    None => pooled.push((*c, cell, stages, sums)),
                }
            }
        }
    }
    let mut checks = Vec::new();
    for (c, srv) in servers.iter_mut() {
        for cell in Cell::ALL {
            let mut p = probe(&http, srv, cell).await?;
            p["config"] = json!(c.label());
            eprintln!("[{}] probe {p}", c.label());
            checks.push(p);
        }
        verify(&http, c.label(), srv).await?;
    }

    let summary = pooled
        .iter()
        .map(|(c, cell, stages, sums)| {
            let mine: Vec<&CellRun> = runs
                .iter()
                .filter(|r| r.config == c.label() && r.cell == cell.label())
                .collect();
            let col = |f: fn(&Stats) -> f64| mine.iter().map(|r| f(&r.stats)).collect::<Vec<_>>();
            let mut p50 = col(|s| s.p50_us);
            let p50_min = p50.iter().copied().fold(f64::INFINITY, f64::min);
            let p50_max = p50.iter().copied().fold(0.0, f64::max);
            CellSummary {
                config: c.label(),
                cell: cell.label(),
                runs: mine.len(),
                p50_median_us: median(&mut p50),
                p50_min_us: p50_min,
                p50_max_us: p50_max,
                p95_median_us: median(&mut col(|s| s.p95_us)),
                p99_median_us: median(&mut col(|s| s.p99_us)),
                rps_median: median(&mut col(|s| s.rps)),
                stages: stage_summaries(stages),
                derived: derived(stages, sums),
            }
        })
        .collect();

    let approval = if args.approval_loops > 0 {
        let policy = format!("{POLICY}{PERMIT_CREATE_ISSUE}{APPROVAL_FORBID}");
        let mut srv = start(
            &work,
            &server_bin,
            &fake_bin,
            &http,
            args,
            "approval",
            true,
            false,
            &policy,
            None,
        )
        .await?;
        eprintln!(
            "[approval] {} + {} rounds",
            args.approval_warmup, args.approval_loops
        );
        let a = run_approvals(&http, &mut srv, args).await?;
        verify(&http, "approval", &srv).await?;
        Some(a)
    } else {
        None
    };

    let report = HotReport {
        meta: json!({
            "date_utc": command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]),
            "host": command_output("hostname", &[]),
            "cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
            "loadavg": std::fs::read_to_string("/proc/loadavg").ok().map(|s| s.trim().to_string()),
            "git_rev": command_output("git", &["rev-parse", "--short", "HEAD"]),
            "rustc": command_output("rustc", &["--version"]),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "duration_s": args.duration,
            "warmup_s": args.warmup,
            "runs": args.runs,
            "clients": args.clients,
            "depth": args.depth,
            "audit": args.audit,
        }),
        runs,
        summary,
        checks,
        approval,
    };
    let md = render(&report);
    println!("{md}");
    if let Some(p) = &args.markdown {
        std::fs::write(p, &md)?;
    }
    if let Some(p) = &args.json {
        std::fs::write(p, serde_json::to_string_pretty(&report)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_patch_applies_to_the_bench_template() {
        let base = render_config(1, 2, std::path::Path::new("/p"), ":memory:", "normal", 3);
        let trusted = config_text(base.clone(), false, false).unwrap();
        assert!(!trusted.contains("track_usage"));
        let tracked = config_text(base.clone(), false, true).unwrap();
        assert_eq!(tracked.matches("track_usage = true").count(), 1);
        assert_eq!(trusted.matches("output = \"trusted\"").count(), 2);
        assert_eq!(trusted.matches("n = \"long\"").count(), 2);
        let untrusted = config_text(base, true, false).unwrap();
        assert!(!untrusted.contains("output ="));
        assert_eq!(untrusted.matches("n = \"long\"").count(), 2);
    }

    #[test]
    fn scalar_reads_unlabelled_samples_only() {
        let text = "attenuo_authorize_duration_seconds_sum 0.25\n\
                    attenuo_authorize_duration_seconds_count 10\n\
                    attenuo_audit_append_duration_seconds_bucket{le=\"0.001\"} 3\n";
        assert_eq!(scalar(text, "attenuo_authorize_duration_seconds_sum"), 0.25);
        assert_eq!(
            scalar(text, "attenuo_authorize_duration_seconds_count"),
            10.0
        );
        assert_eq!(
            scalar(text, "attenuo_audit_append_duration_seconds_sum"),
            0.0
        );
    }
}
