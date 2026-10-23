//! End-to-end benchmark for onbehalf.
//!
//! Starts `onbehalf-server` and the `fake_mcp` example (or is pointed at running ones), mints
//! a root token through the development endpoint, exchanges it down to a chain of the
//! requested depth, and drives `tools/call` with N closed-loop clients for a fixed time:
//! once through the proxy and once straight at `fake_mcp` as the baseline. The added latency
//! is the proxy figure minus the direct one at the same concurrency. At the end it asks the
//! server to verify the audit chain and fails if the chain is broken or short of entries.
//!
//! See `docs/design/performance.md` for the method and its limits.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::process::{Child, Command};

const ADMIN_TOKEN: &str = "bench-admin-token";
/// `printf %s bench-secret | sha256sum`; every bench agent uses this secret.
const AGENT_SECRET: &str = "bench-secret";
const AGENT_SECRET_SHA256: &str =
    "0159438a9235d6abde38e49fb98944660d067d6b9b03d8a8f4ee4e522feb62cb";
const UPSTREAM: &str = "fake";
const MAX_EXCHANGES: usize = 7;

const POLICY: &str = r#"// Policy used by onbehalf-bench: the leak-demo policy with the server name `fake`.
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

/// Where the audit log lives for a group of runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    /// `sqlite_path = ":memory:"`.
    Memory,
    /// A SQLite file in the work directory.
    File,
}

/// What the benchmarked call should come out as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Permitted by policy; reaches the upstream.
    Allow,
    /// `read_file` on a private repo: the capability passes, Cedar denies.
    DenyPolicy,
    /// A tool the token does not carry: denied at the capability stage.
    DenyCapability,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::DenyPolicy => "deny_policy",
            Outcome::DenyCapability => "deny_capability",
        }
    }
    fn body(self) -> String {
        let (name, args) = match self {
            Outcome::Allow => (
                "read_file",
                json!({"repo": "alice/public-docs", "path": "README.md"}),
            ),
            Outcome::DenyPolicy => (
                "read_file",
                json!({"repo": "alice/private-salaries", "path": "2025.csv"}),
            ),
            Outcome::DenyCapability => ("delete_repo", json!({"repo": "alice/public-docs"})),
        };
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": name, "arguments": args}})
        .to_string()
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "onbehalf-bench",
    version,
    about = "End-to-end latency and throughput benchmark for onbehalf"
)]
pub struct Opts {
    /// Directory holding the `onbehalf-server` and `fake_mcp` binaries (also looked up under
    /// `examples/`). Default: the directory of this executable.
    #[arg(long)]
    pub bin_dir: Option<PathBuf>,
    /// Measured seconds per cell.
    #[arg(long, default_value_t = 5.0)]
    pub duration: f64,
    /// Warm-up seconds per cell, discarded.
    #[arg(long, default_value_t = 2.0)]
    pub warmup: f64,
    /// Concurrent closed-loop clients.
    #[arg(long, value_delimiter = ',', default_values_t = [1usize, 8, 32])]
    pub concurrency: Vec<usize>,
    /// Chain depth (number of hops in the token; 1 is the root token itself).
    #[arg(long, value_delimiter = ',', default_values_t = [1usize, 3])]
    pub depths: Vec<usize>,
    /// Audit store: `memory` (`:memory:`) or `file` (SQLite on disk). One server per mode.
    #[arg(long, value_delimiter = ',', value_enum, default_values_t = [AuditMode::Memory, AuditMode::File])]
    pub audit: Vec<AuditMode>,
    /// Call outcomes to measure.
    #[arg(long, value_delimiter = ',', value_enum,
          default_values_t = [Outcome::Allow, Outcome::DenyPolicy, Outcome::DenyCapability])]
    pub outcomes: Vec<Outcome>,
    /// Write the full results as JSON here.
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Write the markdown tables here.
    #[arg(long)]
    pub markdown: Option<PathBuf>,
    /// Use an already running onbehalf server (requires `--upstream-url`). Configure it with
    /// the files `--print-config` writes. Only one `--audit` mode is then run, as a label.
    #[arg(long, requires = "upstream_url")]
    pub onbehalf_url: Option<String>,
    /// Use an already running fake_mcp, base URL without `/mcp` (requires `--onbehalf-url`).
    #[arg(long, requires = "onbehalf_url")]
    pub upstream_url: Option<String>,
    /// Write `config.toml` and `policy.cedar` for an external server into this directory and
    /// exit. Needs `--onbehalf-port` and `--upstream-port`; honours the first `--audit` mode.
    #[arg(long)]
    pub print_config: Option<PathBuf>,
    #[arg(long, default_value_t = 18080)]
    pub onbehalf_port: u16,
    #[arg(long, default_value_t = 13001)]
    pub upstream_port: u16,
}

// ---------------------------------------------------------------------------------------
// Result types

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub requests: u64,
    pub unexpected: u64,
    pub seconds: f64,
    pub rps: f64,
    pub mean_us: f64,
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectRow {
    pub audit_group: String,
    pub concurrency: usize,
    #[serde(flatten)]
    pub stats: Stats,
}

#[derive(Debug, Clone, Serialize)]
pub struct Added {
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub mean_us: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyRow {
    pub audit: String,
    pub depth: usize,
    pub outcome: &'static str,
    pub concurrency: usize,
    #[serde(flatten)]
    pub stats: Stats,
    /// Proxy minus direct (allow call) at the same concurrency. For denied calls the upstream
    /// is never contacted, so this is the cost of the answer, not of an added hop.
    pub added: Added,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditCheck {
    pub audit: String,
    pub ok: bool,
    pub entries: u64,
    pub proxied_calls_sent: u64,
    pub checkpoints: u64,
    pub unsigned_tail: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub meta: Value,
    pub direct: Vec<DirectRow>,
    pub results: Vec<ProxyRow>,
    pub audit_checks: Vec<AuditCheck>,
}

// ---------------------------------------------------------------------------------------
// Process management

struct Proc {
    child: Child,
}
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(l.local_addr()?.port())
}

fn find_bin(dir: &Path, name: &str) -> Result<PathBuf> {
    for p in [dir.join(name), dir.join("examples").join(name)] {
        if p.is_file() {
            return Ok(p);
        }
    }
    bail!(
        "{name} not found in {} (build it: cargo build --release -p onbehalf-server \
         -p onbehalf-proxy --features onbehalf-proxy/testing --example fake_mcp)",
        dir.display()
    )
}

struct WorkDir(PathBuf);
impl WorkDir {
    fn new() -> Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "onbehalf-bench-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir_all(&p)?;
        Ok(Self(p))
    }
}
impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The server config the bench needs. `sqlite` is the `[audit] sqlite_path` value.
pub fn render_config(
    onbehalf_port: u16,
    upstream_port: u16,
    policy_path: &Path,
    sqlite: &str,
) -> String {
    let mut s = format!(
        r#"# onbehalf-server config written by onbehalf-bench.
[server]
listen = "127.0.0.1:{onbehalf_port}"

[issuer]
issuer = "http://127.0.0.1:{onbehalf_port}"
audience = "onbehalf"
default_ttl_seconds = 3600
# Leases default to 300 s; a long matrix must not outlive them.
lease_interval_seconds = 86400

[policy]
policies_path = "{policy}"

[policy.catalog.{UPSTREAM}.read_file]
readonly = true
inputs = {{ repo = "string", path = "string" }}

[policy.catalog.{UPSTREAM}.create_issue]
inputs = {{ repo = "string", title = "string" }}

[policy.catalog.{UPSTREAM}.delete_repo]
sensitive = true
inputs = {{ repo = "string" }}

[audit]
sqlite_path = "{sqlite}"

[[upstreams]]
name = "{UPSTREAM}"
url = "http://127.0.0.1:{upstream_port}/mcp"

[admin]
token = "{ADMIN_TOKEN}"

[[root_grants]]
subject = "bench-user"
issuer = "https://idp.example"
agent = "bench-root"
capabilities = ["{UPSTREAM}:*"]

[dev]
allow_root_mint = true
"#,
        policy = policy_path.display()
    );
    for i in 1..=MAX_EXCHANGES {
        s.push_str(&format!(
            "\n[[agents]]\nid = \"bench-a{i}\"\nsecret_sha256 = \"{AGENT_SECRET_SHA256}\"\n"
        ));
    }
    s
}

async fn wait_http(client: &reqwest::Client, url: &str) -> Result<()> {
    for _ in 0..200 {
        if let Ok(r) = client.get(url).send().await {
            if r.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("{url} did not come up")
}

async fn wait_tcp(port: u16) -> Result<()> {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("port {port} did not open")
}

// ---------------------------------------------------------------------------------------
// Tokens

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
    body: &Value,
) -> Result<Value> {
    let mut req = client.post(url).json(body);
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await.with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await?;
    ensure!(status.is_success(), "POST {url} answered {status}: {text}");
    serde_json::from_str(&text).with_context(|| format!("non-JSON from {url}: {text}"))
}

/// A token whose chain has `depth` hops and carries only `fake:read_file`.
async fn mint_chain(client: &reqwest::Client, base: &str, depth: usize) -> Result<String> {
    ensure!(
        (1..=MAX_EXCHANGES + 1).contains(&depth),
        "depth must be 1..={}",
        MAX_EXCHANGES + 1
    );
    let root = post_json(
        client,
        &format!("{base}/admin/root-token"),
        Some(ADMIN_TOKEN),
        &json!({
            "subject": "bench-user", "issuer": "https://idp.example", "agent": "bench-root",
            "capabilities": [format!("{UPSTREAM}:read_file")], "ttl_seconds": 3600,
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
            client,
            &format!("{base}/token"),
            None,
            &json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor, "client_id": actor, "client_secret": AGENT_SECRET,
                "requested_ttl_seconds": 3600,
                "authorization_details": [{"type": "onbehalf_capabilities",
                    "capabilities": [{"server": UPSTREAM, "tool": "read_file"}]}],
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

// ---------------------------------------------------------------------------------------
// Load generation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Result,
    RpcError,
}

fn classify(text: &str) -> Option<Expect> {
    let v: Value = serde_json::from_str(text).ok().or_else(|| {
        text.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .find_map(|d| serde_json::from_str(d.trim()).ok())
    })?;
    if v.get("error").is_some() {
        Some(Expect::RpcError)
    } else if v.get("result").is_some() {
        Some(Expect::Result)
    } else {
        None
    }
}

#[derive(Clone)]
struct Target {
    url: String,
    token: Option<String>,
    body: String,
    expect: Expect,
}

struct PhaseOut {
    hist: Histogram<u64>,
    sent: u64,
    unexpected: u64,
    first_bad: Option<String>,
}

async fn client_loop(
    http: reqwest::Client,
    t: Target,
    warm_end: Instant,
    end: Instant,
) -> PhaseOut {
    let mut out = PhaseOut {
        hist: Histogram::new_with_bounds(1, 120_000_000_000, 3).expect("histogram bounds"),
        sent: 0,
        unexpected: 0,
        first_bad: None,
    };
    loop {
        let start = Instant::now();
        if start >= end {
            break;
        }
        let mut req = http
            .post(&t.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(t.body.clone());
        if let Some(tok) = &t.token {
            req = req.bearer_auth(tok);
        }
        let verdict = match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                match resp.text().await {
                    Ok(text) => {
                        if classify(&text) == Some(t.expect) {
                            None
                        } else {
                            Some(format!("HTTP {status}: {text}"))
                        }
                    }
                    Err(e) => Some(format!("body error: {e}")),
                }
            }
            Err(e) => Some(format!("request error: {e}")),
        };
        let elapsed = start.elapsed();
        out.sent += 1;
        if start < warm_end {
            continue;
        }
        match verdict {
            None => {
                let _ = out.hist.record((elapsed.as_nanos() as u64).max(1));
            }
            Some(why) => {
                out.unexpected += 1;
                out.first_bad.get_or_insert(why);
            }
        }
    }
    out
}

/// Run `conc` closed-loop clients; returns the stats and the number of requests sent in total
/// (warm-up included).
async fn drive(
    target: &Target,
    conc: usize,
    warmup: Duration,
    duration: Duration,
) -> Result<(Stats, u64)> {
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(conc)
        .timeout(Duration::from_secs(30))
        .build()?;
    let t0 = Instant::now();
    let warm_end = t0 + warmup;
    let end = warm_end + duration;
    let tasks: Vec<_> = (0..conc)
        .map(|_| tokio::spawn(client_loop(http.clone(), target.clone(), warm_end, end)))
        .collect();
    let mut hist = Histogram::<u64>::new_with_bounds(1, 120_000_000_000, 3)?;
    let (mut sent, mut unexpected, mut first_bad) = (0, 0, None);
    for t in tasks {
        let o = t.await?;
        hist.add(&o.hist)?;
        sent += o.sent;
        unexpected += o.unexpected;
        if first_bad.is_none() {
            first_bad = o.first_bad;
        }
    }
    if let Some(bad) = first_bad {
        eprintln!("  unexpected answer ({unexpected} total), first: {bad}");
    }
    let us = |ns: f64| (ns / 1000.0 * 10.0).round() / 10.0;
    let secs = duration.as_secs_f64();
    let n = hist.len();
    Ok((
        Stats {
            requests: n,
            unexpected,
            seconds: secs,
            rps: (n as f64 / secs * 10.0).round() / 10.0,
            mean_us: us(hist.mean()),
            p50_us: us(hist.value_at_quantile(0.50) as f64),
            p90_us: us(hist.value_at_quantile(0.90) as f64),
            p99_us: us(hist.value_at_quantile(0.99) as f64),
            max_us: us(hist.max() as f64),
        },
        sent,
    ))
}

// ---------------------------------------------------------------------------------------
// Orchestration

struct Endpoints {
    onbehalf: String,
    upstream_mcp: String,
}

async fn run_group(
    opts: &Opts,
    mode_label: &str,
    ep: &Endpoints,
    http: &reqwest::Client,
    report: &mut Report,
) -> Result<()> {
    let warmup = Duration::from_secs_f64(opts.warmup);
    let duration = Duration::from_secs_f64(opts.duration);
    let mut proxied_sent = 0u64;

    // Baseline: the allow call straight at the upstream, once per concurrency.
    let direct_target = Target {
        url: ep.upstream_mcp.clone(),
        token: None,
        body: Outcome::Allow.body(),
        expect: Expect::Result,
    };
    let mut direct: Vec<(usize, Stats)> = Vec::new();
    for &c in &opts.concurrency {
        eprintln!("[{mode_label}] direct, {c} clients");
        let (stats, _) = drive(&direct_target, c, warmup, duration).await?;
        report.direct.push(DirectRow {
            audit_group: mode_label.into(),
            concurrency: c,
            stats: stats.clone(),
        });
        direct.push((c, stats));
    }

    for &depth in &opts.depths {
        let token = mint_chain(http, &ep.onbehalf, depth).await?;
        for &outcome in &opts.outcomes {
            for &c in &opts.concurrency {
                eprintln!(
                    "[{mode_label}] depth {depth} {} , {c} clients",
                    outcome.label()
                );
                let target = Target {
                    url: format!("{}/mcp/{UPSTREAM}", ep.onbehalf),
                    token: Some(token.clone()),
                    body: outcome.body(),
                    expect: if outcome == Outcome::Allow {
                        Expect::Result
                    } else {
                        Expect::RpcError
                    },
                };
                let (stats, sent) = drive(&target, c, warmup, duration).await?;
                proxied_sent += sent;
                let d = &direct.iter().find(|(dc, _)| *dc == c).unwrap().1;
                let added = Added {
                    p50_us: round1(stats.p50_us - d.p50_us),
                    p90_us: round1(stats.p90_us - d.p90_us),
                    p99_us: round1(stats.p99_us - d.p99_us),
                    mean_us: round1(stats.mean_us - d.mean_us),
                };
                report.results.push(ProxyRow {
                    audit: mode_label.into(),
                    depth,
                    outcome: outcome.label(),
                    concurrency: c,
                    stats,
                    added,
                });
            }
        }
    }

    // The chain must verify, and every proxied call must have left an entry.
    let v: Value = http
        .get(format!("{}/admin/audit/verify", ep.onbehalf))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await?
        .json()
        .await
        .context("audit verify")?;
    let check = AuditCheck {
        audit: mode_label.into(),
        ok: v["ok"].as_bool() == Some(true) && v["first_bad_seq"].is_null(),
        entries: v["entries"].as_u64().unwrap_or(0),
        proxied_calls_sent: proxied_sent,
        checkpoints: v["checkpoints"].as_u64().unwrap_or(0),
        unsigned_tail: v["unsigned_tail"].as_u64().unwrap_or(0),
    };
    eprintln!(
        "[{mode_label}] audit verify: ok={} entries={} (proxied calls sent {}), checkpoints={}",
        check.ok, check.entries, check.proxied_calls_sent, check.checkpoints
    );
    let ok = check.ok && check.entries >= check.proxied_calls_sent;
    report.audit_checks.push(check);
    ensure!(
        ok,
        "audit chain did not verify or is missing entries ({v}); proxied calls sent {proxied_sent}"
    );
    Ok(())
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn command_output(cmd: &str, args: &[&str]) -> Option<String> {
    let o = std::process::Command::new(cmd).args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn meta(opts: &Opts) -> Value {
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
        "git_rev": command_output("git", &["rev-parse", "--short", "HEAD"]),
        "rustc": command_output("rustc", &["--version"]),
        "bench_version": env!("CARGO_PKG_VERSION"),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "duration_s": opts.duration,
        "warmup_s": opts.warmup,
        "load": "closed loop, one request in flight per client, loopback, HTTP/1.1 keep-alive",
        "external_servers": opts.onbehalf_url.is_some(),
    })
}

pub fn render_markdown(r: &Report) -> String {
    let mut s = String::new();
    s.push_str("### Direct to the upstream (baseline, allow call)\n\n");
    s.push_str(
        "| clients | req/s | p50 us | p90 us | p99 us | max us |\n|---|---|---|---|---|---|\n",
    );
    for d in &r.direct {
        if d.audit_group != r.direct[0].audit_group {
            continue;
        }
        let x = &d.stats;
        s.push_str(&format!(
            "| {} | {:.0} | {} | {} | {} | {} |\n",
            d.concurrency, x.rps, x.p50_us, x.p90_us, x.p99_us, x.max_us
        ));
    }
    let mut modes: Vec<&str> = Vec::new();
    for row in &r.results {
        if !modes.contains(&row.audit.as_str()) {
            modes.push(&row.audit);
        }
    }
    for m in modes {
        s.push_str(&format!(
            "\n### Through the proxy, audit = {m}\n\n\
             | hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |\n\
             |---|---|---|---|---|---|---|---|---|---|---|\n"
        ));
        for x in r.results.iter().filter(|x| x.audit == m) {
            let t = &x.stats;
            s.push_str(&format!(
                "| {} | {} | {} | {:.0} | {} | {} | {} | {} | {} | {} | {} |\n",
                x.depth,
                x.outcome,
                x.concurrency,
                t.rps,
                t.p50_us,
                t.p90_us,
                t.p99_us,
                t.max_us,
                x.added.p50_us,
                x.added.p99_us,
                x.added.mean_us
            ));
        }
    }
    s.push_str("\n### Audit chain after each run\n\n| audit | verified | entries | proxied calls sent | checkpoints |\n|---|---|---|---|---|\n");
    for a in &r.audit_checks {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            a.audit, a.ok, a.entries, a.proxied_calls_sent, a.checkpoints
        ));
    }
    s
}

fn default_bin_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let mut dir = exe
        .parent()
        .ok_or_else(|| anyhow!("no exe dir"))?
        .to_path_buf();
    if dir.file_name().is_some_and(|n| n == "deps") {
        dir.pop();
    }
    Ok(dir)
}

/// Run the whole benchmark as configured by `opts`.
pub async fn run(opts: Opts) -> Result<()> {
    ensure!(opts.duration > 0.0, "--duration must be positive");
    ensure!(
        !opts.concurrency.contains(&0),
        "--concurrency values must be at least 1"
    );

    if let Some(dir) = &opts.print_config {
        std::fs::create_dir_all(dir)?;
        let policy = dir.join("policy.cedar");
        std::fs::write(&policy, POLICY)?;
        let sqlite = match opts.audit.first().copied().unwrap_or(AuditMode::Memory) {
            AuditMode::Memory => ":memory:".to_string(),
            AuditMode::File => dir.join("audit.db").display().to_string(),
        };
        let cfg = render_config(opts.onbehalf_port, opts.upstream_port, &policy, &sqlite);
        std::fs::write(dir.join("config.toml"), cfg)?;
        eprintln!("wrote {}/config.toml and policy.cedar", dir.display());
        return Ok(());
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut report = Report {
        meta: meta(&opts),
        direct: Vec::new(),
        results: Vec::new(),
        audit_checks: Vec::new(),
    };

    if let (Some(ob), Some(up)) = (&opts.onbehalf_url, &opts.upstream_url) {
        let ep = Endpoints {
            onbehalf: ob.trim_end_matches('/').to_string(),
            upstream_mcp: format!("{}/mcp", up.trim_end_matches('/')),
        };
        wait_http(&http, &format!("{}/healthz", ep.onbehalf)).await?;
        let label = opts.audit.first().map_or("external", |m| match m {
            AuditMode::Memory => "memory",
            AuditMode::File => "file",
        });
        run_group(&opts, label, &ep, &http, &mut report).await?;
    } else {
        let bin_dir = match &opts.bin_dir {
            Some(d) => d.clone(),
            None => default_bin_dir()?,
        };
        let work = WorkDir::new()?;
        // Copy the binaries: a shared target dir may be rebuilt by another checkout mid-run.
        let server_bin = work.0.join("onbehalf-server");
        let fake_bin = work.0.join("fake_mcp");
        std::fs::copy(find_bin(&bin_dir, "onbehalf-server")?, &server_bin)?;
        std::fs::copy(find_bin(&bin_dir, "fake_mcp")?, &fake_bin)?;
        let policy = work.0.join("policy.cedar");
        std::fs::write(&policy, POLICY)?;

        let mut seen = Vec::new();
        for &mode in &opts.audit {
            if seen.contains(&mode) {
                continue;
            }
            seen.push(mode);
            let (label, sqlite) = match mode {
                AuditMode::Memory => ("memory", ":memory:".to_string()),
                AuditMode::File => (
                    "file",
                    work.0
                        .join(format!("audit-{}.db", seen.len()))
                        .display()
                        .to_string(),
                ),
            };
            let (ob_port, up_port) = (free_port()?, free_port()?);
            let cfg_path = work.0.join(format!("config-{label}.toml"));
            std::fs::write(&cfg_path, render_config(ob_port, up_port, &policy, &sqlite))?;

            let _fake = Proc {
                child: Command::new(&fake_bin)
                    .args(["--port", &up_port.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                    .context("start fake_mcp")?,
            };
            let log = std::fs::File::create(work.0.join(format!("server-{label}.log")))?;
            let _server = Proc {
                child: Command::new(&server_bin)
                    .arg("--config")
                    .arg(&cfg_path)
                    .env("RUST_LOG", "warn")
                    .stdout(Stdio::null())
                    .stderr(log)
                    .kill_on_drop(true)
                    .spawn()
                    .context("start onbehalf-server")?,
            };
            wait_tcp(up_port).await?;
            let ep = Endpoints {
                onbehalf: format!("http://127.0.0.1:{ob_port}"),
                upstream_mcp: format!("http://127.0.0.1:{up_port}/mcp"),
            };
            if let Err(e) = wait_http(&http, &format!("{}/healthz", ep.onbehalf)).await {
                let log = std::fs::read_to_string(work.0.join(format!("server-{label}.log")))
                    .unwrap_or_default();
                bail!("{e}; server log:\n{log}");
            }
            run_group(&opts, label, &ep, &http, &mut report).await?;
        }
    }

    let unexpected: u64 = report
        .results
        .iter()
        .map(|r| r.stats.unexpected)
        .chain(report.direct.iter().map(|d| d.stats.unexpected))
        .sum();
    let md = render_markdown(&report);
    println!("{md}");
    if let Some(p) = &opts.markdown {
        std::fs::write(p, &md)?;
    }
    if let Some(p) = &opts.json {
        std::fs::write(p, serde_json::to_string_pretty(&report)?)?;
    }
    ensure!(
        unexpected == 0,
        "{unexpected} responses were not what the scenario expects (allow answered with an \
         error, or a deny answered with a result); the figures are not trustworthy"
    );
    Ok(())
}
