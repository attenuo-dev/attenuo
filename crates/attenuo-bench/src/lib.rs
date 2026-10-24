//! End-to-end benchmark for attenuo.
//!
//! Starts `attenuo-server` and the `fake_mcp` example (or is pointed at running ones), mints
//! a root token through the development endpoint, exchanges it down to a chain of the
//! requested depth, and drives `tools/call` with N closed-loop clients for a fixed time:
//! once through the proxy and once straight at `fake_mcp` as the baseline. The added latency
//! is the proxy figure minus the direct one at the same concurrency. At the end it asks the
//! server to verify the audit chain and fails if the chain is broken or short of entries.
//!
//! Every answer is checked against the scenario: an allow must be a JSON-RPC `result` that
//! carries an `X-Attenuo-Decision-Id`, and a denial must be the proxy's own `-32003` with the
//! expected reason code (`policy_deny`, `capability_denied`) and a `data.decision_id` listed in
//! that header, the rule the SDKs use. Anything else (an `audit_error` denial, `-32007`
//! `too_many_sessions`, a `5xx`) stops the run after that cell.
//!
//! The server it starts serves `/metrics` on its own port; the harness reads the
//! `attenuo_proxy_stage_seconds` histograms before and after each measured window and reports
//! the time per stage (token verification, lease check, policy, audit append, blocking-pool
//! hop, upstream round trip, response handling, total).
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

pub mod exchange;
pub mod hotpath;

const ADMIN_TOKEN: &str = "bench-admin-token";
/// `printf %s bench-secret | sha256sum`; every bench agent uses this secret.
const AGENT_SECRET: &str = "bench-secret";
const AGENT_SECRET_SHA256: &str =
    "0159438a9235d6abde38e49fb98944660d067d6b9b03d8a8f4ee4e522feb62cb";
const UPSTREAM: &str = "fake";
const MAX_EXCHANGES: usize = 7;

const POLICY: &str = r#"// Policy used by attenuo-bench: the leak-demo policy with the server name `fake`.
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
    /// A SQLite file in the work directory, `[audit] durability = "normal"` (the default).
    File,
    /// A SQLite file in the work directory, `[audit] durability = "full"` (sync every commit).
    FileFull,
}

impl AuditMode {
    fn label(self) -> &'static str {
        match self {
            AuditMode::Memory => "memory",
            AuditMode::File => "file",
            AuditMode::FileFull => "file_full",
        }
    }

    /// `[audit] sqlite_path` and `durability` for this mode, with files under `dir`.
    fn settings(self, dir: &Path) -> (String, &'static str) {
        match self {
            AuditMode::Memory => (":memory:".to_string(), "normal"),
            AuditMode::File => (dir.join("audit-normal.db").display().to_string(), "normal"),
            AuditMode::FileFull => (dir.join("audit-full.db").display().to_string(), "full"),
        }
    }
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

/// Reason code of a Cedar denial (`attenuo_policy::REASON_POLICY_DENY`).
pub const REASON_POLICY_DENY: &str = "policy_deny";
/// Reason code of a capability-stage denial (`attenuo_policy::REASON_CAPABILITY_DENIED`).
pub const REASON_CAPABILITY_DENIED: &str = "capability_denied";

impl Outcome {
    /// The answer a call of this outcome must get through the proxy.
    pub fn expect(self) -> Expect {
        match self {
            Outcome::Allow => Expect::Result {
                decision_header: true,
            },
            Outcome::DenyPolicy => Expect::Denied(REASON_POLICY_DENY),
            Outcome::DenyCapability => Expect::Denied(REASON_CAPABILITY_DENIED),
        }
    }

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
    name = "attenuo-bench",
    version,
    about = "End-to-end latency and throughput benchmark for attenuo"
)]
pub struct Opts {
    /// Directory holding the `attenuo-server` and `fake_mcp` binaries (also looked up under
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
    /// Audit store: `memory` (`:memory:`), `file` (SQLite on disk, `durability = "normal"`) or
    /// `file_full` (SQLite on disk, `durability = "full"`). One server per mode.
    #[arg(long, value_delimiter = ',', value_enum, default_values_t = [AuditMode::Memory, AuditMode::File, AuditMode::FileFull])]
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
    /// Use an already running attenuo server (requires `--upstream-url`). Configure it with
    /// the files `--print-config` writes. Only one `--audit` mode is then run, as a label.
    #[arg(long, requires = "upstream_url")]
    pub attenuo_url: Option<String>,
    /// Use an already running fake_mcp, base URL without `/mcp` (requires `--attenuo-url`).
    #[arg(long, requires = "attenuo_url")]
    pub upstream_url: Option<String>,
    /// Write `config.toml` and `policy.cedar` for an external server into this directory and
    /// exit. Needs `--attenuo-port` and `--upstream-port`; honours the first `--audit` mode.
    #[arg(long)]
    pub print_config: Option<PathBuf>,
    #[arg(long, default_value_t = 18080)]
    pub attenuo_port: u16,
    #[arg(long, default_value_t = 13001)]
    pub upstream_port: u16,
    /// Port of the `/metrics` listener in the config `--print-config` writes.
    #[arg(long, default_value_t = 19100)]
    pub metrics_port: u16,
    /// With `--attenuo-url`: the running server's metrics base URL (for example
    /// `http://127.0.0.1:19100`), to report per-stage times. Without it no stage table is made.
    #[arg(long, requires = "attenuo_url")]
    pub metrics_url: Option<String>,
    /// Open loop: drive the proxied call (and the direct baseline) with Poisson arrivals at
    /// these rates in requests per second, instead of closed-loop clients. See
    /// [`exchange::run_call_open`]. `--audit`, `--depths`, `--outcomes`, `--duration` and
    /// `--warmup` apply; the cells use their own servers.
    #[arg(long, value_delimiter = ',')]
    pub open_loop: Vec<f64>,
    #[command(subcommand)]
    pub command: Option<exchange::Command>,
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
    pub p95_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
    /// Requests that took longer than 3, 5 and 10 ms (the single-client outliers).
    pub over_3ms: u64,
    pub over_5ms: u64,
    pub over_10ms: u64,
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

/// Time in one stage over one measured window, from the server's
/// `attenuo_proxy_stage_seconds` histogram (difference of two scrapes). The quantiles are
/// interpolated inside the histogram's buckets, the way Prometheus' `histogram_quantile` does,
/// so they are estimates; the mean is exact.
#[derive(Debug, Clone, Serialize)]
pub struct StageRow {
    pub audit: String,
    pub depth: usize,
    pub outcome: &'static str,
    pub concurrency: usize,
    pub stage: String,
    pub count: u64,
    pub mean_us: f64,
    pub p50_us: f64,
    pub p90_us: f64,
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
    pub stages: Vec<StageRow>,
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
        "{name} not found in {} (build it: cargo build --release -p attenuo-server \
         -p attenuo-proxy --features attenuo-proxy/testing --example fake_mcp)",
        dir.display()
    )
}

struct WorkDir(PathBuf);
impl WorkDir {
    fn new() -> Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "attenuo-bench-{}-{}",
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

/// The server config the bench needs. `sqlite` and `durability` are the `[audit]`
/// `sqlite_path` and `durability` values.
pub fn render_config(
    attenuo_port: u16,
    upstream_port: u16,
    policy_path: &Path,
    sqlite: &str,
    durability: &str,
    metrics_port: u16,
) -> String {
    let mut s = format!(
        r#"# attenuo-server config written by attenuo-bench.
[server]
listen = "127.0.0.1:{attenuo_port}"

[issuer]
issuer = "http://127.0.0.1:{attenuo_port}"
audience = "attenuo"
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
durability = "{durability}"

[metrics]
enabled = true
listen = "127.0.0.1:{metrics_port}"

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

/// How long a server or upstream gets to come up. Generous because the smoke tests start
/// several debug-build servers at once, and a loaded CI runner (macOS most of all) can take
/// well over ten seconds to get one listening.
const START_BUDGET: Duration = Duration::from_secs(60);
const START_POLL: Duration = Duration::from_millis(50);

async fn wait_http(client: &reqwest::Client, url: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + START_BUDGET;
    while tokio::time::Instant::now() < deadline {
        if let Ok(r) = client.get(url).send().await {
            if r.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(START_POLL).await;
    }
    bail!("{url} did not come up within {START_BUDGET:?}")
}

async fn wait_tcp(port: u16) -> Result<()> {
    let deadline = tokio::time::Instant::now() + START_BUDGET;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(START_POLL).await;
    }
    bail!("port {port} did not open within {START_BUDGET:?}")
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
                "authorization_details": [{"type": "attenuo_capabilities",
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

/// The proxy's JSON-RPC error code for a denied call (`attenuo_proxy::jsonrpc::CODE_DENIED`).
pub const CODE_DENIED: i64 = -32003;
/// Response header listing the proxy's decision ids (`attenuo_proxy::DECISION_ID_HEADER`).
pub const DECISION_ID_HEADER: &str = "x-attenuo-decision-id";

/// What a correct answer looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A JSON-RPC `result`; through the proxy it must also carry a decision id header.
    Result { decision_header: bool },
    /// The proxy's own denial (`-32003`) with this reason code.
    Denied(&'static str),
}

/// The JSON-RPC response in a JSON or `text/event-stream` body.
fn rpc_message(text: &str) -> Option<Value> {
    serde_json::from_str(text).ok().or_else(|| {
        text.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .find_map(|d| serde_json::from_str(d.trim()).ok())
    })
}

/// Check one answer against `expect`. `Err` says what was wrong, for the run's failure message.
///
/// A denial counts only when it is the expected reason and the proxy vouches for it: the
/// `-32003` error's `data.decision_id` is one of the ids in `X-Attenuo-Decision-Id`, as the
/// SDKs require (an upstream can put any `-32003` in its own body). So an `audit_error` denial,
/// a `-32007` `too_many_sessions`, a `-32001` or any non-200 status is a failure, not a denial.
pub fn check_answer(
    expect: Expect,
    status: u16,
    decision_header: Option<&str>,
    text: &str,
) -> std::result::Result<(), String> {
    let short = |t: &str| t.chars().take(300).collect::<String>();
    if status != 200 {
        return Err(format!("HTTP {status}: {}", short(text)));
    }
    let Some(msg) = rpc_message(text) else {
        return Err(format!("no JSON-RPC response in body: {}", short(text)));
    };
    let header_ids: Vec<&str> = decision_header
        .map(|h| {
            h.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let err = msg.get("error");
    match expect {
        Expect::Result { decision_header } => {
            if err.is_some() || msg.get("result").is_none() {
                return Err(format!(
                    "expected a result, got {}",
                    short(&msg.to_string())
                ));
            }
            if decision_header && header_ids.is_empty() {
                return Err(format!("result without {DECISION_ID_HEADER}"));
            }
            Ok(())
        }
        Expect::Denied(want) => {
            let Some(err) = err else {
                return Err(format!(
                    "expected denial `{want}`, got {}",
                    short(&msg.to_string())
                ));
            };
            let code = err.get("code").and_then(Value::as_i64);
            let reason = err
                .pointer("/data/reason")
                .and_then(Value::as_str)
                .unwrap_or("");
            if code != Some(CODE_DENIED) || reason != want {
                return Err(format!(
                    "expected denial `{want}` (code {CODE_DENIED}), got code {} reason `{reason}`: {}",
                    code.map_or_else(|| "none".to_string(), |c| c.to_string()),
                    short(&err.to_string())
                ));
            }
            let id = err.pointer("/data/decision_id").and_then(Value::as_str);
            match id {
                Some(id) if header_ids.contains(&id) => Ok(()),
                _ => Err(format!(
                    "denial `{want}` whose decision id {id:?} is not in {DECISION_ID_HEADER} \
                     ({decision_header:?})"
                )),
            }
        }
    }
}

/// In a request body, replaced on every request by a number no other request of this process
/// has had ([`fill_seq`]), so a cell can send a new argument value on every call.
const SEQ_MARKER: &str = "@SEQ@";

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `body` with every [`SEQ_MARKER`] replaced by the next number of the process-wide sequence
/// (one number per call, the same in every marker of one body).
fn fill_seq(body: &str) -> String {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    body.replace(SEQ_MARKER, &n.to_string())
}

#[derive(Clone)]
struct Target {
    url: String,
    token: Option<String>,
    /// When set, every call sends the next token of this list in place of `token`, each
    /// client starting at its own offset, so tokens are not reused call after call (to make
    /// every call a verified-token cache miss, as `hot-path --rotate-tokens` does).
    rotate: Option<std::sync::Arc<[String]>>,
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
    client: usize,
    clients: usize,
    warm_end: Instant,
    end: Instant,
) -> PhaseOut {
    let mut out = PhaseOut {
        hist: Histogram::new_with_bounds(1, 120_000_000_000, 3).expect("histogram bounds"),
        sent: 0,
        unexpected: 0,
        first_bad: None,
    };
    let vary = t.body.contains(SEQ_MARKER);
    let mut next = t
        .rotate
        .as_ref()
        .map_or(0, |r| client * r.len() / clients.max(1));
    loop {
        let start = Instant::now();
        if start >= end {
            break;
        }
        let body = if vary {
            fill_seq(&t.body)
        } else {
            t.body.clone()
        };
        let mut req = http
            .post(&t.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body);
        if let Some(list) = &t.rotate {
            req = req.bearer_auth(&list[next % list.len()]);
            next += 1;
        } else if let Some(tok) = &t.token {
            req = req.bearer_auth(tok);
        }
        let verdict = match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let header = resp
                    .headers()
                    .get(DECISION_ID_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                match resp.text().await {
                    Ok(text) => check_answer(t.expect, status, header.as_deref(), &text).err(),
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

/// What one cell produced.
struct DriveOut {
    stats: Stats,
    /// Requests sent in total, warm-up included.
    sent: u64,
    /// The first answer that was not what the scenario expects.
    first_bad: Option<String>,
    /// Stage histograms over the measured window, when a metrics URL was given.
    stages: Option<Vec<(String, StageHist)>>,
    /// The two `/metrics` scrapes the stage histograms came from (warm-up end, clients done),
    /// for figures other than the stage histogram.
    metrics_raw: Option<(String, String)>,
}

/// Run `conc` closed-loop clients, client `i` on `targets[i % targets.len()]` (one target for
/// all of them, or one each, such as a token per client). With `metrics` (the server's
/// `/metrics` URL), scrape the stage histograms when the warm-up ends and when the clients
/// stop.
async fn drive(
    targets: &[Target],
    conc: usize,
    warmup: Duration,
    duration: Duration,
    metrics: Option<(&reqwest::Client, &str)>,
) -> Result<DriveOut> {
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(conc)
        .timeout(Duration::from_secs(30))
        .build()?;
    let t0 = Instant::now();
    let warm_end = t0 + warmup;
    let end = warm_end + duration;
    ensure!(!targets.is_empty(), "no target to drive");
    let tasks: Vec<_> = (0..conc)
        .map(|i| {
            let t = targets[i % targets.len()].clone();
            tokio::spawn(client_loop(http.clone(), t, i, conc, warm_end, end))
        })
        .collect();
    let before = match metrics {
        Some((client, url)) => {
            tokio::time::sleep_until(tokio::time::Instant::from_std(warm_end)).await;
            Some(scrape_metrics(client, url).await?)
        }
        None => None,
    };
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
    if let Some(bad) = &first_bad {
        eprintln!("  unexpected answer ({unexpected} total), first: {bad}");
    }
    let (stages, metrics_raw) = match (metrics, before) {
        (Some((client, url)), Some(before)) => {
            let after = scrape_metrics(client, url).await?;
            let d = stage_delta(&parse_stages(&before), &parse_stages(&after));
            (Some(d), Some((before, after)))
        }
        _ => (None, None),
    };
    let us = |ns: f64| (ns / 1000.0 * 10.0).round() / 10.0;
    let secs = duration.as_secs_f64();
    let n = hist.len();
    Ok(DriveOut {
        stats: Stats {
            requests: n,
            unexpected,
            seconds: secs,
            rps: (n as f64 / secs * 10.0).round() / 10.0,
            mean_us: us(hist.mean()),
            p50_us: us(hist.value_at_quantile(0.50) as f64),
            p90_us: us(hist.value_at_quantile(0.90) as f64),
            p95_us: us(hist.value_at_quantile(0.95) as f64),
            p99_us: us(hist.value_at_quantile(0.99) as f64),
            max_us: us(hist.max() as f64),
            over_3ms: over_ns(&hist, 3_000_000),
            over_5ms: over_ns(&hist, 5_000_000),
            over_10ms: over_ns(&hist, 10_000_000),
        },
        sent,
        first_bad,
        stages,
        metrics_raw,
    })
}

/// Stop the run when a cell had answers that were not what it expects: the figures would mix
/// in failures (an `audit_error` denial is cheap and fast) and mean nothing.
fn ensure_expected(cell: &str, out: &DriveOut) -> Result<()> {
    ensure!(
        out.stats.unexpected == 0,
        "{cell}: {} answers were not what the scenario expects; first: {}",
        out.stats.unexpected,
        out.first_bad.as_deref().unwrap_or("?")
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Stage metrics

const STAGE_METRIC: &str = "attenuo_proxy_stage_seconds";

/// Samples in `h` (nanoseconds) above `ns`.
pub fn over_ns(h: &Histogram<u64>, ns: u64) -> u64 {
    if h.max() <= ns {
        return 0;
    }
    h.count_between(ns + 1, h.max())
}

/// One stage's histogram as scraped: cumulative bucket counts by upper bound (the last is
/// `+Inf`), sum in seconds, and count.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StageHist {
    pub buckets: Vec<(f64, u64)>,
    pub sum: f64,
    pub count: u64,
}

impl StageHist {
    /// Samples above `bound` seconds, when `bound` is one of the bucket bounds (`None`
    /// otherwise: the histogram cannot tell).
    pub fn over(&self, bound: f64) -> Option<u64> {
        let (_, cum) = self
            .buckets
            .iter()
            .find(|(b, _)| (b - bound).abs() <= bound * 1e-9)?;
        Some(self.count.saturating_sub(*cum))
    }

    /// Quantile `q` in seconds, interpolated linearly inside the bucket it falls in (lower
    /// bound of the first bucket 0), as Prometheus' `histogram_quantile`. `None` when empty.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        let rank = q * self.count as f64;
        let mut prev = (0.0, 0u64);
        for &(bound, cum) in &self.buckets {
            if cum as f64 >= rank {
                if bound.is_infinite() {
                    return Some(prev.0);
                }
                let in_bucket = (cum - prev.1) as f64;
                let frac = if in_bucket > 0.0 {
                    (rank - prev.1 as f64) / in_bucket
                } else {
                    0.0
                };
                return Some(prev.0 + (bound - prev.0) * frac);
            }
            prev = (bound, cum);
        }
        Some(prev.0)
    }
}

/// Parse the `attenuo_proxy_stage_seconds` samples of a Prometheus text exposition, stages in
/// the order they appear.
pub fn parse_stages(text: &str) -> Vec<(String, StageHist)> {
    let mut out: Vec<(String, StageHist)> = Vec::new();
    let label = |s: &str, key: &str| -> Option<String> {
        let start = s.find(&format!("{key}=\""))? + key.len() + 2;
        let end = s[start..].find('"')?;
        Some(s[start..start + end].to_string())
    };
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(STAGE_METRIC) else {
            continue;
        };
        let Some((name_labels, value)) = rest.rsplit_once(' ') else {
            continue;
        };
        let Some(stage) = label(name_labels, "stage") else {
            continue;
        };
        let idx = match out.iter().position(|(s, _)| *s == stage) {
            Some(i) => i,
            None => {
                out.push((stage, StageHist::default()));
                out.len() - 1
            }
        };
        let h = &mut out[idx].1;
        if name_labels.starts_with("_bucket{") {
            let Some(le) = label(name_labels, "le") else {
                continue;
            };
            let bound = if le == "+Inf" {
                f64::INFINITY
            } else {
                le.parse().unwrap_or(f64::NAN)
            };
            h.buckets.push((bound, value.parse().unwrap_or(0)));
        } else if name_labels.starts_with("_sum{") {
            h.sum = value.parse().unwrap_or(0.0);
        } else if name_labels.starts_with("_count{") {
            h.count = value.parse().unwrap_or(0);
        }
    }
    out
}

/// `after - before`, stage by stage.
pub fn stage_delta(
    before: &[(String, StageHist)],
    after: &[(String, StageHist)],
) -> Vec<(String, StageHist)> {
    after
        .iter()
        .map(|(stage, a)| {
            let b = before.iter().find(|(s, _)| s == stage).map(|(_, h)| h);
            let d = match b {
                None => a.clone(),
                Some(b) => StageHist {
                    buckets: a
                        .buckets
                        .iter()
                        .map(|&(bound, n)| {
                            let prev = b
                                .buckets
                                .iter()
                                .find(|(bb, _)| *bb == bound)
                                .map_or(0, |(_, m)| *m);
                            (bound, n.saturating_sub(prev))
                        })
                        .collect(),
                    sum: (a.sum - b.sum).max(0.0),
                    count: a.count.saturating_sub(b.count),
                },
            };
            (stage.clone(), d)
        })
        .collect()
}

/// The server's `/metrics` text, checked to hold the stage histograms.
async fn scrape_metrics(client: &reqwest::Client, url: &str) -> Result<String> {
    let text = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()?
        .text()
        .await?;
    ensure!(
        !parse_stages(&text).is_empty(),
        "{url} has no {STAGE_METRIC} samples (server too old?)"
    );
    Ok(text)
}

// ---------------------------------------------------------------------------------------
// Orchestration

struct Endpoints {
    attenuo: String,
    upstream_mcp: String,
    /// The server's `/metrics` URL, if it serves one.
    metrics: Option<String>,
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
        rotate: None,
        body: Outcome::Allow.body(),
        expect: Expect::Result {
            decision_header: false,
        },
    };
    let mut direct: Vec<(usize, Stats)> = Vec::new();
    for &c in &opts.concurrency {
        eprintln!("[{mode_label}] direct, {c} clients");
        let out = drive(
            std::slice::from_ref(&direct_target),
            c,
            warmup,
            duration,
            None,
        )
        .await?;
        ensure_expected(&format!("[{mode_label}] direct, {c} clients"), &out)?;
        let stats = out.stats;
        report.direct.push(DirectRow {
            audit_group: mode_label.into(),
            concurrency: c,
            stats: stats.clone(),
        });
        direct.push((c, stats));
    }

    for &depth in &opts.depths {
        let token = mint_chain(http, &ep.attenuo, depth).await?;
        for &outcome in &opts.outcomes {
            for &c in &opts.concurrency {
                eprintln!(
                    "[{mode_label}] depth {depth} {} , {c} clients",
                    outcome.label()
                );
                let target = Target {
                    url: format!("{}/mcp/{UPSTREAM}", ep.attenuo),
                    token: Some(token.clone()),
                    rotate: None,
                    body: outcome.body(),
                    expect: outcome.expect(),
                };
                let probe = ep.metrics.as_deref().map(|u| (http, u));
                let out = drive(std::slice::from_ref(&target), c, warmup, duration, probe).await?;
                proxied_sent += out.sent;
                ensure_expected(
                    &format!(
                        "[{mode_label}] depth {depth} {}, {c} clients",
                        outcome.label()
                    ),
                    &out,
                )?;
                for (stage, h) in out.stages.unwrap_or_default() {
                    if h.count == 0 {
                        continue;
                    }
                    let us = |s: Option<f64>| round1(s.unwrap_or(0.0) * 1e6);
                    report.stages.push(StageRow {
                        audit: mode_label.into(),
                        depth,
                        outcome: outcome.label(),
                        concurrency: c,
                        mean_us: us(Some(h.sum / h.count as f64)),
                        p50_us: us(h.quantile(0.5)),
                        p90_us: us(h.quantile(0.9)),
                        count: h.count,
                        stage,
                    });
                }
                let stats = out.stats;
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
        .get(format!("{}/admin/audit/verify", ep.attenuo))
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
        "external_servers": opts.attenuo_url.is_some(),
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
    let mut stage_modes: Vec<&str> = Vec::new();
    for row in &r.stages {
        if !stage_modes.contains(&row.audit.as_str()) {
            stage_modes.push(&row.audit);
        }
    }
    for m in stage_modes {
        s.push_str(&format!(
            "\n### Time by stage through the proxy, audit = {m}\n\n\
             From the server's `attenuo_proxy_stage_seconds` over each measured window. \
             p50 and p90 are interpolated inside histogram buckets (estimates); the mean is \
             exact.\n\n\
             | hops | outcome | clients | stage | count | mean us | p50 us | p90 us |\n\
             |---|---|---|---|---|---|---|---|\n"
        ));
        for x in r.stages.iter().filter(|x| x.audit == m) {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                x.depth, x.outcome, x.concurrency, x.stage, x.count, x.mean_us, x.p50_us, x.p90_us
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
    if let Some(cmd) = &opts.command {
        return exchange::run_command(cmd).await;
    }
    if !opts.open_loop.is_empty() {
        return exchange::run_call_open(&opts).await;
    }
    ensure!(opts.duration > 0.0, "--duration must be positive");
    ensure!(
        !opts.concurrency.contains(&0),
        "--concurrency values must be at least 1"
    );

    if let Some(dir) = &opts.print_config {
        std::fs::create_dir_all(dir)?;
        let policy = dir.join("policy.cedar");
        std::fs::write(&policy, POLICY)?;
        let mode = opts.audit.first().copied().unwrap_or(AuditMode::Memory);
        let (sqlite, durability) = mode.settings(dir);
        let cfg = render_config(
            opts.attenuo_port,
            opts.upstream_port,
            &policy,
            &sqlite,
            durability,
            opts.metrics_port,
        );
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
        stages: Vec::new(),
        audit_checks: Vec::new(),
    };

    if let (Some(ob), Some(up)) = (&opts.attenuo_url, &opts.upstream_url) {
        let ep = Endpoints {
            attenuo: ob.trim_end_matches('/').to_string(),
            upstream_mcp: format!("{}/mcp", up.trim_end_matches('/')),
            metrics: opts
                .metrics_url
                .as_ref()
                .map(|m| format!("{}/metrics", m.trim_end_matches('/'))),
        };
        wait_http(&http, &format!("{}/healthz", ep.attenuo)).await?;
        let label = opts.audit.first().map_or("external", |m| m.label());
        run_group(&opts, label, &ep, &http, &mut report).await?;
    } else {
        let bin_dir = match &opts.bin_dir {
            Some(d) => d.clone(),
            None => default_bin_dir()?,
        };
        let work = WorkDir::new()?;
        // Copy the binaries: a shared target dir may be rebuilt by another checkout mid-run.
        let server_bin = work.0.join("attenuo-server");
        let fake_bin = work.0.join("fake_mcp");
        std::fs::copy(find_bin(&bin_dir, "attenuo-server")?, &server_bin)?;
        std::fs::copy(find_bin(&bin_dir, "fake_mcp")?, &fake_bin)?;
        let policy = work.0.join("policy.cedar");
        std::fs::write(&policy, POLICY)?;

        let mut seen = Vec::new();
        for &mode in &opts.audit {
            if seen.contains(&mode) {
                continue;
            }
            seen.push(mode);
            let label = mode.label();
            let (sqlite, durability) = mode.settings(&work.0);
            let (ob_port, up_port, metrics_port) = (free_port()?, free_port()?, free_port()?);
            let cfg_path = work.0.join(format!("config-{label}.toml"));
            std::fs::write(
                &cfg_path,
                render_config(ob_port, up_port, &policy, &sqlite, durability, metrics_port),
            )?;

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
                    .context("start attenuo-server")?,
            };
            wait_tcp(up_port).await?;
            let ep = Endpoints {
                attenuo: format!("http://127.0.0.1:{ob_port}"),
                upstream_mcp: format!("http://127.0.0.1:{up_port}/mcp"),
                metrics: Some(format!("http://127.0.0.1:{metrics_port}/metrics")),
            };
            if let Err(e) = wait_http(&http, &format!("{}/healthz", ep.attenuo)).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b8f3d1e-3c55-4b47-9a43-0d6c3f0f7a10";

    fn denial(code: i64, reason: &str) -> String {
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code,
            "message": format!("attenuo: denied: {reason}"),
            "data": {"reason": reason, "decision_id": ID}}})
        .to_string()
    }

    #[test]
    fn fill_seq_gives_each_body_a_new_number() {
        // Both markers of one body get the same number; the next body gets another.
        let a = fill_seq("r@SEQ@ h@SEQ@");
        let (r, h) = a.split_once(' ').unwrap();
        assert_eq!(
            r[1..].parse::<u64>().unwrap(),
            h[1..].parse::<u64>().unwrap()
        );
        assert_ne!(fill_seq("@SEQ@"), fill_seq("@SEQ@"));
        assert_eq!(fill_seq("no marker"), "no marker");
    }

    #[test]
    fn only_the_expected_vouched_denial_counts() {
        let policy = Outcome::DenyPolicy.expect();
        let cap = Outcome::DenyCapability.expect();
        // The expected denial, with its id in the header (alone or among others).
        assert_eq!(
            check_answer(policy, 200, Some(ID), &denial(-32003, "policy_deny")),
            Ok(())
        );
        let several = format!("11111111-1111-1111-1111-111111111111, {ID}");
        assert_eq!(
            check_answer(
                cap,
                200,
                Some(&several),
                &denial(-32003, "capability_denied")
            ),
            Ok(())
        );
        // A denial for another reason is a failure, `audit_error` above all.
        let e = check_answer(policy, 200, Some(ID), &denial(-32003, "audit_error")).unwrap_err();
        assert!(e.contains("audit_error"), "{e}");
        assert!(check_answer(cap, 200, Some(ID), &denial(-32003, "policy_deny")).is_err());
        // Other error codes: too_many_sessions (-32007), unauthorized (-32001).
        let e =
            check_answer(policy, 200, Some(ID), &denial(-32007, "too_many_sessions")).unwrap_err();
        assert!(
            e.contains("-32007") && e.contains("too_many_sessions"),
            "{e}"
        );
        assert!(check_answer(policy, 200, Some(ID), &denial(-32001, "lease_revoked")).is_err());
        // A 5xx is never a denial, even with a denial-shaped body.
        let e = check_answer(policy, 503, Some(ID), &denial(-32003, "policy_deny")).unwrap_err();
        assert!(e.starts_with("HTTP 503"), "{e}");
        assert!(check_answer(policy, 502, None, "bad gateway").is_err());
        // A -32003 the proxy does not vouch for (an upstream's own) is not a denial.
        assert!(check_answer(policy, 200, None, &denial(-32003, "policy_deny")).is_err());
        let other = "22222222-2222-2222-2222-222222222222";
        assert!(check_answer(policy, 200, Some(other), &denial(-32003, "policy_deny")).is_err());
        // A result where a denial was expected.
        let ok = json!({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}).to_string();
        assert!(check_answer(policy, 200, Some(ID), &ok).is_err());
    }

    #[test]
    fn allow_needs_a_result_and_through_the_proxy_a_decision_id() {
        let ok = json!({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}).to_string();
        let allow = Outcome::Allow.expect();
        assert_eq!(check_answer(allow, 200, Some(ID), &ok), Ok(()));
        assert!(check_answer(allow, 200, None, &ok).is_err());
        let direct = Expect::Result {
            decision_header: false,
        };
        assert_eq!(check_answer(direct, 200, None, &ok), Ok(()));
        // As an SSE event.
        let sse = format!("event: message\ndata: {ok}\n\n");
        assert_eq!(check_answer(allow, 200, Some(ID), &sse), Ok(()));
        assert!(check_answer(allow, 200, Some(ID), &denial(-32003, "audit_error")).is_err());
        assert!(check_answer(allow, 500, Some(ID), &ok).is_err());
    }

    #[test]
    fn stage_histograms_parse_diff_and_interpolate() {
        let render = |policy: [u64; 3], sum: f64| {
            format!(
                "# TYPE attenuo_proxy_stage_seconds histogram\n\
                 attenuo_proxy_stage_seconds_bucket{{stage=\"policy\",le=\"0.00001\"}} {}\n\
                 attenuo_proxy_stage_seconds_bucket{{stage=\"policy\",le=\"0.00002\"}} {}\n\
                 attenuo_proxy_stage_seconds_bucket{{stage=\"policy\",le=\"+Inf\"}} {}\n\
                 attenuo_proxy_stage_seconds_sum{{stage=\"policy\"}} {sum}\n\
                 attenuo_proxy_stage_seconds_count{{stage=\"policy\"}} {}\n\
                 attenuo_proxy_stage_seconds_bucket{{stage=\"upstream\",le=\"0.00001\"}} 0\n\
                 attenuo_proxy_stage_seconds_bucket{{stage=\"upstream\",le=\"+Inf\"}} 0\n\
                 attenuo_proxy_stage_seconds_sum{{stage=\"upstream\"}} 0\n\
                 attenuo_proxy_stage_seconds_count{{stage=\"upstream\"}} 0\n\
                 attenuo_authorize_duration_seconds_count 9\n",
                policy[0], policy[1], policy[2], policy[2]
            )
        };
        let before = parse_stages(&render([5, 5, 5], 0.00004));
        assert_eq!(before.len(), 2);
        assert_eq!(before[0].0, "policy");
        assert_eq!(before[0].1.count, 5);
        assert_eq!(before[0].1.buckets.len(), 3);
        // 10 more calls: none under 10 us, 10 between 10 and 20 us.
        let after = parse_stages(&render([5, 15, 15], 0.00019));
        let d = stage_delta(&before, &after);
        let policy = &d[0].1;
        assert_eq!(policy.count, 10);
        assert_eq!(
            policy.buckets,
            vec![(1e-5, 0), (2e-5, 10), (f64::INFINITY, 10)]
        );
        assert!((policy.sum - 0.00015).abs() < 1e-12);
        // The median is half-way through the 10 to 20 us bucket.
        let p50 = policy.quantile(0.5).unwrap();
        assert!((p50 - 1.5e-5).abs() < 1e-12, "{p50}");
        assert_eq!(d[1].1.quantile(0.5), None, "empty stage");
    }
}
