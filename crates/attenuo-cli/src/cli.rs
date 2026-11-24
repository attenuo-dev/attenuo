//! Command line definition.

use clap::builder::NonEmptyStringValueParser;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

/// Default server address (matches `config/example.toml`).
pub(crate) const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// attenuo: mint, exchange and inspect delegation tokens, call tools through the proxy and
/// administer a running attenuo server.
///
/// `--server` here is the attenuo server's base URL and goes before the subcommand. The MCP
/// upstream a subcommand talks to (`call`, `tools`, `authzen eval`, `policy evaluate`,
/// `audit tail`) is `--upstream` (for example `github`).
#[derive(Debug, Parser)]
#[command(name = "attenuo", version, about, long_about)]
pub(crate) struct Cli {
    /// Base URL of the attenuo server.
    #[arg(long, visible_alias = "url", env = "ATTENUO_SERVER", default_value = DEFAULT_SERVER)]
    pub server: String,

    /// Base URL of the server's admin API, for a server with `[admin] listen`. Every request
    /// to `/admin/*` goes here; every other request (tokens, AuthZEN, the proxy, `health`,
    /// the JWKS) still goes to `--server`. Unset or empty, `/admin/*` goes to `--server` too.
    #[arg(long, global = true, env = "ATTENUO_ADMIN_SERVER", value_name = "URL")]
    pub admin_server: Option<String>,

    /// PEM file of the CA certificates to trust for the server's TLS certificate, for a server
    /// whose certificate comes from a private CA. When set, only these are trusted for
    /// `--server` and `--admin-server`, not the public roots built into the CLI.
    #[arg(
        long,
        global = true,
        env = "ATTENUO_TLS_CA_CERT",
        value_name = "PATH",
        value_parser = path_or_empty()
    )]
    pub tls_ca_cert: Option<std::path::PathBuf>,

    /// PEM file of a TLS client certificate to present to `--server` (never to
    /// `--admin-server`), for an agent pinned with `tls_client_cert_sha256`. Needs
    /// `--tls-client-key`.
    #[arg(
        long,
        global = true,
        env = "ATTENUO_TLS_CLIENT_CERT",
        value_name = "PATH",
        value_parser = path_or_empty()
    )]
    pub tls_client_cert: Option<std::path::PathBuf>,

    /// PEM file of the private key of `--tls-client-cert` (unencrypted). Needs
    /// `--tls-client-cert`.
    #[arg(
        long,
        global = true,
        env = "ATTENUO_TLS_CLIENT_KEY",
        value_name = "PATH",
        value_parser = path_or_empty()
    )]
    pub tls_client_key: Option<std::path::PathBuf>,

    /// Bearer token for `/admin/*` (token root, lease, audit, policy). Without this flag,
    /// `--admin-token-stdin` or `--admin-token-file`, the `ATTENUO_ADMIN_TOKEN` environment
    /// variable is used.
    ///
    /// Prefer `ATTENUO_ADMIN_TOKEN`, `--admin-token-stdin` or `--admin-token-file`: an argument
    /// is visible to other local users in `ps` and ends up in shell history.
    #[arg(
        long,
        global = true,
        conflicts_with_all = ["admin_token_stdin", "admin_token_file"]
    )]
    pub admin_token: Option<String>,

    /// Read the admin token from the first line of standard input.
    #[arg(long, global = true, conflicts_with = "admin_token_file")]
    pub admin_token_stdin: bool,

    /// Read the admin token from the first line of this file.
    #[arg(long, global = true, value_name = "PATH")]
    pub admin_token_file: Option<std::path::PathBuf>,

    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// A path that may be empty, so that an empty environment variable (a compose file's
/// `${VAR:-}`) reaches the code that treats it as unset instead of failing to parse.
fn path_or_empty() -> impl clap::builder::TypedValueParser<Value = std::path::PathBuf> {
    use clap::builder::TypedValueParser;
    clap::builder::OsStringValueParser::new().map(std::path::PathBuf::from)
}

/// Warning printed when a subcommand is given its deprecated `--server` (audit K-13).
pub(crate) fn server_flag_warning(cmd: &str) -> String {
    format!(
        "warning: `{cmd} --server` is deprecated, use `--upstream`; `--server` before the \
         subcommand is the attenuo server URL"
    )
}

/// Move a deprecated `--server` value into `upstream`, and say so in `warnings`.
fn adopt(
    upstream: &mut Option<String>,
    old: &mut Option<String>,
    cmd: &str,
    warnings: &mut Vec<String>,
) {
    if let Some(v) = old.take() {
        *upstream = Some(v);
        warnings.push(server_flag_warning(cmd));
    }
}

/// The upstream name of `call`, `tools` and `policy evaluate`, after
/// [`Cli::resolve_deprecated`] (clap makes one of the two flags required).
macro_rules! upstream_accessor {
    ($($t:ty),*) => {$(
        impl $t {
            /// The MCP upstream name, from `--upstream` or the deprecated `--server`.
            pub(crate) fn upstream(&self) -> &str {
                self.upstream
                    .as_deref()
                    .or(self.server_deprecated.as_deref())
                    .unwrap_or_default()
            }
        }
    )*};
}
upstream_accessor!(CallArgs, ToolsArgs, EvaluateArgs);

impl Cli {
    /// Apply the deprecated `--server` spelling of a subcommand's `--upstream`, which clap
    /// keeps apart so that its use can be warned about. Returns one warning line per use, for
    /// stderr.
    pub(crate) fn resolve_deprecated(&mut self) -> Vec<String> {
        let mut warnings = Vec::new();
        match &mut self.command {
            Command::Call(a) => adopt(
                &mut a.upstream,
                &mut a.server_deprecated,
                "call",
                &mut warnings,
            ),
            Command::Tools(a) => adopt(
                &mut a.upstream,
                &mut a.server_deprecated,
                "tools",
                &mut warnings,
            ),
            Command::Policy(PolicyCmd::Evaluate(a)) => adopt(
                &mut a.upstream,
                &mut a.server_deprecated,
                "policy evaluate",
                &mut warnings,
            ),
            Command::Audit(AuditCmd::Tail { filter, .. }) => adopt(
                &mut filter.upstream,
                &mut filter.server_deprecated,
                "audit tail",
                &mut warnings,
            ),
            Command::Authzen(AuthzenCmd::Eval {
                upstream,
                server_deprecated,
                ..
            }) => {
                if let Some(v) = server_deprecated.take() {
                    *upstream = v;
                    warnings.push(server_flag_warning("authzen eval"));
                }
            }
            _ => {}
        }
        warnings
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Mint, exchange and inspect delegation tokens.
    #[command(subcommand)]
    Token(TokenCmd),
    /// Call a tool through the proxy (`tools/call`).
    Call(CallArgs),
    /// List the tools the token may see (`tools/list`).
    Tools(ToolsArgs),
    /// Inspect and revoke leases.
    #[command(subcommand)]
    Lease(LeaseCmd),
    /// List, show, grant and decline approvals of gated calls (as an operator).
    #[command(subcommand)]
    Approval(ApprovalCmd),
    /// Administer run-limit budgets (ADR-0010).
    #[command(subcommand)]
    Budget(BudgetCmd),
    /// Read and verify the audit log.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Administer the policy set.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Query the AuthZEN decision endpoint.
    #[command(subcommand)]
    Authzen(AuthzenCmd),
    /// Generate keys.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Admin operators: make their credentials offline, and reload them on the server
    /// (ADR-0016).
    #[command(subcommand)]
    Admin(AdminCmd),
    /// Check that the server is up (`GET /healthz`), or ready with `--ready` (`GET /readyz`).
    /// Exits 0 when it is and 1 when it is not or cannot be reached, never 2, so it can be a
    /// container `HEALTHCHECK` (Docker reserves exit status 2 there). Needs no token.
    Health(HealthArgs),
    /// Run a local STDIO MCP server as a child process and serve it as a Streamable HTTP MCP
    /// endpoint at `http://<listen>/mcp`, so it can be an `[[upstreams]]` entry of the
    /// attenuo proxy. The bridge has no authentication of its own: anyone who can reach it
    /// bypasses attenuo, so it binds loopback only unless `--allow-non-loopback` is given.
    /// Runs until SIGINT or SIGTERM (exit 0) or until the child exits (exit 1); the child is
    /// stopped with it.
    StdioBridge(StdioBridgeArgs),
    /// Write a working starter configuration for one MCP server into a directory:
    /// `attenuo.toml`, `policy.cedar` and `attenuo.env`. Asks the MCP server for its tools
    /// and lists each in the catalog; the starter policy denies every call until a permit is
    /// written (or, with `--trust-readonly-hints`, permits the tools the server marks
    /// read-only). For trying attenuo on one machine: the configuration
    /// listens on loopback with the development root mint on. Talks to no attenuo server.
    Init(InitArgs),
    /// Speak MCP over STDIO for a desktop MCP client (Claude Desktop, Claude Code, Cursor)
    /// and forward every message to the proxy at `<--server>/mcp/<--upstream>` over
    /// Streamable HTTP, with a fresh delegation token as the bearer. The client starts it as
    /// a command. It gets a new token from `--token-command` or `--token-file` before the old
    /// one runs out, renews the lease, and writes only MCP messages on stdout; everything it
    /// logs goes to stderr. Runs until stdin ends or a stop signal (exit 0); exits 1
    /// before reading stdin when no token can be had.
    Connect(ConnectArgs),
}

/// `attenuo connect`. Its `Debug` leaves out the token command, which may hold a secret.
#[derive(Args)]
pub(crate) struct ConnectArgs {
    /// MCP upstream name, as mounted at `/mcp/<name>`.
    #[arg(long, value_name = "NAME")]
    pub upstream: String,
    /// A program and its arguments, as one string, that prints a delegation token on the
    /// first line of its stdout. It is split into words the way a shell would (spaces,
    /// `'...'`, `"..."`, `\`), but no shell runs it: no variables, globs or pipes. It runs at
    /// start and whenever a new token is needed, with this process's environment, no stdin,
    /// and its stderr on ours. Its arguments are never logged.
    #[arg(long, value_name = "CMD", conflicts_with = "token_file")]
    pub token_command: Option<String>,
    /// Read the delegation token from the first line of this file, again whenever a new
    /// token is needed (something else keeps the file fresh).
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<std::path::PathBuf>,
    /// How long `--token-command` may run, in seconds, before it is killed and counts as
    /// failed.
    #[arg(long, value_name = "SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=600), requires = "token_command")]
    pub token_command_timeout: u64,
    /// How long one request may take, answer included (a streamed answer too), in seconds.
    /// Past it the client gets a JSON-RPC error with the request's id.
    #[arg(long, value_name = "SECS", default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub timeout: u64,
    /// Largest single message, in bytes: a line from stdin, a JSON answer, or one event of a
    /// streamed answer.
    #[arg(long, value_name = "BYTES", default_value_t = 16 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1024..=(1 << 30)))]
    pub max_message_bytes: u64,
    /// Most bytes read from the streamed (SSE) answer to one request, all events together.
    #[arg(long, value_name = "BYTES", default_value_t = 64 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1024..=(1 << 34)))]
    pub max_stream_bytes: u64,
    /// Most requests waiting for an answer at once. A request over the limit gets a JSON-RPC
    /// error at once and is not sent.
    #[arg(long, value_name = "N", default_value_t = 64, value_parser = clap::value_parser!(u64).range(1..=4096))]
    pub max_in_flight: u64,
}

impl std::fmt::Debug for ConnectArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectArgs")
            .field("upstream", &self.upstream)
            .field(
                "token_command",
                &self.token_command.as_ref().map(|_| "<redacted>"),
            )
            .field("token_file", &self.token_file)
            .field("token_command_timeout", &self.token_command_timeout)
            .field("timeout", &self.timeout)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("max_stream_bytes", &self.max_stream_bytes)
            .field("max_in_flight", &self.max_in_flight)
            .finish()
    }
}

/// `attenuo init`.
#[derive(Debug, Args)]
pub(crate) struct InitArgs {
    /// The MCP server to protect, as `NAME=URL`: the name it gets in attenuo (the server
    /// part of capabilities such as `github:read_file`) and its Streamable HTTP URL
    /// (`github=http://127.0.0.1:3001/mcp`).
    #[arg(long, value_name = "NAME=URL")]
    pub upstream: String,
    /// The directory the files are written into; created when it does not exist.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub dir: std::path::PathBuf,
    /// The address the attenuo server will listen on. Must be loopback.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
    pub listen: std::net::SocketAddr,
    /// Do not ask the MCP server for its tools. The catalog is left empty, so every call is
    /// denied until the tools are listed by hand. For a server that needs credentials or is
    /// not running.
    #[arg(long)]
    pub no_discover: bool,
    /// Believe the MCP server's `readOnlyHint` annotations: a tool that carries one is marked
    /// read-only, and the starter policy permits read-only tools. Without this flag the hint
    /// is only reported and nothing is permitted, because it is the server's own claim.
    #[arg(long, conflicts_with = "no_discover")]
    pub trust_readonly_hints: bool,
    /// Overwrite the three files when they exist. New secrets are generated.
    #[arg(long)]
    pub force: bool,
}

/// `attenuo stdio-bridge`.
#[derive(Debug, Args)]
pub(crate) struct StdioBridgeArgs {
    /// The address to serve on, an IP address and a port (`127.0.0.1:3001`; port 0 picks a
    /// free one). The URL is printed on stdout once bound: `listening on http://ADDR/mcp`.
    #[arg(long, value_name = "ADDR")]
    pub listen: std::net::SocketAddr,
    /// Accept a `--listen` address that is not loopback. The bridge does not authenticate
    /// its callers: anyone who reaches it calls the STDIO server without attenuo.
    #[arg(long)]
    pub allow_non_loopback: bool,
    /// How long a request waits for the STDIO server's answer, in seconds, before it gets a
    /// JSON-RPC error with HTTP 504. Keep it below the proxy's
    /// `upstream_response_timeout_seconds` (120 by default).
    #[arg(long, value_name = "SECS", default_value_t = 90, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: u64,
    /// Largest HTTP request body accepted, in bytes; a larger one gets HTTP 413.
    #[arg(long, value_name = "BYTES", default_value_t = 4 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..=(1 << 30)))]
    pub max_request_bytes: u64,
    /// Longest line read from the STDIO server's stdout, in bytes; a longer one is dropped
    /// (and the request it answered times out).
    #[arg(long, value_name = "BYTES", default_value_t = 16 * 1024 * 1024, value_parser = clap::value_parser!(u64).range(1..=(1 << 30)))]
    pub max_line_bytes: u64,
    /// Print one line to stderr for each message of the STDIO server the bridge drops
    /// (notifications, its own requests, answers nobody waits for).
    #[arg(long)]
    pub verbose: bool,
    /// The STDIO server's command and its arguments, after `--`. It inherits the bridge's
    /// environment, without any variable whose name starts with `ATTENUO_` (attenuo's own
    /// secrets and configuration overrides).
    #[arg(required = true, last = true, num_args = 1.., value_name = "COMMAND", value_parser = clap::value_parser!(std::ffi::OsString))]
    pub command: Vec<std::ffi::OsString>,
}

/// `attenuo health`.
#[derive(Debug, Args)]
pub(crate) struct HealthArgs {
    /// Ask `/readyz` (audit log and lease store answer, last audit append succeeded) instead of
    /// `/healthz` (the process answers HTTP).
    #[arg(long)]
    pub ready: bool,
    /// Give up after this many seconds, connect and answer together.
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub timeout: u64,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminCmd {
    /// Named admin operators (`[[admin.operators]]`).
    #[command(subcommand)]
    Operator(OperatorCmd),
    /// The agents and PEPs of the server's config (`[[agents]]`, `[[peps]]`).
    #[command(subcommand)]
    Agent(AgentCmd),
    /// The server's token signing key and the retired keys that still verify (`[issuer]`).
    #[command(subcommand)]
    Key(AdminKeyCmd),
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminKeyCmd {
    /// Ask the server to re-read the key files named by `[issuer] private_key_pem_path` and
    /// `previous_key_paths` in its config file and put them in force without a restart
    /// (`POST /admin/keys/reload`, role `admin`). Prints the signing key id before and after,
    /// the key ids added to and removed from the verifying set, and the sections of the file
    /// that differ from the ones in force and need a restart; warnings go to stderr, and the
    /// exit status stays 0. On a refusal (a key file that cannot be read or is not an Ed25519
    /// key, a key listed twice, a reload that drops the current key or a key that signed the
    /// audit log) the keys in force are unchanged. Only key ids are shown, never a key.
    Reload {
        /// Accept a new signing key while the current one is not in `previous_key_paths`:
        /// every token it signed stops verifying at once (key compromise).
        #[arg(long)]
        allow_drop_current: bool,
        /// Accept verifying keys that leave out a key that signed audit checkpoints or anchors
        /// the log holds: `attenuo audit verify` then reports them as signed by an unknown key.
        #[arg(long)]
        allow_drop_audit_key: bool,
        /// Accept a file whose `[issuer]` (its key files aside) or `[audit]` differs from the
        /// running config. Refused without it, as such a file may be another server's.
        #[arg(long)]
        allow_mismatch: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AgentCmd {
    /// Ask the server to re-read `[[agents]]` and `[[peps]]` from its config file and put them
    /// in force without a restart (`POST /admin/agents/reload`, role `admin`). Prints the
    /// agents and PEPs added, removed and changed, and the other sections of the file that
    /// differ from the ones in force and need a restart; warnings go to stderr, and the exit
    /// status stays 0. On a refusal (a file that does not parse, lists that break a startup
    /// rule, a file that empties a list or looks like another server's) the lists in force are
    /// unchanged. Tokens already issued are not revoked: use `attenuo lease revoke` for that.
    Reload {
        /// Accept a file that leaves `[[agents]]` or `[[peps]]` empty while the server has
        /// entries in force. Refused without it, as an empty or cut-off file reads that way.
        #[arg(long)]
        allow_empty: bool,
        /// Accept a file whose `[issuer]` or `[audit]` differs from the running config.
        /// Refused without it, as such a file may be another server's.
        #[arg(long)]
        allow_mismatch: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum OperatorCmd {
    /// Generate a token for a new operator: 32 random bytes, base64url. Prints the token once
    /// on stdout, then the `[[admin.operators]]` entry to add to the server's config, which
    /// holds only the token's SHA-256. Writes nothing to disk and sends nothing to a server;
    /// the server picks the entry up on `attenuo admin operator reload` or a restart.
    New {
        /// The operator's name, `[a-z0-9_-]{1,64}` and not `admin`; recorded in the audit
        /// log as `urn:attenuo:admin:<name>`.
        #[arg(long)]
        name: String,
        /// What the operator may do: `viewer` (reads), `operator` (also revoke leases and
        /// decide approvals) or `admin` (everything).
        #[arg(long)]
        role: OperatorRole,
        /// The token stops working this long from now: a whole number and a unit, `s`, `m`,
        /// `h` or `d` (`90d`, `12h`). Written into the entry as `expires_at`.
        #[arg(long, value_name = "DURATION", value_parser = parse_expires_in, conflicts_with = "expires_at")]
        expires_in: Option<time::Duration>,
        /// The token stops working at this RFC 3339 time with an offset
        /// (`2026-12-31T23:59:59Z`), which must be in the future.
        #[arg(long, value_name = "RFC3339", value_parser = parse_expires_at)]
        expires_at: Option<time::OffsetDateTime>,
    },
    /// Print the `token_sha256` of a token read from the first line of standard input, for
    /// a token made some other way.
    Hash,
    /// Ask the server to re-read `[[admin.operators]]` from its config file and put them in
    /// force without a restart (`POST /admin/operators/reload`, role `admin`). Prints the
    /// operators added, removed and changed. `[admin] token` is not reloaded. On a refusal
    /// (a list that does not parse or breaks a rule, or one that would leave no `admin`) the
    /// operators in force are unchanged.
    Reload,
}

/// Longest `--expires-in`: ten years.
const MAX_EXPIRES_IN_DAYS: i64 = 3650;

/// `--expires-in`: a whole number of `s`, `m`, `h` or `d`, at least one second and at most
/// [`MAX_EXPIRES_IN_DAYS`] days.
pub(crate) fn parse_expires_in(s: &str) -> Result<time::Duration, String> {
    let bad = || {
        format!("`{s}` is not a duration: write a whole number and a unit, s, m, h or d (like 90d)")
    };
    let unit = s.chars().last().ok_or_else(bad)?;
    let digits = &s[..s.len() - unit.len_utf8()];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: i64 = digits.parse().map_err(|_| bad())?;
    let seconds_per = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return Err(bad()),
    };
    let secs = n.checked_mul(seconds_per).ok_or_else(bad)?;
    if secs < 1 {
        return Err(format!("`{s}`: the duration must be at least 1s"));
    }
    if secs > MAX_EXPIRES_IN_DAYS * 86_400 {
        return Err(format!(
            "`{s}`: the duration must be at most {MAX_EXPIRES_IN_DAYS}d"
        ));
    }
    Ok(time::Duration::seconds(secs))
}

/// `--expires-at`: an RFC 3339 time with an offset, in the future.
fn parse_expires_at(s: &str) -> Result<time::OffsetDateTime, String> {
    use time::format_description::well_known::Rfc3339;
    let t = time::OffsetDateTime::parse(s, &Rfc3339).map_err(|_| {
        format!("`{s}` is not an RFC 3339 time with an offset (like 2026-12-31T23:59:59Z)")
    })?;
    if t <= time::OffsetDateTime::now_utc() {
        return Err(format!("`{s}` is in the past"));
    }
    Ok(t)
}

/// The role of an admin operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OperatorRole {
    /// Read-only admin routes.
    Viewer,
    /// A viewer that may also revoke leases and decide approvals.
    Operator,
    /// Every admin route.
    Admin,
}

impl OperatorRole {
    /// The config spelling.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OperatorRole::Viewer => "viewer",
            OperatorRole::Operator => "operator",
            OperatorRole::Admin => "admin",
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum KeyCmd {
    /// Generate a key. `--dpop <PATH>` writes a new Ed25519 DPoP key (RFC 9449) as a private
    /// JWK, readable only by you, and prints its thumbprint (the `cnf.jkt` of tokens bound to
    /// it). Use it with `--dpop-key`; the Python and TypeScript SDKs take the same file.
    /// `--client <PATH>` writes a new Ed25519 client key for `private_key_jwt` (RFC 7523) the
    /// same way, and prints the `jwks` line with its public half to add to the agent's
    /// `[[agents]]` (or the PEP's `[[peps]]`) entry. Use it with `token exchange --client-key`.
    #[command(group(clap::ArgGroup::new("kind").required(true).args(["dpop", "client"])))]
    Gen {
        /// Where to write the DPoP key. An existing file is never overwritten.
        #[arg(long, value_name = "PATH")]
        dpop: Option<std::path::PathBuf>,
        /// Where to write the client key. An existing file is never overwritten.
        #[arg(long, value_name = "PATH")]
        client: Option<std::path::PathBuf>,
        /// The client key's `kid` (default: its RFC 7638 thumbprint). Give each key of an
        /// agent its own `kid`, so a new key can be added next to the old one.
        #[arg(
            long,
            requires = "client",
            conflicts_with = "dpop",
            value_parser = NonEmptyStringValueParser::new()
        )]
        kid: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TokenCmd {
    /// Mint a root (hop 0) token. Development endpoint; needs the admin token.
    Root(RootArgs),
    /// RFC 8693 exchange: delegate a subset of a token's capabilities to a sub-agent.
    Exchange(ExchangeArgs),
    /// Consent, as the holder of a DPoP-bound token, to one exchange of it that binds the new
    /// token to a sub-agent's own key. Prints the proof to pass as
    /// `token exchange --subject-token-dpop-file`; it names the key and the agent, is good for
    /// one exchange, and expires with the server's DPoP window (default 5 minutes).
    SignOff(SignOffArgs),
    /// Decode a token and show its delegation chain as a tree.
    Inspect(InspectArgs),
}

/// Which single value of a token response to print (for shell scripting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Field {
    /// The JWT.
    Token,
    /// The lease id.
    Lease,
}

#[derive(Debug, Args)]
pub(crate) struct RootArgs {
    /// The user the agent acts for.
    #[arg(long)]
    pub subject: String,
    /// Issuer of the user's identity.
    #[arg(long, default_value = "https://idp.example")]
    pub issuer: String,
    /// The root agent.
    #[arg(long)]
    pub agent: String,
    /// Capability `server:tool` (globs allowed), or a full capability as a JSON object (with
    /// `constraints` and run `limits`, e.g. `{"server":"bank","tool":"send_money","limits":{"calls":1}}`).
    /// Repeatable; plain `server:tool` values may also be comma-separated. Omit to take the server's `[[root_grants]]` ceiling.
    #[arg(long = "cap")]
    pub caps: Vec<String>,
    /// Requested lifetime in seconds.
    #[arg(long)]
    pub ttl_seconds: Option<u64>,
    /// User attribute `key=value` (`key:=json` for non-strings). Repeatable.
    #[arg(long = "attr", value_parser = parse_kv)]
    pub attrs: Vec<(String, Value)>,
    /// RFC 8693 `may_act` for the root token: an agent allowed to exchange it next. Repeatable;
    /// values may also be comma-separated. Must be within the `[[root_grants]]` entry's
    /// `may_act` when it has one. Without it (and without `--no-delegation`) the grant's
    /// `may_act` applies; when the grant has none, or the server has no `[[root_grants]]`, the
    /// root token carries no `may_act`, so any authenticated agent may exchange it.
    #[arg(
        long = "may-act",
        value_name = "AGENT",
        conflicts_with = "no_delegation"
    )]
    pub may_act: Vec<String>,
    /// Send `may_act: []`: no agent may exchange the root token. Always within a
    /// `[[root_grants]]` entry's `may_act`.
    #[arg(long)]
    pub no_delegation: bool,
    /// Bind the root token to this DPoP key (a private JWK from `attenuo key gen --dpop`).
    #[arg(long, value_name = "PATH")]
    pub dpop_key: Option<std::path::PathBuf>,
    /// Print only this value, for scripts.
    #[arg(long, value_enum)]
    pub print: Option<Field>,
}

impl RootArgs {
    /// The JSON body for `POST /admin/root-token`.
    pub(crate) fn request_body(&self) -> anyhow::Result<Value> {
        let mut body = serde_json::Map::new();
        body.insert("subject".into(), self.subject.clone().into());
        body.insert("issuer".into(), self.issuer.clone().into());
        body.insert("agent".into(), self.agent.clone().into());
        if !self.caps.is_empty() {
            body.insert("capabilities".into(), parse_caps(&self.caps)?.into());
        }
        if let Some(ttl) = self.ttl_seconds {
            body.insert("ttl_seconds".into(), ttl.into());
        }
        if !self.attrs.is_empty() {
            body.insert(
                "attributes".into(),
                self.attrs
                    .iter()
                    .cloned()
                    .collect::<serde_json::Map<_, _>>()
                    .into(),
            );
        }
        if let Some(may_act) = self.may_act_claim()? {
            body.insert("may_act".into(), serde_json::json!({ "sub": may_act }));
        }
        Ok(Value::Object(body))
    }

    /// The `may_act` to send: `None` without `--may-act` and `--no-delegation` (the grant's
    /// applies), `Some([])` with `--no-delegation`. `--may-act` values that are all empty are
    /// refused rather than dropped, since sending nothing would fall back to the grant's list,
    /// or to none at all.
    pub(crate) fn may_act_claim(&self) -> anyhow::Result<Option<Vec<String>>> {
        may_act_claim(&self.may_act, self.no_delegation)
    }
}

/// The `may_act` a `token root` or `token exchange` sends, from `--may-act` and
/// `--no-delegation`: `None` when neither is given, `Some([])` for `--no-delegation`, an error
/// when every `--may-act` value is empty.
fn may_act_claim(values: &[String], no_delegation: bool) -> anyhow::Result<Option<Vec<String>>> {
    if no_delegation {
        return Ok(Some(Vec::new()));
    }
    if values.is_empty() {
        return Ok(None);
    }
    let agents = split_agents(values);
    if agents.is_empty() {
        anyhow::bail!(
            "--may-act names no agent; use --no-delegation for a token nobody may exchange"
        );
    }
    Ok(Some(agents))
}

/// Agent ids from repeatable, comma-separated flag values, trimmed, without empties.
fn split_agents(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// What `token exchange` sends as its subject token: the `subject_token_type` of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub(crate) enum SubjectTokenType {
    /// An attenuo token: an exchange from hop n to hop n+1.
    #[default]
    Jwt,
    /// An OIDC ID token from an `[[idps]]` issuer: hop 0, which mints a root token.
    IdToken,
    /// An ID-JAG from an `[[idps]]` issuer: hop 0, which mints a root token.
    IdJag,
}

impl SubjectTokenType {
    /// The RFC 8693 token type URN the request carries.
    pub(crate) fn urn(self) -> &'static str {
        match self {
            Self::Jwt => "urn:ietf:params:oauth:token-type:jwt",
            Self::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            Self::IdJag => "urn:ietf:params:oauth:token-type:id-jag",
        }
    }

    /// Is the subject token an IdP credential (hop 0) rather than an attenuo token?
    pub(crate) fn is_hop0(self) -> bool {
        self != Self::Jwt
    }
}

#[derive(Debug, Args)]
pub(crate) struct ExchangeArgs {
    /// The parent token (or, with `--subject-token-type id-token | id-jag`, the IdP
    /// credential), or `-` to read it from the first line of stdin. Without this flag or
    /// `--subject-token-file`, the `ATTENUO_TOKEN` environment variable is used. Prefer those:
    /// an argument is visible to other local users in `ps`.
    #[arg(long, conflicts_with = "subject_token_file")]
    pub subject_token: Option<String>,
    /// Read the parent token (or the IdP credential) from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub subject_token_file: Option<std::path::PathBuf>,
    /// What the subject token is. `jwt`: an attenuo token, exchanged from hop n to hop n+1.
    /// `id-token` (an OIDC ID token) or `id-jag` (an ID-JAG): a user credential from an
    /// `[[idps]]` issuer, exchanged at hop 0 for a root token held by `--actor`, within the
    /// server's `[[root_grants]]`. Sent as `subject_token_type`
    /// (`urn:ietf:params:oauth:token-type:jwt`, `...:id_token`, `...:id-jag`).
    #[arg(long, value_enum, value_name = "TYPE", default_value_t = SubjectTokenType::Jwt)]
    pub subject_token_type: SubjectTokenType,
    /// The sub-agent that will hold the new token (at hop 0, the agent presenting the user's
    /// credential). The request authenticates as this agent.
    #[arg(long)]
    pub actor: String,
    /// Client id to authenticate with (an `[[agents]]` entry). Defaults to `--actor`; the server
    /// requires the two to match.
    #[arg(long)]
    pub client_id: Option<String>,
    /// The agent's client secret. Required by servers with `[token] require_actor_auth`
    /// (the default), unless the agent authenticates with `--client-key` or `--actor-token`.
    /// Without this flag, `--client-secret-stdin`, `--client-secret-file` or `--client-key`,
    /// the `ATTENUO_CLIENT_SECRET` environment variable is used. Prefer those: an argument is
    /// visible to other local users in `ps`.
    #[arg(long, conflicts_with_all = ["client_secret_stdin", "client_secret_file", "client_key"])]
    pub client_secret: Option<String>,
    /// Read the client secret from the first line of standard input.
    #[arg(long, conflicts_with_all = ["client_secret_file", "client_key"])]
    pub client_secret_stdin: bool,
    /// Read the client secret from the first line of this file.
    #[arg(long, value_name = "PATH", conflicts_with = "client_key")]
    pub client_secret_file: Option<std::path::PathBuf>,
    /// Authenticate with `private_key_jwt` (RFC 7523) instead of a secret: sign a client
    /// assertion with this key, a private JWK (Ed25519 or P-256) such as `attenuo key gen
    /// --client` writes; its `kid`, if the file has one, goes in the header. The assertion
    /// names the client id, has a fresh `jti` and lives one minute. `ATTENUO_CLIENT_SECRET` is
    /// then ignored.
    #[arg(long, value_name = "PATH")]
    pub client_key: Option<std::path::PathBuf>,
    /// The `aud` of the client assertion: the server's `[issuer] issuer`. Default: the `iss`
    /// of the subject token, which this server issued. Required at hop 0, where the subject
    /// token is the IdP's.
    #[arg(long, value_name = "ISSUER", requires = "client_key")]
    pub client_assertion_audience: Option<String>,
    /// RFC 8693 actor token authenticating `--actor`: a workload-identity JWT (for example a
    /// SPIFFE JWT-SVID) from an `[[actor_trust]]` issuer, or `-` to read it from stdin. Sent as
    /// `actor_token` with `actor_token_type` `urn:ietf:params:oauth:token-type:jwt`. Each
    /// token authenticates one exchange.
    #[arg(long, conflicts_with = "actor_token_file")]
    pub actor_token: Option<String>,
    /// Read the actor token from this file (for example the JWT-SVID a SPIFFE helper writes).
    #[arg(long, value_name = "PATH")]
    pub actor_token_file: Option<std::path::PathBuf>,
    /// RFC 8693 `may_act` for the new token: an agent allowed to exchange it next. Repeatable;
    /// values may also be comma-separated. Without it (and without `--no-delegation`) the new
    /// token carries no `may_act`, so any authenticated agent may exchange it: it does not
    /// inherit the parent's list.
    #[arg(
        long = "may-act",
        value_name = "AGENT",
        conflicts_with = "no_delegation"
    )]
    pub may_act: Vec<String>,
    /// Send `may_act: []`: no agent may exchange the new token.
    #[arg(long)]
    pub no_delegation: bool,
    /// Capability `server:tool`, or a full capability as a JSON object (with `constraints` and
    /// run `limits`). Repeatable; plain `server:tool` values may also be comma-separated. Must
    /// be covered by the parent's capabilities; limits are inherited from the parent and
    /// clamped to what it has left. At hop 0, must be covered by the `[[root_grants]]` entry,
    /// and a limited capability of the entry cannot be split across two requested
    /// capabilities (`limit_split_at_root`): ask for one with a `one_of` constraint instead.
    #[arg(long = "cap", required = true)]
    pub caps: Vec<String>,
    /// Requested lifetime in seconds (clamped to the parent's expiry; at hop 0, to the
    /// credential's).
    #[arg(long)]
    pub ttl_seconds: Option<u64>,
    /// Bind the new token to this DPoP key (a private JWK from `attenuo key gen --dpop`): a
    /// proof by it goes in the `DPoP` header. When the parent token is bound to the same key,
    /// the proof also covers the parent. Required for a bound parent, and at hop 0 for an
    /// ID-JAG with a `cnf` key, which must be this key.
    #[arg(long, value_name = "PATH")]
    pub dpop_key: Option<std::path::PathBuf>,
    /// The parent token's DPoP key, when it differs from `--dpop-key`: its proof goes in the
    /// body as `subject_token_dpop`, the parent holder's consent to binding the new token to
    /// `--dpop-key` for `--actor`. Only when one party holds both keys; otherwise the parent
    /// makes the consent with `attenuo token sign-off` and you pass it with
    /// `--subject-token-dpop-file`. Not at hop 0.
    #[arg(long, value_name = "PATH", conflicts_with = "subject_token_dpop_file")]
    pub subject_dpop_key: Option<std::path::PathBuf>,
    /// The parent holder's consent (`subject_token_dpop`) made with `attenuo token sign-off`
    /// for this exchange's `--dpop-key` and `--actor`, read from the first line of this file.
    /// Not at hop 0.
    #[arg(long, value_name = "PATH")]
    pub subject_token_dpop_file: Option<std::path::PathBuf>,
    /// Print only this value, for scripts.
    #[arg(long, value_enum)]
    pub print: Option<Field>,
}

impl ExchangeArgs {
    /// Refuse the flags that mean nothing at hop 0 (`--subject-token-type id-token | id-jag`),
    /// where there is no parent token: the server would ignore a parent's sign-off, and the
    /// client assertion's audience cannot be read from an IdP credential.
    pub(crate) fn check_hop0(&self) -> anyhow::Result<()> {
        if !self.subject_token_type.is_hop0() {
            return Ok(());
        }
        let ty = self
            .subject_token_type
            .to_possible_value()
            .map(|v| v.get_name().to_owned())
            .unwrap_or_default();
        if self.subject_dpop_key.is_some() || self.subject_token_dpop_file.is_some() {
            anyhow::bail!(
                "--subject-dpop-key and --subject-token-dpop-file sign off on an exchange of a \
                 bound parent token; at hop 0 (--subject-token-type {ty}) there is none. Use \
                 --dpop-key to bind the root token"
            );
        }
        if self.client_key.is_some() && self.client_assertion_audience.is_none() {
            anyhow::bail!(
                "--client-key at hop 0 (--subject-token-type {ty}) needs \
                 --client-assertion-audience <the server's [issuer] issuer>: the subject token \
                 is the IdP's, so its `iss` is not the server's"
            );
        }
        Ok(())
    }

    /// The actor token from `--actor-token` (`-` reads `stdin`) or `--actor-token-file`,
    /// trimmed; `None` when neither is given.
    pub(crate) fn actor_token(&self, stdin: impl std::io::Read) -> anyhow::Result<Option<String>> {
        use anyhow::Context;
        let raw = match (&self.actor_token, &self.actor_token_file) {
            (None, None) => return Ok(None),
            (Some(t), _) if t == "-" => {
                let mut s = String::new();
                let mut stdin = stdin;
                stdin
                    .read_to_string(&mut s)
                    .context("reading the actor token from stdin")?;
                s
            }
            (Some(t), _) => t.clone(),
            (None, Some(path)) => std::fs::read_to_string(path)
                .with_context(|| format!("reading actor token {}", path.display()))?,
        };
        let token = raw.trim().to_string();
        if token.is_empty() {
            anyhow::bail!("the actor token is empty");
        }
        Ok(Some(token))
    }

    /// The `may_act` to send: `None` without `--may-act` and `--no-delegation`, `Some([])` with
    /// `--no-delegation`. `--may-act` values that are all empty are refused rather than
    /// dropped, since sending nothing would let any agent exchange the token.
    pub(crate) fn may_act_claim(&self) -> anyhow::Result<Option<Vec<String>>> {
        may_act_claim(&self.may_act, self.no_delegation)
    }
}

#[derive(Debug, Args)]
pub(crate) struct SignOffArgs {
    /// The bound token to be exchanged (the parent), or `-` to read it from the first line of
    /// stdin. Without this flag or `--subject-token-file`, `ATTENUO_TOKEN` is used.
    #[arg(long, conflicts_with = "subject_token_file")]
    pub subject_token: Option<String>,
    /// Read the parent token from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub subject_token_file: Option<std::path::PathBuf>,
    /// The parent token's DPoP key (a private JWK).
    #[arg(long, value_name = "PATH")]
    pub dpop_key: std::path::PathBuf,
    /// Thumbprint (`jkt`) of the sub-agent's key, which the new token will be bound to
    /// (`attenuo key gen --dpop` prints it).
    #[arg(long, value_name = "JKT")]
    pub child_jkt: String,
    /// The sub-agent that will exchange the token for itself.
    #[arg(long)]
    pub actor: String,
}

#[derive(Debug, Args)]
pub(crate) struct InspectArgs {
    /// The JWT, or `-` to read it from stdin.
    pub jwt: String,
    /// Fetch the server's JWKS and verify signature, issuer, audience and chain.
    #[arg(long)]
    pub verify: bool,
    /// With `--verify`: expected issuer (default: the token's own `iss`).
    #[arg(long, requires = "verify")]
    pub issuer: Option<String>,
    /// With `--verify`: expected audience (default: the token's own `aud`).
    #[arg(long, requires = "verify")]
    pub audience: Option<String>,
}

/// `--token` / `--token-file`: where the delegation token of `call`, `tools` and
/// `authzen eval` comes from.
#[derive(Debug, Args)]
pub(crate) struct TokenSource {
    /// Delegation token, or `-` to read it from the first line of stdin. Without this flag or
    /// `--token-file`, the `ATTENUO_TOKEN` environment variable is used. Prefer those: an
    /// argument is visible to other local users in `ps`.
    #[arg(long, conflicts_with = "token_file")]
    pub token: Option<String>,
    /// Read the delegation token from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<std::path::PathBuf>,
    /// The DPoP key the token is bound to (a private JWK): every request carries a proof by
    /// it and `Authorization: DPoP <token>`. Needed for tokens bound with `--dpop-key`.
    #[arg(long, value_name = "PATH", env = "ATTENUO_DPOP_KEY")]
    pub dpop_key: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct CallArgs {
    #[command(flatten)]
    pub token: TokenSource,
    /// MCP upstream name, as mounted at `/mcp/<name>`.
    #[arg(
        long,
        value_name = "NAME",
        required_unless_present = "server_deprecated"
    )]
    pub upstream: Option<String>,
    /// Deprecated spelling of `--upstream`.
    #[arg(
        long = "server",
        value_name = "NAME",
        hide = true,
        conflicts_with = "upstream"
    )]
    pub server_deprecated: Option<String>,
    /// Tool name.
    #[arg(long)]
    pub tool: String,
    /// Tool argument `key=value` (`key:=json` for numbers, booleans, objects). Repeatable.
    #[arg(long = "arg", value_parser = parse_kv)]
    pub args: Vec<(String, Value)>,
}

#[derive(Debug, Args)]
pub(crate) struct ToolsArgs {
    #[command(flatten)]
    pub token: TokenSource,
    /// MCP upstream name, as mounted at `/mcp/<name>`.
    #[arg(
        long,
        value_name = "NAME",
        required_unless_present = "server_deprecated"
    )]
    pub upstream: Option<String>,
    /// Deprecated spelling of `--upstream`.
    #[arg(
        long = "server",
        value_name = "NAME",
        hide = true,
        conflicts_with = "upstream"
    )]
    pub server_deprecated: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum LeaseCmd {
    /// Revoke a lease and every lease delegated from it. With `--user`, `--chain-id` or
    /// `--session` instead of an id, revoke every unrevoked lease of that originating user,
    /// delegation chain or MCP session's chain, each with its descendants
    /// (`POST /admin/leases/revoke`), and list them.
    #[command(group(clap::ArgGroup::new("selector").args(["user", "chain_id", "session"]).multiple(false)))]
    Revoke {
        /// The lease to revoke.
        #[arg(required_unless_present_any = ["user", "chain_id", "session"], conflicts_with_all = ["user", "chain_id", "session"])]
        id: Option<String>,
        /// Revoke every lease issued for this originating user (the `sub` of the chain's
        /// originating user, under any issuer).
        #[arg(long, conflicts_with_all = ["chain_id", "session"], value_parser = NonEmptyStringValueParser::new())]
        user: Option<String>,
        /// Revoke one whole delegation chain: the `chain_id` of its audit records, which is the
        /// lease of its first hop.
        #[arg(long, conflicts_with = "session", value_parser = NonEmptyStringValueParser::new())]
        chain_id: Option<String>,
        /// Revoke the delegation chain that opened this MCP session through the proxy: the raw
        /// `Mcp-Session-Id` (the server hashes it; audit records carry only its 12-character
        /// tag). A session the server has no record of matches nothing.
        #[arg(long, value_parser = NonEmptyStringValueParser::new())]
        session: Option<String>,
        /// With `--user`, `--chain-id` or `--session`: list what would be revoked and change
        /// nothing.
        #[arg(long, requires = "selector")]
        preview: bool,
        /// Recorded with the revocation.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Show a lease's state.
    Show { id: String },
    /// Show the lease, everything delegated from it and its ancestors, and how many leases a
    /// revoke sent now would change. A dry run of `lease revoke`: nothing is written. Under
    /// each lease with run limits, one line per limit (used, maximum and what is left) and, on
    /// the run's root lease, the run's usage per destructive tool.
    Tree {
        id: String,
        /// Most leases to list (server default 1000, at most 10000). `would_revoke` still
        /// counts the whole subtree.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        max_nodes: Option<u64>,
    },
}

/// Run-limit budgets: what a token's `limits` let a run spend (ADR-0010). The figures
/// themselves are shown by `lease tree`.
#[derive(Debug, Subcommand)]
pub(crate) enum BudgetCmd {
    /// Give back to every run-limit counter what one allowed decision charged, once, for a
    /// call whose effect did not happen (`POST /admin/budgets/refund`). The refund is audited
    /// as an `admin.budget.refund` record. Exits 2 when there is nothing to refund (an unknown
    /// decision, or one that charged nothing), 3 when it was already refunded and 4 when its
    /// charge was pruned (`[leases] run_state_retention_seconds`).
    Refund {
        /// The allowed call's decision id (the record id `audit tail` prints as `id=`, or the
        /// AuthZEN `context.decision_id`).
        #[arg(value_parser = NonEmptyStringValueParser::new())]
        decision_id: String,
        /// Why the charge is given back. Recorded in the audit log; required and not blank.
        #[arg(long, value_parser = parse_reason)]
        reason: String,
    },
}

/// A refund reason: any text that is not blank.
fn parse_reason(s: &str) -> Result<String, String> {
    if s.trim().is_empty() {
        return Err("the reason must not be empty".to_string());
    }
    Ok(s.to_string())
}

/// Approvals of calls a policy gated with `@obligation("approval")` (JSON-RPC `-32008`). These
/// use the admin API, so a grant here is recorded with `by = "operator"`; the originating user
/// grants with an ID token at `POST /approvals/{id}` instead.
#[derive(Debug, Subcommand)]
pub(crate) enum ApprovalCmd {
    /// Approvals, newest first, one page at a time (`--all` for every page).
    List {
        /// Only the approvals of this delegation run (its first hop's lease).
        #[arg(long)]
        chain_id: Option<String>,
        /// Only approvals in this state.
        #[arg(long, value_parser = ["pending", "granted", "declined", "consumed"])]
        state: Option<String>,
        /// Page size (server default 100, at most 500).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=500))]
        limit: Option<u64>,
        /// Start at this page: the `next_cursor` of an earlier listing with the same filters.
        #[arg(long, conflicts_with = "all")]
        cursor: Option<String>,
        /// Follow `next_cursor` and list every matching approval.
        #[arg(long)]
        all: bool,
    },
    /// Show one approval: the exact call, the run's labels, state and expiry.
    Show { id: String },
    /// Grant a pending approval as the operator. The agent's identical retry then runs once.
    Grant { id: String },
    /// Decline a pending approval.
    Decline { id: String },
    /// Verify a signed approval token (`typ: attenuo-approval+jwt`) offline: the Ed25519
    /// signature against the issuer's JWKS, `typ`, `iss`, `aud` and `exp`, and, when given, the
    /// call it must be bound to. Exits 2 when the token does not verify. This proves the grant
    /// was made; only the server knows whether it was used already.
    Verify(ApprovalVerifyArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ApprovalVerifyArgs {
    /// The approval token, or `-` to read it from stdin.
    pub token: String,
    /// The issuer's JWKS: an `http(s)://` URL or a file. Default:
    /// `<server>/.well-known/jwks.json`.
    #[arg(long, value_name = "URL|PATH")]
    pub jwks: Option<String>,
    /// Expected issuer (default: the token's own `iss`).
    #[arg(long)]
    pub issuer: Option<String>,
    /// Expected audience (default: the token's own `aud`).
    #[arg(long)]
    pub audience: Option<String>,
    /// The delegation run the call belongs to (`chain_id`: its first hop's lease).
    #[arg(long)]
    pub chain_id: Option<String>,
    /// The lease of the hop making the call.
    #[arg(long)]
    pub lease: Option<String>,
    /// The call hash (`ch`): SHA-256 of the canonical `{server, tool, arguments}`.
    #[arg(long)]
    pub call_hash: Option<String>,
    /// The calling hop's key thumbprint (`cnf.jkt`); `none` for a bearer hop.
    #[arg(long)]
    pub jkt: Option<String>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuditCmd {
    /// Show the most recent audit entries, oldest of them first. Filters keep only matching
    /// entries, so `-n 5 --decision deny` is the last five denials.
    Tail {
        /// How many entries to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: u64,
        /// Show the entries just below this seq instead of the newest ones, to page back
        /// through history (the next page is `--before <oldest seq shown>`).
        #[arg(long, conflicts_with = "follow", value_parser = clap::value_parser!(u64).range(1..))]
        before: Option<u64>,
        /// Keep polling for new entries.
        #[arg(short, long)]
        follow: bool,
        /// Polling interval with `--follow`, in milliseconds.
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        // Boxed: the filter is most of the variant's size.
        #[command(flatten)]
        filter: Box<AuditFilter>,
    },
    /// Show one audit entry with its context: the state of each lease in its chain now, the
    /// checkpoint that covers it and whether the policy was reloaded after it.
    Show {
        /// The entry's sequence number.
        #[arg(required_unless_present = "id", conflicts_with = "id")]
        seq: Option<u64>,
        /// The record id instead: the UUID that denials and AuthZEN answers return as
        /// `decision_id`.
        #[arg(long)]
        id: Option<String>,
    },
    /// List stored checkpoints, newest first. Read-only: never signs a new one.
    Checkpoints {
        /// The next (older) page: the `next_cursor` of an earlier listing.
        #[arg(long)]
        cursor: Option<String>,
        /// Page size (server default 100, at most 1000).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=1000))]
        limit: Option<u64>,
    },
    /// Walk the whole hash chain and verify the signed checkpoints. Exits 2 if the chain is
    /// broken or a checkpoint is invalid. With `--file`, verify an exported file offline
    /// instead (it needs only the issuer's JWKS, no admin token); that check is strict: it
    /// also fails if the file holds entries outside the range its header declares, or entries
    /// after its last valid checkpoint (unless `--allow-unsigned-tail`). Add `--checkpoints`
    /// to cross-check the export against checkpoints and prune anchors shipped off the host.
    /// Give `--file` several times, oldest first, to check archives and the retained export
    /// as one log: each file must verify, and each must link to the next (contiguous seqs,
    /// the next file's first `prev_hash` is this file's last entry hash, this file ends at a
    /// checkpoint, and a header anchor in the next file, if present, names this file's end).
    /// It reports where the set starts: from genesis, right after a prune, or at a later seq
    /// whose earlier entries are not covered.
    Verify {
        /// An export made with `audit export` or `audit prune` (JSON Lines, or the `--format
        /// json` object). Repeat it, oldest file first, to verify several files as one log.
        #[arg(long)]
        file: Vec<std::path::PathBuf>,
        /// JWKS file holding the issuer keys; with `--file` and without this, the JWKS is
        /// fetched from `<server>/.well-known/jwks.json`, and the check then only shows that
        /// the file is consistent with the keys the server publishes. Pass keys you saved
        /// yourself for a stronger check.
        #[arg(long, requires = "file")]
        jwks: Option<std::path::PathBuf>,
        /// With `--file`: accept entries after the export's last valid checkpoint, which only
        /// the hash chain covers (an export taken while the log was ahead of its newest
        /// checkpoint). They are still reported as `unsigned_tail`. With several files it
        /// applies to the last one only; every earlier file must end at a checkpoint.
        #[arg(long, requires = "file")]
        allow_unsigned_tail: bool,
        /// With `--file`: checkpoints shipped off the host by `[audit.sink]` (the file sink's
        /// JSON Lines, webhook bodies one per line, or bare checkpoint lines). Every shipped
        /// checkpoint inside the export's range must match the export's checkpoint at that
        /// seq exactly, and the export's entry there must hash to its `head_hash`; one that
        /// differs was signed again after it was shipped (SR-21). Shipped prune anchors are
        /// checked too: the anchor of the boundary right before the export's start must be the
        /// export header's anchor, and an anchor that says entries the export holds were
        /// pruned means the log was rewound. Exits 2 on any mismatch. With several files,
        /// each file is checked against it.
        #[arg(long, requires = "file")]
        checkpoints: Option<std::path::PathBuf>,
    },
    /// Prune the start of the audit log through a checkpoint, after archiving it. Needs
    /// `[audit.retention] prune = "manual"` on the server.
    ///
    /// The steps: ask the server for the plan (the largest boundary its guards allow at or
    /// below `--through`, or for entries older than `--before`); export `from..=through` to a
    /// temporary file next to `--archive` (mode 0600 on Unix), flushed to disk; verify it
    /// strictly with the JWKS (`--jwks`, else the server's `/.well-known/jwks.json`) and check
    /// it is the plan's range; move it to `--archive` (never over an existing file); take the
    /// SHA-256 of its bytes; and `POST /admin/audit/prune` with the archive's first seq and
    /// last entry hash, which the server checks before it signs that digest into the prune
    /// anchor. Nothing on the server changes before that last request, so a failure or a
    /// crash at any earlier step leaves the log as it was (a temporary `.<name>.partial-*`
    /// file may be left). The anchor the server answers is checked against the archive.
    ///
    /// If the request fails after the archive was written, the archive is kept: repeat with
    /// `--reuse-archive`, which verifies the file again, checks that it starts where the log
    /// now starts, and sends the same digest. A request that already succeeded answers with
    /// the same anchor. Exits 2 when the server refuses (a guard, printed with its code),
    /// nothing can be pruned, the archive does not fit, or the answered anchor does not match
    /// the archive (the prune was committed); 1 on an error.
    Prune {
        /// Prune entries older than this RFC 3339 time (up to the newest checkpoint that is).
        #[arg(long, value_parser = parse_rfc3339, required_unless_present_any = ["through", "reuse_archive"], conflicts_with = "through")]
        before: Option<String>,
        /// Prune at most through this seq; the boundary is the newest checkpoint the guards
        /// allow at or below it.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        through: Option<u64>,
        /// Where to write the archive, the export of the pruned entries (mode 0600 on Unix).
        /// Refused if the file exists. Keep it off the host: it is the only copy of those
        /// entries.
        #[arg(long, value_name = "PATH", required_unless_present = "dry_run")]
        archive: Option<std::path::PathBuf>,
        /// JWKS file holding the issuer keys to verify the archive with; without it the JWKS
        /// is fetched from `<server>/.well-known/jwks.json`, which only shows that the archive
        /// is consistent with the keys the server publishes.
        #[arg(long)]
        jwks: Option<std::path::PathBuf>,
        /// Print the plan and stop. Changes nothing.
        #[arg(long, conflicts_with = "reuse_archive")]
        dry_run: bool,
        /// The archive already exists from an earlier run whose request failed: verify it
        /// again, take its digest and send the prune for its last seq (which `--through`, if
        /// given, must equal).
        #[arg(long, conflicts_with = "before", requires = "archive")]
        reuse_archive: bool,
    },
    /// Shrink the server's SQLite file after a prune, offline, with the server stopped. Talks
    /// to no server and needs no token. Take a backup first.
    ///
    /// A prune frees pages inside the file but the file does not get smaller. This runs
    /// SQLite's `VACUUM` on the file in place and truncates its write-ahead log, between
    /// checks. It refuses, and changes nothing, when the file is in use (the server's
    /// `<db>.lock` is held, or SQLite's exclusive lock cannot be taken within 2 seconds),
    /// when it is not in WAL mode or is on a network filesystem, when `PRAGMA
    /// integrity_check` is not `ok`, when the schema version is not the one this
    /// attenuo reads, when the hash chain does not verify, or when there is not enough free
    /// space for `VACUUM`'s copy. After `VACUUM` it checks that the integrity check, the schema
    /// version, the entry count, the chain head, the prune marker, the newest anchor and every
    /// row of every table are as before. It writes no audit entry. Exits 2 on a refusal, 3
    /// when the check after `VACUUM` fails or cannot run (restore the backup), 1 on an
    /// error.
    Compact {
        /// The database file: the server's `[audit] sqlite_path`.
        #[arg(long, value_name = "PATH")]
        db: std::path::PathBuf,
        /// Run the checks before `VACUUM` and print what would be freed. Changes nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Export entries `--from` to `--to` (inclusive) and the checkpoints inside that range.
    /// Defaults to the whole log. Writes to stdout unless `--out` is given.
    Export {
        /// First sequence number. Default: the first entry of the log (1, or one above the
        /// boundary of a prune, whose export then carries the signed anchor).
        #[arg(long)]
        from: Option<u64>,
        /// Last sequence number. Default: the head of the log.
        #[arg(long)]
        to: Option<u64>,
        /// `jsonl` streams one object per line; `json` writes a single object.
        #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl)]
        format: ExportFormat,
        /// Write here instead of stdout. A regular file (or a new one) is written through a
        /// temporary file and replaced only when the export ended cleanly, keeping the old
        /// file's mode; a symlink, FIFO, device or path under /dev or /proc is written
        /// directly.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Keep only records of this kind: decision, tool_result, approval_request,
        /// approval_grant, exchange, root_token, lease_renew, lease_revoke, admin or search. A refused exchange or renewal is a `decision`,
        /// not an `exchange` or `lease_renew`; `--tool token.exchange --decision deny` exports
        /// those. A filtered export has gaps in its hash chain, so `audit verify --file`
        /// refuses it; verify an unfiltered export, then filter.
        #[arg(long, value_parser = parse_record_kind)]
        kind: Option<attenuo_core::RecordKind>,
        /// Keep only records of this delegation chain (the `chain_id` field: the lease id of
        /// the chain's first hop). Same verification caveat as `--kind`.
        #[arg(long)]
        chain_id: Option<String>,
        /// Keep only records for this tool, as `audit tail --tool` (`token.exchange`,
        /// `lease.renew`, `admin.*` or an MCP tool name). Same verification caveat as `--kind`.
        #[arg(long, value_parser = NonEmptyStringValueParser::new())]
        tool: Option<String>,
        /// Keep only records with this decision, `allow` or `deny`, as `audit tail
        /// --decision`. Same verification caveat as `--kind`.
        #[arg(long, value_enum)]
        decision: Option<DecisionArg>,
    },
}

fn parse_record_kind(s: &str) -> Result<attenuo_core::RecordKind, String> {
    s.parse()
}

/// The server's `decision` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DecisionArg {
    Allow,
    Deny,
}

impl From<DecisionArg> for attenuo_core::Decision {
    fn from(d: DecisionArg) -> Self {
        match d {
            DecisionArg::Allow => Self::Allow,
            DecisionArg::Deny => Self::Deny,
        }
    }
}

/// Filters of `GET /admin/audit`, all exact matches combined with AND. Checked here as far as
/// the server would check them, so a typo fails before any request.
#[derive(Debug, Default, Args)]
pub(crate) struct AuditFilter {
    /// Record kind: decision, tool_result, approval_request, approval_grant, exchange,
    /// root_token, lease_renew, lease_revoke, admin or search. Repeatable, or comma-separated;
    /// any of them matches.
    #[arg(long, value_parser = parse_record_kind, value_delimiter = ',')]
    pub kind: Vec<attenuo_core::RecordKind>,
    /// `allow` or `deny`.
    #[arg(long, value_enum)]
    pub decision: Option<DecisionArg>,
    /// The record's reason (`policy_deny`, `lease_revoked`, ...).
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub reason: Option<String>,
    /// The originating user (`originating_subject`).
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub subject: Option<String>,
    /// An agent anywhere in the record's chain.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub agent: Option<String>,
    /// A lease anywhere in the record's chain.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub lease: Option<String>,
    /// The MCP upstream the call went to (the record's `server`; not the attenuo server URL,
    /// which is the global `--server` before the subcommand).
    #[arg(long, value_name = "NAME", value_parser = NonEmptyStringValueParser::new())]
    pub upstream: Option<String>,
    /// Deprecated spelling of `--upstream`.
    #[arg(
        long = "server",
        value_name = "NAME",
        hide = true,
        conflicts_with = "upstream",
        value_parser = NonEmptyStringValueParser::new()
    )]
    pub server_deprecated: Option<String>,
    /// The tool. attenuo's own records use `token.root`, `token.exchange`, `lease.renew` and
    /// `admin.*`: `--tool token.exchange --decision deny` lists refused exchanges, `--tool
    /// lease.renew --decision deny` refused renewals.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub tool: Option<String>,
    /// The delegation chain (`chain_id`: the lease id of its first hop).
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub chain_id: Option<String>,
    /// Records at or after this RFC 3339 time.
    #[arg(long, value_parser = parse_rfc3339)]
    pub since: Option<String>,
    /// Records strictly before this RFC 3339 time.
    #[arg(long, value_parser = parse_rfc3339)]
    pub until: Option<String>,
}

impl AuditFilter {
    /// The filter as query parameters, each with a leading `&` (empty when there is none).
    pub(crate) fn query(&self) -> String {
        use crate::client::query_escape;
        let mut q = String::new();
        if !self.kind.is_empty() {
            let kinds: Vec<String> = self.kind.iter().map(|k| k.to_string()).collect();
            q.push_str(&format!("&kind={}", query_escape(&kinds.join(","))));
        }
        if let Some(d) = self.decision {
            let d = match d {
                DecisionArg::Allow => "allow",
                DecisionArg::Deny => "deny",
            };
            q.push_str(&format!("&decision={d}"));
        }
        let text = [
            ("reason", &self.reason),
            ("subject", &self.subject),
            ("agent", &self.agent),
            ("lease", &self.lease),
            ("server", &self.upstream),
            ("tool", &self.tool),
            ("chain_id", &self.chain_id),
            ("since", &self.since),
            ("until", &self.until),
        ];
        for (name, value) in text {
            if let Some(v) = value {
                q.push_str(&format!("&{name}={}", query_escape(v)));
            }
        }
        q
    }
}

/// Accept an RFC 3339 time and keep it as written, for the server to parse again.
fn parse_rfc3339(s: &str) -> Result<String, String> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(s, &Rfc3339)
        .map(|_| s.to_string())
        .map_err(|_| format!("`{s}` is not an RFC 3339 time (like 2026-10-23T09:00:00Z)"))
}

/// Output format of `audit export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExportFormat {
    Jsonl,
    Json,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PolicyCmd {
    /// Re-read the policy file on the server.
    Reload,
    /// Show the policy set the server has in force: file, digest, load time and each policy's
    /// text. After an edit that was not reloaded, this is still the old text.
    Show,
    /// Lint the policy file as it is on the server's disk now, against the running schema,
    /// without loading it. Exit 0 when a reload would succeed, 2 when the file has errors.
    Check,
    /// Dry run: what the loaded policies decide for one call. No lease check and no audit
    /// record. Exit 0 for allow, 2 for deny.
    Evaluate(EvaluateArgs),
    /// Run YAML policy test files, offline by default (`--via` sends them to a server). Exit 0
    /// if every case passes, 2 if any fails, 1 if a file cannot be run. Ends with the policies
    /// no case exercised.
    Test(TestArgs),
    /// Parse a Cedar policy file and validate it against the generated schema, printing
    /// errors with line and column. Exit 0 if clean, 2 if it has errors.
    Lint {
        /// The Cedar policy file.
        policy: std::path::PathBuf,
        /// Server config whose `[policy.catalog]` declares the tools (or a JSON catalog).
        /// Without it, tools are declared from the policy's own `<server>/<tool>` action names
        /// and a note says what could not be checked (tool attributes, input types).
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// Cedar schema file replacing the built-in base schema (the entity types), over the
        /// config's `[policy] schema_path`. It must keep the default's entity types, attributes
        /// and hierarchy.
        #[arg(long, value_name = "PATH")]
        schema_file: Option<std::path::PathBuf>,
        /// Also print the generated schema the policy was validated against.
        #[arg(long)]
        schema: bool,
    },
}

/// `policy test`: the files and how to run them.
#[derive(Debug, Args)]
pub(crate) struct TestArgs {
    /// Test files (format documented in docs/guides/writing-policies.md).
    #[arg(required = true)]
    pub files: Vec<std::path::PathBuf>,
    /// Exit 2 when some policy was not exercised by any case (no case's decision depended on
    /// it), even if every case passed.
    #[arg(long)]
    pub fail_on_unexercised: bool,
    /// Cedar schema file replacing the built-in base schema (the entity types) for every test
    /// file, over any `[policy] schema_path` of the config a test file's `catalog` names. It
    /// must keep the default's entity types, attributes and hierarchy. Only with `--via local`.
    #[arg(long, value_name = "PATH")]
    pub schema_file: Option<std::path::PathBuf>,
    /// Run again whenever a test file, or a policy, catalog, config or schema file one of them
    /// reads, changes (polled every 250 ms, settled for 200 ms). Clears the screen before each
    /// run; stop with Ctrl-C.
    #[arg(long)]
    pub watch: bool,
    /// Where the cases are decided: `local` (default, the in-process engine, offline),
    /// `authzen` (each case is sent to `POST /access/v1/evaluation` of the server named by the
    /// global `--server`, with `--token` as the bearer) or `admin-evaluate` (each case, with its
    /// own chain, is sent to that server's `POST /admin/policies/evaluate` dry run, with the
    /// admin token, its `budget` too; nothing is audited or charged).
    #[arg(long, value_enum, default_value_t = Via::Local)]
    pub via: Via,
    /// With `--via authzen`: the delegation token whose chain makes every call.
    #[command(flatten)]
    pub token: TokenSource,
}

/// Where `policy test` decides the cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Via {
    /// The in-process engine built from the test file (offline).
    Local,
    /// A running server's AuthZEN endpoint.
    Authzen,
    /// A running server's admin dry run, `POST /admin/policies/evaluate`.
    AdminEvaluate,
}

/// `policy evaluate`: the call, and the chain it is made for (from a token or a file).
#[derive(Debug, Args)]
pub(crate) struct EvaluateArgs {
    /// Delegation token whose chain makes the call, or `-` to read it from stdin. An expired
    /// token is accepted (the answer says so). Without this flag, `--token-file` or
    /// `--chain-file`, `ATTENUO_TOKEN` is used.
    #[arg(long, conflicts_with_all = ["token_file", "chain_file"])]
    pub token: Option<String>,
    /// Read the delegation token from the first line of this file.
    #[arg(long, value_name = "PATH", conflicts_with = "chain_file")]
    pub token_file: Option<std::path::PathBuf>,
    /// A delegation chain as JSON instead of a token. Only checked for shape: nothing shows
    /// this server issued it.
    #[arg(long, value_name = "PATH")]
    pub chain_file: Option<std::path::PathBuf>,
    /// MCP upstream name.
    #[arg(
        long,
        value_name = "NAME",
        required_unless_present = "server_deprecated"
    )]
    pub upstream: Option<String>,
    /// Deprecated spelling of `--upstream`.
    #[arg(
        long = "server",
        value_name = "NAME",
        hide = true,
        conflicts_with = "upstream"
    )]
    pub server_deprecated: Option<String>,
    /// Tool name.
    #[arg(long)]
    pub tool: String,
    /// Tool argument `key=value` (`key:=json`). Repeatable.
    #[arg(long = "arg", value_parser = parse_kv)]
    pub args: Vec<(String, Value)>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthzenCmd {
    /// Ask the PDP whether the token's chain may make this call, without making it.
    Eval {
        /// The delegation token, sent as the bearer.
        #[command(flatten)]
        token: TokenSource,
        /// MCP upstream name.
        #[arg(long, value_name = "NAME", default_value = "github")]
        upstream: String,
        /// Deprecated spelling of `--upstream`.
        #[arg(
            long = "server",
            value_name = "NAME",
            hide = true,
            conflicts_with = "upstream"
        )]
        server_deprecated: Option<String>,
        /// Tool name.
        #[arg(long)]
        tool: String,
        /// Tool argument `key=value` (`key:=json`). Repeatable.
        #[arg(long = "arg", value_parser = parse_kv)]
        args: Vec<(String, Value)>,
    },
    /// List the catalogued tools of an upstream that the token's chain may call with these
    /// arguments (AuthZEN action search). Nothing is called or charged; the server writes one
    /// `search` audit record.
    Search {
        /// The delegation token, sent as the bearer.
        #[command(flatten)]
        token: TokenSource,
        /// MCP upstream name.
        #[arg(long, value_name = "NAME", default_value = "github")]
        upstream: String,
        /// Argument `key=value` (`key:=json`) every candidate is decided with. Repeatable.
        #[arg(long = "arg", value_parser = parse_kv)]
        args: Vec<(String, Value)>,
        /// How many catalogued tools one page evaluates (the server clamps it to its
        /// `[authzen] max_batch`).
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
        limit: Option<u64>,
        /// Ask for the page after this one: the `next_token` a previous search printed.
        #[arg(long, value_name = "TOKEN", conflicts_with = "all")]
        page_token: Option<String>,
        /// Follow `next_token` and print every page's results.
        #[arg(long)]
        all: bool,
    },
}

/// Turn `--cap` values into capability objects. A value starting with `{` is a full
/// capability (JSON, may carry constraints and limits); anything else is
/// `server:tool[,server:tool...]`.
pub(crate) fn parse_caps(raw: &[String]) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::new();
    for item in raw {
        let item = item.trim();
        if item.starts_with('{') {
            let cap: attenuo_core::Capability = serde_json::from_str(item)
                .map_err(|e| anyhow::anyhow!("invalid capability JSON `{item}`: {e}"))?;
            out.push(serde_json::to_value(cap)?);
            continue;
        }
        for part in item.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (server, tool) = part
                .split_once(':')
                .filter(|(s, t)| !s.is_empty() && !t.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("capability `{part}` must look like `server:tool`")
                })?;
            out.push(serde_json::to_value(attenuo_core::Capability::new(
                server, tool,
            ))?);
        }
    }
    Ok(out)
}

/// Warnings about capabilities as [`parse_caps`] returns them: a `prefix` constraint on an
/// argument that looks like a file path, where `path_prefix` is meant
/// ([`attenuo_core::Capability::path_prefix_warnings`]). The request is sent anyway.
pub(crate) fn cap_warnings(caps: &[Value]) -> Vec<String> {
    caps.iter()
        .filter_map(|v| serde_json::from_value::<attenuo_core::Capability>(v.clone()).ok())
        .flat_map(|c| c.path_prefix_warnings())
        .collect()
}

/// Parse `key=value` (a string) or `key:=json` (any JSON value).
pub(crate) fn parse_kv(s: &str) -> Result<(String, Value), String> {
    let (left, right) = s
        .split_once('=')
        .ok_or_else(|| format!("expected key=value or key:=json, got `{s}`"))?;
    let (key, raw_json) = match left.strip_suffix(':') {
        Some(k) => (k, true),
        None => (left, false),
    };
    if key.is_empty() {
        return Err(format!("empty key in `{s}`"));
    }
    let value = if raw_json {
        serde_json::from_str(right).map_err(|e| format!("`{key}`: invalid JSON: {e}"))?
    } else {
        Value::String(right.to_string())
    };
    Ok((key.to_string(), value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("attenuo").chain(args.iter().copied()))
    }

    #[test]
    fn clap_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn kv_forms() {
        assert_eq!(
            parse_kv("repo=acme/api").unwrap(),
            ("repo".into(), json!("acme/api"))
        );
        assert_eq!(parse_kv("n:=5").unwrap(), ("n".into(), json!(5)));
        assert_eq!(
            parse_kv("o:={\"a\":[1]}").unwrap(),
            ("o".into(), json!({"a": [1]}))
        );
        // Only the first `=` splits, so values may contain `=`.
        assert_eq!(parse_kv("q=a=b").unwrap(), ("q".into(), json!("a=b")));
        assert!(parse_kv("novalue").is_err());
        assert!(parse_kv("=x").is_err());
        assert!(parse_kv("n:=notjson").is_err());
    }

    #[test]
    fn call_parses_both_server_flags() {
        let cli = parse(&[
            "--server",
            "http://ob:9",
            "--admin-token",
            "t",
            "call",
            "--token",
            "T",
            "--upstream",
            "github",
            "--tool",
            "read_file",
            "--arg",
            "repo=acme/api",
            "--arg",
            "depth:=2",
        ])
        .unwrap();
        assert_eq!(cli.server, "http://ob:9");
        assert_eq!(cli.admin_token.as_deref(), Some("t"));
        let Command::Call(c) = cli.command else {
            panic!("not call")
        };
        assert_eq!((c.upstream(), c.tool.as_str()), ("github", "read_file"));
        assert_eq!(c.args.len(), 2);
        assert_eq!(c.args[1].1, json!(2));
    }

    /// K-13: a subcommand's MCP upstream is `--upstream`; its old `--server` spelling still
    /// works, is hidden from help and is warned about once, and the two cannot be combined.
    #[test]
    fn subcommand_server_is_a_deprecated_upstream() {
        let cases: [(&[&str], &str); 5] = [
            (&["call", "--tool", "t"], "call"),
            (&["tools"], "tools"),
            (&["authzen", "eval", "--tool", "t"], "authzen eval"),
            (
                &["policy", "evaluate", "--tool", "t", "--token", "x"],
                "policy evaluate",
            ),
            (&["audit", "tail"], "audit tail"),
        ];
        let upstream_of = |cli: &Cli| -> Option<String> {
            match &cli.command {
                Command::Call(a) => Some(a.upstream().to_string()),
                Command::Tools(a) => Some(a.upstream().to_string()),
                Command::Policy(PolicyCmd::Evaluate(a)) => Some(a.upstream().to_string()),
                Command::Audit(AuditCmd::Tail { filter, .. }) => filter.upstream.clone(),
                Command::Authzen(AuthzenCmd::Eval { upstream, .. }) => Some(upstream.clone()),
                _ => panic!("unexpected command"),
            }
        };
        for (args, name) in cases {
            let with = |flag: &str| {
                let mut a = vec!["--server", "http://ob:9"];
                a.extend_from_slice(args);
                a.extend_from_slice(&[flag, "gh"]);
                parse(&a)
            };
            let mut cli = with("--upstream").unwrap();
            assert!(cli.resolve_deprecated().is_empty(), "{name}");
            assert_eq!(upstream_of(&cli).as_deref(), Some("gh"), "{name}");
            assert_eq!(cli.server, "http://ob:9", "{name}");

            let mut cli = with("--server").unwrap();
            assert_eq!(
                cli.resolve_deprecated(),
                vec![server_flag_warning(name)],
                "{name}"
            );
            assert_eq!(upstream_of(&cli).as_deref(), Some("gh"), "{name}");
            assert_eq!(cli.server, "http://ob:9", "{name}");
            // Resolved once: a second pass has nothing left to warn about.
            assert!(cli.resolve_deprecated().is_empty(), "{name}");

            let mut both: Vec<&str> = args.to_vec();
            both.extend_from_slice(&["--upstream", "a", "--server", "b"]);
            assert!(parse(&both).is_err(), "{name}: both flags must conflict");
        }
        assert!(server_flag_warning("call").starts_with("warning: `call --server` is deprecated"));
        assert!(!server_flag_warning("call").contains('\n'));
        // `call` and `tools` still need one of the two.
        assert!(parse(&["call", "--tool", "t"]).is_err());
        assert!(parse(&["tools"]).is_err());

        // Hidden from help; `--upstream` is shown.
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        for path in [
            &["call"][..],
            &["tools"],
            &["authzen", "eval"],
            &["policy", "evaluate"],
            &["audit", "tail"],
        ] {
            let mut sub = &mut cmd;
            for p in path {
                sub = sub.find_subcommand_mut(p).unwrap();
            }
            let help = sub.render_long_help().to_string();
            assert!(help.contains("--upstream"), "{path:?}: {help}");
            assert!(!help.contains("--server <"), "{path:?}: {help}");
        }
    }

    #[test]
    fn authzen_search_flags() {
        let cli = parse(&["authzen", "search", "--arg", "repo=a/b", "--limit", "5"]).unwrap();
        match cli.command {
            Command::Authzen(AuthzenCmd::Search {
                upstream,
                args,
                limit,
                page_token,
                all,
                ..
            }) => {
                assert_eq!(upstream, "github");
                assert_eq!(args, vec![("repo".to_string(), json!("a/b"))]);
                assert_eq!((limit, page_token, all), (Some(5), None, false));
            }
            _ => panic!("not authzen search"),
        }
        assert!(parse(&["authzen", "search", "--limit", "0"]).is_err());
        assert!(parse(&["authzen", "search", "--all", "--page-token", "t"]).is_err());
        assert!(parse(&[
            "authzen",
            "search",
            "--page-token",
            "t",
            "--token-file",
            "/t"
        ])
        .is_ok());
    }

    #[test]
    fn exchange_splits_caps_and_requires_one() {
        let cli = parse(&[
            "token",
            "exchange",
            "--subject-token",
            "J",
            "--actor",
            "coder",
            "--cap",
            "github:read_file,github:read_dir",
            "--cap",
            "github:search",
        ])
        .unwrap();
        let Command::Token(TokenCmd::Exchange(e)) = cli.command else {
            panic!("not exchange")
        };
        assert_eq!(e.caps.len(), 2);
        assert_eq!(parse_caps(&e.caps).unwrap().len(), 3);
        assert_eq!(e.client_id, None);
        let cli = parse(&[
            "token",
            "exchange",
            "--subject-token",
            "J",
            "--actor",
            "coder",
            "--client-secret",
            "s3cret",
            "--cap",
            "github:search",
        ])
        .unwrap();
        let Command::Token(TokenCmd::Exchange(e)) = cli.command else {
            panic!("not exchange")
        };
        assert_eq!(e.client_secret.as_deref(), Some("s3cret"));
        assert!(parse(&["token", "exchange", "--subject-token", "J", "--actor", "c"]).is_err());
    }

    /// `--subject-token-type` picks the URN; `jwt` (an exchange from hop n) is the default.
    #[test]
    fn exchange_subject_token_type_sets_the_urn() {
        let ex = |extra: &[&str]| {
            let mut a = vec!["token", "exchange", "--actor", "planner", "--cap", "g:t"];
            a.extend_from_slice(extra);
            match parse(&a).map(|c| c.command) {
                Ok(Command::Token(TokenCmd::Exchange(e))) => Ok(e),
                Ok(_) => panic!("not exchange"),
                Err(e) => Err(e),
            }
        };
        let e = ex(&[]).unwrap();
        assert_eq!(e.subject_token_type, SubjectTokenType::Jwt);
        assert_eq!(
            e.subject_token_type.urn(),
            "urn:ietf:params:oauth:token-type:jwt"
        );
        assert!(!e.subject_token_type.is_hop0());
        for (flag, urn) in [
            ("jwt", "urn:ietf:params:oauth:token-type:jwt"),
            ("id-token", "urn:ietf:params:oauth:token-type:id_token"),
            ("id-jag", "urn:ietf:params:oauth:token-type:id-jag"),
        ] {
            let e = ex(&["--subject-token-type", flag]).unwrap();
            assert_eq!(e.subject_token_type.urn(), urn);
            assert_eq!(e.subject_token_type.is_hop0(), flag != "jwt");
            e.check_hop0().unwrap();
        }
        for bad in ["id_token", "jag", ""] {
            assert!(ex(&["--subject-token-type", bad]).is_err(), "{bad:?}");
        }
        // The subject token's sources, the agent's authentication and the rest of the request
        // are the same flags as for an exchange from hop n.
        let e = ex(&[
            "--subject-token-type",
            "id-token",
            "--subject-token-file",
            "/run/id",
            "--client-secret-stdin",
            "--no-delegation",
            "--ttl-seconds",
            "60",
            "--dpop-key",
            "/k",
        ])
        .unwrap();
        e.check_hop0().unwrap();
        assert!(e.subject_token_file.is_some() && e.client_secret_stdin && e.no_delegation);
    }

    /// At hop 0 there is no parent token: the parent's sign-off flags are refused (the server
    /// would ignore them), and a client assertion needs its audience given, since the IdP
    /// credential's `iss` is not the server's.
    #[test]
    fn hop0_refuses_what_only_an_exchange_from_hop_n_uses() {
        let ex = |extra: &[&str]| {
            let mut a = vec!["token", "exchange", "--actor", "planner", "--cap", "g:t"];
            a.extend_from_slice(extra);
            let Command::Token(TokenCmd::Exchange(e)) = parse(&a).unwrap().command else {
                panic!("not exchange")
            };
            e
        };
        for ty in ["id-token", "id-jag"] {
            for extra in [
                ["--subject-token-dpop-file", "/s"].as_slice(),
                ["--dpop-key", "/k", "--subject-dpop-key", "/p"].as_slice(),
                ["--client-key", "/c"].as_slice(),
            ] {
                let mut a = vec!["--subject-token-type", ty];
                a.extend_from_slice(extra);
                let err = ex(&a).check_hop0().unwrap_err().to_string();
                assert!(err.contains(ty), "{err}");
                // The same flags at hop n are fine (the server checks them).
                ex(extra).check_hop0().unwrap();
            }
            ex(&[
                "--subject-token-type",
                ty,
                "--client-key",
                "/c",
                "--client-assertion-audience",
                "https://attenuo.example",
            ])
            .check_hop0()
            .unwrap();
        }
    }

    #[test]
    fn secrets_can_come_from_stdin_or_a_file() {
        let cli = parse(&["--admin-token-stdin", "lease", "show", "L"]).unwrap();
        assert!(cli.admin_token_stdin && cli.admin_token.is_none());
        let cli = parse(&["--admin-token-file", "/run/s", "lease", "show", "L"]).unwrap();
        assert_eq!(
            cli.admin_token_file.as_deref(),
            Some(std::path::Path::new("/run/s"))
        );
        let ex = |extra: &[&str]| {
            let mut a = vec![
                "token",
                "exchange",
                "--subject-token",
                "J",
                "--actor",
                "c",
                "--cap",
                "g:t",
            ];
            a.extend_from_slice(extra);
            parse(&a)
        };
        let Command::Token(TokenCmd::Exchange(e)) = ex(&["--client-secret-stdin"]).unwrap().command
        else {
            panic!("not exchange")
        };
        assert!(e.client_secret_stdin && e.client_secret.is_none());
        let Command::Token(TokenCmd::Exchange(e)) =
            ex(&["--client-secret-file", "/run/c"]).unwrap().command
        else {
            panic!("not exchange")
        };
        assert!(e.client_secret_file.is_some());
    }

    #[test]
    fn secret_sources_are_mutually_exclusive() {
        assert!(parse(&[
            "--admin-token",
            "t",
            "--admin-token-stdin",
            "lease",
            "show",
            "L"
        ])
        .is_err());
        assert!(parse(&[
            "--admin-token-stdin",
            "--admin-token-file",
            "/x",
            "lease",
            "show",
            "L"
        ])
        .is_err());
        let both = [
            "token",
            "exchange",
            "--subject-token",
            "J",
            "--actor",
            "c",
            "--cap",
            "g:t",
        ];
        for extra in [
            ["--client-secret", "s", "--client-secret-stdin"].as_slice(),
            ["--client-secret", "s", "--client-secret-file", "/x"].as_slice(),
            ["--client-secret-stdin", "--client-secret-file", "/x"].as_slice(),
            ["--client-key", "/k", "--client-secret", "s"].as_slice(),
            ["--client-key", "/k", "--client-secret-stdin"].as_slice(),
            ["--client-key", "/k", "--client-secret-file", "/x"].as_slice(),
            ["--client-assertion-audience", "https://a"].as_slice(),
        ] {
            let mut a = both.to_vec();
            a.extend_from_slice(extra);
            assert!(parse(&a).is_err(), "{extra:?}");
        }
        let mut a = both.to_vec();
        a.extend_from_slice(&[
            "--client-key",
            "/k",
            "--client-assertion-audience",
            "https://a",
        ]);
        let Command::Token(TokenCmd::Exchange(e)) = parse(&a).unwrap().command else {
            panic!()
        };
        assert_eq!(e.client_key.as_deref(), Some(std::path::Path::new("/k")));
        assert_eq!(e.client_assertion_audience.as_deref(), Some("https://a"));
    }

    /// `key gen` makes exactly one kind of key; `--kid` is for client keys.
    #[test]
    fn key_gen_takes_dpop_or_client() {
        let Command::Key(KeyCmd::Gen { client, kid, dpop }) =
            parse(&["key", "gen", "--client", "/c", "--kid", "k1"])
                .unwrap()
                .command
        else {
            panic!()
        };
        assert_eq!(
            (client.is_some(), kid.as_deref(), dpop),
            (true, Some("k1"), None)
        );
        assert!(parse(&["key", "gen", "--dpop", "/d"]).is_ok());
        for bad in [
            &["key", "gen"][..],
            &["key", "gen", "--dpop", "/d", "--client", "/c"],
            &["key", "gen", "--dpop", "/d", "--kid", "k1"],
            &["key", "gen", "--client", "/c", "--kid", ""],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// SR-35: `--token` and `--subject-token` take `-` for stdin and have `--…-file` forms, which
    /// are mutually exclusive with the flag; with neither, `ATTENUO_TOKEN` is read at run time
    /// (not by clap, so the environment never conflicts with a file flag).
    #[test]
    fn delegation_tokens_from_stdin_or_a_file() {
        let call = |extra: &[&str]| {
            let mut a = vec!["call", "--upstream", "github", "--tool", "t"];
            a.extend_from_slice(extra);
            parse(&a).map(|c| match c.command {
                Command::Call(c) => c.token,
                _ => panic!("not call"),
            })
        };
        let t = call(&["--token", "-"]).unwrap();
        assert_eq!(t.token.as_deref(), Some("-"));
        let t = call(&["--token-file", "/run/t"]).unwrap();
        assert!(t.token.is_none() && t.token_file.is_some());
        let t = call(&[]).unwrap();
        assert!(t.token.is_none() && t.token_file.is_none());
        assert!(call(&["--token", "x", "--token-file", "/run/t"]).is_err());
        for cmd in [
            ["tools", "--upstream", "github", "--token-file", "/t"].as_slice(),
            ["authzen", "eval", "--tool", "t", "--token-file", "/t"].as_slice(),
        ] {
            assert!(parse(cmd).is_ok(), "{cmd:?}");
        }

        let ex = |extra: &[&str]| {
            let mut a = vec!["token", "exchange", "--actor", "c", "--cap", "g:t"];
            a.extend_from_slice(extra);
            parse(&a).map(|c| match c.command {
                Command::Token(TokenCmd::Exchange(e)) => e,
                _ => panic!("not exchange"),
            })
        };
        assert!(ex(&[]).unwrap().subject_token.is_none());
        assert!(ex(&["--subject-token-file", "/t"])
            .unwrap()
            .subject_token_file
            .is_some());
        assert!(ex(&["--subject-token", "J", "--subject-token-file", "/t"]).is_err());
    }

    #[test]
    fn root_may_act_and_body() {
        let root = |extra: &[&str]| {
            let mut args = vec!["token", "root", "--subject", "alice", "--agent", "planner"];
            args.extend_from_slice(extra);
            match parse(&args).unwrap().command {
                Command::Token(TokenCmd::Root(r)) => r,
                _ => panic!("not root"),
            }
        };
        let plain = root(&[]);
        assert_eq!(plain.may_act_claim().unwrap(), None);
        assert_eq!(
            plain.request_body().unwrap(),
            serde_json::json!({"subject": "alice", "issuer": "https://idp.example", "agent": "planner"})
        );
        let full = root(&[
            "--may-act",
            "coder, reviewer",
            "--may-act",
            "tester",
            "--cap",
            "github:read_file",
            "--ttl-seconds",
            "60",
            "--attr",
            "mfa:=true",
        ]);
        assert_eq!(
            full.may_act_claim().unwrap(),
            Some(vec![
                "coder".to_string(),
                "reviewer".into(),
                "tester".into()
            ])
        );
        let body = full.request_body().unwrap();
        assert_eq!(
            body["may_act"],
            serde_json::json!({"sub": ["coder", "reviewer", "tester"]})
        );
        assert_eq!(body["ttl_seconds"], 60);
        assert_eq!(body["attributes"], serde_json::json!({"mfa": true}));
        assert_eq!(body["capabilities"].as_array().unwrap().len(), 1);

        // --no-delegation sends an explicit empty list; it conflicts with --may-act.
        let nobody = root(&["--no-delegation"]);
        assert_eq!(nobody.may_act_claim().unwrap(), Some(Vec::new()));
        assert_eq!(
            nobody.request_body().unwrap()["may_act"],
            serde_json::json!({"sub": []})
        );
        assert!(parse(&[
            "token",
            "root",
            "--subject",
            "alice",
            "--agent",
            "planner",
            "--no-delegation",
            "--may-act",
            "coder",
        ])
        .is_err());
        // An all-empty --may-act is refused, not silently dropped (which would fall back to
        // the grant's list).
        for empty in ["", " , "] {
            let r = root(&["--may-act", empty]);
            assert!(r.may_act_claim().is_err());
            let err = r.request_body().unwrap_err().to_string();
            assert!(err.contains("--no-delegation"), "{err}");
        }
    }

    #[test]
    fn exchange_actor_token_from_flag_stdin_or_file() {
        let exchange = |extra: &[&str]| {
            let mut args = vec![
                "token",
                "exchange",
                "--subject-token",
                "J",
                "--actor",
                "coder",
                "--cap",
                "github:read_file",
            ];
            args.extend_from_slice(extra);
            match parse(&args).map(|c| c.command) {
                Ok(Command::Token(TokenCmd::Exchange(e))) => Ok(e),
                Ok(_) => panic!("not exchange"),
                Err(e) => Err(e),
            }
        };
        let none = exchange(&[]).unwrap();
        assert_eq!(none.actor_token(std::io::empty()).unwrap(), None);
        assert_eq!(none.may_act_claim().unwrap(), None);
        // Nobody may exchange it: an explicit empty list.
        let nobody = exchange(&["--no-delegation"]).unwrap();
        assert_eq!(nobody.may_act_claim().unwrap(), Some(Vec::new()));
        assert!(exchange(&["--no-delegation", "--may-act", "x"]).is_err());
        // An empty --may-act is refused, not silently dropped.
        let empty = exchange(&["--may-act", ""]).unwrap();
        assert!(empty.may_act_claim().is_err());
        let commas = exchange(&["--may-act", " , "]).unwrap();
        assert!(commas.may_act_claim().is_err());

        let flag = exchange(&[
            "--actor-token",
            " a.b.c\n",
            "--may-act",
            "x,y",
            "--may-act",
            "z",
        ])
        .unwrap();
        assert_eq!(
            flag.actor_token(std::io::empty()).unwrap().as_deref(),
            Some("a.b.c")
        );
        assert_eq!(
            flag.may_act_claim().unwrap(),
            Some(vec!["x".to_string(), "y".into(), "z".into()])
        );

        let stdin = exchange(&["--actor-token", "-"]).unwrap();
        assert_eq!(
            stdin.actor_token(&b"s.v.id\n"[..]).unwrap().as_deref(),
            Some("s.v.id")
        );
        assert!(stdin.actor_token(&b"  \n"[..]).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("svid.jwt");
        std::fs::write(&path, "f.i.le\n").unwrap();
        let file = exchange(&["--actor-token-file", path.to_str().unwrap()]).unwrap();
        assert_eq!(
            file.actor_token(std::io::empty()).unwrap().as_deref(),
            Some("f.i.le")
        );
        let missing = exchange(&["--actor-token-file", "/nonexistent/svid"]).unwrap();
        assert!(missing.actor_token(std::io::empty()).is_err());
        assert!(exchange(&["--actor-token", "x", "--actor-token-file", "y"]).is_err());
    }

    #[test]
    fn caps_short_and_full() {
        let caps = parse_caps(&[
            "github:read_file".into(),
            r#"{"server":"github","tool":"create_issue","constraints":{"repo":{"op":"prefix","value":"acme/"}}}"#.into(),
        ])
        .unwrap();
        assert_eq!(caps[0], json!({"server": "github", "tool": "read_file"}));
        assert_eq!(caps[1]["constraints"]["repo"]["op"], "prefix");
        assert!(parse_caps(&["nocolon".into()]).is_err());
        // A repository prefix is not taken for a file path.
        assert!(cap_warnings(&caps).is_empty());
        // `path_prefix` passes through; a malformed one is refused before the request, and a
        // `prefix` on a path argument gets a warning.
        let paths = parse_caps(&[
            r#"{"server":"fs","tool":"read_file","constraints":{"path":{"op":"path_prefix","value":"/workspace/"}}}"#.into(),
            r#"{"server":"fs","tool":"write_file","constraints":{"path":{"op":"prefix","value":"/workspace/"}}}"#.into(),
        ])
        .unwrap();
        assert_eq!(paths[0]["constraints"]["path"]["op"], "path_prefix");
        assert_eq!(paths[0]["constraints"]["path"]["value"], "/workspace/");
        let warnings = cap_warnings(&paths);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with("fs:write_file argument \"path\""),
            "{warnings:?}"
        );
        assert!(warnings[0].contains("use `path_prefix`"), "{warnings:?}");
        let bad = parse_caps(&[
            r#"{"server":"fs","tool":"read_file","constraints":{"path":{"op":"path_prefix","value":"/workspace/../etc"}}}"#.into(),
        ])
        .unwrap_err();
        assert!(
            bad.to_string()
                .contains("a path_prefix constraint's path holds a `.` or `..` segment"),
            "{bad}"
        );
        assert!(parse_caps(&["github:".into()]).is_err());
        assert!(parse_caps(&[r#"{"server":1}"#.into()]).is_err());
        // A `range` constraint passes through; a malformed one is refused before the request.
        let ranged = parse_caps(&[
            r#"{"server":"bank","tool":"send_money","constraints":{"amount":{"op":"range","value":{"min":0,"max":2000}}}}"#.into(),
            r#"{"server":"bank","tool":"refund","constraints":{"amount":{"op":"range","value":{"max":50}}}}"#.into(),
        ])
        .unwrap();
        assert_eq!(
            ranged[0]["constraints"]["amount"],
            json!({"op": "range", "value": {"min": 0, "max": 2000}})
        );
        assert_eq!(
            ranged[1]["constraints"]["amount"],
            json!({"op": "range", "value": {"max": 50}})
        );
        for bad in [
            r#"{"op":"range","value":{}}"#,
            r#"{"op":"range","value":{"min":3,"max":1}}"#,
            r#"{"op":"range","value":{"min":0,"maximum":1}}"#,
            r#"{"op":"range","value":{"max":1.5}}"#,
        ] {
            let cap = format!(r#"{{"server":"bank","tool":"t","constraints":{{"amount":{bad}}}}}"#);
            assert!(parse_caps(&[cap]).is_err(), "{bad}");
        }
        // Run limits (ADR-0010) pass through; a kind this version does not know is refused.
        let limited = parse_caps(&[
            r#"{"server":"bank","tool":"send_money","limits":{"calls":1,"sum":{"arg":"amount","max":10}}}"#.into(),
        ])
        .unwrap();
        assert_eq!(
            limited[0]["limits"],
            json!({"calls": 1, "sum": {"arg": "amount", "max": 10}})
        );
        // `distinct` and derived values (phase 2) pass through too.
        let distinct = parse_caps(&[
            r#"{"server":"web","tool":"get_webpage","limits":{"distinct":{"arg":"url","derive":"host","max":1}}}"#.into(),
        ])
        .unwrap();
        assert_eq!(
            distinct[0]["limits"],
            json!({"distinct": {"arg": "url", "derive": "host", "max": 1}})
        );
        for bad in [
            r#"{"server":"bank","tool":"send_money","limits":{"window":{"arg":"to","max":1}}}"#,
            r#"{"server":"web","tool":"get","limits":{"distinct":{"arg":"url","derive":"path","max":1}}}"#,
        ] {
            assert!(parse_caps(&[bad.into()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn json_flag_is_global_and_defaults_apply() {
        let cli = parse(&["audit", "tail", "-n", "5", "-f", "--json"]).unwrap();
        assert!(cli.json);
        assert_eq!(cli.server, DEFAULT_SERVER);
        assert_eq!(cli.admin_server, None);
        let Command::Audit(AuditCmd::Tail { lines, follow, .. }) = cli.command else {
            panic!("not tail")
        };
        assert_eq!((lines, follow), (5, true));
    }

    #[test]
    fn inspect_verify_flags_need_verify() {
        assert!(parse(&["token", "inspect", "a.b.c", "--issuer", "x"]).is_err());
        assert!(parse(&["token", "inspect", "a.b.c", "--verify", "--issuer", "x"]).is_ok());
    }

    #[test]
    fn approval_subcommands() {
        let cli = parse(&["approval", "list", "--chain-id", "L1", "--state", "pending"]).unwrap();
        let Command::Approval(ApprovalCmd::List {
            chain_id, state, ..
        }) = cli.command
        else {
            panic!("not list")
        };
        assert_eq!(chain_id.as_deref(), Some("L1"));
        assert_eq!(state.as_deref(), Some("pending"));
        assert!(parse(&["approval", "list", "--state", "maybe"]).is_err());
        assert!(parse(&["approval", "list", "--limit", "0"]).is_err());
        assert!(parse(&["approval", "list", "--cursor", "c", "--all"]).is_err());
        assert!(parse(&["approval", "show", "A"]).is_ok());
        assert!(parse(&["approval", "grant", "A"]).is_ok());
        assert!(parse(&["approval", "decline", "A"]).is_ok());
        assert!(parse(&["approval", "grant"]).is_err());
        let cli = parse(&[
            "approval",
            "verify",
            "a.b.c",
            "--jwks",
            "j.json",
            "--call-hash",
            "ab",
            "--jkt",
            "none",
        ])
        .unwrap();
        let Command::Approval(ApprovalCmd::Verify(v)) = cli.command else {
            panic!("not verify")
        };
        assert_eq!(v.token, "a.b.c");
        assert_eq!(v.jwks.as_deref(), Some("j.json"));
        assert_eq!(v.call_hash.as_deref(), Some("ab"));
        assert_eq!(v.jkt.as_deref(), Some("none"));
        assert!(parse(&["approval", "verify"]).is_err());
    }

    #[test]
    fn lease_and_policy_subcommands() {
        let cli = parse(&["lease", "revoke", "L1", "--reason", "demo"]).unwrap();
        let Command::Lease(LeaseCmd::Revoke {
            id,
            reason,
            user,
            chain_id,
            session,
            preview,
        }) = cli.command
        else {
            panic!("not revoke")
        };
        assert_eq!(
            (id.as_deref(), reason.as_deref()),
            (Some("L1"), Some("demo"))
        );
        assert_eq!(
            (user, chain_id, session, preview),
            (None, None, None, false)
        );
        assert!(parse(&["policy", "reload"]).is_ok());
        assert!(parse(&["audit", "verify"]).is_ok());
        assert!(parse(&["audit", "verify", "--file", "a.jsonl", "--jwks", "j.json"]).is_ok());
        assert!(parse(&[
            "audit",
            "verify",
            "--file",
            "a.jsonl",
            "--checkpoints",
            "s.jsonl"
        ])
        .is_ok());
        assert!(
            parse(&["audit", "verify", "--checkpoints", "s.jsonl"]).is_err(),
            "--checkpoints needs --file"
        );
        assert!(
            parse(&["audit", "verify", "--jwks", "j.json"]).is_err(),
            "--jwks only makes sense with --file"
        );
        assert!(
            parse(&["audit", "export", "--from", "5", "--to", "9", "--format", "json"]).is_ok()
        );
        assert!(parse(&["audit", "export", "--format", "xml"]).is_err());
        assert!(parse(&[
            "audit",
            "export",
            "--kind",
            "lease_renew",
            "--chain-id",
            "l1"
        ])
        .is_ok());
        assert!(parse(&["audit", "export", "--kind", "nope"]).is_err());
        assert!(parse(&["nope"]).is_err());
    }

    fn tail(extra: &[&str]) -> Result<(Option<u64>, AuditFilter), clap::Error> {
        let mut a = vec!["audit", "tail"];
        a.extend_from_slice(extra);
        parse(&a).map(|c| match c.command {
            Command::Audit(AuditCmd::Tail { before, filter, .. }) => (before, *filter),
            _ => panic!("not tail"),
        })
    }

    #[test]
    fn tail_without_filters_sends_no_filter() {
        let (before, f) = tail(&[]).unwrap();
        assert_eq!(before, None);
        assert_eq!(f.query(), "");
    }

    #[test]
    fn tail_filters_become_escaped_query_parameters() {
        let (_, f) = tail(&[
            "--kind",
            "decision,exchange",
            "--kind",
            "admin",
            "--decision",
            "deny",
            "--reason",
            "policy_deny",
            "--subject",
            "alice@example.com",
            "--agent",
            "coder",
            "--lease",
            "L 1",
            "--upstream",
            "github",
            "--tool",
            "read_file",
            "--chain-id",
            "c&x",
            "--since",
            "2026-10-23T09:00:00Z",
            "--until",
            "2026-10-23T10:00:00+02:00",
        ])
        .unwrap();
        assert_eq!(f.kind.len(), 3);
        assert_eq!(
            f.query(),
            "&kind=decision%2Cexchange%2Cadmin&decision=deny&reason=policy_deny\
             &subject=alice%40example.com&agent=coder&lease=L%201&server=github\
             &tool=read_file&chain_id=c%26x&since=2026-10-23T09%3A00%3A00Z\
             &until=2026-10-23T10%3A00%3A00%2B02%3A00"
        );
    }

    #[test]
    fn tail_rejects_bad_filter_values_before_any_request() {
        assert!(tail(&["--kind", "nope"]).is_err());
        assert!(tail(&["--decision", "maybe"]).is_err());
        assert!(tail(&["--since", "yesterday"]).is_err());
        assert!(tail(&["--until", "2026-10-23"]).is_err());
        assert!(tail(&["--agent", ""]).is_err());
        assert!(tail(&["--chain-id", ""]).is_err());
    }

    #[test]
    fn tail_before_pages_back_and_excludes_follow() {
        let (before, _) = tail(&["-n", "5", "--before", "40"]).unwrap();
        assert_eq!(before, Some(40));
        assert!(tail(&["--before", "0"]).is_err());
        assert!(tail(&["--before", "40", "--follow"]).is_err());
        // The upstream filter is `--upstream` after the subcommand; `--server` before it is the
        // attenuo server URL.
        let cli = parse(&[
            "--server",
            "http://ob:9",
            "audit",
            "tail",
            "--upstream",
            "github",
        ])
        .unwrap();
        assert_eq!(cli.server, "http://ob:9");
        let Command::Audit(AuditCmd::Tail { filter, .. }) = cli.command else {
            panic!("not tail")
        };
        assert_eq!(filter.query(), "&server=github");
    }

    #[test]
    fn audit_show_takes_a_seq_or_an_id() {
        let show = |extra: &[&str]| {
            let mut a = vec!["audit", "show"];
            a.extend_from_slice(extra);
            parse(&a).map(|c| match c.command {
                Command::Audit(AuditCmd::Show { seq, id }) => (seq, id),
                _ => panic!("not show"),
            })
        };
        assert_eq!(show(&["7"]).unwrap(), (Some(7), None));
        let id = "0b7c4f1e-0000-4000-8000-000000000001";
        assert_eq!(show(&["--id", id]).unwrap(), (None, Some(id.to_string())));
        assert!(show(&[]).is_err(), "one of them is required");
        assert!(show(&["7", "--id", id]).is_err(), "not both");
        assert!(show(&["seven"]).is_err());
    }

    #[test]
    fn audit_checkpoints_paging_flags() {
        let cps = |extra: &[&str]| {
            let mut a = vec!["audit", "checkpoints"];
            a.extend_from_slice(extra);
            parse(&a).map(|c| match c.command {
                Command::Audit(AuditCmd::Checkpoints { cursor, limit }) => (cursor, limit),
                _ => panic!("not checkpoints"),
            })
        };
        assert_eq!(cps(&[]).unwrap(), (None, None));
        assert_eq!(
            cps(&["--cursor", "AQIC", "--limit", "3"]).unwrap(),
            (Some("AQIC".to_string()), Some(3))
        );
        assert!(cps(&["--before", "9"]).is_err(), "removed: use --cursor");
        assert!(cps(&["--limit", "0"]).is_err());
        assert!(cps(&["--limit", "1001"]).is_err());
    }

    #[test]
    fn lease_revoke_takes_exactly_one_target() {
        let Command::Lease(LeaseCmd::Revoke {
            id, user, preview, ..
        }) = parse(&["lease", "revoke", "--user", "alice", "--preview"])
            .unwrap()
            .command
        else {
            panic!("not revoke")
        };
        assert_eq!((id, user.as_deref(), preview), (None, Some("alice"), true));
        let Command::Lease(LeaseCmd::Revoke { chain_id, .. }) =
            parse(&["lease", "revoke", "--chain-id", "L0", "--reason", "x"])
                .unwrap()
                .command
        else {
            panic!("not revoke")
        };
        assert_eq!(chain_id.as_deref(), Some("L0"));
        let Command::Lease(LeaseCmd::Revoke {
            session, preview, ..
        }) = parse(&["lease", "revoke", "--session", "s1", "--preview"])
            .unwrap()
            .command
        else {
            panic!("not revoke")
        };
        assert_eq!((session.as_deref(), preview), (Some("s1"), true));
        for bad in [
            &["lease", "revoke"][..],
            &["lease", "revoke", "--preview"],
            &["lease", "revoke", "L1", "--preview"],
            &["lease", "revoke", "L1", "--user", "alice"],
            &["lease", "revoke", "L1", "--chain-id", "L0"],
            &["lease", "revoke", "--user", "alice", "--chain-id", "L0"],
            &["lease", "revoke", "--user", ""],
            &["lease", "revoke", "--session", ""],
            &["lease", "revoke", "L1", "--session", "s1"],
            &["lease", "revoke", "--session", "s1", "--chain-id", "L0"],
            &["lease", "revoke", "--session", "s1", "--user", "alice"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn lease_tree_takes_max_nodes() {
        let Command::Lease(LeaseCmd::Tree { id, max_nodes }) =
            parse(&["lease", "tree", "L1", "--max-nodes", "50"])
                .unwrap()
                .command
        else {
            panic!("not tree")
        };
        assert_eq!((id.as_str(), max_nodes), ("L1", Some(50)));
        assert!(parse(&["lease", "tree"]).is_err());
        assert!(parse(&["lease", "tree", "L1", "--max-nodes", "0"]).is_err());
    }

    #[test]
    fn budget_refund_needs_a_decision_and_a_reason() {
        let Command::Budget(BudgetCmd::Refund {
            decision_id,
            reason,
        }) = parse(&["budget", "refund", "D1", "--reason", "upstream timed out"])
            .unwrap()
            .command
        else {
            panic!("not refund")
        };
        assert_eq!(
            (decision_id.as_str(), reason.as_str()),
            ("D1", "upstream timed out")
        );
        // `--json` is global, so it goes on either side of the subcommand.
        let cli = parse(&["budget", "refund", "D1", "--reason", "x", "--json"]).unwrap();
        assert!(cli.json);
        assert!(
            parse(&["budget", "refund", "D1"]).is_err(),
            "--reason required"
        );
        assert!(parse(&["budget", "refund", "--reason", "x"]).is_err());
        assert!(parse(&["budget", "refund", "", "--reason", "x"]).is_err());
        assert!(parse(&["budget", "refund", "D1", "--reason", ""]).is_err());
        assert!(parse(&["budget", "refund", "D1", "--reason", "  \t"]).is_err());
        assert!(parse(&["budget"]).is_err());
    }

    #[test]
    fn policy_show_check_and_evaluate() {
        assert!(matches!(
            parse(&["policy", "show"]).unwrap().command,
            Command::Policy(PolicyCmd::Show)
        ));
        assert!(matches!(
            parse(&["policy", "check"]).unwrap().command,
            Command::Policy(PolicyCmd::Check)
        ));
        let eval = |extra: &[&str]| {
            let mut a = vec![
                "policy",
                "evaluate",
                "--upstream",
                "github",
                "--tool",
                "read_file",
            ];
            a.extend_from_slice(extra);
            parse(&a).map(|c| match c.command {
                Command::Policy(PolicyCmd::Evaluate(e)) => e,
                _ => panic!("not evaluate"),
            })
        };
        let e = eval(&["--token", "-", "--arg", "repo=a/b", "--arg", "n:=1"]).unwrap();
        assert_eq!(e.token.as_deref(), Some("-"));
        assert_eq!((e.upstream(), e.args.len()), ("github", 2));
        let e = eval(&["--chain-file", "c.json"]).unwrap();
        assert!(e.chain_file.is_some() && e.token.is_none());
        assert!(eval(&["--token-file", "/t"]).unwrap().token_file.is_some());
        assert!(eval(&["--token", "x", "--chain-file", "c.json"]).is_err());
        assert!(eval(&["--token-file", "/t", "--chain-file", "c.json"]).is_err());
        assert!(eval(&["--token", "x", "--token-file", "/t"]).is_err());
        assert!(
            parse(&["policy", "evaluate", "--tool", "t"]).is_err(),
            "--server required"
        );
    }

    #[test]
    fn operator_new_takes_one_expiry() {
        let new = |extra: &[&str]| {
            let mut a = vec![
                "admin", "operator", "new", "--name", "a", "--role", "viewer",
            ];
            a.extend_from_slice(extra);
            parse(&a).map(|c| match c.command {
                Command::Admin(AdminCmd::Operator(OperatorCmd::New {
                    expires_in,
                    expires_at,
                    ..
                })) => (expires_in, expires_at),
                _ => panic!("not operator new"),
            })
        };
        assert_eq!(new(&[]).unwrap(), (None, None));
        assert_eq!(
            new(&["--expires-in", "90d"]).unwrap().0,
            Some(time::Duration::days(90))
        );
        let at = new(&["--expires-at", "2999-01-01T00:00:00+02:00"])
            .unwrap()
            .1
            .unwrap();
        assert_eq!(at.offset().whole_hours(), 2);
        assert!(new(&["--expires-in", "1h", "--expires-at", "2999-01-01T00:00:00Z"]).is_err());
        assert!(
            new(&["--expires-at", "2020-01-01T00:00:00Z"]).is_err(),
            "past"
        );
        assert!(
            new(&["--expires-at", "2999-01-01T00:00:00"]).is_err(),
            "no offset"
        );
        assert!(parse(&["admin", "operator", "reload"]).is_ok());
    }

    #[test]
    fn expires_in_is_a_number_and_a_unit() {
        for (s, secs) in [
            ("1s", 1),
            ("30m", 1800),
            ("12h", 43_200),
            ("90d", 7_776_000),
            ("3650d", 315_360_000),
        ] {
            assert_eq!(parse_expires_in(s).unwrap().whole_seconds(), secs, "{s}");
        }
        for bad in [
            "",
            "d",
            "0s",
            "1",
            "1w",
            "1.5h",
            "-1d",
            "+1d",
            " 1d",
            "1 d",
            "1D",
            "3651d",
            "99999999999999999999d",
            "1dé",
        ] {
            assert!(parse_expires_in(bad).is_err(), "{bad:?}");
        }
    }
}
