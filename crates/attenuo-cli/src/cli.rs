//! Command line definition.

use clap::builder::NonEmptyStringValueParser;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

/// Default server address (matches `config/example.toml`).
pub const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// attenuo: mint, exchange and inspect delegation tokens, call tools through the proxy and
/// administer a running attenuo server.
///
/// `--server` here is the attenuo server's base URL and goes before the subcommand. The
/// `--server` of `call` and `tools` names the MCP upstream (for example `github`).
#[derive(Debug, Parser)]
#[command(name = "attenuo", version, about, long_about)]
pub struct Cli {
    /// Base URL of the attenuo server.
    #[arg(long, visible_alias = "url", env = "ATTENUO_SERVER", default_value = DEFAULT_SERVER)]
    pub server: String,

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

#[derive(Debug, Subcommand)]
pub enum Command {
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
}

#[derive(Debug, Subcommand)]
pub enum KeyCmd {
    /// Generate a key. `--dpop <PATH>` writes a new Ed25519 DPoP key (RFC 9449) as a private
    /// JWK, readable only by you, and prints its thumbprint (the `cnf.jkt` of tokens bound to
    /// it). Use it with `--dpop-key`; the Python and TypeScript SDKs take the same file.
    Gen {
        /// Where to write the DPoP key. An existing file is never overwritten.
        #[arg(long, value_name = "PATH", required = true)]
        dpop: std::path::PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenCmd {
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
pub enum Field {
    /// The JWT.
    Token,
    /// The lease id.
    Lease,
}

#[derive(Debug, Args)]
pub struct RootArgs {
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
    pub fn request_body(&self) -> anyhow::Result<Value> {
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
    pub fn may_act_claim(&self) -> anyhow::Result<Option<Vec<String>>> {
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

#[derive(Debug, Args)]
pub struct ExchangeArgs {
    /// The parent token, or `-` to read it from the first line of stdin. Without this flag or
    /// `--subject-token-file`, the `ATTENUO_TOKEN` environment variable is used. Prefer those:
    /// an argument is visible to other local users in `ps`.
    #[arg(long, conflicts_with = "subject_token_file")]
    pub subject_token: Option<String>,
    /// Read the parent token from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub subject_token_file: Option<std::path::PathBuf>,
    /// The sub-agent that will hold the new token. The request authenticates as this agent.
    #[arg(long)]
    pub actor: String,
    /// Client id to authenticate with (an `[[agents]]` entry). Defaults to `--actor`; the server
    /// requires the two to match.
    #[arg(long)]
    pub client_id: Option<String>,
    /// The agent's client secret. Required by servers with `[token] require_actor_auth`
    /// (the default). Without this flag, `--client-secret-stdin` or `--client-secret-file`,
    /// the `ATTENUO_CLIENT_SECRET` environment variable is used. Prefer those: an argument is
    /// visible to other local users in `ps`.
    #[arg(long, conflicts_with_all = ["client_secret_stdin", "client_secret_file"])]
    pub client_secret: Option<String>,
    /// Read the client secret from the first line of standard input.
    #[arg(long, conflicts_with = "client_secret_file")]
    pub client_secret_stdin: bool,
    /// Read the client secret from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub client_secret_file: Option<std::path::PathBuf>,
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
    /// clamped to what it has left.
    #[arg(long = "cap", required = true)]
    pub caps: Vec<String>,
    /// Requested lifetime in seconds (clamped to the parent's expiry).
    #[arg(long)]
    pub ttl_seconds: Option<u64>,
    /// Bind the new token to this DPoP key (a private JWK from `attenuo key gen --dpop`): a
    /// proof by it goes in the `DPoP` header. When the parent token is bound to the same key,
    /// the proof also covers the parent. Required for a bound parent.
    #[arg(long, value_name = "PATH")]
    pub dpop_key: Option<std::path::PathBuf>,
    /// The parent token's DPoP key, when it differs from `--dpop-key`: its proof goes in the
    /// body as `subject_token_dpop`, the parent holder's consent to binding the new token to
    /// `--dpop-key` for `--actor`. Only when one party holds both keys; otherwise the parent
    /// makes the consent with `attenuo token sign-off` and you pass it with
    /// `--subject-token-dpop-file`.
    #[arg(long, value_name = "PATH", conflicts_with = "subject_token_dpop_file")]
    pub subject_dpop_key: Option<std::path::PathBuf>,
    /// The parent holder's consent (`subject_token_dpop`) made with `attenuo token sign-off`
    /// for this exchange's `--dpop-key` and `--actor`, read from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub subject_token_dpop_file: Option<std::path::PathBuf>,
    /// Print only this value, for scripts.
    #[arg(long, value_enum)]
    pub print: Option<Field>,
}

impl ExchangeArgs {
    /// The actor token from `--actor-token` (`-` reads `stdin`) or `--actor-token-file`,
    /// trimmed; `None` when neither is given.
    pub fn actor_token(&self, stdin: impl std::io::Read) -> anyhow::Result<Option<String>> {
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
    pub fn may_act_claim(&self) -> anyhow::Result<Option<Vec<String>>> {
        may_act_claim(&self.may_act, self.no_delegation)
    }
}

#[derive(Debug, Args)]
pub struct SignOffArgs {
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
pub struct InspectArgs {
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
pub struct TokenSource {
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
pub struct CallArgs {
    #[command(flatten)]
    pub token: TokenSource,
    /// MCP upstream name, as mounted at `/mcp/<name>`.
    #[arg(long, alias = "upstream")]
    pub server: String,
    /// Tool name.
    #[arg(long)]
    pub tool: String,
    /// Tool argument `key=value` (`key:=json` for numbers, booleans, objects). Repeatable.
    #[arg(long = "arg", value_parser = parse_kv)]
    pub args: Vec<(String, Value)>,
}

#[derive(Debug, Args)]
pub struct ToolsArgs {
    #[command(flatten)]
    pub token: TokenSource,
    /// MCP upstream name.
    #[arg(long, alias = "upstream")]
    pub server: String,
}

#[derive(Debug, Subcommand)]
pub enum LeaseCmd {
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
pub enum BudgetCmd {
    /// Give back to every run-limit counter what one allowed decision charged, once, for a
    /// call whose effect did not happen (`POST /admin/budgets/refund`). The refund is audited
    /// as an `admin.budget.refund` record. Exits 2 when the decision charged nothing and 3 when
    /// it was already refunded.
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
pub enum ApprovalCmd {
    /// The newest approvals, newest first.
    List {
        /// Only the approvals of this delegation run (its first hop's lease).
        #[arg(long)]
        chain_id: Option<String>,
        /// Only approvals in this state.
        #[arg(long, value_parser = ["pending", "granted", "declined", "consumed"])]
        state: Option<String>,
        /// At most this many (server maximum 500).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=500))]
        limit: Option<u64>,
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
pub struct ApprovalVerifyArgs {
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
pub enum AuditCmd {
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
        /// Only checkpoints with a seq below this (the next page of an earlier listing).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        before: Option<u64>,
        /// Page size (server default 100, at most 1000).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        limit: Option<u64>,
    },
    /// Walk the whole hash chain and verify the signed checkpoints. Exits 2 if the chain is
    /// broken or a checkpoint is invalid. With `--file`, verify an exported file offline
    /// instead (it needs only the issuer's JWKS, no admin token); that check is strict: it
    /// also fails if the file holds entries outside the range its header declares, or entries
    /// after its last valid checkpoint (unless `--allow-unsigned-tail`). Add `--checkpoints`
    /// to cross-check the export against checkpoints shipped off the host.
    Verify {
        /// An export made with `audit export` (JSON Lines, or the `--format json` object).
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// JWKS file holding the issuer keys; with `--file` and without this, the JWKS is
        /// fetched from `<server>/.well-known/jwks.json`.
        #[arg(long, requires = "file")]
        jwks: Option<std::path::PathBuf>,
        /// With `--file`: accept entries after the export's last valid checkpoint, which only
        /// the hash chain covers (an export taken while the log was ahead of its newest
        /// checkpoint). They are still reported as `unsigned_tail`.
        #[arg(long, requires = "file")]
        allow_unsigned_tail: bool,
        /// With `--file`: checkpoints shipped off the host by `[audit.sink]` (the file sink's
        /// JSON Lines, webhook bodies one per line, or bare checkpoint lines). Every shipped
        /// checkpoint inside the export's range must match the export's checkpoint at that
        /// seq exactly, and the export's entry there must hash to its `head_hash`; one that
        /// differs was signed again after it was shipped (SR-21). Exits 2 on any mismatch.
        #[arg(long, requires = "file")]
        checkpoints: Option<std::path::PathBuf>,
    },
    /// Export entries `--from` to `--to` (inclusive) and the checkpoints inside that range.
    /// Defaults to the whole log. Writes to stdout unless `--out` is given.
    Export {
        /// First sequence number.
        #[arg(long, default_value_t = 1)]
        from: u64,
        /// Last sequence number. Default: the head of the log.
        #[arg(long)]
        to: Option<u64>,
        /// `jsonl` streams one object per line; `json` writes a single object.
        #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl)]
        format: ExportFormat,
        /// Write here instead of stdout.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Keep only records of this kind: decision, tool_result, exchange, root_token,
        /// lease_renew, lease_revoke or admin. A refused exchange or renewal is a `decision`,
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
pub struct AuditFilter {
    /// Record kind: decision, tool_result, exchange, root_token, lease_renew, lease_revoke or
    /// admin. Repeatable, or comma-separated; any of them matches.
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
    /// The MCP upstream the call went to (not the attenuo server URL, which is the global
    /// `--server` before the subcommand).
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub server: Option<String>,
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
    pub fn query(&self) -> String {
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
            ("server", &self.server),
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
pub enum ExportFormat {
    Jsonl,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
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
pub struct TestArgs {
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
pub enum Via {
    /// The in-process engine built from the test file (offline).
    Local,
    /// A running server's AuthZEN endpoint.
    Authzen,
    /// A running server's admin dry run, `POST /admin/policies/evaluate`.
    AdminEvaluate,
}

/// `policy evaluate`: the call, and the chain it is made for (from a token or a file).
#[derive(Debug, Args)]
pub struct EvaluateArgs {
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
    #[arg(long, alias = "upstream")]
    pub server: String,
    /// Tool name.
    #[arg(long)]
    pub tool: String,
    /// Tool argument `key=value` (`key:=json`). Repeatable.
    #[arg(long = "arg", value_parser = parse_kv)]
    pub args: Vec<(String, Value)>,
}

#[derive(Debug, Subcommand)]
pub enum AuthzenCmd {
    /// Ask the PDP whether the token's chain may make this call, without making it.
    Eval {
        /// The delegation token, sent as the bearer.
        #[command(flatten)]
        token: TokenSource,
        /// MCP server name.
        #[arg(long, default_value = "github")]
        server: String,
        /// Tool name.
        #[arg(long)]
        tool: String,
        /// Tool argument `key=value` (`key:=json`). Repeatable.
        #[arg(long = "arg", value_parser = parse_kv)]
        args: Vec<(String, Value)>,
    },
}

/// Turn `--cap` values into capability objects. A value starting with `{` is a full
/// capability (JSON, may carry constraints and limits); anything else is
/// `server:tool[,server:tool...]`.
pub fn parse_caps(raw: &[String]) -> anyhow::Result<Vec<Value>> {
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

/// Parse `key=value` (a string) or `key:=json` (any JSON value).
pub fn parse_kv(s: &str) -> Result<(String, Value), String> {
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
            "--server",
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
        assert_eq!(
            (c.server.as_str(), c.tool.as_str()),
            ("github", "read_file")
        );
        assert_eq!(c.args.len(), 2);
        assert_eq!(c.args[1].1, json!(2));
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
        ] {
            let mut a = both.to_vec();
            a.extend_from_slice(extra);
            assert!(parse(&a).is_err(), "{extra:?}");
        }
    }

    /// SR-35: `--token` and `--subject-token` take `-` for stdin and have `--…-file` forms, which
    /// are mutually exclusive with the flag; with neither, `ATTENUO_TOKEN` is read at run time
    /// (not by clap, so the environment never conflicts with a file flag).
    #[test]
    fn delegation_tokens_from_stdin_or_a_file() {
        let call = |extra: &[&str]| {
            let mut a = vec!["call", "--server", "github", "--tool", "t"];
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
            ["tools", "--server", "github", "--token-file", "/t"].as_slice(),
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
            "--server",
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
        // The upstream `--server` filter lives after the subcommand; the global one before it.
        let cli = parse(&[
            "--server",
            "http://ob:9",
            "audit",
            "tail",
            "--server",
            "github",
        ])
        .unwrap();
        assert_eq!(cli.server, "http://ob:9");
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
                Command::Audit(AuditCmd::Checkpoints { before, limit }) => (before, limit),
                _ => panic!("not checkpoints"),
            })
        };
        assert_eq!(cps(&[]).unwrap(), (None, None));
        assert_eq!(
            cps(&["--before", "9", "--limit", "3"]).unwrap(),
            (Some(9), Some(3))
        );
        assert!(cps(&["--before", "0"]).is_err());
        assert!(cps(&["--limit", "0"]).is_err());
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
                "--server",
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
        assert_eq!((e.server.as_str(), e.args.len()), ("github", 2));
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
}
