//! Command line definition.

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

/// Default server address (matches `config/example.toml`).
pub const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// onbehalf: mint, exchange and inspect delegation tokens, call tools through the proxy and
/// administer a running onbehalf server.
///
/// `--server` here is the onbehalf server's base URL and goes before the subcommand. The
/// `--server` of `call` and `tools` names the MCP upstream (for example `github`).
#[derive(Debug, Parser)]
#[command(name = "onbehalf", version, about, long_about)]
pub struct Cli {
    /// Base URL of the onbehalf server.
    #[arg(long, visible_alias = "url", env = "ONBEHALF_SERVER", default_value = DEFAULT_SERVER)]
    pub server: String,

    /// Bearer token for `/admin/*` (token root, lease, audit, policy). Without this flag,
    /// `--admin-token-stdin` or `--admin-token-file`, the `ONBEHALF_ADMIN_TOKEN` environment
    /// variable is used.
    ///
    /// Prefer `ONBEHALF_ADMIN_TOKEN`, `--admin-token-stdin` or `--admin-token-file`: an argument
    /// is visible to other local users in `ps` and ends up in shell history.
    #[arg(long, conflicts_with_all = ["admin_token_stdin", "admin_token_file"])]
    pub admin_token: Option<String>,

    /// Read the admin token from the first line of standard input.
    #[arg(long, conflicts_with = "admin_token_file")]
    pub admin_token_stdin: bool,

    /// Read the admin token from the first line of this file.
    #[arg(long, value_name = "PATH")]
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
    /// Capability `server:tool` (globs allowed), or a full capability as a JSON object.
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
    /// `may_act` when it has one. Without it the grant's `may_act` applies (or, if none, any
    /// authenticated agent may).
    #[arg(long = "may-act", value_name = "AGENT")]
    pub may_act: Vec<String>,
    /// Bind the root token to this DPoP key (a private JWK from `onbehalf key gen --dpop`).
    #[arg(long, value_name = "PATH")]
    pub dpop_key: Option<std::path::PathBuf>,
    /// Print only this value, for scripts.
    #[arg(long, value_enum)]
    pub print: Option<Field>,
}

impl RootArgs {
    /// `--may-act` values, split on commas, without empties.
    pub fn may_act(&self) -> Vec<String> {
        split_agents(&self.may_act)
    }

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
        let may_act = self.may_act();
        if !may_act.is_empty() {
            body.insert("may_act".into(), serde_json::json!({ "sub": may_act }));
        }
        Ok(Value::Object(body))
    }
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
    /// `--subject-token-file`, the `ONBEHALF_TOKEN` environment variable is used. Prefer those:
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
    /// the `ONBEHALF_CLIENT_SECRET` environment variable is used. Prefer those: an argument is
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
    /// values may also be comma-separated. Without it, any authenticated agent may.
    #[arg(long = "may-act", value_name = "AGENT")]
    pub may_act: Vec<String>,
    /// Capability `server:tool`, or a full capability as a JSON object. Repeatable; plain
    /// `server:tool` values may also be comma-separated. Must be covered by the parent's capabilities.
    #[arg(long = "cap", required = true)]
    pub caps: Vec<String>,
    /// Requested lifetime in seconds (clamped to the parent's expiry).
    #[arg(long)]
    pub ttl_seconds: Option<u64>,
    /// Bind the new token to this DPoP key (a private JWK from `onbehalf key gen --dpop`): a
    /// proof by it goes in the `DPoP` header. When the parent token is bound to the same key,
    /// the proof also covers the parent. Required for a bound parent.
    #[arg(long, value_name = "PATH")]
    pub dpop_key: Option<std::path::PathBuf>,
    /// The parent token's DPoP key, when it differs from `--dpop-key`: its proof goes in the
    /// body as `subject_token_dpop`, the parent holder's consent to binding the new token to
    /// `--dpop-key` for `--actor`. Only when one party holds both keys; otherwise the parent
    /// makes the consent with `onbehalf token sign-off` and you pass it with
    /// `--subject-token-dpop-file`.
    #[arg(long, value_name = "PATH", conflicts_with = "subject_token_dpop_file")]
    pub subject_dpop_key: Option<std::path::PathBuf>,
    /// The parent holder's consent (`subject_token_dpop`) made with `onbehalf token sign-off`
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

    /// `--may-act` values, split on commas, without empties.
    pub fn may_act(&self) -> Vec<String> {
        split_agents(&self.may_act)
    }
}

#[derive(Debug, Args)]
pub struct SignOffArgs {
    /// The bound token to be exchanged (the parent), or `-` to read it from the first line of
    /// stdin. Without this flag or `--subject-token-file`, `ONBEHALF_TOKEN` is used.
    #[arg(long, conflicts_with = "subject_token_file")]
    pub subject_token: Option<String>,
    /// Read the parent token from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub subject_token_file: Option<std::path::PathBuf>,
    /// The parent token's DPoP key (a private JWK).
    #[arg(long, value_name = "PATH")]
    pub dpop_key: std::path::PathBuf,
    /// Thumbprint (`jkt`) of the sub-agent's key, which the new token will be bound to
    /// (`onbehalf key gen --dpop` prints it).
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
    /// `--token-file`, the `ONBEHALF_TOKEN` environment variable is used. Prefer those: an
    /// argument is visible to other local users in `ps`.
    #[arg(long, conflicts_with = "token_file")]
    pub token: Option<String>,
    /// Read the delegation token from the first line of this file.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<std::path::PathBuf>,
    /// The DPoP key the token is bound to (a private JWK): every request carries a proof by
    /// it and `Authorization: DPoP <token>`. Needed for tokens bound with `--dpop-key`.
    #[arg(long, value_name = "PATH", env = "ONBEHALF_DPOP_KEY")]
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
    /// Revoke a lease and every lease delegated from it.
    Revoke {
        id: String,
        /// Recorded with the revocation.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Show a lease's state.
    Show { id: String },
}

#[derive(Debug, Subcommand)]
pub enum AuditCmd {
    /// Show the most recent audit entries.
    Tail {
        /// How many entries to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: u64,
        /// Keep polling for new entries.
        #[arg(short, long)]
        follow: bool,
        /// Polling interval with `--follow`, in milliseconds.
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Walk the whole hash chain and verify the signed checkpoints. Exits 2 if the chain is
    /// broken or a checkpoint is invalid. With `--file`, verify an exported file offline
    /// instead (it needs only the issuer's JWKS, no admin token); that check is strict: it
    /// also fails if the file holds entries outside the range its header declares, or entries
    /// after its last valid checkpoint (unless `--allow-unsigned-tail`).
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
        /// Keep only records of this kind: decision, exchange, root_token, lease_renew,
        /// lease_revoke or admin. A filtered export has gaps in its hash chain, so
        /// `audit verify --file` refuses it; verify an unfiltered export, then filter.
        #[arg(long, value_parser = parse_record_kind)]
        kind: Option<onbehalf_core::RecordKind>,
        /// Keep only records of this delegation chain (the `chain_id` field: the lease id of
        /// the chain's first hop). Same verification caveat as `--kind`.
        #[arg(long)]
        chain_id: Option<String>,
    },
}

fn parse_record_kind(s: &str) -> Result<onbehalf_core::RecordKind, String> {
    s.parse()
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
    /// Run YAML policy test files offline. Exit 0 if every case passes, 2 if any fails,
    /// 1 if a file cannot be run.
    Test {
        /// Test files (format documented in docs/guides/writing-policies.md).
        #[arg(required = true)]
        files: Vec<std::path::PathBuf>,
    },
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
        /// Also print the generated schema the policy was validated against.
        #[arg(long)]
        schema: bool,
    },
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
/// capability (JSON, may carry constraints); anything else is `server:tool[,server:tool...]`.
pub fn parse_caps(raw: &[String]) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::new();
    for item in raw {
        let item = item.trim();
        if item.starts_with('{') {
            let cap: onbehalf_core::Capability = serde_json::from_str(item)
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
            out.push(serde_json::to_value(onbehalf_core::Capability::new(
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
        Cli::try_parse_from(std::iter::once("onbehalf").chain(args.iter().copied()))
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
    /// are mutually exclusive with the flag; with neither, `ONBEHALF_TOKEN` is read at run time
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
        assert!(plain.may_act().is_empty());
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
        assert_eq!(full.may_act(), ["coder", "reviewer", "tester"]);
        let body = full.request_body().unwrap();
        assert_eq!(
            body["may_act"],
            serde_json::json!({"sub": ["coder", "reviewer", "tester"]})
        );
        assert_eq!(body["ttl_seconds"], 60);
        assert_eq!(body["attributes"], serde_json::json!({"mfa": true}));
        assert_eq!(body["capabilities"].as_array().unwrap().len(), 1);
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
        assert!(none.may_act().is_empty());

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
        assert_eq!(flag.may_act(), ["x", "y", "z"]);

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
    fn lease_and_policy_subcommands() {
        let cli = parse(&["lease", "revoke", "L1", "--reason", "demo"]).unwrap();
        let Command::Lease(LeaseCmd::Revoke { id, reason }) = cli.command else {
            panic!("not revoke")
        };
        assert_eq!((id.as_str(), reason.as_deref()), ("L1", Some("demo")));
        assert!(parse(&["policy", "reload"]).is_ok());
        assert!(parse(&["audit", "verify"]).is_ok());
        assert!(parse(&["audit", "verify", "--file", "a.jsonl", "--jwks", "j.json"]).is_ok());
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
}
