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

    /// Bearer token for `/admin/*` (token root, lease, audit, policy).
    ///
    /// Prefer `ONBEHALF_ADMIN_TOKEN`, `--admin-token-stdin` or `--admin-token-file`: an argument
    /// is visible to other local users in `ps` and ends up in shell history.
    #[arg(
        long,
        env = "ONBEHALF_ADMIN_TOKEN",
        hide_env_values = true,
        conflicts_with_all = ["admin_token_stdin", "admin_token_file"]
    )]
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
}

#[derive(Debug, Subcommand)]
pub enum TokenCmd {
    /// Mint a root (hop 0) token. Development endpoint; needs the admin token.
    Root(RootArgs),
    /// RFC 8693 exchange: delegate a subset of a token's capabilities to a sub-agent.
    Exchange(ExchangeArgs),
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
    /// Print only this value, for scripts.
    #[arg(long, value_enum)]
    pub print: Option<Field>,
}

#[derive(Debug, Args)]
pub struct ExchangeArgs {
    /// The parent token.
    #[arg(long, env = "ONBEHALF_TOKEN", hide_env_values = true)]
    pub subject_token: String,
    /// The sub-agent that will hold the new token. The request authenticates as this agent.
    #[arg(long)]
    pub actor: String,
    /// Client id to authenticate with (an `[[agents]]` entry). Defaults to `--actor`; the server
    /// requires the two to match.
    #[arg(long)]
    pub client_id: Option<String>,
    /// The agent's client secret. Required by servers with `[token] require_actor_auth`
    /// (the default). Prefer `ONBEHALF_CLIENT_SECRET`, `--client-secret-stdin` or
    /// `--client-secret-file`: an argument is visible to other local users in `ps`.
    #[arg(
        long,
        env = "ONBEHALF_CLIENT_SECRET",
        hide_env_values = true,
        conflicts_with_all = ["client_secret_stdin", "client_secret_file"]
    )]
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
        self.may_act
            .iter()
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }
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

#[derive(Debug, Args)]
pub struct CallArgs {
    /// Delegation token.
    #[arg(long, env = "ONBEHALF_TOKEN", hide_env_values = true)]
    pub token: String,
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
    /// Delegation token.
    #[arg(long, env = "ONBEHALF_TOKEN", hide_env_values = true)]
    pub token: String,
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
    /// instead (it needs only the issuer's JWKS, no admin token).
    Verify {
        /// An export made with `audit export` (JSON Lines, or the `--format json` object).
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// JWKS file holding the issuer keys; with `--file` and without this, the JWKS is
        /// fetched from `<server>/.well-known/jwks.json`.
        #[arg(long, requires = "file")]
        jwks: Option<std::path::PathBuf>,
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
    },
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
        /// Without it the catalog is empty and any policy naming an action fails validation.
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
        /// Delegation token, sent as the bearer.
        #[arg(long, env = "ONBEHALF_TOKEN", hide_env_values = true)]
        token: String,
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
        assert!(parse(&["nope"]).is_err());
    }
}
