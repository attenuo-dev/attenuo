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
    #[arg(long, env = "ONBEHALF_ADMIN_TOKEN", hide_env_values = true)]
    pub admin_token: Option<String>,

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
    /// The sub-agent that will hold the new token.
    #[arg(long)]
    pub actor: String,
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
    /// Walk the whole hash chain. Exits 1 if it is broken.
    Verify,
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
        assert!(parse(&["token", "exchange", "--subject-token", "J", "--actor", "c"]).is_err());
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
        assert!(parse(&["nope"]).is_err());
    }
}
