//! `attenuo init`: write a working starter configuration for one MCP server.
//!
//! The command asks the MCP server for its tools (`initialize`, then `tools/list`), and writes
//! three files into a directory: `attenuo.toml` (the server's configuration, with every tool
//! in `[policy.catalog]`), `policy.cedar` (a starter policy that permits the read-only tools
//! and nothing else) and `attenuo.env` (the secrets the CLI needs, to `source`). It talks to
//! no attenuo server.
//!
//! What it takes from the MCP server, and what it does with it. The MCP server is the thing
//! being put behind a guard, so nothing it says is trusted further than this:
//!
//! - **Tool names.** A name that breaks attenuo's naming rules cannot be called through the
//!   proxy at all; it is left out and reported.
//! - **`annotations.readOnlyHint == true`** marks the tool `readonly` in the catalog, and the
//!   starter policy permits read-only tools. This is the server's own claim. The command
//!   lists those tools so the operator can check them, and the generated files say where the
//!   flag came from. `--no-readonly-hints` ignores the hint: then every tool is denied until
//!   the operator writes a permit.
//! - **`annotations.destructiveHint == true`** marks the tool `sensitive`.
//! - **`inputSchema.properties`** of type `string`, `integer` or `boolean` become catalog
//!   inputs (`string`, `long`, `bool`), so a policy can test them. Other types are left out.
//! - Descriptions and every other text are not written anywhere.
//!
//! The generated configuration is for trying attenuo on one machine: it binds loopback and
//! turns on the development root mint. The files say so.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::cli::InitArgs;
use crate::client::{http_client, parse_rpc_body};
use crate::operator_cmd::{generate_token, token_sha256_hex};

/// Most tools read from one server, and most `tools/list` pages followed.
const MAX_TOOLS: usize = 2000;
const MAX_PAGES: usize = 200;
/// Most inputs kept for one tool.
const MAX_INPUTS: usize = 64;
/// Largest `tools/list` or `initialize` answer read, in bytes.
const MAX_BODY: usize = 16 * 1024 * 1024;
/// The MCP protocol revision offered in `initialize`.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The file names written into the directory.
const CONFIG_FILE: &str = "attenuo.toml";
const POLICY_FILE: &str = "policy.cedar";
const ENV_FILE: &str = "attenuo.env";

/// One tool as the catalog will hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tool {
    pub name: String,
    pub readonly: bool,
    pub sensitive: bool,
    /// Argument name to catalog type (`string`, `long`, `bool`).
    pub inputs: BTreeMap<String, &'static str>,
}

/// What `tools/list` gave, sorted into what is kept and what is not.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Discovered {
    pub tools: Vec<Tool>,
    /// Tool names left out because they break the naming rules, escaped for display.
    pub skipped: Vec<String>,
    /// Entries without a string `name`.
    pub nameless: usize,
    /// Tools listed more than once (the first one is kept).
    pub duplicates: usize,
}

/// An argument name the catalog and a Cedar policy can both write without quoting.
fn is_plain_input_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name.len() <= 64
}

/// The catalog inputs of one tool's `inputSchema`.
fn inputs_of(schema: Option<&Value>) -> BTreeMap<String, &'static str> {
    let mut out = BTreeMap::new();
    let Some(props) = schema
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object)
    else {
        return out;
    };
    for (name, prop) in props {
        if out.len() >= MAX_INPUTS {
            break;
        }
        if !is_plain_input_name(name) {
            continue;
        }
        let ty = match prop.get("type").and_then(Value::as_str) {
            Some("string") => "string",
            Some("integer") => "long",
            Some("boolean") => "bool",
            _ => continue,
        };
        out.insert(name.clone(), ty);
    }
    out
}

/// Sort the entries of `tools/list` into catalog tools. `trust_readonly` is whether a
/// `readOnlyHint` of `true` marks the tool read-only.
pub(crate) fn sort_tools(entries: &[Value], trust_readonly: bool) -> Discovered {
    let mut d = Discovered::default();
    let mut seen = std::collections::BTreeSet::new();
    for entry in entries {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            d.nameless += 1;
            continue;
        };
        if attenuo_core::names::check_tool_name(name).is_err() {
            // `{:?}` escapes control characters and quotes: the name came from the server.
            let shown: String = format!("{name:?}").chars().take(80).collect();
            d.skipped.push(shown);
            continue;
        }
        if !seen.insert(name.to_string()) {
            d.duplicates += 1;
            continue;
        }
        let hint = |key: &str| {
            entry
                .get("annotations")
                .and_then(|a| a.get(key))
                .and_then(Value::as_bool)
                == Some(true)
        };
        let readonly = trust_readonly && hint("readOnlyHint");
        d.tools.push(Tool {
            name: name.to_string(),
            readonly,
            // A tool cannot be both: the read-only claim is the one the policy acts on, and
            // a server that claims both is contradicting itself, so neither is believed.
            sensitive: hint("destructiveHint"),
            inputs: inputs_of(entry.get("inputSchema")),
        });
    }
    for t in &mut d.tools {
        if t.readonly && t.sensitive {
            t.readonly = false;
        }
    }
    d.tools.sort_by(|a, b| a.name.cmp(&b.name));
    d
}

/// The first complete SSE event in `buf`: where it ends, and where the next one starts. An
/// event ends at a blank line (`\n\n`, or `\n\r\n` when lines end in CRLF).
fn event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while let Some(off) = buf[i..].iter().position(|b| *b == b'\n') {
        let nl = i + off;
        match buf.get(nl + 1..) {
            Some([b'\n', ..]) => return Some((nl, nl + 2)),
            Some([b'\r', b'\n', ..]) => return Some((nl, nl + 3)),
            _ => i = nl + 1,
        }
    }
    None
}

/// One JSON-RPC exchange with the MCP server. Returns the response headers and, for a
/// request (one with an id), the JSON-RPC response.
async fn rpc(
    http: &reqwest::Client,
    url: &str,
    session: Option<&str>,
    protocol: Option<&str>,
    body: &Value,
) -> Result<(reqwest::header::HeaderMap, Option<Value>)> {
    let mut req = http
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .json(body);
    if let Some(s) = session {
        req = req.header("mcp-session-id", s);
    }
    if let Some(p) = protocol {
        req = req.header("mcp-protocol-version", p);
    }
    let method = body.get("method").and_then(Value::as_str).unwrap_or("?");
    let mut resp = req
        .send()
        .await
        .with_context(|| format!("could not reach the MCP server at {url}"))?;
    let status = resp.status();
    if status.is_redirection() {
        bail!("the MCP server answered `{method}` with a redirect (HTTP {status}); give the URL that answers without one");
    }
    if !status.is_success() {
        bail!(
            "the MCP server answered `{method}` with HTTP {status}{}",
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                "; `attenuo init` cannot discover the tools of a server that needs credentials: use --no-discover and fill in [policy.catalog] by hand"
            } else {
                ""
            }
        );
    }
    let headers = resp.headers().clone();
    if body.get("id").is_none() {
        return Ok((headers, None));
    }
    let sse = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("event-stream"));
    let mut bytes = Vec::new();
    // Where the next unread SSE event starts: each event is parsed once, so a body sent in
    // many small pieces costs no more than one sent whole.
    let mut event_start = 0;
    let mut reply = None;
    'read: while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("reading the MCP server's answer to `{method}`"))?
    {
        if bytes.len() + chunk.len() > MAX_BODY {
            bail!("the MCP server's answer to `{method}` is larger than {MAX_BODY} bytes");
        }
        bytes.extend_from_slice(&chunk);
        if !sse {
            continue;
        }
        // An SSE answer may stay open after the response event: stop once it is there.
        while let Some((end, next)) = event_end(&bytes[event_start..]) {
            let event = String::from_utf8_lossy(&bytes[event_start..event_start + end]);
            event_start += next;
            if let Some(v) = parse_rpc_body(&event, true) {
                reply = Some(v);
                break 'read;
            }
        }
    }
    let reply = match reply {
        Some(v) => Some(v),
        // Plain JSON, or a last SSE event that no blank line ended.
        None => parse_rpc_body(&String::from_utf8_lossy(&bytes[event_start..]), sse),
    }
    .with_context(|| format!("the MCP server's answer to `{method}` is not a JSON-RPC response"))?;
    if let Some(err) = reply.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        bail!("the MCP server refused `{method}` (JSON-RPC error {code})");
    }
    Ok((headers, Some(reply)))
}

/// Ask the MCP server at `url` for its tools: the raw entries of every `tools/list` page.
pub(crate) async fn discover(url: &str) -> Result<Vec<Value>> {
    let http = http_client()?;
    let (headers, reply) = rpc(
        &http,
        url,
        None,
        None,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "attenuo-init", "version": env!("CARGO_PKG_VERSION")}
            }
        }),
    )
    .await?;
    // Both values go back to the server in headers: keep them only if they can be one.
    let header_safe =
        |s: &str| !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b));
    let session = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| header_safe(s))
        .map(str::to_string);
    let protocol = reply
        .as_ref()
        .and_then(|r| r.pointer("/result/protocolVersion"))
        .and_then(Value::as_str)
        .filter(|s| header_safe(s))
        .unwrap_or(PROTOCOL_VERSION)
        .to_string();
    let session = session.as_deref();
    let protocol = Some(protocol.as_str());

    rpc(
        &http,
        url,
        session,
        protocol,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await?;

    let mut entries = Vec::new();
    let mut cursor: Option<String> = None;
    let listed = async {
        for page in 0..MAX_PAGES {
            let mut params = serde_json::Map::new();
            if let Some(c) = &cursor {
                params.insert("cursor".into(), Value::String(c.clone()));
            }
            let (_, reply) = rpc(
                &http,
                url,
                session,
                protocol,
                &json!({"jsonrpc": "2.0", "id": page + 2, "method": "tools/list", "params": params}),
            )
            .await?;
            let result = reply
                .as_ref()
                .and_then(|r| r.get("result"))
                .context("the MCP server's answer to `tools/list` has no result")?;
            let tools = result
                .get("tools")
                .and_then(Value::as_array)
                .context("the MCP server's answer to `tools/list` has no `tools` array")?;
            if entries.len() + tools.len() > MAX_TOOLS {
                bail!("the MCP server lists more than {MAX_TOOLS} tools; use --no-discover and write [policy.catalog] by hand");
            }
            entries.extend(tools.iter().cloned());
            match result.get("nextCursor").and_then(Value::as_str) {
                Some(next) if !next.is_empty() => {
                    if cursor.as_deref() == Some(next) {
                        bail!("the MCP server's `tools/list` returned the same cursor twice");
                    }
                    cursor = Some(next.to_string());
                }
                _ => return Ok(()),
            }
        }
        bail!("the MCP server's `tools/list` did not end within {MAX_PAGES} pages")
    }
    .await;

    // End the session whatever happened; a server may not support it, so the answer is ignored.
    if let Some(s) = session {
        let _ = http.delete(url).header("mcp-session-id", s).send().await;
    }
    listed?;
    Ok(entries)
}

/// A TOML basic string.
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A TOML key: bare when it can be, else a basic string (a tool name may hold a `.`).
fn toml_key(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        s.to_string()
    } else {
        toml_str(s)
    }
}

/// What the files are generated from.
pub(crate) struct Plan<'a> {
    pub upstream: &'a str,
    pub url: &'a str,
    pub listen: std::net::SocketAddr,
    pub admin_token: &'a str,
    pub coder_secret_sha256: &'a str,
    /// `None` when the tools were not discovered (`--no-discover`).
    pub tools: Option<&'a [Tool]>,
}

/// The text of `attenuo.toml`.
pub(crate) fn render_config(p: &Plan<'_>) -> String {
    let up = toml_key(p.upstream);
    let mut s = String::new();
    s.push_str(&format!(
        "# attenuo starter configuration, written by `attenuo init` (attenuo {}).\n\
         #\n\
         # It is for trying attenuo on one machine: it listens on loopback and turns on the\n\
         # development root mint (see [dev] at the end). Before anyone else can reach this\n\
         # server, read docs/guides/deploying.md. Every key is explained in config/example.toml:\n\
         # https://github.com/attenuo-dev/attenuo/blob/main/config/example.toml\n\
         #\n\
         # This file holds the admin token. Keep it readable by you only (it was created 0600).\n\
         # Relative paths resolve against the directory the server is started from.\n\n",
        env!("CARGO_PKG_VERSION")
    ));
    s.push_str(&format!(
        "[server]\nlisten = {}\n\n",
        toml_str(&p.listen.to_string())
    ));
    s.push_str(
        "[issuer]\n# Created on first start when it does not exist.\nprivate_key_pem_path = \"data/issuer.pem\"\n\n",
    );
    s.push_str("[audit]\nsqlite_path = \"data/attenuo.sqlite\"\n\n");
    s.push_str(&format!(
        "# The MCP server to protect. {name} is the server part of capabilities such as\n\
         # {cap}, and clients connect to http://{listen}/mcp/{raw}.\n\
         [[upstreams]]\nname = {name}\nurl = {url}\n\n",
        name = toml_str(p.upstream),
        cap = toml_str(&format!("{}:<tool>", p.upstream)),
        listen = p.listen,
        raw = p.upstream,
        url = toml_str(p.url),
    ));
    s.push_str("[policy]\npolicies_path = \"policy.cedar\"\n");
    s.push_str(
        "# A tool that is not in the catalog below is denied (reason tool_not_in_catalog).\n\
         unknown_tools = \"deny\"\n\n",
    );
    match p.tools {
        None => s.push_str(&format!(
            "# The tools were not discovered (--no-discover). List each tool your agents may call,\n\
             # with the arguments a policy should be able to test:\n\
             #\n\
             # [policy.catalog.{up}.read_file]\n\
             # readonly = true\n\
             # inputs = {{ path = \"string\" }}\n\n"
        )),
        Some(tools) => {
            s.push_str(
                "# The catalog: every tool the MCP server listed when `attenuo init` ran, with the\n\
                 # arguments a policy can test. `readonly` and `sensitive` are the server's own\n\
                 # claims about its tools (the MCP annotations readOnlyHint and destructiveHint).\n\
                 # The starter policy permits readonly tools, so CHECK each `readonly = true` below.\n\
                 # A tool the server adds later is denied until you add it here.\n\n",
            );
            for t in tools {
                s.push_str(&format!("[policy.catalog.{up}.{}]\n", toml_key(&t.name)));
                if t.readonly {
                    s.push_str("readonly = true\n");
                }
                if t.sensitive {
                    s.push_str("sensitive = true\n");
                }
                if !t.inputs.is_empty() {
                    let inputs: Vec<String> = t
                        .inputs
                        .iter()
                        .map(|(k, v)| format!("{k} = {}", toml_str(v)))
                        .collect();
                    s.push_str(&format!("inputs = {{ {} }}\n", inputs.join(", ")));
                }
                s.push('\n');
            }
        }
    }
    s.push_str(&format!(
        "[admin]\n# The bearer for everything under /admin. Also in attenuo.env.\ntoken = {}\n\n",
        toml_str(p.admin_token)
    ));
    s.push_str(&format!(
        "# Agents that authenticate to POST /token. `coder` is a sub-agent that receives narrower\n\
         # tokens; its client secret is in attenuo.env, and only the SHA-256 is kept here.\n\
         [[agents]]\nid = \"coder\"\nsecret_sha256 = {}\n\n",
        toml_str(p.coder_secret_sha256)
    ));
    s.push_str(&format!(
        "# The most a root token may carry: for users of `issuer`, held by the agent `planner`.\n\
         [[root_grants]]\nissuer = \"https://idp.example\"\nagent = \"planner\"\ncapabilities = [{}]\n\n",
        toml_str(&format!("{}:*", p.upstream))
    ));
    s.push_str(
        "# DEVELOPMENT ONLY. Lets the admin mint a root token for any user, with no login\n\
         # (`attenuo token root`). The server refuses to start with this on a listener that is\n\
         # not loopback. For a real login see docs/guides/identity-providers.md, then set this\n\
         # to false.\n\
         [dev]\nallow_root_mint = true\n",
    );
    s
}

/// The text of `policy.cedar`.
pub(crate) fn render_policy(upstream: &str, tools: Option<&[Tool]>) -> String {
    let mut s = String::from(
        "// attenuo starter policy, written by `attenuo init`.\n\
         //\n\
         // Cedar denies by default: a call is allowed only if at least one `permit` matches and\n\
         // no `forbid` matches. A policy is evaluated after the token's capabilities, so it can\n\
         // only narrow what was delegated, never widen it.\n\
         //\n\
         //   principal  Agent::\"<agent id>\"\n\
         //   action     Action::\"<server>/<tool>\"\n\
         //   resource   Tool::\"<server>/<tool>\", with readonly and sensitive from the catalog\n\
         //   context    { input, originating_user, chain, ... }\n\
         //\n\
         // Guide: https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/writing-policies.md\n\
         // Check a change before the server loads it: attenuo policy check --help\n\n\
         // Read-only tools are allowed for any agent whose token covers them. `readonly` is\n\
         // set per tool in [policy.catalog] of attenuo.toml, from the MCP server's own\n\
         // readOnlyHint annotation: check that list.\n\
         @id(\"permit_readonly_tools\")\n\
         permit(principal, action, resource)\n\
         when { resource.readonly };\n\n\
         // Deep delegation chains are almost always a bug or an attack.\n\
         @id(\"forbid_deep_chains\")\n\
         forbid(principal, action, resource)\n\
         when { context.chain.depth > 3 };\n",
    );
    let Some(tools) = tools else {
        return s;
    };
    let rest: Vec<&Tool> = tools.iter().filter(|t| !t.readonly).collect();
    if rest.is_empty() {
        return s;
    }
    s.push_str(
        "\n// The tools below are not read-only, so nothing permits them yet and every call to\n\
         // them is denied (policy_deny). To allow one, uncomment its permit and narrow it with\n\
         // a `when` on the arguments, for example:\n\
         //\n\
         //   when { context.input has repo && context.input.repo == \"acme/docs\" };\n\
         //\n\
         // Only arguments listed under the tool's `inputs` in attenuo.toml can be tested.\n",
    );
    for t in rest {
        s.push_str(&format!(
            "\n// {name}{note}\n// @id(\"permit_{id}\")\n// permit(principal, action == Action::\"{upstream}/{name}\", resource);\n",
            name = t.name,
            note = if t.sensitive {
                " (marked sensitive: the server says it can destroy data)"
            } else {
                ""
            },
            id = t.name.replace(['.', '-'], "_"),
        ));
    }
    s
}

/// The text of `attenuo.env`.
fn render_env(listen: std::net::SocketAddr, admin_token: &str, coder_secret: &str) -> String {
    format!(
        "# Written by `attenuo init`. Secrets: keep this file readable by you only (0600).\n\
         # Load it into a shell with:  . ./attenuo.env\n\
         export ATTENUO_SERVER=http://{listen}\n\
         export ATTENUO_ADMIN_TOKEN={admin_token}\n\
         # The client secret of the agent `coder`, for `attenuo token exchange --actor coder`.\n\
         export ATTENUO_CLIENT_SECRET={coder_secret}\n"
    )
}

/// `NAME=URL`, checked.
fn parse_upstream(spec: &str) -> Result<(String, String)> {
    let (name, url) = spec
        .split_once('=')
        .context("--upstream takes NAME=URL, for example github=http://127.0.0.1:3001/mcp")?;
    attenuo_core::names::check_server_name(name)
        .map_err(|e| anyhow::anyhow!("--upstream: the name is not a valid server name: {e}"))?;
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| anyhow::anyhow!("--upstream: `{}` is not a URL: {e}", url.escape_debug()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("--upstream: the URL must start with http:// or https://");
    }
    if parsed.host_str().is_none() {
        bail!("--upstream: the URL has no host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("--upstream: the URL must not carry a user name or password");
    }
    if parsed.fragment().is_some() {
        bail!("--upstream: the URL must not have a fragment");
    }
    Ok((name.to_string(), url.to_string()))
}

/// Create `path` with `text`, readable by the owner only when `secret`. Fails when the file
/// exists unless `force`.
fn write_file(path: &Path, text: &str, secret: bool, force: bool) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if secret { 0o600 } else { 0o644 });
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    #[cfg(unix)]
    if secret {
        // An existing file keeps its mode on open: with --force, tighten it before writing.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("could not set the mode of {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = secret;
    f.write_all(text.as_bytes())
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

/// A path for display in a shell command: quoted when it needs it.
fn shell_path(p: &Path) -> String {
    let s = p.display().to_string();
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~'))
    {
        s
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// `attenuo init`.
pub(crate) async fn run(args: InitArgs) -> Result<()> {
    let (upstream, url) = parse_upstream(&args.upstream)?;
    if !args.listen.ip().is_loopback() {
        bail!(
            "--listen must be a loopback address (127.0.0.1 or [::1]): the starter configuration turns on the development root mint, which the server refuses off loopback"
        );
    }
    if args.listen.port() == 0 {
        bail!("--listen needs a fixed port: clients and attenuo.env are given the address");
    }
    let dir: PathBuf = args.dir.clone();
    let files = [CONFIG_FILE, POLICY_FILE, ENV_FILE];
    if !args.force {
        // Check before anything is asked or written, so a refusal leaves nothing half done.
        for f in files {
            if dir.join(f).exists() {
                bail!(
                    "{} already exists; choose another --dir, or pass --force to overwrite the three files",
                    dir.join(f).display()
                );
            }
        }
    }

    let discovered = if args.no_discover {
        None
    } else {
        let entries = discover(&url).await.with_context(|| {
            "could not read the tools of the MCP server (start it first, or pass --no-discover to write the configuration without a catalog)"
        })?;
        Some(sort_tools(&entries, !args.no_readonly_hints))
    };

    let admin_token = generate_token()?;
    let coder_secret = generate_token()?;
    let plan = Plan {
        upstream: &upstream,
        url: &url,
        listen: args.listen,
        admin_token: &admin_token,
        coder_secret_sha256: &token_sha256_hex(&coder_secret),
        tools: discovered.as_ref().map(|d| d.tools.as_slice()),
    };
    let config = render_config(&plan);
    let policy = render_policy(&upstream, plan.tools);
    let env = render_env(args.listen, &admin_token, &coder_secret);

    std::fs::create_dir_all(dir.join("data"))
        .with_context(|| format!("could not create {}", dir.join("data").display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The issuer key and the audit log will live here.
        std::fs::set_permissions(dir.join("data"), std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("could not set the mode of {}", dir.join("data").display()))?;
    }
    write_file(&dir.join(CONFIG_FILE), &config, true, args.force)?;
    write_file(&dir.join(POLICY_FILE), &policy, false, args.force)?;
    write_file(&dir.join(ENV_FILE), &env, true, args.force)?;

    outln!("wrote {}", dir.join(CONFIG_FILE).display())?;
    outln!("wrote {}", dir.join(POLICY_FILE).display())?;
    outln!(
        "wrote {}  (secrets, mode 0600)",
        dir.join(ENV_FILE).display()
    )?;
    outln!("")?;
    match &discovered {
        None => {
            outln!(
                "The tools were not discovered: every call is denied until you list the tools in"
            )?;
            outln!("[policy.catalog] of {CONFIG_FILE}.")?;
        }
        Some(d) => {
            let readonly: Vec<&str> = d
                .tools
                .iter()
                .filter(|t| t.readonly)
                .map(|t| t.name.as_str())
                .collect();
            outln!("{} tools found on `{upstream}`.", d.tools.len())?;
            if readonly.is_empty() {
                outln!("None is permitted yet: write a permit in {POLICY_FILE} for each tool to allow.")?;
            } else {
                outln!(
                    "Permitted by the starter policy, because the server says they only read ({}):",
                    readonly.len()
                )?;
                for chunk in readonly.chunks(6) {
                    outln!("  {}", chunk.join(", "))?;
                }
                outln!("Check that list. Every other tool is denied until you write a permit in {POLICY_FILE}.")?;
            }
            if !d.skipped.is_empty() {
                outln!(
                    "Left out, because the name breaks attenuo's naming rules ([A-Za-z0-9_.-]) and cannot be called through the proxy: {}",
                    d.skipped.join(", ")
                )?;
            }
            if d.nameless > 0 || d.duplicates > 0 {
                outln!(
                    "Ignored: {} entries without a name, {} listed twice.",
                    d.nameless,
                    d.duplicates
                )?;
            }
        }
    }
    let example_tool = discovered
        .as_ref()
        .and_then(|d| d.tools.iter().find(|t| t.readonly))
        .map_or("<tool>", |t| t.name.as_str());
    outln!("")?;
    outln!("Next:")?;
    outln!("  cd {}", shell_path(&dir))?;
    outln!("  attenuo-server --config {CONFIG_FILE}        # in another terminal")?;
    outln!("  . ./{ENV_FILE}")?;
    outln!("  ROOT=$(attenuo token root --subject alice --agent planner --cap '{upstream}:*' --print token)")?;
    outln!("  export ATTENUO_TOKEN=$(ATTENUO_TOKEN=$ROOT attenuo token exchange --actor coder --cap '{upstream}:*' --print token)")?;
    outln!("  attenuo tools --upstream {upstream}")?;
    outln!("  attenuo call --upstream {upstream} --tool {example_tool}")?;
    outln!("")?;
    outln!(
        "MCP clients connect to http://{}/mcp/{upstream} with `Authorization: Bearer <token>`.",
        args.listen
    )?;
    outln!("This configuration is for one machine only (development root mint on).")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, readonly: bool, sensitive: bool, inputs: &[(&str, &'static str)]) -> Tool {
        Tool {
            name: name.into(),
            readonly,
            sensitive,
            inputs: inputs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
        }
    }

    #[test]
    fn tools_are_sorted_into_the_catalog() {
        let entries = vec![
            json!({"name": "write_file", "annotations": {"destructiveHint": true},
                   "inputSchema": {"type": "object", "properties": {
                       "path": {"type": "string"}, "mode": {"type": "integer"},
                       "force": {"type": "boolean"}, "tags": {"type": "array"},
                       "weird-name": {"type": "string"}, "n": {"type": "number"},
                       "any": {}}}}),
            json!({"name": "read_file", "annotations": {"readOnlyHint": true},
                   "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}),
            json!({"name": "plain"}),
            json!({"name": "bad/name"}),
            json!({"name": "ctl\u{1b}[31m"}),
            json!({"description": "no name"}),
            json!({"name": 7}),
            json!({"name": "read_file", "annotations": {"readOnlyHint": false}}),
            json!({"name": "both", "annotations": {"readOnlyHint": true, "destructiveHint": true}}),
            json!({"name": "stringy", "annotations": {"readOnlyHint": "true"}}),
        ];
        let d = sort_tools(&entries, true);
        assert_eq!(
            d.tools,
            vec![
                tool("both", false, true, &[]),
                tool("plain", false, false, &[]),
                tool("read_file", true, false, &[("path", "string")]),
                tool("stringy", false, false, &[]),
                tool(
                    "write_file",
                    false,
                    true,
                    &[("force", "bool"), ("mode", "long"), ("path", "string")]
                ),
            ]
        );
        assert_eq!(d.skipped, vec!["\"bad/name\"", "\"ctl\\u{1b}[31m\""]);
        assert_eq!(d.nameless, 2);
        assert_eq!(d.duplicates, 1);
    }

    #[test]
    fn readonly_hints_can_be_ignored() {
        let entries = vec![json!({"name": "read_file", "annotations": {"readOnlyHint": true}})];
        assert!(sort_tools(&entries, true).tools[0].readonly);
        assert!(!sort_tools(&entries, false).tools[0].readonly);
    }

    #[test]
    fn inputs_are_bounded() {
        let props: serde_json::Map<String, Value> = (0..200)
            .map(|i| (format!("a{i}"), json!({"type": "string"})))
            .collect();
        let entries = vec![json!({"name": "t", "inputSchema": {"properties": props}})];
        assert_eq!(sort_tools(&entries, true).tools[0].inputs.len(), MAX_INPUTS);
    }

    #[test]
    fn sse_events_end_at_a_blank_line() {
        assert_eq!(event_end(b"data: 1\n\ndata: 2\n\n"), Some((7, 9)));
        assert_eq!(event_end(b"data: 1\r\n\r\nrest"), Some((8, 11)));
        assert_eq!(event_end(b"event: m\ndata: 1\n\n"), Some((16, 18)));
        assert_eq!(event_end(b"data: 1\n"), None);
        assert_eq!(event_end(b"data: 1\ndata"), None);
        assert_eq!(event_end(b""), None);
    }

    #[test]
    fn toml_keys_and_strings_are_escaped() {
        assert_eq!(toml_key("read_file"), "read_file");
        assert_eq!(toml_key("fs.read"), "\"fs.read\"");
        assert_eq!(toml_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000A\"");
    }

    #[test]
    fn upstream_specs_are_checked() {
        assert_eq!(
            parse_upstream("github=http://127.0.0.1:3001/mcp").unwrap(),
            (
                "github".to_string(),
                "http://127.0.0.1:3001/mcp".to_string()
            )
        );
        for bad in [
            "github",
            "=http://x/mcp",
            "git hub=http://x/mcp",
            "a/b=http://x/mcp",
            "github=ftp://x/mcp",
            "github=not a url",
            "github=http://user:pw@x/mcp",
            "github=http://x/mcp#frag",
            "github=file:///etc/passwd",
        ] {
            assert!(parse_upstream(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn the_policy_lists_what_is_not_permitted() {
        let tools = [
            tool("read_file", true, false, &[]),
            tool("fs.delete-all", false, true, &[]),
        ];
        let p = render_policy("files", Some(&tools));
        assert!(p.contains("@id(\"permit_readonly_tools\")"));
        assert!(p.contains("// @id(\"permit_fs_delete_all\")"));
        assert!(p.contains(
            "// permit(principal, action == Action::\"files/fs.delete-all\", resource);"
        ));
        assert!(p.contains("marked sensitive"));
        assert!(!p.contains("Action::\"files/read_file\""));
        // Without discovery there is nothing to list.
        assert!(!render_policy("files", None).contains("action == Action::"));
    }
}
