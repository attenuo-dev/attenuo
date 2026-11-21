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
//! - **`annotations.readOnlyHint`** is the server's own claim, and attenuo's rule is that an
//!   annotation may only narrow (ADR-0009). So by default it is not believed: no tool is
//!   marked `readonly`, the starter policy permits nothing, and the tools that carry the hint
//!   are only listed, for the operator to judge. `--trust-readonly-hints` is the operator
//!   saying "I trust this server's hints": then those tools are marked `readonly`, which the
//!   starter policy permits.
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
use crate::sse::{event_end, parse_event};

/// Most tools read from one server, and most `tools/list` pages followed.
const MAX_TOOLS: usize = 2000;
const MAX_PAGES: usize = 200;
/// Most inputs kept for one tool.
const MAX_INPUTS: usize = 64;
/// Largest `tools/list` or `initialize` answer read, in bytes.
const MAX_BODY: usize = 16 * 1024 * 1024;
/// Largest total of all answers read from one server, in bytes.
const MAX_TOTAL: usize = 48 * 1024 * 1024;
/// The MCP protocol revision offered in `initialize`.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// The file names written into the directory.
const CONFIG_FILE: &str = "attenuo.toml";
const POLICY_FILE: &str = "policy.cedar";
const ENV_FILE: &str = "attenuo.env";
/// The server name attenuo keeps for its own audit records (SR-34).
const RESERVED_SERVER: &str = "attenuo";

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
    /// Kept tools the server says only read (`readOnlyHint`), whether or not that is
    /// believed; never one it also calls destructive.
    pub claimed_readonly: Vec<String>,
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
        let sensitive = hint("destructiveHint");
        // A server that calls one tool both read-only and destructive contradicts itself:
        // the read-only claim is the one that could permit a call, so it is dropped.
        let claims_readonly = hint("readOnlyHint") && !sensitive;
        if claims_readonly {
            d.claimed_readonly.push(name.to_string());
        }
        d.tools.push(Tool {
            name: name.to_string(),
            readonly: trust_readonly && claims_readonly,
            sensitive,
            inputs: inputs_of(entry.get("inputSchema")),
        });
    }
    d.claimed_readonly.sort();
    d.tools.sort_by(|a, b| a.name.cmp(&b.name));
    d
}

/// The JSON-RPC response carried by one SSE event: its `data:` lines joined with a line
/// feed, as the SSE format says, and parsed as one JSON text. `None` for an event that is
/// something else (a comment, a notification, a request of the server's own).
fn sse_event_reply(event: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(&parse_event(event).data?).ok()?;
    (v.get("result").is_some() || v.get("error").is_some()).then_some(v)
}

/// A value the MCP server gave that goes back to it in a header: visible ASCII, bounded.
pub(crate) fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// The conversation with one MCP server.
struct Mcp<'a> {
    http: reqwest::Client,
    url: &'a str,
    session: Option<String>,
    protocol: Option<String>,
    /// Bytes of answers that may still be read, over the whole conversation.
    budget: usize,
}

impl Mcp<'_> {
    /// One JSON-RPC exchange. Returns the response headers and, for a request (a message
    /// with an id), the JSON-RPC response, which is a result and carries the request's id.
    async fn rpc(&mut self, body: &Value) -> Result<(reqwest::header::HeaderMap, Option<Value>)> {
        let mut req = self
            .http
            .post(self.url)
            .header("accept", "application/json, text/event-stream")
            .json(body);
        if let Some(s) = &self.session {
            req = req.header("mcp-session-id", s);
        }
        if let Some(p) = &self.protocol {
            req = req.header("mcp-protocol-version", p);
        }
        let method = body.get("method").and_then(Value::as_str).unwrap_or("?");
        let mut resp = req
            .send()
            .await
            .with_context(|| format!("could not reach the MCP server at {}", self.url))?;
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
        let mut bytes: Vec<u8> = Vec::new();
        // Where the next unread SSE event starts, and from where its end is still to be
        // looked for: every byte is scanned once, however small the pieces it arrives in.
        let mut event_start = 0;
        let mut scan_from = 0;
        let mut reply = None;
        'read: while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("reading the MCP server's answer to `{method}`"))?
        {
            if chunk.len() > self.budget || bytes.len() + chunk.len() > MAX_BODY {
                bail!("the MCP server's answer to `{method}` is too large (one answer may be {MAX_BODY} bytes, all of them together {MAX_TOTAL})");
            }
            self.budget -= chunk.len();
            bytes.extend_from_slice(&chunk);
            if !sse {
                continue;
            }
            // An SSE answer may stay open after the response event: stop once it is there.
            while let Some((end, next)) = event_end(&bytes, scan_from) {
                let event = String::from_utf8_lossy(&bytes[event_start..end]);
                event_start = next;
                scan_from = next;
                if let Some(v) = sse_event_reply(&event) {
                    reply = Some(v);
                    break 'read;
                }
            }
            // No blank line up to here. One may still straddle the end (`\n` now, `\n` or
            // `\r\n` in the next piece), so step back over at most two bytes.
            scan_from = scan_from.max(bytes.len().saturating_sub(2));
        }
        let rest = String::from_utf8_lossy(&bytes[event_start..]);
        let reply = match reply {
            Some(v) => Some(v),
            // A last SSE event that no blank line ended.
            None if sse => sse_event_reply(&rest),
            None => parse_rpc_body(&rest, false),
        }
        .with_context(|| {
            format!("the MCP server's answer to `{method}` is not a JSON-RPC response")
        })?;
        if reply.get("id") != body.get("id") {
            bail!("the MCP server answered `{method}` with the id of another request");
        }
        if let Some(err) = reply.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            bail!("the MCP server refused `{method}` (JSON-RPC error {code})");
        }
        Ok((headers, Some(reply)))
    }

    /// `notifications/initialized`, then every page of `tools/list`.
    async fn list_tools(&mut self) -> Result<Vec<Value>> {
        self.rpc(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await?;
        let mut entries = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..MAX_PAGES {
            let mut params = serde_json::Map::new();
            if let Some(c) = &cursor {
                params.insert("cursor".into(), Value::String(c.clone()));
            }
            let (_, reply) = self
                .rpc(&json!({"jsonrpc": "2.0", "id": page + 2, "method": "tools/list", "params": params}))
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
                _ => return Ok(entries),
            }
        }
        bail!("the MCP server's `tools/list` did not end within {MAX_PAGES} pages")
    }
}

/// Ask the MCP server at `url` for its tools: the raw entries of every `tools/list` page.
pub(crate) async fn discover(url: &str) -> Result<Vec<Value>> {
    let mut mcp = Mcp {
        http: http_client()?,
        url,
        session: None,
        protocol: None,
        budget: MAX_TOTAL,
    };
    let (headers, reply) = mcp
        .rpc(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "attenuo-init", "version": env!("CARGO_PKG_VERSION")}
            }
        }))
        .await?;
    // Both values go back to the server in headers.
    if let Some(id) = headers.get("mcp-session-id") {
        match id.to_str().ok().filter(|s| header_safe(s)) {
            Some(s) => mcp.session = Some(s.to_string()),
            None => bail!("the MCP server's Mcp-Session-Id cannot be sent back: it is longer than 256 bytes or not visible ASCII"),
        }
    }
    mcp.protocol = Some(
        reply
            .as_ref()
            .and_then(|r| r.pointer("/result/protocolVersion"))
            .and_then(Value::as_str)
            .filter(|s| header_safe(s))
            .unwrap_or(PROTOCOL_VERSION)
            .to_string(),
    );

    let listed = mcp.list_tools().await;

    // End the session whatever happened; a server may not support it, so the answer is ignored.
    if let Some(s) = &mcp.session {
        let mut req = mcp.http.delete(url).header("mcp-session-id", s);
        if let Some(p) = &mcp.protocol {
            req = req.header("mcp-protocol-version", p);
        }
        let _ = req.send().await;
    }
    listed
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
                 # arguments a policy can test. A tool the server adds later is denied until you\n\
                 # add it here.\n\
                 #\n\
                 # `sensitive = true` is from the server's destructiveHint annotation.\n\
                 # `readonly = true` appears only when `attenuo init` ran with\n\
                 # --trust-readonly-hints: it is the server's own readOnlyHint, and the starter\n\
                 # policy permits every readonly tool. Set it yourself for a tool you know only\n\
                 # reads; a readonly tool is also never treated as destructive.\n\n",
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
         // set per tool in [policy.catalog] of attenuo.toml. `attenuo init` sets it only with\n\
         // --trust-readonly-hints (the MCP server's own claim); otherwise set it yourself.\n\
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
    // Policy ids must be unique, and `a-b`, `a_b` and `a.b` would all give `permit_a_b`.
    let mut ids: std::collections::BTreeSet<String> =
        ["permit_readonly_tools", "forbid_deep_chains"]
            .into_iter()
            .map(String::from)
            .collect();
    for t in rest {
        let base = format!("permit_{}", t.name.replace(['.', '-'], "_"));
        let mut id = base.clone();
        let mut n = 2;
        while !ids.insert(id.clone()) {
            id = format!("{base}_{n}");
            n += 1;
        }
        s.push_str(&format!(
            "\n// {name}{note}\n// @id(\"{id}\")\n// permit(principal, action == Action::\"{upstream}/{name}\", resource);\n",
            name = t.name,
            note = if t.sensitive {
                " (marked sensitive: the server says it can destroy data)"
            } else {
                ""
            },
        ));
    }
    s
}

/// The text of `attenuo.env`.
fn render_env(listen: std::net::SocketAddr, admin_token: &str, coder_secret: &str) -> String {
    format!(
        "# Written by `attenuo init`. Secrets: keep this file readable by you only (0600).\n\
         # Load it into a shell with:  . ./attenuo.env\n\
         export ATTENUO_SERVER='http://{listen}'\n\
         export ATTENUO_ADMIN_TOKEN='{admin_token}'\n\
         # The client secret of the agent `coder`, for `attenuo token exchange --actor coder`.\n\
         export ATTENUO_CLIENT_SECRET='{coder_secret}'\n"
    )
}

/// `NAME=URL`, checked.
fn parse_upstream(spec: &str) -> Result<(String, String)> {
    let (name, url) = spec
        .split_once('=')
        .context("--upstream takes NAME=URL, for example github=http://127.0.0.1:3001/mcp")?;
    attenuo_core::names::check_server_name(name)
        .map_err(|e| anyhow::anyhow!("--upstream: the name is not a valid server name: {e}"))?;
    if name == RESERVED_SERVER {
        bail!("--upstream: the name `{RESERVED_SERVER}` is not a valid server name: it is reserved for the server's own audit records");
    }
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

/// Whether something is at `path`, a symbolic link that points nowhere included.
fn occupied(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// A file being written next to its final place. It is moved there by [`Pending::commit`]
/// and removed when dropped before that.
struct Pending {
    tmp: PathBuf,
    dest: PathBuf,
    done: bool,
}

impl Pending {
    /// Write `text` to a new file beside `dest`, mode 0600 when `secret` and 0644 otherwise.
    fn write(dest: &Path, text: &str, secret: bool) -> Result<Self> {
        let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let tmp = dest.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        // `create_new` never follows a link and never reuses a file someone else made.
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(if secret { 0o600 } else { 0o644 });
        }
        #[cfg(not(unix))]
        let _ = secret;
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("could not create {}", tmp.display()))?;
        let pending = Self {
            tmp,
            dest: dest.to_path_buf(),
            done: false,
        };
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .with_context(|| format!("could not write {}", pending.tmp.display()))?;
        Ok(pending)
    }

    /// Move the file to its place. With `force`, a rename replaces what is there, a symbolic
    /// link too (the link itself, not the file it points to), and the new file keeps its
    /// own mode.
    ///
    /// Without `force` nothing is replaced: the file is linked into place, which fails when
    /// something is already there, however late it appeared.
    fn commit(mut self, force: bool) -> Result<()> {
        if !force {
            match std::fs::hard_link(&self.tmp, &self.dest) {
                // The temporary name is removed when `self` is dropped.
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    bail!(
                        "{} already exists; it was left as it is",
                        self.dest.display()
                    )
                }
                // A filesystem without hard links: fall back to the rename.
                Err(_) => {}
            }
        }
        std::fs::rename(&self.tmp, &self.dest)
            .with_context(|| format!("could not create {}", self.dest.display()))?;
        self.done = true;
        Ok(())
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
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
            if occupied(&dir.join(f)) {
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
        Some(sort_tools(&entries, args.trust_readonly_hints))
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

    std::fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    // The issuer key and the audit log will live in data/. A directory that is already
    // there is the operator's: it is left as it is.
    let data = dir.join("data");
    if !occupied(&data) {
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&data)
            .with_context(|| format!("could not create {}", data.display()))?;
    }
    // All three are written in full before any takes its place, so a failure part-way
    // leaves no half-made set behind.
    let pending = [
        Pending::write(&dir.join(CONFIG_FILE), &config, true)?,
        Pending::write(&dir.join(POLICY_FILE), &policy, false)?,
        Pending::write(&dir.join(ENV_FILE), &env, true)?,
    ];
    if !args.force {
        // Again, now that the MCP server has been asked: something may have appeared.
        for f in files {
            if occupied(&dir.join(f)) {
                bail!(
                    "{} already exists; nothing was written",
                    dir.join(f).display()
                );
            }
        }
    }
    for p in pending {
        p.commit(args.force)?;
    }

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
            let permitted: Vec<&str> = d
                .tools
                .iter()
                .filter(|t| t.readonly)
                .map(|t| t.name.as_str())
                .collect();
            outln!("{} tools found on `{upstream}`.", d.tools.len())?;
            if !permitted.is_empty() {
                outln!(
                    "Permitted by the starter policy, on the server's word that they only read ({}):",
                    permitted.len()
                )?;
                for chunk in permitted.chunks(6) {
                    outln!("  {}", chunk.join(", "))?;
                }
                outln!("Every other tool is denied until you write a permit in {POLICY_FILE}.")?;
            } else {
                outln!("None is permitted yet: every call is denied until you allow it in {POLICY_FILE}.")?;
                if !d.claimed_readonly.is_empty() {
                    outln!(
                        "The server says these only read ({}):",
                        d.claimed_readonly.len()
                    )?;
                    for chunk in d.claimed_readonly.chunks(6) {
                        outln!("  {}", chunk.join(", "))?;
                    }
                    outln!("That is the server's own claim. If you trust it, run again with")?;
                    outln!(
                        "--trust-readonly-hints --force to permit them, or set `readonly = true`"
                    )?;
                    outln!("in {CONFIG_FILE} for the ones you have checked.")?;
                }
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
        .and_then(|d| d.tools.iter().find(|t| t.readonly).or(d.tools.first()))
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
        // `both` contradicts itself and `stringy` is not a boolean: neither counts.
        assert_eq!(d.claimed_readonly, vec!["read_file"]);
    }

    #[test]
    fn readonly_hints_can_be_ignored() {
        let entries = vec![json!({"name": "read_file", "annotations": {"readOnlyHint": true}})];
        assert!(sort_tools(&entries, true).tools[0].readonly);
        // Not believed, but still reported.
        let d = sort_tools(&entries, false);
        assert!(!d.tools[0].readonly);
        assert_eq!(d.claimed_readonly, vec!["read_file"]);
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
    fn an_sse_event_may_spread_its_json_over_data_lines() {
        let one = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        assert_eq!(sse_event_reply(one).unwrap()["id"], 1);
        let split = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":2,\r\ndata:\"result\":{}}";
        assert_eq!(sse_event_reply(split).unwrap()["id"], 2);
        // Not a response: a comment, a notification, a request from the server, bad JSON.
        for other in [
            ": keep-alive",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}",
            "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}",
            "data: {",
            "",
        ] {
            assert!(sse_event_reply(other).is_none(), "{other}");
        }
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
            "attenuo=http://x/mcp",
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
        // Names that differ only in `.`, `-` and `_`, and one that would take the id of a
        // policy the file already has: every id is still unique.
        let tools = [
            tool("a-b", false, false, &[]),
            tool("a.b", false, false, &[]),
            tool("a_b", false, false, &[]),
            tool("readonly_tools", false, false, &[]),
        ];
        let p = render_policy("s", Some(&tools));
        let mut ids: Vec<&str> = p
            .lines()
            .filter_map(|l| l.trim_start_matches("// ").strip_prefix("@id(\""))
            .map(|l| l.trim_end_matches("\")"))
            .collect();
        assert_eq!(ids.len(), 6, "{p}");
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 6, "{p}");
        assert!(p.contains("@id(\"permit_a_b_2\")") && p.contains("@id(\"permit_a_b_3\")"));
        assert!(p.contains("// @id(\"permit_readonly_tools_2\")"));
        // Without discovery there is nothing to list.
        assert!(!render_policy("files", None).contains("action == Action::"));
    }
}
