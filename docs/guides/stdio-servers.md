# STDIO MCP servers

Most MCP servers people run locally are STDIO programs: the client starts them (`npx some-mcp-server`, `uvx some-server`, a Python script) and talks JSON-RPC to them over stdin and stdout. The attenuo proxy only speaks Streamable HTTP to its upstreams, so it cannot sit in front of such a program directly.

`attenuo stdio-bridge` closes that gap. It starts the STDIO server as a child process and serves it as a Streamable HTTP endpoint on a loopback address. You list that endpoint as an ordinary `[[upstreams]]` entry, and the agent talks to attenuo instead of starting the server itself:

```text
agent ──HTTP──▶ attenuo proxy ──HTTP──▶ stdio-bridge ──stdin/stdout──▶ STDIO server
                /mcp/files              127.0.0.1:3001/mcp              (child process)
```

Every `tools/call` is decided and recorded by attenuo before it reaches the bridge. The bridge itself decides nothing: it is a transport.

## 1. Start the bridge

Give it an address to listen on and, after `--`, the command that starts the server:

```sh
attenuo stdio-bridge --listen 127.0.0.1:3001 -- npx -y @modelcontextprotocol/server-filesystem /srv/docs
```

**Untested** with that server: the command shape is right, but only the test server below was run. Once it is bound, the bridge prints `listening on http://127.0.0.1:3001/mcp` on stdout. The server's own log lines (its stderr) show up on the bridge's stderr.

The server gets the bridge's environment, so pass its API keys there (`GITHUB_TOKEN=... attenuo stdio-bridge ...`). The bridge never prints the server's arguments or environment, and it removes every variable whose name starts with `ATTENUO_` from what the server gets: the CLI's secrets (`ATTENUO_ADMIN_TOKEN`, `ATTENUO_TOKEN`, `ATTENUO_CLIENT_SECRET`, `ATTENUO_DPOP_KEY`), the server's (`ATTENUO_AUDIT_SINK_TOKEN`, `ATTENUO_APPROVAL_NOTIFY_SECRET`) and the `ATTENUO__*` configuration overrides. A variable of another name passes, so do not start the bridge in an environment that holds the server's other secrets under names you chose (`[approvals.notify] secret_env` and `headers`).

If the server cannot be started, or exits later, the bridge exits with status 1. It does not restart the server. Run it under a supervisor (a systemd unit with `Restart=on-failure`, a container restart policy) if you want that. Ctrl-C or SIGTERM stops the bridge and the server with it: the bridge closes the server's stdin, waits up to two seconds, then kills it. Only the process the bridge started is killed: when that is a launcher (`npx`, `uvx`, a shell script) and the real server, its child, does not exit when its stdin closes, the real server keeps running after the bridge is gone (SR-135). Start the server directly, or under a supervisor that stops the whole process group or cgroup, such as a systemd unit.

## 2. Add the upstream

In the server's config, point an `[[upstreams]]` entry at the bridge, and put the server's tools in the catalog like any other upstream's:

```toml
[[upstreams]]
name = "files"
url = "http://127.0.0.1:3001/mcp"

[policy.catalog.files.read_text_file]
readonly = true
inputs = { path = "string" }
```

Capabilities and policies name the tools with that server name: `files:read_text_file`, `Action::"files/read_text_file"`. Nothing in attenuo knows that `files` is a STDIO program.

## 3. Point the agent at attenuo

Remove the server from the agent's own MCP configuration, and give the agent the proxy's URL for it and a delegation token instead:

```text
http://127.0.0.1:8080/mcp/files
Authorization: Bearer <attenuo token>
```

[Integrating MCP clients](integrating-mcp-clients.md) covers the client side.

## Try it with the test server

The repository has a small STDIO server for the bridge's tests, `crates/attenuo-cli/examples/stdio_mcp.rs`. Its tools include `read_file`, `create_issue` and `delete_repo`, the names [Getting started](getting-started.md) uses, so you can run that guide against it. Do steps 1 to 3 of Getting started, then build the test server. Step 2 left you in `~/attenuo-try`, so build from the checkout:

```sh
(cd $REPO && cargo build -p attenuo-cli --example stdio_mcp)
```

In step 4, start the bridge on port 3001 in place of `fake_mcp`:

```sh
$REPO/target/debug/attenuo stdio-bridge --listen 127.0.0.1:3001 -- $REPO/target/debug/examples/stdio_mcp
```

Then go on with step 4 (start `attenuo-server`) and steps 5 to 7. The allowed `read_file` call comes back from the STDIO server; the bridge's terminal shows `stdio-mcp: tools/call read_file {...}`. The denied `create_issue` call never shows up there, and `attenuo audit verify` checks the chain as before. Two outputs differ a little from that guide's: `attenuo tools` lists `read_file` with no description, and the echoed call has `name` before `arguments`.

## What it does not do

Read these before you rely on it.

- **The agent must not be able to start the server itself.** If the agent's machine still has the STDIO server in its MCP configuration, or can run `npx` and has the server's API keys, it can go around attenuo, and attenuo sees nothing of it. The bridge only helps when the server and its credentials live where the agent cannot reach them: another user account, another container, another machine. The [threat model](../spec/threat-model.md) calls these bypass routes.
- **Nobody may reach the bridge but the proxy.** The bridge has no authentication of its own. Anyone who can send it HTTP calls the server without attenuo. That is why it listens on loopback only and refuses another `--listen` address unless you pass `--allow-non-loopback`. Use that flag only when a firewall or a private container network lets nothing but the proxy reach the port. It also refuses any request with an `Origin` header, so a web page in a browser on the same machine cannot call it.
- **No messages from the server to the client.** The server's notifications (progress, log messages, list changes) are dropped. Its requests (sampling, elicitation, roots, ping) are answered at once with a JSON-RPC error, so it does not wait for them. A `GET` for the event stream is answered `405`. Tools that need sampling or elicitation do not work behind the bridge. `--verbose` prints a line for each message dropped, and the bridge prints the counts when it stops.
- **One server process, one MCP session.** Every agent that goes through the proxy to this upstream shares the one child process. The bridge sends the server one `initialize`, the first one it gets, and answers later ones with that first answer, so a second client sees the protocol version and capabilities the first one agreed. Any state the server keeps (an open file, a login, a working directory) is shared by all callers. Run one bridge per isolation boundary you need.
- **Answers come back whole.** The bridge answers each request with one JSON body when the server's answer is complete. A request with no answer within `--timeout` (90 seconds by default) gets HTTP 504 and a JSON-RPC error. Keep `--timeout` below the proxy's `upstream_response_timeout_seconds` (120 by default).
- **No JSON-RPC batches.** A batch is refused with `400`. MCP removed batching in its 2025-06-18 revision.
- **Bounded sizes.** A request body over `--max-request-bytes` (4 MiB) is refused with `413`. A line from the server over `--max-line-bytes` (16 MiB) is dropped, and the request it answered times out.
- SIGTERM handling is Unix only. The bridge has been run on Linux only.

The full list of flags and answers is in the [CLI reference](../reference/cli.md#stdio-bridge---listen-addr----command).
