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

This command was run against version 2.4.0 of that server; [the walkthrough below](#try-it-with-a-real-server) has the config and policy that go with it. Once it is bound, the bridge prints `listening on http://127.0.0.1:3001/mcp` on stdout. The server's own log lines (its stderr) show up on the bridge's stderr.

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

## Try it with a real server

This puts attenuo in front of the reference filesystem server, `@modelcontextprotocol/server-filesystem`, and lets an agent read one folder and nothing else. It was run on Linux with version 2.4.0 of that server, Node 22 and attenuo 0.1.0. You need `attenuo-server` and the `attenuo` CLI built (step 1 of [Getting started](getting-started.md)), plus `node`, `jq` and `openssl`.

Make two folders, one the agent may read and one it may not:

```sh
export REPO=$PWD            # your attenuo checkout
mkdir -p ~/attenuo-files/data ~/attenuo-files/docs/public ~/attenuo-files/docs/private
cd ~/attenuo-files
echo "hello public" > docs/public/readme.txt
echo "not for agents" > docs/private/salaries.txt
```

Start the bridge in one terminal. The filesystem server itself is told to serve all of `docs`; attenuo will narrow that:

```sh
$REPO/target/debug/attenuo stdio-bridge --listen 127.0.0.1:3001 -- \
  npx -y @modelcontextprotocol/server-filesystem@2.4.0 $HOME/attenuo-files/docs
```

In a second terminal, from `~/attenuo-files` (set `REPO` again), write a policy and a config. The policy permits reading text files under `docs/public` and refuses any path with `..` in it. The filesystem server resolves `..` itself, so without that line `docs/public/../private/salaries.txt` would match `docs/public/*`:

```sh
cat > policy.cedar <<EOF
@id("read_public_docs_only")
permit(principal, action == Action::"files/read_text_file", resource)
when {
  context.input has path &&
  context.input.path like "$HOME/attenuo-files/docs/public/*" &&
  !(context.input.path like "*..*")
};
EOF

export ATTENUO_ADMIN_TOKEN=$(openssl rand -hex 32)
export CODER_SECRET=$(openssl rand -hex 16)
export CODER_SECRET_SHA256=$(printf %s "$CODER_SECRET" | openssl dgst -sha256 | sed 's/.* //')

cat > attenuo.toml <<EOF
[server]
listen = "127.0.0.1:8080"

[issuer]
private_key_pem_path = "data/issuer.pem"

[policy]
policies_path = "policy.cedar"

[policy.catalog.files.read_text_file]
readonly = true
inputs = { path = "string" }

[policy.catalog.files.write_file]
inputs = { path = "string", content = "string" }

[audit]
sqlite_path = "data/attenuo.sqlite"

[[upstreams]]
name = "files"
url = "http://127.0.0.1:3001/mcp"

[admin]
token = "$ATTENUO_ADMIN_TOKEN"

[[agents]]
id = "coder"
secret_sha256 = "$CODER_SECRET_SHA256"

[[root_grants]]
issuer = "https://idp.example"
agent = "planner"
capabilities = ["files:*"]

# DEVELOPMENT ONLY. Lets the admin mint a root token for any user, with no login.
[dev]
allow_root_mint = true
EOF
chmod 600 attenuo.toml

$REPO/target/debug/attenuo-server --config attenuo.toml &
```

Mint a root token for the `planner` agent, hand the `coder` agent `read_text_file` only, and make four calls:

```sh
export ATTENUO_SERVER=http://127.0.0.1:8080
alias attenuo=$REPO/target/debug/attenuo
ROOT=$(attenuo --json token root --subject alice --agent planner --cap 'files:*' | jq -r .access_token)
export ATTENUO_TOKEN=$(ATTENUO_TOKEN="$ROOT" ATTENUO_CLIENT_SECRET="$CODER_SECRET" \
  attenuo token exchange --actor coder --cap files:read_text_file --print token)

attenuo call --upstream files --tool read_text_file --arg path=$HOME/attenuo-files/docs/public/readme.txt
attenuo call --upstream files --tool read_text_file --arg path=$HOME/attenuo-files/docs/private/salaries.txt
attenuo call --upstream files --tool read_text_file --arg path=$HOME/attenuo-files/docs/public/../private/salaries.txt
attenuo call --upstream files --tool write_file --arg path=$HOME/attenuo-files/docs/public/x.txt --arg content=hi
attenuo audit verify
```

```text
ALLOWED
hello public

DENIED  policy_deny
decision 2ba9912e-01da-4f1d-9c58-2a06381c9674
DENIED  policy_deny
decision 0ba3ab6e-932c-4132-b208-0559a2080a7c
DENIED  capability_denied
decision 143acf15-b581-4f88-b109-fd5139905f18
audit chain OK: 8 entries verified
checkpoints: none signed yet
```

Your decision ids will differ. The first read reaches the filesystem server. The two reads outside `docs/public` are refused by the policy, and the write is refused before the policy runs, because `coder` was never handed `write_file`. No denied call reaches the filesystem server, and `x.txt` is not created. `attenuo tools --upstream files` lists only `read_text_file`, although the server offers sixteen tools.

What this run does not show: whether a symbolic link inside `docs/public` that points elsewhere is followed is up to the filesystem server, not attenuo, which sees only the path text. Tools that take several paths (`read_multiple_files`, `move_file`) need their own catalog entries and policies before you delegate them.

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
