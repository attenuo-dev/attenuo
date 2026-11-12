# Getting started

This guide takes you from a fresh checkout to a working proxy. You build attenuo, start it in front of an MCP server, mint a token, make an allowed call and a denied call, revoke the token, and read the audit log. It takes about ten minutes, most of it compiling.

attenuo is pre-alpha. This guide runs everything on one machine and uses a development shortcut for the first token. [Identity providers](identity-providers.md) shows how to replace the shortcut with a real login. [Deploying](deploying.md) covers what to change before anyone else can reach the server.

## What you need

- A Rust toolchain. `rust-toolchain.toml` in the repository pins the channel, so `rustup` picks it up on the first build.
- `curl`, `jq` and `openssl`.
- An MCP server that speaks Streamable HTTP. If you do not have one handy, this repository ships a fake one with `read_file`, `create_issue` and `delete_repo` tools. It echoes calls and does nothing else, which is enough here.

## 1. Build

```sh
git clone https://github.com/attenuo-dev/attenuo.git
cd attenuo
cargo build -p attenuo-server -p attenuo-cli
cargo build -p attenuo-proxy --features testing --example fake_mcp
```

You now have three binaries in `target/debug/`: `attenuo-server`, `attenuo` (the CLI) and `examples/fake_mcp`.

## 2. Make a working directory, a key and an admin token

Set `REPO` to your checkout, then make a scratch directory.

```sh
export REPO=$PWD
mkdir -p ~/attenuo-try/data
cd ~/attenuo-try
cp $REPO/config/policies/default.cedar policy.cedar

openssl genpkey -algorithm ed25519 -out data/issuer.pem
chmod 600 data/issuer.pem

export ATTENUO_ADMIN_TOKEN=$(openssl rand -hex 32)

# The sub-agent's client secret, and the hash the server stores.
export CODER_SECRET=$(openssl rand -hex 16)
export CODER_SECRET_SHA256=$(printf %s "$CODER_SECRET" | openssl dgst -sha256 | sed 's/.* //')
```

The issuer key is an Ed25519 key in PKCS#8 PEM form, which is what `openssl genpkey` writes. You can skip generating it. If the file named by `private_key_pem_path` does not exist, the server creates it with mode 0600 on first start. Generating it yourself just shows where it comes from.

The admin token is a static bearer for everything under `/admin`. The server reads it from `[admin] token` in the config file, or from `ATTENUO_ADMIN_TOKEN`, which wins when both are set. The next step writes it into the file. Off a loopback address the server refuses to start with a token shorter than 32 bytes or one copied from an example; on `127.0.0.1` it only warns.

Every agent that receives a delegated token proves who it is with a client secret. The server keeps only the SHA-256 of the secret, so the config gets `CODER_SECRET_SHA256` and the agent keeps `CODER_SECRET`.

## 3. Write a minimal config

Run this in `~/attenuo-try`. The heredoc is unquoted, so your shell fills in the admin token.

```sh
cat > attenuo.toml <<EOF
[server]
listen = "127.0.0.1:8080"

[issuer]
private_key_pem_path = "data/issuer.pem"

[policy]
policies_path = "policy.cedar"

# Every tool a policy names must be in the catalog, with the types of the arguments it tests.
[policy.catalog.github.read_file]
readonly = true
inputs = { repo = "string", path = "string" }

[policy.catalog.github.create_issue]
inputs = { repo = "string", title = "string" }

[policy.catalog.github.delete_repo]
sensitive = true
inputs = { repo = "string" }

[audit]
sqlite_path = "data/attenuo.sqlite"

# The MCP server to protect. "github" is the server part of capabilities such as github:read_file.
[[upstreams]]
name = "github"
url = "http://127.0.0.1:3001/mcp"

[admin]
token = "$ATTENUO_ADMIN_TOKEN"

# Agents that authenticate to POST /token. An exchange must authenticate as its actor.
[[agents]]
id = "coder"
secret_sha256 = "$CODER_SECRET_SHA256"

# The most a root token may carry for this user and agent.
[[root_grants]]
issuer = "https://idp.example"
agent = "planner"
capabilities = ["github:*"]

# DEVELOPMENT ONLY. Lets the admin mint a root token for any user, with no login.
[dev]
allow_root_mint = true
EOF
chmod 600 attenuo.toml
```

The config has more keys than this. `config/example.toml` in the repository is the annotated reference. Tools missing from `[policy.catalog]` are denied (`tool_not_in_catalog`) unless `[policy] unknown_tools` says otherwise, so list every tool your agents should be able to call. Unknown keys are rejected, so a typo stops the server at startup instead of being ignored. Relative paths in the file resolve against the directory you start the server from.

## 4. Run the fake MCP server and attenuo

In one terminal:

```sh
$REPO/target/debug/examples/fake_mcp --port 3001
```

In a second terminal, from `~/attenuo-try` (set `REPO` again there):

```sh
$REPO/target/debug/attenuo-server --config attenuo.toml
```

`ATTENUO_CONFIG=attenuo.toml` works in place of `--config`. The server logs the issuer public key and the policy ids it loaded, then listens on `127.0.0.1:8080`. It also warns that the development root mint is on. That is expected here. Set `RUST_LOG=debug` for more output.

Check that it is up:

```sh
curl -s http://127.0.0.1:8080/healthz
# {"status":"ok","version":"0.1.0"}
```

## 5. Point a client at the proxy

The proxy mounts each upstream at `/mcp/<name>`. For this config, an MCP client connects to:

```text
http://127.0.0.1:8080/mcp/github
```

and sends the header `Authorization: Bearer <attenuo token>`. That is all a client has to change: the URL and the bearer. The proxy does not pass the bearer on to the upstream. [Integrating MCP clients](integrating-mcp-clients.md) covers the client side in detail.

The rest of this guide uses the `attenuo` CLI as the client. It is a thin HTTP client, so everything it does can be done with `curl`.

```sh
export ATTENUO_SERVER=http://127.0.0.1:8080
alias attenuo=$REPO/target/debug/attenuo
```

The CLI reads `ATTENUO_ADMIN_TOKEN` from step 2.

## 6. Mint your first token

A root token is the first link in a delegation chain. Here, user Alice has handed the agent `planner` the right to call any `github` tool. Ask for JSON so you can keep both the token and its lease id.

```sh
ROOT_JSON=$(attenuo --json token root --subject alice --agent planner --cap 'github:*')
ROOT=$(echo "$ROOT_JSON" | jq -r .access_token)
ROOT_LEASE=$(echo "$ROOT_JSON" | jq -r .lease)
```

This uses the development endpoint `POST /admin/root-token`, which trusts you to say who Alice is. In a real deployment the first token comes from a verified login instead. See [Identity providers](identity-providers.md). Everything after this step works the same either way.

Now delegate less to a sub-agent. The `coder` agent gets one tool:

```sh
CODER=$(ATTENUO_TOKEN="$ROOT" ATTENUO_CLIENT_SECRET="$CODER_SECRET" attenuo token exchange --actor coder --cap github:read_file --print token)
attenuo token inspect "$CODER" --verify
```

```text
user alice  (issuer https://idp.example)
  authenticated 2026-10-22T22:14:20Z
└─ agent planner
     can   github:*
     until 2026-10-22T22:29:20Z (in 14m 59s)
     lease 83a988a5-b1a5-48cc-b045-6f2085ccef32
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-10-22T22:29:20Z (in 14m 59s)
        lease c5e66077-7b36-43d2-8333-69d31b0e1e24

may_act (absent): any authenticated agent may exchange this token
verified: signature, type, issuer, audience, expiry, chain
```

The exchange authenticates as `coder` with its client secret (from `ATTENUO_CLIENT_SECRET`, as above, or `--client-secret-stdin` / `--client-secret-file`; avoid `--client-secret`, which shows up in `ps` and shell history), so only `coder` can receive a token in its own name. An exchange can only narrow. If `coder` tried to pass `github:create_issue` on to another agent, the exchange would fail, because the `coder` token only holds `read_file`.

## 7. Make a call

```sh
export ATTENUO_TOKEN="$CODER"   # or --token-file PATH, or --token - to read it from stdin
attenuo tools --upstream github
attenuo call --upstream github --tool read_file --arg repo=acme/api --arg path=README.md
```

```text
ALLOWED
{"name":"read_file","arguments":{"repo":"acme/api","path":"README.md"}}
```

`tools` lists only the tools the token may call. The call went through the whole pipeline: token check, lease check, capability check, Cedar policy, audit append, then the upstream.

Now one that should fail. `coder` was never given `create_issue`:

```sh
attenuo call --upstream github --tool create_issue --arg repo=acme/api --arg title=x
echo $?
```

```text
DENIED  capability_denied
decision bb02c69a-6ac1-47b8-bd62-0ce0f8cd5173
2
```

The CLI exits with 2 when the server said no. The fake MCP server never saw this call. On the wire it is an HTTP 200 carrying a JSON-RPC error:

```sh
curl -s -X POST http://127.0.0.1:8080/mcp/github \
  -H "Authorization: Bearer $CODER" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{"repo":"acme/api","title":"x"}}}'
```

```json
{"jsonrpc":"2.0","id":2,"error":{"code":-32003,"message":"attenuo: denied: capability_denied","data":{"reason":"capability_denied","decision_id":"98849dc3-f053-4649-9b1a-fae0c2f11426"}}}
```

## 8. Revoke

Revoking a lease cuts off that hop and everything delegated from it. Revoke the root lease:

```sh
attenuo lease revoke "$ROOT_LEASE" --reason "trying it out"
attenuo call --upstream github --tool read_file --arg repo=acme/api --arg path=README.md
```

```text
revoked 2 lease(s) starting at 83a988a5-b1a5-48cc-b045-6f2085ccef32 (reason: trying it out)
DENIED  lease_revoked
decision 51282084-9e0e-4a0b-9623-1ba535ab811f
```

The call that worked a minute ago is refused now, although the token has not expired. There is no cache in v0, so a revoke takes effect on the very next request.

## 9. Read the audit log

```sh
attenuo audit tail -n 10
attenuo audit verify
```

```text
#1  2026-10-22T22:14:20Z  ALLOW attenuo/token.root          planner for alice          reason=token_issued
#2  2026-10-22T22:14:20Z  ALLOW attenuo/admin.root_token    by urn:attenuo:admin      reason=admin_action
#3  2026-10-22T22:14:20Z  ALLOW attenuo/token.exchange      planner > coder for alice  reason=token_issued
#4  2026-10-22T22:14:20Z  ALLOW github/read_file             planner > coder for alice  reason=policy_allow
#5  2026-10-22T22:14:20Z  DENY  github/create_issue          planner > coder for alice  reason=capability_denied
#6  2026-10-22T22:14:21Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin      reason=admin_action
#7  2026-10-22T22:14:21Z  DENY  github/read_file             planner > coder for alice  reason=lease_revoked
audit chain OK: 7 entries verified
```

Timestamps and ids are shortened here. Every row names the agents and the user separately, and admin actions (the development root mint, the revocation) are recorded too. Each row also carries the hash of the row before it. `audit verify` walks the whole chain from the start and exits 1 if any row was changed, removed or reordered. The log stores a digest of the call arguments, not the arguments themselves. Use `audit tail --follow` to watch decisions as they happen.

The same data is available over HTTP:

```sh
curl -s "http://127.0.0.1:8080/admin/audit?from=1&limit=20" -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN"
curl -s http://127.0.0.1:8080/admin/audit/verify     -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN"
curl -s http://127.0.0.1:8080/admin/audit/checkpoint -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN"
```

## 10. Change the policy

Cedar policy narrows what a chain already allows. It never widens it. Edit `policy.cedar`, then reload without a restart:

```sh
attenuo policy reload
```

```text
reloaded 5 policies
  forbid_deep_chains
  forbid_sensitive_without_mfa
  permit_create_issue_in_acme
  permit_delete_acme_sandbox_repo
  permit_readonly_tools
```

If the new file does not parse or does not validate against the catalog, the old policy stays in force and the command reports why. The starter policy permits read-only tools, permits `create_issue` only in a repository `acme/<name>` (one `/`, a name that is not empty, `.` or `..`), permits `delete_repo` only on `acme/sandbox-<name>`, caps chain depth at 3, and requires MFA for tools marked `sensitive` (so the sandbox delete needs MFA too). The token still has to grant a tool before any of this applies. The GitHub leak demo has a smaller policy you can read in a minute: [examples/github-leak-demo/policy.cedar](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/policy.cedar).

## Where to go next

- Replay a real incident end to end with [examples/github-leak-demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md). `run.sh` does the whole thing in about a second once the workspace is built; the first run spends about a minute and a half compiling on a 4-core machine.
- Watch delegation narrow over three hops with [examples/multi-hop-demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/multi-hop-demo/README.md): a planner hands a coder less than it holds, the coder cannot pass its token on, and one `lease revoke --chain-id` ends the run.
- Replace the development mint with a real login: [Identity providers](identity-providers.md).
- Put this on something other than your laptop: [Deploying](deploying.md).
- Write the agent side: [Integrating MCP clients](integrating-mcp-clients.md).
- Read how a request is decided: [design/server.md](../design/server.md).
