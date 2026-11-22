# Walkthrough: the HTTP API, the CLI and the SDKs

This page runs a server from a checkout and goes through one delegation by hand: a root token, an exchange for a sub-agent, an allowed call, a denied call and a revocation. First with `curl`, then the same with the `attenuo` command line and with the Python and TypeScript SDKs. [Getting started](getting-started.md) covers the same ground more slowly, with a config you write yourself.

You need a Rust toolchain, `curl`, `jq` and `openssl`. Run the commands from the root of a checkout.

## Run the server

<!-- scripts/check-doc-commands.sh docs/guides/walkthrough.md (CI job getting-started) runs every sh block of this page in order and compares its output with the text or json block right after it. Run it when you change a command or an output here. The "check:" comments before some blocks tell it how to run them. -->

Run the server with the example config. It generates an issuer key in `data/` on first start, keeps the audit log and lease registry in `data/attenuo.sqlite`, and proxies an MCP server expected at `http://127.0.0.1:3001/mcp` as `github` (edit `[[upstreams]]` to point at yours, or start the repository's fake one there, as below). Build the server, the CLI and the fake MCP server (the commands below run them from `target/debug/`; use `$CARGO_TARGET_DIR/debug/` if you set it):

<!-- check: build -->
```sh
cargo build -p attenuo-server
cargo build -p attenuo-cli
cargo build -p attenuo-proxy --features testing --example fake_mcp
```

The flows below start from a root token. A deployment mints it from the user's identity provider ([hop 0](#hop-0-from-your-identity-provider)). To try them without one, run a copy of the example config with the development-only root mint switched on ([development only](#development-only-a-root-token-without-an-idp)), and pick an admin token:

```sh
mkdir -p data
sed 's/^allow_root_mint = false/allow_root_mint = true/' config/example.toml > data/dev.toml
export ATTENUO_ADMIN_TOKEN=$(openssl rand -hex 32)   # the /admin bearer; overrides [admin] token
```

Start the fake MCP server in one terminal:

<!-- check: background -->
```sh
target/debug/examples/fake_mcp --port 3001
```

and attenuo in a second one, from the checkout, with the same `ATTENUO_ADMIN_TOKEN` exported:

<!-- check: background -->
```sh
target/debug/attenuo-server --config data/dev.toml   # or ATTENUO_CONFIG=data/dev.toml
```

With an identity provider, run `config/example.toml` as it ships instead. The example ships no admin token. On a loopback `listen` address a missing, short or placeholder token only produces a warning (and without one the admin routes answer 403); on any other address the server refuses to start unless the token is at least 32 bytes and not a published placeholder, or named operators with their own tokens and roles are configured instead (`[[admin.operators]]`, `attenuo admin operator new`). Revocations, policy reloads and dev root mints are written to the audit log as admin actions, under the operator who took them.

The flows below use `curl` and `jq`, in a third terminal with the same `ATTENUO_ADMIN_TOKEN`. [Getting started](getting-started.md) covers the same ground step by step.

```sh
SRV=http://127.0.0.1:8080
ADMIN=$ATTENUO_ADMIN_TOKEN   # as the server got it
curl -s $SRV/healthz
```

```json
{"status":"ok","version":"0.2.0"}
```

### Hop 0 from your identity provider

The first token in a chain is minted from a credential the user's IdP issued: an OIDC ID token, or an ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant). Any OIDC issuer works. List it under `[[idps]]` (its JWKS is found through `/.well-known/openid-configuration` unless you set `jwks_url`), register the agent under `[[agents]]`, and cap what the agent may get for those users under `[[root_grants]]`:

```toml
[[idps]]
issuer = "https://your-tenant.example.com"   # exact `iss`
client_ids = { planner = "your-client-id" }   # agent id -> the `aud` its ID tokens carry

[[agents]]
id = "planner"
secret_sha256 = "..."                        # printf %s "$SECRET" | sha256sum

[[root_grants]]
issuer = "https://your-tenant.example.com"
agent = "planner"
capabilities = ["github:*"]
```

An ID token is accepted only from the agent whose `client_ids` entry its `aud` names (an agent without an entry must have a client id equal to its agent id). The agent exchanges the user's ID token for a root delegation token (RFC 8693), authenticating with its own client credentials. The token's originating user comes from the verified ID token: `sub`, `iss`, `auth_time`, the configured `attribute_claims`, and an `mfa` flag derived from `amr`.

<!-- check: skip needs an ID token from a real identity provider; the next section mints the root token without one -->
```sh
ID_TOKEN=...   # from your IdP's login flow

# 1. Exchange the user's ID token for a root token held by "planner".
ROOT=$(curl -s -X POST $SRV/token -u planner:planner-secret-change-me \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$ID_TOKEN \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  --data-urlencode scope=github:*)
ROOT_TOKEN=$(echo "$ROOT" | jq -r .access_token); ROOT_LEASE=$(echo "$ROOT" | jq -r .lease)
```

For an ID-JAG, send `subject_token_type=urn:ietf:params:oauth:token-type:id-jag` (or `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with `assertion=`). Its `aud` must be `[issuer] issuer` and its `client_id` must be the authenticated agent. The CLI sends the same exchange with `attenuo token exchange --subject-token-type id-token` (or `id-jag`; see the [CLI reference](../reference/cli.md#hop-0-from-an-id-token)). Failures come back as `invalid_client` (401), or as `invalid_grant` or `invalid_scope` (400), each with a stable `code` (also in `error_description`, deprecated as a machine field) such as `audience_mismatch`, `expired`, `unknown_kid` or `scope_exceeds_grant`.

### Development only: a root token without an IdP

`data/dev.toml` above sets `[dev] allow_root_mint = true` (`config/example.toml` ships with `false`). This mounts `POST /admin/root-token`, which mints a root token for whichever user the admin names. Nothing about that user is verified, so it is for local development only: the server logs a warning at startup, and refuses to start with the setting on when the admin API's listener (`[admin] listen` when set, else `[server] listen`) is not a loopback address. With the setting off (the default) the route does not exist and answers 404. Use it in place of step 1:

```sh
ROOT=$(curl -s -X POST $SRV/admin/root-token -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"subject":"alice","issuer":"https://idp.example","agent":"planner","capabilities":["github:*"]}')
ROOT_TOKEN=$(echo "$ROOT" | jq -r .access_token); ROOT_LEASE=$(echo "$ROOT" | jq -r .lease)
```

### Delegate, call, revoke

RFC 8693 exchange: the planner delegates `read_file` only to a `coder` sub-agent. The coder authenticates as itself (`[[agents]]`); only it can receive a token in its name.

```sh
CHILD_TOKEN=$(curl -s -X POST $SRV/token -u coder:coder-secret-change-me \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$ROOT_TOKEN \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode actor=coder \
  --data-urlencode scope=github:read_file | jq -r .access_token)
```

Call through the proxy: `read_file` is allowed and forwarded upstream.

```sh
mcp() { curl -s -X POST $SRV/mcp/github -H "Authorization: Bearer $CHILD_TOKEN" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$1"; }
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"acme/api"}}}'
```

```json
{"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"{\"arguments\":{\"repo\":\"acme/api\"},\"name\":\"read_file\"}","type":"text"}],"isError":false}}
```

The fake server echoes the call. The proxy records the answer in the audit log as untrusted output: an argument of a later call in the run that copies a value from it is listed in that call's `untrusted_args`, as in the next answer.

A denial: the coder was never delegated `create_issue`.

```sh
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{"repo":"acme/api","title":"x"}}}'
```

```json
{"jsonrpc":"2.0","id":2,"error":{"code":-32003,"message":"attenuo: denied: capability_denied","data":{"reason":"capability_denied","decision_id":"86bdd6bf-1cce-4b77-9d3d-fa6fc2b4f0e7","untrusted_args":[{"arg":"repo","seq":5,"kind":"leaf"},{"arg":"repo","seq":5,"kind":"entity"}],"code":"capability_denied"}}}
```

Revoke the root lease. The revocation cascades to the coder's lease, and the coder's next call is denied.

```sh
curl -s -X POST $SRV/admin/leases/$ROOT_LEASE/revoke -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' -d '{"reason":"demo"}'
```

```json
{"lease_id":"3cdebe33-0a21-45ee-aadb-5badd8e77f24","revoked":2,"reason":"demo","audit_id":"4e1f2c18-a341-4e2b-a4a8-ccc0f7c996b8"}
```

```sh
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"acme/api"}}}'
```

```json
{"jsonrpc":"2.0","id":3,"error":{"code":-32003,"message":"attenuo: denied: lease_revoked","data":{"reason":"lease_revoked","decision_id":"88b41a87-13fe-4dbb-8b11-3af7f7dfd8f9","code":"lease_revoked"}}}
```

Every decision and issuance is in the hash-chained audit log.

```sh
curl -s $SRV/admin/audit/verify -H "Authorization: Bearer $ADMIN"
```

```json
{"entries":8,"ok":true,"first_bad_seq":null,"checkpoints":0,"last_signed_seq":null,"unsigned_tail":8,"bad_checkpoints":[],"pruned_through":null,"anchors":0,"bad_anchors":[]}
```

```sh
curl -s "$SRV/admin/audit?from=1&limit=20" -H "Authorization: Bearer $ADMIN" | jq -c '.entries[].record | {decision,reason,tool,agents}'
```

```json
{"decision":"allow","reason":"token_issued","tool":"token.root","agents":["planner"]}
{"decision":"allow","reason":"admin_action","tool":"admin.root_token","agents":[]}
{"decision":"allow","reason":"token_issued","tool":"token.exchange","agents":["planner","coder"]}
{"decision":"allow","reason":"policy_allow","tool":"read_file","agents":["planner","coder"]}
{"decision":"allow","reason":"tool_result","tool":"read_file","agents":["planner","coder"]}
{"decision":"deny","reason":"capability_denied","tool":"create_issue","agents":["planner","coder"]}
{"decision":"allow","reason":"admin_action","tool":"admin.lease.revoke","agents":[]}
{"decision":"deny","reason":"lease_revoked","tool":"read_file","agents":["planner","coder"]}
```

Other endpoints: `POST /token/renew` (extend your lease), `POST /access/v1/evaluation`, `/evaluations` and `/search/action` (AuthZEN, single, batch and action search; the delegation token as bearer is required unless `[authzen] allow_unsigned_chain` is set for authenticated `[[peps]]`), `GET /.well-known/jwks.json`, `GET /.well-known/authzen-configuration`, `POST /admin/policies/reload`, `GET /admin/leases/{id}`, `GET /admin/leases/{id}/tree`, `POST /approvals/{id}` (the user grants or declines with an ID token) and `/admin/approvals` (the operator does), `POST /admin/budgets/refund`, `GET /admin/audit/checkpoint` (signed), `GET /admin/audit/export`, `GET /healthz`, `GET /readyz`. The request pipeline is described in [docs/design/server.md](../design/server.md). Set `RUST_LOG=debug` for more logging, `[logging] format = "json"` (or `ATTENUO_LOG_FORMAT=json`) for one JSON object per line, and `[logging] redact_subjects = true` to write user subjects into log lines as a keyed digest ([config reference](../reference/config.md#logging)).

## Command line

`attenuo` (crate `attenuo-cli`) talks HTTP to a running server, so the `curl` flow above becomes:

```sh
export ATTENUO_SERVER=http://127.0.0.1:8080   # and ATTENUO_ADMIN_TOKEN, as the server got it
export PATH=$PWD/target/debug:$PATH   # or $CARGO_TARGET_DIR/debug

# token root uses the dev mint: it needs [dev] allow_root_mint = true (data/dev.toml above; local
# development only). With the example config as shipped it gets a 404.
ROOT_JSON=$(attenuo --json token root --subject alice --issuer https://idp.example --agent planner --cap 'github:*')
ROOT_TOKEN=$(echo "$ROOT_JSON" | jq -r .access_token); ROOT_LEASE=$(echo "$ROOT_JSON" | jq -r .lease)
CHILD_TOKEN=$(printf '%s\n' coder-secret-change-me | ATTENUO_TOKEN="$ROOT_TOKEN" attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print token)
attenuo token inspect "$CHILD_TOKEN" --verify      # the chain as a tree; --verify checks it against the server's JWKS
```

```text
user alice  (issuer https://idp.example)
  authenticated 2026-11-13T12:39:13Z
  attributes mfa=false
└─ agent planner
     can   github:*
     until 2026-11-13T12:54:13Z (in 14m 59s)
     lease 54cd811d-a767-4487-b875-61cf6ea785c1
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-11-13T12:54:13Z (in 14m 59s)
        lease 6ef1b201-6aec-4c2c-8b86-1165773cf251

iss http://127.0.0.1:8080   aud attenuo   jti 41ef2119-6fd8-4ad8-b0c6-6aa5a7375bbf
kid SIGySX_YgqyWpmQNxea9Cw   ou_kid SIGySX_YgqyWpmQNxea9Cw
exp 2026-11-13T12:54:13Z (in 14m 59s)
may_act (absent): any authenticated agent may exchange this token
verified: signature, type, issuer, audience, expiry, chain
```

```sh
printf '%s\n' "$CHILD_TOKEN" | attenuo call --token - --upstream github --tool read_file --arg repo=acme/api
attenuo lease revoke "$ROOT_LEASE" --reason demo
attenuo audit verify
```

```text
ALLOWED
{"arguments":{"repo":"acme/api"},"name":"read_file"}
revoked 2 lease(s) starting at 54cd811d-a767-4487-b875-61cf6ea785c1 (reason: demo)
audit chain OK: 14 entries verified
checkpoints: none signed yet
```

The chain has 14 entries here because the `curl` flow above wrote the first 8. `audit tail` shows the newest; `--follow` keeps polling until Ctrl-C:

```sh
attenuo audit tail -n 3
```

```text
#12   2026-11-13T12:39:13.679764325Z  ALLOW github/read_file  planner > coder for alice  reason=policy_allow  id=ac0c...
#13   2026-11-13T12:39:13.687373923Z  tool_result  github/read_file  planner > coder for alice  decision=ac0c...  label=untrusted size=117  id=9f45...
#14   2026-11-13T12:39:13.698017447Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action  id=12be...
```

Other subcommands: `tools` (`tools/list`), `lease show`, `lease tree` (the delegation tree under a lease, with each hop's run limits and what is left), `approval` (list, show, grant and decline approvals), `budget refund` (give back what one decision charged, for a call whose effect did not happen), `policy reload`, `authzen eval`, `authzen search` (AuthZEN action search), `health` (the container health check), `stdio-bridge` (serve a local STDIO MCP server over HTTP so attenuo can front it, [guide](stdio-servers.md)), `key gen` (DPoP and client keys) and `admin operator` (named admin credentials, offline). Output is for people by default and JSON with `--json`. Exit status is 0 on success, 1 on an error and 2 when the server said no (a denied call, a negative AuthZEN decision, a broken audit chain). Secrets stay out of the argument list: use the environment variables, `-stdin` flags or `-file` flags described in the [CLI reference](../reference/cli.md).

A `Dockerfile` and `docker-compose.yml` run the same pair of servers in containers: the release image for the server and a separate `demo` image for the fake GitHub server. `scripts/compose-smoke.sh` builds both and plays the scenario through them; see the [demo's README](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md#run-it-in-docker).

## Python SDK

[`sdk/python`](https://github.com/attenuo-dev/attenuo/blob/main/sdk/python/README.md) is a Python client (`pip install -e sdk/python`, Python 3.10 or newer, depends on `httpx`) for agents written in Python: token exchange with typed capabilities, constraints and run limits, calls through the proxy that raise `Denied(reason, decision_id)` on a denial and `ApprovalRequired` when a policy asks for an approval (`call_tool_with_approval` waits for it and retries once), lease renewal, a token refresher that renews leases and re-exchanges before `exp`, AuthZEN evaluation (single and batch), action search and discovery, granting or declining an approval as the run's user, closing a proxy session, token inspection, and an admin client for revocation, budget refunds and the audit log. A timeout raises `TransportTimeout`; a server refusing for its load raises `Unavailable` (503) or `RateLimited` (429), retried only with `max_retries`. There is an async variant of each client. [`examples/python-agent`](https://github.com/attenuo-dev/attenuo/blob/main/examples/python-agent/agent.py) shows a planner delegating to a coder, with a run limit and an approval, and a second script wires the official `mcp` client to the proxy.

```python
import os

from attenuo import AdminClient, Capability, Client, Denied, Prefix

admin = AdminClient("http://127.0.0.1:8080", os.environ["ATTENUO_ADMIN_TOKEN"])  # as the server got it
root = admin.mint_root_dev("alice", "https://idp.example", "planner", ["github:*"])   # dev only
with Client("http://127.0.0.1:8080") as ob:
    coder = ob.exchange(
        root, "coder", [Capability("github", "read_file", repo=Prefix("alice/public-"))],
        client_secret="coder-secret-change-me",   # the coder authenticates as itself
    )
    try:
        ob.call_tool(coder, "github", "create_issue", {"repo": "alice/public-docs", "title": "x"})
    except Denied as d:
        print(d.reason, d.decision_id)   # capability_denied <audit record id>
```

It is pre-alpha like the rest and is not published to PyPI.

## TypeScript SDK

[`sdk/typescript`](https://github.com/attenuo-dev/attenuo/blob/main/sdk/typescript/README.md) is the same client for Node 20 or newer as the npm package `@attenuo/sdk` (ESM and CJS, strict types, no runtime dependencies, global `fetch`, Ed25519 verification through WebCrypto): `AttenuoClient` for exchange (capabilities with `withLimits` for run limits), renew, `callTool` (throws `DeniedError` with `reason` and `decisionId`), `callToolWithApproval`, `listTools`, AuthZEN (`authzenEvaluate`, `authzenEvaluateBatch`, `authzenSearchAction`, `authzenSearchActionIter`, `authzenConfiguration`), `grantApproval` / `declineApproval` for the run's user, `closeSession` and `inspect`, and `AdminClient` for revocation, budget refunds, the audit log and policy reload. A timeout throws `TransportTimeoutError`; a server refusing for its load throws `UnavailableError` (503) or `RateLimitedError` (429), retried only with `maxRetries`. `TokenRefresher` keeps a token alive (lease renewal, re-exchange before `exp`). `mcpUrl` and `mcpHeaders` point the official `@modelcontextprotocol/sdk` client at the proxy. [`examples/typescript-agent`](https://github.com/attenuo-dev/attenuo/blob/main/examples/typescript-agent/agent.ts) shows a planner delegating to a coder, with a run limit and an approval.

```ts
import { AdminClient, DeniedError, AttenuoClient, capability, prefix } from "@attenuo/sdk";

const admin = new AdminClient("http://127.0.0.1:8080", process.env.ATTENUO_ADMIN_TOKEN!); // as the server got it
const root = await admin.mintRootDev("alice", "https://idp.example", "planner", {
  capabilities: ["github:*"], // dev only
});
const ob = new AttenuoClient("http://127.0.0.1:8080");
const coder = await ob.exchange(
  root,
  "coder",
  [capability("github", "read_file", { repo: prefix("alice/public-") })],
  { clientSecret: "coder-secret-change-me" }, // the coder authenticates as itself
);
try {
  await ob.callTool(coder, "github", "create_issue", { repo: "alice/public-docs", title: "x" });
} catch (e) {
  if (e instanceof DeniedError) console.log(e.reason, e.decisionId); // capability_denied <audit record id>
}
```

It is pre-alpha like the rest and is not published to npm.
