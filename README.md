# onbehalf

[![CI](https://github.com/7Mudit/onbehalf/actions/workflows/ci.yml/badge.svg)](https://github.com/7Mudit/onbehalf/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](docs/spec/rfc-0001-onbehalf.md)
<!-- TODO once published: crates.io and docs.rs badges for onbehalf-core -->

Delegated authorization for software agents. onbehalf lets a principal hand an agent a scoped, attenuable, revocable capability to act on their behalf, checks every call against policy, and writes a tamper-evident audit record of each decision. It is written in Rust and ships as a set of crates plus a standalone server.

**Status: pre-alpha.** The design is in [RFC-0001](docs/spec/rfc-0001-onbehalf.md) and is still open for comment. Nothing here is ready for production use and formats will change before 1.0.

## Where to look

- [Guides](docs/guides/README.md): [getting started](docs/guides/getting-started.md), [deploying](docs/guides/deploying.md), [integrating MCP clients](docs/guides/integrating-mcp-clients.md) and [identity providers](docs/guides/identity-providers.md).
- [FAQ](docs/faq.md): why a proxy, how it differs from gateways and policy engines, what happens when it is down.
- [RFC-0001: onbehalf](docs/spec/rfc-0001-onbehalf.md): what the system is, the token model, the policy and audit design.
- [docs/](docs/README.md): specifications, architecture decisions, research notes, task board and engineering log.
- [Python SDK](sdk/python/README.md): `pip install -e sdk/python`, sync and async clients, an admin client, and an [agent example](examples/python-agent/agent.py).
- [examples/github-leak-demo](examples/github-leak-demo/README.md): the May 2025 GitHub MCP prompt-injection leak, replayed and stopped (`run.sh`, about a minute).
- [docs/guides/writing-policies.md](docs/guides/writing-policies.md): writing Cedar policies for agents and testing them offline with `onbehalf policy test` and `onbehalf policy lint`, including a CI recipe.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to build, test and submit changes.
- [SECURITY.md](SECURITY.md): how to report a vulnerability. Please do not file security issues publicly.
- [CHANGELOG.md](CHANGELOG.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Crates

| Crate | Purpose |
| --- | --- |
| `onbehalf-core` | Delegation chains, capability sets, attenuation, decision records |
| `onbehalf-token` | Token encoding, signing and verification |
| `onbehalf-policy` | Policy evaluation |
| `onbehalf-audit` | Append-only, hash-chained audit log |
| `onbehalf-proxy` | Enforcement in front of upstream services |
| `onbehalf-server` | The standalone server binary |
| `onbehalf-cli` | The `onbehalf` command line for a running server |

## Building

```sh
cargo build --workspace
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full set of checks CI runs.

## Quick start

Run the server with the example config. It generates an issuer key in `data/` on first start, keeps the audit log and lease registry in `data/onbehalf.sqlite`, and proxies an MCP server expected at `http://127.0.0.1:3001/mcp` as `github` (edit `[[upstreams]]` to point at yours).

```sh
cargo build -p onbehalf-server
cargo run -p onbehalf-server -- --config config/example.toml   # or ONBEHALF_CONFIG=config/example.toml
```

The flows below use `curl` and `jq`.

### Hop 0 from your identity provider

The first token in a chain is minted from a credential the user's IdP issued: an OIDC ID token, or an ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant). Any OIDC issuer works. List it under `[[idps]]` (its JWKS is found through `/.well-known/openid-configuration` unless you set `jwks_url`), register the agent under `[[agents]]`, and cap what the agent may get for those users under `[[root_grants]]`:

```toml
[[idps]]
issuer = "https://your-tenant.example.com"   # exact `iss`
audience = "your-client-id"                  # `aud` of the ID tokens

[[agents]]
id = "planner"
secret_sha256 = "..."                        # printf %s "$SECRET" | sha256sum

[[root_grants]]
issuer = "https://your-tenant.example.com"
agent = "planner"
capabilities = ["github:*"]
```

The agent exchanges the user's ID token for a root delegation token (RFC 8693), authenticating with its own client credentials. The token's originating user comes from the verified ID token: `sub`, `iss`, `auth_time`, the configured `attribute_claims`, and an `mfa` flag derived from `amr`.

```sh
OB=http://127.0.0.1:8080
ADMIN=dev-admin-token-change-me
ID_TOKEN=...   # from your IdP's login flow

# 1. Exchange the user's ID token for a root token held by "planner".
ROOT=$(curl -s -X POST $OB/token -u planner:planner-secret-change-me \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$ID_TOKEN \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  --data-urlencode scope=github:*)
ROOT_TOKEN=$(echo "$ROOT" | jq -r .access_token); ROOT_LEASE=$(echo "$ROOT" | jq -r .lease)
```

For an ID-JAG, send `subject_token_type=urn:ietf:params:oauth:token-type:id-jag` (or `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with `assertion=`). Its `aud` must be `[issuer] issuer` and its `client_id` must be the authenticated agent. Failures come back as `invalid_client` (401), or as `invalid_grant` or `invalid_scope` (400), each with a stable `error_description` code such as `audience_mismatch`, `expired`, `unknown_kid` or `scope_exceeds_grant`.

### Delegate, call, revoke

```sh
# 2. RFC 8693 exchange: planner delegates read_file only to a "coder" sub-agent.
CHILD_TOKEN=$(curl -s -X POST $OB/token \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$ROOT_TOKEN \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode actor=coder \
  --data-urlencode scope=github:read_file | jq -r .access_token)

# 3. Call through the proxy: read_file is allowed (forwarded upstream).
mcp() { curl -s -X POST $OB/mcp/github -H "Authorization: Bearer $CHILD_TOKEN" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$1"; }
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"acme/api"}}}'

# 4. See a denial: the coder was never delegated create_issue.
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{"repo":"acme/api","title":"x"}}}'
# {"jsonrpc":"2.0","id":2,"error":{"code":-32003,"message":"onbehalf: denied: capability_denied",...}}

# 5. Revoke the ROOT lease; the revocation cascades to the coder's lease.
curl -s -X POST $OB/admin/leases/$ROOT_LEASE/revoke -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' -d '{"reason":"demo"}'
# {"lease_id":"...","revoked":2,"reason":"demo"}

# 6. The coder's next call is denied.
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"acme/api"}}}'
# ... "message":"onbehalf: denied: lease_revoked" ...

# Every decision and issuance is in the hash-chained audit log.
curl -s $OB/admin/audit/verify -H "Authorization: Bearer $ADMIN"   # {"entries":5,"ok":true,"first_bad_seq":null}
curl -s "$OB/admin/audit?from=1&limit=20" -H "Authorization: Bearer $ADMIN" | jq '.entries[].record | {decision,reason,tool,agents}'
```

### Development only: a root token without an IdP

To try the flow without an identity provider, set `[dev] allow_root_mint = true`. This mounts `POST /admin/root-token`, which mints a root token for whichever user the admin names. Nothing about that user is verified, so the server logs a warning at startup. With the setting off (the default) the route does not exist and answers 404. Use it in place of step 1:

```sh
ROOT=$(curl -s -X POST $OB/admin/root-token -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"subject":"alice","issuer":"https://idp.example","agent":"planner","capabilities":["github:*"]}')
ROOT_TOKEN=$(echo "$ROOT" | jq -r .access_token); ROOT_LEASE=$(echo "$ROOT" | jq -r .lease)
```

Other endpoints: `POST /token/renew` (extend your lease), `POST /access/v1/evaluation` (AuthZEN; send the delegation token as bearer), `GET /.well-known/jwks.json`, `GET /.well-known/authzen-configuration`, `POST /admin/policies/reload`, `GET /admin/leases/{id}`, `GET /admin/audit/checkpoint`, `GET /healthz`. The request pipeline is described in [docs/design/server.md](docs/design/server.md). Set `RUST_LOG=debug` for more logging.

## Command line

`onbehalf` (crate `onbehalf-cli`) talks HTTP to a running server, so the quick start above becomes:

```sh
cargo build -p onbehalf-cli
export ONBEHALF_SERVER=http://127.0.0.1:8080 ONBEHALF_ADMIN_TOKEN=dev-admin-token-change-me
alias onbehalf=target/debug/onbehalf

onbehalf token root --subject alice --issuer https://idp.example --agent planner --cap 'github:*'
onbehalf token exchange --subject-token "$ROOT_TOKEN" --actor coder --cap github:read_file
onbehalf token inspect "$CHILD_TOKEN" --verify      # the chain as a tree; --verify checks it against the server's JWKS
onbehalf call --token "$CHILD_TOKEN" --server github --tool read_file --arg repo=acme/api
onbehalf lease revoke "$ROOT_LEASE" --reason demo
onbehalf audit tail -n 10 --follow
onbehalf audit verify
```

Other subcommands: `tools` (`tools/list`), `lease show`, `policy reload`, `authzen eval`. Output is for people by default and JSON with `--json`; `--print token|lease` on `token root` and `token exchange` prints one value for scripts. `--server` before the subcommand is the onbehalf URL; after `call` or `tools` it names the MCP upstream. Exit status is 0 on success, 1 on an error and 2 when the server said no (a denied call, a negative AuthZEN decision, a broken audit chain). `ONBEHALF_TOKEN` can stand in for `--token` and `--subject-token`.

A scripted end-to-end run of the GitHub leak scenario, with a fake MCP server, is in [examples/github-leak-demo](examples/github-leak-demo/README.md). A `Dockerfile` and `docker-compose.yml` run the same pair of servers in containers (untested).

## Python SDK

[`sdk/python`](sdk/python/README.md) is a Python client (`pip install -e sdk/python`, Python 3.10 or newer, depends on `httpx`) for agents written in Python: token exchange with typed capabilities and constraints, calls through the proxy that raise `Denied(reason, decision_id)` on a denial, lease renewal, AuthZEN evaluation, token inspection, and an admin client for revocation and the audit log. There is an async variant of each client. [`examples/python-agent`](examples/python-agent/agent.py) shows a planner delegating to a coder, and a second script wires the official `mcp` client to the proxy.

```python
from onbehalf import AdminClient, Capability, Client, Denied, Prefix

admin = AdminClient("http://127.0.0.1:8080", "dev-admin-token-change-me")
root = admin.mint_root_dev("alice", "https://idp.example", "planner", ["github:*"])   # dev only
with Client("http://127.0.0.1:8080") as ob:
    coder = ob.exchange(root, "coder", [Capability("github", "read_file", repo=Prefix("alice/public-"))])
    try:
        ob.call_tool(coder, "github", "create_issue", {"repo": "alice/public-docs", "title": "x"})
    except Denied as d:
        print(d.reason, d.decision_id)   # capability_denied <audit record id>
```

It is pre-alpha like the rest and is not published to PyPI.

## License

Apache-2.0. See [LICENSE](LICENSE).
