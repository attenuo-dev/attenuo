# onbehalf (Python SDK)

Python client for the [onbehalf](../../README.md) authorization server: exchange delegation tokens, attenuate capabilities, call MCP tools through the enforcing proxy, handle denials, renew leases, and read the audit log.

**Status: pre-alpha**, like the server. The API follows the server's wire format as of this repository and will change with it. Not on PyPI yet; install from a checkout.

```sh
pip install -e sdk/python            # runtime dependency: httpx
pip install -e 'sdk/python[verify]'  # adds cryptography, for Client.inspect(..., verify=True)
```

Python 3.10 or newer.

## Quickstart

Start a server with the example config (`[dev] allow_root_mint = true` for the dev root token) and an MCP upstream, as in [getting started](../../docs/guides/getting-started.md). Then:

```python
import os

from onbehalf import AdminClient, Capability, Client, Denied, Prefix

URL = "http://127.0.0.1:8080"

# Development only: mint a root token for an asserted user. In production hop 0 comes from
# your IdP: client.exchange(id_token, "planner", ["github:*"], client_id=..., client_secret=...).
admin = AdminClient(URL, "dev-admin-token-change-me")
root = admin.mint_root_dev("alice", "https://idp.example", "planner", ["github:*"])

with Client(URL) as ob:
    # The planner hands the coder read_file on alice's public repos only.
    # The coder authenticates as itself with its [[agents]] secret.
    coder = ob.exchange(
        root,
        "coder",
        [Capability("github", "read_file", repo=Prefix("alice/public-"))],
        ttl_seconds=600,
        client_secret=os.environ["CODER_SECRET"],
    )
    print(coder.chain.agents, coder.lease)  # ('planner', 'coder') <lease id>

    ok = ob.call_tool(
        coder, "github", "read_file", {"repo": "alice/public-docs", "path": "README.md"}
    )
    print(ok.text, ok.decision_id)

    try:
        ob.call_tool(coder, "github", "create_issue", {"repo": "alice/public-docs", "title": "x"})
    except Denied as d:
        print("denied:", d.reason, d.decision_id)  # capability_denied, <audit record id>

    ob.renew(coder)  # keep the lease alive

admin.revoke_lease(root.lease, "session compromised")  # cascades to the coder
print(admin.audit_verify())  # VerifyReport(ok=True, entries=..., ...)
```

`AsyncClient` and `AsyncAdminClient` have the same methods; put `await` in front.

## What is in it

| Call                                                                                                 | Does                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Client(server_url, token=None, timeout=30)`                                                         | HTTP client for the server. `token` is a default bearer.                                                                                                                                                                                                                                                                                                                                                          |
| `exchange(subject_token, actor, capabilities, ttl_seconds=None, client_id=None, client_secret=None, subject_token_type=None, *, actor_token=None, may_act=None)` | RFC 8693 exchange. Returns a `Token`. From a delegation token, `client_secret` is the actor's `[[agents]]` secret (`client_id` defaults to `actor`), which the server requires by default. From any other subject token, `client_id` and `client_secret` make it a hop-0 exchange of an IdP credential (`subject_token_type="...:id-jag"` for an ID-JAG). A parent token can be exchanged for a given actor once. `actor_token` (a workload-identity JWT such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer) authenticates the actor instead of a secret, depending on `[token] actor_auth`; each one works for one exchange. `may_act` lists the agents allowed to exchange the new token next. |
| `renew(token)`                                                                                       | `POST /token/renew`. Returns `Lease(lease, expires_at, expires_in)`.                                                                                                                                                                                                                                                                                                                                              |
| `call_tool(token, server, tool, arguments, session_id=None)`                                         | `tools/call` through `/mcp/{server}`. Returns `ToolResult` (`.text`, `.content`, `.is_error`, `.decision_id`).                                                                                                                                                                                                                                                                                                    |
| `list_tools(token, server)`                                                                          | `tools/list`, filtered by the proxy to what the token may call.                                                                                                                                                                                                                                                                                                                                                   |
| `initialize(token, server)`                                                                          | MCP `initialize`; returns the `Mcp-Session-Id`, if any.                                                                                                                                                                                                                                                                                                                                                           |
| `authzen_evaluate(token, server, tool, arguments)`                                                   | AuthZEN decision without calling the tool. A deny is a falsy `AuthzenDecision`, not an exception.                                                                                                                                                                                                                                                                                                                 |
| `inspect(jwt, verify=False)`                                                                         | Decode a token. With `verify=True` fetch the JWKS and check the Ed25519 signature, `typ`, `exp` and that `sub`/`act` match the chain.                                                                                                                                                                                                                                                                             |
| `AdminClient(server_url, admin_token)`                                                               | `revoke_lease`, `lease_status`, `audit`, `audit_head` (reads `head` from `GET /admin/audit`, signs nothing), `audit_tail`, `audit_export` (iterator of JSON Lines objects), `audit_checkpoint` (explicit; signs and stores a checkpoint), `audit_verify`, `policy_reload`, `mint_root_dev`.                                                                                                                       |

`Token` carries `jwt` (also `str(token)`), `lease`, `expires_at`, `chain` (user, hops, capabilities per hop), and `verified`. `repr` does not print the JWT. Everything decoded from a token is untrusted unless `verified` is true.

### Capabilities

```python
from onbehalf import Capability, Equals, OneOf, Prefix

Capability("github", "read_file")  # github:read_file
Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))
Capability("github", "read_*", repo=Prefix("alice/public-"), ref=Equals("main"))
```

These serialize to the server's `authorization_details` shape, the same JSON `onbehalf token exchange --cap` produces. Plain strings (`"github:read_file"`, or comma separated) work anywhere a capability is accepted. A child must constrain every argument its parent constrains, at least as tightly; the server refuses an exchange that widens (`ApiError` with `error == "invalid_scope"`).

### Errors

All SDK errors derive from `OnbehalfError`.

| Exception                                   | When                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Denied` (`.reason`, `.decision_id`)        | The proxy said no (JSON-RPC `-32003` with the `X-Onbehalf-Decision-Id` header naming `data.decision_id`; an upstream's own `-32003` without that proof is an `RpcError`). Branch on `reason`: `capability_denied`, `policy_deny`, `lease_revoked`, `lease_expired`, ... See the [integration guide](../../docs/guides/integrating-mcp-clients.md#handling-denied-responses). |
| `Unauthorized`                              | HTTP 401: missing, bad or expired bearer.                                                                                                                                                                                                                                                                                                                                    |
| `ApiError` (`.status`, `.error`, `.detail`) | Any other non-success from the server: `invalid_scope`, `invalid_grant`, 404, 422.                                                                                                                                                                                                                                                                                           |
| `RpcError`                                  | A JSON-RPC error that is not a denial (unknown upstream, upstream down).                                                                                                                                                                                                                                                                                                     |
| `VerificationError`                         | `inspect(verify=True)` failed.                                                                                                                                                                                                                                                                                                                                               |

A denied `tools/call` is a decision, not a glitch: do not retry it blindly. A `lease_expired` denial is the one case where `renew()` then one retry makes sense; `lease_revoked` means stop.

## MCP clients

`onbehalf.mcp` produces the URL and headers an MCP client needs; see [`examples/python-agent/mcp_client_example.py`](../../examples/python-agent/mcp_client_example.py) for the official `mcp` package.

```python
from onbehalf.mcp import mcp_headers, mcp_url

url = mcp_url("http://127.0.0.1:8080", "github")  # http://127.0.0.1:8080/mcp/github
headers = mcp_headers(coder)  # {"Authorization": "Bearer ..."}
```

`TokenAuth(provider)` is an `httpx.Auth` that reads the current token on each request, for tokens that get replaced.

## Verifying

```python
tok = ob.inspect(jwt, verify=True, issuer="http://127.0.0.1:8080", audience="onbehalf")
```

Local verification checks the signature against the server's JWKS and the claims listed above. It does not check the detached `ou_sig` over the user block; the server does that on every request. Without `issuer`/`audience` pins it proves "signed by this server's key and unexpired", as the CLI's `token inspect --verify` does.

## Development

```sh
cd sdk/python
pip install -e '.[dev]'
ruff check --config pyproject.toml . ../../examples/python-agent
ruff format --check --config pyproject.toml . ../../examples/python-agent
mypy --strict src tests ../../examples/python-agent
pytest                       # unit tests, no server needed
ONBEHALF_INTEGRATION=1 pytest -m integration   # builds and starts the real server (needs cargo)
```

The integration test builds `onbehalf-server` and the `fake_mcp` example, starts both on free ports, and replays the [GitHub leak scenario](../../examples/github-leak-demo/README.md) through the SDK: dev root mint, exchange, an allowed call, a policy denial, a capability denial, revocation, `lease_revoked`, and an audit chain check.

## Limits

- The server's JSON-RPC and header behaviour is what is implemented in this repository today. Nothing here is tested against a server of another version.
- Streaming responses (long-lived SSE, server-initiated requests) are not supported by `call_tool`: it reads one response and returns the first JSON-RPC result or error in it. Use a full MCP client with `onbehalf.mcp` for that.
- Hop-0 exchange (`client_id`/`client_secret`) is covered by unit tests against a mock transport only, not against a live IdP.
