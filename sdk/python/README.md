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
| `Client(server_url, token=None, timeout=30, dpop_key=None)`                                                        | HTTP client for the server. `token` is a default bearer.                                                                                                                                                                                                                                                                                                                                                          |
| `exchange(subject_token, actor, capabilities, ttl_seconds=None, client_id=None, client_secret=None, subject_token_type=None, *, actor_token=None, may_act=None)` | RFC 8693 exchange. Returns a `Token`. From a delegation token, `client_secret` is the actor's `[[agents]]` secret (`client_id` defaults to `actor`), which the server requires by default. From any other subject token, `client_id` and `client_secret` make it a hop-0 exchange of an IdP credential (`subject_token_type="...:id-jag"` for an ID-JAG). A parent token can be exchanged for a given actor once. `actor_token` (a workload-identity JWT such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer) authenticates the actor instead of a secret, depending on `[token] actor_auth`; each one works for one exchange. `may_act` lists the agents allowed to exchange the new token next. |
| `renew(token)`                                                                                       | `POST /token/renew`. Returns `Lease(lease, expires_at, expires_in)`.                                                                                                                                                                                                                                                                                                                                              |
| `call_tool(token, server, tool, arguments, session_id=None)`                                         | `tools/call` through `/mcp/{server}`. Returns `ToolResult` (`.text`, `.content`, `.is_error`, `.decision_id`).                                                                                                                                                                                                                                                                                                    |
| `list_tools(token, server)`                                                                          | `tools/list`, filtered by the proxy to what the token may call.                                                                                                                                                                                                                                                                                                                                                   |
| `initialize(token, server)`                                                                          | MCP `initialize`; returns the `Mcp-Session-Id`, if any.                                                                                                                                                                                                                                                                                                                                                           |
| `authzen_evaluate(token, server, tool, arguments)`                                                   | AuthZEN decision without calling the tool. A deny is a falsy `AuthzenDecision`, not an exception.                                                                                                                                                                                                                                                                                                                 |
| `inspect(jwt, verify=False)`                                                                         | Decode a token. With `verify=True` fetch the JWKS and check the Ed25519 signature, `typ`, `exp` and that `sub`/`act` match the chain.                                                                                                                                                                                                                                                                             |
| `AdminClient(server_url, admin_token)`                                                               | `revoke_lease`, `lease_status`, `audit`, `audit_head` (reads `head` from `GET /admin/audit`, signs nothing), `audit_tail`, `audit_export` (iterator of JSON Lines objects; `kind=` and `chain_id=` filter), `audit_checkpoint` (explicit; signs and stores a checkpoint), `audit_verify`, `policy_reload`, `mint_root_dev`.                                                                                                                       |

`Token` carries `jwt` (also `str(token)`), `lease`, `expires_at`, `chain` (user, hops, capabilities per hop), and `verified`. `repr` does not print the JWT. Everything decoded from a token is untrusted unless `verified` is true.

### Capabilities

```python
from onbehalf import Capability, Equals, OneOf, Prefix

Capability("github", "read_file")  # github:read_file
Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))
Capability("github", "read_*", repo=Prefix("alice/public-"), ref=Equals("main"))
```

These serialize to the server's `authorization_details` shape, the same JSON `onbehalf token exchange --cap` produces. Plain strings (`"github:read_file"`, or comma separated) work anywhere a capability is accepted. A child must constrain every argument its parent constrains, at least as tightly; the server refuses an exchange that widens (`ApiError` with `error == "invalid_scope"`).

### Workload identity and `may_act`

An agent can authenticate with a workload-identity JWT instead of a client secret: an RFC 8693 `actor_token` from an `[[actor_trust]]` issuer, such as a SPIFFE JWT-SVID. It works at hop 0 (with the user's ID token or ID-JAG as the subject token) and on every exchange. Each actor token authenticates one request, and the token it obtains never outlives it.

```python
svid = open("/run/spire/svid.jwt").read()  # written by a SPIFFE helper, aud = the server
root = ob.exchange(id_token, "planner", ["github:*"], actor_token=svid)
```

`may_act` limits who may exchange a token next (RFC 8693 §4.4). Pass it when exchanging, or when minting a dev root:

```python
coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=..., may_act=["reviewer"])
root = admin.mint_root_dev(
    "alice", "https://idp.example", "planner", ["github:*"], may_act=["coder"]
)
```

`may_act` is a list of agent ids (a bare string is a `TypeError`); `[]` means nobody may exchange the token. For a root it must be within the `[[root_grants]]` entry's `may_act` when that has one.

### Binding tokens to keys (DPoP)

A token can be bound to a key the agent holds (RFC 9449), so a leaked copy is useless without the key. Give the client a `dpop_key`: a `DpopKey` or a private JWK dict, such as the file `onbehalf key gen --dpop` writes. Signing needs `cryptography` (`pip install 'onbehalf[dpop]'`).

```python
from onbehalf import Client, DpopKey

coder_key = DpopKey.load("coder.jwk")  # or DpopKey.generate(); keep key.private_jwk() to reuse it

# In the planner's process: consent to delegating `root` to the coder's key and agent id.
sign_off = planner_key.sign_off(f"{url}/token", str(root), coder_key.thumbprint, "coder")

# In the coder's process: the new token is bound to coder_key.
with Client(url, dpop_key=coder_key) as ob:
    coder = ob.exchange(
        root, "coder", ["github:read_file"], client_secret=..., subject_token_dpop=sign_off
    )
    ob.call_tool(coder, "github", "read_file", {"repo": "alice/docs"})  # proof attached
```

With a key, every `call_tool`, `list_tools`, `renew` and `authzen_evaluate` sends `Authorization: DPoP <token>` and a fresh proof, and every `exchange` binds the new token. When the parent is bound to another key, its holder's sign-off names the new key and agent and works for that one exchange; a process that holds both keys can pass `subject_dpop_key=planner_key` instead. When the parent is bound to the client's own key, no sign-off is needed. `Token.dpop_jkt` is the thumbprint a token is bound to (`None` for a bearer token), and `AuditEntry.dpop_bound` says whether a decision was made with a proven bound token. A bound token without a proof is `Unauthorized` with `error == "dpop_required"`. See [Binding tokens to keys](../../docs/guides/binding-tokens-to-keys.md).

Server nonces (RFC 9449 §8, `[token] dpop_nonce = "required"`) need no code. `Client`, `AsyncClient`, `AdminClient.mint_root_dev` and `TokenAuth` keep the latest `DPoP-Nonce` header the server sent and put it in each proof. When the server refuses a proof with `use_dpop_nonce`, they retry the request once with a new proof carrying the nonce from that response. For your own HTTP code, `DpopKey.proof(method, url, token, nonce=...)` adds the claim, and `onbehalf.dpop.NonceCache` does the bookkeeping: `update(response)` stores the nonce and returns true when the request should be retried.

### Keeping a token alive

`TokenRefresher` (threads) and `AsyncTokenRefresher` (`asyncio`) renew the lease at a third of the lease interval, call your `exchange` function before the token's `exp`, and keep the current token in `.token`:

```python
from onbehalf import Client, RefreshError, TokenRefresher
from onbehalf.mcp import TokenAuth


def new_coder_token():
    # Each exchange needs a fresh subject token: a parent delegates to a given actor once,
    # so re-exchanging the same parent is refused as `replayed`.
    return ob.exchange(planner.fresh_root(), "coder", ["github:read_file"], client_secret=SECRET)


def on_dead(err: RefreshError):
    print("stopping:", err.reason)  # lease_revoked, token_expired, refused, ...


with (
    Client(URL, dpop_key=key) as ob,
    TokenRefresher(ob, new_coder_token(), new_coder_token, on_error=on_dead) as refresher,
):
    auth = TokenAuth(refresher, dpop_key=key)  # reads refresher.token on every request
    ob.call_tool(refresher.token, "github", "read_file", {"repo": "alice/docs"})
```

- **Schedule.** `lease_interval` is the server's `[issuer] lease_interval_seconds`; left out, it is learned from the first renewal, which then happens right away. The token is re-exchanged `margin` seconds before `exp` (default 20% of its lifetime, at least 5 s, at most half the lifetime). `on_change(token)` is called with each replacement.
- **Failures.** Network errors, 5xx, 408 and 429 are retried with jittered exponential backoff (1 s doubling to 30 s). It stops, calls `on_error` once and sets `.error` when the lease is revoked (`RefreshError.reason == "lease_revoked"`, or `lease_lost` when an ancestor lapsed), the server refuses an exchange for good (`refused`: `invalid_scope`, `replayed`, a bad secret), or the token reaches `exp` (`token_expired`). It never loops on a revoked lease. `refresher()` raises the `RefreshError` once it has given up.
- **DPoP.** Renewals go through your client and are signed with its `dpop_key`. A replacement must be bound to the same key as the current token; otherwise it is not adopted and the refresher stops with `key_mismatch`.
- **Logging.** The `onbehalf.refresh` logger writes lease ids and reason codes only, never tokens.
- **Testing.** `tick()` runs whatever is due and returns the seconds to wait; the thread is a loop around it, and `clock=` and `rng=` replace the time source and the jitter.

### Errors

All SDK errors derive from `OnbehalfError`.

| Exception                                   | When                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Denied` (`.reason`, `.decision_id`)        | The proxy said no (JSON-RPC `-32003` with the `X-Onbehalf-Decision-Id` header naming `data.decision_id`; an upstream's own `-32003` without that proof is an `RpcError`). Branch on `reason`: `capability_denied`, `policy_deny`, `lease_revoked`, `lease_expired`, ... See the [integration guide](../../docs/guides/integrating-mcp-clients.md#handling-denied-responses). |
| `Unauthorized`                              | HTTP 401: missing, bad or expired bearer.                                                                                                                                                                                                                                                                                                                                    |
| `ApiError` (`.status`, `.error`, `.detail`) | Any other non-success from the server: `invalid_scope`, `invalid_grant`, 404, 422.                                                                                                                                                                                                                                                                                           |
| `RpcError`                                  | A JSON-RPC error that is not a denial (unknown upstream, upstream down).                                                                                                                                                                                                                                                                                                     |
| `RefreshError` (`.reason`)                  | A `TokenRefresher` gave up: `lease_revoked`, `lease_lost`, `token_expired`, `refused`, `key_mismatch`.
| `VerificationError`                         | `inspect(verify=True)` failed.                                                                                                                                                                                                                                                                                                                                               |

A denied `tools/call` is a decision, not a glitch: do not retry it blindly. A `lease_expired` denial is the one case where `renew()` then one retry makes sense; `lease_revoked` means stop.

## MCP clients

`onbehalf.mcp` produces the URL and headers an MCP client needs; see [`examples/python-agent/mcp_client_example.py`](../../examples/python-agent/mcp_client_example.py) for the official `mcp` package.

```python
from onbehalf.mcp import mcp_headers, mcp_url

url = mcp_url("http://127.0.0.1:8080", "github")  # http://127.0.0.1:8080/mcp/github
headers = mcp_headers(coder)  # {"Authorization": "Bearer ..."}
```

`TokenAuth(provider)` is an `httpx.Auth` that reads the current token on each request, for tokens that get replaced (a [`TokenRefresher`](#keeping-a-token-alive) is a provider). `TokenAuth(provider, dpop_key=key)` also adds a DPoP proof per request, which a bound token needs; static headers cannot carry one.

## Verifying

```python
tok = ob.inspect(jwt, verify=True, issuer="http://127.0.0.1:8080", audience="onbehalf")
```

Local verification checks the signature against the server's JWKS and the claims listed above. It does not check the detached `ou_sig` over the user block; the server does that on every request. Without `issuer`/`audience` pins it proves "signed by this server's key and unexpired", as the CLI's `token inspect --verify` does.

## Verifying an audit export offline

```python
import httpx
from onbehalf.audit import verify_export

jwks = httpx.get("http://127.0.0.1:8080/.well-known/jwks.json").json()
report = verify_export("audit.jsonl", checkpoint_public_keys=jwks)  # from `onbehalf audit export`
if not report.ok:
    print(report.first_bad_seq, report.bad_checkpoints, report.truncated, report.unsigned_tail)
```

`verify_export(path_or_lines, *, checkpoint_public_keys, allow_unsigned_tail=False)` takes a path (`str` or `PathLike`; a `str` is always a path) or an iterable of lines, in JSON Lines or the `--format json` form. `checkpoint_public_keys` is the JWKS or a `{kid: public key}` map (raw 32 bytes or base64url). It re-checks the SHA-256 hash chain over RFC 8785 canonical JSON of `["onbehalf-audit-entry-v2", seq, prev_hash, record]`, the range the header declares and the Ed25519 checkpoint signatures, with the same strictness as `onbehalf audit verify --file`: a short file, entries outside the range and entries after the last valid checkpoint (unless `allow_unsigned_tail=True`) all fail. The `ExportReport` has `ok`, `first_bad_seq`, `bad_checkpoints`, `last_signed_seq`, `unsigned_tail`, `truncated`, `outside_range` and the rest of the Rust report. A file that is not a verifiable export (no header, wrong format, a filtered export, not JSON) raises `onbehalf.audit.ExportError`. It needs the `verify` extra (`cryptography`) for the signatures and depends on the pinned `rfc8785`. It hashes each record as it appears in the file and refuses duplicate object members, so it is a little stricter than the Rust check. A filtered export (`audit_export(kind=..., chain_id=...)`) cannot be verified: its chain has gaps, so verify the unfiltered one, then filter. `AuditEntry` has `kind` and `chain_id`.

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
