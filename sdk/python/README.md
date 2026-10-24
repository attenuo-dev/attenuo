# attenuo (Python SDK)

Python client for the [attenuo](https://github.com/attenuo-dev/attenuo/blob/main/README.md) authorization server: exchange delegation tokens, attenuate capabilities, call MCP tools through the enforcing proxy, handle denials, renew leases, and read the audit log.

**Status: pre-alpha**, like the server. Version 0.1.0, released together with attenuo 0.1.0: the SDK carries the server's version number, follows that release's wire format and will change with it. Once 0.1.0 is on PyPI, `pip install attenuo` installs it; until the maintainer publishes it, install from a checkout.

```sh
pip install -e sdk/python            # runtime dependency: httpx
pip install -e 'sdk/python[verify]'  # adds cryptography, for Client.inspect(..., verify=True)
```

Python 3.10 or newer.

## Quickstart

Start a server with the example config (`[dev] allow_root_mint = true` for the dev root token) and an MCP upstream, as in [getting started](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/getting-started.md). Then:

```python
import os

from attenuo import AdminClient, Capability, Client, Denied, Prefix

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
| `call_tool_with_approval(token, server, tool, arguments, *, on_approval=None, timeout=None, interval=2.0)` | `call_tool`; when the call needs an approval (`-32008`), calls `on_approval(err)`, waits for the grant, and retries the call once, with the grant's `approval_token` when it has one. `call_tool(..., approval_token=...)` sends a token yourself. See [Approvals](#approvals). |
| `get_approval(approval_id, token)`, `wait_for_approval(approval_id, token, *, timeout=None, interval=2.0)` | `GET /approvals/{id}` as the agent (same run, DPoP signed when the client has a key); `wait_for_approval` polls until granted and raises `ApprovalNotGranted` otherwise. |
| `list_tools(token, server)`                                                                          | `tools/list`, filtered by the proxy to what the token may call.                                                                                                                                                                                                                                                                                                                                                   |
| `initialize(token, server)`                                                                          | MCP `initialize`; returns the `Mcp-Session-Id`, if any.                                                                                                                                                                                                                                                                                                                                                           |
| `authzen_evaluate(token, server, tool, arguments)`                                                   | AuthZEN decision without calling the tool. A deny is a falsy `AuthzenDecision`, not an exception.                                                                                                                                                                                                                                                                                                                 |
| `inspect(jwt, verify=False)`                                                                         | Decode a token. With `verify=True` fetch the JWKS and check the Ed25519 signature, `typ`, `exp` and that `sub`/`act` match the chain.                                                                                                                                                                                                                                                                             |
| `AdminClient(server_url, admin_token)`                                                               | `revoke_lease`, `lease_status`, `audit`, `audit_head` (reads `head` from `GET /admin/audit`, signs nothing), `audit_tail`, `audit_export` (iterator of JSON Lines objects; `kind=` and `chain_id=` filter), `audit_checkpoint` (explicit; signs and stores a checkpoint), `audit_verify`, `policy_reload`, `mint_root_dev`, the approval calls (`approvals`, `approval`, `grant_approval`, `decline_approval`); and the read-only console helpers below (`audit_query`, `audit_iter`, `audit_entry`, `audit_record`, `audit_checkpoints`, `lease_tree`, `policies`, `policy_check`, `policy_evaluate`).                                                                                                                       |

`Token` carries `jwt` (also `str(token)`), `lease`, `expires_at`, `chain` (user, hops, capabilities per hop), and `verified`. `repr` does not print the JWT. Everything decoded from a token is untrusted unless `verified` is true.

### Admin: querying the audit log, lease trees, policies

These wrap the read-only operator routes the admin console uses. None of them signs, changes or audits anything.

```python
from attenuo import AdminClient, AuditFilter

admin = AdminClient(URL, "dev-admin-token-change-me")

# Newest denials first. A filtered page can come back short (even empty) with a link still
# set, so iterate rather than reading one page: audit_iter follows prev/next until null.
for e in admin.audit_iter(AuditFilter(decision="deny", agent="coder"), order="desc"):
    print(e.seq, e.reason, e.tool)
page = admin.audit_query(AuditFilter(kind=["lease_renew"], lease=lease_id), limit=50)

detail = admin.audit_record(denied.decision_id)  # or admin.audit_entry(seq)
print(detail.lease_states, detail.covered_by_checkpoint, detail.policy_reloaded_after)

admin.audit_checkpoints(before=None, limit=20)  # stored checkpoints, newest first; never signs
tree = admin.lease_tree(lease_id)  # what a revoke would reach: nodes, ancestors, would_revoke

admin.policies()  # the loaded set: path, sha256, loaded_at, {id: text}
admin.policy_check()  # lint the file on disk now; .ok means a reload would succeed
ev = admin.policy_evaluate("github", "read_file", {"repo": "alice/x"}, token=coder)
print(ev.decision, ev.reason, ev.policy_ids)  # no lease check, no audit record
```

| Call | Route | Returns |
| --- | --- | --- |
| `audit_query(filter=None, *, order="asc", from_seq=None, before=None, limit=100)` | `GET /admin/audit` | `AuditPage(entries, next, prev, head)` |
| `audit_iter(...)` (same arguments, `limit` defaults to 1000) | `GET /admin/audit`, repeated | iterator of `AuditEntry`, following `next` (asc) or `prev` (desc) until null |
| `audit_entry(seq)`, `audit_record(record_id)` | `GET /admin/audit/entries/{seq}`, `/admin/audit/records/{id}` | `AuditEntryDetail(entry, lease_states, covered_by_checkpoint, policy_reloaded_after)` |
| `audit_checkpoints(before=None, limit=None)` | `GET /admin/audit/checkpoints` | `CheckpointPage(checkpoints, prev)` |
| `lease_tree(lease_id, max_nodes=None)` | `GET /admin/leases/{id}/tree` | `LeaseTree(root, ancestors, nodes, would_revoke, truncated)` |
| `policies()` | `GET /admin/policies` | `PolicySet(path, sha256, loaded_at, policy_ids, warnings, policies)` |
| `policy_check()` | `GET /admin/policies/check` | `PolicyCheck(ok, issues, differs_from_loaded, ...)` |
| `policy_evaluate(server, tool, arguments=None, *, token=None, chain=None)` | `POST /admin/policies/evaluate` | `PolicyEvaluation(decision, reason, policy_ids, ..., token_expired)`; `.allowed` |
| `approvals(chain_id=None, *, state=None, limit=None)` | `GET /admin/approvals` | `list[Approval]`, newest first |
| `approval(approval_id)` | `GET /admin/approvals/{id}` | `Approval` |
| `grant_approval(approval_id)`, `decline_approval(approval_id)` | `POST /admin/approvals/{id}` | `Approval` after the decision (`by = \"operator\"`); `ApiError` 409 when it is no longer pending |

`AuditFilter` fields are exact matches combined with AND: `kind` (one or a list), `decision`, `reason`, `subject`, `agent`, `lease`, `server`, `tool`, `chain_id`, and `since` / `until` (RFC 3339 strings or timezone-aware datetimes). Errors map as everywhere else: a 404 for an unknown seq, record or lease is an `ApiError` with `status == 404`, a bad filter is a 400 `invalid_request`. `AsyncAdminClient` has the same methods; `audit_iter` is an async iterator there.

### Capabilities

```python
from attenuo import Capability, Equals, OneOf, Prefix

Capability("github", "read_file")  # github:read_file
Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))
Capability("github", "read_*", repo=Prefix("alice/public-"), ref=Equals("main"))
```

These serialize to the server's `authorization_details` shape, the same JSON `attenuo token exchange --cap` produces. Plain strings (`"github:read_file"`, or comma separated) work anywhere a capability is accepted. A child must constrain every argument its parent constrains, at least as tightly; the server refuses an exchange that widens (`ApiError` with `error == "invalid_scope"`).

#### Run limits on a child token

A capability can carry run limits ([ADR-0010](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0010-run-limits.md)): how many calls, how much in total, how many calls per value and how many different values. Set them with `with_limits` before you exchange:

```python
from attenuo import ArgLimit, Capability

helper = ob.exchange(
    planner,
    "helper",
    [
        # At most one payment, 40 in total, to Emma only.
        Capability("banking", "send_money", recipient="FR00EMMA").with_limits(
            calls=1, sum=("amount", 40), calls_per=("recipient", 1)
        ),
        # Pages from at most two sites: `derive="host"` counts the host of the URL.
        Capability("web", "get_webpage").with_limits(distinct=ArgLimit("url", 2, derive="host")),
    ],
)
```

Argument limits are `(arg, max)` tuples or `ArgLimit`s; `with_limits` also takes a whole `Limits`, and `Capability.typed_limits` reads them back (from a decoded token's hops, too). The server lowers a figure larger than the parent's, fills in a limit the child leaves out, and charges every call to every hop, so a child can spend at most what its parent has left. A call over a limit is `Denied` with `reason == "budget_exhausted"`; one whose argument a limit cannot count (a missing recipient, a URL without a host) is `limit_arg_invalid`. A kind or derivation the SDK does not know raises `ValueError` instead of being dropped.

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

A token can be bound to a key the agent holds (RFC 9449), so a leaked copy is useless without the key. Give the client a `dpop_key`: a `DpopKey` or a private JWK dict, such as the file `attenuo key gen --dpop` writes. Signing needs `cryptography` (`pip install 'attenuo[dpop]'`).

```python
from attenuo import Client, DpopKey

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

With a key, every `call_tool`, `list_tools`, `renew` and `authzen_evaluate` sends `Authorization: DPoP <token>` and a fresh proof, and every `exchange` binds the new token. When the parent is bound to another key, its holder's sign-off names the new key and agent and works for that one exchange; a process that holds both keys can pass `subject_dpop_key=planner_key` instead. When the parent is bound to the client's own key, no sign-off is needed. `Token.dpop_jkt` is the thumbprint a token is bound to (`None` for a bearer token), and `AuditEntry.dpop_bound` says whether a decision was made with a proven bound token. A bound token without a proof is `Unauthorized` with `error == "dpop_required"`. See [Binding tokens to keys](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/binding-tokens-to-keys.md).

Server nonces (RFC 9449 §8, `[token] dpop_nonce = "required"`) need no code. `Client`, `AsyncClient`, `AdminClient.mint_root_dev` and `TokenAuth` keep the latest `DPoP-Nonce` header the server sent and put it in each proof. When the server refuses a proof with `use_dpop_nonce`, they retry the request once with a new proof carrying the nonce from that response. For your own HTTP code, `DpopKey.proof(method, url, token, nonce=...)` adds the claim, and `attenuo.dpop.NonceCache` does the bookkeeping: `update(response)` stores the nonce and returns true when the request should be retried.

### Keeping a token alive

`TokenRefresher` (threads) and `AsyncTokenRefresher` (`asyncio`) renew the lease at a third of the lease interval, call your `exchange` function before the token's `exp`, and keep the current token in `.token`:

```python
from attenuo import Client, RefreshError, TokenRefresher
from attenuo.mcp import TokenAuth


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
- **Logging.** The `attenuo.refresh` logger writes lease ids and reason codes only, never tokens.
- **Testing.** `tick()` runs whatever is due and returns the seconds to wait; the thread is a loop around it, and `clock=` and `rng=` replace the time source and the jitter.

### Approvals

A policy can hold a call until a person approves it (`@obligation("approval")`, see [Writing policies](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/writing-policies.md)). The proxy then answers JSON-RPC `-32008`, which the SDK raises as `ApprovalRequired`, a `Denied` with `reason == "approval_required"` plus `.approval_id`, `.expires_at` and `.call_hash`. The user grants it with their own sign-in (`POST /approvals/{id}`), or an operator does with `attenuo approval grant` or `AdminClient.grant_approval(id)`. The agent's own token can read the approval but never decide it. The grant is good for one retry of the identical call (same server, tool and arguments) by the same hop, until `expires_at`.

```python
from attenuo import ApprovalNotGranted, ApprovalRequired


def tell_user(err: ApprovalRequired) -> None:
    print(f"Approval needed: {err.approval_id} (expires {err.expires_at})")


try:
    result = ob.call_tool_with_approval(
        token, "github", "delete_repo", {"repo": "alice/site"}, on_approval=tell_user
    )
except ApprovalNotGranted as e:
    print("not approved:", e.state)  # declined, expired, consumed or timeout
```

`approval_id` is `None` when the server could not open an approval; treat that as a plain denial. Like `-32003`, a `-32008` counts only when the `X-Attenuo-Decision-Id` header names its `data.decision_id`; otherwise it is an upstream's own `RpcError`.

A granted `Approval` carries `approval_token`, a JWT signed with the server's issuer key (`typ: attenuo-approval+jwt`) and bound to the run, the hop's lease, the call hash and, for a DPoP-bound agent, its key. `call_tool_with_approval` retries with it in `params._meta["dev.attenuo/approval"]`; a token the server refuses is a `Denied` with reason `approval_invalid`. An external enforcement point can check a token offline against the JWKS:

```python
from attenuo import call_hash, verify_approval_token

claims = verify_approval_token(
    token_from_agent,
    ob.jwks(),
    chain_id=run_id,
    lease=hop_lease,
    call_hash=call_hash("github", "delete_repo", {"repo": "alice/site"}),
    jkt=None,  # the hop's cnf.jkt, or None for a bearer hop
)
print(claims.approval_id, claims.by, claims.expires_at)
```

It raises `VerificationError` on a bad signature, `typ`, expiry or binding. It proves the grant was made; only the server knows whether it has been used (needs the `verify` extra).

### Errors

All SDK errors derive from `AttenuoError`.

| Exception                                   | When                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Denied` (`.reason`, `.decision_id`)        | The proxy said no (JSON-RPC `-32003` with the `X-Attenuo-Decision-Id` header naming `data.decision_id`; an upstream's own `-32003` without that proof is an `RpcError`). Branch on `reason`: `capability_denied`, `policy_deny`, `lease_revoked`, `lease_expired`, ... See the [integration guide](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/integrating-mcp-clients.md#handling-denied-responses). |
| `ApprovalRequired` (`.approval_id`, `.expires_at`, `.call_hash`) | A `Denied` for JSON-RPC `-32008`: a policy holds the call until it is approved. See [Approvals](#approvals). |
| `ApprovalNotGranted` (`.approval_id`, `.state`) | Waiting for an approval ended without a grant: `declined`, `expired`, `consumed` or `timeout`. |
| `Unauthorized`                              | HTTP 401: missing, bad or expired bearer.                                                                                                                                                                                                                                                                                                                                    |
| `ApiError` (`.status`, `.error`, `.detail`) | Any other non-success from the server: `invalid_scope`, `invalid_grant`, 404, 422.                                                                                                                                                                                                                                                                                           |
| `RpcError`                                  | A JSON-RPC error that is not a denial (unknown upstream, upstream down).                                                                                                                                                                                                                                                                                                     |
| `RefreshError` (`.reason`)                  | A `TokenRefresher` gave up: `lease_revoked`, `lease_lost`, `token_expired`, `refused`, `key_mismatch`.
| `VerificationError`                         | `inspect(verify=True)` failed.                                                                                                                                                                                                                                                                                                                                               |

A denied `tools/call` is a decision, not a glitch: do not retry it blindly. A `lease_expired` denial is the one case where `renew()` then one retry makes sense; `lease_revoked` means stop.

## MCP clients

`attenuo.mcp` produces the URL and headers an MCP client needs; see [`examples/python-agent/mcp_client_example.py`](https://github.com/attenuo-dev/attenuo/blob/main/examples/python-agent/mcp_client_example.py) for the official `mcp` package.

```python
from attenuo.mcp import mcp_headers, mcp_url

url = mcp_url("http://127.0.0.1:8080", "github")  # http://127.0.0.1:8080/mcp/github
headers = mcp_headers(coder)  # {"Authorization": "Bearer ..."}
```

`TokenAuth(provider)` is an `httpx.Auth` that reads the current token on each request, for tokens that get replaced (a [`TokenRefresher`](#keeping-a-token-alive) is a provider). `TokenAuth(provider, dpop_key=key)` also adds a DPoP proof per request, which a bound token needs; static headers cannot carry one.

## Verifying

```python
tok = ob.inspect(jwt, verify=True, issuer="http://127.0.0.1:8080", audience="attenuo")
```

Local verification checks the signature against the server's JWKS and the claims listed above. It does not check the detached `ou_sig` over the user block; the server does that on every request. Without `issuer`/`audience` pins it proves "signed by this server's key and unexpired", as the CLI's `token inspect --verify` does.

## Verifying an audit export offline

```python
import httpx
from attenuo.audit import verify_export

jwks = httpx.get("http://127.0.0.1:8080/.well-known/jwks.json").json()
report = verify_export("audit.jsonl", checkpoint_public_keys=jwks)  # from `attenuo audit export`
if not report.ok:
    print(report.first_bad_seq, report.bad_checkpoints, report.truncated, report.unsigned_tail)
```

`verify_export(path_or_lines, *, checkpoint_public_keys, allow_unsigned_tail=False)` takes a path (`str` or `PathLike`; a `str` is always a path) or an iterable of lines, in JSON Lines or the `--format json` form. `checkpoint_public_keys` is the JWKS or a `{kid: public key}` map (raw 32 bytes or base64url). It re-checks the SHA-256 hash chain over RFC 8785 canonical JSON of `["attenuo-audit-entry-v2", seq, prev_hash, record]`, the range the header declares and the Ed25519 checkpoint signatures, with the same strictness as `attenuo audit verify --file`: a short file, entries outside the range and entries after the last valid checkpoint (unless `allow_unsigned_tail=True`) all fail. The `ExportReport` has `ok`, `first_bad_seq`, `bad_checkpoints`, `last_signed_seq`, `unsigned_tail`, `truncated`, `outside_range` and the rest of the Rust report. A file that is not a verifiable export (no header, wrong format, a filtered export, not JSON) raises `attenuo.audit.ExportError`. It needs the `verify` extra (`cryptography`) for the signatures and depends on the pinned `rfc8785`. It hashes each record as it appears in the file and refuses duplicate object members, so it is a little stricter than the Rust check. A filtered export (`audit_export(kind=..., chain_id=...)`) cannot be verified: its chain has gaps, so verify the unfiltered one, then filter. `AuditEntry` has `kind` and `chain_id`.

### Cross-checking shipped checkpoints

A checkpoint is signed with the server's own key, so someone who holds the host and the key can rewrite the log and sign it again. `[audit.sink]` ships each checkpoint off the host; `cross_check` compares an export with those copies (SR-21), like `attenuo audit verify --file --checkpoints`:

```python
from attenuo.audit import cross_check, verify_export

assert verify_export("audit.jsonl", checkpoint_public_keys=jwks).ok
cross = cross_check("audit.jsonl", "shipped.jsonl", checkpoint_public_keys=jwks)
for m in cross.mismatches:  # in the order of the shipped file
    print(m.seq, m.line, m.reason)
```

`cross_check(export, shipped, *, checkpoint_public_keys)` takes the export and the shipped file (the file sink's JSON Lines, webhook bodies one per line, or bare checkpoint lines) as paths or iterables of lines. For every shipped checkpoint inside the export's range it requires that the checkpoint verifies, that the export holds an identical one at that `seq`, and that the export's entry there hashes to the shipped `head_hash`. The `CrossCheckReport` has `ok`, `shipped`, `in_range`, `matched`, `beyond_range`, `last_shipped_seq` and `mismatches` (`seq`, `line`, `reason`): a checkpoint signed again after it was shipped, one deleted from the export, two different shipped copies for one `seq`, and a shipped copy that does not verify or whose envelope disagrees with itself. The reasons are the Rust ones, word for word. Run it next to `verify_export`, not instead. A shipped file that is not checkpoints raises `ExportError`; `parse_shipped` parses one on its own.

## Development

```sh
cd sdk/python
pip install -e '.[dev]'
ruff check --config pyproject.toml . ../../examples/python-agent
ruff format --check --config pyproject.toml . ../../examples/python-agent
mypy --strict src tests ../../examples/python-agent
pytest -rf                   # unit tests, no server needed
ATTENUO_INTEGRATION=1 pytest -rf -m integration   # builds and starts the real server (needs cargo)
```

Keep `-rf`: it prints the name of every failed test in the summary, which a long run otherwise scrolls away.

The integration test builds `attenuo-server` and the `fake_mcp` example, starts both on free ports, and replays the [GitHub leak scenario](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md) through the SDK: dev root mint, exchange, an allowed call, a policy denial, a capability denial, revocation, `lease_revoked`, and an audit chain check.

## Limits

- The server's JSON-RPC and header behaviour is what is implemented in this repository today. Nothing here is tested against a server of another version.
- Streaming responses (long-lived SSE, server-initiated requests) are not supported by `call_tool`: it reads one response and returns the first JSON-RPC result or error in it. Use a full MCP client with `attenuo.mcp` for that.
- Hop-0 exchange (`client_id`/`client_secret`) is covered by unit tests against a mock transport only, not against a live IdP.
