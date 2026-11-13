# attenuo (Python SDK)

Python client for the [attenuo](https://github.com/attenuo-dev/attenuo/blob/main/README.md) authorization server: exchange delegation tokens, attenuate capabilities, call MCP tools through the enforcing proxy, handle denials, renew leases, and read the audit log.

**Status: pre-alpha**, like the server. Version 0.1.0, released together with attenuo 0.1.0: the SDK carries the server's version number, follows that release's wire format and will change with it. Once 0.1.0 is on PyPI, `pip install attenuo` installs it; until the maintainer publishes it, install from a checkout.

```sh
pip install -e sdk/python            # runtime dependency: httpx
pip install -e 'sdk/python[verify]'  # adds cryptography, for Client.inspect(..., verify=True)
```

Python 3.10 or newer.

## Quickstart

Start a server with the example config (`[dev] allow_root_mint = true` for the dev root token) and an MCP upstream, as in [getting started](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/getting-started.md). Export the admin token the server was started with as `ATTENUO_ADMIN_TOKEN`, and the coder's client secret as `CODER_SECRET` (`coder-secret-change-me` in `config/example.toml`). Then:

```python
import os

from attenuo import AdminClient, Capability, Client, Denied, Prefix

URL = "http://127.0.0.1:8080"

# Development only: mint a root token for an asserted user. In production hop 0 comes from
# your IdP: client.exchange(id_token, "planner", ["github:*"], client_id=..., client_secret=...).
admin = AdminClient(URL, os.environ["ATTENUO_ADMIN_TOKEN"])
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
| `exchange(subject_token, actor, capabilities, ttl_seconds=None, client_id=None, client_secret=None, subject_token_type=None, *, actor_token=None, may_act=None, client_assertion=None)` | RFC 8693 exchange. Returns a `Token`. From a delegation token, `client_secret` is the actor's `[[agents]]` secret (`client_id` defaults to `actor`), which the server requires by default. From any other subject token, `client_id` and `client_secret` make it a hop-0 exchange of an IdP credential (`subject_token_type="...:id-jag"` for an ID-JAG). A parent token can be exchanged for a given actor once. `actor_token` (a workload-identity JWT such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer) authenticates the actor instead of a secret, depending on `[token] actor_auth`; each one works for one exchange. `client_assertion` is a `private_key_jwt` assertion (RFC 7523) for an agent whose `[[agents]]` entry lists public keys (`jwks`), made with `DpopKey.load(path).client_assertion(agent_id, server_issuer)` from the key `attenuo key gen --client` wrote; it replaces `client_secret` (never both) and works for one request (the nonce retry and the `max_retries` retry send it again; see [Load refusals](#load-refusals)). `may_act` lists the agents allowed to exchange the new token next. |
| `renew(token)`                                                                                       | `POST /token/renew`. Returns `Lease(lease, expires_at, expires_in)`.                                                                                                                                                                                                                                                                                                                                              |
| `call_tool(token, server, tool, arguments, session_id=None)`                                         | `tools/call` through `/mcp/{server}`. Returns `ToolResult` (`.text`, `.content`, `.is_error`, `.decision_id`).                                                                                                                                                                                                                                                                                                    |
| `call_tool_with_approval(token, server, tool, arguments, *, on_approval=None, timeout=None, interval=2.0)` | `call_tool`; when the call needs an approval (`-32008`), calls `on_approval(err)`, waits for the grant, and retries the call once, with the grant's `approval_token` when it has one. `call_tool(..., approval_token=...)` sends a token yourself. See [Approvals](#approvals). |
| `get_approval(approval_id, token)`, `wait_for_approval(approval_id, token, *, timeout=None, interval=2.0)` | `GET /approvals/{id}` as the agent (same run, DPoP signed when the client has a key); `wait_for_approval` polls until granted and raises `ApprovalNotGranted` otherwise. |
| `grant_approval(approval_id, id_token)`, `decline_approval(approval_id, id_token)` | `POST /approvals/{id}` as the run's originating user, with their OIDC ID token as a plain bearer. Returns the decided `Approval`. See [Approvals](#approvals). |
| `list_tools(token, server)`                                                                          | `tools/list`, filtered by the proxy to what the token may call.                                                                                                                                                                                                                                                                                                                                                   |
| `initialize(token, server)`                                                                          | MCP `initialize`; returns the `Mcp-Session-Id`, if any.                                                                                                                                                                                                                                                                                                                                                           |
| `close_session(token, server, session_id)` | `DELETE /mcp/{server}`: ends the MCP session. `True` when the upstream closed it, `False` when it does not let clients close sessions (405). |
| `authzen_evaluate(token, server, tool, arguments)`                                                   | AuthZEN decision without calling the tool. A deny is a falsy `AuthzenDecision`, not an exception; on `approval_required` it also has `call_hash`, `approval_id` and `expires_at` (see [Approvals](#approvals)).                                                                                                                                                                                                   |
| `authzen_evaluate_batch(token, evaluations, *, semantic=None)`, `authzen_configuration()` | `POST /access/v1/evaluations`: several decisions in one request, one `AuthzenDecision` per call; and the AuthZEN discovery document. See [AuthZEN batches and discovery](#authzen-batches-and-discovery). |
| `inspect(jwt, verify=False)`                                                                         | Decode a token. With `verify=True` fetch the JWKS and check the Ed25519 signature, `typ`, `exp` and that `sub`/`act` match the chain.                                                                                                                                                                                                                                                                             |
| `AdminClient(server_url, admin_token)`                                                               | `revoke_lease`, `revoke_by_selector` (every lease of one user, chain or MCP session; see [below](#admin-revoking-by-user-chain-or-session)), `lease_status`, `refund_budget` (see [below](#admin-refunding-a-budget-charge)), `audit`, `audit_head` (reads `head` from `GET /admin/audit`, signs nothing), `audit_tail`, `audit_export` (iterator of JSON Lines objects; `kind=`, `chain_id=`, `tool=` and `decision=` filter), `audit_checkpoint` (explicit; signs and stores a checkpoint), `audit_verify`, `policy_reload`, `mint_root_dev`, the approval calls (`approvals`, `approval`, `grant_approval`, `decline_approval`); and the read-only console helpers below (`audit_query`, `audit_iter`, `audit_entry`, `audit_record`, `audit_checkpoints`, `lease_tree`, `policies`, `policy_check`, `policy_evaluate`, `whoami`).                                                                                                                       |

`Token` carries `jwt` (also `str(token)`), `lease`, `expires_at`, `chain` (user, hops, capabilities per hop), and `verified`. `repr` does not print the JWT. Everything decoded from a token is untrusted unless `verified` is true.

`AdminClient` talks to the admin API (`/admin/*`). A server with `[admin] listen` serves it on that address only, so give `AdminClient` that listener's URL, not the main one ([network exposure](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/deploying.md#network-exposure)).

### Admin: querying the audit log, lease trees, policies

These wrap the read-only operator routes the admin console uses. None of them signs, changes or audits anything.

```python
import os

from attenuo import AdminClient, AuditFilter

admin = AdminClient(URL, os.environ["ATTENUO_ADMIN_TOKEN"])

# Newest denials first. A filtered page can come back short (even empty) with next_cursor
# still set, so iterate rather than reading one page: audit_iter follows the cursor to the end.
for e in admin.audit_iter(AuditFilter(decision="deny", agent="coder"), order="desc"):
    print(e.seq, e.reason, e.tool)
page = admin.audit_query(AuditFilter(kind=["lease_renew"], lease=lease_id), limit=50)

detail = admin.audit_record(denied.decision_id)  # or admin.audit_entry(seq)
print(detail.lease_states, detail.covered_by_checkpoint, detail.policy_reloaded_after)

admin.audit_checkpoints(limit=20)  # stored checkpoints, newest first; never signs
for a in admin.approvals_iter(state="pending"):  # every pending approval, newest first
    print(a.approval_id, a.tool)
tree = admin.lease_tree(lease_id)  # what a revoke would reach: nodes, ancestors, would_revoke

admin.policies()  # the loaded set: path, sha256, loaded_at, {id: text}
admin.policy_check()  # lint the file on disk now; .ok means a reload would succeed
ev = admin.policy_evaluate("github", "read_file", {"repo": "alice/x"}, token=coder)
print(ev.decision, ev.reason, ev.policy_ids)  # no lease check, no audit record
```

| Call | Route | Returns |
| --- | --- | --- |
| `audit_query(filter=None, *, order="asc", from_seq=None, to_seq=None, cursor=None, limit=100)` | `GET /admin/audit` | `AuditPage(entries, next_cursor, head)` |
| `audit_iter(filter=None, *, order="asc", from_seq=None, to_seq=None, limit=1000)` | `GET /admin/audit`, repeated | iterator of `AuditEntry`, following `next_cursor` until null |
| `audit_entry(seq)`, `audit_record(record_id)` | `GET /admin/audit/entries/{seq}`, `/admin/audit/records/{id}` | `AuditEntryDetail(entry, lease_states, covered_by_checkpoint, policy_reloaded_after)` |
| `audit_checkpoints(cursor=None, limit=None)`, `audit_checkpoints_iter(limit=None)` | `GET /admin/audit/checkpoints` | `CheckpointPage(checkpoints, next_cursor)`; the iterator yields every checkpoint, newest first |
| `lease_tree(lease_id, max_nodes=None)` | `GET /admin/leases/{id}/tree` | `LeaseTree(root, ancestors, nodes, would_revoke, truncated)` |
| `whoami()` | `GET /admin/whoami` | `AdminIdentity(name, role)`: the operator the admin token belongs to (`admin` for the server's `[admin] token`) and its role |
| `policies()` | `GET /admin/policies` | `PolicySet(path, sha256, loaded_at, policy_ids, warnings, policies)` |
| `policy_check()` | `GET /admin/policies/check` | `PolicyCheck(ok, issues, differs_from_loaded, ...)` |
| `policy_evaluate(server, tool, arguments=None, *, token=None, chain=None, budget=None, session=None, approval=None, usage=None)` | `POST /admin/policies/evaluate` | `PolicyEvaluation(decision, reason, policy_ids, ..., token_expired, budget, limit, labels, usage, approval_by)`; `.allowed` |
| `approvals(chain_id=None, *, state=None, limit=None, cursor=None)` | `GET /admin/approvals` | `ApprovalPage(approvals, next_cursor)`, newest first (server default page 100, at most 500) |
| `approvals_iter(chain_id=None, *, state=None, limit=None)` | `GET /admin/approvals`, repeated | iterator of every matching `Approval`, following `next_cursor` |
| `approval(approval_id)` | `GET /admin/approvals/{id}` | `Approval` |
| `grant_approval(approval_id)`, `decline_approval(approval_id)` | `POST /admin/approvals/{id}` | `Approval` after the decision (`by = \"operator\"`); `ApiError` 409 when it is no longer pending |

`AuditFilter` fields are exact matches combined with AND: `kind` (one or a list), `decision`, `reason`, `subject`, `agent`, `lease`, `server`, `tool`, `chain_id`, and `since` / `until` (RFC 3339 strings or timezone-aware datetimes). Errors map as everywhere else: a 404 for an unknown seq, record or lease is an `ApiError` with `status == 404`, a bad filter is a 400 `invalid_request`, a bad cursor a 400 `invalid_cursor`. `AsyncAdminClient` has the same methods; the `*_iter` methods are async iterators there.

Every list pages with an opaque cursor ([Paging](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#paging)): pass a page's `next_cursor` back as `cursor` with the same filters, or use the `*_iter` methods, which do that and raise `AttenuoError` if the server ever repeats a cursor. `audit(from_seq, limit, *, cursor=None)` returns `(entries, next_cursor)`. A `limit` above the route's maximum is the server's 400, not clamped.

`audit_export(from_seq=1, to_seq=None, *, kind=None, chain_id=None, tool=None, decision=None)` takes the same four filters as `GET /admin/audit/export` (`decision` is `"allow"` or `"deny"`), combined with AND. The header of a filtered export has a `filter` member naming them, and [`verify_export`](#verifying-an-audit-export-offline) refuses it.

```python
denied = list(admin.audit_export(tool="token.exchange", decision="deny"))
assert denied[0]["filter"] == {"tool": "token.exchange", "decision": "deny"}
```

### Admin: a dry run with a stated budget

`policy_evaluate` reads the run's limit counters from the store unless you state them. `budget=` takes a `StatedBudget` (or the raw block as a dict) in the vocabulary of a `policy test` case's `budget`: `calls_remaining`, `amount_remaining`, `destination_new`, `limited`, and `limits`, single counters as `BudgetLimit(hop, kind, used, arg=None, max=None)`. Members left `None` are not sent. The server checks the counters with the same code a live call goes through, never touches the store and writes no audit record; a malformed block is its 400 `invalid_request`, raised as `ApiError`.

```python
from attenuo import BudgetLimit, StatedBudget

# The coder's token carries a `distinct` limit of one `repo` at hop 1. Is a second repo refused?
ev = admin.policy_evaluate(
    "github",
    "read_file",
    {"repo": "alice/other"},
    token=coder,
    budget=StatedBudget(limits=[BudgetLimit(hop=1, kind="distinct", arg="repo", used=1)]),
)
assert ev.reason == "budget_exhausted"
print(ev.limit)  # BudgetLimit(hop=1, kind='distinct', used=1, arg='repo', max=1)
print(ev.budget.source)  # "request"; "store" when no budget was stated
```

The answer's `budget` is an `EvaluationBudget(limited, calls_remaining, amount_remaining, destination_new, source)`, where a remaining figure is `2**63 - 1` when no limit of that kind matches. `limit` is set only on `budget_exhausted` and has the `BudgetLimit` shape, so it can be stated back as it came. `labels` (the run's output labels), `usage` (`context.usage`) and `approval_by` complete the picture the policy saw.

The other inputs the policy sees can be stated the same way, each instead of what the store holds for the run:

- `session=StatedSession(tainted_by=(), tainted=None, untrusted_args=(), args_contain_untrusted=None)`: the run's output labels. `tainted` defaults on the server to whether `tainted_by` names a source, `args_contain_untrusted` to whether `untrusted_args` names an argument. The answer's `labels.source` is then `"request"`.
- `approval=StatedApproval(by="user" | "operator" | "policy")`: evaluate the call as a retry that carries a granted approval. The dry run never looks up or consumes a stored approval, so there is no id or token to pass. The answer's `approval_by` is then `by`.
- `usage=StatedUsage(calls=None, amount=None, destination_seen=None)`: `context.usage` (the server takes a member left out as 0 or `False`). The answer's `usage.source` is then `"request"`. With a stated `budget` and no `usage`, the usage is zero and also reported as `"request"`.

Each also takes the raw block as a dict, and members left `None` or empty are not sent. Nothing is checked in the SDK: an unknown member, a negative figure or an unknown approver is the server's 400 `invalid_request`, raised as `ApiError`.

```python
from attenuo import StatedApproval, StatedSession

# Would a create_issue ask for approval once the run has read a web page, and pass with one?
taint = StatedSession(tainted_by=["web/fetch"])
asked = admin.policy_evaluate("github", "create_issue", issue, token=root, session=taint)
print(asked.reason, asked.labels.source)  # approval_required request (with a taint rule loaded)
ok = admin.policy_evaluate(
    "github", "create_issue", issue, token=root, session=taint, approval=StatedApproval(by="user")
)
print(ok.decision, ok.approval_by)  # allow user
```

### Admin: revoking by user, chain or session

`revoke_by_selector` wraps `POST /admin/leases/revoke`: it revokes every unrevoked lease of one originating user, one delegation chain or the chain that opened one MCP session, each with its descendants, in one transaction. Give exactly one selector; anything else raises `ValueError` before a request is sent.

```python
admin.revoke_by_selector(user="alice@example.com", reason="laptop stolen")
admin.revoke_by_selector(chain_id=root.lease, preview=True)  # dry run: nothing written
r = admin.revoke_by_selector(session=session_id, reason="session hijacked")
print(r.selector)  # {"session_tag": "<12 hex>", "chain_ids": [...]}, never the raw id
print(r.matched_count, r.revoked_count, r.audit_id)
```

| Argument | Matches |
| --- | --- |
| `user` | every lease the server recorded for that originating `sub`, under any issuer |
| `chain_id` | that chain's first-hop lease and everything delegated from it (a lease with a parent matches nothing) |
| `session` | the raw `Mcp-Session-Id`; the server hashes it and revokes, as `chain_id`, each chain that opened the session through the proxy |

It returns a `SelectorRevocation`: `selector` (as the server shows it), `preview`, `matched`, `revoked` (matches first, then the cascade; each list cut at 10,000 ids, `truncated` says so), `matched_count`, `revoked_count`, `reason` and `audit_id`. With `preview=True` nothing changes and no audit record is written; `revoked` is what a revocation sent now would change, and `reason` and `audit_id` are `None`. Matching nothing is not an error: the lists come back empty, also for a session the server never recorded. The SDK never logs the session id and no error message it raises contains it. `revoke_lease(lease_id)` still revokes one lease by id; its `RevokeResult` carries the `audit_id` of the `admin.lease.revoke` record (`None` when the server could not write it). See [Revoke by user or chain](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#revoke-by-user-or-chain) for the server side.

### Admin: refunding a budget charge

An allowed call is charged to its run's limits before it goes upstream. When its effect did not happen (the upstream failed, or a person undid it), an operator can give the charge back, once, by the decision's id:

```python
import os

from attenuo import AdminClient, ApiError

admin = AdminClient(URL, os.environ["ATTENUO_ADMIN_TOKEN"])
try:
    r = admin.refund_budget(result.decision_id, "upstream returned 502")
    print(r.refunded, r.audit_id)  # counters credited; the admin.budget.refund record
except ApiError as e:
    print(e.status, e.error, e.detail)  # 409 already_refunded, 410 charge_pruned, 404 not_found
```

`refund_budget(decision_id, reason=None)` sends `POST /admin/budgets/refund` and returns `BudgetRefund(decision_id, refunded, reason, audit_id)`. `refunded` counts the run-limit counters credited; the run usage and per-user windows the decision charged are given back as well but not counted, so it can be 0. A refusal writes no audit record, so its `ApiError` has no `decision_id`; `detail` says why, from the decision's audit record ([HTTP API](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#budget-refund)).

### Capabilities

```python
from attenuo import Capability, Equals, OneOf, PathPrefix, Prefix, Range

Capability("github", "read_file")  # github:read_file
Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))
Capability("github", "read_*", repo=Prefix("alice/public-"), ref=Equals("main"))
Capability("fs", "read_file", path=PathPrefix("/workspace"))  # /workspace and below, no ..
Capability("banking", "send_money", amount=Range(0, 2000))  # 0 <= amount <= 2000
Capability("banking", "refund", amount=Range(max=50))  # no lower bound
```

`Range(min, max)` bounds an integer argument, both ends inclusive; leave one out for no bound on that side, but not both. It raises `ValueError` for no bound, `min > max` or a bound that is not an integer. The server reads the argument as Cedar does (`5.0` is `5`), and a fraction or a numeric string is outside every range. A child may narrow a range (`Range(10, 500)` under `Range(0, 2000)`, or `OneOf(100, 200)`), never widen it. A range bounds each call; to bound the total over a run as well, add a `sum` limit (below).

`PathPrefix(path)` is for file paths. It compares by `/` segment, so `PathPrefix("/workspace")` admits `/workspace/a.txt` but not `/workspace-secrets/x`, and the server refuses a value with a `.` or `..` segment, `//`, a backslash, a control character, a percent-encoded `.`, `/` or `\`, a double-encoded escape (`%252e`) or a character that normalises to `.`, `/` or `\` (such as `．` or `／`) instead of normalising it, so `/workspace/../etc/passwd` is denied. `Prefix("/workspace/")` admits that value: it is a plain string comparison, for URL or id prefixes. A trailing `/` on `path` asks for something below it (`PathPrefix("/workspace/")` does not admit `/workspace` itself). The constructor raises `ValueError` for a path the server would refuse; `path_problem(path)` says why. A child may narrow a `PathPrefix` to a deeper one, to values under it, or narrow a `Prefix` to a `PathPrefix` whose path starts with the prefix; never the other way round.

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

With a key, every `call_tool`, `list_tools`, `close_session`, `renew`, `authzen_evaluate` and `authzen_evaluate_batch` sends `Authorization: DPoP <token>` and a fresh proof, and every `exchange` binds the new token. When the parent is bound to another key, its holder's sign-off names the new key and agent and works for that one exchange; a process that holds both keys can pass `subject_dpop_key=planner_key` instead. When the parent is bound to the client's own key, no sign-off is needed. `Token.dpop_jkt` is the thumbprint a token is bound to (`None` for a bearer token), and `AuditEntry.dpop_bound` says whether a decision was made with a proven bound token. A bound token without a proof is `Unauthorized` with `reason == "dpop_required"`, from `call_tool` as from `renew` or `exchange` (see [Errors](#errors)). See [Binding tokens to keys](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/binding-tokens-to-keys.md).

Server nonces (RFC 9449 §8, `[token] dpop_nonce = "required"`) need no code. `Client`, `AsyncClient`, `AdminClient.mint_root_dev` and `TokenAuth` keep the latest `DPoP-Nonce` header the server sent and put it in each proof. When the server refuses a proof with `use_dpop_nonce`, they retry the request once with a new proof carrying the nonce from that response, on a new connection: the server can close the connection that carried the refusal without saying so (it does when it answers before reading the request body), so `NonceCache.update` shuts that socket down and the pool opens another (`attenuo.dpop.drop_connection`; a response without a socket, such as from a mock transport, is left alone). For your own HTTP code, `DpopKey.proof(method, url, access_token, nonce=...)` adds the claim, and `attenuo.dpop.NonceCache` does the bookkeeping: `update(response)` stores the nonce and returns true when the request should be retried.

### Keeping a token alive

`TokenRefresher` (threads) and `AsyncTokenRefresher` (`asyncio`) renew the lease at a third of the lease interval, call your `exchange` function before the token's `exp`, and keep the current token in `.token`:

```python
from attenuo import Client, RefreshError, TokenAuth, TokenRefresher


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

`approval_id` is `None` when the server could not open an approval; treat that as a plain denial. One case is a run that already holds 32 pending approvals (SR-92): the server keeps no more for one run, so the next gated call is answered `-32008` without an `approval_id`, `call_tool_with_approval` raises it at once without calling `on_approval`, and a PEP that gets AuthZEN diagnostics sees `"too many pending approvals for this run"`. Deciding one of the run's approvals, or letting it lapse, makes room. `authzen_evaluate` says the same: on `approval_required` its `AuthzenDecision` carries `call_hash`, and `approval_id` and `expires_at` when an approval was opened. A route that would have to open an approval past the cap answers HTTP 429 `too_many_pending_approvals`, raised as `ApiError`. Like `-32003`, a `-32008` counts only when the `X-Attenuo-Decision-Id` header names its `data.decision_id`; otherwise it is an upstream's own `RpcError`.

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

The user decides with their own sign-in. A front end that holds the user's OIDC ID token (from the same `[[idps]]` issuer and client id the run started with) calls:

```python
approval = ob.grant_approval(approval_id, user_id_token)  # or decline_approval
print(
    approval.state, approval.approver
)  # granted, {"subject": "alice", "method": "id_token", "by": "user"}
```

The ID token goes as `Authorization: Bearer`, never with DPoP and never the client's own token: the server refuses a delegation token there (403 `agent_token_refused`), another user's token (403 `wrong_user`) and an ID token used before (400 `invalid_grant`, `description == "replayed"`); a decided or expired approval is 409. Each is an `ApiError` (`Unauthorized` for a 401, such as an expired ID token).

### AuthZEN batches and discovery

`authzen_evaluate_batch` sends several calls in one `POST /access/v1/evaluations`. Each is decided, charged and audited like `authzen_evaluate`, and the answer has one `AuthzenDecision` per call, in order:

```python
from attenuo import AuthzenEvaluation

decisions = ob.authzen_evaluate_batch(
    token,
    [
        AuthzenEvaluation("github", "read_file", {"repo": "alice/docs"}),
        ("github", "create_issue", {"repo": "alice/docs"}),  # a tuple works too
    ],
    semantic="deny_on_first_deny",
)
for d in decisions:
    print(bool(d), d.reason, d.decision_id, d.error)
```

`semantic` is AuthZEN's `evaluations_semantic`: `execute_all` (the default), `deny_on_first_deny` or `permit_on_first_permit`. A batch that stops early answers only the calls it decided, so the list can be shorter than the request. A call the server could not decide is a deny with `error`, an `AuthzenEntryError(status, code, message)`. An empty batch raises `ValueError` before anything is sent (the server would answer it as a single evaluation), and more calls than `[authzen] max_batch` (default 64) is `ApiError` 400 `batch_too_large`.

`authzen_configuration()` reads `GET /.well-known/authzen-configuration` without a credential and returns `AuthzenConfiguration(policy_decision_point, access_evaluation_endpoint, access_evaluations_endpoint, raw)`.

### Streaming a call

A long tool can stream its answer: the upstream sends progress notifications on an SSE stream before the result. `call_tool` waits for the whole body. `call_tool_stream` (same arguments, plus `max_event_bytes` and `deadline`) yields each JSON-RPC message as it arrives:

```python
from attenuo import Denied

try:
    for event in ob.call_tool_stream(coder, "github", "read_file", {"repo": "alice/docs"}):
        if event.result is not None:  # the last event
            print(event.result.text, event.result.decision_id)
        elif event.method == "notifications/progress":
            print("progress:", event.message["params"].get("progress"))
except Denied as d:
    print("denied or cut:", d.reason, d.decision_id)
```

`AsyncClient.call_tool_stream` is the same as an async iterator (`async for`, no `await`). It is a separate method, not a `stream=True` flag on `call_tool`, because it returns something else: an iterator of `StreamEvent`, not a `ToolResult`. That keeps both return types exact for type checkers, and `call_tool` behaves as before.

- **Events.** Each `StreamEvent` has `message` (the JSON-RPC message as sent), `method` (for a notification or a server request, else `None`), `last_event_id` (the SSE id at that point, what a client would send as `Last-Event-ID` to resume) and `decision_id` (the proxy's `X-Attenuo-Decision-Id`). The final event carries `result`, the same `ToolResult` that `call_tool` returns, and `is_final` is true. Nothing is yielded after it.
- **Errors.** A denial raises `Denied` (or `ApprovalRequired`) before anything is yielded, as `call_tool` does. When the proxy cuts a stream because the lease was revoked or expired, or the token expired (it re-checks every `[proxy] stream_recheck_seconds`, default 2), its last event is a JSON-RPC `-32001` error with `id: null`. That raises `Denied` with `reason` (`lease_revoked`, `lease_expired`, `lease_unknown`, `token_expired`, ...) and `decision_id`, the id of the proxy's `stream.end` audit record. So code that catches `Denied` around `call_tool` also handles a revocation in the middle of a stream. The `X-Attenuo-Decision-Id` header is sent before the cut, so it cannot vouch for this id as it does for a `-32003`. A `-32001` with `id: null` counts as a cut only when `data.reason` is one the proxy sends and `data.decision_id` is absent or a UUID; anything else of that shape raises `RpcError` with code `-32001`, a belt-and-braces check, since the proxy itself rewrites any upstream message of that shape to `-32005` (`upstream_stream_end_shape`). Any other JSON-RPC error raises what `call_tool` raises. A stream that ends without the response raises `AttenuoError`.
- **Plain answers.** When the proxy answers with a JSON body instead of SSE (most upstreams do), you get one final event.
- **Limits.** An SSE event, or a plain body, over `max_event_bytes` raises `AttenuoError`. The default is 16 MiB (`DEFAULT_MAX_EVENT_BYTES`), the same as the proxy's `[proxy] max_upstream_body_bytes` default. The client's `timeout` applies to each read, so a stream that is quiet for longer fails. Keep-alive comments restart that timer, so pass `deadline=` (seconds, from the request's start, default none) to bound the whole call: once it has passed, the next read raises `TransportTimeout` naming the deadline and closes the response. Leaving the loop early closes the connection once the iterator is closed or garbage collected.
- **Wire.** It sends the same `POST` as `call_tool`: `Accept: application/json, text/event-stream`, the session id, the approval token in `_meta`, and a DPoP proof (with one retry on `use_dpop_nonce`) when the client has a key. Only the response handling differs. SSE parsing follows the WHATWG rules: `data:` lines are joined, a blank line ends an event, and comments, `event:` and `retry:` are ignored. A final event with no blank line after it is dropped, as the proxy also drops it.

### Errors

All SDK errors derive from `AttenuoError`, transport failures included.

| Exception | When |
| --- | --- |
| `Denied` (`.reason`, `.stable_code`, `.decision_id`, `.data`, `.limit`, `.usage`, `.untrusted_args`) | The proxy said no (JSON-RPC `-32003` with the `X-Attenuo-Decision-Id` header naming `data.decision_id`; an upstream's own `-32003` without that proof is an `RpcError`). Also raised by `call_tool_stream` when the proxy cuts a stream for a lease or token reason ([Streaming a call](#streaming-a-call)). Branch on `reason`: `capability_denied`, `policy_deny`, `budget_exhausted`, `lease_revoked`, `lease_expired`, ... See the [integration guide](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/integrating-mcp-clients.md#handling-denied-responses). `data` is the error's whole `data` object; what the server adds to it is typed too (below). |
| `ApprovalRequired` (`.approval_id`, `.expires_at`, `.call_hash`) | A `Denied` for JSON-RPC `-32008`: a policy holds the call until it is approved. See [Approvals](#approvals). |
| `ApprovalNotGranted` (`.approval_id`, `.state`) | Waiting for an approval ended without a grant: `declined`, `expired`, `consumed` or `timeout`. |
| `Unauthorized` (`.reason`, `.decision_id`, `.data`) | HTTP 401 or JSON-RPC `-32001`: missing, bad or expired bearer, a DPoP failure, or (from the proxy) a lease that is no longer live. A subclass of `ApiError`. Branch on `reason` (below). |
| `Unavailable` (`.reason`, `.retry_after`, `.data`) | HTTP 503 from the server itself (REST `temporarily_unavailable`, or the proxy's JSON-RPC `-32006`): `overloaded`, `request_timeout`, `session_registry_full`, ... A subclass of `ApiError`, not a denial. See [Load refusals](#load-refusals). |
| `RateLimited` (`.reason`, `.retry_after`, `.data`) | HTTP 429 (REST `rate_limited`, or the proxy's JSON-RPC `-32007`): `rate_limited` or `too_many_sessions`. A subclass of `ApiError`, not a denial. See [Load refusals](#load-refusals). |
| `ApiError` (`.status`, `.code`, `.error`, `.detail`, `.decision_id`) | Any other non-success from the server: `invalid_scope`, `invalid_grant`, 404, 408 `request_timeout`, 422. Branch on `code`, the server's stable code (`audience_mismatch`, `replayed`, `invalid_cursor`, ...; every code is listed under [Errors](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#errors)), not on `detail`, which is text for people. `error` is the broader OAuth-style error and `description` the deprecated `error_description`. Every subclass has `code` too, and `stable_code`, the same string. `decision_id` names the audit record of a refused exchange or renewal. |
| `TransportError` | No answer: the connection was refused or dropped, a timeout ran out, TLS or a proxy failed. `__cause__` is the `httpx` error. |
| `TransportTimeout` | A `TransportError` because a timeout ran out: the client's `timeout` (`__cause__` is the `httpx.TimeoutException`) or a streamed call's `deadline`. Also an `httpx.TimeoutException`. |
| `RpcError` (`.code`, `.stable_code`, `.message`, `.data`) | A JSON-RPC error that is not a denial (unknown upstream, upstream down). `code` is the JSON-RPC number (`-32004`, `-32005`, ...); `stable_code` is the server's stable code (below). |
| `RefreshError` (`.reason`) | A `TokenRefresher` gave up: `lease_revoked`, `lease_lost`, `token_expired`, `refused`, `key_mismatch`. |
| `VerificationError` | `inspect(verify=True)` failed. |

**`Unauthorized.reason`** is the server's stable code, the same for `call_tool` and the REST routes: `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce` (the clients already retry this one once with the server's nonce), and from the proxy also `lease_revoked`, `lease_expired` and `lease_unknown`. A lease refusal of a request the proxy decides nothing for (`initialize`, `tools/list`, ...) is recorded in the audit log, and `decision_id` names the record. `error` keeps its old value: `"unauthorized"` for every proxy 401, and the REST body's `error` (`unauthorized`, `dpop_required`, ...) otherwise.

```python
from attenuo import Denied, TransportError, Unauthorized

try:
    ob.call_tool(token, "github", "read_file", {"repo": "alice/docs"})
except Unauthorized as e:
    if e.reason in ("lease_revoked", "lease_unknown"):
        stop(e.decision_id)  # the run was revoked: do not retry
    elif e.reason == "lease_expired":
        ob.renew(token)  # the lease stopped renewing: renew once, then retry once
    else:
        raise
except Denied as d:
    if d.reason == "budget_exhausted" and d.limit is not None:
        print(f"limit {d.limit.kind} of hop {d.limit.hop}: used {d.limit.used} of {d.limit.max}")
    raise
except TransportError as e:
    print("server unreachable:", e.__cause__)
```

**Branching on the stable code.** Every error the server answers with names a stable code, listed under [Errors](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#errors). On an `ApiError` (and its subclasses) it is `code`. On an `RpcError`, `code` is the JSON-RPC number, so the stable code is `stable_code`: the proxy's `data["code"]`, or `data["reason"]` for a server older than `code`, else `None`. `Denied` carries it as `stable_code` too (the same string as `reason`), and `ApiError.stable_code` is `code`, so `stable_code` reads the same on all three. An error the proxy relays from the upstream keeps the upstream's `data`, so its `stable_code` is what the upstream sent there, usually `None`.

```python
from attenuo import ApiError, RpcError

try:
    ob.call_tool(token, "github", "read_file", {"repo": "alice/docs"})
except ApiError as e:
    if e.code == "token_expired":  # an Unauthorized; e.stable_code is the same string
        token = new_token()
    else:
        raise
except RpcError as e:
    if e.stable_code == "unknown_server":  # e.code is the JSON-RPC number, -32004
        raise RuntimeError("no [[upstreams]] entry named github") from e
    if e.stable_code == "upstream_timeout":  # the upstream may have acted: do not resend blindly
        report(e)
    raise
```

**What a denial carries.** `Denied.limit` is the run limit a `budget_exhausted` call would take past its `max`, as a `BudgetLimit` (the same type a dry run's `limit` is, so it can be stated back to `policy_evaluate`); `None` otherwise. `Denied.usage` is set for a tool the catalog marks destructive or gives an `outbound` input: a `RunUsage(calls, amount, destination_seen, user_window)`, the run's usage before this call as the policy saw it, with `user_window` a `UserWindow(hour, day)` of `WindowUsage(calls, amount)` when a policy reads per-user windows and a figure is not zero. `Denied.untrusted_args` lists the arguments that copy an untrusted result of the run as `UntrustedArg(arg, kind, seq)`, empty when the server sent none. `ApprovalRequired` carries the same three next to its approval fields. The shapes are in the [HTTP API reference](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#mcp-proxy).

**Decision ids are proven.** A `decision_id` on `Unauthorized` or `ApiError` is taken from the body only when the `X-Attenuo-Decision-Id` header names it, as for `Denied`: the proxy never forwards that header from an upstream, so an upstream's answer cannot pass off an id.

**Transport failures.** `TransportError` is also an `httpx.TransportError`, so `except httpx.TransportError` (or `httpx.RequestError`, `httpx.HTTPError`) keeps catching it; a handler for one `httpx` subclass, such as `httpx.ConnectError`, should test `isinstance(e.__cause__, httpx.ConnectError)` now. A failure while a streamed answer is read is one too. A timeout is the subclass `TransportTimeout` (also an `httpx.TimeoutException`), so a retry policy can tell a slow server from an unreachable one. `TokenAuth` runs inside your own `httpx` client, whose errors stay plain `httpx` errors.

A denied `tools/call` is a decision, not a glitch: do not retry it blindly. A `lease_expired` denial is the one case where `renew()` then one retry makes sense; `lease_revoked` means stop.

#### Load refusals

A server with [`[limits]`](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/config.md#limits) can refuse a request because it is busy or because the caller is over a rate limit. These are not authorization decisions: `Unavailable` and `RateLimited` are `ApiError`s, never `Denied` or `Unauthorized`, so `except Denied` and `except Unauthorized` do not catch them. Both carry `reason` (the server's code), `retry_after` (the `Retry-After` header in whole seconds, `None` when it is missing or not a number), `status` and, for a proxy answer, the JSON-RPC `data`.

| `reason` | Error | Ran on the server? | Retried by `max_retries` |
| --- | --- | --- | --- |
| `overloaded` | `Unavailable` (503) | No: refused before any decision, audit record or upstream call. Safe to retry after `retry_after`. | Yes |
| `rate_limited` | `RateLimited` (429) | No: `POST /token` per agent or address, `/mcp/{server}` per run, refused before the work. Safe to retry after `retry_after` (the end of the caller's minute). | Yes |
| `request_timeout` | `Unavailable` (503) | Maybe: the handler may have issued a token or written a decision. | No |
| `too_many_sessions`, `session_registry_full` | `RateLimited` (429), `Unavailable` (503) | The upstream answered `initialize`; the proxy then closed that session. | No |
| `jwks_unavailable`, `dpop_replay_cache_full` | `Unavailable` (503) | No decision was made. | No |

A body that does not arrive within `request_body_timeout_seconds` is a plain `ApiError` (408 `request_timeout`). On `/mcp/{server}`, a `-32006` or `-32007` counts as the proxy's own only when the answer carries `Retry-After`, which the proxy sets on its refusals and never relays from an upstream; an upstream's error of that shape stays an `RpcError`.

The clients do not retry by default. `Client(..., max_retries=N)` (and `AsyncClient`) retries `overloaded` and `rate_limited` up to `N` times (at most 10), waiting each answer's `Retry-After` (1 s without one), up to 20 % longer so that clients refused together do not come back together. A `Retry-After` over `max_retry_delay` (seconds, default 10, at most 300) is not waited out: the error is raised at once, so the retries of one call wait at most `max_retries * max_retry_delay` in all. Each retry is a new request with new DPoP proofs. `call_tool_stream` retries only before the stream starts, and never past its `deadline`. When the retries run out, the last refusal is raised. Nothing else is retried. `AdminClient` raises the same errors and does not retry.

An exchange with a `client_assertion` sends the same assertion on each retry, as it does on the `use_dpop_nonce` retry: the server leaves an assertion unused when it answers `429 rate_limited`, `503 overloaded` or `use_dpop_nonce`. Treat it as spent after any other answer. The server refuses an expired assertion, so a retry whose wait would reach the assertion's `exp` is not made: the client raises the `RateLimited` (or `Unavailable`) at once. Then mint a new assertion after `retry_after` and call again, or mint the assertion with a `lifetime` that covers the waits, at most the server's `[token] client_assertion_max_lifetime_seconds` (300 by default; `client_assertion()` makes 60 s ones).

```python
from attenuo import Client, Denied, RateLimited, Unavailable

ob = Client("http://127.0.0.1:8080", max_retries=3, max_retry_delay=30)
try:
    ob.call_tool(token, "github", "read_file", {"repo": "alice/docs"})
except (Unavailable, RateLimited) as e:
    print(f"server refused ({e.reason}); try again in {e.retry_after or 1} s")
except Denied as d:
    print("denied:", d.reason)  # a decision: do not retry it
```

## MCP clients

`attenuo.mcp` produces the URL and headers an MCP client needs; see [`examples/python-agent/mcp_client_example.py`](https://github.com/attenuo-dev/attenuo/blob/main/examples/python-agent/mcp_client_example.py) for the official `mcp` package.

```python
from attenuo import mcp_headers, mcp_url

url = mcp_url("http://127.0.0.1:8080", "github")  # http://127.0.0.1:8080/mcp/github
headers = mcp_headers(coder)  # {"Authorization": "Bearer ..."}
```

The MCP helpers (`mcp_url`, `mcp_headers`, `TokenAuth`) are importable from the package root, like the TypeScript SDK's `mcpUrl`, `mcpHeaders` and `mcpFetch`; `from attenuo.mcp import mcp_url` still works.

`TokenAuth(provider)` is an `httpx.Auth` that reads the current token on each request, for tokens that get replaced (a [`TokenRefresher`](#keeping-a-token-alive) is a provider). `TokenAuth(provider, dpop_key=key)` also adds a DPoP proof per request, which a bound token needs; static headers cannot carry one.

## Verifying

```python
tok = ob.inspect(jwt, verify=True, issuer="http://127.0.0.1:8080", audience="attenuo")
```

Local verification checks the signature against the server's JWKS and the claims listed above. It does not check the detached `ou_sig` over the user block; the server does that on every request. Without `issuer`/`audience` pins it proves "signed by this server's key and unexpired", as the CLI's `token inspect --verify` does.

## Verifying an audit export offline

```python
import httpx
from attenuo import verify_export

jwks = httpx.get("http://127.0.0.1:8080/.well-known/jwks.json").json()
report = verify_export("audit.jsonl", checkpoint_public_keys=jwks)  # from `attenuo audit export`
if not report.ok:
    print(report.first_bad_seq, report.bad_checkpoints, report.truncated, report.unsigned_tail)
```

The audit helpers (`verify_export`, `cross_check`, `parse_shipped`, `entry_hash`, `ExportError`, the report types, `SHIPPED_FORMAT`, `EXPORT_FORMAT`, `ENTRY_HASH_VERSION` and `GENESIS_HASH`), the DPoP helpers (`NonceCache`, `access_token_hash`, `jwk_thumbprint`, `is_use_dpop_nonce`, `NONCE_HEADER`, `USE_DPOP_NONCE`, `PROOF_TYPE`) and `capabilities_to_json` are importable from `attenuo` itself, as in the TypeScript SDK; `from attenuo.audit import verify_export` is the same function.

`verify_export(path_or_lines, *, checkpoint_public_keys, allow_unsigned_tail=False)` takes a path (`str` or `PathLike`; a `str` is always a path) or an iterable of lines, in JSON Lines or the `--format json` form. `checkpoint_public_keys` is the JWKS or a `{kid: public key}` map (raw 32 bytes or base64url). It re-checks the SHA-256 hash chain over RFC 8785 canonical JSON of `["attenuo-audit-entry-v2", seq, prev_hash, record]`, the range the header declares and the Ed25519 checkpoint signatures, with the same strictness as `attenuo audit verify --file`: a short file, entries outside the range and entries after the last valid checkpoint (unless `allow_unsigned_tail=True`) all fail. The `ExportReport` has `ok`, `first_bad_seq`, `bad_checkpoints`, `last_signed_seq`, `unsigned_tail`, `truncated`, `outside_range` and the rest of the Rust report. A file that is not a verifiable export (no header, wrong format, a filtered export, not JSON) raises `attenuo.ExportError`. It needs the `verify` extra (`cryptography`) for the signatures and depends on the pinned `rfc8785`. It hashes each record as it appears in the file and refuses duplicate object members, so it is a little stricter than the Rust check. A filtered export (`audit_export(kind=..., chain_id=..., tool=..., decision=...)`, any of them) cannot be verified: its chain has gaps, so verify the unfiltered one, then filter. `AuditEntry` has `kind` and `chain_id`.

### Cross-checking shipped checkpoints

A checkpoint is signed with the server's own key, so someone who holds the host and the key can rewrite the log and sign it again. `[audit.sink]` ships each checkpoint off the host; `cross_check` compares an export with those copies (SR-21), like `attenuo audit verify --file --checkpoints`:

```python
from attenuo import cross_check, verify_export

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

The integration test builds `attenuo-server` and the `fake_mcp` example, starts both on free ports, and replays the [GitHub leak scenario](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md) through the SDK: dev root mint, exchange, an allowed call, a policy denial, a capability denial, revocation, `lease_revoked`, and an audit chain check. Other tests cover DPoP, server nonces (sync and async), refresh, the cap of 32 pending approvals per run, a `decimal` catalog input (on a stack of its own, with `amount = "decimal"` for `read_file` and a policy comparing it), the examples, offline export verification across Rust, Python and TypeScript, an export filtered on `tool` and `decision`, and revocation by chain and by MCP session (the session test starts a stack of its own: the fake upstream gives every caller the same session id and the proxy binds it to the first). `test_call_tool_stream_relays_events_and_raises_on_revocation` starts one with `fake_mcp --sse` and `[proxy] stream_recheck_seconds = 1`: a streamed answer arrives as a notification then the result, and a call the upstream holds open (`hold_ms`) is cut by the proxy when the lease is revoked, raising `Denied` with the `stream.end` record's id.

## Limits

- The server's JSON-RPC and header behaviour is what is implemented in this repository today. Nothing here is tested against a server of another version.
- `call_tool` reads the whole response and returns the first JSON-RPC result or error in it; `call_tool_stream` yields a streamed answer as it arrives. Neither answers server-initiated requests (sampling, elicitation) or resumes a broken stream with `Last-Event-ID`: `call_tool_stream` yields such requests and keeps the id, but replying and resuming need a full MCP client with `attenuo.mcp`.
- Hop-0 exchange (`client_id`/`client_secret`) is covered by unit tests against a mock transport only, not against a live IdP.
