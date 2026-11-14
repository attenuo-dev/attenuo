# @attenuo/sdk (TypeScript SDK)

TypeScript client for the [attenuo](https://github.com/attenuo-dev/attenuo/blob/main/README.md) authorization server: exchange delegation tokens, attenuate capabilities, call MCP tools through the enforcing proxy, handle denials, renew leases, and read the audit log.

**Status: pre-alpha**, like the server. Version 0.1.0, released together with attenuo 0.1.0: the SDK carries the server's version number, follows that release's wire format and will change with it. Once 0.1.0 is on npm, `npm install @attenuo/sdk` installs it; until the maintainer publishes it, build it from a checkout.

```sh
cd sdk/typescript
npm install && npm run build   # ESM + CJS + .d.ts in dist/
```

Node 20 or newer (Ed25519 in WebCrypto needs no flag there: it is available since Node 18.4, still documented as experimental), zero runtime dependencies. It uses the global `fetch` and WebCrypto (`crypto.subtle` with `Ed25519`) for local token verification. It is the same API as the [Python SDK](https://github.com/attenuo-dev/attenuo/blob/main/sdk/python/README.md), with camelCase names and promises.

## Quickstart

Start a server with the example config (`[dev] allow_root_mint = true` for the dev root token) and an MCP upstream, as in [getting started](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/getting-started.md). Export the admin token the server was started with as `ATTENUO_ADMIN_TOKEN`, and the coder's client secret as `ATTENUO_CLIENT_SECRET` (`coder-secret-change-me` in `config/example.toml`). Then:

```ts
import { AdminClient, DeniedError, AttenuoClient, capability, prefix } from "@attenuo/sdk";

const SERVER = "http://127.0.0.1:8080";

// Development only: mint a root token for an asserted user. In production hop 0 comes from
// your IdP: ob.exchange(idToken, "planner", ["github:*"], { clientId, clientSecret }).
const admin = new AdminClient(SERVER, process.env.ATTENUO_ADMIN_TOKEN!); // the token the server was started with
const root = await admin.mintRootDev("alice", "https://idp.example", "planner", {
  capabilities: ["github:*"],
});

const ob = new AttenuoClient(SERVER);

// The planner hands the coder read_file on alice's public repos only.
const coder = await ob.exchange(
  root,
  "coder",
  [capability("github", "read_file", { repo: prefix("alice/public-") })],
  // The coder's [[agents]] secret: a hop n+1 exchange authenticates as its actor.
  { ttlSeconds: 600, clientSecret: process.env.ATTENUO_CLIENT_SECRET },
);
console.log(coder.agents, coder.lease); // [ 'planner', 'coder' ] <lease id>

const ok = await ob.callTool(coder, "github", "read_file", {
  repo: "alice/public-docs",
  path: "README.md",
});
console.log(ok.text, ok.decisionId);

try {
  await ob.callTool(coder, "github", "create_issue", { repo: "alice/public-docs", title: "x" });
} catch (e) {
  if (!(e instanceof DeniedError)) throw e;
  console.log("denied:", e.reason, e.decisionId); // capability_denied <audit record id>
}

await ob.renew(coder); // keep the lease alive

await admin.revokeLease(root.lease, "session compromised"); // cascades to the coder
console.log(await admin.auditVerify()); // { ok: true, entries: ..., firstBadSeq: undefined }
```

## What is in it

| Call                                                                                                                                                | Does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new AttenuoClient(serverUrl, { token?, fetch?, headers?, timeoutMs?, dpopKey? })`                                                                  | HTTP client for the server. `token` is a default bearer; `fetch` swaps the transport (tests, proxies, custom TLS). Timeout defaults to 30 s.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `exchange(subjectToken, actor, capabilities, { ttlSeconds?, clientId?, clientSecret?, clientAssertion?, subjectTokenType?, actorToken?, mayAct? })` | RFC 8693 exchange. Returns a `Token`. Every hop n+1 exchange authenticates as its actor: pass the actor's `[[agents]]` secret as `clientSecret` (`clientId` defaults to `actor`). With an IdP credential as the subject and both `clientId` and `clientSecret`, it is a hop-0 exchange (`subjectTokenType: "urn:ietf:params:oauth:token-type:id-jag"` for an ID-JAG). `actorToken` (a workload-identity JWT such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer) authenticates the actor instead of a secret, depending on `[token] actor_auth`; each one works for one exchange. `clientAssertion` is a `private_key_jwt` assertion (RFC 7523) for an agent whose `[[agents]]` entry lists public keys (`jwks`), made with `(await DpopKey.fromJwk(jwk)).clientAssertion(agentId, serverIssuer)` from the key `attenuo key gen --client` wrote; it replaces `clientSecret` (never both) and works for one request (the nonce retry and the `maxRetries` retry send it again; see [Load refusals](#load-refusals)). `mayAct` lists the agents allowed to exchange the new token next. |
| `renew(token?)`                                                                                                                                     | `POST /token/renew`. Returns `{ lease, expiresAt, expiresIn }`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `callTool(token, server, tool, args?, { sessionId? })`                                                                                              | `tools/call` through `/mcp/{server}`. Returns `{ text, content, isError, decisionId, structuredContent, raw }`. Throws `DeniedError` when refused.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `callToolWithApproval(token, server, tool, args?, { onApproval?, timeoutMs?, intervalMs?, sessionId? })`                                            | `callTool`; when the call needs an approval (`-32008`), calls `onApproval(err)`, waits for the grant, and retries the call once, with the grant's `approvalToken` when it has one. `callTool(..., { approvalToken })` sends a token yourself. See [Approvals](#approvals).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `getApproval(approvalId, token?)`, `waitForApproval(approvalId, token?, { timeoutMs?, intervalMs? })`                                               | `GET /approvals/{id}` as the agent (same run, DPoP signed when the client has a key); `waitForApproval` polls until granted and throws `ApprovalNotGrantedError` otherwise.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `grantApproval(approvalId, idToken)`, `declineApproval(approvalId, idToken)`                                                                        | `POST /approvals/{id}` as the run's originating user, with their OIDC ID token as a plain bearer. Resolves to the decided `Approval`. See [Approvals](#approvals).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `listTools(token, server)`                                                                                                                          | `tools/list`, filtered by the proxy to what the token may call.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `initialize(token, server)`                                                                                                                         | MCP `initialize`; returns the `Mcp-Session-Id`, if any.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `closeSession(token, server, sessionId)`                                                                                                            | `DELETE /mcp/{server}`: ends the MCP session. `true` when the upstream closed it, `false` when it does not let clients close sessions (405).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `authzenEvaluate(token, server, tool, args?)`                                                                                                       | AuthZEN decision without calling the tool. A deny is `{ decision: false, reason, decisionId, ... }`, not an exception; on `approval_required` it also has `callHash`, `approvalId` and `expiresAt` (see [Approvals](#approvals)).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `authzenEvaluateBatch(token, evaluations, { semantic? })`, `authzenConfiguration()`                                                                 | `POST /access/v1/evaluations`: several decisions in one request, one `AuthzenDecision` per call; and the AuthZEN discovery document. See [AuthZEN batches and discovery](#authzen-batches-and-discovery).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `authzenSearchAction(token, server, args?, { pageToken?, limit? })`, `authzenSearchActionIter(token, server, args?, { limit? })`                    | `POST /access/v1/search/action`: the catalogued tools of `server` that an evaluation with these arguments would allow now, one `AuthzenActionPage` per page, or every `AuthzenAction` across pages. Nothing is audited or charged. See [AuthZEN action search](#authzen-action-search).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `jwks()`                                                                                                                                            | `GET /.well-known/jwks.json`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `inspect(jwt, { verify?, jwksUrl?, issuer?, audience? })`                                                                                           | Decode a token. With `verify: true` fetch the JWKS and check the Ed25519 signature, `typ`, `exp` and that `sub`/`act` match the chain.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `new AdminClient(serverUrl, adminToken, opts?)`                                                                                                     | `revokeLease`, `revokeBySelector` (every lease of one user, chain or MCP session; see [below](#admin-revoking-by-user-chain-or-session)), `refundBudget` (see [below](#admin-refunding-a-budget-charge)), `leaseStatus`, `audit`, `auditHead` (reads `head` from `GET /admin/audit`, signs nothing), `auditTail`, `auditExport` (async iterator of JSON Lines objects; optional `{ kind, chainId, tool, decision }` filter), `auditCheckpoint` (explicit; signs and stores a checkpoint), `auditVerify`, `policyReload`, `mintRootDev`, the approval calls (`approvals`, `approval`, `grantApproval`, `declineApproval`); and the read-only console helpers below (`auditQuery`, `auditIter`, `auditEntry`, `auditRecord`, `auditCheckpoints`, `leaseTree`, `policies`, `policyCheck`, `policyEvaluate`, `whoami`).                                                                                                                                                                                                                                                                          |

Wherever a token is expected you can pass a `Token` or its JWT string; leave it out to use the client's default `token`.

A `Token` carries `lease`, `expiresAt`, `chain` (user and hops with capabilities), `agents`, `agent`, `subject`, and `verified`. The JWT is available as `token.jwt` and `String(token)`, but it is not an enumerable property, so `console.log(token)` and `JSON.stringify(token)` do not print it. Everything decoded from a token is untrusted unless `verified` is true.

`AdminClient` talks to the admin API (`/admin/*`). A server with `[admin] listen` serves it on that address only, so give `AdminClient` that listener's URL, not the main one ([network exposure](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/deploying.md#network-exposure)).

### Admin: querying the audit log, lease trees, policies

These wrap the read-only operator routes the admin console uses. None of them signs, changes or audits anything.

```ts
const admin = new AdminClient(SERVER, process.env.ATTENUO_ADMIN_TOKEN!);

// Newest denials first. A filtered page can come back short (even empty) with nextCursor
// still set, so iterate rather than reading one page: auditIter follows the cursor to the end.
for await (const e of admin.auditIter({ order: "desc", decision: "deny", agent: "coder" })) {
  console.log(e.seq, e.record.reason, e.record.tool);
}
const page = await admin.auditQuery({ kind: ["lease_renew"], lease: leaseId, limit: 50 });

const detail = await admin.auditRecord(denied.decisionId); // or admin.auditEntry(seq)
console.log(detail.leaseStates, detail.coveredByCheckpoint, detail.policyReloadedAfter);

await admin.auditCheckpoints({ limit: 20 }); // stored checkpoints, newest first; never signs
for await (const a of admin.approvalsIter({ state: "pending" })) console.log(a.approvalId);
const tree = await admin.leaseTree(leaseId); // what a revoke would reach

await admin.policies(); // the loaded set: path, sha256, loadedAt, { id: text }
await admin.policyCheck(); // lint the file on disk now; ok means a reload would succeed
const ev = await admin.policyEvaluate("github", "read_file", { repo: "alice/x" }, { token: coder });
console.log(ev.decision, ev.reason, ev.policyIds); // no lease check, no audit record
```

| Call                                                                                            | Route                                                         | Returns                                                                                                           |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `auditQuery(query?)`                                                                            | `GET /admin/audit`                                            | `{ entries, nextCursor, head }`                                                                                   |
| `auditIter(query?)` (`limit` defaults to 1000)                                                  | `GET /admin/audit`, repeated                                  | async iterator of `AuditEntry`, following `nextCursor` until undefined                                            |
| `auditEntry(seq)`, `auditRecord(id)`                                                            | `GET /admin/audit/entries/{seq}`, `/admin/audit/records/{id}` | `{ entry, leaseStates, coveredByCheckpoint, policyReloadedAfter }`                                                |
| `auditCheckpoints({ cursor?, limit? })`, `auditCheckpointsIter({ limit? })`                     | `GET /admin/audit/checkpoints`                                | `{ checkpoints, nextCursor }`; the iterator yields every checkpoint, newest first                                 |
| `leaseTree(leaseId, maxNodes?)`                                                                 | `GET /admin/leases/{id}/tree`                                 | `{ root, ancestors, nodes, wouldRevoke, truncated, userWindows }`                                                 |
| `whoami()`                                                                                      | `GET /admin/whoami`                                           | `{ name, role }`: the operator the admin token belongs to (`admin` for the server's `[admin] token`) and its role |
| `policies()`                                                                                    | `GET /admin/policies`                                         | `{ path, sha256, loadedAt, policyIds, warnings, policies }`                                                       |
| `policyCheck()`                                                                                 | `GET /admin/policies/check`                                   | `{ ok, issues, differsFromLoaded, ... }`                                                                          |
| `policyEvaluate(server, tool, args?, { token?, chain?, budget?, session?, approval?, usage? })` | `POST /admin/policies/evaluate`                               | `{ decision, allowed, reason, policyIds, ..., tokenExpired, budget, limit, labels, usage, approvalBy }`           |
| `approvals({ chainId?, state?, limit?, cursor? })`                                              | `GET /admin/approvals`                                        | `{ approvals, nextCursor }`, newest first (server default page 100, at most 500)                                  |
| `approvalsIter({ chainId?, state?, limit? })`                                                   | `GET /admin/approvals`, repeated                              | async iterator of every matching `Approval`, following `nextCursor`                                               |
| `approval(approvalId)`                                                                          | `GET /admin/approvals/{id}`                                   | `Approval`                                                                                                        |
| `grantApproval(approvalId)`, `declineApproval(approvalId)`                                      | `POST /admin/approvals/{id}`                                  | `Approval` after the decision (`by = \"operator\"`); `ApiError` 409 when it is no longer pending                  |

`AuditQuery` takes `order` (`"asc"` or `"desc"`), a `seq` range `from` / `to`, `limit`, `cursor` (a page's `nextCursor`, sent with the same query), and exact-match filters combined with AND: `kind` (one or an array), `decision` (a `Decision`, `"allow" | "deny"`), `reason`, `subject`, `agent`, `lease`, `server`, `tool`, `chainId`, and `since` / `until` (RFC 3339 strings or `Date`s). Errors map as everywhere else: a 404 for an unknown seq, record or lease is an `ApiError` with `status: 404`, a bad filter is a 400 `invalid_request`, a bad cursor a 400 `invalid_cursor`.

Every list pages with an opaque cursor ([Paging](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#paging)): pass a page's `nextCursor` back as `cursor` with the same filters, or use the `*Iter` methods, which do that and throw `AttenuoError` if the server ever repeats a cursor. `audit(fromSeq, limit, cursor?)` returns `{ entries, nextCursor, head }`. A `limit` above the route's maximum is the server's 400, not clamped.

`auditExport(fromSeq?, toSeq?, filter?)` takes an `AuditExportFilter` with the same four filters as `GET /admin/audit/export`: `kind`, `chainId`, `tool` and `decision` (`"allow"` or `"deny"`), combined with AND. The header of a filtered export has a `filter` member naming them, and [`verifyExport`](#verifying-an-audit-export-offline) refuses it.

```ts
for await (const line of admin.auditExport(1, undefined, {
  tool: "token.exchange",
  decision: "deny",
}))
  console.log(line);
```

### Admin: a dry run with a stated budget

`policyEvaluate` reads the run's limit counters from the store unless you state them. `opts.budget` takes a `StatedBudget` in the vocabulary of a `policy test` case's `budget`: `callsRemaining`, `amountRemaining`, `destinationNew`, `limited`, and `limits`, single counters as `BudgetLimit` (`{ hop, kind, used, arg?, max? }`). Members left out are not sent. The server checks the counters with the same code a live call goes through, never touches the store and writes no audit record; a malformed block is its 400 `invalid_request`, thrown as `ApiError`.

```ts
// The coder's token carries a `distinct` limit of one `repo` at hop 1. Is a second repo refused?
const ev = await admin.policyEvaluate(
  "github",
  "read_file",
  { repo: "alice/other" },
  { token: coder, budget: { limits: [{ hop: 1, kind: "distinct", arg: "repo", used: 1 }] } },
);
console.log(ev.reason); // "budget_exhausted"
console.log(ev.limit); // { hop: 1, kind: "distinct", arg: "repo", used: 1, max: 1 }
console.log(ev.budget?.source); // "request"; "store" when no budget was stated
```

The answer's `budget` is an `EvaluationBudget` (`{ limited, callsRemaining, amountRemaining, destinationNew, source }`), where a remaining figure is `Infinity` when no limit of that kind matches (the server's `2^63 - 1` does not fit a JavaScript number). `limit` is set only on `budget_exhausted` and has the `BudgetLimit` shape, so it can be stated back as it came. `labels` (the run's output labels), `usage` (`context.usage`) and `approvalBy` complete the picture the policy saw.

The other inputs the policy sees can be stated the same way, each instead of what the store holds for the run:

- `opts.session: StatedSession` (`{ taintedBy?, tainted?, untrustedArgs?, argsContainUntrusted? }`): the run's output labels. `tainted` defaults on the server to whether `taintedBy` names a source, `argsContainUntrusted` to whether `untrustedArgs` names an argument. The answer's `labels.source` is then `"request"`.
- `opts.approval: StatedApproval` (`{ by: "user" | "operator" | "policy" }`, the `ApprovalBy` type): evaluate the call as a retry that carries a granted approval. The dry run never looks up or consumes a stored approval, so there is no id or token to pass. The answer's `approvalBy` is then `by`.
- `opts.usage: StatedUsage` (`{ calls?, amount?, destinationSeen? }`): `context.usage` (the server takes a member left out as 0 or `false`). The answer's `usage.source` is then `"request"`. With a stated `budget` and no `usage`, the usage is zero and also reported as `"request"`.

Members left out (and empty lists) are not sent. Nothing is checked in the SDK beyond the types: a negative figure is the server's 400 `invalid_request`, thrown as `ApiError`.

```ts
// Would a create_issue ask for approval once the run has read a web page, and pass with one?
const session = { taintedBy: ["web/fetch"] };
const asked = await admin.policyEvaluate("github", "create_issue", issue, { token: root, session });
console.log(asked.reason, asked.labels?.source); // approval_required request (with a taint rule loaded)
const ok = await admin.policyEvaluate("github", "create_issue", issue, {
  token: root,
  session,
  approval: { by: "user" },
});
console.log(ok.decision, ok.approvalBy); // allow user
```

### Admin: revoking by user, chain or session

`revokeBySelector` wraps `POST /admin/leases/revoke`: it revokes every unrevoked lease of one originating user, one delegation chain or the chain that opened one MCP session, each with its descendants, in one transaction. The `LeaseSelector` type takes exactly one of `user`, `chainId`, `session`; the call checks it again at run time and throws a `TypeError` before sending anything otherwise.

```ts
await admin.revokeBySelector({ user: "alice@example.com" }, { reason: "laptop stolen" });
await admin.revokeBySelector({ chainId: root.lease }, { preview: true }); // dry run
const r = await admin.revokeBySelector({ session: sessionId }, { reason: "session hijacked" });
console.log(r.selector); // { session_tag: "<12 hex>", chain_ids: [...] }, never the raw id
console.log(r.matchedCount, r.revokedCount, r.auditId);
```

| Selector  | Matches                                                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `user`    | every lease the server recorded for that originating `sub`, under any issuer                                                   |
| `chainId` | that chain's first-hop lease and everything delegated from it (a lease with a parent matches nothing)                          |
| `session` | the raw `Mcp-Session-Id`; the server hashes it and revokes, as `chainId`, each chain that opened the session through the proxy |

It resolves to a `SelectorRevocation`: `selector` (as the server shows it, with its snake_case keys), `preview`, `matched`, `revoked` (matches first, then the cascade; each list cut at 10,000 ids, `truncated` says so), `matchedCount`, `revokedCount`, `reason` and `auditId`. With `preview: true` nothing changes and no audit record is written; `revoked` is what a revocation sent now would change, and `reason` and `auditId` are `undefined`. Matching nothing is not an error: the lists come back empty, also for a session the server never recorded. The SDK never logs the session id and no error it throws contains it. `revokeLease(leaseId)` still revokes one lease by id; its `RevokeResult` carries the `auditId` of the `admin.lease.revoke` record (`undefined` when the server could not write it). See [Revoke by user or chain](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#revoke-by-user-or-chain) for the server side.

### Admin: refunding a budget charge

An allowed call is charged to its run's limits before it goes upstream. When its effect did not happen (the upstream failed, or a person undid it), an operator can give the charge back, once, by the decision's id:

```ts
import { AdminClient, ApiError } from "@attenuo/sdk";

const admin = new AdminClient(SERVER, process.env.ATTENUO_ADMIN_TOKEN!);
try {
  const r = await admin.refundBudget(result.decisionId!, "upstream returned 502");
  console.log(r.refunded, r.auditId); // counters credited; the admin.budget.refund record
} catch (e) {
  if (e instanceof ApiError)
    console.log(e.status, e.error, e.detail); // 409, 410 or 404
  else throw e;
}
```

`refundBudget(decisionId, reason?)` sends `POST /admin/budgets/refund` and resolves to `{ decisionId, refunded, reason, auditId }` (`BudgetRefund`). `refunded` counts the run-limit counters credited; the run usage and per-user windows the decision charged are given back as well but not counted, so it can be 0. A refusal (409 `already_refunded`, 410 `charge_pruned`, 404 `not_found`) writes no audit record, so its `ApiError` has no `decisionId`; `detail` says why, from the decision's audit record ([HTTP API](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#budget-refund)).

### Capabilities

```ts
import { capability, equals, oneOf, pathPrefix, prefix, range } from "@attenuo/sdk";

capability("github", "read_file"); // github:read_file
capability("github", "create_issue", { repo: oneOf("acme/api", "acme/web") });
capability("github", "read_*", { repo: prefix("alice/public-"), ref: equals("main") });
capability("fs", "read_file", { path: pathPrefix("/workspace") }); // /workspace and below, no ..
capability("banking", "send_money", { amount: range({ min: 0, max: 2000 }) }); // 0 <= amount <= 2000
capability("banking", "refund", { amount: range({ max: 50 }) }); // no lower bound
capability("github", "list_issues", { state: "open" }); // a bare value means equals
```

Capabilities serialize as the server expects: `{ server, tool, constraints: { repo: { op: "prefix", value: "..." } } }`, with `constraints` omitted when empty. `exchange` and `mintRootDev` also take `"server:tool"` strings (comma-separated lists too, like the CLI's `--cap`) and raw objects.

`range({ min, max })` bounds an integer argument, both ends inclusive; leave one out for no bound on that side, but not both. It throws a `TypeError` for no bound, `min > max` or a bound that is not a safe integer. The server reads the argument as Cedar does (`5.0` is `5`), and a fraction or a numeric string is outside every range. A child may narrow a range (`range({ min: 10, max: 500 })` under `range({ min: 0, max: 2000 })`, or `oneOf(100, 200)`), never widen it. A range bounds each call; to bound the total over a run as well, add a `sum` limit (below).

`pathPrefix(path)` is for file paths. It compares by `/` segment, so `pathPrefix("/workspace")` admits `/workspace/a.txt` but not `/workspace-secrets/x`, and the server refuses a value with a `.` or `..` segment, `//`, a backslash, a control character, a percent-encoded `.`, `/` or `\`, a double-encoded escape (`%252e`) or a character that normalises to `.`, `/` or `\` (such as `．` or `／`) instead of normalising it, so `/workspace/../etc/passwd` is denied. `prefix("/workspace/")` admits that value: it is a plain string comparison, for URL or id prefixes. A trailing `/` on `path` asks for something below it (`pathPrefix("/workspace/")` does not admit `/workspace` itself). It throws a `TypeError` for a path the server would refuse; `pathProblem(path)` says why. A child may narrow a `pathPrefix` to a deeper one or to values under it, or narrow a `prefix` to a `pathPrefix` whose path starts with the prefix; never the other way round.

#### Run limits on a child token

A capability can carry run limits ([ADR-0010](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0010-run-limits.md)): how many calls, how much in total, how many calls per value and how many different values. Set them with `withLimits` before you exchange:

```ts
import { argLimit, capability, withLimits } from "@attenuo/sdk";

const helper = await ob.exchange(planner, "helper", [
  // At most one payment, 40 in total, to Emma only.
  withLimits(capability("banking", "send_money", { recipient: "FR00EMMA" }), {
    calls: 1,
    sum: argLimit("amount", 40),
    calls_per: argLimit("recipient", 1),
  }),
  // Pages from at most two sites: `derive: "host"` counts the host of the URL.
  withLimits(capability("web", "get_webpage"), {
    distinct: argLimit("url", 2, { derive: "host" }),
  }),
]);
```

The `Limits` and `ArgLimit` types say what each kind takes. The server lowers a figure larger than the parent's, fills in a limit the child leaves out, and charges every call to every hop, so a child can spend at most what its parent has left. A call over a limit is a `DeniedError` with `reason: "budget_exhausted"`; one whose argument a limit cannot count (a missing recipient, a URL without a host) is `limit_arg_invalid`. A kind or derivation the SDK does not know throws a `TypeError` instead of being dropped.

### Workload identity and `mayAct`

An agent can authenticate with a workload-identity JWT instead of a client secret: an RFC 8693 `actor_token` from an `[[actor_trust]]` issuer, such as a SPIFFE JWT-SVID. It works at hop 0 (with the user's ID token or ID-JAG as the subject token) and on every exchange. Each actor token authenticates one request, and the token it obtains never outlives it.

```ts
const svid = await readFile("/run/spire/svid.jwt", "utf8"); // aud = the server
const root = await ob.exchange(idToken, "planner", ["github:*"], { actorToken: svid });
```

`mayAct` limits who may exchange a token next (RFC 8693 §4.4). Pass it when exchanging, or when minting a dev root:

```ts
await ob.exchange(root, "coder", ["github:read_file"], { clientSecret, mayAct: ["reviewer"] });
await admin.mintRootDev("alice", "https://idp.example", "planner", { mayAct: ["coder"] });
```

`mayAct` is a list of agent ids (a bare string is a `TypeError`); `[]` means nobody may exchange the token. For a root it must be within the `[[root_grants]]` entry's `may_act` when that has one.

### Binding tokens to keys (DPoP)

A token can be bound to a key the agent holds (RFC 9449), so a leaked copy is useless without the key. Give the client a `dpopKey`: a `DpopKey` or a private JWK object, such as the file `attenuo key gen --dpop` writes. Proofs are signed with WebCrypto (Ed25519 or P-256); there is no extra dependency.

```ts
import { DpopKey, AttenuoClient } from "@attenuo/sdk";

const coderKey = await DpopKey.fromJwk(JSON.parse(await readFile("coder.jwk", "utf8")));
// or: await DpopKey.generate(), and keep key.privateJwk() to reuse it

// In the planner's process: consent to delegating `root` to the coder's key and agent id.
const signOff = await plannerKey.signOff(`${SERVER}/token`, root.jwt, coderKey.thumbprint, "coder");

// In the coder's process: the new token is bound to coderKey.
const ob = new AttenuoClient(SERVER, { dpopKey: coderKey });
const coder = await ob.exchange(root, "coder", "github:read_file", {
  clientSecret,
  subjectTokenDpop: signOff,
});
await ob.callTool(coder, "github", "read_file", { repo: "alice/docs" }); // proof attached
```

With a key, every `callTool`, `listTools`, `initialize`, `closeSession`, `renew`, `authzenEvaluate`, `authzenEvaluateBatch` and `authzenSearchAction` sends `Authorization: DPoP <token>` and a fresh proof, and every `exchange` binds the new token. When the parent is bound to another key, its holder's sign-off names the new key and agent and works for that one exchange; a process that holds both keys can pass `subjectDpopKey: plannerKey` instead. When the parent is bound to the client's own key, no sign-off is needed. `Token.dpopJkt` is the thumbprint a token is bound to (undefined for a bearer token), and `AuditEntry.dpopBound` says whether a decision was made with a proven bound token. A bound token without a proof is an `UnauthorizedError` with `reason === "dpop_required"`, from `callTool` as from `renew` or `exchange` (see [Errors](#errors)). See [Binding tokens to keys](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/binding-tokens-to-keys.md).

Server nonces (RFC 9449 §8, `[token] dpop_nonce = "required"`) need no code. `AttenuoClient`, `AdminClient.mintRootDev` and `mcpFetch` keep the latest `DPoP-Nonce` header the server sent and put it in each proof. When the server refuses a proof with `use_dpop_nonce`, they retry the request once with a new proof carrying the nonce from that response (`mcpFetch` does not retry a request whose body is a stream). The server can close the connection that carried the refusal without saying so (it does when it answers before reading the request body), and `fetch` may put the retry on it; when the retry fails that way (a `TypeError`, which the client wraps in a `TransportError`), it is sent once more with the same headers. The proof is the same, so if the server did get the first copy it refuses the second as a replayed `jti`; an abort is not resent. For your own HTTP code, `key.proof(method, url, token, { nonce })` adds the claim, and `NonceCache` does the bookkeeping: `await cache.update(response)` stores the nonce and resolves to true when the request should be retried.

### Keeping a token alive

`TokenRefresher` renews the lease at a third of the lease interval, calls your `exchange` function before the token's `exp`, and keeps the current token in `refresher.token`. `start()` returns a disposer.

```ts
import { mcpFetch, RefreshError, TokenRefresher } from "@attenuo/sdk";

// Each exchange needs a fresh subject token: a parent delegates to a given actor once, so
// re-exchanging the same parent is refused as `replayed`.
const exchange = async () =>
  ob.exchange(await planner.freshRoot(), "coder", "github:read_file", { clientSecret });

const refresher = new TokenRefresher({
  client: ob,
  token: await exchange(),
  exchange,
  onError: (e: RefreshError) => console.error("stopping:", e.reason), // lease_revoked, ...
});
const dispose = refresher.start();

// A per-request token hook for the MCP transport: it always sends the current token.
const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(SERVER, "github")), {
  fetch: refresher.fetch({ dpopKey: coderKey }), // = mcpFetch(refresher.provider, { dpopKey })
});

await dispose(); // stop the loop
```

- **Schedule.** `leaseInterval` (seconds) is the server's `[issuer] lease_interval_seconds`; left out, it is learned from the first renewal, which then happens right away. The token is re-exchanged `margin` seconds before `exp` (default 20% of its lifetime, at least 5 s, at most half the lifetime). `onChange(token)` is called with each replacement.
- **Failures.** Network errors, 5xx, 408 and 429 are retried with jittered exponential backoff (1 s doubling to 30 s). It stops, calls `onError` once and sets `refresher.error` when the lease is revoked (`RefreshError.reason === "lease_revoked"`, or `lease_lost` when an ancestor lapsed), the server refuses an exchange for good (`refused`: `invalid_scope`, `replayed`, a bad secret), or the token reaches `exp` (`token_expired`). It never loops on a revoked lease. `refresher.provider()` throws the `RefreshError` once it has given up.
- **DPoP.** Renewals go through your client and are signed with its `dpopKey`. A replacement must be bound to the same key as the current token; otherwise it is not adopted and the refresher stops with `key_mismatch`.
- **Logging.** Nothing is logged, and no error message contains a token.
- **Testing.** `tick()` runs whatever is due and returns the milliseconds to wait; `start()` is a loop around it, and `now` and `random` options replace the clock and the jitter.

### Approvals

A policy can hold a call until a person approves it (`@obligation("approval")`, see [Writing policies](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/writing-policies.md)). The proxy then answers JSON-RPC `-32008`, which the SDK throws as `ApprovalRequiredError`, a `DeniedError` with `reason === "approval_required"` plus `approvalId`, `expiresAt` and `callHash`. The user grants it with their own sign-in (`POST /approvals/{id}`), or an operator does with `attenuo approval grant` or `AdminClient.grantApproval(id)`. The agent's own token can read the approval but never decide it. The grant is good for one retry of the identical call (same server, tool and arguments) by the same hop, until `expiresAt`.

```ts
import { ApprovalNotGrantedError } from "@attenuo/sdk";

try {
  const r = await ob.callToolWithApproval(
    token,
    "github",
    "delete_repo",
    { repo: "alice/site" },
    {
      onApproval: (e) => console.log(`Approval needed: ${e.approvalId} (expires ${e.expiresAt})`),
    },
  );
  console.log(r.text);
} catch (e) {
  if (e instanceof ApprovalNotGrantedError) console.log("not approved:", e.state);
  else throw e;
}
```

`approvalId` is undefined when the server could not open an approval; treat that as a plain denial. One case is a run that already holds 32 pending approvals (SR-92): the server keeps no more for one run, so the next gated call is answered `-32008` without an `approval_id`, `callToolWithApproval` throws it at once without calling `onApproval`, and a PEP that gets AuthZEN diagnostics sees `"too many pending approvals for this run"`. Deciding one of the run's approvals, or letting it lapse, makes room. `authzenEvaluate` says the same: on `approval_required` its answer carries `callHash`, and `approvalId` and `expiresAt` when an approval was opened. A route that would have to open an approval past the cap answers HTTP 429 `too_many_pending_approvals`, thrown as `ApiError`. Like `-32003`, a `-32008` counts only when the `X-Attenuo-Decision-Id` header names its `data.decision_id`; otherwise it is an upstream's own `RpcError`.

A granted `Approval` carries `approvalToken`, a JWT signed with the server's issuer key (`typ: attenuo-approval+jwt`) and bound to the run, the hop's lease, the call hash and, for a DPoP-bound agent, its key. `callToolWithApproval` retries with it in `params._meta["dev.attenuo/approval"]`; a token the server refuses is a `DeniedError` with reason `approval_invalid`. An external enforcement point can check a token offline against the JWKS:

```ts
import { callHash, verifyApprovalToken } from "@attenuo/sdk";

const claims = await verifyApprovalToken(tokenFromAgent, await ob.jwks(), {
  chainId: runId,
  lease: hopLease,
  callHash: await callHash("github", "delete_repo", { repo: "alice/site" }),
  jkt: null, // the hop's cnf.jkt, or null for a bearer hop
});
console.log(claims.approvalId, claims.by, claims.expiresAt);
```

It throws `VerificationError` on a bad signature, `typ`, expiry or binding. It proves the grant was made; only the server knows whether it has been used.

The user decides with their own sign-in. A front end that holds the user's OIDC ID token (from the same `[[idps]]` issuer and client id the run started with) calls:

```ts
const approval = await ob.grantApproval(approvalId, userIdToken); // or declineApproval
console.log(approval.state, approval.approver); // granted, { subject, method: "id_token", by: "user" }
```

The ID token goes as `Authorization: Bearer`, never with DPoP and never the client's own token: the server refuses a delegation token there (403 `agent_token_refused`), another user's token (403 `wrong_user`) and an ID token used before (400 `invalid_grant`, `description === "replayed"`); a decided or expired approval is 409. Each is an `ApiError` (`UnauthorizedError` for a 401, such as an expired ID token).

### AuthZEN batches and discovery

`authzenEvaluateBatch` sends several calls in one `POST /access/v1/evaluations`. Each is decided, charged and audited like `authzenEvaluate`, and the answer has one `AuthzenDecision` per call, in order:

```ts
const decisions = await ob.authzenEvaluateBatch(
  token,
  [
    { server: "github", tool: "read_file", args: { repo: "alice/docs" } },
    ["github", "create_issue", { repo: "alice/docs" }], // a tuple works too
  ],
  { semantic: "deny_on_first_deny" },
);
for (const d of decisions) console.log(d.decision, d.reason, d.decisionId, d.error);
```

`semantic` is AuthZEN's `evaluations_semantic`: `execute_all` (the default), `deny_on_first_deny` or `permit_on_first_permit`. A batch that stops early answers only the calls it decided, so the array can be shorter than the request. A call the server could not decide is a deny with `error: { status, code, message }`. An empty batch throws `TypeError` before anything is sent (the server would answer it as a single evaluation), and more calls than `[authzen] max_batch` (default 64) is `ApiError` 400 `batch_too_large`.

`authzenConfiguration()` reads `GET /.well-known/authzen-configuration` without a credential and resolves to `{ policyDecisionPoint, accessEvaluationEndpoint, accessEvaluationsEndpoint, searchActionEndpoint, raw }`; `searchActionEndpoint` is `""` when the server does not publish action search.

### AuthZEN action search

`authzenSearchAction` asks which tools of one MCP server the token may call with these arguments (`POST /access/v1/search/action`, AuthZEN section 8.6). The candidates are the tools the server's `[policy] catalog` lists for `server` that the token's capabilities name, and a result is one an evaluation with the same token and arguments would allow now. A search is not a decision: it writes no audit record, charges no run limit and takes no approval, so an approval-gated tool is never a result. Calling the tool, or `authzenEvaluate`, still decides it.

```ts
const args = { repo: "alice/docs" };
let page = await ob.authzenSearchAction(token, "github", args, { limit: 16 });
for (const a of page.actions) console.log(a.server, a.name);
if (page.nextToken !== undefined) {
  page = await ob.authzenSearchAction(token, "github", args, { pageToken: page.nextToken });
}

// Or every result, following the pages:
for await (const a of ob.authzenSearchActionIter(token, "github", args)) console.log(a.name);
```

`limit` is how many catalogued tools one page evaluates; the server clamps it to `[authzen] max_batch` (default 64). So a page can hold fewer results than `limit`, even none, while `nextToken` is set; `nextToken` is undefined after the last page. Send it back as `pageToken` with the same `token`, `server` and arguments (`limit` may change): the server binds a page token to the chain, server and arguments it was issued for. `server` names the MCP server, not one tool: `"github/read_file"` is `ApiError` 400 `invalid_search_resource`, and a token the server did not issue, or one sent with another token, server or arguments, is 400 `invalid_cursor`. Authentication, DPoP proofs (for the search URL), retries and errors are as for `authzenEvaluate`.

### Streaming a call

A long tool can stream its answer: the upstream sends progress notifications on an SSE stream before the result. `callTool` waits for the whole body. `callToolStream` (same arguments; options add `maxEventBytes`, `signal` and `deadlineMs`) returns an `AsyncIterable` that yields each JSON-RPC message as it arrives:

```ts
import { DeniedError } from "@attenuo/sdk";

try {
  for await (const event of ob.callToolStream(coder, "github", "read_file", {
    repo: "alice/docs",
  })) {
    if (event.result)
      console.log(event.result.text, event.result.decisionId); // the last event
    else if (event.method === "notifications/progress")
      console.log("progress:", event.message.params);
  }
} catch (e) {
  if (e instanceof DeniedError) console.log("denied or cut:", e.reason, e.decisionId);
  else throw e;
}
```

- **Events.** Each `StreamEvent` has `message` (the JSON-RPC message as sent), `method` (for a notification or a server request, else `undefined`), `lastEventId` (the SSE id at that point, what a client would send as `Last-Event-ID` to resume) and `decisionId` (the proxy's `X-Attenuo-Decision-Id`). The final event carries `result`, the same `ToolResult` that `callTool` returns, and `isFinal` is true. Nothing is yielded after it.
- **Errors.** A denial throws `DeniedError` (or `ApprovalRequiredError`) before anything is yielded, as `callTool` does. When the proxy cuts a stream because the lease was revoked or expired, or the token expired (it re-checks every `[proxy] stream_recheck_seconds`, default 2), its last event is a JSON-RPC `-32001` error with `id: null`. That throws `DeniedError` with `reason` (`lease_revoked`, `lease_expired`, `lease_unknown`, `token_expired`, ...) and `decisionId`, the id of the proxy's `stream.end` audit record. So code that catches `DeniedError` around `callTool` also handles a revocation in the middle of a stream. The `X-Attenuo-Decision-Id` header is sent before the cut, so it cannot vouch for this id as it does for a `-32003`. A `-32001` with `id: null` counts as a cut only when `data.reason` is one the proxy sends and `data.decision_id` is absent or a UUID; anything else of that shape throws `RpcError` with code `-32001`, a belt-and-braces check, since the proxy itself rewrites any upstream message of that shape to `-32005` (`upstream_stream_end_shape`). Any other JSON-RPC error throws what `callTool` throws. A stream that ends without the response throws `AttenuoError`.
- **Plain answers.** When the proxy answers with a JSON body instead of SSE (most upstreams do), you get one final event.
- **Limits.** An SSE event, or a plain body, over `maxEventBytes` throws `AttenuoError`. The default is 16 MiB (`DEFAULT_MAX_EVENT_BYTES`), the same as the proxy's `[proxy] max_upstream_body_bytes` default. The client's `timeoutMs` restarts on every read, so it bounds silence, not the length of the stream; `signal` aborts the call. Pass `deadlineMs` to bound the whole call, keep-alive comments included: on expiry the request is aborted and the stream throws `TransportTimeoutError` naming the deadline; a stream silent for longer than `timeoutMs` throws one too. Leaving the loop early (`break`, a throw) cancels the body and closes the connection. The request goes out when iteration starts.
- **Wire.** It sends the same `POST` as `callTool`: `Accept: application/json, text/event-stream`, the session id, the approval token in `_meta`, and a DPoP proof (with one retry on `use_dpop_nonce`) when the client has a key. Only the response handling differs. SSE parsing follows the WHATWG rules: `data:` lines are joined, a blank line ends an event, and comments, `event:` and `retry:` are ignored. A final event with no blank line after it is dropped, as the proxy also drops it. Tested on Node 20 and 22.

### Errors

| Error                              | When                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DeniedError`                      | The proxy denied a call (JSON-RPC `-32003` with the `X-Attenuo-Decision-Id` header naming `data.decision_id`; an upstream's own `-32003` without that proof is an `RpcError`). Also thrown by `callToolStream` when the proxy cuts a stream for a lease or token reason. Branch on `reason` (`capability_denied`, `policy_deny`, `budget_exhausted`, `lease_revoked`, ...), log `decisionId`. `stableCode` is the same string as `reason`. `data` is the error's whole `data` object; `limit`, `usage` and `untrustedArgs` type what the server adds (below).                                                                     |
| `ApprovalRequiredError`            | A `DeniedError` for JSON-RPC `-32008`: a policy holds the call until it is approved. `approvalId`, `expiresAt`, `callHash`. See [Approvals](#approvals).                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `ApprovalNotGrantedError`          | Waiting for an approval ended without a grant. `state`: `declined`, `expired`, `consumed` or `timeout`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `UnauthorizedError`                | HTTP 401 or JSON-RPC `-32001`: the bearer is missing, malformed, expired or not ours, a DPoP failure, or (from the proxy) a lease that is no longer live. A subclass of `ApiError`. Branch on `reason` (below); `decisionId` and `data` as for a denial.                                                                                                                                                                                                                                                                                                                                                                          |
| `UnavailableError`                 | HTTP 503 from the server itself (REST `temporarily_unavailable`, or the proxy's JSON-RPC `-32006`): `reason` (`overloaded`, `request_timeout`, `session_registry_full`, ...), `retryAfter`, `data`. A subclass of `ApiError`, not a denial. See [Load refusals](#load-refusals).                                                                                                                                                                                                                                                                                                                                                  |
| `RateLimitedError`                 | HTTP 429 (REST `rate_limited`, or the proxy's JSON-RPC `-32007`): `reason` (`rate_limited` or `too_many_sessions`), `retryAfter`, `data`. A subclass of `ApiError`, not a denial. See [Load refusals](#load-refusals).                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ApiError`                         | A non-success HTTP status. `status`, `code` (the server's stable code, such as `audience_mismatch`, `replayed` or `invalid_cursor`; every code is listed under [Errors](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#errors); branch on it, not on `detail`, which is text for people), `error` (the broader OAuth-style error, for example `invalid_scope`, or `request_timeout` for a 408), `description` (the deprecated `error_description`), `detail`, and `decisionId`, the audit record of a refused exchange or renewal. Every subclass has `code` too, and `stableCode`, the same string. |
| `ApiError` `redirect_not_followed` | The server URL answered a 3xx (in a browser, an opaque redirect with `status` 0). No client follows a redirect (`redirect: "manual"`, also passed to a `fetch` you give), since a `307` or `308` would send the body (a client secret or assertion, a subject token) again to wherever `Location` names (SR-112). The message names the request and the `Location` when it can be read: set the server URL to the final one. `mcpFetch` asks for manual redirects too and hands the 3xx to the MCP library as it is.                                                                                                              |
| `TransportError`                   | No answer: `fetch` failed (connection refused or dropped, DNS, TLS) or the client's `timeoutMs` ran out, while sending or while reading the body. `cause` is what `fetch` threw.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `TransportTimeoutError`            | A `TransportError` because one of the client's own timers ran out: `timeoutMs` (a whole request, or the silence between two reads of a stream) or a stream's `deadlineMs`. `cause` is the `TimeoutError` the request was aborted with.                                                                                                                                                                                                                                                                                                                                                                                            |
| `RpcError`                         | Any other JSON-RPC error (`code`, `stableCode`, `rpcMessage`, `data`). `code` is the JSON-RPC number (`-32004`, `-32005`, ...); `stableCode` is the server's stable code (below).                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `RefreshError`                     | A `TokenRefresher` gave up. `reason`: `lease_revoked`, `lease_lost`, `token_expired`, `refused`, `key_mismatch`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `VerificationError`                | `inspect(..., { verify: true })` failed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `AttenuoError`                     | Base class of all of these; also thrown for responses that are not what the server sends.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

**`UnauthorizedError.reason`** is the server's stable code, the same for `callTool` and the REST routes: `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce` (the client already retries this one once with the server's nonce), and from the proxy also `lease_revoked`, `lease_expired` and `lease_unknown`. A lease refusal of a request the proxy decides nothing for (`initialize`, `tools/list`, ...) is recorded in the audit log, and `decisionId` names the record. `error` keeps its old value: `"unauthorized"` for every proxy 401, and the REST body's `error` (`unauthorized`, `dpop_required`, ...) otherwise.

```ts
import { DeniedError, TransportError, UnauthorizedError } from "@attenuo/sdk";

try {
  await ob.callTool(token, "github", "read_file", { repo: "alice/docs" });
} catch (e) {
  if (e instanceof UnauthorizedError && ["lease_revoked", "lease_unknown"].includes(e.reason)) {
    stop(e.decisionId); // the run was revoked: do not retry
  } else if (e instanceof DeniedError && e.reason === "budget_exhausted" && e.limit) {
    console.log(`limit ${e.limit.kind} of hop ${e.limit.hop}: used ${e.limit.used}`);
  } else if (e instanceof TransportError) {
    console.log("server unreachable:", e.cause);
  }
  throw e;
}
```

**Branching on the stable code.** Every error the server answers with names a stable code, listed under [Errors](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#errors). On an `ApiError` (and its subclasses) it is `code`. On an `RpcError`, `code` is the JSON-RPC number, so the stable code is `stableCode`: the proxy's `data.code`, or `data.reason` for a server older than `code`, else undefined. `DeniedError` carries it as `stableCode` too (the same string as `reason`), and `ApiError.stableCode` is `code`, so `stableCode` reads the same on all three. An error the proxy relays from the upstream keeps the upstream's `data`, so its `stableCode` is what the upstream sent there, usually undefined.

```ts
import { ApiError, RpcError } from "@attenuo/sdk";

try {
  await ob.callTool(token, "github", "read_file", { repo: "alice/docs" });
} catch (e) {
  if (e instanceof ApiError && e.code === "token_expired") {
    token = await newToken(); // an UnauthorizedError; e.stableCode is the same string
  } else if (e instanceof RpcError && e.stableCode === "unknown_server") {
    throw new Error("no [[upstreams]] entry named github", { cause: e }); // e.code is -32004
  } else if (e instanceof RpcError && e.stableCode === "upstream_timeout") {
    report(e); // the upstream may have acted: do not resend blindly
  }
  throw e;
}
```

**What a denial carries.** `DeniedError.limit` is the run limit a `budget_exhausted` call would take past its `max`, as a `BudgetLimit` (the type of a dry run's `limit`, so it can be stated back to `policyEvaluate`); undefined otherwise. `usage` is set for a tool the catalog marks destructive or gives an `outbound` input: a `RunUsage` (`calls`, `amount`, `destinationSeen`, and `userWindow: { hour, day }` of `{ calls, amount }` when a policy reads per-user windows and a figure is not zero), the run's usage before this call as the policy saw it. `untrustedArgs` lists the arguments that copy an untrusted result of the run (`{ arg, kind, seq? }`), empty when the server sent none. `ApprovalRequiredError` carries the same three next to its approval fields. The shapes are in the [HTTP API reference](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md#mcp-proxy).

**Decision ids are proven.** A `decisionId` on `UnauthorizedError` or `ApiError` is taken from the body only when the `X-Attenuo-Decision-Id` header names it, as for `DeniedError`: the proxy never forwards that header from an upstream, so an upstream's answer cannot pass off an id.

**Transport failures.** Code that caught `fetch`'s `TypeError` from the client should catch `TransportError` and read `cause`. A timeout of the client's own (`timeoutMs`, a streamed call's idle timer or `deadlineMs`) is the subclass `TransportTimeoutError`, so a retry policy can tell a slow server from an unreachable one. An abort through a signal you passed (`callToolStream`'s `signal`) is thrown as it came, an `AbortError` or the reason you gave, and is never wrapped: a cancellation stays a cancellation. `mcpFetch` is a `fetch` for other libraries and keeps `fetch`'s errors.

An AuthZEN deny and a tool's own `isError` are results, not exceptions.

#### Load refusals

A server with [`[limits]`](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/config.md#limits) can refuse a request because it is busy or because the caller is over a rate limit. These are not authorization decisions: `UnavailableError` and `RateLimitedError` are `ApiError`s, never `DeniedError` or `UnauthorizedError`, so a check for a denial does not match them. Both carry `reason` (the server's code), `retryAfter` (the `Retry-After` header in whole seconds, as the header gives it; undefined when it is missing or not a number), `status` and, for a proxy answer, the JSON-RPC `data`.

| `reason`                                     | Error                                              | Ran on the server?                                                                                                                                           | Retried by `maxRetries` |
| -------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| `overloaded`                                 | `UnavailableError` (503)                           | No: refused before any decision, audit record or upstream call. Safe to retry after `retryAfter`.                                                            | Yes                     |
| `rate_limited`                               | `RateLimitedError` (429)                           | No: `POST /token` per agent or address, `/mcp/{server}` per run, refused before the work. Safe to retry after `retryAfter` (the end of the caller's minute). | Yes                     |
| `request_timeout`                            | `UnavailableError` (503)                           | Maybe: the handler may have issued a token or written a decision.                                                                                            | No                      |
| `too_many_sessions`, `session_registry_full` | `RateLimitedError` (429), `UnavailableError` (503) | The upstream answered `initialize`; the proxy then closed that session.                                                                                      | No                      |
| `jwks_unavailable`, `dpop_replay_cache_full` | `UnavailableError` (503)                           | No decision was made.                                                                                                                                        | No                      |

A body that does not arrive within `request_body_timeout_seconds` is a plain `ApiError` (408 `request_timeout`). On `/mcp/{server}`, a `-32006` or `-32007` counts as the proxy's own only when the answer carries `Retry-After`, which the proxy sets on its refusals and never relays from an upstream; an upstream's error of that shape stays an `RpcError`.

The client does not retry by default. `new AttenuoClient(url, { maxRetries: N })` retries `overloaded` and `rate_limited` up to `N` times (at most 10), waiting each answer's `Retry-After` (1 s without one), up to 20 % longer so that clients refused together do not come back together. A `Retry-After` over `maxRetryDelayMs` (default 10000, at most 300000) is not waited out: the error is thrown at once, so the retries of one call wait at most `maxRetries * maxRetryDelayMs` in all. Each retry is a new request with new DPoP proofs. `callToolStream` retries only before the stream starts, never past its `deadlineMs`, and its `signal` aborts the wait. When the retries run out, the last refusal is thrown. Nothing else is retried. `AdminClient` throws the same errors and does not retry.

An exchange with a `clientAssertion` sends the same assertion on each retry, as it does on the `use_dpop_nonce` retry: the server leaves an assertion unused when it answers `429 rate_limited`, `503 overloaded` or `use_dpop_nonce`. Treat it as spent after any other answer. The server refuses an expired assertion, so a retry whose wait would reach the assertion's `exp` is not made: the client throws the `RateLimitedError` (or `UnavailableError`) at once. Then mint a new assertion after `retryAfter` and call again, or mint the assertion with a `lifetime` that covers the waits, at most the server's `[token] client_assertion_max_lifetime_seconds` (300 by default; `clientAssertion()` makes 60 s ones).

```ts
import { AttenuoClient, DeniedError, RateLimitedError, UnavailableError } from "@attenuo/sdk";

const ob = new AttenuoClient("http://127.0.0.1:8080", { maxRetries: 3, maxRetryDelayMs: 30_000 });
try {
  await ob.callTool(token, "github", "read_file", { repo: "alice/docs" });
} catch (e) {
  if (e instanceof UnavailableError || e instanceof RateLimitedError) {
    console.log(`server refused (${e.reason}); try again in ${e.retryAfter ?? 1} s`);
  } else if (e instanceof DeniedError) {
    console.log("denied:", e.reason); // a decision: do not retry it
  }
  throw e;
}
```

## Using the official MCP client

attenuo mounts each upstream at `<server>/mcp/<name>` and speaks MCP Streamable HTTP there. An MCP client needs that URL and `Authorization: Bearer <token>` on every request. `mcpUrl` and `mcpHeaders` produce both:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { mcpHeaders, mcpUrl } from "@attenuo/sdk";

const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(SERVER, "github")), {
  requestInit: { headers: mcpHeaders(coder) },
});
const client = new Client({ name: "my-agent", version: "1.0.0" });
await client.connect(transport);
console.log((await client.listTools()).tools.map((t) => t.name)); // only what the token may call
```

A denied call surfaces as an `McpError` carrying JSON-RPC code `-32003`; `error.data` holds `{ reason, decision_id }`. Complete examples are in [`examples/typescript-agent`](https://github.com/attenuo-dev/attenuo/tree/main/examples/typescript-agent): `agent.ts` (planner delegates to coder, with a run limit and an approval) and `mcp_client_example.ts` (the official client through the proxy; tested with `@modelcontextprotocol/sdk` 1.32.1).

`requestInit.headers` is fixed when the transport is built. If your token changes (re-exchange before `exp`), or it is bound to a key (each request then needs a fresh DPoP proof), pass `mcpFetch` as the transport's `fetch` instead: it sets `Authorization` (and `DPoP`) per request.

```ts
const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(SERVER, "github")), {
  fetch: mcpFetch(() => currentToken, { dpopKey: coderKey }),
});
```

To have the token replaced for you, use a [`TokenRefresher`](#keeping-a-token-alive) and `refresher.fetch({ dpopKey })`.

## Verifying an audit export offline

```ts
import { verifyExport } from "@attenuo/sdk";

const jwks = (await (await fetch("http://127.0.0.1:8080/.well-known/jwks.json")).json()) as {
  keys: unknown[];
};
const report = await verifyExport({ path: "audit.jsonl" }, { checkpointPublicKeys: jwks });
if (!report.ok) console.log(report.firstBadSeq, report.badCheckpoints, report.truncated);
```

`verifyExport(source, { checkpointPublicKeys, allowUnsignedTail })` takes the export as text (`string`), bytes, an iterable of lines or `{ path }` (Node), in JSON Lines or the `--format json` form. `checkpointPublicKeys` is the JWKS or a `{ kid: key }` map (raw 32 bytes or base64url). It re-checks the SHA-256 hash chain over RFC 8785 canonical JSON of `["attenuo-audit-entry-v2", seq, prev_hash, record]`, the range the header declares and the Ed25519 checkpoint signatures (WebCrypto), with the same strictness as `attenuo audit verify --file`: a short file, entries outside the range and entries after the last valid checkpoint (unless `allowUnsignedTail`) all fail. The `ExportReport` has `ok`, `firstBadSeq`, `badCheckpoints`, `lastSignedSeq`, `unsignedTail`, `truncated`, `outsideRange` and the rest of the Rust report. A file that is not a verifiable export (no header, wrong format, a filtered export, not JSON) throws `ExportError`. The canonicalizer is a small RFC 8785 implementation tested against the RFC's vectors; it, and the strict JSON parser the verifier uses, refuse integers beyond 2^53 (a `seq` that large cannot be checked here) and duplicate object members. A filtered export (`auditExport(from, to, { kind, chainId, tool, decision })`, any of them) cannot be verified: its chain has gaps, so verify the unfiltered one, then filter. `AuditEntry` has `kind` and `chainId`.

The pieces are exported from the package root as in the Python SDK: `entryHash(seq, prevHash, record)` (the SHA-256 above, as a hex string), `GENESIS_HASH` (the `prev_hash` of entry 1), `ENTRY_HASH_VERSION`, `EXPORT_FORMAT`, `SHIPPED_FORMAT`, and the DPoP `PROOF_TYPE`.

### Cross-checking shipped checkpoints

A checkpoint is signed with the server's own key, so someone who holds the host and the key can rewrite the log and sign it again. `[audit.sink]` ships each checkpoint off the host; `crossCheck` compares an export with those copies (SR-21), like `attenuo audit verify --file --checkpoints`:

```ts
import { crossCheck, verifyExport } from "@attenuo/sdk";

const opts = { checkpointPublicKeys: jwks };
const verdict = await verifyExport({ path: "audit.jsonl" }, opts);
const cross = await crossCheck({ path: "audit.jsonl" }, { path: "shipped.jsonl" }, opts);
for (const m of cross.mismatches) console.log(m.seq, m.line, m.reason); // shipped-file order
```

`crossCheck(export, shipped, { checkpointPublicKeys })` takes both as text, bytes, an iterable of lines or `{ path }`; the shipped file is the file sink's JSON Lines, webhook bodies one per line, or bare checkpoint lines. For every shipped checkpoint inside the export's range it requires that the checkpoint verifies, that the export holds an identical one at that `seq`, and that the export's entry there hashes to the shipped `head_hash`. The `CrossCheckReport` has `ok`, `shipped`, `inRange`, `matched`, `beyondRange`, `lastShippedSeq` and `mismatches` (`seq`, `line`, `reason`): a checkpoint signed again after it was shipped, one deleted from the export, two different shipped copies for one `seq`, and a shipped copy that does not verify or whose envelope disagrees with itself. The reasons are the Rust ones, word for word. Run it next to `verifyExport`, not instead. A shipped file that is not checkpoints throws `ExportError`; `parseShipped` parses one on its own.

## Development

```sh
npm install
npm run build        # tsup: dist/index.js (ESM), dist/index.cjs, .d.ts
npm test             # vitest: unit tests on a mocked fetch
npm run lint         # tsc --noEmit, eslint, prettier --check
```

The integration test replays the GitHub leak scenario from [`examples/github-leak-demo`](https://github.com/attenuo-dev/attenuo/tree/main/examples/github-leak-demo) against a real `attenuo-server` and the `fake_mcp` upstream, then runs both examples. Other tests cover DPoP, server nonces, refresh, the cap of 32 pending approvals per run, a `decimal` catalog input (on a stack of its own, with `amount = "decimal"` for `read_file` and a policy comparing it), an export filtered on `tool` and `decision`, and revocation by chain and by MCP session (on a stack of their own, since the fake upstream gives every caller the same session id and the proxy binds it to the first). The streaming test runs on a stack with `fake_mcp --sse` and `[proxy] stream_recheck_seconds = 1`: a streamed answer arrives as a notification then the result, and a call the upstream holds open (`hold_ms`) is cut by the proxy when the lease is revoked, throwing `DeniedError` with the `stream.end` record's id. It needs prebuilt binaries:

```sh
cargo build -p attenuo-server -p attenuo-cli && cargo build -p attenuo-proxy --example fake_mcp
mkdir -p .bin/examples
cp target/debug/attenuo-server .bin/ && cp target/debug/examples/fake_mcp .bin/examples/
(cd examples/typescript-agent && npm install)      # for the two example tests
cd sdk/typescript && npm run build && ATTENUO_INTEGRATION=1 npm test
```

`ATTENUO_BIN_DIR` points at another directory holding `attenuo-server` and `examples/fake_mcp` (default: `<repo>/.bin`, which is gitignored). The test copies the binaries into a temp directory before starting them, so a shared `CARGO_TARGET_DIR` rebuilt by another checkout cannot swap them mid-run. Without `ATTENUO_INTEGRATION=1` it is skipped.

## Not done

- Not on npm until the maintainer publishes 0.1.0.
- `callToolStream` yields server-initiated requests (sampling, elicitation) but cannot answer them, and does not resume a broken stream with `Last-Event-ID` (it keeps the id on each event). Use the MCP client for those.
- The detached `ou_sig` over the user block is not checked locally; the server checks it on every request.
- Hop-0 exchange against a live IdP is untested.
- Browsers: nothing here is Node-only, but only Node 20 and 22 are tested.
