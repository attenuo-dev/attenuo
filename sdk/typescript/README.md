# @attenuo/sdk (TypeScript SDK)

TypeScript client for the [attenuo](../../README.md) authorization server: exchange delegation tokens, attenuate capabilities, call MCP tools through the enforcing proxy, handle denials, renew leases, and read the audit log.

**Status: pre-alpha**, like the server. The API follows the server's wire format as of this repository and will change with it. Not on npm yet; build it from a checkout.

```sh
cd sdk/typescript
npm install && npm run build   # ESM + CJS + .d.ts in dist/
```

Node 20 or newer (Ed25519 in WebCrypto needs no flag there: it is available since Node 18.4, still documented as experimental), zero runtime dependencies. It uses the global `fetch` and WebCrypto (`crypto.subtle` with `Ed25519`) for local token verification. It is the same API as the [Python SDK](../python/README.md), with camelCase names and promises.

## Quickstart

Start a server with the example config (`[dev] allow_root_mint = true` for the dev root token) and an MCP upstream, as in [getting started](../../docs/guides/getting-started.md). Then:

```ts
import { AdminClient, DeniedError, AttenuoClient, capability, prefix } from "@attenuo/sdk";

const URL = "http://127.0.0.1:8080";

// Development only: mint a root token for an asserted user. In production hop 0 comes from
// your IdP: ob.exchange(idToken, "planner", ["github:*"], { clientId, clientSecret }).
const admin = new AdminClient(URL, "dev-admin-token-change-me");
const root = await admin.mintRootDev("alice", "https://idp.example", "planner", {
  capabilities: ["github:*"],
});

const ob = new AttenuoClient(URL);

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

| Call                                                                                                                              | Does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new AttenuoClient(serverUrl, { token?, fetch?, headers?, timeoutMs?, dpopKey? })`                                                | HTTP client for the server. `token` is a default bearer; `fetch` swaps the transport (tests, proxies, custom TLS). Timeout defaults to 30 s.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `exchange(subjectToken, actor, capabilities, { ttlSeconds?, clientId?, clientSecret?, subjectTokenType?, actorToken?, mayAct? })` | RFC 8693 exchange. Returns a `Token`. Every hop n+1 exchange authenticates as its actor: pass the actor's `[[agents]]` secret as `clientSecret` (`clientId` defaults to `actor`). With an IdP credential as the subject and both `clientId` and `clientSecret`, it is a hop-0 exchange (`subjectTokenType: "urn:ietf:params:oauth:token-type:id-jag"` for an ID-JAG). `actorToken` (a workload-identity JWT such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer) authenticates the actor instead of a secret, depending on `[token] actor_auth`; each one works for one exchange. `mayAct` lists the agents allowed to exchange the new token next. |
| `renew(token?)`                                                                                                                   | `POST /token/renew`. Returns `{ lease, expiresAt, expiresIn }`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `callTool(token, server, tool, args?, { sessionId? })`                                                                            | `tools/call` through `/mcp/{server}`. Returns `{ text, content, isError, decisionId, structuredContent, raw }`. Throws `DeniedError` when refused.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `listTools(token, server)`                                                                                                        | `tools/list`, filtered by the proxy to what the token may call.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `initialize(token, server)`                                                                                                       | MCP `initialize`; returns the `Mcp-Session-Id`, if any.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `authzenEvaluate(token, server, tool, args?)`                                                                                     | AuthZEN decision without calling the tool. A deny is `{ decision: false, reason, decisionId, ... }`, not an exception.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `jwks()`                                                                                                                          | `GET /.well-known/jwks.json`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `inspect(jwt, { verify?, jwksUrl?, issuer?, audience? })`                                                                         | Decode a token. With `verify: true` fetch the JWKS and check the Ed25519 signature, `typ`, `exp` and that `sub`/`act` match the chain.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `new AdminClient(serverUrl, adminToken, opts?)`                                                                                   | `revokeLease`, `leaseStatus`, `audit`, `auditHead` (reads `head` from `GET /admin/audit`, signs nothing), `auditTail`, `auditExport` (async iterator of JSON Lines objects; optional `{ kind, chainId }` filter), `auditCheckpoint` (explicit; signs and stores a checkpoint), `auditVerify`, `policyReload`, `mintRootDev`; and the read-only console helpers below (`auditQuery`, `auditIter`, `auditEntry`, `auditRecord`, `auditCheckpoints`, `leaseTree`, `policies`, `policyCheck`, `policyEvaluate`).                                                                                                                                               |

Wherever a token is expected you can pass a `Token` or its JWT string; leave it out to use the client's default `token`.

A `Token` carries `lease`, `expiresAt`, `chain` (user and hops with capabilities), `agents`, `agent`, `subject`, and `verified`. The JWT is available as `token.jwt` and `String(token)`, but it is not an enumerable property, so `console.log(token)` and `JSON.stringify(token)` do not print it. Everything decoded from a token is untrusted unless `verified` is true.

### Admin: querying the audit log, lease trees, policies

These wrap the read-only operator routes the admin console uses. None of them signs, changes or audits anything.

```ts
const admin = new AdminClient(URL, "dev-admin-token-change-me");

// Newest denials first. A filtered page can come back short (even empty) with a link still
// set, so iterate rather than reading one page: auditIter follows prev/next until null.
for await (const e of admin.auditIter({ order: "desc", decision: "deny", agent: "coder" })) {
  console.log(e.seq, e.record.reason, e.record.tool);
}
const page = await admin.auditQuery({ kind: ["lease_renew"], lease: leaseId, limit: 50 });

const detail = await admin.auditRecord(denied.decisionId); // or admin.auditEntry(seq)
console.log(detail.leaseStates, detail.coveredByCheckpoint, detail.policyReloadedAfter);

await admin.auditCheckpoints({ limit: 20 }); // stored checkpoints, newest first; never signs
const tree = await admin.leaseTree(leaseId); // what a revoke would reach

await admin.policies(); // the loaded set: path, sha256, loadedAt, { id: text }
await admin.policyCheck(); // lint the file on disk now; ok means a reload would succeed
const ev = await admin.policyEvaluate("github", "read_file", { repo: "alice/x" }, { token: coder });
console.log(ev.decision, ev.reason, ev.policyIds); // no lease check, no audit record
```

| Call                                                      | Route                                                         | Returns                                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `auditQuery(query?)`                                      | `GET /admin/audit`                                            | `{ entries, next, prev, head }`                                                    |
| `auditIter(query?)` (`limit` defaults to 1000)            | `GET /admin/audit`, repeated                                  | async iterator of `AuditEntry`, following `next` (asc) or `prev` (desc) until null |
| `auditEntry(seq)`, `auditRecord(id)`                      | `GET /admin/audit/entries/{seq}`, `/admin/audit/records/{id}` | `{ entry, leaseStates, coveredByCheckpoint, policyReloadedAfter }`                 |
| `auditCheckpoints({ before?, limit? })`                   | `GET /admin/audit/checkpoints`                                | `{ checkpoints, prev }`                                                            |
| `leaseTree(leaseId, maxNodes?)`                           | `GET /admin/leases/{id}/tree`                                 | `{ root, ancestors, nodes, wouldRevoke, truncated }`                               |
| `policies()`                                              | `GET /admin/policies`                                         | `{ path, sha256, loadedAt, policyIds, warnings, policies }`                        |
| `policyCheck()`                                           | `GET /admin/policies/check`                                   | `{ ok, issues, differsFromLoaded, ... }`                                           |
| `policyEvaluate(server, tool, args?, { token?, chain? })` | `POST /admin/policies/evaluate`                               | `{ decision, allowed, reason, policyIds, ..., tokenExpired }`                      |

`AuditQuery` takes `order` (`"asc"` with `from`, or `"desc"` with `before`), `limit`, and exact-match filters combined with AND: `kind` (one or an array), `decision`, `reason`, `subject`, `agent`, `lease`, `server`, `tool`, `chainId`, and `since` / `until` (RFC 3339 strings or `Date`s). Errors map as everywhere else: a 404 for an unknown seq, record or lease is an `ApiError` with `status: 404`, a bad filter is a 400 `invalid_request`.

### Capabilities

```ts
import { capability, equals, oneOf, prefix } from "@attenuo/sdk";

capability("github", "read_file"); // github:read_file
capability("github", "create_issue", { repo: oneOf("acme/api", "acme/web") });
capability("github", "read_*", { repo: prefix("alice/public-"), ref: equals("main") });
capability("github", "list_issues", { state: "open" }); // a bare value means equals
```

Capabilities serialize as the server expects: `{ server, tool, constraints: { repo: { op: "prefix", value: "..." } } }`, with `constraints` omitted when empty. `exchange` and `mintRootDev` also take `"server:tool"` strings (comma-separated lists too, like the CLI's `--cap`) and raw objects.

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
const signOff = await plannerKey.signOff(`${URL}/token`, root.jwt, coderKey.thumbprint, "coder");

// In the coder's process: the new token is bound to coderKey.
const ob = new AttenuoClient(URL, { dpopKey: coderKey });
const coder = await ob.exchange(root, "coder", "github:read_file", {
  clientSecret,
  subjectTokenDpop: signOff,
});
await ob.callTool(coder, "github", "read_file", { repo: "alice/docs" }); // proof attached
```

With a key, every `callTool`, `listTools`, `initialize`, `renew` and `authzenEvaluate` sends `Authorization: DPoP <token>` and a fresh proof, and every `exchange` binds the new token. When the parent is bound to another key, its holder's sign-off names the new key and agent and works for that one exchange; a process that holds both keys can pass `subjectDpopKey: plannerKey` instead. When the parent is bound to the client's own key, no sign-off is needed. `Token.dpopJkt` is the thumbprint a token is bound to (undefined for a bearer token), and `AuditEntry.dpopBound` says whether a decision was made with a proven bound token. A bound token without a proof is an `UnauthorizedError` with `error === "dpop_required"`. See [Binding tokens to keys](../../docs/guides/binding-tokens-to-keys.md).

Server nonces (RFC 9449 §8, `[token] dpop_nonce = "required"`) need no code. `AttenuoClient`, `AdminClient.mintRootDev` and `mcpFetch` keep the latest `DPoP-Nonce` header the server sent and put it in each proof. When the server refuses a proof with `use_dpop_nonce`, they retry the request once with a new proof carrying the nonce from that response (`mcpFetch` does not retry a request whose body is a stream). For your own HTTP code, `key.proof(method, url, token, { nonce })` adds the claim, and `NonceCache` does the bookkeeping: `await cache.update(response)` stores the nonce and resolves to true when the request should be retried.

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
const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(URL, "github")), {
  fetch: refresher.fetch({ dpopKey: coderKey }), // = mcpFetch(refresher.provider, { dpopKey })
});

await dispose(); // stop the loop
```

- **Schedule.** `leaseInterval` (seconds) is the server's `[issuer] lease_interval_seconds`; left out, it is learned from the first renewal, which then happens right away. The token is re-exchanged `margin` seconds before `exp` (default 20% of its lifetime, at least 5 s, at most half the lifetime). `onChange(token)` is called with each replacement.
- **Failures.** Network errors, 5xx, 408 and 429 are retried with jittered exponential backoff (1 s doubling to 30 s). It stops, calls `onError` once and sets `refresher.error` when the lease is revoked (`RefreshError.reason === "lease_revoked"`, or `lease_lost` when an ancestor lapsed), the server refuses an exchange for good (`refused`: `invalid_scope`, `replayed`, a bad secret), or the token reaches `exp` (`token_expired`). It never loops on a revoked lease. `refresher.provider()` throws the `RefreshError` once it has given up.
- **DPoP.** Renewals go through your client and are signed with its `dpopKey`. A replacement must be bound to the same key as the current token; otherwise it is not adopted and the refresher stops with `key_mismatch`.
- **Logging.** Nothing is logged, and no error message contains a token.
- **Testing.** `tick()` runs whatever is due and returns the milliseconds to wait; `start()` is a loop around it, and `now` and `random` options replace the clock and the jitter.

### Errors

| Error               | When                                                                                                                                                                                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DeniedError`       | The proxy denied a call (JSON-RPC `-32003` with the `X-Attenuo-Decision-Id` header naming `data.decision_id`; an upstream's own `-32003` without that proof is an `RpcError`). Branch on `reason` (`capability_denied`, `policy_deny`, `lease_revoked`, ...), log `decisionId`. |
| `UnauthorizedError` | HTTP 401 or JSON-RPC `-32001`: the bearer is missing, malformed, expired or not ours. A subclass of `ApiError`.                                                                                                                                                                 |
| `ApiError`          | A non-success HTTP status. `status`, `error` (for example `invalid_scope`), `detail`.                                                                                                                                                                                           |
| `RpcError`          | Any other JSON-RPC error (`code`, `rpcMessage`, `data`).                                                                                                                                                                                                                        |
| `RefreshError`      | A `TokenRefresher` gave up. `reason`: `lease_revoked`, `lease_lost`, `token_expired`, `refused`, `key_mismatch`.                                                                                                                                                                |
| `VerificationError` | `inspect(..., { verify: true })` failed.                                                                                                                                                                                                                                        |
| `AttenuoError`      | Base class; also thrown for responses that are not what the server sends.                                                                                                                                                                                                       |

An AuthZEN deny and a tool's own `isError` are results, not exceptions.

## Using the official MCP client

attenuo mounts each upstream at `<server>/mcp/<name>` and speaks MCP Streamable HTTP there. An MCP client needs that URL and `Authorization: Bearer <token>` on every request. `mcpUrl` and `mcpHeaders` produce both:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { mcpHeaders, mcpUrl } from "@attenuo/sdk";

const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(URL, "github")), {
  requestInit: { headers: mcpHeaders(coder) },
});
const client = new Client({ name: "my-agent", version: "1.0.0" });
await client.connect(transport);
console.log((await client.listTools()).tools.map((t) => t.name)); // only what the token may call
```

A denied call surfaces as an `McpError` carrying JSON-RPC code `-32003`; `error.data` holds `{ reason, decision_id }`. Complete examples are in [`examples/typescript-agent`](../../examples/typescript-agent): `agent.ts` (planner delegates to coder) and `mcp_client_example.ts` (the official client through the proxy; tested with `@modelcontextprotocol/sdk` 1.32.1).

`requestInit.headers` is fixed when the transport is built. If your token changes (re-exchange before `exp`), or it is bound to a key (each request then needs a fresh DPoP proof), pass `mcpFetch` as the transport's `fetch` instead: it sets `Authorization` (and `DPoP`) per request.

```ts
const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(URL, "github")), {
  fetch: mcpFetch(() => currentToken, { dpopKey: coderKey }),
});
```

To have the token replaced for you, use a [`TokenRefresher`](#keeping-a-token-alive) and `refresher.fetch({ dpopKey })`.

## Verifying an audit export offline

```ts
import { verifyExport } from "@attenuo/sdk";

const jwks = await (await fetch("http://127.0.0.1:8080/.well-known/jwks.json")).json();
const report = await verifyExport({ path: "audit.jsonl" }, { checkpointPublicKeys: jwks });
if (!report.ok) console.log(report.firstBadSeq, report.badCheckpoints, report.truncated);
```

`verifyExport(source, { checkpointPublicKeys, allowUnsignedTail })` takes the export as text (`string`), bytes, an iterable of lines or `{ path }` (Node), in JSON Lines or the `--format json` form. `checkpointPublicKeys` is the JWKS or a `{ kid: key }` map (raw 32 bytes or base64url). It re-checks the SHA-256 hash chain over RFC 8785 canonical JSON of `["attenuo-audit-entry-v2", seq, prev_hash, record]`, the range the header declares and the Ed25519 checkpoint signatures (WebCrypto), with the same strictness as `attenuo audit verify --file`: a short file, entries outside the range and entries after the last valid checkpoint (unless `allowUnsignedTail`) all fail. The `ExportReport` has `ok`, `firstBadSeq`, `badCheckpoints`, `lastSignedSeq`, `unsignedTail`, `truncated`, `outsideRange` and the rest of the Rust report. A file that is not a verifiable export (no header, wrong format, a filtered export, not JSON) throws `ExportError`. The canonicalizer is a small RFC 8785 implementation tested against the RFC's vectors; it, and the strict JSON parser the verifier uses, refuse integers beyond 2^53 (a `seq` that large cannot be checked here) and duplicate object members. A filtered export (`auditExport(from, to, { kind, chainId })`) cannot be verified: its chain has gaps, so verify the unfiltered one, then filter. `AuditEntry` has `kind` and `chainId`.

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

The integration test replays the GitHub leak scenario from [`examples/github-leak-demo`](../../examples/github-leak-demo) against a real `attenuo-server` and the `fake_mcp` upstream, then runs both examples. It needs prebuilt binaries:

```sh
cargo build -p attenuo-server -p attenuo-cli && cargo build -p attenuo-proxy --example fake_mcp
mkdir -p .bin/examples
cp target/debug/attenuo-server .bin/ && cp target/debug/examples/fake_mcp .bin/examples/
(cd examples/typescript-agent && npm install)      # for the two example tests
cd sdk/typescript && npm run build && ATTENUO_INTEGRATION=1 npm test
```

`ATTENUO_BIN_DIR` points at another directory holding `attenuo-server` and `examples/fake_mcp` (default: `<repo>/.bin`, which is gitignored). The test copies the binaries into a temp directory before starting them, so a shared `CARGO_TARGET_DIR` rebuilt by another checkout cannot swap them mid-run. Without `ATTENUO_INTEGRATION=1` it is skipped.

## Not done

- Not published to npm.
- No streaming: `callTool` reads the whole response, so a long-lived SSE stream or server-initiated requests are not supported through the SDK's own methods (use the MCP client for those).
- The detached `ou_sig` over the user block is not checked locally; the server checks it on every request.
- Hop-0 exchange against a live IdP is untested.
- Browsers: nothing here is Node-only, but only Node 20 and 22 are tested.
