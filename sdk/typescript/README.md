# @onbehalf/sdk (TypeScript SDK)

TypeScript client for the [onbehalf](../../README.md) authorization server: exchange delegation tokens, attenuate capabilities, call MCP tools through the enforcing proxy, handle denials, renew leases, and read the audit log.

**Status: pre-alpha**, like the server. The API follows the server's wire format as of this repository and will change with it. Not on npm yet; build it from a checkout.

```sh
cd sdk/typescript
npm install && npm run build   # ESM + CJS + .d.ts in dist/
```

Node 20 or newer, zero runtime dependencies. It uses the global `fetch` and WebCrypto (`crypto.subtle` with `Ed25519`) for local token verification. It is the same API as the [Python SDK](../python/README.md), with camelCase names and promises.

## Quickstart

Start a server with the example config (`[dev] allow_root_mint = true` for the dev root token) and an MCP upstream, as in [getting started](../../docs/guides/getting-started.md). Then:

```ts
import { AdminClient, DeniedError, OnbehalfClient, capability, prefix } from "@onbehalf/sdk";

const URL = "http://127.0.0.1:8080";

// Development only: mint a root token for an asserted user. In production hop 0 comes from
// your IdP: ob.exchange(idToken, "planner", ["github:*"], { clientId, clientSecret }).
const admin = new AdminClient(URL, "dev-admin-token-change-me");
const root = await admin.mintRootDev("alice", "https://idp.example", "planner", {
  capabilities: ["github:*"],
});

const ob = new OnbehalfClient(URL);

// The planner hands the coder read_file on alice's public repos only.
const coder = await ob.exchange(
  root,
  "coder",
  [capability("github", "read_file", { repo: prefix("alice/public-") })],
  // The coder's [[agents]] secret: a hop n+1 exchange authenticates as its actor.
  { ttlSeconds: 600, clientSecret: process.env.ONBEHALF_CLIENT_SECRET },
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

| Call                                                                                                        | Does                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new OnbehalfClient(serverUrl, { token?, fetch?, headers?, timeoutMs? })`                                   | HTTP client for the server. `token` is a default bearer; `fetch` swaps the transport (tests, proxies, custom TLS). Timeout defaults to 30 s.                                                                                                                                                                                                                          |
| `exchange(subjectToken, actor, capabilities, { ttlSeconds?, clientId?, clientSecret?, subjectTokenType? })` | RFC 8693 exchange. Returns a `Token`. Every hop n+1 exchange authenticates as its actor: pass the actor's `[[agents]]` secret as `clientSecret` (`clientId` defaults to `actor`). With an IdP credential as the subject and both `clientId` and `clientSecret`, it is a hop-0 exchange (`subjectTokenType: "urn:ietf:params:oauth:token-type:id-jag"` for an ID-JAG). |
| `renew(token?)`                                                                                             | `POST /token/renew`. Returns `{ lease, expiresAt, expiresIn }`.                                                                                                                                                                                                                                                                                                       |
| `callTool(token, server, tool, args?, { sessionId? })`                                                      | `tools/call` through `/mcp/{server}`. Returns `{ text, content, isError, decisionId, structuredContent, raw }`. Throws `DeniedError` when refused.                                                                                                                                                                                                                    |
| `listTools(token, server)`                                                                                  | `tools/list`, filtered by the proxy to what the token may call.                                                                                                                                                                                                                                                                                                       |
| `initialize(token, server)`                                                                                 | MCP `initialize`; returns the `Mcp-Session-Id`, if any.                                                                                                                                                                                                                                                                                                               |
| `authzenEvaluate(token, server, tool, args?)`                                                               | AuthZEN decision without calling the tool. A deny is `{ decision: false, reason, decisionId, ... }`, not an exception.                                                                                                                                                                                                                                                |
| `jwks()`                                                                                                    | `GET /.well-known/jwks.json`.                                                                                                                                                                                                                                                                                                                                         |
| `inspect(jwt, { verify?, jwksUrl?, issuer?, audience? })`                                                   | Decode a token. With `verify: true` fetch the JWKS and check the Ed25519 signature, `typ`, `exp` and that `sub`/`act` match the chain.                                                                                                                                                                                                                                |
| `new AdminClient(serverUrl, adminToken, opts?)`                                                             | `revokeLease`, `leaseStatus`, `audit`, `auditHead` (reads `head` from `GET /admin/audit`, signs nothing), `auditTail`, `auditExport` (async iterator of JSON Lines objects), `auditCheckpoint` (explicit; signs and stores a checkpoint), `auditVerify`, `policyReload`, `mintRootDev`.                                                                               |

Wherever a token is expected you can pass a `Token` or its JWT string; leave it out to use the client's default `token`.

A `Token` carries `lease`, `expiresAt`, `chain` (user and hops with capabilities), `agents`, `agent`, `subject`, and `verified`. The JWT is available as `token.jwt` and `String(token)`, but it is not an enumerable property, so `console.log(token)` and `JSON.stringify(token)` do not print it. Everything decoded from a token is untrusted unless `verified` is true.

### Capabilities

```ts
import { capability, equals, oneOf, prefix } from "@onbehalf/sdk";

capability("github", "read_file"); // github:read_file
capability("github", "create_issue", { repo: oneOf("acme/api", "acme/web") });
capability("github", "read_*", { repo: prefix("alice/public-"), ref: equals("main") });
capability("github", "list_issues", { state: "open" }); // a bare value means equals
```

Capabilities serialize as the server expects: `{ server, tool, constraints: { repo: { op: "prefix", value: "..." } } }`, with `constraints` omitted when empty. `exchange` and `mintRootDev` also take `"server:tool"` strings (comma-separated lists too, like the CLI's `--cap`) and raw objects.

### Errors

| Error               | When                                                                                                                                                                                                                                                                             |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DeniedError`       | The proxy denied a call (JSON-RPC `-32003` with the `X-Onbehalf-Decision-Id` header naming `data.decision_id`; an upstream's own `-32003` without that proof is an `RpcError`). Branch on `reason` (`capability_denied`, `policy_deny`, `lease_revoked`, ...), log `decisionId`. |
| `UnauthorizedError` | HTTP 401 or JSON-RPC `-32001`: the bearer is missing, malformed, expired or not ours. A subclass of `ApiError`.                                                                                                                                                                  |
| `ApiError`          | A non-success HTTP status. `status`, `error` (for example `invalid_scope`), `detail`.                                                                                                                                                                                            |
| `RpcError`          | Any other JSON-RPC error (`code`, `rpcMessage`, `data`).                                                                                                                                                                                                                         |
| `VerificationError` | `inspect(..., { verify: true })` failed.                                                                                                                                                                                                                                         |
| `OnbehalfError`     | Base class; also thrown for responses that are not what the server sends.                                                                                                                                                                                                        |

An AuthZEN deny and a tool's own `isError` are results, not exceptions.

## Using the official MCP client

onbehalf mounts each upstream at `<server>/mcp/<name>` and speaks MCP Streamable HTTP there. An MCP client needs that URL and `Authorization: Bearer <token>` on every request. `mcpUrl` and `mcpHeaders` produce both:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { mcpHeaders, mcpUrl } from "@onbehalf/sdk";

const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(URL, "github")), {
  requestInit: { headers: mcpHeaders(coder) },
});
const client = new Client({ name: "my-agent", version: "1.0.0" });
await client.connect(transport);
console.log((await client.listTools()).tools.map((t) => t.name)); // only what the token may call
```

A denied call surfaces as an `McpError` carrying JSON-RPC code `-32003`; `error.data` holds `{ reason, decision_id }`. Complete examples are in [`examples/typescript-agent`](../../examples/typescript-agent): `agent.ts` (planner delegates to coder) and `mcp_client_example.ts` (the official client through the proxy; tested with `@modelcontextprotocol/sdk` 1.32.1).

`requestInit.headers` is fixed when the transport is built. If your token changes (re-exchange before `exp`), build a new transport or pass a custom `fetch` to the transport that sets `Authorization` per request.

## Development

```sh
npm install
npm run build        # tsup: dist/index.js (ESM), dist/index.cjs, .d.ts
npm test             # vitest: unit tests on a mocked fetch
npm run lint         # tsc --noEmit, eslint, prettier --check
```

The integration test replays the GitHub leak scenario from [`examples/github-leak-demo`](../../examples/github-leak-demo) against a real `onbehalf-server` and the `fake_mcp` upstream, then runs both examples. It needs prebuilt binaries:

```sh
cargo build -p onbehalf-server -p onbehalf-cli && cargo build -p onbehalf-proxy --example fake_mcp
mkdir -p .bin/examples
cp target/debug/onbehalf-server .bin/ && cp target/debug/examples/fake_mcp .bin/examples/
(cd examples/typescript-agent && npm install)      # for the two example tests
cd sdk/typescript && npm run build && ONBEHALF_INTEGRATION=1 npm test
```

`ONBEHALF_BIN_DIR` points at another directory holding `onbehalf-server` and `examples/fake_mcp` (default: `<repo>/.bin`, which is gitignored). The test copies the binaries into a temp directory before starting them, so a shared `CARGO_TARGET_DIR` rebuilt by another checkout cannot swap them mid-run. Without `ONBEHALF_INTEGRATION=1` it is skipped.

## Not done

- Not published to npm.
- No token-refresh helper (renew on a timer, re-exchange before `exp`), and no streaming: `callTool` reads the whole response, so a long-lived SSE stream or server-initiated requests are not supported through the SDK's own methods (use the MCP client for those).
- The detached `ou_sig` over the user block is not checked locally; the server checks it on every request.
- Hop-0 exchange against a live IdP is untested.
- Browsers: nothing here is Node-only, but only Node 20 and 22 are tested.
