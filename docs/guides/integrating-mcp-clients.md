# Integrating MCP clients

This guide is for the person writing the agent side: an agent framework, an MCP client library, or a script. It covers how to send the attenuo token, how a token passes from one agent to the next, what to do with a denial, how to keep a lease alive, and how a client that does not speak MCP can ask attenuo for a decision.

The examples use `curl` so you can see the wire format. Every request and response shape below was run against a local server.

## The model in one paragraph

An agent holds a **delegation token**: a signed JWT that names the user the agent acts for, every agent between the user and this one, what each of them may do, and a lease id for each hop. The agent sends it as a bearer on every request to the proxy. The proxy checks it and decides each call. When the agent wants a sub-agent to do part of the work, it exchanges its own token for a narrower one and hands that over. Nobody ever gets more than the hop above them had.

## Sending the bearer to the proxy

attenuo mounts each configured upstream at `/mcp/<name>` and speaks MCP Streamable HTTP on it. To use an upstream through attenuo:

1. Change the MCP server URL in your client from the upstream's URL to `https://<attenuo host>/mcp/<name>`.
2. Send `Authorization: Bearer <delegation token>` on every request, including `initialize`, `tools/list` and the `GET` and `DELETE` session requests. Without it, or with a bad one, you get HTTP 401 and JSON-RPC error `-32001`.
3. Keep sending `Accept: application/json, text/event-stream` and `Content-Type: application/json` as MCP requires. The proxy forwards `Accept`, `Content-Type`, `Mcp-Session-Id`, `Mcp-Protocol-Version` and `Last-Event-ID` to the upstream.

```sh
curl -s -X POST https://attenuo.example.com/mcp/github \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"acme/api","path":"README.md"}}}'
```

Things that are different from a plain MCP server:

- **Tokens can be bound to keys.** A token with `cnf.jkt` needs a DPoP proof on every request, and the 401 then says `WWW-Authenticate: DPoP`. See [Binding tokens to keys](binding-tokens-to-keys.md).
- **The bearer is not forwarded.** The upstream never sees the attenuo token. If the upstream needs its own credential, attenuo has no setting for injecting one in v0. Today that means the upstream must trust the proxy by network placement, or hold its own static credential.
- **No OAuth discovery.** attenuo does not serve Protected Resource Metadata (RFC 9728) or an authorization server. A 401 carries `WWW-Authenticate: Bearer realm="attenuo"` and nothing else. An MCP client that tries to discover an authorization server will not find one. Configure the bearer yourself, as a static header or through a token provider you write.
- **Whether your MCP client lets you set a header** (and refresh it) depends on the client. Most Streamable HTTP clients take custom headers. Which ones support changing the header between requests is untested here. If yours cannot, run a small local forwarder that adds a fresh bearer. The SDKs have the per-request hook: `TokenAuth(provider)` in Python and `mcpFetch(provider)` in TypeScript, and a token refresher is such a provider.
- **`tools/list` is filtered.** You see only the tools the token may call. A tool missing from the list is not necessarily missing upstream.
- **Resources and prompts are authorized like tool calls.** `resources/read`, `resources/subscribe`, `prompts/get` and `completion/complete` need a capability with the method name as the tool, for example `github:resources/read`. Any other method outside a short allowlist is denied unless a capability and the policy permit it. `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list` show only entries your capabilities could permit (the cursor is passed through, so a page can be empty while `nextCursor` is set). See [design/server.md](../design/server.md#mcp-method-coverage).

Every response to a request that was decided carries the header `X-Attenuo-Decision-Id`, a comma-separated list in request order when the body is a batch.

## Getting the first token

The first token in a chain is the **root token**. It binds one user to one agent. How you get it depends on the deployment:

- **Production.** The agent authenticates itself to `POST /token` with its client id and secret and presents a credential the user's identity provider issued: an OIDC ID token or an ID-JAG. attenuo checks the credential and builds the user block from it. Details are in [Identity providers](identity-providers.md).
- **Development.** An operator mints it with `attenuo token root`, which needs `[dev] allow_root_mint = true`. See [Getting started](getting-started.md).

A root token request, from a registered agent:

```sh
curl -s -X POST https://attenuo.example.com/token \
  -u planner:$PLANNER_SECRET \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$ID_TOKEN \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  --data-urlencode scope='github:*'
```

The response:

```json
{
  "access_token": "<jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 900,
  "lease": "5b0c6f0e-0d54-4d0e-9a53-0c1f6a9c2a11"
}
```

Keep `access_token` and `lease`. You need the token for every call and the lease id if your orchestration wants to show or revoke it.

Each ID token or ID-JAG can be used once. Presenting the same one again, from any agent, fails with `invalid_grant` / `replayed`, so fetch a fresh credential for every root token. The root token never outlives the credential: its `expires_in` is at most the time left until the credential's `exp`.

## How exchange works, hop to hop

Take a run with a planner, a coder and a tester. Alice asks the planner to fix a bug.

1. **Hop 0.** The planner trades Alice's login for a root token. The token says: Alice, acting through `planner`, may call `github:*`.
2. **Hop 1.** The planner decides the coder should read files and open issues in one repository. It sends its own token to `POST /token` as the `subject_token`, names `coder` as the `actor`, authenticates with the coder's client credentials, and asks for `github:read_file` and `github:create_issue` limited to `acme/api`. The server checks that the request fits inside what the planner holds. It returns a new token for the coder. The planner passes it to the coder.
3. **Hop 2.** The coder wants the tester to read files only. It repeats step 2 with its token and asks for `github:read_file`. The result is a token for the tester.

At every step the rule is the same: the requested capabilities must be covered by the token you present, the new token cannot outlive its parent, and the chain cannot be deeper than `max_depth` (default 8). A request that breaks any of these fails with 400 and nothing is issued.

The exchange request, with a constraint, as JSON:

```sh
curl -s -X POST https://attenuo.example.com/token \
  -u coder:$CODER_SECRET \
  -H 'content-type: application/json' \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "'"$PLANNER_TOKEN"'",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "actor": "coder",
    "requested_ttl_seconds": 600,
    "authorization_details": [
      { "type": "attenuo_capabilities",
        "capabilities": [
          { "server": "github", "tool": "create_issue",
            "constraints": { "repo": { "op": "prefix", "value": "acme/" } } }
        ] }
    ]
  }'
```

The form encoding takes `scope` instead, a space-separated list of `server:tool` with no constraints:

```sh
curl -s -X POST https://attenuo.example.com/token \
  -u coder:$CODER_SECRET \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$PLANNER_TOKEN \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode actor=coder \
  --data-urlencode scope='github:read_file github:create_issue'
```

With a SPIFFE JWT-SVID instead of a client secret, the receiving agent sends its own identity:

```sh
SVID=$(spire-agent api fetch jwt -audience https://attenuo.example.com \
  -socketPath /run/spire/sockets/agent.sock | sed -n 2p | tr -d '[:space:]')   # untested
curl -s -X POST https://attenuo.example.com/token \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$PLANNER_TOKEN \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode actor=coder \
  --data-urlencode scope='github:read_file' \
  --data-urlencode actor_token=$SVID \
  --data-urlencode actor_token_type=urn:ietf:params:oauth:token-type:jwt
```

The SDKs take the same: Python `client.exchange(parent, "coder", caps, actor_token=svid)`, TypeScript `ob.exchange(parent, "coder", caps, { actorToken: svid })`, CLI `attenuo token exchange ... --actor-token-file svid.jwt`.

Rules to know:

- Capabilities are `{server, tool, constraints}`. `server` and `tool` are an exact name, `*`, or a prefix glob such as `read_*`. A constraint is `equals`, `one_of` or `prefix` on one argument. A call that leaves out a constrained argument is denied.
- A child must constrain every argument its parent constrains, at least as tightly. It may add constraints.
- A child is covered only by a single parent capability, not by a combination of several. If you need to split authority, ask for each piece separately.
- A parent whose lease is revoked, expired or unknown cannot delegate. The exchange fails with `invalid_grant`.
- The request must authenticate as `actor`. Either with that agent's `[[agents]]` client credentials (its client secret by HTTP Basic or as `client_id` and `client_secret` in the body, or a signed client assertion, `private_key_jwt`, when the entry holds `jwks`: see [A key instead of a secret](identity-providers.md#a-key-instead-of-a-secret)), or with an `actor_token`: a workload-identity JWT for the agent, such as a SPIFFE JWT-SVID, from an `[[actor_trust]]` issuer (see [Workload identity for sub-agents](identity-providers.md#workload-identity-for-sub-agents)). `[token] actor_auth` says which the server accepts. The agent receiving the token proves who it is, so whoever orchestrates the exchange needs the receiving agent's credential, or the receiving agent makes the request itself with the parent token. A wrong or missing secret is 401 `invalid_client`, a bad actor token is 400 `invalid_request` with an `actor_token_*` code, and authenticating as someone else is 400 `actor_mismatch`. An operator can turn this off with `[token] require_actor_auth = false` (the server warns), and then `actor` is only asserted.
- An actor token works for one exchange (`replayed` the second time), and the child token expires no later than the actor token. Fetch a fresh one per exchange.
- A parent can name who may exchange it next with `may_act` (RFC 8693 §4.4). Send `"may_act": ["coder"]` on the exchange that mints it (or let `[[root_grants]] may_act` set it at hop 0). Exchanging such a token for an agent that is not listed fails with `actor_not_permitted`. Without `may_act`, any authenticated agent may.
- An agent cannot appear twice in a chain (`duplicate_actor`).
- A parent token delegates to a given actor once. A second exchange of the same token for the same actor is `invalid_grant` / `replayed`; renew the child's lease (below) to keep it alive instead.
- Failed exchanges answer `{"error": "...", "detail": "..."}`. `invalid_scope` means you asked for too much. `invalid_grant` means the parent token or one of its leases is no good. When the parent token verified, the refusal is also a `deny` audit record and the body carries its `decision_id` (also in `X-Attenuo-Decision-Id`).

Each hop gets its own lease. Revoking a lease revokes its whole subtree. So if the tester misbehaves, revoke the tester's lease and only the tester stops. If the planner's lease is revoked, all three stop.

To see what a token carries:

```sh
attenuo token inspect "$TOKEN" --verify
```

## Worked examples with agent frameworks

Two runnable examples put an orchestrator and a `coder` sub-agent behind the proxy, each with its own token, and replay the GitHub-leak scenario:

- [Claude Agent SDK](https://github.com/attenuo-dev/attenuo/blob/main/examples/claude-agent-sdk/README.md): the sub-agent's `AgentDefinition` carries an inline MCP server (`{"type": "http", "url": ".../mcp/github", "headers": {"Authorization": "Bearer ..."}}`), so only that agent holds the narrowed token.
- [LangChain](https://github.com/attenuo-dev/attenuo/blob/main/examples/langchain-agent/README.md): `langchain-mcp-adapters` with the same URL and header, and a tool interceptor that hands a `-32003` denial to the model as a tool error instead of letting it end the run. The adapter opens a new MCP session per call, so after a revocation it sees HTTP 401 rather than `-32003`.

Both run without an API key in a dry-run mode (`run.sh`). The live mode with a model is untested.

## Handling `DENIED` responses

A denied `tools/call` comes back as HTTP 200 with a JSON-RPC error. The MCP request was understood and answered. The answer is no.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32003,
    "message": "attenuo: denied: capability_denied",
    "data": {
      "reason": "capability_denied",
      "decision_id": "98849dc3-f053-4649-9b1a-fae0c2f11426"
    }
  }
}
```

Code on `-32003`. Branch on `error.data.reason`, not on the message text. The `decision_id` is the id of the audit record for this decision. It is also in the `X-Attenuo-Decision-Id` header.

What each reason means for the agent:

| `reason` | Meaning | What the client should do |
| --- | --- | --- |
| `capability_denied` | The token does not allow this tool or these arguments | Do not retry. Tell the model the tool is unavailable. Ask the parent for a wider token only if the task truly needs it |
| `policy_deny` | The token allows it but the Cedar policy does not | Do not retry with the same arguments. A different argument value may pass |
| `lease_revoked` | The hop, or an ancestor, was revoked | Stop the run. This is the user or an operator pulling the plug. Do not renew or re-exchange. Surface it |
| `lease_expired` | The lease ran out before it was renewed | Call `POST /token/renew`, then retry once. If renewal fails, stop |
| `lease_unknown` | The server does not know a lease in the chain | Treat as fatal. The token was not issued by this server, or the database was reset |
| `tool_not_in_catalog` | The tool is not in the server's catalog, and the operator denies unknown tools (the default) | Do not retry. The operator has to add the tool to `[policy.catalog]` |
| `input_type_mismatch` | An argument does not have the type the catalog declares for it (a number where a string is declared, for example) | Do not retry as is. Send each argument with the type the catalog declares (`tools/list` input schemas usually say the same) |
| `audit_error`, `lease_error`, `policy_error` | Internal failure. The server fails closed | Retry with backoff a few times, then give up and alert an operator |

A request with no valid token is different: HTTP 401, JSON-RPC `-32001`, and `"id": null` when the proxy could not read the request id. Branch on `error.data.reason`, as for a denial: `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce`, or `lease_revoked`, `lease_expired`, `lease_unknown` on a request that carries no per-call decision, such as `tools/list`; such a lease refusal also names its audit record in `data.decision_id` and `X-Attenuo-Decision-Id`. The SDKs raise it as `Unauthorized` (Python) and `UnauthorizedError` (TypeScript) with `reason` and `decision_id` / `decisionId`. An expired or malformed token is a 401 as well. On a 401, a client that holds a fresh credential can re-run its exchange. One that does not should stop.

A request the server refused for its load is not a decision either: HTTP 503 with JSON-RPC `-32006` (`data.reason` `overloaded`, `[limits] max_in_flight` reached) or HTTP 429 with `-32007` (`rate_limited`, the run is over `[limits] mcp_requests_per_minute`), each with `Retry-After` in seconds. The request was refused before any decision, audit record or upstream call, so it is safe to send again after `Retry-After`. The SDKs raise these as `Unavailable` / `RateLimited` (Python) and `UnavailableError` / `RateLimitedError` (TypeScript), with `reason` and `retry_after` / `retryAfter`, and never as a denial; they retry them only when the client is built with `max_retries` / `maxRetries` ([HTTP API reference](../reference/http-api.md#mcp-proxy)).

Other proxy errors: `-32004` (HTTP 404) for an unknown upstream name, `-32005` (HTTP 502) when the upstream cannot be reached, `-32602` for a request missing a field the proxy needs.

**Streamed answers.** When the upstream streams a `tools/call` answer over SSE, the proxy relays it event by event and re-checks the token and lease every `[proxy] stream_recheck_seconds` (default 2). If the lease is revoked or expires, or the token expires, while the stream is open, the last event is a JSON-RPC `-32001` error with `"id": null` and `data.reason` (`lease_revoked`, `lease_expired`, `lease_unknown`, `token_expired`), plus `data.decision_id` naming the `stream.end` audit record. Treat it like the denial with the same reason in the table above. The SDKs do: `call_tool_stream` (Python) and `callToolStream` (TypeScript) yield each message as it arrives and raise the usual denial error (`Denied`, `DeniedError`) with that reason and decision id.

**Sessions.** The proxy binds each `Mcp-Session-Id` the upstream assigns to the user and the root lease of the token that opened it. Every agent of the same run (same root token lineage) can use the session; any other token gets HTTP 403 with JSON-RPC `-32003` and reason `session_mismatch`, on `POST`, `GET` and `DELETE` alike. A session id the proxy does not know, for example after a proxy restart or an hour without use, gets HTTP 404: start a new session with `initialize`, as MCP clients already do on 404.

Good client behaviour:

- Return the denial to the model as a plain tool error that says what was denied and why, in your words. Do not paste raw server output into the model's context, and do not invite it to try other routes.
- Log the `decision_id` next to your own request id. When a user asks "why did the agent not do X", an operator can look it up. Over HTTP: `GET /admin/audit?from=1&limit=1000`, then pick the entry where `record.id` matches. With the CLI and `jq`: `attenuo --json audit tail -n 1000 | jq '.entries[] | select(.record.id == "<decision id>")'`. Untested against a large log.
- Do not loop on a denial. A denial is a decision, not a glitch.

## Renewing leases

A lease is short-lived. When it expires, calls on that hop are denied with `lease_expired` even if the token itself is still valid. The agent that holds the token keeps its lease alive.

```sh
curl -s -X POST https://attenuo.example.com/token/renew \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "lease": "a94b3c66-5c93-4ea3-a847-10f75757d95b",
  "expires_at": "2026-10-22T22:22:40.733780689Z",
  "expires_in": 299
}
```

How to use it:

- Renew your own hop only. The bearer is your token, and only the last hop's lease is extended. A parent's lease is the parent's job.
- Renew at about a third of `lease_interval_seconds` (default 300, so about every 100 seconds). The response's `expires_in` tells you the real window. Use it instead of a hard-coded number.
- The new expiry is the shortest of now plus the interval, the token's own `exp`, and the parent lease's expiry. It never shortens an existing lease. When the token itself is about to expire, renewing cannot help. Ask for a new token through an exchange.
- Renewal fails with `400 invalid_grant` and `detail` `lease_revoked`, `lease_expired` or `lease_unknown` when the lease or an ancestor is in that state. A revoked lease is final. Stop.
- An expired token gets 401. Mint a new one.
- Every renewal is one audit row. Do not renew faster than you need to.

A client that has finished should simply stop renewing. The lease lapses on its own. There is no "release" call in v0. The operator can revoke at once if needed with `attenuo lease revoke <id>`.

A sub-agent that crashes and stops renewing is denied within one interval. A revoke is immediate.

## Using the AuthZEN endpoint from a non-MCP PEP

You do not need MCP to use attenuo. `POST /access/v1/evaluation` is an [OpenID AuthZEN](https://openid.net/wg/authzen/) Authorization API endpoint. Anything that enforces policy, such as an API gateway, a sidecar, a function wrapper or a service that guards its own routes, can send it a question and enforce the answer. The same pipeline decides, so you get the same lease check, the same capability check, the same Cedar policy and the same audit record as the proxy path.

The discovery document is at `/.well-known/authzen-configuration`.

The simplest form sends the delegation token as the bearer and describes the call in the body:

```sh
curl -s -X POST https://attenuo.example.com/access/v1/evaluation \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "subject":  { "type": "agent", "id": "" },
    "action":   { "name": "create_issue", "properties": { "server": "github" } },
    "resource": { "type": "tool", "id": "github/create_issue",
                  "properties": { "server": "github", "tool": "create_issue" } },
    "context":  { "input": { "repo": "acme/api", "title": "x" } }
  }'
```

An allow:

```json
{
  "decision": true,
  "context": {
    "reason": "policy_allow",
    "policy_ids": ["permit_create_issue_in_acme"],
    "diagnostics": [],
    "decision_id": "97474e21-9d8a-4d2d-bd55-5ee4b9eb278f"
  }
}
```

A deny has `"decision": false` and a `reason` from the same list as above. `diagnostics` explains it in prose, but only to callers `[authzen] diagnostics` allows: by default a PEP that authenticates as a `[[peps]]` entry (add `pep_id` and `pep_secret` to the body next to the bearer token). Everyone else gets an empty list, since the prose names the token's effective capabilities and lease ids. Prose may change between versions, so branch on `reason`.

Field notes:

- `subject.type` must be `agent`. An empty `subject.id` is filled from the token's current agent.
- `action.name` is the tool name. The server name comes from `action.properties.server` or `resource.properties.server`. `resource.type` is `tool`.
- Tool arguments go in `context.input`. An optional `context.session_id` is passed to policy. (Through the MCP proxy, policy sees a 12-hex-digit hash prefix of the `Mcp-Session-Id`, not the id.)
- The chain comes from the verified token. If you also send `subject.properties.chain`, it must equal the token's chain, or you get 400 `chain_mismatch`.
- The call is audited as an ordinary decision, so the `decision_id` points at a real row.
- Each question is a decision, and it is logged. Ask once per action you will enforce.

The CLI does the same: `ATTENUO_TOKEN="$TOKEN" attenuo authzen eval --upstream github --tool create_issue --arg repo=acme/api --arg title=x`. It exits 2 on a negative decision.

**Without a bearer.** By default a request without a bearer gets 401. An operator can allow PEPs that cannot carry the token to send the chain in `subject.properties.chain` instead, with `[authzen] allow_unsigned_chain = true` and a `[[peps]]` entry per PEP. The PEP then authenticates with its client secret (HTTP Basic, or `pep_id` and `pep_secret` at the top level of the body), or, when its entry holds `jwks`, with a client assertion (`client_assertion_type` and `client_assertion` at the top level of the body, one per request; [details](../reference/http-api.md#client-authentication)). The server checks that the chain is well-formed, and that every hop's lease is live and was issued for exactly that chain prefix; a chain it never issued, or one with any field changed, is 403 `chain_not_issued`. Prefer the bearer.

**Enforcing the answer.** attenuo only answers. The PEP has to refuse the action on `false`, and refuse it when the call to attenuo fails. A PEP that fails open turns attenuo off. Revocation reaches a PEP only when it asks, since there is no push channel in v0. Do not cache an allow for longer than you are willing to leave a revoked agent running.

## A checklist for client authors

- Send the bearer on every request to `/mcp/<name>`.
- Keep the token and its lease id together, per agent.
- Treat `-32003` as a decision. Branch on `data.reason`. Never retry blindly.
- Log `decision_id`.
- Renew your lease at a third of the interval, and stop on `lease_revoked`. The Python (`TokenRefresher`) and TypeScript (`TokenRefresher`) SDKs do this, and re-exchange before `exp`, for you.
- Refresh the root token before it expires. Tokens last `default_ttl_seconds` (900 by default). A parent token delegates to a given actor once, so a refresh needs a fresh subject token, not the same one again.
- Hand sub-agents the narrowest token that does the job, with the shortest TTL that does the job.
- Where a workload identity exists (SPIFFE, a cloud workload token), authenticate exchanges with an `actor_token` rather than a shared secret, one fresh token per exchange. Set `may_act` on tokens meant for one specific sub-agent.
- Keep tokens out of prompts, tool arguments and logs. A token in a model's context can be leaked by the model.
