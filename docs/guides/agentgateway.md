# Using attenuo with agentgateway

[agentgateway](https://github.com/agentgateway/agentgateway) is an open-source MCP gateway. Its `extAuthz` policy asks an external service about each request before forwarding it. This guide sets attenuo up as that service, so that the gateway forwards a tool call only when attenuo's proxy would have.

**Not run against a real agentgateway.** attenuo's side is tested (`crates/attenuo-server/tests/ext_authz.rs`) with a fake gateway that sends what agentgateway's source sends, read at commit `18f8370` (2026-11-13). The agentgateway configuration below was written from that source and its schema; it has not been loaded into agentgateway or run.

## Two ways to put attenuo behind a gateway

1. **Gateway in front of attenuo's proxy.** Point the gateway's MCP target at attenuo's `/mcp/<server>`, and attenuo's proxy at the MCP server. No adapter is involved. attenuo sees the answers too, so output labelling, list filtering and the stream re-check all work. Prefer this when an extra hop is acceptable. It has not been tried, and DPoP-bound tokens do not pass that way: the agent's proof names the gateway's URL, which attenuo's proxy does not accept.
2. **attenuo as the gateway's authorizer** (this guide). The gateway talks to the MCP server itself and asks attenuo first. attenuo decides each request exactly as its proxy would, but never sees the answers. The [design note](../design/agentgateway-ext-authz.md) lists what that leaves out.

## What happens on a request

1. The agent sends its MCP request to the gateway with its attenuo delegation token as the bearer (and a DPoP proof made for the gateway's URL, if the token is bound to a key).
2. The gateway sends attenuo a check request: the agent's method, a fixed path `/ext-authz/v1/mcp/<server>`, the agent's `Authorization` and `DPoP` headers, a shared secret, and the agent's body.
3. attenuo checks the secret, the token and the body, and decides the JSON-RPC message with the proxy's code. Allowed: 200. Otherwise the proxy's error, with a non-2xx status.
4. On 200 the gateway forwards the request to the MCP server. On anything else it sends attenuo's answer to the agent. A `tools/call` that policy denies reaches the agent as HTTP 403 with the usual JSON-RPC error (`-32003`, `data.reason`, `data.decision_id`).

## attenuo

Make a secret for the gateway and put its SHA-256 in the server config:

```sh
SECRET=$(openssl rand -hex 32)
printf %s "$SECRET" | sha256sum
```

```toml
[[ext_authz]]
server = "github"                          # the server name in capabilities and policies
secret_sha256 = "<the sha256sum output>"
# Only for DPoP-bound tokens: the URL agents call on the gateway.
# dpop_url = "https://gateway.example/mcp"

[policy.catalog.github]
# ... the tools of this server, as for a proxied server
```

The route is on the main listener (`[server] listen`), like `/mcp/<server>`. Requests to it share `[proxy] max_request_body_bytes`, `[limits] mcp_requests_per_minute` and `[limits] max_in_flight` with the proxy, and `[limits] request_timeout_seconds` bounds them as it bounds the routes other than `/mcp/<server>`. Keep the secret out of logs and version control; anyone who has it, and an agent's token, can ask attenuo for decisions in that agent's name (each one recorded and charged as a real call).

## agentgateway

Not run against agentgateway (see the top of the page). Replace the secret, the hosts and the target.

```yaml
# yaml-language-server: $schema=https://agentgateway.dev/schema/config
mcp:
  port: 3000
  targets:
  - name: github
    mcp:
      host: http://127.0.0.1:3001/mcp
  policies:
    extAuthz:
      host: 127.0.0.1:8080              # attenuo's [server] listen
      protocol:
        http:
          # A CEL string literal: the same path for every request of this route.
          path: '"/ext-authz/v1/mcp/github"'
          addRequestHeaders:
            x-attenuo-gateway-secret: '"REPLACE_WITH_SECRET"'
      # The list replaces the default (Authorization only), so name both.
      includeRequestHeaders: [authorization, dpop]
      # The whole JSON-RPC body. Leave allowPartialMessage unset (false).
      includeRequestBody:
        maxRequestBytes: 1048576
      failureMode: deny
    # Runs after extAuthz: the upstream never sees the agent's attenuo token or proof.
    requestHeaderModifier:
      remove: [authorization, dpop]
```

What each part is for, and what to keep:

- **`path`** must be a fixed string. It names the server attenuo decides for; the secret must belong to that server's `[[ext_authz]]` entry, so a route cannot ask about another server.
- **`includeRequestBody`** must be set and **`allowPartialMessage`** left false. attenuo refuses every request without `x-envoy-auth-partial-body: false`, which the gateway sends only with a whole body. A body over `maxRequestBytes` is refused by the gateway with 413 (default 8192 bytes, which a large tool call can pass). Do not set `protocol.http.body`: it replaces the agent's body.
- **`failureMode`** must be `deny` (the default) or `denyWithStatus`, never `allow`. When attenuo cannot be reached or does not answer within the gateway's 2 second default, the gateway then refuses the request.
- **No `cache`.** A cached allow is replayed without asking attenuo: no lease check, no run-limit charge, no audit record, and a DPoP proof would no longer be single use.
- **One target per route**, with the default `prefixMode`. attenuo decides on the tool name in the agent's body; with several targets the gateway adds and strips a `<target>_` prefix, and the names would not match the catalog.
- **`requestHeaderModifier`** keeps the agent's attenuo token away from the MCP server. agentgateway forwards `Authorization` upstream by default.
- **The MCP server must be reachable only through the gateway**, as it must be only through attenuo's proxy otherwise.

`includeResponseHeaders: [x-attenuo-decision-id]` under `protocol.http` copies the decision record's id into the upstream request, if the MCP server should log it.

## What agents change

Nothing but the URL: the agent sends its MCP requests to the gateway with its attenuo token as the bearer, as it would to attenuo's proxy. A DPoP-bound token needs `dpop_url` set to the URL the agent calls, and proofs made for that URL; without `dpop_url` attenuo refuses any request that carries a proof (`ext_authz_dpop_url_unset`).

## What you lose compared with attenuo's proxy

- No output labelling: tool results are not recorded or labelled, and do not taint the run. Policies that ask for approval after untrusted output do not see such output. AuthZEN callers have the same limit.
- No list filtering: the agent sees the MCP server's full `tools/list`.
- Revocation is seen at the next request; an open listen stream is not ended.
- Sessions are not bound to the agent that opened them by attenuo, and Cedar sees no `context.session_id`.
- JSON-RPC batches are refused (`ext_authz_batch_unsupported`).
- Bodies that parsers can read differently (a member named twice, two member names that differ only in case such as `name` and `Name`, a number written in a form serde_json would write differently, such as `1e3` or `1.50`) are refused (`ext_authz_ambiguous_body`), because the MCP server receives the agent's bytes, not attenuo's reading of them.
- An approval token in `params._meta["dev.attenuo/approval"]` reaches the MCP server, which the proxy would have removed.

The full list, with the reasons: [design note](../design/agentgateway-ext-authz.md#4-what-is-not-covered). Refusals and their codes: [HTTP API](../reference/http-api.md#gateway-external-authorization).

## Checking attenuo's side by hand

This is the request the gateway sends for a `tools/call`, written as `curl`. `$SECRET` is the secret from above and `$TOKEN` an agent's delegation token (`$CODER` in [Getting started](getting-started.md) is one):

```sh
curl -i http://127.0.0.1:8080/ext-authz/v1/mcp/github \
  -H "authorization: Bearer $TOKEN" \
  -H "x-attenuo-gateway-secret: $SECRET" \
  -H "x-envoy-auth-partial-body: false" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"acme/api"}}}'
```

`200` with an `x-attenuo-decision-id` header means the gateway would forward the call; `attenuo audit tail` shows the record.
