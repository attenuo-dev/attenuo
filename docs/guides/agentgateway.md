# Using attenuo with agentgateway

[agentgateway](https://github.com/agentgateway/agentgateway) is an open-source MCP gateway. Its `extAuthz` policy asks an external service about each request before forwarding it. This guide sets attenuo up as that service, so that the gateway forwards a tool call only when attenuo's proxy would have.

**Run once, against agentgateway v1.7.0.** On 2026-11-16 the setup on this page was run end to end on one machine, everything on 127.0.0.1: agentgateway v1.7.0 (commit `26f5aebe`, built from source without the UI), attenuo, and `fake_mcp` as the MCP server, with plain HTTP requests and the MCP Python SDK 2.3.0 as clients. [What was run](#what-was-run) lists each case and its result; `scripts/agentgateway-smoke.sh` repeats the allowed and the denied call (not part of CI). Other agentgateway versions, TLS, a gateway on another host, and the parts this page tells you not to use were not run. attenuo's side is also tested without a gateway (`crates/attenuo-server/tests/ext_authz.rs`), with a stand-in that sends what agentgateway sent in that run.

## Two ways to put attenuo behind a gateway

1. **Gateway in front of attenuo's proxy.** Point the gateway's MCP target at attenuo's `/mcp/<server>`, and attenuo's proxy at the MCP server. No adapter is involved. attenuo sees the answers too, so output labelling, list filtering and the stream re-check all work. Prefer this when an extra hop is acceptable. It has not been tried, and DPoP-bound tokens do not pass that way: the agent's proof names the gateway's URL, which attenuo's proxy does not accept.
2. **attenuo as the gateway's authorizer** (this guide). The gateway talks to the MCP server itself and asks attenuo first. attenuo decides each request exactly as its proxy would, but never sees the answers. The [design note](../design/agentgateway-ext-authz.md) lists what that leaves out.

## What happens on a request

1. The agent sends its MCP request to the gateway with its attenuo delegation token as the bearer (and a DPoP proof made for the gateway's URL, if the token is bound to a key).
2. The gateway sends attenuo a check request: the agent's method, a fixed path `/ext-authz/v1/mcp/<server>`, the agent's `Authorization` and `DPoP` headers, a shared secret, and the agent's body.
3. attenuo checks the secret, the token and the body, and decides the JSON-RPC message with the proxy's code. Allowed: 200. Otherwise the proxy's error, with a non-2xx status.
4. On 200 the gateway forwards the request to the MCP server. On anything else it sends attenuo's answer to the agent: its status, headers and body. A `tools/call` that policy denies reaches the agent as HTTP 403 with `content-type: application/json`, an `x-attenuo-decision-id` header and the usual JSON-RPC error (`-32003`, `data.reason`, `data.decision_id`). The MCP Python SDK 2.3.0 raises it as an `MCPError` with that code and data.

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

This is the configuration that was run with agentgateway v1.7.0, with the ports changed back. Replace the secret, the hosts and the target.

```yaml
# yaml-language-server: $schema=https://agentgateway.dev/schema/config
gateways:
  default:
    port: 3000
    bindAddress: 127.0.0.1             # leave out to listen on every interface
mcp:
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

- **`gateways`** sets the port agents call and the address it listens on; the `mcp:` routes attach to the gateway named `default`. `mcp.port` still loads in v1.7.0 but is marked deprecated, and it always listens on every interface (`[::]`, or `0.0.0.0` with `config.enableIpv6: false`); on a host without IPv6 it did not start.

- **`path`** must be a fixed string. It names the server attenuo decides for; the secret must belong to that server's `[[ext_authz]]` entry, so a route cannot ask about another server.
- **`includeRequestBody`** must be set and **`allowPartialMessage`** left false. attenuo refuses every request without `x-envoy-auth-partial-body: false`, which the gateway sends, on `GET` and `DELETE` too, only with a whole body. A body over `maxRequestBytes` is refused by the gateway itself with 413 and the text body `authorization failed`, and attenuo is not asked (default 8192 bytes, which a large tool call can pass). With `allowPartialMessage: true` attenuo gets the first `maxRequestBytes` bytes and `x-envoy-auth-partial-body: true`, and answers 403 `ext_authz_body_incomplete`; without `includeRequestBody` the header is missing and the answer is the same. Do not set `protocol.http.body`: it replaces the agent's body.
- **`failureMode`** must be `deny` (the default) or `denyWithStatus`, never `allow`. It decides what happens when attenuo cannot be reached or does not answer within the gateway's 2 second default. With attenuo stopped, `deny` and an unset `failureMode` answered every request with 403 and the text body `authorization failed`, and `denyWithStatus: 503` with 503 and the same text: the gateway fails closed. With `failureMode: allow` the gateway failed open: the `tools/call` went to the MCP server with no decision and no audit record. A listener that accepted the connection and never answered gave the same 403 after 2.0 seconds.
- **No `cache`.** A cached allow is replayed without asking attenuo: no lease check, no run-limit charge, no audit record, and a DPoP proof would no longer be single use.
- **One target per route**, with the default `prefixMode`. attenuo decides on the tool name in the agent's body; with several targets the gateway adds and strips a `<target>_` prefix, and the names would not match the catalog.
- **`requestHeaderModifier`** keeps the agent's attenuo token away from the MCP server. agentgateway forwards `Authorization` upstream by default; with this setting the MCP server received neither `Authorization` nor `DPoP`.
- **The config file is rewritten.** On its first start without `SESSION_KEY` set, agentgateway v1.7.0 generates a session key and writes it into the config file as `config.session.key`. Keep the file's permissions tight: it holds the gateway secret and then that key.
- **The MCP server must be reachable only through the gateway**, as it must be only through attenuo's proxy otherwise.

`includeResponseHeaders: [x-attenuo-decision-id]` under `protocol.http` copies the decision record's id into the upstream request, if the MCP server should log it (checked in the run). The agent does not see that header on an allowed call.

## What agents change

Nothing but the URL: the agent sends its MCP requests to the gateway with its attenuo token as the bearer, as it would to attenuo's proxy. A DPoP-bound token needs `dpop_url` set to the URL the agent calls, and proofs made for that URL; without `dpop_url` attenuo refuses any request that carries a proof (`ext_authz_dpop_url_unset`).

## What you lose compared with attenuo's proxy

- No output labelling: tool results are not recorded or labelled, and do not taint the run. Policies that ask for approval after untrusted output do not see such output. AuthZEN callers have the same limit.
- No list filtering: the agent sees the MCP server's full `tools/list`.
- Revocation is seen at the next request; an open listen stream is not ended.
- Sessions are not bound to the agent that opened them by attenuo, and Cedar sees no `context.session_id`.
- JSON-RPC batches are refused (`ext_authz_batch_unsupported`).
- Bodies that parsers can read differently (a member named twice, two member names that differ only in case such as `name` and `Name`, a number written in a form serde_json would write differently, such as `1e3` or `1.50`) are refused (`ext_authz_ambiguous_body`), because the MCP server receives the gateway's reading of the agent's bytes, not attenuo's. agentgateway v1.7.0 parses each message and sends its own encoding of it (it adds `params._meta`, moves members and writes `1e3` as `1000.0`); for the bodies tried, its reading matched attenuo's, but nothing ties a gateway version to that.
- An approval token in `params._meta["dev.attenuo/approval"]` reaches the MCP server, which the proxy would have removed. The gateway kept the agent's `params._meta` members in the run.

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

`200` with an `x-attenuo-decision-id` header means the gateway would forward the call; `attenuo audit tail` shows the record. agentgateway v1.7.0 sent exactly these headers in the run (plus `host` and `content-length`), with no `content-type`, and on `GET` and `DELETE` the same headers with no body.

## What was run

On 2026-11-16, on one Linux machine, all on 127.0.0.1: agentgateway v1.7.0 (commit `26f5aebe`, built from source without the UI) with the configuration above (other ports, and `config.adminAddr`, `statsAddr` and `readinessAddr` moved to free loopback ports), attenuo from this repository with the `[[ext_authz]]` entry above and no `[[upstreams]]`, and `fake_mcp` from [Getting started](getting-started.md) as the MCP server. The token was a `coder` token that may call `github:read_file` only, as in Getting started. Clients: plain HTTP requests (initialize, `notifications/initialized`, `tools/list`, `tools/call`, `GET`, `DELETE`) and the MCP Python SDK 2.3.0. One case at a time, the gateway's configuration was changed as the table says.

| Case | Expected from this page | What the agent got |
| --- | --- | --- |
| `initialize`, `tools/list` | forwarded after a lease check | 200 (`text/event-stream`), the MCP server's answer; `notifications/initialized` 202 |
| Allowed `tools/call` (`read_file`) | 200 from attenuo, forwarded once, allow recorded | 200 with the MCP server's result; `fake_mcp` saw the call once; `attenuo audit tail` shows `ALLOW github/read_file ... reason=policy_allow` with its id |
| Denied `tools/call` (`create_issue`) | 403 with JSON-RPC `-32003` | 403, `application/json`, `x-attenuo-decision-id`, `{"jsonrpc":"2.0","id":4,"error":{"code":-32003,"message":"attenuo: denied: capability_denied","data":{"reason":"capability_denied","decision_id":"...","code":"capability_denied"}}}`; not forwarded; the Python SDK raised `MCPError(-32003, ...)` |
| No token | 401 | 401, `www-authenticate: Bearer realm="attenuo"`, JSON-RPC `-32001` `missing_token`; a malformed token: `invalid_token` |
| Wrong secret on the gateway | 403 `ext_authz_unauthenticated` | 403 `ext_authz_unauthenticated` on every request, `initialize` included |
| Body over `maxRequestBytes` (1 MiB, and the 8192 default) | 413 from the gateway | 413, `text/plain`, `authorization failed`; attenuo was not called. A body of 8000 bytes passed the default limit, one of 9000 did not |
| `allowPartialMessage: true` (limit 1024, a 2000-byte body) | 403 `ext_authz_body_incomplete` | attenuo got 1024 bytes and `x-envoy-auth-partial-body: true`; 403 `ext_authz_body_incomplete` |
| No `includeRequestBody` | 403 `ext_authz_body_incomplete` | no `x-envoy-auth-partial-body`, no body; 403 `ext_authz_body_incomplete` |
| `GET` (listen stream) | 200 from attenuo, then the stream | attenuo answered 200 and the gateway forwarded the `GET`. `fake_mcp` has no listen stream and answered 405, which reached the agent; with the MCP Python SDK's server as the upstream the stream opened (200, `text/event-stream`) |
| `DELETE` (session) | 200 from attenuo, then forwarded | 202 from the MCP server through the gateway |
| Lease revoked while a `GET` stream was open | stream stays open, next request refused | the stream stayed open; the next `tools/call` got 403 `lease_revoked`, the next `GET` 401 `lease_revoked` |
| DPoP-bound token, `dpop_url` unset | 401 `ext_authz_dpop_url_unset` | 401 `ext_authz_dpop_url_unset` |
| DPoP-bound token, `dpop_url` set to the URL the client called on the gateway (`http://127.0.0.1:<port>/mcp`) | allowed and denied as with a bearer token | `Authorization: DPoP` and a proof for the gateway URL: allowed and denied calls as above; no proof: 401 `dpop_required`; the same proof twice: 401 `invalid_dpop_proof` |
| attenuo stopped, `failureMode: deny` or unset | gateway refuses | 403, `text/plain`, `authorization failed` |
| attenuo stopped, `denyWithStatus: 503` | 503 | 503, `authorization failed` |
| attenuo stopped, `failureMode: allow` | not to be used | the call reached the MCP server: fails open |
| attenuo accepts the connection and never answers | refused after 2 s | 403 `authorization failed` after 2.0 s |

Not run: agentgateway versions other than v1.7.0; TLS anywhere; a gateway, attenuo or MCP server on another host; `cache`; more than one target or another `prefixMode`; the gRPC mode; a JSON-RPC batch through the gateway; an approval flow; load of any kind.
