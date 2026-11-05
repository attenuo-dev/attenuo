# Enforcement points

A decision is only useful if something enforces it. attenuo has one decision pipeline and two ways to reach it. You can use either, or both.

## One pipeline

For every call, `Pipeline::decide` does these things in order:

1. Check the lease of every hop in the chain.
2. Read the run's state: whether it has read untrusted tool output, and what its run limits have left.
3. Take a granted approval for exactly this call, if there is one.
4. Ask the policy engine: the capability stage first (including the run limits, which deny with `budget_exhausted`), then Cedar.
5. For an allowed call, charge its run limits.
6. Append a record to the audit log.

If any step fails, the answer is deny. A Cedar deny that comes only from forbids marked `@obligation("approval")` opens an approval instead, and the proxy answers `-32008` with its id. Both enforcement points call the same code. They cannot disagree.

## The MCP proxy

The proxy is a reverse proxy for MCP over streamable HTTP. Each upstream is mounted at `/mcp/{server}`. An agent points its MCP client at that URL and sends its delegation token as the bearer.

For each request the proxy verifies the token, then asks the pipeline. On allow, it forwards the request to the upstream. It does not pass the attenuo token on. On deny, it answers with a JSON-RPC error (`-32003`) that carries the reason and the decision id. When the policy asks for an approval, the error is `-32008` and also carries the approval id. After an allowed call, the proxy records the upstream's answer in the audit log before relaying it. A bad or expired token gets HTTP 401 and `-32001`.

The proxy is the enforcement point. The agent cannot skip it, because the upstream is only reachable through it. Run the upstream where the agent cannot reach it directly.

Use the proxy when you control how agents reach MCP servers and want enforcement with no code changes in the agent.

The proxy covers `tools/call` and also maps `resources/read`, `prompts/get` and some other methods onto the same decision. Unknown methods are denied by default.

## The AuthZEN endpoint

`POST /access/v1/evaluation` follows the AuthZEN evaluation shape, and `POST /access/v1/evaluations` takes a batch of them. It lets some other component ask attenuo for a decision and enforce it itself. That component might be an API gateway, a tool server or a sandbox. attenuo then acts as a policy decision point (PDP) and the other component is the policy enforcement point (PEP).

There is a discovery document at `/.well-known/authzen-configuration`.

The chain can arrive two ways:

- **With a bearer token.** The chain comes from the verified token. This is the safe way.
- **Without a bearer.** Off by default: a request with no bearer gets 401. With `[authzen] allow_unsigned_chain = true`, a PEP listed under `[[peps]]` that authenticates (HTTP Basic, or `pep_id` and `pep_secret` in the body) may send the chain in `subject.properties.chain`. The chain carries no signatures, so every hop must match what this server issued for its lease (leases are bound to a digest of the chain at issuance), or the request gets 403 `chain_not_issued`. It then has to pass the lease check like any other chain.

The call arguments go in `context.input`. The response includes a decision id.

Use AuthZEN when the thing that makes the call is not an MCP client you control, or when a gateway already sits in the path.

## Choosing

| | Proxy | AuthZEN |
| --- | --- | --- |
| Who enforces | attenuo | The caller of the endpoint |
| Protocol | MCP over HTTP | AuthZEN evaluation |
| Agent changes needed | Point at `/mcp/{server}` | None, but the PEP must call the endpoint |
| If the PEP skips the call | Not possible when the upstream is private | Nothing stops the call |
| Revocation | Seen on the next request | Seen only when the PEP asks |

Both paths write to the same audit log.

## Limits today

- There is no push channel, so a PEP that caches decisions will not learn of a revocation.
- Admin routes use one static bearer and should not be public.
- AuthZEN conformance is checked by fixtures in `crates/attenuo-server/tests/fixtures/authzen/`; what is and is not implemented is in [AuthZEN conformance](../reference/authzen.md). The Search APIs are not served.

More detail: [design/server.md](../design/server.md#the-decision-pipeline), [ADR-0001](../decisions/0001-separate-enforcement-layer.md) and [RFC-0001 section 5](../spec/rfc-0001-attenuo.md#5-per-call-authorization).
