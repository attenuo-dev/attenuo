# ADR-0001: Enforce delegation and per-call authorization in a separate layer

- Status: accepted
- Date: 2026-10-22

## Context

Three places could hold the guarantees in [RFC-0001](../spec/rfc-0001-attenuo.md): the MCP protocol itself, each MCP server, or a separate component between client and server.

- The MCP `2026-07-28` spec covers token audience and per-server scopes; "whether a specific tool call is allowed for a specific user is left to the server or a gateway" ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). Authorization support in MCP is optional, and the spec covers authentication and token handling, not fine-grained authorization ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).
- The incident record shows both ends of the connection failing: clients get prompt-injected or exploited (GitHub MCP, mcp-remote, Cursor CVEs), and servers ship over-privileged, cross-tenant, or outright malicious (Asana, Smithery, Postmark) ([AuthZed](https://authzed.com/blog/timeline-mcp-breaches)).
- Audit needs a vantage point that sees agent, user and call together; servers "see user or service tokens, not which agent acted for which user" ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)).
- The relevant standards are drafts: ID-JAG at -04, the IETF agentproto working group "active but contested", the AuthZEN MCP binding at Draft 1 ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/), [Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

## Decision

Build attenuo as a separate reference monitor: a proxy and PDP that both the agent client and the MCP server are untrusted relative to. It verifies tokens, applies attenuation and policy, and writes the audit log; neither endpoint can skip it for traffic that flows through it.

Three consequences of the reference-monitor framing are design rules:

1. **Complete mediation** for the transport it covers: every `tools/call` over streamable HTTP passes the same check; there is no bypass flag.
2. **Tamper-evidence**: the monitor's own state (keys, leases, log) is the trusted base, kept small and tested.
3. **Verifiability**: the attenuation and lease invariants are stated as predicates and covered by property tests ([CONTRIBUTING](https://github.com/attenuo-dev/attenuo/blob/main/CONTRIBUTING.md)).

## Consequences

- Positive: works with any MCP server and any client today, without waiting for protocol changes; a single place for policy, revocation and audit; the same component can serve as an AuthZEN PDP for gateways.
- Positive: the implementation can feed interop reports into the drafts it tracks, which is how reference implementations have shaped identity standards before (the SPIFFE path noted at [QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)).
- Negative: traffic that does not pass through the proxy (STDIO servers, direct API keys) is unprotected; see [threat model](../spec/threat-model.md).
- Negative: one more hop of latency per call; must be measured and kept small.
- Negative: argument-level policy sees requests, not server behaviour; server-side misbehaviour needs a sandbox layer, which is a non-goal here.

## Alternatives considered

- **Change the MCP protocol** to carry delegation chains and per-call authorization. Right scope eventually, but the spec is settling transport and auth, revisions take months, and both endpoints would still have to be trusted to implement it correctly. A working implementation is a better input to that process than a proposal.
- **In-server checks** (each server validates the originating user and arguments). Puts the security argument in the least trusted, most numerous component; thousands of public servers would each need to get it right, and the incident list shows they do not.
- **In-client checks** (the agent framework enforces policy). The client is the component that gets prompt-injected; text-based deny patterns in agent clients are "not a security boundary" per the clients' own documentation ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)).
- **Only a gateway plugin.** Gateways are the right enforcement point in many deployments, but tying the model to one gateway's extension API would make the guarantees depend on it. attenuo stands alone and also exposes the PDP interface gateways can call.
