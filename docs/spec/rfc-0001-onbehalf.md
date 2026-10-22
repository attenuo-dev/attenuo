# RFC-0001: onbehalf, an authorization and enforcement plane for AI agents

- Status: draft
- Date: 2026-10-22
- Related: [threat model](threat-model.md), [standards](../research/standards.md), [incidents](../research/incidents-2025-2026.md), [ADR-0001](../decisions/0001-separate-enforcement-layer.md), [ADR-0002](../decisions/0002-cedar-for-policy.md)

## 1. Problem

The MCP `2026-07-28` revision settles the transport layer: servers are OAuth 2.1 resource servers, clients send resource indicators, registration uses Client ID Metadata Documents ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)). It does not settle what happens after the token. The token is issued to the agent and "has no slot for the human the agent acts for"; scopes are coarse and fixed at issue time and cannot see call arguments; "no widely adopted standard slot reliably carries 'which human is this agent acting for' across every hop of a delegation chain" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). Servers "see user or service tokens, not which agent acted for which user, so audit logs can't distinguish agent actions from user actions" ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)). Withdrawal of in-flight decisions is "not addressed by most implementations" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

The 2025-2026 incident record is mostly over-privilege, missing isolation and missing audit, not model failure: the May 2025 GitHub MCP leak paired prompt injection with an over-privileged PAT; Smithery leaked a platform token controlling 3,000+ apps; the WhatsApp MCP server exfiltrated message history while "evading DLP tooling" ([AuthZed](https://authzed.com/blog/timeline-mcp-breaches)). See the [incident list](../research/incidents-2025-2026.md).

onbehalf is a self-hosted, IdP-neutral reference monitor that sits between agent clients and MCP tool servers. It issues attenuated delegation tokens, authorizes every tool call against a policy that sees the arguments, revokes in-flight runs, and records every decision in a tamper-evident log.

## 2. Guaranteed properties

Let a *run* be a tree of hops rooted at an originating user `u`. Hop `h_n` is an agent acting with capability set `C_n`.

- **P1. Verified originating user on every hop.** Every token onbehalf issues carries an `obo` block naming `u`, derived only from a credential verified against the user's IdP (ID token, ID-JAG, or a parent onbehalf token whose `obo` was itself verified). A request without a verifiable `obo` is rejected, never defaulted.
- **P2. Monotonic attenuation.** For every parent/child pair, `C_{n+1} ⊑ C_n`, `exp_{n+1} ≤ exp_n`, and `depth_{n+1} = depth_n + 1 ≤ max_depth`. Exchange requests that would widen any dimension fail closed. This is checked at issue time and re-checked at call time against the full lineage.
- **P3. Argument-aware per-call authorization.** Every `tools/call` is evaluated as an AuthZEN-shaped request whose context contains the call arguments, the originating user, chain depth, and session/time. A call is forwarded only on an explicit `permit`. Deny is the default.
- **P4. Tamper-evident audit and in-flight revocation.** Every decision, token issuance, lease renewal and revocation is appended to a hash-chained log. Every token is bound to a lease; a revoked lease (or any ancestor lease) causes the next call to be denied within one lease interval.

P2 and P4 are the invariants that must carry property tests, not only unit tests ([CONTRIBUTING](../../CONTRIBUTING.md)).

## 3. Delegation-chain data model

```json
{
  "chain_id": "dc_01JAXK3V9P",
  "originating_user": {
    "iss": "https://idp.example.com",
    "sub": "u_8f2a",
    "email": "alice@example.com",
    "auth_time": 1761134400,
    "amr": ["pwd", "mfa"],
    "evidence": { "type": "id-jag", "jti": "jag_7c1d", "digest": "sha256:9b1e…" }
  },
  "max_depth": 3,
  "hops": [
    {
      "depth": 0,
      "actor": "spiffe://example.com/agent/planner",
      "jti": "tok_a1",
      "lease_id": "lease_a1",
      "exp": 1761138000,
      "caps": [
        { "server": "github", "tool": "*", "constraints": { "repo": ["acme/public-site", "acme/docs"] } },
        { "server": "mail", "tool": "send", "constraints": { "to_domain": ["acme.com"] } }
      ]
    },
    {
      "depth": 1,
      "actor": "spiffe://example.com/agent/coder",
      "parent_jti": "tok_a1",
      "jti": "tok_b7",
      "lease_id": "lease_b7",
      "exp": 1761137400,
      "caps": [
        { "server": "github", "tool": "create_issue", "constraints": { "repo": ["acme/public-site"] } }
      ]
    }
  ]
}
```

**Capability.** `(server, tool, constraints)`. `tool` is a name or `*`. `constraints` is a map from argument name to an allowed set (or range, for numeric and time types).

**Attenuation rule (`⊑`).** `C_{n+1} ⊑ C_n` iff every `c' ∈ C_{n+1}` is dominated by some `c ∈ C_n`, where `c ⊑' c'` holds when:
1. `c'.server == c.server`;
2. `c.tool == "*"` or `c'.tool == c.tool`;
3. for every key `k` in `c.constraints`, `k` is present in `c'.constraints` and `c'.constraints[k] ⊆ c.constraints[k]`;
4. `c'` may add keys that `c` lacks (adding a constraint only narrows).

The empty capability set is valid. A child can never gain a server, tool, or argument value its parent lacked. The same rule is applied as a policy predicate at call time, so a forged or replayed child token still cannot exceed its lineage. This is the "permissions can only be narrowed" discipline AgentGate formalizes for single-session chains ([NeurIPS 2026](https://neurips.cc/virtual/2026/168219)) and the `containsAll` subset check in AWS's Cedar sample ([AWS Security Blog](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/)), applied here across hops and services.

## 4. Token exchange

onbehalf exposes an RFC 8693 token-exchange endpoint. Each hop is one exchange.

**Hop 0: entering from the IdP.** The agent client presents a user credential as `subject_token`: an OIDC ID token, or an ID-JAG issued by the enterprise IdP under the Cross-App Access profile that Okta's Agent SSO and Descope ship today ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)). onbehalf verifies it against the IdP's JWKS, extracts `originating_user`, and mints a hop-0 token whose `caps` are the intersection of the requested capabilities, the user's policy-derived ceiling, and the client's registration.

**Hop n+1: agent to sub-agent.**

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<parent onbehalf token tok_a1>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&actor_token=<sub-agent workload credential, e.g. SPIFFE JWT-SVID>
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
&authorization_details=[{"type":"mcp_tool","server":"github","tool":"create_issue","constraints":{"repo":["acme/public-site"]}}]
```

`authorization_details` uses the RAR (RFC 9396) shape so requested capabilities are structured, not scope strings ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)). onbehalf checks `requested ⊑ parent.caps`, that `parent.obo` is present and verified, that depth and expiry narrow, and that the parent's lease is live. The response is a JWT:

```json
{
  "iss": "https://onbehalf.example.com",
  "sub": "spiffe://example.com/agent/coder",
  "aud": "https://onbehalf.example.com/proxy",
  "jti": "tok_b7",
  "exp": 1761137400,
  "act": { "sub": "spiffe://example.com/agent/planner", "jti": "tok_a1" },
  "obo": { "iss": "https://idp.example.com", "sub": "u_8f2a", "amr": ["pwd","mfa"], "auth_time": 1761134400 },
  "chain_id": "dc_01JAXK3V9P",
  "depth": 1,
  "lease": { "id": "lease_b7", "ttl": 30 },
  "cap": [
    { "server": "github", "tool": "create_issue", "constraints": { "repo": ["acme/public-site"] } }
  ]
}
```

`act` nests per RFC 8693 so the full actor chain is recoverable from the token alone. `may_act` on a token restricts which workloads may later present it as `subject_token`; when present, onbehalf enforces it against `actor_token`. The `obo` block is signed with the token, which replaces the detached HMAC side-channel AWS uses for `context.originating_user` ([AWS Security Blog](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/)).

## 5. Per-call authorization

The proxy intercepts MCP `tools/call` over streamable HTTP, validates the bearer token, and builds an AuthZEN-shaped request ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)):

```json
{
  "subject":  { "type": "agent", "id": "spiffe://example.com/agent/coder",
                "properties": { "chain_id": "dc_01JAXK3V9P", "depth": 1, "jti": "tok_b7" } },
  "action":   { "name": "create_issue" },
  "resource": { "type": "mcp_tool", "id": "github/create_issue",
                "properties": { "server": "github" } },
  "context": {
    "arguments": { "repo": "acme/public-site", "title": "Fix 404 on /pricing", "labels": ["bug"] },
    "originating_user": { "iss": "https://idp.example.com", "sub": "u_8f2a", "amr": ["pwd","mfa"] },
    "chain_depth": 1,
    "session": { "id": "sess_41", "started_at": 1761134400 },
    "time": "2026-10-22T14:02:11Z",
    "lease_state": "active"
  }
}
```

The same request is served on `POST /access/v1/evaluation` so an external PEP (for example a gateway) can use onbehalf as a PDP. Internally it maps to Cedar: `principal = Agent::"spiffe://…"`, `action = Action::"github/create_issue"`, `resource = Tool::"github/create_issue"`, and the context above as `context`, following the request shape AgentCore uses where arguments are `context.input` and "the model's text is not an input" ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). Two checks run before policy and cannot be overridden by it: capability match (`arguments` must satisfy some `cap` in the token, and that cap must be dominated by the lineage) and lease liveness.

```cedar
forbid (principal, action == Action::"github/create_issue", resource)
  when { !(context.arguments.repo in ["acme/public-site", "acme/docs"]) };

forbid (principal, action, resource)
  when { context.chain_depth > 2 && resource.sensitivity == "high" };

permit (principal, action, resource)
  when { context.originating_user.amr.contains("mfa") };
```

## 6. Revocation via leases

Every token carries a `lease` with a short TTL (default 30 s). The holder renews with `POST /lease/{id}/renew`; the proxy caches lease state for at most one TTL. Revocation targets a user, a session, a chain, or a single token; it marks that lease and all descendant leases revoked. The next call on any affected hop is denied within one TTL, and renewal fails. Because leases form a tree that mirrors `act`, revoking the originating user's session stops every sub-agent of every agent in that run, which is the "withdrawal of in-flight decisions" gap ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). Long human-in-the-loop waits expire the lease; resumption requires a fresh exchange, so a resumed run cannot hold broader authority than policy grants at resume time.

## 7. Audit record and hash chaining

```json
{
  "seq": 104233,
  "ts": "2026-10-22T14:02:11.418Z",
  "kind": "decision",
  "chain_id": "dc_01JAXK3V9P",
  "depth": 1,
  "principal": "spiffe://example.com/agent/coder",
  "originating_user": "https://idp.example.com#u_8f2a",
  "action": "github/create_issue",
  "arguments_digest": "sha256:4c7a…",
  "decision": "deny",
  "determining_policies": ["forbid-private-repo"],
  "token_lineage": ["tok_a1", "tok_b7"],
  "lease_id": "lease_b7",
  "prev_hash": "sha256:e1f0…",
  "hash": "sha256:77ab…"
}
```

`hash = SHA-256(prev_hash || canonical_json(record \ {hash}))` using RFC 8785 canonicalization. The log stores argument digests, not arguments, by default; a per-server policy can opt into storing redacted arguments. A signed checkpoint `(seq, hash)` is emitted every N records and can be anchored externally. Verification is a single pass. Record kinds: `issue`, `decision`, `renew`, `revoke`, `checkpoint`. Every record names the agent and the originating user separately, which is the attribution OWASP MCP08 and Archestra say is missing ([Equixly](https://equixly.com/blog/2026/06/04/mapping-nsa-s-mcp-guidance-to-the-owasp-mcp-top-10-how-to-test-for-the-risks/), [Archestra](https://archestra.ai/blog/state-of-mcp-2026)).

## 8. Non-goals

- Not an OAuth authorization server or IdP. Users authenticate elsewhere; onbehalf consumes IdP-issued credentials.
- Not a general MCP gateway. Routing, rate limits, OTel and tool federation belong to gateways such as AgentGateway; onbehalf plugs in as a PDP ([agentgateway](https://github.com/agentgateway/agentgateway)).
- Not a VMM or sandbox. Isolation sits below onbehalf; the policy model is designed so a sandbox can later enforce the same capabilities ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)).
- Not prompt-injection detection. onbehalf bounds what an injected agent can do; it does not try to detect injection.

## 9. Open questions

1. **Token binding.** Should hop tokens be sender-constrained (`cnf` with DPoP or mTLS/SPIFFE), and at what cost to clients that cannot do either?
2. **Cross-organization chains.** How does `obo` survive when hop n+1 is in another trust domain? ID-JAG and the "crossing-the-trustee problem" are unresolved ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).
3. **Constraint algebra.** Sets and ranges cover most tool arguments; nested objects, globs and regexes make `⊑` undecidable or expensive. Where is the line?
4. **ReBAC composition.** Relationship facts (who owns which repo) are consulted via an external graph (SpiceDB/OpenFGA-style) and projected into Cedar entities; cache consistency with revocation is unsettled ([ADR-0002](../decisions/0002-cedar-for-policy.md)).
5. **Information flow.** Labelling tool outputs as untrusted and forbidding flow into destructive tools without approval would address the WhatsApp/GitHub class directly; it is out of scope for v0.1.
6. **Lease TTL vs. load.** 30 s renewals at agent call rates may need batching or push-based revocation.
