# RFC-0001: onbehalf, an authorization and enforcement plane for AI agents

- Status: draft (implementation v0 in progress)
- Date: 2026-10-22
- Related: [threat model](threat-model.md), [standards](../research/standards.md), [incidents](../research/incidents-2025-2026.md), [ADR-0001](../decisions/0001-separate-enforcement-layer.md), [ADR-0002](../decisions/0002-cedar-for-policy.md)

## 1. Problem

The MCP `2026-07-28` revision settles the transport layer: servers are OAuth 2.1 resource servers, clients send resource indicators, registration uses Client ID Metadata Documents ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)). It does not settle what happens after the token. The token is issued to the agent and "has no slot for the human the agent acts for"; scopes are coarse and fixed at issue time and cannot see call arguments; "no widely adopted standard slot reliably carries 'which human is this agent acting for' across every hop of a delegation chain" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). Audit logs "can't distinguish agent actions from user actions" ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)), and withdrawal of in-flight decisions is "not addressed by most implementations" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

The 2025-2026 incident record is mostly over-privilege, missing isolation and missing audit, not model failure: the May 2025 GitHub MCP leak paired prompt injection with an over-privileged PAT ([AuthZed](https://authzed.com/blog/timeline-mcp-breaches)). See the [incident list](../research/incidents-2025-2026.md).

onbehalf is a self-hosted, IdP-neutral reference monitor that sits between agent clients and MCP tool servers. It issues attenuated delegation tokens, authorizes every tool call against a policy that sees the arguments, revokes in-flight runs, and records every decision in a tamper-evident log.

## 2. Guaranteed properties

Let a *run* be a tree of hops rooted at an originating user `u`. Hop `h_n` is an agent acting with capability set `C_n`.

- **P1. Verified originating user on every hop.** Every token onbehalf issues carries the originating user in `chain.originating_user` (mirrored in `sub`), protected by `ou_sig` and copied unchanged through every exchange. A token whose user block fails `ou_sig` is rejected, never defaulted. At hop 0 the block is derived from a verified IdP credential (OIDC ID token or ID-JAG, section 4); the development-only root mint, off by default, is the one exception.
- **P2. Monotonic attenuation.** For every parent/child pair, `C_{n+1} ⊑ C_n` (section 3), `exp_{n+1} ≤ exp_n`, and hop count `≤ max_depth`. Exchange requests that would widen any dimension fail closed. This is checked at issue time and re-checked at call time against the full lineage.
- **P3. Argument-aware per-call authorization.** Every `tools/call` is evaluated as an AuthZEN-shaped request whose context contains the call arguments, the originating user, chain depth, and session/time. A call is forwarded only on an explicit `permit`. Deny is the default.
- **P4. Tamper-evident audit and in-flight revocation.** Every decision, token issuance, lease renewal and revocation is appended to a hash-chained log. Every token is bound to a lease; a revoked lease (or any ancestor lease) causes the next call to be denied within one lease interval.

P2 and P4 are the invariants that must carry property tests, not only unit tests ([CONTRIBUTING](https://github.com/7Mudit/onbehalf/blob/main/CONTRIBUTING.md)).

## 3. Delegation-chain data model

The authoritative object is the `DelegationChain` (`onbehalf-core`): the originating user plus one `Hop` per agent, root first. It is embedded whole in every token as the `chain` claim.

```json
{
  "originating_user": {
    "subject": "user:alice",
    "issuer": "https://idp.example.com",
    "authenticated_at": "2026-10-22T20:00:00Z",
    "attributes": { "amr": ["pwd", "mfa"], "tenant": "acme" }
  },
  "hops": [
    {
      "agent": "agent:planner",
      "capabilities": [
        { "server": "github", "tool": "*", "constraints": { "repo": { "op": "prefix", "value": "acme/" } } }
      ],
      "issued_at": "2026-10-22T21:00:00Z",
      "expires_at": "2026-10-22T22:00:00Z",
      "lease": "5b0c6f0e-0d54-4d0e-9a53-0c1f6a9c2a11"
    },
    {
      "agent": "agent:coder",
      "capabilities": [
        { "server": "github", "tool": "create_issue", "constraints": { "repo": { "op": "equals", "value": "acme/api" } } }
      ],
      "issued_at": "2026-10-22T21:05:00Z",
      "expires_at": "2026-10-22T21:35:00Z",
      "lease": "e2a41c7b-31f0-4b63-8d1a-77c0a54c9d02"
    }
  ]
}
```

`attributes` is an optional map of verified facts for policy (roles, MFA level, tenant). A hop's `lease` is the id revoked to deny that hop and everything delegated from it.

**Capability.** `{server, tool, constraints}`. `server` and `tool` are an exact name, `*`, or a `prefix*` glob. `constraints` maps an argument name to `{op, value}` with `op` one of `equals` (a JSON value), `one_of` (a list of JSON values) or `prefix` (a string). Arguments not mentioned are unconstrained; a call that omits a constrained argument is denied.

**Attenuation rule.** `parent.covers(child)` holds when:
1. server and tool patterns are covered: `*` covers anything; `p*` covers `q*` iff `q` starts with `p`, and covers an exact name starting with `p`; an exact parent covers only the identical exact name, never a glob;
2. every argument the parent constrains is also constrained by the child, and the child's constraint *implies* the parent's. The child may add constraints.

Constraint implication (child implies parent):

| child \ parent | `equals b` | `one_of bs` | `prefix q` |
|---|---|---|---|
| `equals a` | `a == b` | `a ∈ bs` | `a` is a string starting with `q` |
| `one_of as` | `as` non-empty, all `== b` | `as` non-empty, `as ⊆ bs` | `as` non-empty, every `a` a string starting with `q` |
| `prefix p` | never | never | `p` starts with `q` |

A set `P` covers a set `C` only if each `c ∈ C` is covered by a *single* `p ∈ P`. A child covered only by the union of several parent capabilities is rejected: sound, linear, explainable. `CapabilitySet::attenuate` applies this and also rejects an empty request. A chain is valid at time `t` only if every hop is unexpired, no hop's `expires_at` exceeds its parent's, every hop's capabilities are covered by its parent's and non-empty, and the hop count is at most `max_depth` (`validate_at`). `Issuer::exchange` clamps the child's expiry to the parent's instead of failing on it.

### 3.1 Not yet implemented / proposed

These parts of the original design have no counterpart in the code. They are tracked in [the task board](../tasks/board.md) (Next: "Token claims: proposed extensions").

- **`evidence`** on the originating user (type, `jti` and digest of the ID token or ID-JAG it came from), so audit can show how the user was verified. Hop 0 is minted from an IdP credential (section 4), but the credential itself is not referenced from the token; `ou_sig` is onbehalf's own signature. TODO: [board](../tasks/board.md).
- **`chain_id`**, a stable id for a whole run, for revoking by chain and correlating audit. TODO: [board](../tasks/board.md).
- **`may_act`** and a verified `actor_token` (for example a SPIFFE JWT-SVID). In v0 the actor is a name the caller asserts.
- **Numeric and time-range constraints.**

## 4. Token exchange

A delegation token is a compact JWS, EdDSA (Ed25519), with header `typ` = `onbehalf+jwt`. Its claims (`onbehalf-token::Claims`):

```json
{
  "iss": "https://onbehalf.example.com",
  "aud": "https://onbehalf.example.com/proxy",
  "sub": "user:alice",
  "act": { "sub": "agent:coder", "act": { "sub": "agent:planner" } },
  "jti": "0f8c1d52-9b0e-4a8e-bb43-5d61f3a1c7e0",
  "iat": 1761167100,
  "exp": 1761168900,
  "typ": "onbehalf+jwt",
  "chain": { "originating_user": { "...": "as in section 3" }, "hops": [ "...planner...", "...coder..." ] },
  "ou_sig": "<base64url Ed25519 signature over canonical JSON of chain.originating_user>"
}
```

- `sub` is the originating user. `act` is the RFC 8693 §4.1 actor chain: outermost is the agent currently acting, innermost the root agent (no `act`). Both are derived from `chain` so generic consumers can read who acts for whom without parsing it; the verifier requires them to agree.
- `exp` always equals the last hop's `expires_at`. Leases are not a top-level claim; each hop carries its own inside `chain`.
- `ou_sig` is made once at root issuance and copied unchanged through every exchange, so the user block is verifiable independently of the outer signature.

**Root issuance** (`Issuer::issue_root`) builds the chain, signs the user block and mints. The server calls it only after verifying a user credential (hop 0):

**Hop 0** is a `POST /token` exchange whose subject token is a user credential from a configured IdP: an OIDC ID token (`subject_token_type` `urn:ietf:params:oauth:token-type:id_token`) or an ID-JAG (`urn:ietf:params:oauth:token-type:id-jag`, header `typ` `oauth-id-jag+jwt`, draft -04). The agent authenticates with its client credentials and becomes the root hop's agent. The credential is verified against the IdP's JWKS (`kid`, allowed asymmetric `alg`, `iss`, `aud`, `exp`, `iat`, `sub`; `nonce` ignored), the user block is built from `sub`, `iss`, `auth_time` and selected claims plus a derived `mfa`, and the requested capabilities are attenuated against the configured root grant. Details and error codes: [design/server.md](../design/server.md#hop-0-intake-from-an-identity-provider).

**Exchange request** (JSON body; RFC 8693 with RFC 9396 `authorization_details`):

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<parent onbehalf jwt>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "actor": "agent:coder",
  "authorization_details": [
    { "type": "onbehalf_capabilities",
      "capabilities": [ { "server": "github", "tool": "create_issue",
                          "constraints": { "repo": { "op": "equals", "value": "acme/api" } } } ] }
  ],
  "requested_ttl_seconds": 600
}
```

Any other `grant_type` or `subject_token_type` is rejected. Capabilities from every `onbehalf_capabilities` entry are merged; `requested_ttl_seconds` is optional. `actor` is the agent identifier of the new hop.

**Exchange response:**

```json
{
  "access_token": "<child jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 600,
  "lease": "e2a41c7b-31f0-4b63-8d1a-77c0a54c9d02"
}
```

**Exchange** (`Issuer::exchange`) verifies the parent at `now`, then calls `DelegationChain::extend`: the requested set must be non-empty and covered per section 3, the new depth must not exceed `max_depth`, and the child's expiry is `min(now + ttl, parent.expires_at)` (default TTL from issuer config). The child gets a fresh lease and `jti`, and the parent's `ou_sig`.

**Verification order** (`Verifier::verify`; `now` is supplied by the caller, never read from the system clock):
1. EdDSA signature and algorithm;
2. header and claim `typ` equal `onbehalf+jwt`;
3. `iss`, then 4. `aud`, then 5. `exp > now`;
6. `sub` equals `chain.originating_user.subject`, and `act` equals the actor chain rebuilt from `chain.hops`;
7. `exp` equals the last hop's `expires_at`;
8. `ou_sig` over the canonical user block (compact `serde_json`, `BTreeMap` key order);
9. `chain.validate_at(now, max_depth)`: non-empty subject, at least one hop, depth, per-hop expiry, expiry monotonicity, attenuation.


## 5. Per-call authorization

The shape below is the design target. The implemented wire shape is in `onbehalf-policy::authzen`: `subject.properties.chain` carries the whole `DelegationChain`, `context.input` the call arguments, and `context.session_id` the session. The Cedar context exposes `input`, `originating_user`, `chain{depth, agents, root_agent, leases}`, `session_id` and `now_unix`. `chain_id` and `lease_state` below are proposed (section 3.1, section 6).

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

The same request is served on `POST /access/v1/evaluation` so an external PEP (for example a gateway) can use onbehalf as a PDP. Internally it maps to Cedar with arguments in `context.input` and "the model's text is not an input" ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). Two checks run before policy and cannot be overridden by it: capability match (`arguments` must satisfy some capability of the last hop, and the chain must validate) and lease liveness.

```cedar
forbid (principal, action == Action::"github/create_issue", resource)
  when { !(context.arguments.repo in ["acme/public-site", "acme/docs"]) };

forbid (principal, action, resource)
  when { context.chain_depth > 2 && resource.sensitivity == "high" };

```

## 6. Revocation via leases

Every hop in a token's `chain` carries a `lease` id, and each lease is short-lived: it is registered at issuance with `expires_at = min(now + lease_interval, token exp)`, where `lease_interval` is `[issuer] lease_interval_seconds` (default 300 s). The holder keeps its last hop alive with `POST /token/renew` (bearer = its delegation token), which sets the lease expiry to `min(now + lease_interval, token exp, parent lease expiry)` and never shortens it; the response is `{lease, expires_at, expires_in}`. Renewal fails with `invalid_grant` when the lease or any ancestor is revoked or unknown, or an ancestor has expired, so a child cannot outlive a parent that stopped renewing. Every request is checked against every lease in the chain: a revoked, unknown or expired lease denies the call (`lease_revoked`, `lease_unknown`, `lease_expired`) even while the JWT still verifies, and requests that carry no per-call decision (`tools/list`, `GET`/`DELETE` session requests) are refused with 401 under the same check. Revocation targets a lease; it marks that lease and all descendant leases revoked. The next request on any affected hop is denied (v0 has no lease cache, so an explicit revoke takes effect on the next request), and an agent that simply stops renewing is denied within one lease interval. See [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md). Because leases form a tree that mirrors `act`, revoking the originating user's session stops every sub-agent of every agent in that run, which is the "withdrawal of in-flight decisions" gap ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

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

The design target is `hash = SHA-256(prev_hash || canonical_json(record \ {hash}))` using RFC 8785 canonicalization, a signed checkpoint `(seq, hash)` every N records that can be anchored externally, and record kinds `issue`, `decision`, `renew`, `revoke` and `checkpoint`.

**Implemented in v0** (`onbehalf-audit`): each entry is `{seq, prev_hash, record, entry_hash}` with `entry_hash = SHA-256(JSON of (seq, prev_hash, record))`. The JSON is compact `serde_json` output with sorted keys, not yet RFC 8785 canonical form (task board, SR-20). The first entry's `prev_hash` is a fixed genesis value. The `record` is a `DecisionRecord`: decision id, time, allow or deny, reason code, originating subject, agents, chain depth and digest, leases, server, tool, argument digest, session id and policy ids. Issuance and renewal are stored as decision records with `server = onbehalf` and tool `token.root`, `token.exchange` or `lease.renew` ([design/server.md](../design/server.md#audit-convention-for-issuance)), so there is no separate `kind` field yet. `GET /admin/audit/checkpoint` returns the head `{seq, hash}` and `GET /admin/audit/verify` walks the chain. Checkpoints are not emitted or signed automatically: an operator has to copy the head off the host to detect truncation ([Deploying](../guides/deploying.md#sqlite-file-placement-and-backup)). The log stores argument digests, not arguments.

Every record names the agent and the originating user separately, the attribution OWASP MCP08 says is missing ([Equixly](https://equixly.com/blog/2026/06/04/mapping-nsa-s-mcp-guidance-to-the-owasp-mcp-top-10-how-to-test-for-the-risks/)). Field names here are illustrative (`chain_id` is proposed, section 3.1); the implemented record is in `onbehalf-audit`.

## 8. Non-goals

- Not an OAuth authorization server or IdP. Users authenticate elsewhere; onbehalf consumes IdP-issued credentials.
- Not a general MCP gateway. Routing, rate limits, OTel and tool federation belong to gateways such as AgentGateway; onbehalf plugs in as a PDP ([agentgateway](https://github.com/agentgateway/agentgateway)).
- Not a VMM or sandbox. Isolation sits below onbehalf; the policy model is designed so a sandbox can later enforce the same capabilities ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)).
- Not prompt-injection detection. onbehalf bounds what an injected agent can do; it does not try to detect injection.

## 9. Open questions

1. **Token binding.** Should hop tokens be sender-constrained (`cnf` with DPoP or mTLS/SPIFFE), and at what cost to clients that cannot do either?
2. **Cross-organization chains.** How does the originating-user block survive when hop n+1 is in another trust domain? ID-JAG and the "crossing-the-trustee problem" are unresolved ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).
3. **Constraint algebra.** Sets and ranges cover most tool arguments; nested objects, globs and regexes make `⊑` undecidable or expensive. Where is the line?
4. **ReBAC composition.** Relationship facts (who owns which repo) are consulted via an external graph (SpiceDB/OpenFGA-style) and projected into Cedar entities; cache consistency with revocation is unsettled ([ADR-0002](../decisions/0002-cedar-for-policy.md)).
5. **Information flow.** Labelling tool outputs as untrusted is out of scope for v0.1.
6. **Lease interval vs. load.** The default interval is 300 s; shortening it tightens the bound for a holder that stops renewing at the cost of renewal traffic. A short interval at agent call rates may need batching or push-based revocation.

## 10. Implementation status

| Property | Enforced by | Tests | Gap |
|---|---|---|---|
| P1 | `onbehalf-token` (`Verifier::verify`, `ou_sig`); `onbehalf-server` `idp` (hop-0 ID token / ID-JAG verification) | `token_exchange.rs`: `originating_user_tamper_is_caught_by_ou_sig`, `inconsistent_sub_or_act_is_rejected`; server `oidc.rs`: `valid_id_token_yields_root_token_for_the_verified_user`, `bad_id_tokens_are_rejected_with_stable_codes`, `id_jag_yields_root_token_and_typ_is_enforced` | No `evidence` linking the token to the credential; no `jti` replay cache for ID tokens |
| P2 | `onbehalf-core` (`Capability::covers`, `CapabilitySet::attenuate`, `DelegationChain::extend`/`validate_at`), `onbehalf-token` (`Issuer::exchange`) | core: `set_attenuation_only_narrows`, `union_coverage_is_rejected_conservatively`, `extend_cannot_widen`, `expiry_and_depth`; token: `exchange_cannot_widen_capabilities`, `exchange_ttl_is_clamped_to_parent_expiry`, `max_depth_exceeded_is_rejected` | No proptest suite for `covers` yet |
| P3 | `onbehalf-policy` (capability stage, then Cedar), `onbehalf-proxy` | policy `engine.rs`: `capability_stage_denies_before_cedar`, `create_issue_argument_rule_allows_acme_and_denies_others`, `github_mcp_over_privileged_token_is_narrowed_by_policy`; proxy: `denied_tools_call_returns_32003_and_never_reaches_upstream`, `github_leak_scenario_repo_prefix_constraint` | Proxy tests use the stub authorizer, not the token verifier |
| P4 | `onbehalf-audit` (hash chain, `LeaseStore`) | `audit.rs`: `tamper_every_byte_of_record_json_is_detected`, `delete_middle_row_is_detected`, `reordered_rows_are_detected`; `leases.rs`: `revoke_cascades_to_descendants_only`, `renew_rejects_unknown_and_revoked`; server `e2e.rs`: `unrenewed_lease_denies_even_though_the_jwt_is_valid`, `renew_never_goes_beyond_the_parent_lease` | Revocation takes effect on the next request (no lease cache); lease state is not yet pushed to external PEPs |
