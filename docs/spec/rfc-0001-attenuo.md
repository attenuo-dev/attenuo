# RFC-0001: attenuo, an authorization and enforcement plane for AI agents

- RFC: 0001
- Title: attenuo, an authorization and enforcement plane for AI agents
- Version: 0.1 (draft)
- Status: draft (implementation v0 in progress)
- Created: 2026-10-22
- Updated: 2026-11-12
- Supersedes: (none)
- Superseded by: (none)
- Related: [threat model](threat-model.md), [standards](../research/standards.md), [incidents](../research/incidents-2025-2026.md), [ADR-0001](../decisions/0001-separate-enforcement-layer.md), [ADR-0002](../decisions/0002-cedar-for-policy.md)

## Summary

attenuo is a self-hosted reference monitor between AI agent clients and MCP tool servers. A user's credential from an identity provider becomes a delegation token whose `chain` names the originating user and every agent hop, each hop holding a capability set that can only narrow (section 3). Every `tools/call` is decided against those capabilities and a Cedar policy that sees the call arguments (section 5), every hop is bound to a lease that can be revoked while the run is in flight (section 6), and every decision is appended to a hash-chained, checkpoint-signed audit log (section 7). Section 2 states the four properties the design is meant to guarantee, section 10 lists the code and tests that enforce each one today, and the [Security considerations](#11-security-considerations) and [Compatibility](#12-compatibility) sections say what is out of scope and what is versioned.

## Conventions and terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

This is version 0.1 of the document, and its status is draft: it is not binding (see [the RFC statuses](README.md#statuses)). The requirements in capitals describe what the implementation on `main` does. Text that describes a "design target", the JSON examples whose field names are marked illustrative (sections 5 and 7), and the Cedar examples are not normative; the implemented shapes are named next to them.

## 1. Problem

The MCP `2026-07-28` revision settles the transport layer: servers are OAuth 2.1 resource servers, clients send resource indicators, registration uses Client ID Metadata Documents ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)). It does not settle what happens after the token. The token is issued to the agent and "has no slot for the human the agent acts for"; scopes are coarse and fixed at issue time and cannot see call arguments; "no widely adopted standard slot reliably carries 'which human is this agent acting for' across every hop of a delegation chain" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). Audit logs "can't distinguish agent actions from user actions" ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)), and withdrawal of in-flight decisions is "not addressed by most implementations" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

The 2025-2026 incident record is mostly over-privilege, missing isolation and missing audit, not model failure: the May 2025 GitHub MCP leak paired prompt injection with an over-privileged PAT ([AuthZed](https://authzed.com/blog/timeline-mcp-breaches)). See the [incident list](../research/incidents-2025-2026.md).

attenuo is a self-hosted, IdP-neutral reference monitor that sits between agent clients and MCP tool servers. It issues attenuated delegation tokens, authorizes every tool call against a policy that sees the arguments, revokes in-flight runs, and records every decision in a tamper-evident log.

## 2. Security properties

These are the properties the design sets out to hold. The implementation is checked against them with unit, property and integration tests and with fuzzing; none of them is formally proven.

Let a *run* be a tree of hops rooted at an originating user `u`. Hop `h_n` is an agent acting with capability set `C_n`.

- **P1. Verified originating user on every hop.** Every token attenuo issues carries the originating user in `chain.originating_user` (mirrored in `sub`), protected by `ou_sig` and copied unchanged through every exchange. A token whose user block fails `ou_sig` MUST be rejected, never defaulted. At hop 0 the block is derived from a verified IdP credential (OIDC ID token or ID-JAG, section 4); the development-only root mint, off by default, is the one exception.
- **P2. Monotonic attenuation.** For every parent/child pair, `C_{n+1} ⊑ C_n` (section 3), `exp_{n+1} ≤ exp_n`, and hop count `≤ max_depth`. Exchange requests that would widen any dimension fail closed. This is checked at issue time and re-checked at call time against the full lineage.
- **P3. Argument-aware per-call authorization.** Every `tools/call` is evaluated as an AuthZEN-shaped request whose context contains the call arguments, the originating user, chain depth, and session/time. A call MUST NOT be forwarded without an explicit `permit`. Deny is the default.
- **P4. Tamper-evident audit and in-flight revocation.** Every decision, token issuance, lease renewal and revocation is appended to a hash-chained log. Every token is bound to a lease; a revoked lease (or any ancestor lease) causes the next call to be denied within one lease interval. "Appended" means committed before the answer; with `[audit] durability = "normal"` (the default) the commit is not synced, so a power failure can lose the newest records, including those of calls that were forwarded. `durability = "full"` closes that gap; revocations are synced either way (SR-48).

P2 and P4 are the invariants that need property or integration tests, not only unit tests ([CONTRIBUTING](https://github.com/attenuo-dev/attenuo/blob/main/CONTRIBUTING.md)).

## 3. Delegation-chain data model

The authoritative object is the `DelegationChain` (`attenuo-core`): the originating user plus one `Hop` per agent, root first. It is embedded whole in every token as the `chain` claim.

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

**Capability.** `{server, tool, constraints, limits}`. `server` and `tool` are an exact name, `*`, or a `prefix*` glob. `constraints` maps an argument name to `{op, value}` with `op` one of `equals` (a JSON value), `one_of` (a list of JSON values), `prefix` (a string), `path_prefix` (a string, a path compared by `/` segment) or `range` (`{"min": a, "max": b}`, inclusive integer bounds). Arguments not mentioned are unconstrained; a call that omits a constrained argument MUST be denied. An argument has one constraint, so kinds never combine on one argument; a bound with an exception ("1 to 100 but not 13") is a Cedar rule.

**`range`.** The value is an object with integer members `min` and/or `max` (JSON integers in the `i64` range) and nothing else: at least one bound, and `min <= max`. A missing bound is unbounded on that side. A token, an exchange request or a `--cap` whose range breaks these rules MUST be refused (`invalid_request`) and MUST NOT be read as a looser range; that includes a misspelt member such as `maximum`, which would otherwise mean "no upper bound". An argument satisfies the range when it is a Cedar `long` within the bounds, read as the Cedar translation reads numbers (section 5): a JSON integer that fits in `i64`, or a float with no fractional part and a magnitude of at most 922337203685477 (`5.0` is `5`). A fraction, a numeric string, `null`, a list, or a larger number satisfies no range, so the call is `capability_denied` in the capability stage, before the declared-type check and Cedar. The denial's diagnostic names the argument and the bound it fails (``argument `amount` is above the maximum 2000``), as it does for every constraint kind, and never echoes the value. `limits` (optional, [ADR-0010](../decisions/0010-run-limits.md)) bounds how often and how much: `calls` (a count), `sum: {arg, max}` (a total over one non-negative integer argument), `calls_per: {arg, max}` (a count per value of one argument) and `distinct: {arg, max}` (how many different values of one argument). `calls_per` and `distinct` may add `"derive": "host"` to count the host of a URL argument instead of the whole value. The server keeps the counters, charged against every hop of the chain ([design/server.md](../design/server.md#run-limits)).

**`path_prefix`.** The value is a path `P`, and an argument satisfies it when it is a string whose `/`-separated segments begin with `P`'s, both absolute (leading `/`) or both relative. A value that is empty or holds a `.` or `..` segment, an empty segment (`//`), a backslash, a control character (Unicode `Cc`), a percent-encoded `.`, `/` or `\` (`%2e`, `%2f`, `%5c`, any case), `%25` followed by two hex digits, or one of the code points U+2024, U+2025, U+2026, U+FE19, U+FE30, U+FE52, U+FE68, U+FF0E, U+FF0F, U+FF3C, U+2044, U+2215, U+29F8 (which NFKC or Windows best-fit conversion turn into `.`, `/` or `\`) satisfies no `path_prefix`; it is refused, never normalised. One trailing `/` on the value is not a segment. When `P` ends in `/`, the value also has to continue it: have more segments than `P`, or end in `/`. So every value satisfying `path_prefix P` starts with `P` as a string. `P` MUST itself pass the value rules; a token, an exchange request, a `--cap` or a config whose `path_prefix` breaks them is refused (`invalid_request`), like a malformed `range`. Unlike `prefix`, it does not admit `P/../x` or a sibling `P-x`. `prefix` keeps its plain string meaning.

**Attenuation rule.** `parent.covers(child)` holds when:
1. server and tool patterns are covered: `*` covers anything; `p*` covers `q*` iff `q` starts with `p`, and covers an exact name starting with `p`; an exact parent covers only the identical exact name, never a glob;
2. every argument the parent constrains is also constrained by the child, and the child's constraint *implies* the parent's. The child may add constraints;
3. every limit of the parent is also a limit of the child, over the same argument and derivation, with a `max` no larger, except that a parent `calls_per` or `distinct` is also met by a child `calls` no larger than its `max`. The child may add limits.

Constraint implication (child implies parent):

| child \ parent | `equals b` | `one_of bs` | `prefix q` | `path_prefix Q` | `range [c, d]` |
|---|---|---|---|---|---|
| `equals a` | `a == b` | `a ∈ bs` | `a` is a string starting with `q` | `a` satisfies `path_prefix Q` | `a` is an integer in `[c, d]` |
| `one_of as` | `as` non-empty, all `== b` | `as` non-empty, `as ⊆ bs` | `as` non-empty, every `a` a string starting with `q` | every `a` satisfies `path_prefix Q` | every `a` an integer in `[c, d]` |
| `prefix p` | never | never | `p` starts with `q` | never | never |
| `path_prefix P` | never | never | `P` starts with `q` | `P`, as a value, satisfies `path_prefix Q` | never |
| `range [a, b]` | `a == b` and that integer `== b` | `a == b` and that integer `∈ bs` | never | never | `c <= a` and `b <= d` |

`path_prefix P` implies `prefix q` exactly when `P` starts with `q`: it admits `P` itself, and everything else it admits continues `P` after a `/`. `prefix p` never implies a `path_prefix`, since it admits `p../x`. `path_prefix P` implies `path_prefix Q` when `P` lies at or below `Q`, which is the same test as `P` satisfying `Q`: under `Q = /w/`, `P = /w` is refused (it admits `/w`), `P = /w/` and `P = /w/a` are not.

For `range`, a missing bound is the end of `i64` on that side, so `[a, b] ⊑ [c, d]` is containment of integer intervals and is exact: `range(max: 5)` and `range(min: -2^63, max: 5)` cover each other. A range covers an `equals` or a `one_of` only when it holds exactly one integer; `range [1, 3]` does not cover `one_of [1, 2, 3]`, which is sound and keeps the rule short. Numbers compare by value as everywhere (`equals 5.0` is `equals 5`). An empty `one_of` covers everything vacuously, as before.

A set `P` covers a set `C` only if each `c ∈ C` is covered by a *single* `p ∈ P`. A child covered only by the union of several parent capabilities MUST be rejected: sound, linear, explainable. `CapabilitySet::attenuate` applies this and also rejects an empty request. A chain is valid at time `t` only if every hop is unexpired, no hop's `expires_at` exceeds its parent's, every hop's capabilities are covered by its parent's and non-empty, and the hop count is at most `max_depth` (`validate_at`). `Issuer::exchange` clamps the child's expiry to the parent's instead of failing on it.

### 3.1 Not yet implemented / proposed

These parts of the original design have no counterpart in the code. They are tracked in [the task board](../tasks/board.md) (Next: "Token claims: proposed extensions").

- **`evidence`** on the originating user (type, `jti` and digest of the ID token or ID-JAG it came from), so audit can show how the user was verified. Hop 0 is minted from an IdP credential (section 4), but the credential itself is not referenced from the token; `ou_sig` is attenuo's own signature. Not yet implemented; tracked on the [task board](../tasks/board.md).
- **`chain_id`**, a stable id for a whole run, for revoking by chain and correlating audit. In the audit log it is implemented as the lease id of the first hop (section 7), and that id is also the revocation handle (`POST /admin/leases/revoke` with `{"chain_id": ...}`, which revokes the first hop's lease and everything delegated from it). As a token claim it is not yet implemented; tracked on the [task board](../tasks/board.md).
- **Time-range constraints.** Deferred, not only unbuilt. A constraint tests one argument of one call, and tool arguments that are times (a meeting's start, a report's `since`) are strings in many formats and time zones, so a `range` over them would first need a typed `datetime` argument in the catalog and a parser shared by the capability check and the Cedar translation; until then a Cedar rule over the argument is the honest tool, because the policy author knows its format. What people usually mean by "time range" is something else: when the *call* may happen (office hours, the next 30 minutes). Token expiry already bounds the end, and an earliest time or a recurring window is a property of the token or of the run, not of an argument. A window per run (at most n calls an hour) belongs to run limits phase 3 ([ADR-0010](../decisions/0010-run-limits.md), [design](../design/run-limits.md)), and a window of the day is a Cedar rule over `context.now_unix`. So the board item is split: numeric ranges done, time ranges deferred with this reasoning.

Implemented since this section was first written: **`may_act`** and a verified **`actor_token`** (see section 4, "Actor authentication", and [ADR-0007](../decisions/0007-actor-authentication.md)), the numeric **`range`** constraint (section 3, "Capability"), and the segment-wise **`path_prefix`** constraint (section 3, "`path_prefix`").

## 4. Token exchange

A delegation token is a compact JWS, EdDSA (Ed25519), with header `typ` = `attenuo+jwt`. Its claims (`attenuo-token::Claims`):

```json
{
  "iss": "https://attenuo.example.com",
  "aud": "https://attenuo.example.com/proxy",
  "sub": "user:alice",
  "act": { "sub": "agent:coder", "act": { "sub": "agent:planner" } },
  "jti": "0f8c1d52-9b0e-4a8e-bb43-5d61f3a1c7e0",
  "iat": 1761167100,
  "exp": 1761168900,
  "typ": "attenuo+jwt",
  "chain": { "originating_user": { "...": "as in section 3" }, "hops": [ "...planner...", "...coder..." ] },
  "ou_sig": "<base64url Ed25519 signature, construction v3, see below>",
  "ou_sig_v": 3,
  "ou_kid": "<kid of the key that made ou_sig>",
  "may_act": { "sub": ["agent:reviewer"] }
}
```

- `sub` is the originating user. `act` is the RFC 8693 §4.1 actor chain: outermost is the agent currently acting, innermost the root agent (no `act`). Both are derived from `chain` so generic consumers can read who acts for whom without parsing it; the verifier MUST reject a token in which they disagree with `chain`.
- `exp` always equals the last hop's `expires_at`. Leases are not a top-level claim; each hop carries its own inside `chain`.
- `ou_sig` is made once at root issuance and copied unchanged through every exchange, together with `ou_sig_v` and `ou_kid`, so the user block is verifiable independently of the outer signature, under the key that made it (which may be a retired key after a rotation).
- `ou_kid` is the key id of `ou_sig`, a sibling claim rather than part of an `{sig, kid}` object, so `ou_sig` stays a plain string. It is not covered by `ou_sig` itself (the outer signature covers it) and has been required since `ou_sig` version 2: the root mint sets it to the signing key's `kid` (the same value as the JWT header `kid`, base64url of the first 16 bytes of SHA-256 over the key's SPKI DER), and every exchange copies it from the parent. The verifier MUST check `ou_sig` under that one key and MUST NOT try the other trusted keys: an `ou_kid` that is missing, empty or names no trusted key fails verification. No accepted token lacks it, and a fallback would let a token pick a path costing one Ed25519 check per trusted key.
- **`ou_sig` construction, version 3** (`ou_sig_v` = 3, the only version verifiers accept). The payload is three fields, each a `u32` big-endian length followed by the bytes: `iss`; the RFC 8785 canonical JSON of `chain.originating_user`; the RFC 8785 canonical JSON of `chain.hops[0]` restricted to `agent`, `capabilities`, `issued_at` and `lease`. The signed message is `len("attenuo-ou-v3") || "attenuo-ou-v3" || payload`, signed with Ed25519 by the issuer key named in `ou_kid` (`attenuo_token::claims::ou_sig_message`). The context string separates it from JWS signatures and from other detached signatures (audit checkpoints use `attenuo-checkpoint-v1`), and binding `iss` and the root hop means a user's signature lifted from one chain does not verify in a chain with another issuer or another root hop, even when the outer token is re-signed by a trusted key (SR-14). Hop 0's `expires_at` is not covered: it is bounded by every hop's expiry and the outer `exp`. Version 1 (a bare signature over the user block, no `ou_sig_v` claim) and version 2 (the same framing over `serde_json` output, whose nested objects kept their insertion order and whose numbers kept their spelling, SR-20) MUST be refused (`UnsupportedOuSig`); nothing was deployed with either.
- **Canonical JSON** in this document means RFC 8785 (JCS), as implemented by `attenuo_core::jcs`: members sorted by UTF-16 code units, no whitespace, the RFC's string escaping, numbers as ECMAScript writes the IEEE 754 double. One departure, outside the RFC's I-JSON domain: an integer beyond ±2^53 is written with all its digits rather than rounded to a double, so two different integers never share bytes. NaN and infinities have no canonical form. Everything attenuo hashes or signs as JSON uses it: `ou_sig`, the chain digest (`DelegationChain::digest`, also the lease bindings), the argument digest, audit entry hashes, checkpoint signatures. Constraint values compare the same way (`1` equals `1.0`; member order does not matter), so two chains with the same digest admit the same calls.
- `may_act` is optional (RFC 8693 §4.4): the agents allowed to exchange this token. See "`may_act`" below.
- `cnf` is optional (RFC 7800, RFC 9449): `{"jkt": "<RFC 7638 SHA-256 thumbprint>"}` binds the token to a key. See section 4.1.

**Root issuance** (`Issuer::issue_root`) builds the chain, signs the user block and mints. The server calls it only after verifying a user credential (hop 0):

**Hop 0** is a `POST /token` exchange whose subject token is a user credential from a configured IdP: an OIDC ID token (`subject_token_type` `urn:ietf:params:oauth:token-type:id_token`) or an ID-JAG (`urn:ietf:params:oauth:token-type:id-jag`, header `typ` `oauth-id-jag+jwt`, draft -04). The agent authenticates with its client credentials or an `actor_token` from an `[[actor_trust]]` issuer (same `[token] actor_auth` modes as an exchange, see "Actor authentication"; the actor token is single-use and caps the root's expiry) and becomes the root hop's agent. The credential is verified against the IdP's JWKS (`kid`, allowed asymmetric `alg`, `iss`, `aud`, `exp`, `iat`, `sub`; `nonce` ignored), the user block is built from `sub`, `iss`, `auth_time` and selected claims plus a derived `mfa`, and the requested capabilities are attenuated against the configured root grant. Each credential mints at most one root token (an in-memory replay cache keyed by `iss` and `jti`, or the credential's hash), and the root token never outlives the credential's `exp`. Details and error codes: [design/server.md](../design/server.md#hop-0-intake-from-an-identity-provider).

**Exchange request** (JSON body; RFC 8693 with RFC 9396 `authorization_details`):

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<parent attenuo jwt>",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "actor": "agent:coder",
  "authorization_details": [
    { "type": "attenuo_capabilities",
      "capabilities": [ { "server": "github", "tool": "create_issue",
                          "constraints": { "repo": { "op": "equals", "value": "acme/api" } } } ] }
  ],
  "requested_ttl_seconds": 600
}
```

An exchange request with any other `grant_type` or `subject_token_type` MUST be rejected. Capabilities from every `attenuo_capabilities` entry are merged; `requested_ttl_seconds` is optional. `actor` is the agent identifier of the new hop. An optional `may_act` (a list of agent ids, or `{"sub": [...]}`) becomes the child's `may_act` claim.

**Actor authentication.** The caller MUST prove it is `actor` while `[token] require_actor_auth` is on (the default). `[token] actor_auth` (`secret`, `actor_token` or `either`, the default) selects how:

- client credentials from `[[agents]]` (HTTP Basic or `client_id` / `client_secret`), whose id MUST equal `actor`;
- or an RFC 8693 §2.1 `actor_token` with `actor_token_type` = `urn:ietf:params:oauth:token-type:jwt`: a workload-identity JWT, such as a SPIFFE JWT-SVID, from an `[[actor_trust]]` entry. The entry is a SPIFFE trust domain (keys from the SPIRE bundle endpoint, configured explicitly) or any issuer with a JWKS. The server checks `typ` (not another token kind), `alg`, the key by `kid`, the signature, `iss` (when the entry names one), `aud`, `exp` (required), `nbf`, `iat` and `sub` (a SPIFFE ID in the trust domain, for SPIFFE entries), maps `sub` to an agent id (`subject_to_agent`: `sub`, the SPIFFE path, or a table) and requires it to equal `actor`. Each actor token is used once (replay cache keyed by entry and `jti`, or the hash of the signing input), and the child's expiry is capped at the actor token's `exp`.

When both are sent, both are checked. An agent id MUST NOT appear more than once in a chain; an exchange that would repeat one is refused with `duplicate_actor`.

**`may_act`** (RFC 8693 §4.4). A token may carry `"may_act": {"sub": ["agent:a", ...]}`: the agents allowed to exchange it. It is set at issuance from the request's `may_act` or, at hop 0, from `[[root_grants]] may_act` (a ceiling the request may narrow). When the parent carries it, an exchange for an actor it does not list MUST fail with `invalid_request` / `actor_not_permitted`. It is not inherited: a child carries only the `may_act` its own exchange asked for. Without it, any authenticated actor may exchange the token.

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

**Exchange** (`Issuer::exchange` / `exchange_with`) verifies the parent at `now`, checks the parent's `may_act` against the actor, then calls `DelegationChain::extend`: the requested set MUST be non-empty and covered per section 3, the new depth MUST NOT exceed `max_depth`, and the child's expiry is `min(now + ttl, parent.expires_at)` (default TTL from issuer config), further capped by `IssueOptions::not_after` (the actor token's `exp` when one authenticated the exchange). The child gets a fresh lease and `jti`, and the parent's `ou_sig`, `ou_sig_v` and `ou_kid`. The server lets a parent token delegate to a given actor once (replay cache keyed by parent `jti` and actor, until the parent's `exp`).

**Verification order** (`Verifier::verify`; `now` is supplied by the caller, never read from the system clock):
1. EdDSA signature and algorithm;
2. header and claim `typ` equal `attenuo+jwt`;
3. `iss`, then 4. `aud`, then 5. `exp > now`;
6. `sub` equals `chain.originating_user.subject`, and `act` equals the actor chain rebuilt from `chain.hops`;
7. `exp` equals the last hop's `expires_at`;
8. `ou_sig_v` equals 3, then `ou_sig` (construction above, RFC 8785 canonical JSON) under the trusted key named by `ou_kid` (that key only; no `ou_kid`, or one naming no trusted key, fails);
9. `chain.validate_at(now, max_depth)`: non-empty subject, at least one hop, depth, per-hop expiry, expiry monotonicity, attenuation.

A `cnf` claim whose `jkt` is not a 43-character base64url SHA-256 thumbprint MUST fail verification.

### 4.1 Sender-constrained tokens (DPoP)

A token may be bound to a key with DPoP (RFC 9449). A bound token is accepted only together with a proof signed by that key, so a copy of the token alone is useless (threat model A4, SR-24). Binding is optional per request and per deployment.

**Keys and proofs.** Proof keys are Ed25519 (`alg` `EdDSA`) or P-256 (`ES256`). A proof is a compact JWS with header `typ` = `dpop+jwt`, `alg` and `jwk` (the public key, no private members) and claims `htm`, `htu`, `iat`, `jti` (at most 256 bytes) and, when a bound token goes with the request, `ath` = base64url(SHA-256(token)). A proof MUST be at most 4096 bytes and MUST be sent as exactly one `DPoP` header (`attenuo_token::dpop::verify_proof`).

A proof is valid for a request when:

1. it parses, `typ` and `alg` are as above, `alg` matches the `jwk`, and the signature verifies under `jwk`;
2. `htm` equals the request method;
3. `htu`, normalized (lowercase scheme and host, default port removed, query and fragment dropped, empty path as `/`), equals the request URL normalized the same way. The server builds the request URL from `[server] public_url` plus the path. When `public_url` is unset it uses `http://<Host>` plus the path only for a loopback `Host` (`localhost`, `127.0.0.1`, `[::1]`, any port), and `http://localhost` plus the path otherwise, so a client cannot choose the URL its proofs are checked against (SR-42);
4. `|now - iat| <= [token] dpop_max_age_seconds` (default 300);
5. `ath`, when the request presents a bound token, equals the hash of that token;
6. the RFC 7638 thumbprint of `jwk` equals the token's `cnf.jkt`, when the request presents a bound token;
7. its `jti` has not been seen for this key within the `iat` window (an in-memory cache per process, bounded by `[token] dpop_replay_capacity`; a full cache refuses new proofs with 503 rather than forget old ones). The `jti` is recorded only after every other check, including 6, has passed, so proofs by the wrong key cannot fill the cache (SR-41). The proofs of one request (an exchange's header and sign-off) are recorded together or not at all.

With `[token] dpop_nonce = "required"`, a `DPoP` header proof MUST also carry a current server nonce (see "Server nonces" below). That check runs after 1 to 5 and before 6 and 7, so a nonce failure never uses up a `jti`.

**Binding at issuance.** `POST /token` (hop 0 and exchanges) and the dev `POST /admin/root-token` bind the new token to the key of a valid `DPoP` header proof: `cnf.jkt` is its thumbprint and the response's `token_type` is `DPoP` (otherwise `Bearer`). `[token] dpop` controls this: `off` never binds new tokens, `optional` (the default) binds when a proof is sent, `required` refuses a request without a proof with `dpop_required`.

**Attenuation.** A child of a bound token MUST be bound (`TokenError::BindingRequired`): binding is part of what a token cannot widen. The exchange's `DPoP` header names the child's key.

- Same key as the parent: the header proof MUST carry `ath` of the subject token. It proves possession of the parent's key and binds the child to it.
- Another key (a sub-agent with its own key): the body field `subject_token_dpop` MUST hold a second proof, the **sign-off**, by the parent's key, for `POST` and the `/token` URL, with `ath` of the subject token, plus `child_jkt` (the thumbprint of the header proof's key) and `child_actor` (the request's `actor`). It is the parent holder's consent to delegate to that key and that agent only; a sign-off that names another key or agent, or neither, is `invalid_dpop_proof` (SR-40). The parent's holder can make it in its own process and hand it to the sub-agent (`attenuo token sign-off`, `DpopKey.sign_off` / `signOff`), so the parent's key never has to leave it.

Without these, the exchange fails with `dpop_required` or `invalid_dpop_proof`, so a stolen bound token cannot be exchanged either.

**Use.** A token with `cnf` MUST be accompanied by a valid proof wherever it is presented: the proxy (`/mcp/{server}`, every method), `POST /token/renew`, the AuthZEN endpoints, and `POST /token` as `subject_token`. `Authorization` may use the `DPoP` or the `Bearer` scheme; the token, not the scheme, decides whether a proof is needed. A proof sent with an unbound token is ignored, except under `dpop = "required"`, where an unbound token is refused on these routes. `dpop = "off"` does not relax the check for tokens that are already bound.

**Errors.** 401 with `error` (and `error_description`) `dpop_required` when a proof is missing, or `invalid_dpop_proof` when one fails a check above, and `WWW-Authenticate: DPoP error="invalid_token", error_description="dpop_required", algs="EdDSA ES256"` or `DPoP error="invalid_dpop_proof", algs="EdDSA ES256"`. The proxy answers HTTP 401 with JSON-RPC `-32001` and `data.reason` set to the same code. A full replay cache is HTTP 503 at both: `temporarily_unavailable` with `error_description` `dpop_replay_cache_full` at the server, JSON-RPC `-32006` with `data.reason` `dpop_replay_cache_full` and `Retry-After` at the proxy (SR-47).

**Server nonces.** `[token] dpop_nonce` is `off` (the default) or `required` (RFC 9449 §8). When required:

- The server issues nonces without storing them: nonce = base64url(HMAC-SHA256(k, b)), with b = floor(unix time / `dpop_max_age_seconds`) as a big-endian 64-bit integer. The key is k = HMAC-SHA256(issuer private key PEM, `"attenuo/dpop-nonce/v1"`), so an ephemeral issuer key gives ephemeral nonces, and replicas that share the signing key share nonces. A nonce is accepted while the current bucket is b or b + 1, so it lives between one and two windows. Rotating the signing key invalidates outstanding nonces; clients recover with one retry.
- Every response to a request with a `DPoP` header, and every response with a `WWW-Authenticate: DPoP` challenge (including `dpop_required`), carries `DPoP-Nonce: <current nonce>`.
- Every proof checked from a `DPoP` header (binding at issuance, a presented bound token, the header proof of an exchange) MUST carry a `nonce` claim the server accepts. A missing, stale or unknown nonce is 401 `use_dpop_nonce` with `WWW-Authenticate: DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof", algs="EdDSA ES256"` and a `DPoP-Nonce` header. The proxy answers JSON-RPC `-32001` with `data.reason` `use_dpop_nonce`. Unlike RFC 9449 §8, which has an authorization server answer 400, `POST /token` uses 401 too, like its other DPoP errors. Clients SHOULD accept either.
- The exchange sign-off (`subject_token_dpop`) is not a proof of the request and needs no nonce: the parent makes it ahead of time, and it is already limited to one key, one agent and the `iat` window.
- A proof that fails another check is still `invalid_dpop_proof`. When `dpop_nonce` is `off`, a `nonce` claim is ignored.

Clients SHOULD keep the latest `DPoP-Nonce` they were sent, put it in each proof, and retry a request once when it is refused with `use_dpop_nonce`. The Python and TypeScript SDKs and the CLI do this.

**Audit.** A decision made for a request whose bound token was proven, and an issuance that bound the new token, carry `"dpop_bound": true` in the record. The field is omitted when false, so the hashes of existing records do not change.

**Not covered.** Server nonces are optional and off by default; without them, freshness relies on `iat` and the `jti` cache, which is per process. A nonce is shared by all clients for its lifetime, so it bounds how early a proof can be made but does not stop replay of a proof against another replica within that time. Cedar's context does not include the binding. mTLS-bound tokens (RFC 8705) and SPIFFE X.509 binding are not implemented. An external PEP that verifies tokens locally MUST check proofs itself.


## 5. Per-call authorization

The shape below is the design target. The implemented wire shape is in `attenuo-policy::authzen`: `subject.properties.chain` carries the whole `DelegationChain`, `context.input` the call arguments, and `context.session_id` the session. The Cedar context exposes `input`, `originating_user`, `chain{depth, agents, root_agent, leases}`, `session_id`, `now_unix`, and the run state `session` (output labels), `approval`, `budget` (run limits) and `usage` (run usage of destructive tools). `chain.leases[0]` is the run's `chain_id`; a `chain_id` member and `lease_state` as below are not in the context (lease liveness is checked before policy, section 6). A call for a `(server, tool)` pair missing from the tool catalog is denied with `tool_not_in_catalog` unless the deployment sets `[policy] unknown_tools` to `"sensitive"` or `"allow"`. The endpoint requires the delegation token as bearer, and the chain is taken from it. A deployment may set `[authzen] allow_unsigned_chain = true` to let authenticated PEPs (`[[peps]]`) send the chain in the body instead; every hop of such a chain MUST then equal what the server issued for its lease (each lease is bound to the digest of the chain prefix ending at its hop), otherwise the request is refused with `chain_not_issued`.

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

The same request is served on `POST /access/v1/evaluation` so an external PEP (for example a gateway) can use attenuo as a PDP. Internally it maps to Cedar with arguments in `context.input` and "the model's text is not an input" ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). Two checks MUST run before policy, and policy MUST NOT be able to override them: capability match (`arguments` satisfy some capability of the last hop, and the chain validates) and lease liveness.

```cedar
forbid (principal, action == Action::"github/create_issue", resource)
  when { !(context.arguments.repo in ["acme/public-site", "acme/docs"]) };

forbid (principal, action, resource)
  when { context.chain_depth > 2 && resource.sensitivity == "high" };

```

## 6. Revocation via leases

Every hop in a token's `chain` carries a `lease` id, and each lease is short-lived: it is registered at issuance with `expires_at = min(now + lease_interval, token exp)`, where `lease_interval` is `[issuer] lease_interval_seconds` (default 300 s). The holder keeps its last hop alive with `POST /token/renew` (bearer = its delegation token), which sets the lease expiry to `min(now + lease_interval, token exp, parent lease expiry)` and never shortens it; the response is `{lease, expires_at, expires_in}`. Renewal fails with `invalid_grant` when the lease or any ancestor is revoked or unknown, or an ancestor has expired, so a child cannot outlive a parent that stopped renewing. Every request is checked against every lease in the chain: a revoked, unknown or expired lease MUST deny the call (`lease_revoked`, `lease_unknown`, `lease_expired`) even while the JWT still verifies, and requests that carry no per-call decision (`tools/list`, `GET`/`DELETE` session requests) are refused with 401 under the same check. Revocation targets a lease; it marks that lease and all descendant leases revoked. The next request on any affected hop is denied (v0 has no lease cache, so an explicit revoke takes effect on the next request), and an agent that simply stops renewing is denied within one lease interval. See [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md). Because leases form a tree that mirrors `act`, revoking the originating user's session stops every sub-agent of every agent in that run, which is the "withdrawal of in-flight decisions" gap ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

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

The design target is `hash = SHA-256(prev_hash || canonical_json(record \ {hash}))` using RFC 8785 canonicalization, a signed checkpoint `(seq, hash)` every N records that can be anchored externally, and a record `kind`. The implemented kinds are `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke` and `admin`; checkpoints are not records (see below).

**Implemented** (`attenuo-audit`): each entry is `{seq, prev_hash, record, entry_hash}` with `entry_hash = SHA-256(JCS(["attenuo-audit-entry-v2", seq, prev_hash, record]))`, where JCS is RFC 8785 canonical JSON (section 4) and the leading string names the hash construction (`ENTRY_HASH_VERSION`). The SQLite sink stores the record's canonical text and records the construction in an `audit_meta` table; a database written with the earlier construction (plain `serde_json` output of `[seq, prev_hash, record]`, SR-20) is refused when opened, and there is no migration. The first entry's `prev_hash` is a fixed genesis value. The `record` is a `DecisionRecord`: decision id, time, `kind`, `chain_id` (when there is a chain), allow or deny, reason code, originating subject, agents, chain depth and digest, leases, server, tool, argument digest, session id and policy ids. `kind` is one of `decision`, `tool_result` (the recorded answer of an allowed call, with its output label), `approval_request` and `approval_grant` (output labelling, [ADR-0009](../decisions/0009-output-labelling.md)), `exchange` (tool `token.exchange`), `root_token` (`token.root`), `lease_renew` (`lease.renew`), `lease_revoke` (`admin.lease.revoke`) or `admin` (other `admin.*`); issuance and renewal still use `server = attenuo` and those tool names ([design/server.md](../design/server.md#audit-convention-for-issuance)). `chain_id` is the lease id of the chain's first hop, which every later hop of the run descends from, so it is stable as hops are added and needs no new token claim; admin records have none. Both are top-level members of the hashed record, absent from nothing but `chain_id` on admin records, and the SQLite sink indexes them. They went into entry hash `v2` before any release rather than bumping it. An export can be filtered on either (`?kind=`, `?chain_id=`); a filtered export has gaps in its chain and is refused by offline verification.

**Signed checkpoints are implemented.** A checkpoint is `{seq, head_hash, at, kid, signature}`: an Ed25519 signature by the issuer key `kid` over the canonical JSON array `[seq, head_hash, at, kid]` (for these field types the same bytes `serde_json` wrote before SR-20, so the construction did not change), framed with the context string `attenuo-checkpoint-v1` so it cannot be replayed as a token or any other signed object. Checkpoints are stored in a `checkpoints` table, written inside the append transaction every `[audit] checkpoint_every` entries (default 1000) and by a timer every `checkpoint_interval_seconds` (default 300) when entries arrived since the last one. A transaction that writes a checkpoint commits with `synchronous=FULL` at any durability, before the checkpoint is handed on (the `on_created` hook), so a checkpoint shipped off the host never covers entries that a power failure could still remove (SR-50). `GET /admin/audit/checkpoint` returns the signed checkpoint of the head. `GET /admin/audit/verify` walks the chain and verifies every checkpoint against the JWKS keys, reporting `last_signed_seq`, the `unsigned_tail` after it and any invalid checkpoint; keys retired in a rotation keep verifying old checkpoints while they stay in the JWKS. `GET /admin/audit/export?from&to` streams entries and checkpoints as JSON Lines (format `attenuo-audit-export-v2`, one canonical JSON object per line, after a required header that declares `from..=to`), and `attenuo audit verify --file` checks such a file offline with only the JWKS. That check is strict: entries outside the declared range, a file short of it, and entries after the last valid checkpoint all fail it; `--allow-unsigned-tail` accepts the last kind for an export taken while the log was ahead of its newest checkpoint (fuzzing F5). What a checkpoint does not do: it is signed by the same key the server holds, so an attacker who controls the server process can sign a rewritten history. That is why the checkpoint sink exists (SR-21): with `[audit.sink]` every checkpoint is queued after its synced commit and delivered off the host by a background thread (webhook `POST`, an append-only JSON Lines file, or an S3 `PUT` signed with SigV4), with retries, jittered exponential backoff and a bounded queue that drops the oldest (counted) when full; `/readyz` reports the sink degraded when the queue is full or the oldest undelivered checkpoint is older than `max_lag_seconds`. A shipped checkpoint is the canonical JSON object `{format: "attenuo-shipped-checkpoint-v1", checkpoint, kid, signature, public_url, checkpoint_sha256}`, where `checkpoint_sha256` is SHA-256 over the RFC 8785 form of `checkpoint`. `attenuo audit verify --file <export> --checkpoints <shipped>` requires every shipped checkpoint inside the export's range to equal the export's checkpoint at that seq and to match the entry hash there, so a history rewritten and re-signed with the stolen key is detected as long as one checkpoint covering the rewritten part left the host first. The sink credentials are on the host as well, so they need to allow adding only, not overwriting or deleting ([Audit log](../concepts/audit-log.md#shipping-checkpoints-off-the-host)). Checkpoints have no `kind` because they are not log entries: they are signed separately and are `checkpoint` lines in an export. The SDKs verify exports offline too (`attenuo.audit.verify_export` in Python, `verifyExport` in TypeScript), with the same strictness. The log stores argument digests, not arguments.

Every record names the agent and the originating user separately, the attribution OWASP MCP08 says is missing ([Equixly](https://equixly.com/blog/2026/06/04/mapping-nsa-s-mcp-guidance-to-the-owasp-mcp-top-10-how-to-test-for-the-risks/)). Field names here are illustrative; the implemented record, including `chain_id`, is in `attenuo-audit`.

## 8. Non-goals

- Not an OAuth authorization server or IdP. Users authenticate elsewhere; attenuo consumes IdP-issued credentials.
- Not a general MCP gateway. Routing, rate limits, OTel and tool federation belong to gateways such as AgentGateway; attenuo plugs in as a PDP ([agentgateway](https://github.com/agentgateway/agentgateway)).
- Not a VMM or sandbox. Isolation sits below attenuo; the policy model is designed so a sandbox can later enforce the same capabilities ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)).
- Not prompt-injection detection. attenuo bounds what an injected agent can do; it does not try to detect injection.

## 9. Open questions

1. **Token binding.** DPoP binding is implemented and optional (section 4.1); clients that cannot sign proofs keep using bearer tokens unless the deployment sets `[token] dpop = "required"`. Server nonces (`[token] dpop_nonce`) are implemented. Still open: mTLS or SPIFFE X.509 binding for workloads that already hold certificates, and a replay cache shared by replicas.
2. **Cross-organization chains.** How does the originating-user block survive when hop n+1 is in another trust domain? ID-JAG and the "crossing-the-trustee problem" are unresolved ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).
3. **Constraint algebra.** Sets and ranges cover most tool arguments; nested objects, globs and regexes make `⊑` undecidable or expensive. Where is the line?
4. **ReBAC composition.** Relationship facts (who owns which repo) are consulted via an external graph (SpiceDB/OpenFGA-style) and projected into Cedar entities; cache consistency with revocation is unsettled ([ADR-0002](../decisions/0002-cedar-for-policy.md)).
5. **Information flow.** Tool outputs are labelled (catalog `output`, `context.session.tainted`, matching of arguments against untrusted results, approvals; [ADR-0009](../decisions/0009-output-labelling.md)). Still open: labels that follow data across runs or out of attenuo's sight.
6. **Lease interval vs. load.** The default interval is 300 s; shortening it tightens the bound for a holder that stops renewing at the cost of renewal traffic. A short interval at agent call rates may need batching or push-based revocation.

## 10. Implementation status

| Property | Enforced by | Tests | Gap |
|---|---|---|---|
| P1 | `attenuo-token` (`Verifier::verify`, `ou_sig`); `attenuo-server` `idp` (hop-0 ID token / ID-JAG verification) | `token_exchange.rs`: `originating_user_tamper_is_caught_by_ou_sig`, `ou_sig_cannot_be_lifted_into_a_chain_with_another_root_hop`, `ou_sig_is_bound_to_the_issuer`, `ou_sig_v1_and_unknown_versions_or_kids_are_refused`, `inconsistent_sub_or_act_is_rejected`; server `oidc.rs`: `valid_id_token_yields_root_token_for_the_verified_user`, `bad_id_tokens_are_rejected_with_stable_codes`, `id_jag_yields_root_token_and_typ_is_enforced` | No `evidence` linking the token to the credential; the credential replay cache is in memory, per process |
| P2 | `attenuo-core` (`Capability::covers`, `CapabilitySet::attenuate`, `DelegationChain::extend`/`validate_at`), `attenuo-token` (`Issuer::exchange`) | core: `set_attenuation_only_narrows`, `union_coverage_is_rejected_conservatively`, `range_attenuation_narrows_and_refuses_widening`, `extend_cannot_widen`, `expiry_and_depth`, proptests in `attenuation_props.rs` (`range_tightening_narrows_and_loosening_widens` among them); token: `exchange_cannot_widen_capabilities`, `exchange_ttl_is_clamped_to_parent_expiry`, `max_depth_exceeded_is_rejected`; server `range_constraint.rs`: `range_narrows_at_exchange_and_bounds_every_call` | The proptests check soundness (a covered child never permits more), not that every narrower request is accepted |
| P3 | `attenuo-policy` (capability stage, then Cedar), `attenuo-proxy` | policy `engine.rs`: `capability_stage_denies_before_cedar`, `create_issue_argument_rule_allows_acme_and_denies_others`, `github_mcp_over_privileged_token_is_narrowed_by_policy`; proxy: `denied_tools_call_returns_32003_and_never_reaches_upstream`, `github_leak_scenario_repo_prefix_constraint` | Proxy tests use the stub authorizer, not the token verifier |
| P4 | `attenuo-audit` (hash chain, `LeaseStore`) | `audit.rs`: `tamper_every_byte_of_record_json_is_detected`, `delete_middle_row_is_detected`, `reordered_rows_are_detected`; `leases.rs`: `revoke_cascades_to_descendants_only`, `renew_rejects_unknown_and_revoked`; server `e2e.rs`: `unrenewed_lease_denies_even_though_the_jwt_is_valid`, `renew_never_goes_beyond_the_parent_lease` | Revocation takes effect on the next request (no lease cache); lease state is not yet pushed to external PEPs |

## 11. Security considerations

The full analysis is the [threat model](threat-model.md). This section summarises what it says about the properties in section 2.

**Trust.** The agent client and the model driving it, every sub-agent and every MCP server are untrusted. attenuo is the trusted reference monitor; the identity provider is trusted to authenticate users only, and policy authors and log verifiers are trusted ([trust boundaries](threat-model.md#trust-boundaries)). P1 to P4 are meant to hold against an attacker who injects instructions into anything the agent reads (A1), controls a sub-agent (A2), publishes or compromises an MCP server (A3), replays tokens it observed (A4), asks for wider capabilities or deeper chains (A5), keeps a run alive after consent is withdrawn (A6), or tries to alter the audit log afterwards (A7) ([attacker capabilities](threat-model.md#attacker-capabilities)).

**Out of scope.** Compromise of attenuo's host or signing keys, compromise of the identity provider, side channels and denial of service against attenuo itself are outside the model. attenuo also does not prevent legitimate but harmful reads, misbehaviour inside an MCP server, prompt injection as such, an over-permissive policy at the root, or tools reached around the proxy ([what attenuo does not prevent](threat-model.md#what-attenuo-does-not-prevent)).

**What a wrong implementation would give an attacker.**

- A gap in the attenuation rule (section 3) or in its implementation lets a sub-agent hold or use more than its parent, which breaks P2. The rule is checked at exchange and again at every call against the whole lineage, and it is property-tested for soundness only, not for completeness (section 10).
- A token whose `ou_sig` could be lifted or defaulted would let a run act for a user who never authenticated, which breaks P1. Section 4 binds `ou_sig` to the issuer and the root hop (SR-14) and fixes its encoding to RFC 8785 (SR-20).
- A bearer token that is copied can be used until its lease ends. DPoP binding (section 4.1) removes that for bound tokens; it is optional, and without server nonces the replay cache is per process.
- A missed lease check lets a revoked run continue, which breaks P4. Lease liveness is checked before policy on every request, and open streams are re-checked at an interval (`[proxy] stream_recheck_seconds`).
- The audit log detects tampering after the fact; it does not prevent it. An attacker who holds the host and the issuer key can rewrite history and sign new checkpoints over it, and only checkpoints shipped off the host before that (`[audit.sink]`, SR-21) expose it. With `[audit] durability = "normal"`, the default, a power failure can lose the newest records of calls that were forwarded (SR-48).

The [residual risks](threat-model.md#residual-risks-to-track) in the threat model list the remaining gaps and the settings and metrics that narrow them. The tests that guard each property are named in section 10.

## 12. Compatibility

attenuo is pre-1.0 and follows SemVer 2.0, so a minor release may break things. [API compatibility](../reference/api-compatibility.md) gives the rules for every surface; for the formats this RFC defines they are:

- **Delegation tokens** (sections 3 and 4) are not stable. The header and claim `typ` (`attenuo+jwt`) and `ou_sig_v` (3) are the only version markers; a change to `chain` or the capability format cannot be told apart from a malformed token. Tokens are short-lived, so a format change takes effect at upgrade and ends running sessions.
- **Capabilities and constraints** are tagged, and an unknown `op` or limit kind is refused, never read as looser. A new kind is additive for requests, but a token carrying it fails at an older server, so servers are upgraded before clients use it.
- **Signed and hashed constructions** never change in place: `attenuo-ou-v3`, `attenuo-audit-entry-v2`, `attenuo-checkpoint-v1`, `attenuo-audit-export-v2` and `attenuo-shipped-checkpoint-v1` each carry their version, and a verifier refuses any other ([versioned today](../reference/api-compatibility.md#versioned-today)). An audit database written with another entry-hash construction is refused at start, with no migration.
- **Not versioned yet**: the token payload apart from `typ` and `ou_sig_v`, the chain and argument digests, and the shape of the audit `record` ([not versioned yet](../reference/api-compatibility.md#not-versioned-yet)).
- **The AuthZEN request** (section 5) is served under `/access/v1/`, a prefix taken from the AuthZEN specification. The other routes carry no version.

A breaking change is announced in `CHANGELOG.md` under `Changed` or `Removed` with a `BREAKING CHANGE:` footer in its commit, and is deprecated first where the old form can keep working. A security fix that has to refuse what was accepted before ships at once, as SR-14 and SR-20 did for `ou_sig`. A change to the token format, the policy request shape or the audit schema needs an RFC first ([what needs an RFC](README.md#what-needs-an-rfc)).
