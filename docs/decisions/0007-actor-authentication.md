---
status: proposed
date: 2026-10-23
decision-makers: [7Mudit]
consulted: []
informed: []
---

# ADR-0007. Actor authentication: RFC 8693 actor_token from a workload-identity issuer, alongside client secrets, with may_act on the parent

## Context and Problem Statement

At every exchange after hop 0, a caller asks `POST /token` for a child token in the name of an `actor`. That id becomes Cedar's `principal` and the agent in every audit record of the child, so it has to be authenticated, not asserted (security review 2026-10-22, SR-10). The first fix made the caller present the actor's `[[agents]]` client secret. A shared secret per agent is a credential to distribute, rotate and leak, while many deployments already give each workload a verifiable identity (SPIFFE/SPIRE JWT-SVIDs, Kubernetes service-account tokens, cloud workload tokens). Separately, a parent could not say who may receive its delegation: anyone able to authenticate as some agent could redeem a parent token it got hold of. How should the actor of an exchange prove who it is, and how does a parent limit who may act on it?

## Decision Drivers

- The agent id in a chain must be bound to something the agent holds, not to what the caller typed (SR-10, RFC-0001 P1 and the attribution goal).
- Reuse the identity systems deployments already run; do not ship a new credential type.
- Stay inside RFC 8693, so generic token-exchange clients and the IETF agent-identity work (WIMSE) map onto it.
- Keep secret-based deployments working without a config change.
- No new network trust: keys are fetched only from URLs an operator configured.
- A stolen actor token must be worth as little as possible.

## Considered Options

- RFC 8693 `actor_token` (a JWT) verified against configured workload-identity issuers, alongside client secrets; RFC 8693 §4.4 `may_act` on the parent.
- Client secrets only (status quo), with per-agent rotation tooling.
- mTLS with X.509-SVIDs at `/token`.
- `private_key_jwt` client authentication (RFC 7523) per agent.

## Decision Outcome

Chosen option: "RFC 8693 `actor_token` alongside client secrets, with `may_act`", because it is the mechanism RFC 8693 defines for exactly this, it accepts the JWTs SPIRE and other workload-identity systems already issue, and it composes with the existing secret path.

- `[[actor_trust]]` lists trusted issuers: a SPIFFE trust domain with an explicitly configured bundle endpoint URL, or an `issuer` with a `jwks_url`. Nothing is discovered. Keys are cached with the `[[idps]]` JWKS cache (kid lookup, one refetch on an unknown kid, fail closed).
- The token is checked for `typ` (not another token kind), `alg` (asymmetric, allowed), signature, `iss` (when configured), `aud`, `exp` (required), `nbf`, `iat` and a strictly parsed SPIFFE ID `sub`. `subject_to_agent` (`sub`, the SPIFFE path, or a table) turns `sub` into the agent id, which must equal `actor`.
- `[token] actor_auth = "secret" | "actor_token" | "either"`, default `either`. `require_actor_auth = true` keeps meaning one accepted method is mandatory; when both are sent, both are checked.
- An actor token authenticates one exchange (replay cache, keyed by entry and `jti`, or the hash of the signing input), and the child token never outlives it.
- A token may carry `may_act` (`{"sub": [agent ids]}`), set from the exchange request or, at hop 0, from the request within `[[root_grants]] may_act`. When the parent carries it, an unlisted actor is refused with `actor_not_permitted`. It is not inherited.

### Consequences

- Good, because the agent id in a chain can now rest on a workload identity the agent's platform attests, not on a secret copied into its environment.
- Good, because a parent can pin its delegation to named agents, so a leaked parent token cannot be redeemed by an unrelated agent that authenticates fine.
- Good, because existing configs behave as before (`either`, no `[[actor_trust]]`).
- Bad, because single use clashes with SPIRE's JWT-SVID cache: an agent that exchanges twice within one SVID lifetime must fetch a fresh token (for example with an extra unique audience). Documented in the identity-providers guide.
- Bad, because child tokens from a five-minute JWT-SVID live at most five minutes; longer work relies on lease renewal and re-exchange.
- Neutral, because the child token is still a bearer token. Binding it to the actor's key (`cnf`, DPoP or mTLS) is RFC-0001 open question 1 and is not decided here.
- Good, because hop 0 accepts an actor token too (amended 2026-10-23, `fix/sr14-ou-sig-and-hop0-actor`): on IdP intake the agent may authenticate with an `actor_token` instead of its client secret, under the same `[token] actor_auth` modes, so a deployment can drop `[[agents]]` secrets entirely. The mapped agent must equal `actor` and `client_id` when the request names them and is the agent `[[root_grants]]` and `[[idps]] client_ids` are looked up for; the actor token is used once, recorded together with the IdP credential, and caps the root's expiry. `[token] actor_auth = "actor_token"` now also refuses client secrets at hop 0. `require_actor_auth` does not apply to hop 0, which always authenticates the agent.

### Confirmation

Server integration tests in `crates/attenuo-server/tests/actor_token.rs` and, for hop 0, `actor_token_hop0.rs` (JWT-SVID with ES256 keys from a fake SPIRE bundle endpoint, a generic EdDSA issuer, every rejection code, `actor_auth` modes, single use, TTL cap) and `e2e.rs` (`may_act_on_the_parent_limits_who_may_exchange_it`, `root_grant_may_act_is_applied_and_cannot_be_widened`); token tests `may_act_on_the_parent_limits_the_next_actor`, `not_after_caps_the_child_expiry`; unit tests in `crates/attenuo-server/src/actor.rs` for SPIFFE ID parsing, subject mapping, entry validation and claim checks.

## Pros and Cons of the Options

### RFC 8693 `actor_token` alongside client secrets, with `may_act`

- Good, because it is standard RFC 8693 (§2.1 `actor_token`, §4.4 `may_act`) and the shape WIMSE work builds on.
- Good, because SPIFFE JWT-SVIDs, Kubernetes service-account tokens and cloud workload tokens all fit one verifier.
- Bad, because it adds a configuration surface (`[[actor_trust]]`) that must be set up per issuer.

### Client secrets only

- Good, because it already works and needs nothing new.
- Bad, because every agent needs a provisioned, rotated secret, and a leaked secret lets anyone act as that agent until rotation.

### mTLS with X.509-SVIDs

- Good, because the credential never travels and is bound to the TLS session.
- Bad, because it needs TLS termination at attenuo (or trusted forwarding of client certificates), which most deployments put in a proxy; it does not fit RFC 8693 `actor_token`.

### `private_key_jwt` per agent

- Good, because no shared secret is stored on the server.
- Bad, because it still needs a key per agent provisioned and registered with attenuo, which is the work a workload-identity system already does.

## More Information

- RFC 8693 §2.1 (`actor_token`), §4.4 (`may_act`); SPIFFE JWT-SVID specification; [standards note](../research/standards.md) (SPIFFE, WIMSE).
- [Security review 2026-10-22](../research/security-review-2026-10-22.md), SR-10.
- [RFC-0001](../spec/rfc-0001-attenuo.md) section 4, "Actor authentication" and "`may_act`".
- Revisit when sender-constrained hop tokens (`cnf`) are designed.
