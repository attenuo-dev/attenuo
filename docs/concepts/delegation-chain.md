# Delegation chain

An AI agent rarely works alone. A person asks a planner agent for something. The planner hands part of the job to a coder agent. The coder calls a tool. By then, the tool server sees only the last agent. It has no idea which person started the run.

The delegation chain fixes that. It is the record of who is acting for whom, carried inside every token onbehalf issues.

## What is in a chain

A chain has two parts.

- The **originating user**: the person the run is for. It holds a subject, an issuer, the time they authenticated, and a few verified attributes such as `mfa` or `tenant`.
- A list of **hops**, root first. Each hop is one agent. It has a name, a set of capabilities, an issue time, an expiry and a lease id.

The chain is stored whole in the `chain` claim of the token. The standard `sub` claim repeats the originating user. The standard `act` claim (from RFC 8693) nests the agents, with the agent currently acting on the outside. Generic tools can read `sub` and `act` without understanding `chain`. The verifier checks that all three agree.

## Where a chain starts

Hop 0 starts at `POST /token`. An agent presents a credential for a user from an identity provider you trust: an OIDC ID token or an ID-JAG. onbehalf verifies the signature and claims, then builds the originating user block from them. The agent must authenticate with its own client secret. The requested capabilities must fit inside the root grant you configured for that issuer and agent.

For local trials only, a development endpoint can mint a root token for a user nobody verified. It is off by default.

## Growing the chain

A holder extends the chain by exchanging its token at `POST /token`. It names the new agent and the capabilities it wants to hand over. If the request is valid, the server returns a new token with one more hop. The old token is unchanged.

The exchange fails if the new capabilities are not covered by the parent hop, if the chain would be deeper than `max_depth`, or if the parent's lease is no longer active. The child's expiry is clamped to the parent's. See [Capabilities and attenuation](capabilities-and-attenuation.md).

## Protecting the user block

When a root token is issued, onbehalf signs the originating user block. The signature is the `ou_sig` claim. Every exchange copies `ou_sig` unchanged. A verifier checks it on its own, apart from the outer token signature. A token whose user block fails the check is rejected. It is never filled in with a default.

## What the chain gives you

- Policy can ask who the user is and how deep the chain is. A rule can say "deny sensitive tools when the depth is more than 2".
- The audit log can name the agent and the user separately on every record. See [Audit log](audit-log.md).
- Revoking one hop's lease stops that hop and everything below it. See [Leases and revocation](leases-and-revocation.md).

## Limits today

- The agent name in an exchange is asserted by the caller. There is no verified `actor_token` yet.
- The user block does not record which credential it came from. The RFC calls this `evidence` and lists it as proposed.
- There is no stable `chain_id` yet. A run is identified by its leases.

More detail: [RFC-0001 section 3](../spec/rfc-0001-onbehalf.md#3-delegation-chain-data-model) and [section 4](../spec/rfc-0001-onbehalf.md#4-token-exchange), and [design/server.md](../design/server.md#hop-0-intake-from-an-identity-provider).
