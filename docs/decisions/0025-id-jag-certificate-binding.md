---
status: proposed
date: 2026-11-26
decision-makers: []
consulted: []
informed: []
---

# ADR-0025. ID-JAG bound to a TLS client certificate (`cnf.x5t#S256`): accepted only from an agent that authenticated with that certificate, and only when the root token is bound to it

## Context and Problem Statement

An IdP can bind an ID-JAG to a holder with a `cnf` claim (draft-ietf-oauth-identity-assertion-authz-grant -06 §9.11). attenuo accepts `cnf.jkt` at hop 0: the request needs a DPoP proof by that key, and the root token is bound to the same key. Until now a `cnf.x5t#S256` (a TLS client certificate, -06 §9.11.2, RFC 8705 §3.1) was refused as an unsupported confirmation method.

ADR-0019 to ADR-0021 let an agent authenticate with a TLS client certificate, from attenuo's own handshake or from a trusted proxy. ADR-0022 binds attenuo's own tokens to that certificate. So a request can now show a verified certificate, and the server can check an ID-JAG bound to one.

Which certificate counts, what is the root token bound to, and what is refused?

## Decision Drivers

- The binding the IdP asked for is never dropped. An ID-JAG that demands a holder never becomes a bearer root token. The `cnf.jkt` path already works this way: with `[token] dpop = "off"` such an ID-JAG is refused.
- Do not weaken how the agent is identified at hop 0. The agent always authenticates, and the ID-JAG's `client_id` must be that agent.
- Fail closed. A `cnf` the server cannot check fully is refused.
- A refusal the client can correct uses nothing up (SR-108, SR-111).
- No change for a deployment that does not use certificate binding, except clearer error codes.

## Considered Options

- Accept when the certificate that authenticated the agent has the thumbprint, and bind the root token to it. Refuse when tokens are not bound to certificates.
- Accept when any verified certificate on the request has the thumbprint, whatever authenticated the agent.
- The same as the first, but issue an unbound root token when tokens are not bound to certificates.
- Keep refusing `cnf.x5t#S256`.

## Decision Outcome

Chosen option: the first. An ID-JAG with `cnf.x5t#S256` is accepted at hop 0 only when all of these hold. They are checked in this order:

1. The request has no `DPoP` header. A token has one binding (ADR-0022). Otherwise 400 `invalid_request` / `dpop_with_certificate_binding`.
2. `[token] tls_client_certificate_bound_access_tokens` is on. Otherwise the root token would be a bearer token, so 400 `invalid_grant` / `credential_cert_required`.
3. The agent authenticated with a verified TLS client certificate on this request: `self_signed_tls_client_auth` or `tls_client_auth`, from the handshake or from a trusted proxy's `Client-Cert` header (ADR-0021). An actor token together with such a certificate client counts. A certificate on the connection that did not authenticate the agent does not count: the agent sent a secret or a client assertion, or only an actor token. Otherwise 400 `invalid_grant` / `credential_cert_required`.
4. The SHA-256 of that certificate equals the `x5t#S256` value, compared in constant time. Otherwise 400 `invalid_grant` / `credential_cert_mismatch`. A second certificate from the same CA with the same SAN authenticates as the same agent but is another certificate, so it is refused.

The root token is then bound to that certificate (`cnf.x5t#S256`, `token_type` `Bearer`), as ADR-0022 binds any token of an agent that authenticated with its certificate. Its children keep the binding under the ADR-0022 rules. Before it signs, the server checks that the root token's `cnf` is the ID-JAG's. It cannot differ; if it did, the request would be refused.

What the root token is bound to, by setting:

| `tls_client_certificate_bound_access_tokens` | Agent authenticated with the bound certificate | Result |
| --- | --- | --- |
| `true` | yes | root token bound to that certificate |
| `true` | no (another method, or no certificate) | refused, `credential_cert_required` |
| `true` | yes, another certificate | refused, `credential_cert_mismatch` |
| `false` (the default) | any | refused, `credential_cert_required` |

**The `cnf` claim is read strictly.** It must be absent, `null`, or an object with exactly one member: `jkt` (a non-empty string) or `x5t#S256` (43 base64url characters without padding that decode to 32 bytes, in the one canonical spelling). Both members, another member (RFC 7800 `jwk`, `kid` and the like), or an `x5t#S256` of the wrong length or encoding are refused with 400 `invalid_grant` / `credential_cnf_unsupported`. Before this change a `cnf` with `jkt` and other members was accepted as a `jkt` binding and the other members were ignored. The cases that were refused before keep `credential_pop_required`: a `cnf` that is not an object, an empty object, and a `jkt` that is not a non-empty string.

**Order and single use.** The `cnf` rules run twice. First on the ID-JAG's payload right after the agent is authenticated, before the signature is checked and before anything single-use is recorded: a client assertion's `jti`, a DPoP proof's `jti`, the ID-JAG, the actor token. So a refusal for the binding uses nothing up, and the client can send the request again corrected. Such a refusal is counted by `[limits] token_requests_per_minute`, as the exchange's early binding refusal is. A client assertion that was already used is the exception: on such a refusal its `jti` is looked up in the replay store without being recorded, and a used one is answered 401 `invalid_client` / `client_assertion_replayed`, as it would be later, and is not counted. Without this, whoever holds an old assertion of an agent could spend that agent's budget with forged ID-JAGs. The exchange's early binding refusal (ADR-0022) does the same. If the replay store cannot be read, the early refusal is answered 503 `temporarily_unavailable` / `replay_store_unavailable`, records nothing and is not counted.

**What is left.** An assertion that leaked before its first use can still be sent with forged ID-JAGs, and each such early refusal is counted against the agent's `token_requests_per_minute`. So whoever holds it can rate-limit the agent for a short window. The early refusal does not record the assertion on purpose: the client must be able to send the corrected request with the same assertion. The window ends when the assertion is first used or at its `exp`, at most `[token] client_assertion_max_lifetime_seconds` after it was made. This first pass can only refuse. Then again on the verified claims, which decide. Every `cnf` refusal, also the old `credential_pop_required` cases, therefore comes before the `typ`, issuer and signature checks, `no_capabilities_requested` and DPoP proof errors. A forged ID-JAG may get a binding code instead of `bad_signature`; it is refused either way. A `cnf.jkt` without its proof is decided after the signature, as before.

**Audit.** The `token.root` record of an ID-JAG bound to a certificate carries `"id_jag_cnf": "x5t#S256"` in its digested arguments, next to `cert_bound` and `client_cert` from ADR-0022. Other records do not get the member, so they digest as before. No `SCHEMA_VERSION` change. Refusals are not audited, as other intake refusals are not. The info line has `id_jag_cnf` too.

**No new setting.** Acceptance needs `[token] tls_client_certificate_bound_access_tokens = true`, which is off by default. A deployment without it refuses these ID-JAGs as before, with `credential_cert_required` instead of `credential_pop_required`.

### The trust argument

The IdP signs the ID-JAG. With `cnf.x5t#S256` it says that only the holder of this certificate may use it. The `client_id` in it must still be the authenticated agent. Requiring the certificate to be the one that authenticated the agent ties the two together: the IdP vouches for the thumbprint, and the `[[agents]]` entry vouches for the certificate (a pinned thumbprint, or a CA and a SAN). The second option would let a client authenticate with a secret and show any certificate the IdP named. That is what -06 asks for, but a leaked secret plus a certificate that is not configured for the agent would be enough. The rule chosen is stricter than the draft, and it needs no new trust decision: the root token is bound to a certificate the server already trusts for the agent.

### Consequences

- Good, because an agent with a certificate can use certificate-bound ID-JAGs, and the root token keeps the IdP's binding.
- Good, because a copied ID-JAG is useless without the certificate's private key and the agent's configured certificate.
- Good, because a `cnf` the server only partly understands is now refused instead of partly ignored.
- Bad, because an agent that authenticates with a secret or an assertion cannot use a certificate-bound ID-JAG, even over a connection that shows the certificate. The draft would allow it.
- Bad, because the setting off refuses these ID-JAGs, even when the agent has the certificate. Turning it on binds every token of certificate-authenticated agents (ADR-0022).
- Bad (BREAKING for an IdP that sent them), because an ID-JAG whose `cnf` has `jkt` and another member was accepted before and is now refused.

### Confirmation

- `crates/attenuo-server/tests/cert_bound_tokens.rs`, through `attenuo_server::run` with the native TLS listener and the forwarding listener: accepted with a pinned and with a CA-issued certificate, from the handshake and forwarded, with the record and its digest; a child that keeps the certificate on the proxy; replay of the ID-JAG; no certificate; a certificate that did not authenticate the agent; another pinned certificate; a second certificate from the same CA with the same SAN; an actor token alone; a DPoP proof alongside, with the setting on and off; both `cnf` members, an unknown member, an `x5t#S256` of the wrong length or encoding; the setting off; a `Client-Cert` header on the main listener, from an untrusted peer of the forwarding listener, and without the forwarded section; after the refusals, the same ID-JAG, DPoP proof and client assertion still work.
- `crates/attenuo-server/tests/oidc.rs`: on a server without certificate binding, an ID-JAG bound to a certificate is refused, and a `cnf` with an unsupported member is refused.
- Unit tests: `idp::claims` (the `cnf` parser) and `idp::intake` (the order of the rules and their codes).

## Pros and Cons of the Options

### The certificate that authenticated the agent

- Good, because the certificate is one the operator configured for the agent.
- Bad, because a secret or assertion client cannot use such an ID-JAG.

### Any verified certificate on the request

- Good, because it follows -06 §9.11.2 most closely.
- Bad, because the IdP's word alone would decide that a certificate the operator never configured is the agent's holder key.

### An unbound root token when tokens are not bound to certificates

- Good, because it works without ADR-0022.
- Bad, because the binding the IdP asked for would be dropped, which the `cnf.jkt` path never does.

### Keep refusing

- Good, because there is nothing new to check.
- Bad, because agents with certificates cannot use certificate-bound ID-JAGs.

## More Information

Not done here: a certificate-bound ID-JAG for an agent that authenticates with a secret or an assertion; the `jwt-dpop` grant type; a thumbprint passed by an external PEP.

Related: ADR-0019, ADR-0020 and ADR-0021, which decide the certificate; ADR-0022, which binds the root token. ADR-0022 says that an ID-JAG with `cnf.x5t#S256` is refused; this ADR changes that one point.
