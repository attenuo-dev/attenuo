---
status: proposed
date: 2026-11-24
decision-makers: []
consulted: []
informed: []
---

# ADR-0022. Certificate-bound access tokens (RFC 8705 §3), one binding per token, the same certificate for every child

## Context and Problem Statement

ADR-0019, ADR-0020 and ADR-0021 let an agent authenticate at `/token` with a TLS client certificate. The token it gets is still a bearer token, or a DPoP-bound one. Whoever copies the token can use it without the certificate.

RFC 8705 §3 binds a token to the certificate instead. The token carries `cnf.x5t#S256`, the base64url SHA-256 of the certificate's DER. A resource server takes it only over a connection that shows that certificate. Agents that already hold certificates (SPIFFE X.509-SVIDs, pinned self-signed ones) get sender-constrained tokens without a DPoP key.

The hard parts are the exchange and the places a token is presented. A DPoP holder can sign a sign-off for a child bound to another key (SR-40). A TLS certificate cannot sign anything inside HTTP, and a connection shows one certificate. Every route that takes a token must also see the certificate of that request, from attenuo's own handshake or from a trusted proxy.

Should attenuo bind its tokens to client certificates, and with which rules?

## Decision Drivers

- No change for anyone who does not ask for it. Off by default; tokens with only `jkt` stay byte for byte as they are; records of other requests hash as before.
- Fail closed: an unclear case is a refusal, at start or per request.
- One binding per token. A token is never both key-bound and certificate-bound.
- A binding never weakens along a chain: no unbound child, no child bound to something else.
- The certificate comes only from the two places that already decide it: the TLS accept loop and the forwarding listener's header check (ADR-0021).

## Considered Options

- Bind to the certificate that authenticated the agent at `/token`, and give every child the same certificate.
- The same, and let a parent's holder name another certificate for the child.
- No certificate binding; agents use DPoP.

## Decision Outcome

Chosen option: "bind to the certificate that authenticated, the same certificate for every child", because it is the part of RFC 8705 §3 that needs no new trust decision. Cross-holder delegation is not implemented.

- **Setting.** `[token] tls_client_certificate_bound_access_tokens`, the RFC 8705 metadata name. Default `false`. With `true` the server refuses to start without a listener that takes client certificates (`[server.tls] client_certificates = "optional"` or `[server.forwarded_client_cert]`). It also refuses `[token] dpop = "required"`. That mode means every token is bound to a DPoP key, and a token holds one binding only, so a certificate-bound token would break it.
- **Token format.** `Confirmation` holds exactly one of `jkt` and `x5t#S256`. A `cnf` with both, with neither, with another member, or with a non-string value is refused when a token is parsed, and the issuer refuses to sign one. The value must decode to 32 bytes. A `jkt` token serializes exactly as before.
- **Issue.** With the setting on, `POST /token` binds the token to the certificate when the agent authenticated with it (`self_signed_tls_client_auth` or `tls_client_auth`, from the handshake or forwarded). This covers hop 0 (ID token or ID-JAG intake) and an exchange of an unbound parent. A client that authenticated with a secret, an assertion or an actor token alone is not bound, even over a connection with a certificate. An actor token together with a certificate client (`actor_auth = "either"`) is bound. `token_type` is `Bearer`, because RFC 8705 §3 sends the token as a bearer token over mutual TLS; it is `DPoP` only for a `jkt` token. A request that would be bound to the certificate and carries a `DPoP` header is refused with 400 `invalid_request` / `dpop_with_certificate_binding`. The dev mint (`/admin/root-token`) never binds to a certificate.
- **Use.** A certificate-bound token is accepted only on a request whose verified client certificate has the same SHA-256, compared in constant time. This holds whatever the setting says now: once bound, always bound. Every refusal is 401 `invalid_token`:
  - `client_certificate_required`: no certificate on the request (a plain listener, a TLS connection without one, the ext-authz adapter);
  - `client_certificate_mismatch`: another certificate, also one from the same CA with the same SAN, and the next certificate of a rotation;
  - `dpop_with_certificate_binding`: a `DPoP` header or the `DPoP` authorization scheme.
- **Routes that take a token, and where the check is.** One function, `cert_binding::check_presented`, for all of them except the exchange:
  - `/mcp/{server}` (`POST`, `GET`, `DELETE`): `ServerAuthorizer::authenticate_request`. The proxy crate does not know the server's certificate type, so a server middleware gives it the thumbprint as `ClientCertThumbprint`, and only from the server's `ClientCertificate`.
  - `/ext-authz/v1/mcp/{server}`: the same authorizer, always without a certificate. The connection there is the gateway's, not the agent's, so a certificate-bound token is always refused. The forwarding listener does not serve the route (ADR-0021).
  - `POST /token/renew`: `routes::renew`.
  - `POST /access/v1/evaluation`, `/evaluations` and `/search/action` with a bearer: `routes::authzen::bearer_auth`. A PEP that calls with its own certificate cannot present an agent's certificate-bound token, because the certificate it shows is its own.
  - `GET /approvals/{id}` with a delegation token: `routes::approvals`.
  - `POST /token` with the token as `subject_token`: `cert_binding::bind_exchange`.
  - `ServerAuthorizer::authenticate` without a request (a caller with no headers) refuses every bound token.
- **Exchange.** A child of a certificate-bound token gets the same `x5t#S256`, whoever it is for and however that actor authenticated, and the request must show that certificate. No `DPoP` header and no `subject_token_dpop` are taken with such a subject token (`dpop_with_certificate_binding`). So there is no way to get an unbound child, a key-bound child, or a child bound to another certificate. These refusals come before a client assertion is recorded, so a corrected request can send the same assertion again (SR-108, SR-111). At `/token` a missing or wrong certificate is 401, as a missing DPoP proof for a key-bound subject token is there. A `jkt` parent keeps the DPoP rules exactly, whatever this setting says; its child is key-bound. An unbound parent's child is bound as at hop 0.
- **Approval tokens** are never certificate-bound. For a certificate-bound hop the approval token carries no key binding and stays tied to the lease and the call, as for a bearer hop. An approval token with an `x5t#S256` `cnf` is refused.
- **ID-JAG.** An ID-JAG with `cnf.x5t#S256` is still refused as an unsupported confirmation method. (Changed by [ADR-0025](0025-id-jag-certificate-binding.md): such an ID-JAG is now accepted from an agent that authenticated with that certificate.) An ID-JAG with `cnf.jkt` needs a DPoP proof, so with the setting on an agent that authenticates with its certificate cannot use one: with a `DPoP` header the request is 400 `dpop_with_certificate_binding`, and without one it is 400 `invalid_grant` / `credential_pop_required`.
- **Audit.** Records of requests made with a certificate-bound token, and of issuances that bound a token to a certificate, carry `"cert_bound": true` in the record, and the issuance and renewal arguments carry `"cert_bound": true` too. The member is omitted otherwise, so other records hash as before. No `SCHEMA_VERSION` change. Refused presentations and refused exchange bindings are not audited, as DPoP failures are not.
- **Rotation.** A token dies with its certificate. A new certificate, even for the same agent and pinned next to the old one, does not carry the binding over. The agent gets new tokens with the new certificate.

### Consequences

- Good, because a copied token is useless without the certificate's private key, on every route that takes it.
- Good, because an agent with a SPIFFE X.509-SVID gets sender-constrained tokens with no second key.
- Good, because the forwarded path keeps the ADR-0021 fences. An untrusted peer gets 403 before routing, a `Client-Cert` header on another listener gets 400, and without the section the header is ignored, so it never satisfies a binding.
- Bad, because a sub-agent with its own certificate cannot get a child bound to it. The parent's holder must make each exchange over its own connection, and the child is bound to the parent's certificate. This is open question 1 of RFC-0001.
- Bad, because the ext-authz adapter and external PEPs that verify tokens themselves cannot use certificate-bound tokens. AuthZEN has no field in which a PEP could pass the certificate it saw, and attenuo would have to trust the PEP's word.
- Bad, because a certificate rotation ends the tokens bound to the old certificate. With short-lived SVIDs, a token can live longer than its certificate's next rotation and then fails with `client_certificate_mismatch`.
- Neutral, because the setting off does not unbind tokens issued while it was on.

### Confirmation

- `crates/attenuo-server/tests/cert_bound_tokens.rs`: real sockets through `attenuo_server::run`, a native TLS listener and the forwarding listener. Hop 0 and exchanges by pinned and CA-issued certificates, both sources, `token_type`, the record and its digest; off by default; a secret does not bind; DPoP refused at issue (hop 0, exchange of an unbound and of a bound parent, `subject_token_dpop`); every route above with the bound certificate, none, a pinned certificate of another agent, a second certificate from the same CA with the same SAN, a DPoP proof and the `DPoP` scheme; children and grandchildren keep the certificate; a `jkt` parent keeps the DPoP rules; replay on a plain listener, with a `Client-Cert` header there, from an untrusted peer of the forwarding listener, without the forwarded section, and through ext-authz; rotation; the setting turned off later; start refusals; `DELETE` and a JSON-RPC batch on the proxy; a refused exchange that leaves the client assertion unused; a DPoP-bound ID-JAG; actor tokens; several tokens on one kept-alive connection. Unit tests in `attenuo connect` for its note on a certificate-bound token.
- Unit tests in `attenuo-token` (`cnf` parsing, `check_child_binding`, approval tokens, `token_type`), `crates/attenuo-token/tests/token_exchange.rs`, `cert_binding.rs` and `config.rs`.

## Pros and Cons of the Options

### The same certificate for every child

- Good, because the connection that shows the parent's certificate is all the proof the exchange needs.
- Bad, because delegation to a holder with another certificate is not possible.

### A parent's holder names another certificate for the child

- Good, because it allows delegation to a sub-agent's own certificate.
- Bad, because the child agent is then not the one that authenticates, or the parent must sign a sign-off with a key from its certificate, which is a new protocol. It needs its own design.

### No certificate binding

- Good, because there is nothing new to check.
- Bad, because agents with certificates need a second key for sender-constrained tokens.

## More Information

Not done here: cross-holder delegation, ID-JAG `cnf.x5t#S256` (since done, [ADR-0025](0025-id-jag-certificate-binding.md)), SDK support, a thumbprint passed by an external PEP.

Related: ADR-0019, ADR-0020 and ADR-0021, which decide the certificate; RFC-0001 section 4.1 for DPoP.
