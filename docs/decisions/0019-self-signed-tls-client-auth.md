---
status: proposed
date: 2026-11-24
decision-makers: []
consulted: []
informed: []
---

# ADR-0019. Self-signed TLS client certificates for agents and PEPs, pinned by thumbprint

## Context and Problem Statement

Agents and PEPs authenticate with a client secret or with `private_key_jwt` (ADR-0017). ADR-0007 and ADR-0017 set mTLS aside because attenuo did not do the TLS handshake itself. ADR-0018 added a native TLS listener, so the handshake is now attenuo's own.

Some clients already hold a key pair and a certificate for TLS, and would rather not keep a shared secret or sign a JWT per request. RFC 8705 §2.2 defines `self_signed_tls_client_auth`: the client sends a self-signed certificate in the handshake, and the server knows the certificate (here, by its SHA-256) from the client's registration.

Should attenuo accept a TLS client certificate as a client credential, and how?

## Decision Drivers

- No change for anyone who does not ask for it. A server without the new settings asks for no certificate, and its records hash as before.
- Fail closed: a certificate setting the listener cannot use stops the server.
- The trust decision must follow `POST /admin/agents/reload`, also for TLS connections that are already open.
- One answer for every refusal (SR-110), and the SR-109 rule for a full peer table.
- No new crate in `Cargo.lock`, no `unsafe`, no X.509 parser beyond what rustls already ships.

## Considered Options

- Self-signed certificates pinned by SHA-256 on the entry, trust decided per request (`self_signed_tls_client_auth`).
- Certificates from a CA, matched by subject or SAN (RFC 8705 §2.1, `tls_client_auth`).
- Trust a certificate forwarded by a proxy in a header (`Client-Cert`, RFC 9440, or `X-Forwarded-Client-Cert`).
- Decide in the handshake: refuse any certificate that is not pinned.

## Decision Outcome

Chosen option: "self-signed certificates pinned by SHA-256, trust decided per request", because it needs no PKI, no name matching and no trust in a proxy, and it fits the reload model.

- `[server.tls] client_certificates = "off" | "optional"`, default `"off"`. With `"optional"` the handshake asks for a certificate, with an empty list of acceptable issuers, and never requires one. There is no `"required"`: a server that needs every client to use a certificate can give the entries no other credential.
- The handshake proves possession only. A custom rustls `ClientCertVerifier` (`client_cert_verifier.rs`) parses the end-entity certificate and verifies the TLS 1.3 `CertificateVerify` signature with the provider's algorithms. It builds no chain and checks no dates. TLS 1.2 is refused (the listener speaks TLS 1.3 only). Session resumption stays off, so every certificate a request carries was proven on that connection.
- The accept loop puts the certificate on every request of the connection, as a typed extension next to `ServedOverTls`. Nothing else sets it: no header is read for it.
- `tls_client_cert_sha256 = [...]` on `[[agents]]` and `[[peps]]`: 1 to 8 values, each 64 lowercase hex characters. A value listed twice in an entry, or by two entries of one list, is refused at start and at a reload. A certificate counts as the entry's credential, so an entry may have only this.
- Any `tls_client_cert_sha256` refuses to start (and a reload) unless `[server.tls]` is set with `client_certificates = "optional"`.
- A request uses the certificate when it names the client (`client_id`, or `pep_id`), carries no secret, no Basic and no assertion, and its connection has a certificate. A body credential wins: the certificate is then ignored. The thumbprint is compared in constant time with each pin of the entry; an unknown id makes the same number of comparisons against a dummy value.
- The pinned certificate must also be usable as a client certificate at the time of the request. rustls' `WebPkiClientVerifier`, with the certificate itself as the only trust anchor, checks this: within `notBefore` and `notAfter`, not a CA certificate, `clientAuth` in its extended key usage when it has one, no unknown critical extension, signed by its own key. This uses only rustls and rustls-webpki, already in the build.
- Every refusal is 401 `invalid_client` / `client_authentication_failed` with one `detail`. The reason (`unknown_client`, `no_certificate_settings`, `thumbprint_mismatch`, `certificate_expired`, `certificate_not_yet_valid`, `certificate_not_usable`) is logged at debug only (SR-110).
- `clientauth::presented` and the SR-109 check count "a client id plus a certificate" as client credentials.
- `[token] actor_auth` treats the certificate like the other client credentials: accepted under `"secret"` and `"either"` (with an actor token too, both are checked), refused under `"actor_token"` with `client_auth_not_accepted`.
- Audit. The method is `self_signed_tls_client_auth`, or `actor_token+self_signed_tls_client_auth`, in `agent_auth` / `actor_auth`. Records of requests authenticated this way carry `client_cert` = `{"x5t#S256": "<base64url>", "source": "tls"}` in their digested arguments. Other records are unchanged. No `SCHEMA_VERSION` change.
- Reload. Thumbprints are part of an entry: a change shows under `changed`, and the canonical form behind each list's `sha256` gets one more member, only in the rows of entries that have thumbprints. A list without them keeps its digest.
- Environment overrides. No `[server.tls]` key, `client_certificates` included, can be set from `ATTENUO__...` variables, also when the file has the section, as for `[dev]`: every TLS setting is in the reviewed file.
- A batch (`POST /access/v1/evaluations`) checks the certificate once per request and `pep_id`, and its entries reuse the result, as a client assertion is checked once for the request. A refusal refuses the whole request, so it is never reused.
- Discovery. attenuo publishes no OAuth authorization server metadata, so there is no `token_endpoint_auth_methods_supported` to extend. It never advertises `tls_client_certificate_bound_access_tokens`.

### Consequences

- Good, because a client can authenticate with no shared secret and no per-request JWT, using the key it already holds for TLS.
- Good, because a reload applies at once, also to connections that are already open: the handshake does not cache a trust decision.
- Good, because an expired certificate stops working with no reload.
- Bad, because it needs attenuo's own TLS listener. A proxy that ends TLS in front hides the certificate. Clients must connect directly or through a TCP (layer 4) pass-through.
- Bad, because there is no CRL or OCSP check. A stolen key works until its thumbprint is removed and the lists are reloaded, or the certificate expires.
- Bad, because the issued tokens are bearer or DPoP-bound, not bound to the certificate (no `cnf.x5t#S256`). The certificate proves who asked for a token, not who uses it.
- Bad, because the `attenuo` CLI and the SDKs cannot present a client certificate yet, and the Helm chart and the image's health check do not support `[server.tls]` (ADR-0018).
- Bad, because a plain `openssl req -x509` certificate has `CA:TRUE` and is refused. The guide gives the `-addext` lines that make a usable one.
- Bad, because with `"optional"` a client can send up to 64 KiB of certificate data, which the server keeps for the life of the connection.
- Neutral, because with `"optional"` every client is asked for a certificate. A client that has none answers with an empty certificate message and goes on.
- Neutral, because a certificate on the connection makes `client_id` a client credential, also next to an actor token. Under `actor_auth = "actor_token"`, a request with an actor token and a `client_id` over such a connection is refused (`client_auth_not_accepted`). Under `"either"` both are checked, so a certificate that is not pinned for that `client_id` refuses the request (`client_authentication_failed`) even when the actor token is good. The fix for the client: leave `client_id` out, or present no certificate.

### Confirmation

- `crates/attenuo-server/tests/mtls.rs`: real TLS 1.3 handshakes through `attenuo_server::run`. An agent at hop 0 and at an exchange, and a PEP on the AuthZEN endpoints (with and without a bearer), authenticate with their certificates; a rotation with two thumbprints. One answer for an unknown thumbprint, A's certificate with B's id, a certificate for an entry with a secret only, an unknown id and a PEP's certificate used as an agent. No certificate is `client_auth_missing`. A certificate sent with a handshake signed by another key fails the handshake. A wrong secret next to a pinned certificate is refused. Expired, not-yet-valid, CA and server-only certificates are refused like an unknown one. `"off"` never asks for a certificate, and pins with `"off"` or without `[server.tls]` stop `build`. Forwarded-certificate headers change nothing. Each `actor_auth` mode. A reload that removes and adds a thumbprint, on open connections. SR-109 from many loopback addresses. The audit digests with and without `client_cert`. Discovery. A plain server, unchanged.
- Unit tests in `client_cert_verifier.rs`, `client_cert.rs`, `clientauth.rs` (the config rules, the comparisons, the list digest and changes), `tls.rs`, `config.rs`, `config/overrides.rs` (no `[server.tls]` key from the environment) and `routes/authzen.rs` (a batch checks a certificate once per `pep_id`).

## Pros and Cons of the Options

### Self-signed, pinned by thumbprint, decided per request

- Good, because it needs no CA, no name rules and no trust in anything but the handshake.
- Good, because it works with the reload model.
- Bad, because every certificate change is a config change and a reload.

### CA-issued certificates matched by name (`tls_client_auth`)

- Good, because a CA can issue and renew certificates with no change to attenuo's config.
- Bad, because it needs chain building, trust anchors per entry, name matching rules (subject DN, SAN DNS/URI/IP, SPIFFE IDs) and revocation. Each is a design of its own. It is a follow-up.

### A certificate forwarded in a header

- Good, because it works behind a TLS-terminating proxy.
- Bad, because attenuo would have to trust the proxy to strip and set the header. A missed strip lets any caller claim any certificate. Not done.

### Decide in the handshake

- Good, because an unpinned certificate would fail early.
- Bad, because the decision would be stale after a reload on a connection that stays open, and a handshake failure tells the caller more than one 401 does.

## More Information

Not done here, each for a later change:

- CA chains and name matching (`tls_client_auth`, SAN, SPIFFE X.509-SVIDs).
- Certificate-bound access tokens (`cnf.x5t#S256`, RFC 8705 §3).
- Forwarded certificate headers.
- CLI and SDK options to present a client certificate.
- `x5c` in JWK Sets, CRL and OCSP.

Related: ADR-0007 and ADR-0017, which set mTLS aside; ADR-0018, the native TLS listener; ADR-0014, the SR-109 rule; ADR-0017's SR-110 update, one answer for refusals.
