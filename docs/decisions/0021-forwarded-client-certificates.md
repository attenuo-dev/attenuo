---
status: proposed
date: 2026-11-24
decision-makers: []
consulted: []
informed: []
---

# ADR-0021. TLS client certificates forwarded by a trusted proxy (RFC 9440), on a listener of its own

## Context and Problem Statement

ADR-0019 and ADR-0020 let agents and PEPs authenticate with a TLS client certificate, but only one from attenuo's own handshake (`[server.tls]`). Many deployments end TLS at a reverse proxy or a load balancer. attenuo never sees that handshake, so those clients cannot use certificates at all.

RFC 9440 defines two headers for this: the proxy checks the client's handshake and sends the certificate in `Client-Cert` and its intermediates in `Client-Cert-Chain`.

The threat is plain. attenuo cannot check a header. Whoever can send `Client-Cert` to a listener that trusts it can claim any certificate, and so be any agent or PEP that uses one. A proxy that passes on a client's own copy of the header does the same harm. Done wrong, this turns "mTLS" into "anyone who can reach the port is any client".

Should attenuo trust forwarded certificates, and behind which fences?

## Decision Drivers

- No change for anyone who does not ask for it. Without the new section the headers are ignored, as before, and records hash as before.
- Fail closed: every unclear case is a refusal, at start or per request.
- One source of certificate per request, and one trust decision for both sources: no second implementation of a check.
- Turning header trust on is always visible in the reviewed config file.
- No new crate in `Cargo.lock`.

## Considered Options

- A listener of its own that reads the headers only from listed peer addresses, and every other listener refusing them.
- Read the headers on the main listener, from listed peer addresses.
- A shared secret header from the proxy.
- The proxy connects to attenuo over native mTLS with a pinned certificate, and the headers are trusted only on such connections.

## Decision Outcome

Chosen option: "a listener of its own, listed peers only, refused elsewhere", because each fence holds on its own: a proxy that is bypassed, a listener reached from the wrong place, or a client that sends the header itself all fail closed.

- `[server.forwarded_client_cert]` with `listen` and `trusted_peers`, both required. No key can be set from an environment override, also when the file has the section. Read at start only; a reload does not change it.
- **A listener of its own.** Plain HTTP (the proxy ended TLS). It serves the main router, so state, limits and MCP sessions are shared, but only the routes a client reaches through the proxy: `/token`, `/token/renew`, `/access/v1/evaluation`, `/access/v1/evaluations`, `/access/v1/search/action`, `/mcp/{server}`, `/approvals/{id}`, `/.well-known/jwks.json`, `/.well-known/authzen-configuration`, `/healthz`, `/readyz`. Every other route, `/admin/*` and `/ext-authz/v1/mcp/{server}` included, answers there as an unknown path, for every method, from an outermost layer that checks the matched route. A new route is not served there until it is listed, and a test fails until it is listed as served or not served. `/ext-authz/...` is not served because a gateway copies the agent's headers into its check, and there a copied `Client-Cert` would be read as one the proxy checked. The console and metrics are separate listeners and never there. `listen` equal to the main, admin, console or metrics address (or sharing a port with one on the unspecified address) refuses to start. `[server] public_url` must be an `https://` URL.
- **Peers.** The TCP peer address must be in `trusted_peers`: IP addresses or CIDRs, 1 to 64, none twice, nothing wider than `/8` (IPv4) or `/32` (IPv6), no unspecified address, no bits after the prefix, no IPv4-mapped IPv6 entries, no IPv6 link-local entries (their zone is not compared). An IPv4-mapped peer is compared as IPv4. No header (`X-Forwarded-For`, `Forwarded`) plays a part. Any other peer gets `403 forwarded_peer_not_trusted` for every request, before routing, with `Connection: close`. It is logged at warn with the peer address, at most once per 10 s (the rest at debug, counted).
- **Loud refusal elsewhere.** With the section set, a request with either header on any other listener (main with or without TLS, admin, console, metrics) is `400 client_cert_header_not_accepted`, logged the same way. Without the section the middleware is not mounted at all.
- **Never both sources.** The forwarding listener never speaks TLS and never asks for a certificate. Only its accept loop marks a request as forwarded; the header middleware reads the headers only on such a request, and refuses a request that somehow has a handshake certificate too. `[server.tls]` and this section may both be set: they are different listeners, and each request has one possible source. With `[server.tls]`, the main router's TLS guard accepts forwarded requests in place of TLS ones, because the operator declared that the proxy ended TLS; a plain-HTTP request on any other listener is still refused.
- **Parsing.** By hand, RFC 8941 §4.2 strictly. `Client-Cert`: one line, one Byte Sequence, no parameters, spaces around it allowed; an empty value is malformed, never "no certificate". `Client-Cert-Chain`: optional, one line, a List of at most 4 Byte Sequences (the same bound as the handshake path), no parameters, no empty member, no trailing comma, spaces or tabs around commas and only spaces before the first and after the last; it needs `Client-Cert`. Standard base64 with padding, canonical. At most 16 KiB of DER per certificate and 64 KiB in all (rustls' bound for a handshake's certificate message). Each certificate must be DER that rustls-webpki reads. Anything else is `400 client_cert_header_malformed`, one fixed text, never the header. The headers are removed from the request once read.
- **Authentication.** The certificate becomes the same `ClientCertificate` the handshake makes, with intermediates kept by the same rule, marked `forwarded`, and goes through the same code: the usability check and pins (ADR-0019), the chain, the name and the several-clients rule (ADR-0020), `presented` and SR-109, `actor_auth`, and the one answer (SR-110). A body credential still wins.
- **Cache.** The CA check's answers live with the `ClientCertificate`. On a TLS connection that is one per connection. Here a proxy sends many clients' requests on one connection, so the state is kept per certificate instead: requests that forward byte for byte the same certificate and intermediates kept share one state (key: SHA-256 over each one's length and bytes), with the connection cache's rules unchanged (per CA file `Arc` and name, so a reload never reuses an answer; an accepted path only from when it was checked until the earliest `notAfter`; name refusals kept; no other refusal kept). At most 256 states, the oldest dropped first; a flood of new certificates only makes the check run again.
- **Rate limit.** Every request on this listener comes from the proxy's address. `[limits] token_unauthenticated_requests_per_minute` counts the `/token` requests there that authenticate nobody in one bucket per proxy address (key `forwarded:<address>`, apart from that address's key elsewhere), as when the proxy pointed at the main listener. Over the limit, a request is refused up front, except one whose only credentials are a forwarded certificate and a client id (no secret, assertion, Basic credentials or actor token): it runs and is answered `429` afterwards if it authenticated nobody (the pattern of the full-table rule, SR-109). So secret guessing through the proxy is limited, a made-up certificate earns nothing, and failing floods cannot lock out certificate clients. Agents with secrets behind the proxy share the bucket, as before; the proxy should still limit per client address, and the recipe does. Every other listener keys on the peer address only, whatever certificate a request carries. (A first version counted per certificate and left requests without one uncounted; review found that made secret guessing through the proxy unlimited.)
- **Audit.** `client_cert.source` is `"forwarded"`. Other records are unchanged; no `SCHEMA_VERSION` change. Log lines carry `source` / `client_cert_source`.
- **Rule for certificate settings.** `tls_client_cert_sha256` and `tls_client_ca_pem_path` now need `[server.tls] client_certificates = "optional"` or this section.

### Consequences

- Good, because certificates work behind a TLS-terminating proxy, with the same pins, CAs and names as on the native listener.
- Good, because a client that sends `Client-Cert` to the wrong place is refused and logged, so a spoof attempt or a proxy pointed at the wrong port shows at once.
- Bad, because attenuo sees no proof of possession. It trusts the proxy to have checked the handshake, to strip the client's own copies of both headers, and to set them only from its handshake. attenuo cannot check any of this. A proxy that gets it wrong, or a compromised proxy, can be any certificate client.
- Bad, because anyone who can open a connection from a listed address (any process on the proxy's host, for `127.0.0.1`) can claim any certificate. The guide says to bind the listener where only the proxy reaches it.
- Bad, because with `[server.tls]` too, the forwarding listener takes plain HTTP. That is the operator's declaration; the hop from the proxy to attenuo should be loopback or a private network.
- Bad, because attenuo cannot tell a proxy in TCP mode from one in HTTP mode without a shared secret, which this design avoids (a secret to provision and leak); a fixed marker a client of a TCP-mode proxy can send too. Even a secret would only show that the proxy's HTTP rules run, not that it removes the client's own headers; nothing attenuo can see shows that. Either mistake lets every client claim any certificate. The guide's recipe is checked against the real proxy, and the guide makes a forged-header test a required step.
- Bad, because attenuo cannot limit by client address on this listener: secret clients behind the proxy share one bucket, and over the limit each request with a certificate still costs one client authentication. The proxy should limit per client address.
- Bad, because the CA check runs for each new certificate through the proxy rather than once per connection; repeat requests with the same certificate are answered from the shared state.
- Neutral, because proxies differ: HAProxy can send the leaf (`ssl_c_der,base64`) but not the chain as a list, so the intermediate CA goes in the entry's CA file. nginx has no RFC 9440 form without scripting. Envoy's default is its own `x-forwarded-client-cert`, which is not read.

### Confirmation

- `crates/attenuo-server/tests/forwarded_client_cert.rs`: real sockets through `attenuo_server::run`. Agents and PEPs by pins and by CA (SAN URI and DNS, with a forwarded intermediate), next to a native TLS listener; audit `source`; the headers refused on the main (plain and TLS), admin, console and metrics listeners, and ignored without the section; an untrusted peer (127.0.0.2) refused, `X-Forwarded-For` of no use; the admin API absent and the listed routes present; malformed, repeated, empty and oversized headers; two certificates alternating on one kept-alive connection; A's certificate with B's id; a body credential; `actor_auth = "actor_token"`; refusals equal to the native ones; a reload; the rate limit (wrong secrets with and without made-up certificates limited, a made-up certificate never served over the limit, certificate clients served after a flood, the native listener per address); start refusals; environment overrides; a small TLS proxy in the test that ends a real handshake and forwards; the guide's HAProxy block equal to the recipe file.
- Unit tests in `forwarded.rs` (the parser, the peers, the section rules, the log throttle, every route of the router decided for this listener, the route allowlist, the headers gone before a handler), `client_pki.rs` (the shared states, mirroring the per-connection cache tests) and `config/overrides.rs`.
- The fuzz target `forwarded_client_cert`: compiled; not run here (no nightly toolchain).
- The HAProxy recipe [`deploy/haproxy/forwarded-client-cert.cfg`](https://github.com/attenuo-dev/attenuo/blob/main/deploy/haproxy/forwarded-client-cert.cfg), run as it is by `scripts/haproxy-forwarded-smoke.sh` with HAProxy 2.8.30 and `attenuo-server` on 2026-11-24, over HTTP/1.1 and HTTP/2: a pinned and a CA-issued certificate accepted; no TLS session resumed (`tune.ssl.cachesize 0`, `no-tls-tickets`); the recipe's per-address `/token` limit; a stranger's certificate refused; forged `Client-Cert` and `Client-Cert-Chain` from clients with and without a certificate removed by HAProxy (`client_auth_missing` / `client_authentication_failed`); a direct request from 127.0.0.2 refused; the header on the main listener refused; `haproxy -c` without warnings. A first draft of the guide's recipe left out `mode http`; HAProxy then ran in TCP mode, ignored the header rules (with only a warning) and passed a client's forged `Client-Cert`, which a review reproduced. Not run: HAProxy's `ssl_c_verify` variant, nginx, Envoy, other HAProxy versions.

## Pros and Cons of the Options

### A listener of its own, listed peers, refused elsewhere

- Good, because a bypassed proxy or a misdirected client meets a listener that ignores, or refuses, the header.
- Bad, because it is one more port to bind and protect.

### The headers on the main listener, from listed peers

- Good, because there is no new port.
- Bad, because every client of the main listener is then one mistake (a wrong CIDR, a proxy on the same host as other clients) from claiming any certificate.

### A shared secret header

- Good, because it does not depend on addresses.
- Bad, because it is a secret to provision, rotate and leak, which is what certificates were meant to remove.

### The proxy over native mTLS

- Good, because the proxy proves itself with a key, not an address.
- Bad, because it needs a TLS listener that also reads headers, against "one source per listener", and a certificate story for the proxy. A possible follow-up.

## More Information

Not done here: Envoy's `x-forwarded-client-cert`; the proxy authenticated by its own certificate; reloading `listen` or `trusted_peers`; certificate-bound tokens (`cnf.x5t#S256`).

Related: ADR-0013, the admin listener, the model for a listener of its own; ADR-0018, the native TLS listener; ADR-0019 and ADR-0020, whose checks this reuses.
