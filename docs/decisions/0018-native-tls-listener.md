---
status: proposed
date: 2026-11-24
decision-makers: []
consulted: []
informed: []
---

# ADR-0018. Native TLS on the main listener: optional `[server.tls]`, TLS 1.3 only, read at start, no client certificates yet

## Context and Problem Statement

The server spoke plain HTTP on every listener. TLS had to end in a reverse proxy in front of it. That is still the usual setup, but some deployments have no proxy: a single host, a sidecar, a small pilot. They had to add one only for TLS, or set `[server] allow_insecure_http = true` and send tokens in cleartext.

There is a second reason. mTLS client authentication (RFC 8705) needs a TLS handshake that attenuo sees itself, or a proxy that forwards the client certificate in a header that attenuo must trust. ADR-0007 and ADR-0017 set mTLS aside because attenuo had no TLS of its own. A listener that does the handshake is the first step, and it is useful by itself.

Should the server speak TLS itself, and on which listeners?

## Decision Drivers

- No change for anyone who does not ask for it: without the new section the listener is plain HTTP, exactly as before.
- Fail closed at start: a certificate or key the server cannot use stops it, with a message that names the file and never its content.
- No new crate in `Cargo.lock`. rustls and tokio-rustls are already in every build through reqwest.
- The protections of the plain listener hold for TLS too: the header-read timeout (S-4) and graceful shutdown. The in-flight cap counts requests and still applies to them; it does not count connections or handshakes.
- Room for client certificates later, without a second listener design.

## Considered Options

- An optional `[server.tls]` on the main listener only, TLS 1.3 only, files read at start.
- The same, on every listener (main, `[admin] listen`, console, metrics).
- The same, with the certificate reloaded without a restart.
- No native TLS: keep the reverse proxy as the only way.

## Decision Outcome

Chosen option: "an optional `[server.tls]` on the main listener only, TLS 1.3 only, files read at start", because it is the smallest change that removes the need for a proxy, and it is the base that mTLS client authentication needs.

- `[server.tls]` has two keys, `cert_pem_path` (the server certificate first, then intermediates) and `key_pem_path` (one private key: PKCS#8, SEC1 or PKCS#1, not encrypted). Unknown keys are refused. It cannot be created from an environment override, so turning TLS on is always in the reviewed file.
- The server reads both files once, at start, with the size and file-type rules of `ca_pem_path`. It refuses an unreadable, empty or oversized file, a certificate file with no certificate or with a private key in it, an encrypted one included (unless it is also the key file), a key file with no key, an encrypted key or more than one key, a key that does not belong to the first certificate, and, on Unix, a key file whose owner or mode breaks PostgreSQL's rule for `ssl_key_file`: owned by the server's effective user or by root, no bit for others, no group write or execute, and group read only when root owns the file (at most `0640` for root, `0600` for the server's own user). The owner and mode are read from the open file. Group read for a root-owned file is what lets a Kubernetes Secret volume with `fsGroup`, or a distribution's `ssl-cert` group, give the key to a server that does not run as root. No error shows any part of a key: every error about the files is a fixed text that names the file, the config key and the kind of problem, never a parser's or rustls's detail, and a certificate file that mentions `PRIVATE KEY` anywhere counts as holding a key. The server does not check its own certificate's dates.
- With `[server.tls]`, `[server] public_url` must be set and `https://`, and `allow_insecure_http` is refused. Without a `public_url`, discovery and DPoP would name `http://` URLs for a listener that answers no plain HTTP.
- The listener uses the `ring` provider, given to the rustls builder explicitly (no process-wide default). TLS 1.3 only. ALPN `http/1.1` only, because the accept loop serves HTTP/1. No session resumption: no session cache, no tickets, no early data. No client certificate is asked for.
- The handshake runs in the connection's own task, never in the accept loop, and must finish within `[limits] header_read_timeout_seconds`. Then the request headers get that timeout again, as on a plain connection. A failed handshake is logged at debug and closes the connection. On shutdown a connection still in its handshake is dropped at once.
- The admin, console and metrics listeners stay plain HTTP.
- `serve_until`, the embedder's plain-HTTP entry point, never speaks TLS. A router built over a state with `[server.tls]` answers `500` to every request that did not come over a TLS connection of the server's own accept loop, so it is never served in cleartext by mistake.
- The startup log line `attenuo server listening` carries `tls = true` or `tls = false`.

### Consequences

- Good, because a deployment without a proxy can serve HTTPS without `allow_insecure_http`.
- Good, because the handshake is attenuo's own, which is what mTLS client authentication needs next.
- Good, because a silent or slow peer cannot hold a connection open forever: the handshake has the same deadline as the headers. It can still hold one for up to twice `header_read_timeout_seconds` before a request: once for the handshake, once for the headers.
- Bad, because attenuo now holds a server private key. A file others can read is refused, and so is one its group can read unless root owns it, but whoever can read it as the server's user can impersonate the server.
- Bad, because a renewed certificate takes a restart. Short-lived certificates are not practical yet.
- Bad, because clients that only speak TLS 1.2 cannot connect. A proxy in front can still speak TLS 1.2 to them.
- Bad, because every new connection costs the server CPU for a full handshake (a key exchange and a signature), with no resumption to make it cheaper. RSA keys cost much more than ECDSA; the guide recommends ECDSA P-256. Agents that keep connections alive pay it once.
- Bad, because nothing caps concurrent connections or handshakes, as on the plain listener, and the `[limits]` in-flight cap counts requests, so it does not bound handshakes. A flood of new connections can use up CPU and file descriptors. A front proxy or a connection limit at the network level is still the defence against that.
- Bad, because health checks change: the image's built-in `HEALTHCHECK` and the Helm chart's probes use plain HTTP and fail with `[server.tls]`, and the CLI trusts only the public web PKI roots, so with a private CA it cannot reach the TLS listener (admin commands still go to a plain `[admin] listen`).
- Neutral, because the admin and console listeners need a tunnel or a proxy for TLS, as before.

### Confirmation

- `crates/attenuo-server/tests/server_tls.rs`: real handshakes through `attenuo_server::run`. Requests to `/healthz`, discovery and the dev root mint succeed over TLS. A TLS 1.2 client, an `h2`-only client and a client that does not trust the certificate are refused, and the server goes on. Plain HTTP to the TLS port fails and the server goes on. Every connection makes a full handshake. A silent peer and half a ClientHello are dropped at the header-read timeout while other clients are served. Shutdown closes an open TLS connection and a connection in its handshake at once, and a request in progress finishes during the drain. Without `[server.tls]` the listener speaks plain HTTP. Bad sections stop `build`, a broken key block is never quoted in an error, `serve_until` answers 500 for a router with TLS, and an environment override cannot create the section.
- Unit tests in `crates/attenuo-server/src/tls.rs` for every startup refusal, and in `crates/attenuo-server/src/config.rs` for the section and the `public_url` rules.

## Pros and Cons of the Options

### `[server.tls]` on the main listener only, read at start

- Good, because it is small and has one place to configure.
- Good, because the listener agents use is the one that needs TLS most, and the one that client certificates will need.
- Bad, because a renewal needs a restart.

### TLS on every listener

- Good, because operators would need no tunnel for the admin API.
- Bad, because each listener would need its own certificate story, and the admin and console listeners are meant to stay on loopback or a private network (ADR-0008, ADR-0013). It can be added later, one listener at a time.

### Reload the certificate without a restart

- Good, because short-lived certificates would work.
- Bad, because it adds a reload path, its audit record and its failure cases to the first change. It is a follow-up.

### No native TLS

- Good, because there is nothing new to maintain.
- Bad, because a proxy stays mandatory for HTTPS, and mTLS client authentication would have to trust a forwarded header, which is weaker.

## More Information

Not done here, each for a later change:

- Client certificate authentication (RFC 8705) on `[[agents]]` and `[[peps]]`. The listener asks for no client certificate yet.
- Certificate-bound access tokens (`cnf.x5t#S256`).
- Reloading the server certificate without a restart.
- TLS on the admin, console and metrics listeners.
- HTTP/2.
- A metric for failed handshakes.

Related: ADR-0007 and ADR-0017, which set mTLS aside for lack of native TLS; ADR-0013, the admin listener; ADR-0014, the request limits whose header-read timeout bounds the handshake.

### Update 2026-11-24: client certificates

The decision above stands. The first item of "Not done here" is now done for self-signed certificates: with `[server.tls] client_certificates = "optional"` the listener asks for a client certificate, and `tls_client_cert_sha256` on `[[agents]]` and `[[peps]]` pins it ([ADR-0019](0019-self-signed-tls-client-auth.md)). The default, `"off"`, asks for none, as this ADR decided. The rule that an environment override cannot create the section is made stricter: no key of `[server.tls]` can be set from the environment, also when the file has the section. Certificate-bound access tokens are still not done.

### Update 2026-11-24: CLI TLS options

The decision above stands. The CLI limit named under "Bad" is lifted: `--tls-ca-cert` (`ATTENUO_TLS_CA_CERT`) gives the CLI the CA of a private or self-signed server certificate, and with it the CLI trusts only that file for `--server` and `--admin-server`, not its built-in web PKI roots ([CLI reference](../reference/cli.md#global-options)). The image's built-in `HEALTHCHECK` and the Helm chart's probes are unchanged and still use plain HTTP; a health check override can now use the CLI with that option ([deploying](../guides/deploying.md#health-checks-the-image-and-the-cli)).
