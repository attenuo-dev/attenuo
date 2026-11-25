---
status: proposed
date: 2026-11-25
decision-makers: []
consulted: []
informed: []
---

# ADR-0023. Reload the server certificate through an admin endpoint, the same paths and settings, new connections only; count failed handshakes

## Context and Problem Statement

ADR-0018 gave the main listener its own TLS. It reads the certificate and the key once, at start, so a renewed certificate needs a restart. Short-lived certificates (from an ACME client, cert-manager or SPIRE) are then hard to use. The listener also logs a failed handshake only at debug, so an operator cannot see clients that fail after a rotation.

How should the server put a renewed certificate in force without a restart, and what should it count?

## Decision Drivers

- Fail closed: a file that is not right never replaces a certificate that works.
- A reload must not change any TLS setting: TLS 1.3 only, ALPN `http/1.1`, no session resumption, the client certificate mode. The client certificate code needs a full handshake on every connection (ADR-0019, ADR-0022).
- A handshake uses one certificate and key, the old pair or the new pair, never a mix.
- Follow the reloads that already exist (`POST /admin/agents/reload`, `POST /admin/keys/reload`): admin role, one at a time, audited, nothing changes on an error.
- A flood of failed handshakes must not grow memory, the number of series or the log without bound.

## Considered Options

- An admin endpoint, `POST /admin/tls/reload`.
- Reload on a signal (`SIGHUP`).
- Watch the files and reload when they change.
- Keep the restart.

## Decision Outcome

Chosen option: "an admin endpoint", because it is the pattern the server already has for every other reload. The server has no signal handler and no file watcher for any setting, and this change adds neither.

- **What it reads.** The `cert_pem_path` and `key_pem_path` read at start. A reload does not read the config file again, so a reload cannot change a path or `client_certificates`. The rustls configuration is built by the same code as at start, so the TLS version, ALPN, resumption and client certificate settings come from code and cannot change.
- **Checks.** Every check startup makes (readable regular files within the size limits, PEM, at least one certificate, no private key in the certificate file, exactly one usable key, the key file's owner and mode, the key belongs to the first certificate). A reload also refuses a first certificate that has expired, is not valid yet, or whose dates cannot be read. Startup does not check the dates. Only the first certificate's dates are checked, because chain files often carry an old cross-signed certificate that clients ignore.
- **Swap.** The new configuration replaces the old one in one step. The accept loop takes one snapshot of it for each new connection, before the handshake. So a handshake uses the old or the new configuration, whole. Open connections keep theirs until they close. No lock is held across an `await`.
- **Errors.** 409 `reload_unavailable` without `[server.tls]`. 422 `tls_file_unreadable`, `tls_file_invalid`, `tls_key_mismatch`, `tls_certificate_expired`, `tls_certificate_not_yet_valid`. The message names the setting and the problem, never the path or the content. The 422s are audited as a `deny`.
- **Answer and audit.** The SHA-256 of the first certificate before and after, `changed`, the new certificate's dates and the chain length. The audit record also has the two paths. Never a key.
- **Client CA bundles.** `[server.tls]` has no client CA bundle. The CA files of `tls_client_ca_pem_path` belong to `[[agents]]` and `[[peps]]`, and `POST /admin/agents/reload` already reads them again. A TLS reload does not touch them.
- **Metrics.** `tls_handshake_failures_total{reason}` with five fixed reasons (`bad_client_certificate`, `protocol`, `peer_alert`, `timeout`, `other`), read from the kind of the error only. `tls_certificate_not_after_timestamp_seconds`, the `notAfter` of the certificate in force. `tls_certificate_reloads_total{result}`, with `ok` and `failed`. There is no `no_client_certificate` reason, because the listener never requires a certificate.
- **Log.** A failed handshake is logged at debug at most once per 10 seconds, with the number not logged since.

### Consequences

- Good, because a renewed certificate is put in force without a restart and without dropping open connections.
- Good, because a bad file is refused and the old certificate keeps serving.
- Good, because client certificates and certificate-bound tokens are not touched: they are about the client's certificate, which a reload does not read.
- Bad, because something must call the endpoint after each renewal. The renewal tool's hook can run `attenuo admin tls reload`.
- Bad, because a reload that runs while the files are being written can read a new certificate with the old key. It is then refused as a mismatch. Writing each file to a temporary name and renaming it avoids this.
- Bad, because startup still serves an expired certificate. Making startup refuse one would stop a server that runs today; the gauge shows it instead.

## Pros and Cons of the Options

### An admin endpoint

- Good, because it has an answer, an error code and an audit record, like the other reloads.
- Bad, because it needs an admin credential where the certificate is renewed.

### Reload on a signal

- Good, because a renewal hook only has to send a signal.
- Bad, because a signal has no answer: a refused file is seen only in the log. The server handles no signal for any reload today.

### Watch the files

- Good, because nothing has to be called.
- Bad, because a watcher sees half-written files, needs debouncing, and reloads at a time nobody chose. The server watches no file today.

### Keep the restart

- Good, because there is nothing new.
- Bad, because short-lived certificates stay impractical, and each renewal drops every connection.

## More Information

Not done here: reloading on a signal or on a file change; refusing an expired certificate at startup; checking that the new certificate still names the host of `public_url`; TLS on the admin, console and metrics listeners.

Related: [ADR-0018](0018-native-tls-listener.md), the listener; [ADR-0019](0019-self-signed-tls-client-auth.md) and [ADR-0020](0020-pki-tls-client-auth.md), client certificates; [ADR-0022](0022-certificate-bound-tokens.md), certificate-bound tokens.
