---
status: proposed
date: 2026-11-24
decision-makers: []
consulted: []
informed: []
---

# ADR-0020. TLS client certificates from a CA for agents and PEPs, matched by one SAN

## Context and Problem Statement

ADR-0019 lets an agent or a PEP authenticate with a self-signed TLS client certificate that its entry pins by SHA-256. Every new certificate is then a config change and a reload. Workloads that already get certificates from a CA, such as SPIFFE X.509-SVIDs from SPIRE that renew every hour, cannot use that.

RFC 8705 §2.1 defines `tls_client_auth`: the certificate chains to a CA the server trusts, and it carries one name the client's registration names.

Should attenuo accept CA-issued client certificates, and how does it tell which client a certificate stands for?

## Decision Drivers

- No change for anyone who does not ask for it. Lists without the new settings keep their digest, and records of other requests hash as before.
- One certificate must never authenticate two clients of one list. Many agents share one CA, so the CA alone cannot say who a client is.
- The check runs before the client is authenticated, on certificates the client chose. Its cost must have a small fixed bound.
- The same request rules as ADR-0019: per-request trust decision, reload on open connections, SR-110, SR-109, `actor_auth`.
- No new crate in `Cargo.lock`. No X.509 parser beyond what rustls already uses. No weaker checks than rustls-webpki makes for a server certificate.

## Considered Options

- A CA file per entry and exactly one SAN, URI or DNS, matched exactly.
- The same, plus subject DN, IP and e-mail matching.
- The CA set once for the whole server, and the SAN on each entry.
- Read the CAs from the `[[actor_trust]]` SPIFFE bundle endpoint.

## Decision Outcome

Chosen option: "a CA file per entry and exactly one SAN, URI or DNS", because it covers SPIFFE IDs and DNS-named workloads, it needs only rustls-webpki, and each entry says on its own which CA and which name it trusts.

- New keys on `[[agents]]` and `[[peps]]`: `tls_client_ca_pem_path` and exactly one of `tls_client_auth_san_uri` and `tls_client_auth_san_dns`. A CA file without a name, a name without a CA file, both names, or these next to `tls_client_cert_sha256` refuse to start (and a reload). The same `[server.tls] client_certificates = "optional"` rule as ADR-0019. These settings count as the entry's credential.
- The same name (a URI, or a DNS name without regard to case) on two entries of one list is refused: one name, one client.
- At request time, after the chain and the name, a certificate that also carries the configured name of another entry of the same list is refused (`certificate_names_several_clients`). The list keeps an index of its names, so this is one lookup per name of the certificate. The rule is per list: an agent and a PEP may share a name, since the endpoint tells them apart. A name that no entry uses does not matter.
- The CA file: a regular file of at most 1 MiB, only `CERTIFICATE` blocks, 1 to 16 of them, each a parseable X.509 certificate with `basicConstraints` `CA:TRUE`. A private key anywhere in it, or any other PEM block, is refused. Messages are fixed texts; no parser error is shown. A file is read once per start or reload, so the agents and the PEPs that name it see the same bytes.
- The listener keeps the certificates the client sent after its own next to the end-entity certificate, so they can serve as intermediates. A client may send at most 4; with more, the CA check refuses the certificate without building a path. Of those, once per connection, it keeps only the ones that can help a path: not unreadable, not a copy of the client's certificate, not self-issued (subject = issuer), and only the first one with a given subject. So a client that needs cross-certificates sends the one its path uses. A key-rollover link certificate (the new root signed by the old one) is self-issued, so one the client sends is ignored: put the new root in the CA file.
- The answer is kept per connection, for the CA file in force (the file as read; a reload makes a new one) and the configured name, at most 8 answers. An accepted path is used from the time it was checked until the earliest `notAfter` of the client's certificate and the intermediates kept; a clock set back, or a later time, checks again. A refusal of the name holds for the connection. Other refusals (dates, chain, usage) are not kept: a certificate that is not yet valid may become valid.
- Per request: rustls-webpki `verify_for_usage` with `KeyUsage::client_auth()`, the request's time, the entry's CAs as trust anchors, the client's intermediates, and the `ring` provider's signature algorithms. That is the chain check rustls makes for any certificate, with the CA flag, path length, extended key usage, critical extensions and the CAs' name constraints. Then the name:
  - URI: an exact, case-sensitive string match with one of the certificate's URI SANs. A `spiffe://` value must be a valid SPIFFE ID at start, and the certificate must carry exactly one URI SAN (the X.509-SVID rule).
  - DNS: no wildcard and no IP address in the configured value. Compared without regard to ASCII case. A wildcard SAN in the certificate never matches.
- Method `tls_client_auth`, and `actor_token+tls_client_auth` under `actor_auth = "either"`. Audit records carry the same `client_cert` member as ADR-0019. No `SCHEMA_VERSION` change.
- Refusals are the ADR-0019 answer, `client_authentication_failed` with the same `detail`. The debug log has the reason (`chain_invalid`, `certificate_expired`, `certificate_not_yet_valid`, `certificate_not_usable`, `uri_san_count`, `san_mismatch`, `certificate_names_several_clients`, `too_many_intermediates`) and the certificate's names, escaped.
- Reload: the keys and the CA file's content are part of the entry. A changed file is a change. Only entries with these settings get the new member in the list digest: `{"tls_client_ca_pem_path", "tls_client_ca_pem_sha256", <name key>}`.

### Consequences

- Good, because a CA can issue and renew certificates with no change to attenuo, and short-lived SVIDs work.
- Good, because agent A's certificate never authenticates agent B of the same list, even from the same CA, and even when it carries both names.
- Bad, because there is no CRL or OCSP check. A revoked certificate works until it expires, or until its CA or name is removed from the entry and the lists are reloaded. (ADR-0024 later adds CRL files.)
- Bad, because a CA that issues a certificate with another agent's name makes that agent's identity available. Trust a CA only for the names it should vouch for.
- Bad, because a rotated CA file (a new SPIRE bundle) needs `attenuo admin agent reload`.
- Bad, because the check of an entry with a CA takes longer than a refusal for an unknown id, so timing can show which ids use a CA. The answer is the same.
- Bad, because rustls-webpki applies a CA file certificate's name constraints but not its path length, and refuses URI name constraints, so a CA that sets URI name constraints cannot be used.
- Bad, because the chain check costs CPU before the client is authenticated. It is bounded by at most 4 intermediates, the filter above (at most one intermediate to try at each step, so the work grows with the 4, not with the number of paths), at most 16 CAs per file, rustls-webpki's own limit of 100 signature checks per check, and the per-connection cache. What remains is about (path length) x (CA certificates in the file that share a subject) signature checks per refused chain: measured in review at about 0.1 ms with a normal CA file, and a few ms with 16 CA certificates of one subject. `[limits] token_unauthenticated_requests_per_minute` is off by default and does not cover the PEP endpoints, so it is not what bounds this.
- Bad, because rustls-webpki does not read the client certificate's `keyUsage`: a certificate without `digitalSignature` is accepted. The TLS handshake has already checked a signature made with the certificate's key. A check of our own was not added: rustls does not make it for server certificates either, and a partial X.509 rule of our own is a new place for mistakes. Known limit, tested in `key_usage_is_not_checked`.
- Neutral, because subject DN, IP and e-mail names are not matched. A CA that puts the identity only in the subject cannot be used yet.

### Confirmation

- `crates/attenuo-server/tests/mtls.rs`, the `pki_` tests: real handshakes through `attenuo_server::run`. An agent by SPIFFE ID (from the root, and through an intermediate it sends), an agent at hop 0 by DNS name in another case, a PEP by DNS name. One answer for: another agent's certificate from the same CA, another CA, expired, not yet valid, `CA:TRUE`, the CA's own certificate, server use only, two URI SANs for a SPIFFE ID, a wildcard DNS SAN, a self-signed certificate with the right name, no intermediate sent, five intermediates, a certificate that also carries another entry's name, an unknown id, a secret-only entry. Four intermediates (copies dropped) and an extra name no entry uses work. A body secret wins. `actor_auth = "actor_token"`. Start refusals. A reload that changes the CA file, the name, and removes the settings, on an open connection.
- Unit tests in `client_pki.rs` (the file rules, the name rules, the path and name checks, crafted chains cut down before path building, the cache's expiry and keys, `keyUsage`) and `clientauth.rs` (the entry rules, the one answer, one certificate for two entries, the digest and the changes).
- The fuzz target `client_pki_der` (the DER reads: `basicConstraints`, URI names, names and `notAfter`, the intermediates kept).

## Pros and Cons of the Options

### One CA file and one SAN per entry

- Good, because each entry is complete on its own, and two trust domains can use two CAs.
- Bad, because many agents repeat the same path. The file is read once per list, so the cost is small.

### Subject DN, IP and e-mail too

- Good, because some CAs put the identity only in the subject.
- Bad, because DN matching needs an X.509 parser (`x509-parser`) in the shipped binary and RFC 4514 comparison rules. Not done until someone needs it.

### One CA set for the whole server

- Good, because there is one place to rotate.
- Bad, because a CA that should vouch for PEPs only would vouch for agents too.

### CAs from the SPIFFE bundle endpoint

- Good, because SPIRE rotates bundles without a reload.
- Bad, because it adds a fetch, a cache and its failure rules to the trust decision. It is a follow-up.

## More Information

Not done here: subject DN, IP and e-mail names; CRL files; CAs from a SPIFFE bundle endpoint; certificate-bound tokens (`cnf.x5t#S256`); forwarded certificate headers; CLI and SDK support.

Related: ADR-0018, the TLS listener; ADR-0019, self-signed certificates, whose request rules this follows.

### Update 2026-11-24: forwarded certificates

The decision above stands. A CA-issued certificate can now also come from a trusted proxy, with its intermediates in `Client-Cert-Chain` (at most 4, as here), through `[server.forwarded_client_cert]` ([ADR-0021](0021-forwarded-client-certificates.md)). The checks are the same. The answer cache is kept per request there, not per connection, since one proxy connection carries many clients.
