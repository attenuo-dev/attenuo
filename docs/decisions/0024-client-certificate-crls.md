---
status: proposed
date: 2026-11-25
decision-makers: []
consulted: []
informed: []
---

# ADR-0024. CRL files for client certificates from a CA: read from disk, signed by a CA the entry trusts, stale CRLs refuse by default, checked again for certificate-bound tokens

## Context and Problem Statement

ADR-0020 lets an agent or PEP authenticate with a certificate a CA issued. It has no revocation check. A revoked certificate works until it expires, or until the operator removes the CA or changes the name on the entry. Short-lived certificates, such as SPIRE's, keep that window small. Many CAs issue certificates for months and publish CRLs (RFC 5280 §5).

Should attenuo read CRLs, from where, and what should it do when a CRL is old, missing or broken?

## Decision Drivers

- Fail closed. A CRL that cannot be trusted, or that has run out, refuses.
- No new network path. The server already fetches keys for IdPs; a CRL fetch would be one more outbound connection that an attacker can slow or block.
- No change for anyone who does not ask for it. Entries without CRL settings, and their list digests, stay as they are.
- A reload never puts an older CRL in force, and a cache never keeps a revoked certificate working.
- Bounded cost: lookups per request without parsing or signature checks; bounded file sizes and counts.
- Pinned certificates (ADR-0019) are a thumbprint list. Revoking one is removing the thumbprint.

## Considered Options

- CRL files on each entry, read at start and on reload.
- CRLs fetched from the certificates' distribution points.
- OCSP.

## Decision Outcome

Chosen option: "CRL files on each entry", because it adds no network path, it fits the existing agents reload, and it can fail closed at start.

The rules:

- **Settings.** On an `[[agents]]` or `[[peps]]` entry with `tls_client_ca_pem_path`: `tls_client_crl_paths` (1 to 16 files), `tls_client_crl_issuer_pem_path` (optional intermediate CA certificates that may sign CRLs), `tls_client_crl_stale` (`"refuse"` by default, or `"allow"`) and `tls_client_crl_missing` (`"allow"` by default, or `"refuse"`). Any of them on an entry without a CA file, or the last three without `tls_client_crl_paths`, refuse to start.
- **The file.** One CRL, PEM or DER, at most 4 MiB. rustls-webpki parses it. It must be a version 2 CRL with `nextUpdate`. Delta CRLs, indirect CRLs and CRLs partitioned by reason are refused by the parser. Any `issuingDistributionPoint` extension is refused here: a CRL scoped to some of a CA's certificates would look complete.
- **The signer.** A CA certificate of the entry's CA file, or a certificate of the issuer file. Each certificate of the issuer file must have started (`notBefore` at or before the clock) and be signed by a CA certificate of the CA file or by another accepted certificate of the issuer file, whose `keyUsage`, if it has one, allows `keyCertSign`. The CRL's issuer name must equal the signer's subject byte for byte. The signature must verify with the signer's key, using the algorithms of the TLS listener's provider. A signer with `keyUsage` needs `cRLSign`. Any other CRL refuses to start. Two CRLs are loaded but ignored, with a warning naming the signer by subject: one whose signer (by name and key) a CRL of the entry revokes, through any certificate of the files with that name and key or a CA above one, and one whose signer has no certificate in the files that is valid now through certificates valid now up to a trust anchor (an issuer-file certificate that has expired). A certificate the ignored CRL lists is still `client_certificate_revoked`; every other certificate that CA issues is refused as `client_certificate_revocation_unknown`, whatever `tls_client_crl_missing` says, and never accepted: with cross-signing its certificates might still chain another way. An ignored CRL is not checked for staleness, nor by the reload rule against older CRLs, so its own age never holds back the revocation; its other checks stay. Expiry is seen at a start or reload, not when `notAfter` passes. The start or reload goes on, so the revocation it carries takes effect at once; an earlier version refused it, which kept the old lists in force. Revocations listed by an ignored CRL still count: they can only add refusals. Each signature is checked once per file and key in a start or reload.
- **Dates.** `nextUpdate` after `thisUpdate`; `thisUpdate` at most 300 seconds ahead of the clock. Under `"refuse"`, a stale CRL refuses to start and refuses a reload.
- **One CRL per CA.** One per CA (name and key) in an entry. Across entries, one content per CA, so no entry checks against an older list than another.
- **The check.** rustls-webpki builds the path. A callback runs on each path it builds. Every certificate below the trust anchor is looked up in the CRL of the CA that issued it in that path (by that CA's name and key), by serial number. A listed certificate refuses the path, and path building tries another one.
- **Trust anchors.** rustls-webpki tries the CA file's certificates as trust anchors first, so an intermediate CA that is also in the CA file ends the path, and the path above it is never built. Such an anchor is checked as an intermediate is. At load, for each CA certificate of the CA file that is not self-issued (its issuer name is not its subject), the server finds the certificates of the CA file and of the issuer file whose subject is its issuer name and whose key verifies its signature, and walks up from those the same way to self-issued CAs. Each certificate on the way is looked up in the CRL of the CA that issued it, as an intermediate is: listed refuses the path, and a stale or missing CRL follows `tls_client_crl_stale` and `tls_client_crl_missing`. Where several issuers verify, every one is checked and the worst answer counts. The signatures are checked once per load and pair of files (CA file, issuer file), and a request does lookups only. A cross-signed CA in the CA file is refused when any one of its issuer certificates in the files is revoked. A self-signed root is never looked up, and an anchor whose issuer neither file holds is a root here: nothing above it is checked. The start and each reload log a warning naming, by subject, each anchor a CRL of its entry lists.
- **Serial numbers.** Compared as unsigned numbers: leading zero bytes are stripped from the certificate's and from the CRL's, so `00 01` and `01` are one serial number. Only non-negative serial numbers are meaningful (RFC 5280 forbids negative ones). A negative encoding compares as its bytes would unsigned, so `FF` equals `00 FF`: the comparison can only add refusals.
- **Stale.** A CRL is stale from `nextUpdate` on, by the server's clock. Under `"refuse"`, a path that needs it is refused from that second, with no reload. Under `"allow"`, it is still used. A certificate a stale CRL lists is always refused.
- **Missing.** Under `"allow"`, a certificate whose issuer has no CRL in the entry is not checked. The start and each reload log one warning, by subject, for each CA certificate of the CA file or the issuer file that may issue certificates (`keyCertSign`, or no `keyUsage`) and has no CRL in the entry. Under `"refuse"`, a certificate whose issuer has no CRL is refused.
- **Answers.** A listed certificate: `401 invalid_client`, `client_certificate_revoked`. A stale or missing CRL, or an issuer whose CRL was ignored: `client_certificate_revocation_unknown`. These are given only when the certificate's path and name match the entry the client named. Otherwise the answer is the usual `client_authentication_failed` (SR-110). Logged at info level, not audited, like the other client authentication refusals.
- **Reload.** Every file is read again into new values. A reload is refused (`422 client_crl_older`) when a CA's new CRL has an earlier `thisUpdate`, a smaller `cRLNumber` (compared as numbers), or no `cRLNumber` where the one in force has one. The same content is accepted. This compares with the CRLs in force only, so two things are not caught. A restart accepts any valid CRL: nothing about CRLs is kept across a restart. And a reload that removes a CA's CRL, followed by a reload that lists an older CRL of that CA, is accepted, because the first reload left nothing of that CA in force to compare with.
- **Caches.** The per-connection cache and the shared cache of the forwarding listener key an answer by the identity of the entry's CRL set, which is new on every start and reload. An accepted answer is kept at most until one second before the earliest `nextUpdate` of the entry's CRLs (under `"refuse"`). A CRL refusal is never cached.
- **Certificate-bound tokens.** For a token with `cnf.x5t#S256` whose thumbprint matched the request's certificate, and only for such a token, the full check of each `[[agents]]` entry with `tls_client_auth` and CRLs that is an agent of the token's chain, and whose name the certificate carries, runs again, with the lists in force. The entries are found by the token's agents, then kept only when the certificate carries the entry's `tls_client_auth_san_uri` or `tls_client_auth_san_dns`. An entry may accept a secret or a key as well as a certificate, and a hop that authenticated with its secret may have done so over a connection showing another agent's certificate: the actor of an exchange of a bound token shows the subject's certificate. Checking such an entry against a certificate that is not its own would refuse every token of that chain. The name test comes first and reads the certificate only; a revocation does not change a certificate's names, so a revoked certificate an entry checked once is never skipped by it later. The limit: when no agent's entry carries the certificate's name (the entry was removed, or its name rule changed), only the thumbprint is compared, as before this feature. A listed certificate gives `401 invalid_token` / `client_certificate_revoked`. Any other failure gives `client_certificate_revocation_unknown`. This runs on the MCP route (JSON-RPC `-32001`), at `POST /token/renew`, the AuthZEN routes, `GET /approvals/{id}` (after the run check, so another run's approval stays `not_found`), and an exchange of the token. A token none of whose agents has such an entry carrying the certificate's name (a pinned certificate's, one of an entry without CRLs, one whose entry was removed or renamed) keeps the thumbprint check only. Requests with any other token cost no certificate check. A refusal is logged at info level, at most once every 10 seconds, with the number left out.
- **Limits.** At most 32 distinct files, 16 MiB and 250,000 listed certificates per start or reload; 100,000 per CRL. A lookup is three hash lookups per certificate checked, the trust anchor and those above it included.

### Consequences

- Good, because a revoked certificate stops at the next request after a reload, also on an open connection.
- Good, because a stale CRL stops working at `nextUpdate` without a reload, by default.
- Good, because a forged or wrong CRL stops the server at start, or leaves the lists in force at reload.
- Bad, because the operator must fetch CRLs and reload. A job that copies a CRL into place and runs `attenuo admin agent reload` is needed. If it stops, every certificate of that CA stops at `nextUpdate` under the default.
- Bad, because a restart accepts an older CRL than the one in force before. The server keeps no state about CRLs across restarts.
- Bad, because a self-signed trust anchor, or one whose issuer neither file holds, cannot be revoked by a CRL. Remove it from the CA file.
- Bad, because a reload that revokes an intermediate of the issuer file while its own CRL is still listed, or after its certificate expired, loads with that CRL ignored: every certificate the intermediate issued is refused as unknown, also any that might chain another way, until the operator removes the CRL or lists the intermediate's current certificate.
- Bad, because a reload that drops a CA's CRL and a later one that lists an older CRL of it are both accepted, as is a restart with an older CRL.
- Neutral, because a certificate-bound token now also stops when its certificate stops passing its entry's check for another reason, such as expiry. That is stricter than before, for entries with CRLs only.

### Confirmation

- `crates/attenuo-server/tests/client_crl.rs`: a revoked leaf over TLS and from the proxy; a revoked intermediate; an intermediate in the CA file, revoked by the root's CRL, with no chain sent, and under `tls_client_crl_missing = "refuse"`; two CAs with one name; another CA's CRL revokes nothing; the startup refusals; staleness at `nextUpdate` with a manual clock, under both values; `tls_client_crl_missing`; a reload that revokes on an open connection; reloads with a bad, wrong-key or older CRL keep the CRLs in force; a CRL dropped then restored older; certificate-bound tokens on every route, `GET /approvals/{id}` included; no check and no log for unbound tokens; the rate-limited log; pinned certificates unaffected, also with the name of an entry with CRLs.
- Unit tests in `client_crl.rs` and `client_pki.rs`: the review's case, self-signed roots, anchors issued by an issuer-file certificate, cross-signed intermediates, serial numbers and `cRLNumber`s with leading zero bytes, ECDSA P-256 and P-384, Ed25519 and RSA signers, the issuer-file checks, cache invalidation, limits, the file format.
- The fuzz targets `client_crl_der` (the file reads, the field reads and the `keyUsage` read) and `client_crl_check` (load, `CrlSet::status`, the anchors' checks and the whole path check on real certificates and CRLs signed in the target, and `verify_signature`).

## Pros and Cons of the Options

### CRL files on each entry, read at start and on reload

- Good, because no outbound connection is added.
- Good, because the existing reload gives atomic changes, an audit record and a refusal that keeps the lists in force.
- Bad, because fetching the CRL is the operator's job.

### CRLs fetched from the certificates' distribution points

- Good, because no job is needed.
- Bad, because the URL comes from the certificate, which the client chose. The server would connect where a client says, before the client is authenticated.
- Bad, because a fetch that fails or hangs leaves a choice between failing open and refusing every client of that CA.

### OCSP

- Good, because answers are fresh.
- Bad, because it is a network call per certificate, or a cache with the same freshness questions as a CRL.
- Bad, because the same problems as distribution points apply to the responder URL.

## More Information

- RFC 5280 §5 (CRL profile) and §6.3 (CRL processing). The parts not supported here are listed in [standards](../research/standards.md#rfc-5280-certificate-revocation-lists-added-2026-11-25).
- ADR-0020 (certificates from a CA), ADR-0021 (forwarded certificates), ADR-0022 (certificate-bound tokens).
- Revisit if a deployment needs a CRL fetched by the server, or OCSP stapling from the client.
