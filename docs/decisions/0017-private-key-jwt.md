---
status: proposed
date: 2026-11-13
decision-makers: []
consulted: []
informed: []
---

# ADR-0017. Client authentication with `private_key_jwt`: public keys inline in `[[agents]]` and `[[peps]]`, `aud` fixed to the issuer identifier, and every assertion used once

## Context and Problem Statement

Agents (at `POST /token`, hop 0 and later hops) and PEPs (at the AuthZEN endpoints) authenticate with a client secret whose SHA-256 is in the config. The secret travels with every request, a copy anywhere it is stored or logged lets anyone act as that client until the operator rotates it, and the server's config holds a value that, once its hash is reversed for a weak secret, is the credential itself. [ADR-0007](0007-actor-authentication.md) added RFC 8693 actor tokens for agents that run under a workload-identity system, and named `private_key_jwt` (RFC 7523) as an option it did not take, because such a system already does the provisioning. Many agent runtimes have no SPIRE agent or cloud workload token, and the hop-0 hardening item on the task board lists `private_key_jwt` as missing. How should an agent or PEP prove who it is with a key it holds, without a shared secret on the server, and without weakening the checks the other methods have?

## Decision Drivers

- No secret on the server: the config holds only public keys.
- No replay: a captured assertion must not authenticate a second request, also after a restart.
- No audience confusion: an assertion made for one server must not be accepted by another.
- One way per request (RFC 6749 §2.3), and the same `[token] actor_auth` modes as today.
- Secrets keep working unchanged, for existing configs, demos and SDK users.
- No new dependency, no audit record or `SCHEMA_VERSION` change, no network fetch at authentication time.

## Considered Options

- Public keys inline in the entry (`jwks`, a JWK Set as text), verified per RFC 7523 §3 with `aud` = `[issuer] issuer` only and a mandatory single-use `jti`.
- The same keys from a file (`jwks_path`).
- Keys fetched from a client-hosted `jwks_uri`.
- mTLS client authentication (RFC 8705).

## Decision Outcome

Chosen option: "public keys inline in the entry", because it removes the shared secret with a change confined to client authentication, keeps every key the server trusts in the one reviewed config file, needs no fetch, file watch or TLS termination, and fits the `key gen` command the CLI already has for DPoP keys.

- An `[[agents]]` or `[[peps]]` entry has `secret_sha256`, `jwks`, or both, and must have one. It is authenticated only by what it holds: an assertion for an entry without `jwks`, or a secret for one without `secret_sha256`, is `client_authentication_failed`.
- `jwks` is a public JWK Set of at most 8 keys: RSA of at least 2048 bits (RS256), P-256 (ES256) or Ed25519 (EdDSA). The server refuses to start on a private member (its message names the member, never the value), a symmetric key, another curve or a short RSA key, an `alg` that does not fit the key, a `use` other than `sig`, and a duplicate `kid` or a missing one in a set of several.
- The request carries `client_assertion_type` = `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion` on every endpoint that takes client credentials: `POST /token` at hop 0 and later hops, and the AuthZEN evaluation and batch endpoints for a PEP. A secret and an assertion together, or Basic and an assertion, are `multiple_client_auth`.
- Checks, in order: `typ` not another token kind; `iss` = `sub` = the client id (and `client_id` when sent); the entry has keys; `alg` in the allowlist and equal to the alg of the key the `kid` names (no `kid` only with one key); the signature; `aud`; `exp` and `jti` present; `exp` not past and at most `[token] client_assertion_max_lifetime_seconds` (default 300) ahead, `nbf` and `iat` not in the future, with `[token] client_assertion_clock_skew_seconds` (default 60) of leeway; the `jti` unused. Each failure has its own stable `client_assertion_*` code, a 401 `invalid_client` (400 for an unsupported `client_assertion_type`), and none echoes the assertion.
- **`aud` is the issuer identifier only.** The assertion's `aud` must be `[issuer] issuer`, as a string or an array whose every value is it. The token endpoint URL is not accepted, although RFC 7523 §3 allows it, because the work on RFC 7523bis moves to the issuer identifier as the single value to close audience injection: a client that accepts several audiences can be led to sign an assertion meant for one server that another accepts. The issuer identifier is also what the server already compares an ID-JAG's `aud` with, and it is the `iss` of every token the server issues, so a client that holds one knows the value (the CLI takes it from the subject token).
- **`jti` is mandatory and used once.** RFC 7523 makes `jti` optional and leaves replay protection to the server. Here an assertion without `jti` is refused, and its `jti` is recorded in the replay store the server already has (the `used_credentials` table, which ID tokens, ID-JAGs and actor tokens use) under the client kind and id, until `exp` plus the skew. It survives a restart. It is recorded when the client authenticates, before the rest of the request is decided, so a refused request still spends the assertion, and a second use gets its own code, `client_assertion_replayed`. The bounded lifetime keeps the store small.
- **`actor_auth`.** `"secret"` now means client credentials, a secret or an assertion according to what the entry holds; no new mode. `"actor_token"` refuses both kinds; `"either"` checks client credentials and an actor token together when both are sent, and both must name the actor. The server warns at startup when `actor_auth = "actor_token"` and an agent has `jwks`, because those keys can then never be used.
- **Audit.** The method is recorded in the arguments the exchange and intake records already digest (`actor_auth` / `agent_auth`): `private_key_jwt`, or `actor_token+private_key_jwt`. The record format and `SCHEMA_VERSION` do not change; the log lines name the method too.
- **Tools.** `attenuo key gen --client <PATH> [--kid KID]` writes an Ed25519 private JWK (mode 0600) and prints the `jwks` line to paste. `attenuo token exchange --client-key PATH` signs an assertion with a one-minute lifetime and a random `jti`. The Python and TypeScript SDKs sign one with their DPoP key class (`client_assertion` / `clientAssertion`), with no new dependency.

What this does not do:

- No `jwks_uri`: the server never fetches a client's keys. Adding, rotating or removing a key is editing the config and restarting; an entry can hold the old and the new key during the change.
- No mTLS client authentication (RFC 8705), and no binding of the issued token to the client key; DPoP binding stays separate.
- No `client_secret_jwt` (an HMAC assertion keyed by the secret): it keeps the shared secret this change removes.
- No assertion on `/token/renew` or on the MCP proxy, which take the delegation token, not client credentials.
- No replay store shared between replicas; the per-file limit of the other single-use credentials applies.

### Consequences

- Good, because a deployment can run with no agent or PEP secret on the server, and a captured assertion is useless after one request or its short lifetime.
- Good, because nothing changes for an entry that keeps `secret_sha256`: same requests, same answers, same records.
- Good, because the stable codes say which check failed without revealing the assertion.
- Bad, because every request with an assertion writes a row to the replay store, one more write than a secret needs.
- Bad, because a client must sign a fresh assertion for every request, and a retry of a request that reached the server needs a new one.
- Neutral, because clients that hold the token endpoint URL as their audience must be told the issuer identifier instead.

### Confirmation

- `crates/attenuo-server/src/clientauth.rs` tests: the JWK Set rules (a refusal never repeats a private value), each assertion check and its code, algorithm confusion, secrets and assertions not mixing, single use with the replay store full or failing, and replay keys kept apart for agents and PEPs. Refusal messages are fixed strings, so they cannot carry the assertion.
- `crates/attenuo-server/tests/private_key_jwt.rs`: hop 0 with an assertion; an exchange with key rotation, form encoding, a forged `kid`, `actor_mismatch`, and an audit digest that records `private_key_jwt`; a PEP on single and batch AuthZEN requests, with an assertion inside a batch entry refused; single use across a restart; the `actor_auth` modes; the startup refusals. `crates/attenuo-server/tests/actor_token.rs` checks an assertion and an actor token together under `"either"`.
- `crates/attenuo-cli/tests/client_key.rs`: a key from `key gen --client` pasted into a server's config authenticates `token exchange --client-key`.
- The Python and TypeScript SDK tests sign an assertion and check it against the expected header and claims.

## Pros and Cons of the Options

### Inline `jwks`

- Good, because the trusted keys are in the reviewed config next to the rest of the client's entry, like `secret_sha256`, and `key gen --client` prints a line to paste.
- Bad, because long RSA keys make the config file harder to read.

### `jwks_path`

- Good, because the config stays short.
- Bad, because there is one more file to deploy and keep in sync, and a client's credential would be split from its entry; the `*_path` settings in this config hold the issuer's own private keys, which must not be inline, while these keys are public.

### `jwks_uri`

- Good, because a client could rotate keys without an operator.
- Bad, because the server would fetch from client-controlled URLs on the authentication path (SSRF, availability, cache rules), and whoever controls the URL controls the client's identity; it can be added later as another source of the same key list.

### mTLS

- Good, because the key never leaves the TLS handshake.
- Bad, because it needs TLS termination at attenuo or trusted forwarding of client certificates, which most deployments put in a proxy (as ADR-0007 found for actor tokens).

## More Information

- RFC 7521 (assertion framework), RFC 7523 §2.2 and §3 (JWT client authentication and its checks), RFC 6749 §2.3 (one method per request), the RFC 7523bis work on `aud` (re-check its status before quoting it).
- [ADR-0007](0007-actor-authentication.md): this adds the option it set aside, for agents without a workload-identity system; actor tokens and their checks are unchanged, and ADR-0007 is not superseded.
- Configuration: [`[[agents]]`](../reference/config.md#agents), [`[[peps]]`](../reference/config.md#peps), `[token] client_assertion_*`; HTTP: [client authentication](../reference/http-api.md#client-authentication); CLI: [`key gen --client`](../reference/cli.md).
- Revisit when keys need to change without a restart (`jwks_uri`), or when replicas share a replay store.

### Update 2026-11-13: one answer until the signature verifies (SR-110)

The decision above stands and is kept as written, except for one sentence of it: "Each failure has its own stable `client_assertion_*` code". Security review pass 12 found that those codes told a caller with no credential which client ids have keys ([SR-110](../research/security-review-2026-11-13-pass12.md#sr-110-a-refused-client-assertion-tells-which-client-ids-have-keys-info-fixed)): an assertion signed with any key and naming an id was refused `client_authentication_failed` when no entry with keys had that id, and `client_assertion_bad_signature` or `client_assertion_unknown_kid` when one did, which also said whether the entry had one key or several. The secret path never told which ids exist, and agent ids are not secret, but PEP ids appear in no token, and the codes said which ids to aim a guess at.

Now:

- Every refusal that can be reached without a signature by one of the named client's keys is one answer: 401 `invalid_client`, `code` and `error_description` `client_authentication_failed`, the same `detail` ("unknown client, or the client_assertion is not signed by one of the client's keys") and the same headers. That covers an unknown id, an entry without `jwks`, a `kid` that names none of the entry's keys (or none sent for an entry with several), an allowed `alg` that is not the named key's, and a bad signature. The reason (`unknown_client`, `client_without_keys`, `unknown_kid`, `key_alg_mismatch`, `bad_signature`) goes to the server's debug log only. Client-authentication refusals were never audited (SR-18: an anonymous caller cannot write to the audit log), so there is no record to hold it.
- `client_assertion_bad_signature` and `client_assertion_unknown_kid` are no longer sent and are removed from `ERROR_CODES`. `client_assertion_unsupported_alg` stays, for an `alg` outside RS256, ES256 and EdDSA only; that check, and the check that a `kid` is a string, now come before the client is looked up, so they answer the same for every id.
- Checks that only a holder of the key can reach, after the signature verified (`aud`, `exp`, the lifetime, `nbf` and `iat`, `jti` present, the replay), keep their codes: they tell a client what to fix. So do the checks before the lookup (`typ`, `iss` and `sub`, `alg`, a non-string `kid`).
- Timing: a refusal that has no key of the client to verify with (unknown id, no keys, unknown `kid`, a key of another algorithm) verifies the assertion against a fixed decoy public key of the header's `alg` (`DECOY_JWKS` in `clientauth.rs`; nobody holds the private halves, and the outcome is thrown away), so it costs one signature verification like a bad signature does, as the secret path compares against a dummy digest. It is not constant time: the decoy RSA key is 2048 bits, so an RS256 probe against an entry whose RSA key is larger takes longer than one against an unknown id; looking an id up is a scan of the configured list; and the work before the lookup depends only on the assertion.

Rejected: keeping the codes and documenting what they reveal (option 3 of the report), because the secret path already promises that ids do not show; folding the server-wide `alg` check into the one answer too, because it does not depend on the client and its code helps a client that signs with an algorithm the server does not take.

This is a breaking change of the HTTP API for a client that matched the two removed codes; neither SDK nor the CLI did.
