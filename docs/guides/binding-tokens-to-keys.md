# Binding tokens to keys

A delegation token is a bearer token by default: whoever holds it can use it until it expires or its lease is revoked. If an agent leaks its token (in a log line, a prompt, a crash dump, a tool result it echoes back), the leak is as good as the agent.

A **bound** token is useless without a private key the agent keeps. attenuo implements this with DPoP (RFC 9449): the token carries the thumbprint of a key, and every request that presents it must carry a fresh proof signed by that key. This guide shows how to bind tokens with the CLI and the SDKs, how binding passes from one agent to the next, and what the server refuses. An agent that authenticates with a TLS client certificate can have its tokens bound to that certificate instead ([below](#binding-tokens-to-a-tls-client-certificate)).

Everything below was run against a local server with the [GitHub leak demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md) config. Binding is optional: nothing changes for clients that do not use it, unless the operator sets `[token] dpop = "required"`.

## How it works

1. The agent generates a key pair once and keeps the private key.
2. When it asks for a token (`POST /token`, or the dev `POST /admin/root-token`), it adds a `DPoP` header: a short JWT signed by the key, naming the method and URL of that request. The server puts the key's RFC 7638 thumbprint in the new token as `cnf.jkt` and answers with `token_type: "DPoP"`.
3. Every later request with that token (the proxy, `/token/renew`, AuthZEN, and `/token` when the token is the parent of an exchange) sends `Authorization: DPoP <token>` and a new `DPoP` proof. The proof names the method and URL, carries `ath` (the SHA-256 of the token), a unique `jti` and a current `iat`.
4. The server checks the proof against the key named in the token. No proof, a proof by another key, a proof for another URL, an old proof or a replayed one: the request is refused with 401.

Supported keys are Ed25519 (`EdDSA`) and P-256 (`ES256`). The CLI and SDKs generate Ed25519 keys.

## With the CLI

Generate a key for each agent. The file is a private JWK, written with mode 0600, and an existing file is never overwritten:

```console
$ attenuo key gen --dpop assistant.jwk
wrote DPoP key assistant.jwk (EdDSA)
jkt  4MMDxQj9pafXPrWH6dxBeoSk2DpHFpEZvXvsmr6JibU
$ CODER_JKT=$(attenuo --json key gen --dpop coder.jwk | jq -r .jkt)
```

Mint a root token bound to the assistant's key (the dev endpoint; with an IdP, pass `--dpop-key` to the hop-0 `token exchange` instead):

```sh
ROOT=$(attenuo token root --subject alice --agent assistant --cap 'github:*' \
  --dpop-key assistant.jwk --print token)
```

`attenuo token inspect` shows the binding: `bound to DPoP key jkt 4MMDxQj9…`.

The assistant delegates to a coder that has its own key. A child of a bound token is always bound, so the exchange names the coder's key with `--dpop-key`. The assistant consents to the new binding with a **sign-off**: a proof by its own key that names the coder's key thumbprint and agent id. It makes the sign-off in its own process and hands only the result to the coder, so its key never leaves it:

```sh
# The assistant, with assistant.jwk:
ATTENUO_TOKEN="$ROOT" attenuo token sign-off --dpop-key assistant.jwk \
  --child-jkt "$CODER_JKT" --actor coder > sign-off.txt

# The coder, with coder.jwk and the sign-off:
CODER=$(ATTENUO_TOKEN="$ROOT" ATTENUO_CLIENT_SECRET=demo-coder-secret \
  attenuo token exchange --actor coder --cap github:read_file \
  --dpop-key coder.jwk --subject-token-dpop-file sign-off.txt --print token)
```

The sign-off is good for one exchange (its `jti` is single-use), within `[token] dpop_max_age_seconds` of when it was made, and only for the key and agent it names: whoever intercepts it cannot use it to bind a token to their own key, or exchange as another agent. A sign-off made before a server restart is refused after it, like any proof (see [Limits](#limits)): make a new one. When one process holds both keys (tests, a single-binary agent), `--subject-dpop-key assistant.jwk` on the exchange makes the sign-off in place.

When the child should stay on the parent's key (one agent, two tokens), pass the same file as `--dpop-key` and leave out the sign-off.

The coder calls tools with its key. `--dpop-key` (or `ATTENUO_DPOP_KEY`) works on `call`, `tools` and `authzen eval`:

```console
$ ATTENUO_TOKEN="$CODER" attenuo call --dpop-key coder.jwk --upstream github --tool read_file \
    --arg repo=alice/public-docs --arg path=README.md
ALLOWED
```

The same token without the key:

```console
$ ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool read_file \
    --arg repo=alice/public-docs --arg path=README.md
error -32001: attenuo: unauthorized: dpop_required
```

## With the SDKs

Give the client a key. It then attaches a proof to every request, binds every token it obtains by exchange, and sends tokens as `Authorization: DPoP`.

Python (`pip install 'attenuo[dpop]'` for the `cryptography` package):

```python
from attenuo import AdminClient, Client, DpopKey

assistant_key = DpopKey.load("assistant.jwk")   # or DpopKey.generate()
coder_key = DpopKey.load("coder.jwk")

root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"],
                           dpop_key=assistant_key)
# The assistant signs off on delegating to the coder's key; only the sign-off travels.
sign_off = assistant_key.sign_off(f"{url}/token", str(root), coder_key.thumbprint, "coder")

with Client(url, dpop_key=coder_key) as ob:
    coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=secret,
                        subject_token_dpop=sign_off)
    ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
```

When one process holds both keys, `subject_dpop_key=assistant_key` makes the sign-off inside `exchange`.

For an MCP client library on `httpx`, `TokenAuth(provider, dpop_key=key)` adds the proof per request.

TypeScript (no extra dependencies; WebCrypto signs):

```ts
import { readFileSync } from "node:fs";
import { AdminClient, DpopKey, mcpFetch, AttenuoClient } from "@attenuo/sdk";

const assistantKey = await DpopKey.fromJwk(JSON.parse(readFileSync("assistant.jwk", "utf8")));
const coderKey = await DpopKey.generate(); // keep coderKey.privateJwk() to reuse it

const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
  capabilities: "github:*",
  dpopKey: assistantKey,
});
// The assistant signs off on delegating to the coder's key; only the sign-off travels.
const signOff = await assistantKey.signOff(`${url}/token`, root.jwt, coderKey.thumbprint, "coder");

const ob = new AttenuoClient(url, { dpopKey: coderKey });
const coder = await ob.exchange(root, "coder", "github:read_file", {
  clientSecret,
  subjectTokenDpop: signOff,
});
await ob.callTool(coder, "github", "read_file", { repo: "alice/public-docs" });
```

Static headers cannot carry a proof, because each proof is single-use. For an MCP client library, pass `mcpFetch(() => coder, { dpopKey: coderKey })` as its `fetch` (for the official SDK, the `fetch` option of `StreamableHTTPClientTransport`).

## Without an SDK

A proof is a JWS with header `{"typ": "dpop+jwt", "alg": "EdDSA" or "ES256", "jwk": <public key>}` and claims:

| Claim | Value |
| --- | --- |
| `htm` | The request method, `POST` or `GET` |
| `htu` | The request URL without query or fragment, as the server sees it: `[server] public_url` plus the path. When `public_url` is unset, `http://<Host>` plus the path for a loopback `Host` (`localhost`, `127.0.0.1`, `[::1]`, with any port), and `http://localhost` plus the path for any other `Host`; set `public_url` on any server reached by another name |
| `iat` | Now, in seconds. Accepted up to `[token] dpop_max_age_seconds` (default 300) behind the server's clock and `dpop_future_skew_seconds` (default 10) ahead of it |
| `jti` | Unique per proof. A repeated `jti` for the same key is refused |
| `ath` | base64url(SHA-256(token)), whenever a bound token goes with the request |

Send it as the `DPoP` header (exactly one). For an exchange whose child is bound to a different key than its parent, add `subject_token_dpop` to the request body: the sign-off, a proof by the parent's key for `POST` and the `/token` URL, with `ath` of the parent token and two more claims, `child_jkt` (the thumbprint of the key in the `DPoP` header) and `child_actor` (the request's `actor`). The server refuses a sign-off whose `child_jkt` or `child_actor` does not match the request.

## What the server refuses

| Situation | Answer |
| --- | --- |
| A bound token without a proof | 401 `dpop_required` (MCP: `-32001`, `data.reason` `dpop_required`) |
| A proof by another key, for another method or URL, too old or too far ahead, replayed, made before a quick restart, badly signed, or several `DPoP` headers | 401 `invalid_dpop_proof` |
| Exchanging a bound parent without binding the child | 401 `dpop_required` |
| Binding the child to a new key without `subject_token_dpop` | 401 `dpop_required` |
| A `subject_token_dpop` that names another key or agent, or none | 401 `invalid_dpop_proof` |
| `[token] dpop = "required"` and a request without a proof, or an unbound token | 401 `dpop_required` |
| The replay cache is full (`[token] dpop_replay_capacity`) | 503 `temporarily_unavailable` (`dpop_replay_cache_full`); at the proxy, HTTP 503 with JSON-RPC `-32006` (`data.reason` `dpop_replay_cache_full`) and `Retry-After` |
| The server's liveness marker is behind its clock (see Limits) | 503 `temporarily_unavailable` (`dpop_liveness_stale`) with `Retry-After: 1`; at the proxy, JSON-RPC `-32006` with the same `data.reason` |

Each 401 carries `WWW-Authenticate: DPoP error="…", algs="EdDSA ES256"`. Audit records of requests made with a bound token, and of issuances that bound a token, carry `"dpop_bound": true`.

## Settings

```toml
[token]
dpop = "optional"            # "off": never bind new tokens; "required": every token must be bound
dpop_max_age_seconds = 300   # how far a proof's iat may be behind the server's clock
dpop_future_skew_seconds = 10 # how far it may be ahead (unset: 10, or the max age if smaller)
dpop_replay_capacity = 1000000
dpop_nonce = "off"           # "required": every proof must carry the server's current nonce
```

A bound token stays bound whatever `dpop` says: `off` stops binding new tokens but does not let bound ones through without proofs. Set `[server] public_url` when the server sits behind a proxy or a TLS terminator, so `htu` matches what clients see.

## Server nonces

With `[token] dpop_nonce = "required"` the server supplies the freshness instead of trusting the client's clock (RFC 9449 §8). Every response to a request that sent a `DPoP` header, and every `WWW-Authenticate: DPoP` challenge, carries a `DPoP-Nonce` header. Each proof the server checks in a `DPoP` header must put the latest such value in its `nonce` claim. A proof without it, or with a stale or unknown one, is refused with 401 `use_dpop_nonce`. That response carries the nonce to use, and the client retries with a new proof.

The Python and TypeScript clients (`Client`, `AsyncClient`, `AttenuoClient`, `AdminClient` for the dev root mint, `TokenAuth` and `mcpFetch`) do this for you. They keep the latest nonce and retry a refused request once. The CLI does too: it keeps the latest nonce for the server it talks to, within one command, and retries a refused request once.

The server keeps no nonce state. A nonce is an HMAC of the current time bucket (`dpop_max_age_seconds` wide) under a key derived from the issuer's signing key. The current and the previous bucket's nonces are accepted, so a nonce lives for one to two windows, and replicas that share the signing key accept each other's nonces. The exchange sign-off (`subject_token_dpop`) needs no nonce, because the parent makes it ahead of time.

## Binding tokens to a TLS client certificate

An agent that authenticates at `/token` with a TLS client certificate ([identity providers](identity-providers.md#tls-client-certificates)) can get tokens bound to that certificate (RFC 8705 §3). The token carries `cnf.x5t#S256`, the base64url SHA-256 of the certificate. It is accepted only on a request that shows the same certificate. No DPoP key is needed. Off by default:

```toml
[token]
tls_client_certificate_bound_access_tokens = true
```

The server needs a listener that takes client certificates: `[server.tls] client_certificates = "optional"`, or `[server.forwarded_client_cert]` behind a proxy ([ADR-0021](../decisions/0021-forwarded-client-certificates.md)). It refuses to start without one, and with `dpop = "required"`.

- **Issue.** A token that `POST /token` issues to an agent that authenticated with its certificate is bound to it, at hop 0 and at an exchange of an unbound parent. The answer says `token_type: "Bearer"`: send the token as a bearer token over a connection that shows the certificate. A client that authenticated with a secret, an assertion or an actor token alone gets an unbound token, even over a connection with a certificate. The dev mint never binds to a certificate.
- **One binding.** A token is bound to a key or to a certificate, never both. A request that would be bound to the certificate and carries a `DPoP` header is refused with 400 `dpop_with_certificate_binding`.
- **Use.** Every route that takes a token checks the certificate: the proxy, `/token/renew`, the AuthZEN routes, `GET /approvals/{id}`, and `/token` when the token is the subject of an exchange. Call them over the same TLS listener, or through the same proxy, with the same certificate.
- **Children.** The child of a certificate-bound token is bound to the same certificate, and the exchange must show that certificate. A sub-agent with another certificate cannot take the child. A key-bound parent keeps the DPoP rules above, and its child is key-bound.
- **Once bound, always bound.** Turning the setting off does not unbind tokens issued while it was on.
- **Rotation.** A token dies with its certificate. After a rotation, the tokens bound to the old certificate are refused with `client_certificate_mismatch`, even when both certificates are pinned for the agent. Get new tokens with the new certificate. With short-lived certificates (SPIFFE SVIDs), keep token lifetimes below the rotation interval.

| Situation | Answer |
| --- | --- |
| No certificate on the request (a plain-HTTP listener, a TLS connection without one, the ext-authz gateway route) | 401 `client_certificate_required` (MCP: `-32001`, `data.reason`) |
| Another certificate, also one from the same CA with the same name, or the next one of a rotation | 401 `client_certificate_mismatch` |
| A `DPoP` header or `Authorization: DPoP` with a certificate-bound token | 401 `dpop_with_certificate_binding`; 400 at `/token` |
| The bound certificate is from a CA whose entry lists CRL files, and a CRL lists it or a CA in its path | 401 `client_certificate_revoked` (MCP: `-32001`, `data.reason`) |
| The same, and a CRL its path needs is stale or missing, or the certificate no longer passes its entry's check for another reason (it expired, say) | 401 `client_certificate_revocation_unknown` (MCP: `-32001`, `data.reason`) |

The two CRL rows are checked with the lists and CRLs in force at the time of the request, so a reload that revokes a certificate stops its tokens too. They apply to the entries of the token's agents (those in its delegation chain) that have `tls_client_crl_paths` ([CRL files](../reference/config.md#crl-files)), whatever names the certificate carries. A token bound to a pinned certificate, or to one whose entry has no CRLs, is checked by thumbprint only. A request with any other token costs no certificate check.

A `Client-Cert` header never stands in for a certificate, except on the forwarding listener from a trusted peer. Elsewhere it is refused (400) or ignored. The ext-authz gateway route sees the gateway's connection, not the agent's, so it refuses certificate-bound tokens. An external PEP that verifies tokens itself must check the certificate itself.

Audit records of requests made with a certificate-bound token, and of issuances that bound one, carry `"cert_bound": true`. The CLI and the SDKs were not changed for this, except that `attenuo token inspect` shows an `x5t#S256` binding. They were not tested with certificate-bound tokens. See [ADR-0022](../decisions/0022-certificate-bound-tokens.md).

## Limits

- Proof replay protection is in memory, per process. With several server replicas, a proof could be replayed against another replica within the `iat` window. Proof `jti`s are not written to the database because every proxied call with a bound token checks one, and a write per call would slow every call; the single-use credentials of `POST /token` and approvals are written there and survive a restart.
- A proof made before a restart is refused after it, with 401 `invalid_dpop_proof`, whether the restart was quick or slow. The server writes a liveness marker to its database file at start and every 5 seconds, and the next server on the file refuses every proof the previous one could have accepted. This includes an exchange sign-off (`subject_token_dpop`) made ahead of time, and a request a client retries across a deploy with the same proof: make a new proof.
- Proofs made after the start can be refused too, right after a quick restart: until the clock passes the old marker, which is up to about 21 seconds with the defaults (`dpop_future_skew_seconds` plus 11). A client whose clock is slow waits longer. `/readyz` answers 503 (`checks.dpop_restart_fence` `"fenced"`) for that time, so a rolling deploy sends the new server no traffic yet. A start more than about 20 seconds after the old server's last marker write costs nothing, and so does a new database file. With `sqlite_path = ":memory:"` there is no marker and no fence. If the clock went back between the two runs, proofs are refused until it passes the old marker again.
- The marker only moves forward. If the clock was far ahead when it was written (a VM resumed with a wrong clock, say), every proof is refused until the clock catches up, and the server logs an error at start. To recover: stop the server, run `sqlite3 /var/lib/attenuo/audit.sqlite "DELETE FROM audit_meta WHERE key = 'dpop_max_iat'"` (your `[audit] sqlite_path`), and start it again. That one start is not fenced.
- These starts are not fenced either: the first start of this version on a file used by an older one, and a start on a restored older backup or a replaced file, since the marker there is older than the proofs the last server accepted.
- The heartbeat runs whatever `[token] dpop` says, because bound tokens are checked in every mode. A failed first write stops the start-up. Later, if a write fails (a full disk, a broken file), the server retries every half second and refuses proofs with 503 `dpop_liveness_stale` and `Retry-After: 1` once the marker falls behind its clock, rather than accept proofs a later restart could not fence. No request writes the marker.
- The CLI and both SDKs do not retry `invalid_dpop_proof` (they retry only `use_dpop_nonce`). A call made during the fence fails; the next call makes a new proof and works once the fence has passed. Server nonces survive a restart, so they neither help nor hurt here.
- A proof's `iat` may be at most `dpop_future_skew_seconds` ahead of the server's clock: 10 by default, or `dpop_max_age_seconds` when that is smaller. A client whose clock runs further ahead is refused until its clock is fixed.
- Server nonces are off by default; freshness then rests on `iat` and the `jti` cache. With nonces on, a nonce is shared by every client of the server for its lifetime, so it limits how far ahead a proof can be made. It does not stop the cross-replica replay above.
- Binding is checked by the server and the built-in proxy. An external enforcement point that verifies tokens itself must check proofs too, or ask the AuthZEN endpoint with the token and a proof.
- Cedar policies cannot see whether a call was bound yet; only the audit record says so.
- Certificate binding (above) gives a child the parent's certificate only. Delegation to a holder with another certificate is not implemented.

See [RFC-0001 section 4.1](../spec/rfc-0001-attenuo.md#41-sender-constrained-tokens-dpop) for the specification.
