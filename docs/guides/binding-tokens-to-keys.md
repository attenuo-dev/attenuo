# Binding tokens to keys

A delegation token is a bearer token by default: whoever holds it can use it until it expires or its lease is revoked. If an agent leaks its token (in a log line, a prompt, a crash dump, a tool result it echoes back), the leak is as good as the agent.

A **bound** token is useless without a private key the agent keeps. attenuo implements this with DPoP (RFC 9449): the token carries the thumbprint of a key, and every request that presents it must carry a fresh proof signed by that key. This guide shows how to bind tokens with the CLI and the SDKs, how binding passes from one agent to the next, and what the server refuses.

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
attenuo token sign-off --subject-token "$ROOT" --dpop-key assistant.jwk \
  --child-jkt "$CODER_JKT" --actor coder > sign-off.txt

# The coder, with coder.jwk and the sign-off:
CODER=$(ATTENUO_TOKEN="$ROOT" ATTENUO_CLIENT_SECRET=demo-coder-secret \
  attenuo token exchange --actor coder --cap github:read_file \
  --dpop-key coder.jwk --subject-token-dpop-file sign-off.txt --print token)
```

The sign-off is good for one exchange (its `jti` is single-use), within `[token] dpop_max_age_seconds` of when it was made, and only for the key and agent it names: whoever intercepts it cannot use it to bind a token to their own key, or exchange as another agent. When one process holds both keys (tests, a single-binary agent), `--subject-dpop-key assistant.jwk` on the exchange makes the sign-off in place.

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
| `iat` | Now, in seconds. Accepted within `[token] dpop_max_age_seconds` (default 300) either side of the server's clock |
| `jti` | Unique per proof. A repeated `jti` for the same key is refused |
| `ath` | base64url(SHA-256(token)), whenever a bound token goes with the request |

Send it as the `DPoP` header (exactly one). For an exchange whose child is bound to a different key than its parent, add `subject_token_dpop` to the request body: the sign-off, a proof by the parent's key for `POST` and the `/token` URL, with `ath` of the parent token and two more claims, `child_jkt` (the thumbprint of the key in the `DPoP` header) and `child_actor` (the request's `actor`). The server refuses a sign-off whose `child_jkt` or `child_actor` does not match the request.

## What the server refuses

| Situation | Answer |
| --- | --- |
| A bound token without a proof | 401 `dpop_required` (MCP: `-32001`, `data.reason` `dpop_required`) |
| A proof by another key, for another method or URL, too old, replayed, badly signed, or several `DPoP` headers | 401 `invalid_dpop_proof` |
| Exchanging a bound parent without binding the child | 401 `dpop_required` |
| Binding the child to a new key without `subject_token_dpop` | 401 `dpop_required` |
| A `subject_token_dpop` that names another key or agent, or none | 401 `invalid_dpop_proof` |
| `[token] dpop = "required"` and a request without a proof, or an unbound token | 401 `dpop_required` |
| The replay cache is full (`[token] dpop_replay_capacity`) | 503 `temporarily_unavailable` (`dpop_replay_cache_full`); at the proxy, HTTP 503 with JSON-RPC `-32006` (`data.reason` `dpop_replay_cache_full`) and `Retry-After` |

Each 401 carries `WWW-Authenticate: DPoP error="…", algs="EdDSA ES256"`. Audit records of requests made with a bound token, and of issuances that bound a token, carry `"dpop_bound": true`.

## Settings

```toml
[token]
dpop = "optional"            # "off": never bind new tokens; "required": every token must be bound
dpop_max_age_seconds = 300   # how far a proof's iat may be from the server's clock
dpop_replay_capacity = 1000000
dpop_nonce = "off"           # "required": every proof must carry the server's current nonce
```

A bound token stays bound whatever `dpop` says: `off` stops binding new tokens but does not let bound ones through without proofs. Set `[server] public_url` when the server sits behind a proxy or a TLS terminator, so `htu` matches what clients see.

## Server nonces

With `[token] dpop_nonce = "required"` the server supplies the freshness instead of trusting the client's clock (RFC 9449 §8). Every response to a request that sent a `DPoP` header, and every `WWW-Authenticate: DPoP` challenge, carries a `DPoP-Nonce` header. Each proof the server checks in a `DPoP` header must put the latest such value in its `nonce` claim. A proof without it, or with a stale or unknown one, is refused with 401 `use_dpop_nonce`. That response carries the nonce to use, and the client retries with a new proof.

The Python and TypeScript clients (`Client`, `AsyncClient`, `AttenuoClient`, `AdminClient` for the dev root mint, `TokenAuth` and `mcpFetch`) do this for you. They keep the latest nonce and retry a refused request once. The CLI does too: it keeps the latest nonce for the server it talks to, within one command, and retries a refused request once.

The server keeps no nonce state. A nonce is an HMAC of the current time bucket (`dpop_max_age_seconds` wide) under a key derived from the issuer's signing key. The current and the previous bucket's nonces are accepted, so a nonce lives for one to two windows, and replicas that share the signing key accept each other's nonces. The exchange sign-off (`subject_token_dpop`) needs no nonce, because the parent makes it ahead of time.

## Limits

- Replay protection is in memory, per process. With several server replicas, a proof could be replayed against another replica within the `iat` window.
- Server nonces are off by default; freshness then rests on `iat` and the `jti` cache. With nonces on, a nonce is shared by every client of the server for its lifetime, so it limits how far ahead a proof can be made. It does not stop the cross-replica replay above.
- Binding is checked by the server and the built-in proxy. An external enforcement point that verifies tokens itself must check proofs too, or ask the AuthZEN endpoint with the token and a proof.
- Cedar policies cannot see whether a call was bound yet; only the audit record says so.
- mTLS (RFC 8705) and SPIFFE X.509 binding are not implemented.

See [RFC-0001 section 4.1](../spec/rfc-0001-attenuo.md#41-sender-constrained-tokens-dpop) for the specification.
