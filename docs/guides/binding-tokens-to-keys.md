# Binding tokens to keys

A delegation token is a bearer token by default: whoever holds it can use it until it expires or its lease is revoked. If an agent leaks its token (in a log line, a prompt, a crash dump, a tool result it echoes back), the leak is as good as the agent.

A **bound** token is useless without a private key the agent keeps. onbehalf implements this with DPoP (RFC 9449): the token carries the thumbprint of a key, and every request that presents it must carry a fresh proof signed by that key. This guide shows how to bind tokens with the CLI and the SDKs, how binding passes from one agent to the next, and what the server refuses.

Everything below was run against a local server with the [GitHub leak demo](https://github.com/7Mudit/onbehalf/blob/main/examples/github-leak-demo/README.md) config. Binding is optional: nothing changes for clients that do not use it, unless the operator sets `[token] dpop = "required"`.

## How it works

1. The agent generates a key pair once and keeps the private key.
2. When it asks for a token (`POST /token`, or the dev `POST /admin/root-token`), it adds a `DPoP` header: a short JWT signed by the key, naming the method and URL of that request. The server puts the key's RFC 7638 thumbprint in the new token as `cnf.jkt` and answers with `token_type: "DPoP"`.
3. Every later request with that token (the proxy, `/token/renew`, AuthZEN, and `/token` when the token is the parent of an exchange) sends `Authorization: DPoP <token>` and a new `DPoP` proof. The proof names the method and URL, carries `ath` (the SHA-256 of the token), a unique `jti` and a current `iat`.
4. The server checks the proof against the key named in the token. No proof, a proof by another key, a proof for another URL, an old proof or a replayed one: the request is refused with 401.

Supported keys are Ed25519 (`EdDSA`) and P-256 (`ES256`). The CLI and SDKs generate Ed25519 keys.

## With the CLI

Generate a key for each agent. The file is a private JWK, written with mode 0600, and an existing file is never overwritten:

```console
$ onbehalf key gen --dpop assistant.jwk
wrote DPoP key assistant.jwk (EdDSA)
jkt  4MMDxQj9pafXPrWH6dxBeoSk2DpHFpEZvXvsmr6JibU
$ onbehalf key gen --dpop coder.jwk
```

Mint a root token bound to the assistant's key (the dev endpoint; with an IdP, pass `--dpop-key` to the hop-0 `token exchange` instead):

```sh
ROOT=$(onbehalf token root --subject alice --agent assistant --cap 'github:*' \
  --dpop-key assistant.jwk --print token)
```

`onbehalf token inspect` shows the binding: `bound to DPoP key jkt 4MMDxQj9…`.

The assistant delegates to a coder that has its own key. A child of a bound token is always bound, so the exchange names the coder's key with `--dpop-key`, and the assistant agrees to the new binding with a proof by its own key (`--subject-dpop-key`):

```sh
CODER=$(ONBEHALF_TOKEN="$ROOT" ONBEHALF_CLIENT_SECRET=demo-coder-secret \
  onbehalf token exchange --actor coder --cap github:read_file \
  --dpop-key coder.jwk --subject-dpop-key assistant.jwk --print token)
```

When the child should stay on the parent's key (one agent, two tokens), pass the same file as `--dpop-key` and leave out `--subject-dpop-key`.

The coder calls tools with its key. `--dpop-key` (or `ONBEHALF_DPOP_KEY`) works on `call`, `tools` and `authzen eval`:

```console
$ ONBEHALF_TOKEN="$CODER" onbehalf call --dpop-key coder.jwk --server github --tool read_file \
    --arg repo=alice/public-docs --arg path=README.md
ALLOWED
```

The same token without the key:

```console
$ ONBEHALF_TOKEN="$CODER" onbehalf call --server github --tool read_file \
    --arg repo=alice/public-docs --arg path=README.md
error -32001: onbehalf: unauthorized: dpop_required
```

## With the SDKs

Give the client a key. It then attaches a proof to every request, binds every token it obtains by exchange, and sends tokens as `Authorization: DPoP`.

Python (`pip install 'onbehalf[dpop]'` for the `cryptography` package):

```python
from onbehalf import AdminClient, Client, DpopKey

assistant_key = DpopKey.load("assistant.jwk")   # or DpopKey.generate()
coder_key = DpopKey.load("coder.jwk")

root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"],
                           dpop_key=assistant_key)
with Client(url, dpop_key=coder_key) as ob:
    coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=secret,
                        subject_dpop_key=assistant_key)
    ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
```

For an MCP client library on `httpx`, `TokenAuth(provider, dpop_key=key)` adds the proof per request.

TypeScript (no extra dependencies; WebCrypto signs):

```ts
import { AdminClient, DpopKey, mcpFetch, OnbehalfClient } from "@onbehalf/sdk";

const assistantKey = await DpopKey.fromJwk(JSON.parse(readFileSync("assistant.jwk", "utf8")));
const coderKey = await DpopKey.generate(); // keep coderKey.privateJwk() to reuse it

const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
  capabilities: "github:*",
  dpopKey: assistantKey,
});
const ob = new OnbehalfClient(url, { dpopKey: coderKey });
const coder = await ob.exchange(root, "coder", "github:read_file", {
  clientSecret,
  subjectDpopKey: assistantKey,
});
await ob.callTool(coder, "github", "read_file", { repo: "alice/public-docs" });
```

Static headers cannot carry a proof, because each proof is single-use. For an MCP client library, pass `mcpFetch(() => coder, { dpopKey: coderKey })` as its `fetch` (for the official SDK, the `fetch` option of `StreamableHTTPClientTransport`).

## Without an SDK

A proof is a JWS with header `{"typ": "dpop+jwt", "alg": "EdDSA" or "ES256", "jwk": <public key>}` and claims:

| Claim | Value |
| --- | --- |
| `htm` | The request method, `POST` or `GET` |
| `htu` | The request URL without query or fragment, as the server sees it: `[server] public_url` plus the path, or `http://<Host>` plus the path when `public_url` is unset |
| `iat` | Now, in seconds. Accepted within `[token] dpop_max_age_seconds` (default 300) either side of the server's clock |
| `jti` | Unique per proof. A repeated `jti` for the same key is refused |
| `ath` | base64url(SHA-256(token)), whenever a bound token goes with the request |

Send it as the `DPoP` header (exactly one). For an exchange whose child is bound to a different key than its parent, add `subject_token_dpop` to the request body: a proof by the parent's key for `POST` and the `/token` URL, with `ath` of the parent token.

## What the server refuses

| Situation | Answer |
| --- | --- |
| A bound token without a proof | 401 `dpop_required` (MCP: `-32001`, `data.reason` `dpop_required`) |
| A proof by another key, for another method or URL, too old, replayed, badly signed, or several `DPoP` headers | 401 `invalid_dpop_proof` |
| Exchanging a bound parent without binding the child | 401 `dpop_required` |
| Binding the child to a new key without `subject_token_dpop` | 401 `dpop_required` |
| `[token] dpop = "required"` and a request without a proof, or an unbound token | 401 `dpop_required` |
| The replay cache is full (`[token] dpop_replay_capacity`) | 503 `temporarily_unavailable` (`dpop_replay_cache_full`) |

Each 401 carries `WWW-Authenticate: DPoP error="…", algs="EdDSA ES256"`. Audit records of requests made with a bound token, and of issuances that bound a token, carry `"dpop_bound": true`.

## Settings

```toml
[token]
dpop = "optional"            # "off": never bind new tokens; "required": every token must be bound
dpop_max_age_seconds = 300   # how far a proof's iat may be from the server's clock
dpop_replay_capacity = 1000000
```

A bound token stays bound whatever `dpop` says: `off` stops binding new tokens but does not let bound ones through without proofs. Set `[server] public_url` when the server sits behind a proxy or a TLS terminator, so `htu` matches what clients see.

## Limits

- Replay protection is in memory, per process. With several server replicas, a proof could be replayed against another replica within the `iat` window.
- No server nonce (RFC 9449 §8). Freshness rests on `iat` and the `jti` cache.
- Binding is checked by the server and the built-in proxy. An external enforcement point that verifies tokens itself must check proofs too, or ask the AuthZEN endpoint with the token and a proof.
- Cedar policies cannot see whether a call was bound yet; only the audit record says so.
- mTLS (RFC 8705) and SPIFFE X.509 binding are not implemented.

See [RFC-0001 section 4.1](../spec/rfc-0001-onbehalf.md#41-sender-constrained-tokens-dpop) for the specification.
