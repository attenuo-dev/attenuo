# HTTP endpoints

All routes the server mounts, from the route table in `crates/attenuo-server/src/lib.rs` and the proxy router. Errors on non-MCP routes look like `{"error": "<code>", "detail": "<text>"}`. The codes for `/token` are listed in [design/server.md](../design/server.md#error-codes).

A 401 for a bearer token (`/token/renew`, AuthZEN, `/admin/*`) is `{"error": "unauthorized", "detail": "<reason>", "error_description": "<reason>"}`, where the reason is one of `missing_token`, `invalid_token` or `token_expired`. Why a token did not verify (wrong key, audience, issuer, malformed) is logged at debug level and never returned. A token bound to a key (DPoP, below) adds `dpop_required` and `invalid_dpop_proof`. The same goes for a JWKS the server cannot fetch (503 `temporarily_unavailable`, sub-code `jwks_unavailable`): the URL and the transport error are logged, not returned.

## DPoP (sender-constrained tokens)

Optional, RFC 9449. See [Binding tokens to keys](../guides/binding-tokens-to-keys.md) and [RFC-0001 section 4.1](../spec/rfc-0001-attenuo.md#41-sender-constrained-tokens-dpop).

- **Binding.** A `DPoP` header (one proof by an Ed25519 or P-256 key, for this method and URL) on `POST /token` or `POST /admin/root-token` binds the new token to the key: its `cnf.jkt` is the key's thumbprint and the response says `"token_type": "DPoP"`. A child of a bound token is always bound. To bind it to a key other than the parent's, the body adds `subject_token_dpop`, the sign-off: a proof by the parent's key with `ath` of `subject_token`, `child_jkt` (the new key's thumbprint) and `child_actor` (the `actor`). See [Binding tokens to keys](../guides/binding-tokens-to-keys.md).
- **Use.** A bound token is accepted only with a `DPoP` proof by its key that carries `ath`, on every route that takes a token: `/mcp/{server}`, `/token/renew`, `/access/v1/evaluation(s)` and `/token` (as `subject_token`). Send `Authorization: DPoP <token>`; `Bearer` is also accepted.
- **Nonces.** With `[token] dpop_nonce = "required"`, every response to a request with a `DPoP` header, and every `WWW-Authenticate: DPoP` challenge, carries `DPoP-Nonce: <nonce>`. A `DPoP` header proof must carry the latest one in its `nonce` claim; the exchange sign-off needs none.
- **Errors.** 401 `dpop_required` (no proof where one is needed), `invalid_dpop_proof` (wrong key, method, URL or `ath`, `iat` outside `[token] dpop_max_age_seconds`, replayed `jti`, bad signature, several `DPoP` headers) or `use_dpop_nonce` (a valid proof without a current server nonce; retry with the response's `DPoP-Nonce`), with `WWW-Authenticate: DPoP error="…", algs="EdDSA ES256"`. The proxy uses JSON-RPC `-32001` with the same `data.reason`. A full replay cache is 503 `temporarily_unavailable` with `error_description` `dpop_replay_cache_full`.
- `htu` is `[server] public_url` plus the path, or `http://<Host>` plus the path when `public_url` is unset. The query is not compared.

## Public

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | Liveness. Never touches storage. |
| `GET /readyz` | none | Readiness. Checks the audit store and the lease store. 200 `{"ready":true,"checks":{"audit":"ok","leases":"ok"}}` or 503 with `"error"` for the failing check and no error text. With `[audit.sink]` the body also has `"degraded"` and `checks.checkpoint_sink` (`"ok"` or `"degraded"`); a degraded sink is a 503 only with `fail_readiness = true`. |
| `GET /.well-known/jwks.json` | none | Public keys for token verification, including retired keys. |
| `GET /.well-known/authzen-configuration` | none | AuthZEN discovery: decision point, evaluation and evaluations endpoint URLs, built from `[server] public_url`. Without it (loopback only) from `Host`, which must be `localhost`, `127.0.0.1` or `[::1]`; anything else is 400 `invalid_host`. |

## Token

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /token` | agent client credentials at hop 0; at later hops the parent token, plus the actor's client credentials or an `actor_token` | RFC 8693 token exchange, as a form or JSON. Hop 0 takes an OIDC ID token or an ID-JAG. Later hops take a parent delegation token and `authorization_details`. Optional `may_act` (agent ids) sets who may exchange the new token next. A `DPoP` header binds the new token to a key (`token_type` `DPoP`); `subject_token_dpop` is the parent key's sign-off, naming the new key and `actor`, when the parent is bound to another key. |
| `POST /token/renew` | bearer delegation token (and a DPoP proof if it is bound) | Extend the lease of the token's last hop. Returns `{lease, expires_at, expires_in}`. |

A later-hop request authenticates its `actor` with `client_id` / `client_secret` (or HTTP Basic), or with `actor_token` and `actor_token_type` = `urn:ietf:params:oauth:token-type:jwt` (RFC 8693 §2.1): a workload-identity JWT, such as a SPIFFE JWT-SVID, from an `[[actor_trust]]` issuer. `[token] actor_auth` decides which are accepted. An actor token works for one exchange, and the child expires no later than it does. If the parent token carries `may_act`, the `actor` must be listed (`actor_not_permitted` otherwise).

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<parent attenuo token>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&actor=coder
&scope=github:read_file
&actor_token=<JWT-SVID for spiffe://example.org/ns/agents/sa/coder>
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
&may_act=reviewer
```

## Decision

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /access/v1/evaluation` | bearer token, or a trusted PEP | AuthZEN evaluation. Same pipeline as the proxy. `context.diagnostics` is filled only for callers `[authzen] diagnostics` allows: by default a `[[peps]]` entry, which can authenticate next to a bearer token with `pep_id` and `pep_secret` in the body. |
| `POST /access/v1/evaluations` | same | AuthZEN batch: top-level `subject`, `action`, `resource`, `context` are defaults and each entry of `evaluations` overrides them. Answers `{"evaluations": [{decision, context}, ...]}`, one per entry, each decided and audited like a single evaluation. At most `[authzen] max_batch` entries (default 64): more is 400 `batch_too_large`, none is 400 `invalid_request`. Only the default `execute_all` semantic is supported. |

## MCP proxy

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp/{server}` | bearer delegation token | Send an MCP request to the upstream called `server`. `tools/call` and similar methods are decided first. |
| `GET /mcp/{server}` | bearer delegation token | Passthrough for the streamable HTTP event stream, after the lease check. |
| `DELETE /mcp/{server}` | bearer delegation token | Passthrough session close, after the lease check. |

A denial is a JSON-RPC error with code `-32003`, carrying `reason` and `decision_id`. A missing or bad token is HTTP 401 with `-32001` and `data.reason` set to `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce` or, for a lease that is no longer live, `lease_revoked`, `lease_expired` or `lease_unknown`. An upstream the proxy cannot reach is HTTP 502 with `-32005` and `data.reason` `upstream_unreachable`; the upstream URL and transport error are only logged. Allowed responses carry `X-Attenuo-Decision-Id`.

## Admin

All admin routes need `Authorization: Bearer <admin token>`. They answer 401 without it and 403 `admin_disabled` when no admin token is configured. Every admin answer, errors included, carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

| Method and path | Purpose |
| --- | --- |
| `GET /admin/leases/{lease_id}` | Lease state. |
| `POST /admin/leases/{lease_id}/revoke` | Revoke the lease and all descendants. |
| `GET /admin/audit` | Audit entries in ascending `seq` order, paged with `from` and `limit` (default 100, at most 1000). Also returns `next` (when the page was full) and `head`, the newest `seq`. Filters and newest-first paging are below. |
| `GET /admin/audit/entries/{seq}` | One entry with its context, `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}` (below). 404 when there is no entry at `seq`. |
| `GET /admin/audit/records/{id}` | The same for the entry whose record id is `id`: the UUID that proxy denials and AuthZEN answers return as `decision_id`. 400 if `id` is not a UUID, 404 if no record has it. |
| `GET /admin/audit/checkpoints?before&limit` | Stored checkpoints, newest first, `{checkpoints, prev}`; each is `{seq, head_hash, at, kid, signature}`. `prev` is the `before` of the next (older) page, null after the oldest. Read-only: it never signs, unlike `/admin/audit/checkpoint`. |
| `GET /admin/audit/verify` | Walk the whole hash chain, verify every checkpoint signature against the JWKS, and report `{entries, ok, first_bad_seq, checkpoints, last_signed_seq, unsigned_tail, bad_checkpoints}`. |
| `GET /admin/audit/checkpoint` | The signed checkpoint of the head, `{seq, head_hash, at, kid, signature}` (signing it now if the head has none). For keeping outside the host. `hash` repeats `head_hash` for older clients. |
| `GET /admin/audit/export?from&to` | Entries `from..=to` (default: the whole log) and the checkpoints in that range, streamed as `application/x-ndjson`: a `header` line, `entry` lines, then `checkpoint` lines. Verify offline with `attenuo audit verify --file`. 400 if `from` is 0 or `to < from`. |
| `POST /admin/policies/reload` | Re-read the policy file. On failure the old policy stays. |
| `POST /admin/root-token` | Development root mint. Mounted only when `[dev] allow_root_mint = true`. |

### Querying the audit log

`GET /admin/audit` takes these optional filters. Each is an exact match, never a pattern: `%` and `_` are ordinary characters, and `agent=l1` does not match an agent called `l10`. Filters combine with AND.

| Parameter | Keeps entries whose record has |
| --- | --- |
| `kind` | one of these kinds, comma-separated: `decision`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin` |
| `decision` | `allow` or `deny` |
| `reason` | this `reason` (`policy_deny`, `lease_revoked`, ...) |
| `subject` | this `originating_subject` |
| `agent` | this agent among its `agents` |
| `lease` | this lease among its `leases` |
| `server`, `tool` | this `server`, this `tool` |
| `chain_id` | this `chain_id` (the lease id of the chain's first hop) |
| `since`, `until` | `at` in `[since, until)`, both RFC 3339 times |

Paging:

- `order=asc` (the default) with `from`: oldest first from `from`. The answer is `{entries, next, head}`; `next` is the `from` of the following page, null at the end. Without any of the new parameters the answer is exactly what it was before filters existed.
- `order=desc` with `before`: newest first, entries with `seq < before` (default: from the head). The answer adds `prev`, the `before` of the following (older) page, null once seq 1 has been read; `next` is then the `from` for reading forward with `order=asc` from just above the page, null when the page reached the head. `before` with `order=asc`, or `from` with `order=desc`, is a 400.
- A filtered page reads at most 50,000 seqs (`agent`, `lease`, `since` and `until` cannot use an index). It can therefore come back short, even empty, with `next` or `prev` set: keep following the link until it is null. Unfiltered pages are never cut short.

An unknown `kind` or `decision`, a time that is not RFC 3339, an empty value or an unknown `order` is a 400 `invalid_request`. The renewal history of a lease, for example, is `kind=lease_renew&lease=<id>`.

The single-entry routes (`/admin/audit/entries/{seq}`, `/admin/audit/records/{id}`) answer:

- `entry`: the entry, as in `GET /admin/audit`.
- `lease_states`: one object per lease in the record, root first, as the lease registry sees it now: `{lease_id, known, active, parent, expires_at, revoked_at, revoke_reason}`. A lease the registry does not hold has `known: false`.
- `covered_by_checkpoint`: the oldest stored checkpoint at or after the entry, whose signature covers it through the hash chain, or null when the entry is newer than every checkpoint. It is returned as stored; `GET /admin/audit/verify` checks signatures.
- `policy_reloaded_after`: the seq of the first successful `POST /admin/policies/reload` recorded after the entry, or null. When set, the policy in force now may not be the one that decided.

## Metrics

`GET /metrics` is served by a separate listener, never on the proxy port. It is enabled with `[metrics] enabled = true`, has no authentication and returns Prometheus text format 0.0.4.
