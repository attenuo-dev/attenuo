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

A denial is a JSON-RPC error with code `-32003`, carrying `reason` and `decision_id`. A call that a policy sends for approval (reason `approval_required`) gets `-32008` instead, with `reason`, `decision_id`, `call_hash` (SHA-256 of the RFC 8785 JSON of `{server, tool, arguments}`), `approval_id` and `expires_at`, and is not forwarded. Once the approval is granted, the identical call from the same hop is allowed once (see [Approvals](#approvals)). `approval_id` is absent if the server could not open an approval. If the answer to an allowed call cannot be recorded in the audit log, the agent gets `-32003` with reason `label_error` and the call's `decision_id` instead of the answer. A missing or bad token is HTTP 401 with `-32001` and `data.reason` set to `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce` or, for a lease that is no longer live, `lease_revoked`, `lease_expired` or `lease_unknown`. An upstream the proxy cannot reach is HTTP 502 with `-32005` and `data.reason` `upstream_unreachable`; the upstream URL and transport error are only logged. Allowed responses carry `X-Attenuo-Decision-Id`.

## Approvals

A call gated with `@obligation("approval")` gets an `approval_id` in its `-32008` error. A person decides it through one of these routes; the agent's own delegation token can read it but never decide it.

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /approvals/{id}` | an OIDC ID token of the run's originating user (`Authorization: Bearer`) | Body `{"decision": "grant" \| "decline"}`. Answers the approval as below. |
| `GET /approvals/{id}` | that user's ID token, or a delegation token of the same run (with a DPoP proof when bound) | The approval. Anyone else gets 404. |
| `GET /admin/approvals?chain_id&state&limit` | admin | Approvals newest first, optionally of one run (`chain_id`, the first hop's lease) or in one state; `limit` default and maximum 500. `{"approvals": [...]}`. |
| `GET /admin/approvals/{id}` | admin | One approval. |
| `POST /admin/approvals/{id}` | admin | Body as above; decides as the operator (`by = "operator"`). Also on the console listener with `[admin_ui] allow_write = true`. |

The ID token is verified as at hop 0: signature from a `[[idps]]` issuer, expiry, and `aud`/`azp` equal to `[approvals] client_id` or, when that is unset, to the client id intake expects for the run's root agent. Its `sub` and `iss` must match the run's originating user. A token can decide once; reads do not use it up.

An approval:

```json
{
  "approval_id": "0f8e6c1a-4b7d-4f61-9a39-2f4f5b0e8d11",
  "state": "pending",
  "expired": false,
  "chain_id": "<first hop's lease>",
  "lease": "<calling hop's lease>",
  "call_hash": "<64 hex>",
  "call": { "server": "github", "tool": "delete_repo", "arguments": { "repo": "alice/site" } },
  "labels": [{ "source": "web/fetch", "seq": 41 }],
  "decision_id": "<the gated decision>",
  "subject": "alice",
  "issuer": "https://idp.example",
  "agents": ["planner", "coder"],
  "created_at": "2026-10-24T10:00:00Z",
  "expires_at": "2026-10-24T10:02:00Z"
}
```

`state` is `pending`, `granted`, `declined` or `consumed`; `expired` says whether `expires_at` has passed. A decided approval adds `approver: {subject, method, by}` (`id_token`/`user` or `admin_token`/`operator`) and `decided_at`; a used one adds `consumed_by`, the id of the allowed decision.

| Status | `error` | When |
| --- | --- | --- |
| 400 | `invalid_request` | `decision` is not `grant` or `decline` |
| 401 | `missing_token`, `invalid_token` | no bearer, or the ID token failed verification or was already used |
| 403 | `agent_token_refused` | a delegation token on `POST /approvals/{id}` |
| 403 | `wrong_user` | the ID token belongs to someone other than the run's originating user |
| 404 | `not_found` | unknown approval, or a delegation token of another run |
| 409 | `approval_not_pending`, `approval_expired`, `lease_revoked` | already decided or used, past `expires_at`, or the lease it is bound to is no longer live |

## Admin

All admin routes need `Authorization: Bearer <admin token>`. They answer 401 without it and 403 `admin_disabled` when no admin token is configured. Every admin answer, errors included, carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

| Method and path | Purpose |
| --- | --- |
| `GET /admin/leases/{lease_id}` | Lease state. |
| `POST /admin/leases/{lease_id}/revoke` | Revoke the lease and all descendants. |
| `GET /admin/leases/{lease_id}/tree?max_nodes` | The lease, its descendants and its ancestors, and how many leases a revoke would change now. Read-only; see [Lease tree](#lease-tree). 404 for an unknown lease. |
| `GET /admin/audit` | Audit entries in ascending `seq` order, paged with `from` and `limit` (default 100, at most 1000). Also returns `next` (when the page was full) and `head`, the newest `seq`. Filters and newest-first paging are below. |
| `GET /admin/audit/entries/{seq}` | One entry with its context, `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}` (below). 404 when there is no entry at `seq`. |
| `GET /admin/audit/records/{id}` | The same for the entry whose record id is `id`: the UUID that proxy denials and AuthZEN answers return as `decision_id`. 400 if `id` is not a UUID, 404 if no record has it. |
| `GET /admin/audit/checkpoints?before&limit` | Stored checkpoints, newest first, `{checkpoints, prev}`; each is `{seq, head_hash, at, kid, signature}`. `prev` is the `before` of the next (older) page, null after the oldest. Read-only: it never signs, unlike `/admin/audit/checkpoint`. |
| `GET /admin/audit/verify` | Walk the whole hash chain, verify every checkpoint signature against the JWKS, and report `{entries, ok, first_bad_seq, checkpoints, last_signed_seq, unsigned_tail, bad_checkpoints}`. |
| `GET /admin/audit/checkpoint` | The signed checkpoint of the head, `{seq, head_hash, at, kid, signature}` (signing it now if the head has none). For keeping outside the host. `hash` repeats `head_hash` for older clients. |
| `GET /admin/audit/export?from&to` | Entries `from..=to` (default: the whole log) and the checkpoints in that range, streamed as `application/x-ndjson`: a `header` line, `entry` lines, then `checkpoint` lines. Verify offline with `attenuo audit verify --file`. 400 if `from` is 0 or `to < from`. |
| `POST /admin/policies/reload` | Re-read the policy file. On failure the old policy stays. |
| `GET /admin/policies` | The policy set in force: file path, its `sha256` and `loaded_at` (startup or last successful reload), `policy_ids`, validation `warnings`, and `policies: [{id, text}]`. |
| `GET /admin/policies/check` | Lint the policy file as it is on disk now against the running schema, with line and column for each issue, and say whether it differs from the loaded one. Loads nothing, audits nothing. 409 `check_unavailable` without `policy.policies_path`. |
| `POST /admin/policies/evaluate` | Dry run: what the loaded policies decide for one call, given a token or a chain. No lease check, no audit record, no decision metric. |
| `POST /admin/root-token` | Development root mint. Mounted only when `[dev] allow_root_mint = true`. |

### Lease tree

`GET /admin/leases/{lease_id}/tree` is a dry run of `POST /admin/leases/{lease_id}/revoke`: it shows what the revocation would reach and changes nothing (no lease row, no audit record).

- `nodes`: the lease first, then every lease delegated from it, breadth-first (each level in id order). At most `max_nodes` (default 1000, clamped to 1..10000); `truncated` is `true` when the cap cut the list short.
- `ancestors`: the leases it was delegated from, nearest first, ending at `root`, the chain's first hop. `root` is also the `chain_id` of the chain's audit records. Empty for a root lease.
- `would_revoke`: the leases in the whole subtree that are not revoked yet, counted with the same query the revocation runs, so it is the `revoked` count a revoke sent now would return. It ignores `max_nodes`.
- Per lease: the registry row (`parent`, `expires_at`, `revoked_at`, `revoke_reason`), `active` now, and from the audit record that issued it (`root_token` or `exchange`) the `agent` it was issued to, `issued_at` and `issued_seq`. These three are `null` when no issuance record is found.

```json
{
  "root": "0b7c...",
  "ancestors": [
    {"lease_id": "0b7c...", "parent": null, "agent": "planner", "active": true,
     "expires_at": "2026-10-23T19:20:00Z", "revoked_at": null, "revoke_reason": null,
     "issued_at": "2026-10-23T19:05:00Z", "issued_seq": 41}
  ],
  "nodes": [
    {"lease_id": "5e21...", "parent": "0b7c...", "agent": "coder", "active": true,
     "expires_at": "2026-10-23T19:20:02Z", "revoked_at": null, "revoke_reason": null,
     "issued_at": "2026-10-23T19:05:02Z", "issued_seq": 42},
    {"lease_id": "9a40...", "parent": "5e21...", "agent": "reviewer", "active": false,
     "expires_at": "2026-10-23T19:20:03Z", "revoked_at": "2026-10-23T19:06:10Z",
     "revoke_reason": "rotated", "issued_at": "2026-10-23T19:05:03Z", "issued_seq": 43}
  ],
  "would_revoke": 1,
  "truncated": false
}
```

### Querying the audit log

`GET /admin/audit` takes these optional filters. Each is an exact match, never a pattern: `%` and `_` are ordinary characters, and `agent=l1` does not match an agent called `l10`. Filters combine with AND.

| Parameter | Keeps entries whose record has |
| --- | --- |
| `kind` | one of these kinds, comma-separated: `decision`, `tool_result`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin` |
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

### Policies: read, check, dry run

These three routes change nothing and write no audit record. They answer the questions an operator has before acting: which policy file is loaded, would the edited file load, and what would the policies say about this call.

`GET /admin/policies`:

```json
{
  "path": "/etc/attenuo/policies.cedar",
  "sha256": "9f2c...e1",
  "loaded_at": "2026-10-23T19:02:11.52Z",
  "policy_ids": ["issues", "public_reads"],
  "warnings": [],
  "policies": [
    {"id": "issues", "text": "@id(\"issues\")\npermit(principal, action == Action::\"github/create_issue\", resource);"},
    {"id": "public_reads", "text": "@id(\"public_reads\")\npermit(principal, action == Action::\"github/read_file\", resource)\nwhen { ... };"}
  ]
}
```

`sha256` and `loaded_at` describe the text the engine loaded, so after a failed reload they still name the old file. `path` and `sha256` are `null` when no policy file is configured.

`GET /admin/policies/check` reads the file and lints it as `attenuo policy lint` does, against the schema of the running engine:

```json
{
  "path": "/etc/attenuo/policies.cedar",
  "sha256": "41b0...7a",
  "loaded_sha256": "9f2c...e1",
  "differs_from_loaded": true,
  "ok": false,
  "error_count": 1,
  "warning_count": 0,
  "issues": [
    {"severity": "error", "stage": "validate", "policy_id": "public_reads",
     "message": "...attribute `no_such_attribute` ... not found", "line": 3, "column": 8}
  ],
  "policy_ids": ["issues", "public_reads"]
}
```

`ok` is true when there are no errors, which is when `POST /admin/policies/reload` would succeed.

`POST /admin/policies/evaluate` takes an AuthZEN evaluation request (the body of `POST /access/v1/evaluation`) plus an optional `token`:

```json
{
  "token": "<delegation token>",
  "subject": {"type": "agent", "id": ""},
  "action": {"name": "read_file"},
  "resource": {"type": "tool", "id": "github/read_file", "properties": {"server": "github"}},
  "context": {"input": {"repo": "alice/public-site"}}
}
```

- With `token`, the token is verified with the server's keys and its chain is used; `subject.id` may be empty and `subject.properties.chain` may be left out (if present it must equal the token's chain, else 400 `chain_mismatch`). A bad signature or any other verification failure is 400 `invalid_token`. An expired token is accepted, verified as of the last second it was valid, and the answer has `token_expired: true`. The call counts as DPoP-bound when the token is bound (`cnf`).
- Without `token`, `subject.properties.chain` is required (400 `invalid_request` otherwise) and is only checked structurally, as of now (400 `invalid_chain` if that fails). Nothing checks that this server issued it.
- An optional `session`, `{"tainted_by": ["<server>/<tool>", ...], "tainted": true}`, sets the run's output labels for the dry run (`tainted` defaults to whether `tainted_by` is non-empty). Without it, the labels are read from the store for the chain's run. Anything else in `session` is a 400 `invalid_request`.
- An optional `approval`, `{"by": "user" | "operator" | "policy"}`, evaluates the call as a retry that carries a granted approval (`context.approval.present` true, `by` as given). The dry run never looks up or uses a stored approval.

```json
{
  "decision": "allow",
  "reason": "policy_allow",
  "policy_ids": ["public_reads"],
  "diagnostics": [],
  "lease_check": "skipped",
  "chain_source": "token",
  "token_expired": false,
  "session": {"tainted": false, "tainted_by": [], "source": "store"},
  "approval": {"present": false, "by": ""}
}
```

`chain_source` is `token` or `admin_supplied`. `session.source` is `request` or `store`. The decision comes from the capability stage and Cedar, the same code `POST /access/v1/evaluation` runs after its lease check, so for a token with live leases the two agree on decision, reason and policy ids. A revoked or expired lease does not change the dry run's answer (`lease_check` is always `skipped`).

## Metrics

`GET /metrics` is served by a separate listener, never on the proxy port. It is enabled with `[metrics] enabled = true`, has no authentication and returns Prometheus text format 0.0.4.
