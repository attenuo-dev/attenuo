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
| `GET /.well-known/authzen-configuration` | none | AuthZEN discovery (AuthZEN 1.0 section 9): `policy_decision_point`, `access_evaluation_endpoint` and `access_evaluations_endpoint`, and nothing else; no search endpoints, which are not served. Public metadata: no credential is needed and an `Authorization` header is ignored ([why](authzen.md#discovery)). The URLs are built from `[server] public_url`. Without it (loopback only) from `Host`, which must be `localhost`, `127.0.0.1` or `[::1]`; anything else is 400 `invalid_host`. |

## Token

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /token` | agent client credentials at hop 0; at later hops the parent token, plus the actor's client credentials or an `actor_token` | RFC 8693 token exchange, as a form or JSON. Hop 0 takes an OIDC ID token or an ID-JAG. Later hops take a parent delegation token and `authorization_details`. Optional `may_act` (agent ids) sets who may exchange the new token next. A `DPoP` header binds the new token to a key (`token_type` `DPoP`); `subject_token_dpop` is the parent key's sign-off, naming the new key and `actor`, when the parent is bound to another key. |
| `POST /token/renew` | bearer delegation token (and a DPoP proof if it is bound) | Extend the lease of the token's last hop. Returns `{lease, expires_at, expires_in}`. A refusal of a token that verified is audited (below). |

A capability may carry run `limits` (`calls`, `sum: {arg, max}`, `calls_per: {arg, max}`, `distinct: {arg, max}`; [run limits](../design/server.md#run-limits)). `distinct` allows at most `max` different values of `arg`. `calls_per` and `distinct` may add `"derive": "host"` to count the host of a URL argument instead of the whole value (`{"arg": "url", "derive": "host", "max": 2}`). A child must keep every limit of the parent capability that covers it, on the same argument and derivation, at most as large (`calls: m` also satisfies a parent's `calls_per` or `distinct` with `max >= m`); one it leaves out or asks larger is filled in or lowered (a `sum`, `calls_per` or `distinct` over another argument or derivation is refused as not covered), and its `calls` and `sum` are lowered further to what the parent hop has left. An unknown limit kind or derivation, or `derive` on a `sum`, is 400 `invalid_request`.

A later-hop request authenticates its `actor` with `client_id` / `client_secret` (or HTTP Basic), or with `actor_token` and `actor_token_type` = `urn:ietf:params:oauth:token-type:jwt` (RFC 8693 §2.1): a workload-identity JWT, such as a SPIFFE JWT-SVID, from an `[[actor_trust]]` issuer. `[token] actor_auth` decides which are accepted. An actor token works for one exchange, and the child expires no later than it does. If the parent token carries `may_act`, the `actor` must be listed (`actor_not_permitted` otherwise). `may_act` on the request sets the new token's own list: absent means any authenticated agent may exchange the new token (it does not inherit the parent's list), and `[]` means none may.

**Refused exchanges are audited.** When the subject token verified (signature, issuer, audience, expiry, chain) and so did its DPoP proof, a refusal the request caused is a `deny` record against the parent's chain: server `attenuo`, tool `token.exchange`, kind `decision`, the parent's subject, agents, leases and `chain_id`. The 400 carries the record id in `X-Attenuo-Decision-Id` and as `decision_id` in the body:

```json
{"error": "invalid_scope", "detail": "delegation chain is invalid: ...", "decision_id": "10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223"}
```

| Refusal | `error` / `error_description` | Audit `reason` |
| --- | --- | --- |
| asks for more than the parent holds | `invalid_scope` | `exchange_widening` |
| chain deeper than `[issuer] max_depth` | `invalid_scope` | `exchange_too_deep` |
| actor not in the parent's `may_act` | `invalid_request` / `actor_not_permitted` | `exchange_actor_not_permitted` |
| authenticated agent or actor token is not `actor` | `invalid_request` / `actor_mismatch` | `exchange_actor_mismatch` |
| `actor` already in the chain | `invalid_request` / `duplicate_actor` | `exchange_duplicate_actor` |
| `actor` is `attenuo` | `invalid_request` / `reserved_agent` | `exchange_reserved_agent` |
| actor token expires now | `invalid_request` / `actor_token_expired`, `no_lifetime_left` | `exchange_no_lifetime_left` |
| parent already delegated to this actor, or actor token reused | `invalid_grant` / `replayed` | `exchange_replayed` |
| a requested capability has an invalid name or limit | `invalid_grant` | `exchange_invalid_capability` |
| parent lease revoked, expired or unknown | `invalid_grant` | `lease_revoked`, `lease_expired`, `lease_unknown` |

Not recorded, a server log line only: a malformed request, failed client or actor-token authentication, a subject token or DPoP proof that does not verify (so an anonymous caller cannot write to the log, SR-18), and server errors. A `requested_ttl_seconds` beyond the parent's expiry is not a refusal: the child is clamped to the parent. A refused exchange uses up nothing: the parent can still delegate once to that actor, an actor token can be presented again, and no run limit is charged; only its DPoP proof (its `jti`) is spent. It is counted in `decisions_total{decision="deny",reason}`.

**Refused renewals are audited.** When the token of a `POST /token/renew` verified (signature, issuer, audience, expiry, chain) and so did its DPoP proof, a refusal is a `deny` record against the token's chain: server `attenuo`, tool `lease.renew` (the tool of a successful renewal, so `audit export --tool lease.renew --decision deny` lists the refused ones), kind `decision`, and the arguments digest of `{lease, ancestor, dpop_bound}`. The 400 carries the id in `X-Attenuo-Decision-Id` and `decision_id`:

| Refusal | `error` | Audit `reason` |
| --- | --- | --- |
| the token's own lease, or an ancestor's, is revoked | `invalid_grant` | `lease_revoked` |
| an ancestor lease has expired (stopped renewing) | `invalid_grant` | `lease_expired` |
| the token's own lease, or an ancestor's, is unknown to the lease store | `invalid_grant` | `lease_unknown` |

The token's own lease having lapsed is not a refusal: renewal revives it. Not recorded, a server log line only: a missing token, a token or DPoP proof that does not verify (401, SR-18), and lease store errors (500).

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

Both endpoints echo a request's `X-Request-ID` header on the response, whatever its status (AuthZEN 1.0 section 10.1.3). What of the AuthZEN specification is implemented, extended and left out, with the conformance fixtures that check it: [AuthZEN conformance](authzen.md).

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /access/v1/evaluation` | bearer token, or a trusted PEP | AuthZEN evaluation. Same pipeline as the proxy, run limits included: an allowed evaluation is charged as a proxied call is, and its answer carries `context.budget` (`limited`, `calls_remaining`, `amount_remaining`, `destination_new`) when a limit matched, `context.charged` when it was charged, `context.limit` on `budget_exhausted`, `context.untrusted_args` (`[{arg, seq, kind}]`, as in the proxy's error data) when an argument matched an untrusted result of the run, and `context.usage` (`{calls, amount, destination_seen}`, as in the proxy's error data) for a destructive tool; an allowed evaluation is counted in the run's usage, and anything the PEP sends under `context.usage` is ignored. `context.diagnostics` is filled only for callers `[authzen] diagnostics` allows: by default a `[[peps]]` entry, which can authenticate next to a bearer token with `pep_id` and `pep_secret` in the body. |
| `POST /access/v1/evaluations` | same | AuthZEN batch: top-level `subject`, `action`, `resource`, `context` are defaults and each entry of `evaluations` overrides them. Answers `{"evaluations": [{decision, context}, ...]}`, one per entry, each decided and audited like a single evaluation. At most `[authzen] max_batch` entries (default 64): more is 400 `batch_too_large`. Without `evaluations`, or with an empty one, the request is a single evaluation and is answered with a single `{decision, context}` (AuthZEN 1.0 section 7.1). `options.evaluations_semantic` (AuthZEN 1.0 section 7.1.2.1) is `execute_all` (default: every entry decided and answered), `deny_on_first_deny` (entries decided in order, stopping after the first deny; an entry that fails counts as a deny) or `permit_on_first_permit` (stopping after the first permit). A stopped batch answers only the entries it decided, so `evaluations` is shorter than the request; the entries after the stop are not decided, charged or audited. Any other value is 400 `invalid_request` before anything is decided. |

## MCP proxy

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp/{server}` | bearer delegation token | Send an MCP request to the upstream called `server`. `tools/call` and similar methods are decided first. |
| `GET /mcp/{server}` | bearer delegation token | The streamable HTTP listen stream, after the lease check; resumable with `Last-Event-ID`. List answers on it are filtered and answers to allowed calls labelled, like `POST` answers. Ended (and recorded as `stream.end`, at most once per chain and reason per 60 s) when the lease is revoked or the token expires. |
| `DELETE /mcp/{server}` | bearer delegation token | Passthrough session close, after the lease check. |

A denial is a JSON-RPC error with code `-32003`, carrying `reason` and `decision_id`. A call that a policy sends for approval (reason `approval_required`) gets `-32008` instead, with `reason`, `decision_id`, `call_hash` (SHA-256 of the RFC 8785 JSON of `{server, tool, arguments}`), `approval_id` and `expires_at`, and is not forwarded. Once the approval is granted, the identical call from the same hop is allowed once (see [Approvals](#approvals)); or the retry carries the grant's signed approval token in `params._meta["dev.attenuo/approval"]`, which the proxy removes before the upstream and which does not count as an argument (see [Approval tokens](#approval-tokens)). A token that does not verify, is for another call, hop, run or key, or names an approval that is no longer granted gets `-32003` with reason `approval_invalid`. `approval_id` is absent if the server could not open an approval. When an argument of the call copies a value or span of an untrusted result of the run (output labelling phase 2), the `-32008` data, and a `-32003` policy denial's data, add `untrusted_args: [{arg, seq, kind}]`: the argument, the `seq` of the `tool_result` record it matched (absent for kind `unreadable`) and the kind (`leaf`, `entity`, `kgram`, or `unreadable` when the run's index could not be read). A call over a run limit gets `-32003` with reason `budget_exhausted` and `data.limit: {hop, kind, arg, max, used}` (`arg` absent for `calls`, written `url#host` for a derived value; for `distinct`, `used` is how many values the limit has seen); `budget_error` means the counters could not be read or written, and `limit_arg_invalid` that the call lacks an argument a limit counts, or has a value it cannot count (a `sum` needs a non-negative integer, a `"derive": "host"` limit an absolute URL with a host and no backslash, whitespace or control character, and a `calls_per` or `distinct` list at most 256 values). No policy or approval passes these. For a call to a tool the catalog marks destructive, the `-32008` and `-32003` data also carry `usage: {calls, amount, destination_seen}`, the run's usage of the tool before this call as the policy saw it (`context.usage`): allowed calls of this server and tool by every hop of the run, the sum of the catalog's `amount` input over them, and whether the catalog's `destination` value was seen in one of them. The decision record carries the same figures as `usage`, omitted for other tools. If the answer to an allowed call cannot be recorded in the audit log, the agent gets `-32003` with reason `label_error` and the call's `decision_id` instead of the answer. A missing or bad token is HTTP 401 with `-32001` and `data.reason` set to `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce` or, for a lease that is no longer live, `lease_revoked`, `lease_expired` or `lease_unknown`. A request refused for its lease without a per-call decision (`initialize`, `tools/list`, `ping`, `resources/unsubscribe`, the other allowlisted methods, notifications, `GET` and `DELETE`) is also a `deny` record with that reason, the token's subject and chain, the proxied server, and `tool` set to the method (`http.POST` for a notification, `http.GET`, `http.DELETE`); its 401 carries the record's id in `X-Attenuo-Decision-Id` and `data.decision_id`. These records are bounded like listen-stream ends: the first refusal per delegation chain, tool and reason in 60 s is recorded, and a retry within the window is still a 401 but writes no record, carries the first record's id (both are left out in the moment before a concurrent first record is written) and is counted in `audit_records_suppressed_total`. Refused exchanges and renewals, and `tools/call` denials, are recorded every time. A token that does not verify writes no record. An open stream (the `GET` listen stream, or a streamed answer) whose leases stop being live or whose token expires is ended within `[proxy] stream_recheck_seconds`: an SSE stream's last event is a JSON-RPC error with `id: null`, code `-32001`, `data.reason` (`lease_revoked`, `lease_expired`, `lease_unknown`, `token_expired`) and `data.decision_id`, the id of a `deny` record of tool `stream.end` with the session's hash tag. On the `GET` listen stream that record is written for the first such end per delegation chain and reason in 60 s; later ends in the window carry the same `decision_id` and are counted in `audit_records_suppressed_total` instead of recorded. A stream the client drops or the upstream ends writes no record; `GET` listen streams are counted by how they ended in `proxy_streams_ended_total`. An upstream the proxy cannot reach is HTTP 502 with `-32005` and `data.reason` `upstream_unreachable`; the upstream URL and transport error are only logged. An upstream that answers a `GET` with a success status but not `text/event-stream` is HTTP 502 with `-32005` and `data.reason` `upstream_not_event_stream` (MCP allows only an SSE stream or `405` there); `405` and error answers to a `GET` are relayed. Allowed responses carry `X-Attenuo-Decision-Id`.

## Approvals

A call gated with `@obligation("approval")` gets an `approval_id` in its `-32008` error. A person decides it through one of these routes; the agent's own delegation token can read it but never decide it.

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /approvals/{id}` | an OIDC ID token of the run's originating user (`Authorization: Bearer`) | Body `{"decision": "grant" \| "decline"}`. Answers the approval as below. |
| `GET /approvals/{id}` | that user's ID token, or a delegation token of the same run whose leases are live (with a DPoP proof when bound) | The approval. Anyone else, including a hop whose lease was revoked or has expired, gets 404. |
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
  "untrusted_args": [{ "arg": "repo", "seq": 41, "kind": "leaf" }],
  "decision_id": "<the gated decision>",
  "subject": "alice",
  "issuer": "https://idp.example",
  "agents": ["planner", "coder"],
  "created_at": "2026-10-24T10:00:00Z",
  "expires_at": "2026-10-24T10:02:00Z"
}
```

`state` is `pending`, `granted`, `declined` or `consumed`; `expired` says whether `expires_at` has passed. A decided approval adds `approver: {subject, method, by}` (`id_token`/`user` or `admin_token`/`operator`) and `decided_at`; a used one adds `consumed_by`, the id of the allowed decision. While it is granted and unexpired, every route above also answers with `approval_token` (below).

### Approval tokens

`approval_token` is a JWT signed with the issuer key that signs delegation tokens (same `kid`, same `/.well-known/jwks.json`), header `typ: attenuo-approval+jwt`, `alg: EdDSA`. Claims:

| Claim | Value |
|---|---|
| `iss`, `aud` | the issuer and audience of delegation tokens |
| `sub`, `by` | the approver (`sub` of the user, or `urn:attenuo:admin`), and `user` or `operator` |
| `chain_id`, `lease` | the run (its first hop's lease) and the lease of the hop that made the call |
| `ch` | the call hash, as in the `-32008` data |
| `iat`, `exp`, `jti` | when it was granted, the approval's `expires_at`, the approval id |
| `cnf.jkt` | the calling hop's key thumbprint, present only when its token is DPoP-bound |

Every answer for one grant carries the same token. To use it, retry the call with `"_meta": {"dev.attenuo/approval": "<token>"}` in the `tools/call` params (AuthZEN: `context.approval_token`). The server checks the signature, `typ` and `exp`, then that `chain_id`, `lease`, `ch` and `cnf.jkt` are the call's run, the calling hop's lease, the call hash and the hop's key binding, then consumes the approval named by `jti` once. Anything else is denied with `approval_invalid`; a value that is not a string is `-32602` at the proxy and 400 at AuthZEN. The consuming decision record has `approval: {id, by, presented: "token"}`. An external PEP can verify the token offline against the JWKS (`attenuo approval verify`, or the SDKs' `verify_approval_token` / `verifyApprovalToken`); only the server knows whether it was used already.

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
| `POST /admin/leases/{lease_id}/revoke` | Revoke the lease and all descendants. Body `{"reason": "..."}` (optional). Answers `{lease_id, revoked, reason, audit_id}`: `revoked` counts the leases that changed, `audit_id` is the `admin.lease.revoke` record (null when it could not be written; the revocation stands). The SDKs return it: Python `revoke_lease(...).audit_id`, TypeScript `(await revokeLease(...)).auditId`. |
| `POST /admin/leases/revoke?preview` | Revoke every lease of one originating user, one delegation chain or the chain that opened one MCP session, each with its descendants, in one transaction; `preview=true` is a dry run. See [Revoke by user or chain](#revoke-by-user-or-chain) and [Revoke by session](#revoke-by-session). |
| `GET /admin/leases/{lease_id}/tree?max_nodes` | The lease, its descendants and its ancestors, and how many leases a revoke would change now. Read-only; see [Lease tree](#lease-tree). 404 for an unknown lease. |
| `GET /admin/audit` | Audit entries in ascending `seq` order, paged with `from` and `limit` (default 100, at most 1000). Also returns `next` (when the page was full) and `head`, the newest `seq`. Filters and newest-first paging are below. |
| `GET /admin/audit/entries/{seq}` | One entry with its context, `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}` (below). 404 when there is no entry at `seq`. |
| `GET /admin/audit/records/{id}` | The same for the entry whose record id is `id`: the UUID that proxy denials and AuthZEN answers return as `decision_id`. 400 if `id` is not a UUID, 404 if no record has it. |
| `GET /admin/audit/checkpoints?before&limit` | Stored checkpoints, newest first, `{checkpoints, prev}`; each is `{seq, head_hash, at, kid, signature}`. `prev` is the `before` of the next (older) page, null after the oldest. Read-only: it never signs, unlike `/admin/audit/checkpoint`. |
| `GET /admin/audit/verify` | Walk the whole hash chain, verify every checkpoint signature against the JWKS, and report `{entries, ok, first_bad_seq, checkpoints, last_signed_seq, unsigned_tail, bad_checkpoints}`. |
| `GET /admin/audit/checkpoint` | The signed checkpoint of the head, `{seq, head_hash, at, kid, signature}` (signing it now if the head has none). For keeping outside the host. `hash` repeats `head_hash` for older clients. |
| `GET /admin/audit/export?from&to` | Entries `from..=to` (default: the whole log) and the checkpoints in that range, streamed as `application/x-ndjson`: a `header` line, `entry` lines, then `checkpoint` lines. Verify offline with `attenuo audit verify --file`. `kind`, `chain_id`, `tool` and `decision` keep only the matching entries; the header then has a `filter` member naming them and the file cannot be verified. The SDKs take the same four: Python `audit_export(kind=, chain_id=, tool=, decision=)`, TypeScript `auditExport(from, to, { kind, chainId, tool, decision })`. 400 if `from` is 0 or `to < from`, for an unknown kind or decision, more than one kind, or an empty filter value. |
| `POST /admin/policies/reload` | Re-read the policy file. On failure the old policy stays. |
| `GET /admin/policies` | The policy set in force: file path, its `sha256` and `loaded_at` (startup or last successful reload), `policy_ids`, validation `warnings`, and `policies: [{id, text}]`. |
| `GET /admin/policies/check` | Lint the policy file as it is on disk now against the running schema, with line and column for each issue, and say whether it differs from the loaded one. Loads nothing, audits nothing. 409 `check_unavailable` without `policy.policies_path`. |
| `POST /admin/policies/evaluate` | Dry run: what the loaded policies decide for one call, given a token or a chain, and optionally the run-limit state to assume (`budget`). No lease check, no charge, no audit record, no decision metric. |
| `POST /admin/budgets/refund` | Body `{"decision_id": "<uuid>", "reason": "..."}`: give back to every run-limit counter what that decision charged, once, for an allowed call whose effect did not happen. Answers `{decision_id, refunded, reason, audit_id}` (`refunded` counts the token-limit counters credited; the run usage the decision charged is returned too but not counted, so a call that charged only usage answers 0; a `distinct` value is freed, and counted, only when no other unrefunded decision used it, SR-62) and appends an `admin.budget.refund` record. When there is nothing to refund, the audit log says why: 410 `charge_pruned` when the decision's record shows a run-limit charge whose charge-log entry was pruned, 404 `not_found` for a decision that charged nothing or an unknown id, 409 `already_refunded`; see [Budget refund](#budget-refund). Also on the console listener with `[admin_ui] allow_write = true`. |
| `POST /admin/root-token` | Development root mint. Mounted only when `[dev] allow_root_mint = true`. |

### Budget refund

`POST /admin/budgets/refund` works from the charge log, which keeps what each allowed call charged until `[leases] run_state_retention_seconds` after its run's leases are gone. When the charge log has no entry for `decision_id`, the server looks the decision up in the audit log, which is append-only and keeps every decision record, and answers by what the record shows:

| Status | `error` | When | `detail` |
| --- | --- | --- | --- |
| 410 | `charge_pruned` | an allowed decision whose record carries `budget` (it charged run-limit counters): its charge-log entry can only have gone by run-state pruning, so the charge, refunded or not, can no longer be refunded | ``the charge of decision `<id>` was pruned: its run's leases are gone and the charge is older than [leases] run_state_retention_seconds, so it can no longer be refunded (its audit record keeps what it charged)`` |
| 404 | `not_found` | an allowed decision whose record carries `usage` but no `budget`: it charged run usage only, which is also deleted when its run's root lease is revoked, so the record cannot say whether it was pruned | ``decision `<id>` charged no run limit, only run usage, which is no longer recorded (dropped when its run was revoked, or pruned past [leases] run_state_retention_seconds); nothing to refund`` |
| 404 | `not_found` | any other record: a denied decision, an allowed one that matched no limit and kept no usage, or a record of another kind | ``decision `<id>` charged nothing: its audit record shows no run limit or run usage charged; nothing to refund`` |
| 404 | `not_found` | no audit record has that id (or it is not a UUID) | ``unknown decision `<id>`: no audit record has this id; nothing to refund`` |
| 409 | `already_refunded` | the charge-log entry is there and was refunded | ``the charge of decision `<id>` was already refunded`` |

A refused refund writes no audit record, so no `decision_id` member or `X-Attenuo-Decision-Id` header comes with these answers. A decision that was refunded and then pruned answers 410: its earlier `admin.budget.refund` record is in the audit log.

### Revoke by user or chain

`POST /admin/leases/revoke` takes a JSON body with exactly one selector and an optional reason:

```json
{"user": "alice@example.com", "reason": "laptop stolen"}
{"chain_id": "6f1c2d9e-...", "reason": "run went wrong"}
{"session": "<Mcp-Session-Id>", "reason": "session hijacked"}
```

- `user` matches every lease issued for that originating user: the `sub` of the chain's originating-user block, compared exactly, under any issuer. The server records the subject when it registers a lease. Leases registered by a server older than this route have no recorded subject and are not matched; revoke them by `chain_id` or by id.
- `chain_id` matches one delegation chain: the lease of its first hop (the `chain_id` of its audit records, and the `root` of the lease tree) and everything delegated from it. A lease that has a parent is not a chain id and matches nothing. Found through the parent links, so older leases are matched too.
- `session` takes a raw MCP session id (the `Mcp-Session-Id` header) and matches, as `chain_id` would, the chain that opened that session through the proxy. See [Revoke by session](#revoke-by-session).

| Selector | Value | Matches | `selector` in the answer and the audit arguments |
| --- | --- | --- | --- |
| `user` | the originating user's `sub` | every lease recorded for that subject, any issuer | `{"user": "<sub>"}` |
| `chain_id` | a first-hop lease id | that lease and everything delegated from it | `{"chain_id": "<id>"}` |
| `session` | a raw `Mcp-Session-Id` | each chain that opened the session, as `chain_id` | `{"session_tag": "<12 hex>", "chain_ids": ["<id>", ...]}` |

A selector matches leases that are not revoked, expired ones included (`POST /token/renew` could renew those while the token is valid). Each match is revoked with the same cascade as `POST /admin/leases/{lease_id}/revoke`. Matching nothing is a 200 with empty lists, not an error. The answer:

```json
{
  "selector": {"user": "alice@example.com"}, "preview": false,
  "matched": ["0b7e...", "6f1c..."], "revoked": ["0b7e...", "6f1c...", "a93d..."],
  "matched_count": 2, "revoked_count": 3, "truncated": false,
  "reason": "laptop stolen", "audit_id": "3f2a..."
}
```

- `matched`: the unrevoked leases the selector named, in id order.
- `revoked`: every lease that changed from unrevoked to revoked: the matches first, then the descendants the cascade reached, each group in id order. Each list holds at most 10,000 ids; the counts are always complete, and `truncated` says a list was cut.
- `reason`: defaults to `revoked by admin`. `audit_id`: the record of the revocation, `null` if it could not be written (the revocation stands, as for a single revoke).

With `?preview=true` nothing is written, no lease and no audit record. `revoked` is then what a revocation sent now would change, and `reason` and `audit_id` are `null`.

Each revocation appends one record with tool `admin.lease.revoke` and kind `lease_revoke`, whatever it matched. Its `leases` holds the first 256 revoked ids. Its arguments are `{selector, reason, revoked, listed, truncated}` (the `selector` as the answer shows it, so a session revocation names the resolved chains; the count, how many ids `leases` holds, and whether that list was cut), stored as a digest like every admin record. The `leases_revoked_total` metric counts every revoked lease.

Errors: 400 `invalid_request` for no selector, more than one, an empty value, an unknown field or a body that is not JSON; 401 without the admin bearer. On the console listener the route needs `Content-Type: application/json`. Without `[admin_ui] allow_write = true` it serves only `?preview=true` there and answers a revocation with 404. The console's lease page uses it for "Revoke chain…", "Revoke all for <user>…" and "Revoke by session…".

The SDKs wrap it: Python `AdminClient.revoke_by_selector(user=..., chain_id=..., session=..., reason=..., preview=False)` (and `AsyncAdminClient`) returns a `SelectorRevocation`; TypeScript `AdminClient.revokeBySelector({ user } | { chainId } | { session }, { reason, preview })` resolves to one. Both refuse anything but exactly one non-empty selector before sending, and never log or echo a session id.

#### Revoke by session

When the proxy binds a new MCP session (the upstream assigns an `Mcp-Session-Id`, normally in its answer to `initialize`), the server records the session's SHA-256, the upstream server name and the chain id of the caller (`LeaseStore::record_session`; SQLite table `lease_sessions`). Only a request whose token and DPoP proof verified and whose leases are live can open a session, so nothing else can write a binding. The raw id is never stored; the session tag in audit records and logs is the first 12 hex characters of the same hash. A binding is write-once per session and server: the first chain is kept. It is deleted once its chain's root lease is revoked, or has been expired for longer than `[leases] session_retention_seconds` (default 86400), by a background pass every minute (see [config](config.md#leases)); a pruned session then resolves like one the server never saw.

`{"session": "<id>"}` hashes the id, looks up the chains recorded for it (one per upstream the session was opened with, normally one) and then behaves as `chain_id` for each of them, preview included. The answer's `selector` is `{"session_tag": "...", "chain_ids": [...]}`, never the raw id. A session the server has no record of (a wrong id, or one opened before the server recorded sessions) resolves to `chain_ids: []` and matches nothing: a 200 with empty lists, as for an unknown `chain_id`. The proxy's next request on a revoked session's chain is refused (HTTP 401 `lease_revoked` for `initialize`, `ping`, `tools/list` and session `GET`s; a `-32003` denial for `tools/call`).

### Lease tree

`GET /admin/leases/{lease_id}/tree` is a dry run of `POST /admin/leases/{lease_id}/revoke`: it shows what the revocation would reach and changes nothing (no lease row, no audit record).

- `nodes`: the lease first, then every lease delegated from it, breadth-first (each level in id order). At most `max_nodes` (default 1000, clamped to 1..10000); `truncated` is `true` when the cap cut the list short.
- `ancestors`: the leases it was delegated from, nearest first, ending at `root`, the chain's first hop. `root` is also the `chain_id` of the chain's audit records. Empty for a root lease.
- `would_revoke`: the leases in the whole subtree that are not revoked yet, counted with the same query the revocation runs, so it is the `revoked` count a revoke sent now would return. It ignores `max_nodes`.
- Per lease: the registry row (`parent`, `expires_at`, `revoked_at`, `revoke_reason`), `active` now, and from the audit record that issued it (`root_token` or `exchange`) the `agent` it was issued to, `issued_at` and `issued_seq`. These three are `null` when no issuance record is found.
- Per lease, `chain_id` and `subject`: the chain id, which is the same as `root` for every lease of the tree and is what `POST /admin/leases/revoke` takes as `chain_id`; and the originating user's subject the server recorded when it issued the lease, which that route takes as `user`. `subject` is `null` for a lease registered before the server recorded subjects. The subjects of the whole tree are read with one store call. `subject` is the IdP's `sub`, so treat it as untrusted text.
- Per lease, `budget`: the hop's run limits and what is left of them, `null` when the hop has no limits and nothing was charged under its lease. `{recorded, limits, usage}`: `recorded` says the server kept the hop's limits when it issued the token (a lease issued by an older server has counters but no `max`); `limits` has one entry per limit, `{cap, server, tool, kind, arg, max, used, remaining}` (`arg` is `null` for `calls` and `url#host` for a derived value; `used` is calls, the sum, for `distinct` the values seen, and for `calls_per` the most calls any one value has had, with `values` the number of values seen; `remaining` is `max - used`); `usage`, on a run's root lease, is the run's usage per destructive tool, `{tool, calls, amount, destinations}`. Value hashes are never shown. Calls are charged to every hop, so the smallest `remaining` along the chain is what a lease can still spend.

```json
{
  "root": "0b7c...",
  "ancestors": [
    {"lease_id": "0b7c...", "parent": null, "agent": "planner", "active": true,
     "chain_id": "0b7c...", "subject": "alice@example.com",
     "expires_at": "2026-10-23T19:20:00Z", "revoked_at": null, "revoke_reason": null,
     "issued_at": "2026-10-23T19:05:00Z", "issued_seq": 41, "budget": null}
  ],
  "nodes": [
    {"lease_id": "5e21...", "parent": "0b7c...", "agent": "coder", "active": true,
     "chain_id": "0b7c...", "subject": "alice@example.com",
     "expires_at": "2026-10-23T19:20:02Z", "revoked_at": null, "revoke_reason": null,
     "issued_at": "2026-10-23T19:05:02Z", "issued_seq": 42,
     "budget": {"recorded": true, "usage": [], "limits": [
       {"cap": 0, "server": "web", "tool": "get_webpage", "kind": "distinct",
        "arg": "url#host", "max": 2, "used": 1, "remaining": 1}]}},
    {"lease_id": "9a40...", "parent": "5e21...", "agent": "reviewer", "active": false,
     "chain_id": "0b7c...", "subject": "alice@example.com",
     "expires_at": "2026-10-23T19:20:03Z", "revoked_at": "2026-10-23T19:06:10Z",
     "revoke_reason": "rotated", "issued_at": "2026-10-23T19:05:03Z", "issued_seq": 43,
     "budget": null}
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
- An optional `session`, `{"tainted_by": ["<server>/<tool>", ...], "tainted": true, "untrusted_args": ["<argument>", ...], "args_contain_untrusted": true}`, sets the run's output labels for the dry run (`tainted` defaults to whether `tainted_by` is non-empty, `args_contain_untrusted` to whether `untrusted_args` is). Without it, the labels are read from the store for the chain's run, and the call's arguments are matched against the run's span index as a proxied call's would be. Anything else in `session` is a 400 `invalid_request`.
- An optional `approval`, `{"by": "user" | "operator" | "policy"}`, evaluates the call as a retry that carries a granted approval (`context.approval.present` true, `by` as given). The dry run never looks up or uses a stored approval. `by` is required, so an empty block is refused rather than read as granted, and `approval` takes no other member: no approval id or token. An unknown member (`{"approved_by": ...}`, say) is a 400 `invalid_request` naming it, as in `session`, `usage` and `budget`.
- An optional `usage`, `{"calls": 1, "amount": 10, "destination_seen": true}` (each member optional, 0 or false; the numbers non-negative integers), sets `context.usage` for the dry run. Without it, the run's usage of a destructive tool is read from the store (all zero for any other tool), unless the server keeps no run usage at all (no loaded policy reads `context.usage`, the catalog names no `amount` or `destination`, and `[policy] track_usage` is not `true`): then the figures are zero and `usage.source` is `untracked`. With a `budget` (below) and no `usage`, the figures are zero and nothing is read. Anything else in `usage` is a 400 `invalid_request`.
- An optional `budget` states the run-limit situation to decide the call in, instead of the store's counters, in the vocabulary of a `policy test` case's `budget` (see below).

The `budget` block (every member optional):

```json
{
  "calls_remaining": 1,
  "amount_remaining": 40,
  "destination_new": false,
  "limited": true,
  "limits": [{"hop": 0, "kind": "distinct", "arg": "recipient", "max": 3, "used": 3}]
}
```

| Member | Type | Meaning |
|---|---|---|
| `calls_remaining` | non-negative integer | What every `calls` limit of the chain that matches the call has left before it: its counter is taken as `max - calls_remaining` (0 when that is negative). Left out: nothing used. |
| `amount_remaining` | non-negative integer | The same for `sum` limits. |
| `destination_new` | boolean | `false`: the call's value was already counted, once by each matching `calls_per` limit and by each `distinct` limit. Left out or `true`: the value is new. |
| `limited` | boolean | `context.budget.limited` when no limit of the chain matches the call (default `true`). Ignored when one does. |
| `limits` | list, at most 64 entries | The counter of single limits, over the figures above, in the shape of the `limit` member of a `budget_exhausted` answer: `hop` (position in the chain, root 0), `kind` (`calls`, `sum`, `calls_per` or `distinct`), `arg` (the counted argument as the limit names it, `arg#host` for a derived one; required for every kind but `calls`, refused for `calls`), `used` (required: calls or summed amount; for `calls_per` the calls with this call's value; for `distinct` how many values the limit has seen) and `max` (optional; must equal the limit's). |

The counters are then checked by the same code a live call goes through, before Cedar, so a call that would take a hard limit past its `max` answers `budget_exhausted` with the same `limit` member and diagnostic as a run whose store held those counters. When no limit of the chain matches the call, there is nothing to check, and Cedar sees the figures as given (`context.budget`, members left out as for an unlimited call), as `attenuo policy test` sets them offline. A stated `budget` is never read from or written to the lease store, and nothing is audited. 400 `invalid_request`, with a diagnostic starting `` `budget`: ``, for: a block that is not an object, an unknown member (also inside a `limits` entry), a figure that is negative or not an integer, a flag that is not a boolean, `limits` that is not a list or has more than 64 entries, an unknown `kind`, a missing `hop`, `kind` or `used`, `arg` on a `calls` entry or missing on another, two entries naming the same limit, and an entry that names no limit of the chain matching the call (wrong hop, kind, argument or `max`).

```json
{
  "decision": "allow",
  "reason": "policy_allow",
  "policy_ids": ["public_reads"],
  "diagnostics": [],
  "lease_check": "skipped",
  "chain_source": "token",
  "token_expired": false,
  "session": {"tainted": false, "tainted_by": [], "args_contain_untrusted": false,
              "untrusted_args": [], "source": "store"},
  "approval": {"present": false, "by": ""},
  "budget": {"limited": false, "calls_remaining": 9223372036854775807,
             "amount_remaining": 9223372036854775807, "destination_new": true,
             "source": "store"},
  "usage": {"calls": 0, "amount": 0, "destination_seen": false, "source": "store"}
}
```

The SDKs send the block from Python `policy_evaluate(..., budget=StatedBudget(...))` and TypeScript `policyEvaluate(..., { budget })`, and `session`, `approval` and `usage` the same way (`StatedSession`, `StatedApproval`, `StatedUsage`), and type the answer below; the console's dry-run form has "Budget", "Run labels", "Run usage" and "Approval" sections.

`budget` is `context.budget`: as the run's counters stand now (`source: "store"`; the dry run reads them and never charges), or as the request's `budget` block states them (`source: "request"`). When the call would exceed a limit, the answer is `budget_exhausted` and adds `limit: {hop, kind, arg, max, used}`.

`chain_source` is `token` or `admin_supplied`. `session.source` is `request` or `store`. `usage.source` is `request`, `store`, or `untracked` when the server keeps no run usage (the zeros are then not a reading of the run); usage read from the store is never charged. The decision comes from the capability stage and Cedar, the same code `POST /access/v1/evaluation` runs after its lease check, so for a token with live leases the two agree on decision, reason and policy ids. A revoked or expired lease does not change the dry run's answer (`lease_check` is always `skipped`).

## Metrics

`GET /metrics` is served by a separate listener, never on the proxy port. It is enabled with `[metrics] enabled = true`, has no authentication and returns Prometheus text format 0.0.4.

Every series is prefixed `attenuo_`. Label values come from fixed sets, so the number of series is bounded: nothing is labelled by lease, user, run, agent, tool or argument value. Series with fixed label sets are written at zero before anything happens, so a rate over them is defined from the first scrape. Counters start at zero when the process starts.

| Series | Type | Labels | Help |
|---|---|---|---|
| `decisions_total` | counter | `decision` (`allow`, `deny`), `reason` | Decision records by outcome and reason code: pipeline decisions (MCP proxy and AuthZEN) and the requests the proxy refuses and records before a decision. `reason` is one of `policy_allow`, `policy_deny`, `policy_error`, `approval_required`, `approval_invalid`, `capability_denied`, `tool_not_in_catalog`, `attribute_type_mismatch`, `input_type_mismatch`, `invalid_name`, `tool_not_listed`, `session_mismatch`, `budget_exhausted`, `budget_error`, `limit_arg_invalid`, `lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, `audit_error`, and for a refused token exchange `exchange_widening`, `exchange_too_deep`, `exchange_actor_not_permitted`, `exchange_actor_mismatch`, `exchange_duplicate_actor`, `exchange_reserved_agent`, `exchange_no_lifetime_left`, `exchange_replayed`, `exchange_invalid_capability`, `exchange_refused`. A lease refusal of `initialize` or another undecided request, of an exchange's parent, or of a renewal, counts under its lease reason. Unauthenticated requests (bad token, DPoP) are not counted here. |
| `tokens_issued_total` | counter | `kind` (`root`, `exchange`) | Delegation tokens issued. |
| `leases_revoked_total` | counter | none | Leases moved to revoked, including cascaded descendants. |
| `lease_sessions_pruned_total` | counter | none | Session bindings (revoke by session) deleted because their chain's root lease was revoked or expired longer ago than `[leases] session_retention_seconds`. |
| `leases_pruned_total` | counter | none | Leases deleted from the registry (with their recorded users and bindings) because every lease of their run was revoked or expired longer ago than `[leases] retention_seconds`. |
| `run_state_pruned_total` | counter | `kind` (`counters`, `charges`, `approvals`) | Run state deleted by `[leases] run_state_retention_seconds` once the leases it belongs to were gone from the registry: run-limit and run-usage counters, charge-log entries (one per charged decision) and approvals. |
| `audit_append_errors_total` | counter | none | Audit log appends that failed. |
| `audit_checkpoints_total` | counter | none | Signed audit checkpoints written. |
| `audit_checkpoint_last_timestamp_seconds` | gauge | none | Unix time this process wrote the newest signed audit checkpoint; 0 when none. |
| `audit_sink_delivered_total` | counter | none | Signed checkpoints delivered off the host by `[audit.sink]`. |
| `audit_sink_failures_total` | counter | none | Deliveries by `[audit.sink]` that failed and will be retried. |
| `audit_sink_dropped_total` | counter | none | Checkpoints dropped from a full `[audit.sink]` queue before delivery. |
| `audit_sink_queue_depth` | gauge | none | Checkpoints waiting in the `[audit.sink]` queue. |
| `audit_sink_oldest_undelivered_timestamp_seconds` | gauge | none | Unix time the oldest undelivered checkpoint was queued; 0 when none. |
| `audit_wal_checkpoints_total` | counter | `result` (`complete`, `incomplete`, `error`) | Background WAL checkpoint rounds: `complete` left nothing in the WAL, `incomplete` left frames behind (a reader or the writer was in the way; the next commit starts another round). |
| `audit_wal_locked_passes_total` | counter | none | WAL catch-up passes run holding the store's lock, each pausing appends briefly (only when the WAL passes 64 MB under load). |
| `audit_wal_backstops_total` | counter | none | WAL checkpoints the audit writer ran itself because the WAL outgrew the backstop (128 MB): the background thread fell behind. |
| `audit_wal_presyncs_total` | counter | `file` (`wal`, `db`) | Syncs run off the request path: `wal` ahead of a signed checkpoint, `db` before a locked pass. |
| `audit_wal_frames` | gauge | none | Frames in the WAL at the last checkpoint pass. |
| `audit_wal_last_complete_timestamp_seconds` | gauge | none | Unix time the last complete WAL checkpoint round finished; 0 before the first. |
| `http_requests_total` | counter | `route` (route template, for example `/mcp/{server}`), `status` | HTTP requests by route template and status. |
| `authorize_duration_seconds` | histogram | none | Time to decide one tool call: leases, labels, run limits, run lock, approval, policy, charge and audit append. |
| `audit_append_duration_seconds` | histogram | none | Time for one audit log append, including waiting for the store's lock. |
| `proxy_stage_seconds` | histogram | `stage` (`token_verify_hit`, `token_verify_miss`, `lease_check`, `policy`, `audit_append`, `blocking_pool`, `upstream`, `response`, `total`) | Time per stage of a proxied call. `policy` runs from the end of the lease check to the policy's answer, so it includes the label and budget reads and the wait for the run lock. |
| `budget_charges_total` | counter | `kind` (`calls`, `sum`, `calls_per`, `distinct`) | Run-limit counters charged by allowed calls, one per matching limit in every hop (a call charged to three hops adds 3). Run usage is not counted. |
| `budget_exhausted_total` | counter | `kind`, `at` (`check`, `charge`) | Calls denied with `budget_exhausted`, by the limit kind hit and where: `check` on the counters as read, `charge` in the store's re-check because a concurrent call of the run spent the budget first. |
| `budget_refunds_total` | counter | `source` (`operator`, `audit_error`) | Decisions whose run-limit charge was returned: `operator` through `POST /admin/budgets/refund`, `audit_error` by the pipeline when the allowed decision could not be recorded. |
| `approvals_created_total` | counter | none | Pending approvals stored for `approval_required` calls. A repeated gated call that finds the pending one does not count. |
| `approvals_decided_total` | counter | `outcome` (`granted`, `declined`), `by` (`user`, `operator`) | Approvals granted or declined. Refused attempts (not pending, expired, revoked lease) are not counted. |
| `approvals_consumed_total` | counter | `by` (`user`, `operator`) | Granted approvals spent by the allowed call they were for, by who granted them. |
| `approvals_expired_total` | counter | none | Attempts to grant, decline or present (as an approval token) an approval that had expired. Expiry is not a state, so an approval that lapses with nobody asking is not counted. |
| `results_recorded_total` | counter | `label` (`trusted`, `untrusted`) | Tool results recorded after an allowed call, by output label. Each untrusted one labels its run. A result that could not be recorded is withheld (`label_error`) and not counted. |
| `taint_matches_total` | counter | `decision` (`allow`, `deny`) | Decisions on destructive calls in a tainted run with at least one argument found in the run's untrusted results (or not checkable because the span index could not be read). |
| `proxy_streams_ended_total` | counter | `cause` (`token_expired`, `lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, `lease_other`, `recheck_unavailable`, `recheck_failed`, `client_disconnect`, `upstream_eof`, `upstream_error`) | `GET` listen streams the proxy relayed, counted once each when they end: cut by the re-check (the lease and token causes are also `stream.end` records, the `recheck_*` ones are not), dropped by the client, or finished or broken by the upstream. Streamed `POST` answers are not counted. |
| `audit_records_suppressed_total` | counter | `tool` (`stream.end`, or a lease refusal's `initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, `resources/unsubscribe`, `logging/setLevel`, `http.POST`, `http.GET`, `http.DELETE`), `reason` (`token_expired`, `lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, `lease_other`) | Records not written because the first record of the same delegation chain, tool and reason within 60 s stands for them: listen-stream ends (`stream.end`, all six series always present) and lease refusals of requests without a per-call decision (a series appears once counted). Tool-call decisions, refused exchanges and renewals are never suppressed. |
| `run_lock_wait_seconds` | histogram | none | Time a decision waited for its run's lock (SR-55), from 1 us to 1 s, five buckets per decade. Only decisions on a hop with run limits or on a tool that keeps run usage take it, so `run_lock_wait_seconds_count` is the number of guarded decisions. |

The `audit_wal_*` series appear only when the background WAL checkpointer runs (a file-backed store with `[audit] wal_checkpoint_seconds` above 0, the default). Soft limits (a policy over `context.usage` or `context.budget` that asks for an approval) are not told apart from other `approval_required` decisions: the reason is the same and the deciding policy ids are not labels.
