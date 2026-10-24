# Configuration keys

The server reads one TOML file: `attenuo-server --config <file>` or `ATTENUO_CONFIG=<file>`. Unknown keys are rejected at start-up. Relative paths resolve against the working directory.

The annotated source of truth is [config/example.toml](https://github.com/attenuo-dev/attenuo/blob/main/config/example.toml). Never use its example admin token or agent secret for anything real. [Deploying](../guides/deploying.md) covers what to change before you expose a server.

## `[server]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:8080` | Address to bind. |
| `public_url` | none | Externally visible base URL (`https://attenuo.example.com`), the only source of the URLs in `/.well-known/authzen-configuration`. **Required** when `listen` is not a loopback address: the server refuses to start without it. On loopback it may be left out; discovery then uses `http://<Host>` and answers 400 `invalid_host` unless `Host` is `localhost`, `127.0.0.1` or `[::1]` (with an optional port). Must be `http(s)://host[:port][/path]`, without query or fragment. |

The names reserved for the server's own audit records are refused at start: `attenuo` as a server name (`[[upstreams]]`, the catalog, `[[root_grants]]` capabilities) and as an agent id (`[[agents]]`, `[[peps]]`, `[[root_grants]] agent`). User subjects starting with `urn:attenuo:` are refused at IdP intake and by the dev root mint; admin actions are audited as `urn:attenuo:admin`.

## `[issuer]`

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | `http://127.0.0.1:8080` | The `iss` of tokens. Also the `aud` an ID-JAG must carry. |
| `audience` | `attenuo` | The `aud` of issued tokens. |
| `max_depth` | library default | Longest allowed delegation chain. The example sets 8. |
| `default_ttl_seconds` | `900` | Token lifetime when the exchange does not ask for one. |
| `lease_interval_seconds` | `300` | How long a lease lives after issuance or renewal. Must be positive. |
| `private_key_pem_path` | ephemeral key | Ed25519 PKCS#8 key. Created with mode 0600 on first start if missing. |
| `previous_key_paths` | none | Retired keys (PEM) that stay trusted for verification and in the JWKS. They never sign. |

## `[policy]`

| Key | Default | Meaning |
| --- | --- | --- |
| `policies_path` | none | Cedar policy file. `POST /admin/policies/reload` re-reads it. |
| `catalog_path` | none | JSON tool catalog. Can be combined with `[policy.catalog]`. |
| `user_attributes` | none | Extra `originating_user.attributes` for the Cedar schema, as `{ name = "type" }`. Types: `string`, `long`, `bool`, `set<string>`. A value of another type is denied with `attribute_type_mismatch`. |
| `unknown_tools` | `"deny"` | A call to a `(server, tool)` pair missing from the catalog: `"deny"` (reason `tool_not_in_catalog`), `"sensitive"` (evaluated with `resource.sensitive = true`) or `"allow"` (default attributes). |
| `import_annotations` | `"never"` | What MCP tool annotations from `tools/list` may change in the catalog: `"never"`, or `"narrowing"`, where an explicit `readOnlyHint: false` clears `readonly` and `destructiveHint: true` sets `destructive` for a catalog tool. Nothing an annotation says makes a tool less restricted, and tools missing from the catalog are not affected. |
| `track_usage` | `"auto"` | Whether run usage (`context.usage`, [run limits](../design/run-limits.md#usage-kept-only-when-something-can-read-it-2026-10-24)) is kept for calls to destructive tools. `"auto"` keeps it only when some loaded policy reads `context.usage` or some catalog entry names `amount` or `destination`, and decides again on every policy reload; otherwise allowed destructive calls make no usage write and their records carry no `usage`. `true` always keeps it, for example to watch the counters before writing a policy over them. `false` is refused: usage a policy reads is always kept. |
| `legacy_bare_actions` | `false` | **Deprecated.** Evaluate with the pre-2026-10-23 action ids, `Action::"<tool>"`, instead of `Action::"<server>/<tool>"`. A bare action matches that tool on every server (SR-13). Logged as a warning at start; `attenuo policy lint` lists bare actions. |

The built-in user attributes `mfa` (bool), `roles` (set of string), `tenant` and `email` are always declared.

### `[policy.catalog.<server>.<tool>]`

| Key | Meaning |
| --- | --- |
| `readonly` | Boolean. Tests as `resource.readonly` in policies. |
| `sensitive` | Boolean. Tests as `resource.sensitive` in policies. |
| `destructive` | Boolean, default `true` unless `readonly = true`. Tests as `resource.destructive` in policies. |
| `output` | `"untrusted"` (default) or `"trusted"`. A result of an untrusted tool taints the delegation run (`context.session.tainted`); a trusted tool's result is recorded but taints nothing. |
| `inputs` | Table of argument name to type. Used to validate `context.input.*`. |
| `amount` | Name of the input whose value run usage sums for this tool, as `context.usage.amount` ([run limits](../design/run-limits.md#35-policy)). Only destructive tools keep usage, and naming `amount` or `destination` on any tool makes the server keep it (see `track_usage`). A value that is not a non-negative integer adds 0. If `inputs` declares it, it must be `long`. |
| `destination` | Name of the input that says where the call goes (payee, recipient), for `context.usage.destination_seen`. A list counts each element. Only keyed hashes of the values are stored, per run. `"<input>#host"` (for example `destination = "url#host"`) counts the host of a URL input instead of the whole value, so pages of one site are one destination; a value with no host counts as itself (wrapped as `{"raw": value}`, so it never equals a host), so each different unparseable value is a new destination. A `#` followed by anything but `host` is refused at load. |

Every action a policy names must be in the catalog: the table `[policy.catalog.github.read_file]` declares `Action::"github/read_file"`.

Server and tool names follow one rule everywhere (catalog, `[[upstreams]]`, capabilities, `tools/call`): 1 to 128 ASCII letters, digits, `_`, `.` or `-`, compared case-sensitively and never normalized. A tool key may also be an MCP method name made of such segments joined by `/` (`"resources/read"`), which is how the proxy authorizes methods other than `tools/call`. The server refuses to start with a catalog or grant that breaks the rule.

## `[audit]`

| Key | Default | Meaning |
| --- | --- | --- |
| `sqlite_path` | none | Audit log and lease registry. `:memory:` keeps both in memory and loses them on exit. |
| `checkpoint_every` | 1000 | Sign a checkpoint every this many entries. 0 turns the count trigger off. |
| `checkpoint_interval_seconds` | 300 | Also sign one this often, if entries arrived since the last. 0 turns the timer off. Whichever trigger fires first writes the checkpoint. |
| `durability` | `"normal"` | `"normal"` or `"full"`: SQLite `synchronous` for a file-backed store, which always runs in WAL mode. `normal` does not sync on commit; `full` syncs every commit. Lease revocations always sync. Ignored for `:memory:`. See below. |
| `wal_checkpoint_seconds` | 5 | How often a background thread copies SQLite's write-ahead log into the database file (`PRAGMA wal_checkpoint(PASSIVE)`), so audit appends do not wait while a checkpoint copies and syncs. It also runs after every 256 commits, keeps the WAL from growing under continuous load with a short catch-up pass (appends pause for it) once the WAL passes 64 MB, truncates the WAL when no append is in progress, and runs once more at shutdown. 0 leaves checkpoints to SQLite on the writer (every 1,000 pages). Not the signed checkpoints above. Ignored for `:memory:`. |

**Durability.** With `"normal"` a decision that was answered survives the server process crashing or being killed, because the commit is in the operating system's page cache. If the machine loses power or the kernel crashes before SQLite's next sync (at a WAL checkpoint, normally no more than `wal_checkpoint_seconds` or 256 commits apart), the newest decisions can be lost. What survives is always a prefix of the log: an entry is never half-written, the database is never corrupt, and `audit verify` still passes, with the head at an earlier `seq`. A signed checkpoint you shipped off the host for a lost entry will then show the truncation, as it should. Lease revocations are always committed with `synchronous=FULL`, so a revoked lease cannot come back after a power failure; lease registrations and renewals follow the setting. Choose `"full"` when losing the last moments of the record on power failure is not acceptable; it costs one `fsync` per audit commit (see [performance](../design/performance.md)).

Checkpoints are signed with the issuer key and verified against the JWKS; see [Audit log](../concepts/audit-log.md#signed-checkpoints).

### `[audit.sink]`

Ships every signed checkpoint off the host as it is created (SR-21); see [Shipping checkpoints off the host](../concepts/audit-log.md#shipping-checkpoints-off-the-host). Unset by default. Only the keys of the chosen `kind` may be set; a missing required key fails startup.

| Key | Default | Meaning |
| --- | --- | --- |
| `kind` | required | `"webhook"`, `"file"` or `"s3"`. |
| `url` | required for webhook | URL to `POST` each checkpoint to (`http://` or `https://`). Any 2xx is success; redirects are not followed. |
| `bearer_token` | `ATTENUO_AUDIT_SINK_TOKEN` | webhook: sent as `Authorization: Bearer <token>`. |
| `path` | required for file | JSON Lines file to append to; created if missing, synced after each line. Put it on another mount than `sqlite_path` (a warning at startup otherwise). |
| `endpoint` | required for s3 | Base URL without a path, e.g. `https://s3.eu-west-1.amazonaws.com` or `http://minio:9000`. Requests are path-style. |
| `bucket` | required for s3 | Bucket name. |
| `region` | `us-east-1` | s3: SigV4 signing region. |
| `prefix` | `attenuo/checkpoints/` | s3: object key prefix; keys are `<prefix><seq, 20 digits>-<16 hex of checkpoint_sha256>.json`. |
| `access_key_id`, `secret_access_key`, `session_token` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | s3 credentials. Give them `PutObject` only. |
| `queue_capacity` | 1024 | Checkpoints waiting for delivery, at most. When full, the oldest queued one is dropped and `attenuo_audit_sink_dropped_total` counts it. |
| `max_lag_seconds` | 300 | `/readyz` reports the sink degraded once the oldest undelivered checkpoint is older than this, or the queue is full. |
| `fail_readiness` | `false` | Make a degraded sink fail `/readyz` (503). Off by default: the server keeps serving and reports `"degraded": true`. |
| `timeout_seconds` | 10 | Per-request timeout (webhook, s3). |
| `initial_backoff_ms` | 500 | First retry delay; doubles per attempt up to `max_backoff_seconds`, each wait drawn between half and all of it. Failed deliveries are retried until they succeed. |
| `max_backoff_seconds` | 60 | Longest retry delay. |

## `[authzen]`

| Key | Default | Meaning |
| --- | --- | --- |
| `allow_unsigned_chain` | `false` | Accept `subject.properties.chain` without a bearer token from an authenticated `[[peps]]` entry. Every hop must match what the server issued. |
| `max_batch` | 64 | Most evaluations one `POST /access/v1/evaluations` may carry. More is refused with 400 `batch_too_large` before anything is decided or audited. Must be at least 1. |
| `diagnostics` | `"peps"` | Who gets `context.diagnostics` (the effective capabilities a call fell outside, lease ids, Cedar errors): `"peps"` only callers that authenticated as a `[[peps]]` entry (with a bearer token, by `pep_id` and `pep_secret` in the body), `"always"` every caller, `"never"` nobody. Others get an empty list; `reason`, `policy_ids` and `decision_id` are always returned. |

## `[token]`

How the caller of an exchange (hop n to n+1) proves it is the `actor` it names.

| Key | Default | Meaning |
| --- | --- | --- |
| `require_actor_auth` | `true` | The actor must authenticate with a method `actor_auth` accepts. When `false`, `actor` is asserted (the server warns at start-up), but credentials that are sent are still checked. |
| `actor_auth` | `"either"` | `"secret"`: `[[agents]]` client credentials only; an `actor_token` is refused with `actor_token_not_accepted`. `"actor_token"`: an `actor_token` from an `[[actor_trust]]` issuer only; client credentials are refused with `client_auth_not_accepted`, and the server will not start without an `[[actor_trust]]` entry. `"either"`: both are accepted, and when both are sent both are checked. |

It also sets sender-constrained tokens (DPoP, RFC 9449; see [Binding tokens to keys](../guides/binding-tokens-to-keys.md)):

| Key | Default | Meaning |
| --- | --- | --- |
| `dpop` | `"optional"` | `"off"`: new tokens are never bound (a proof on `/token` is ignored). `"optional"`: a request to `/token` or `/admin/root-token` with a `DPoP` proof gets a token bound to its key. `"required"`: every issuance needs a proof, and unbound tokens are refused wherever a token is presented (`dpop_required`). In every mode, a token that is already bound needs a proof by its key. |
| `dpop_max_age_seconds` | 300 | How far a proof's `iat` may be from the server's clock, either way. 1 to 3600. Proof `jti`s are remembered for this long. |
| `dpop_replay_capacity` | 1000000 | Most proof `jti`s kept in memory. When full, new proofs are refused with 503 `dpop_replay_cache_full` until old ones age out. At least 1. |
| `dpop_nonce` | `"off"` | Server-provided nonces (RFC 9449 §8). `"off"`: a proof's `nonce` claim is ignored. `"required"`: every response to a request with a `DPoP` header, and every `WWW-Authenticate: DPoP` challenge, carries a `DPoP-Nonce` header, and every `DPoP` header proof must carry a current nonce, or the request is refused with 401 `use_dpop_nonce`. Nonces are stateless (an HMAC of a `dpop_max_age_seconds`-wide time bucket, keyed from the issuer's signing key) and live one to two buckets. The exchange sign-off needs none. |

## `[approvals]`

Approvals of calls a policy gates with `@obligation("approval")` (see [Writing policies](../guides/writing-policies.md#asking-for-approval-after-untrusted-output)).

| Key | Default | Meaning |
| --- | --- | --- |
| `ttl_seconds` | 120 | How long a pending or granted approval stays usable. It also ends with the calling hop's token or lease, whichever comes first. 1 to 86400. The default is the one in the output-labelling design, section 3.7. |
| `client_id` | none | The `aud` an ID token must carry to decide at `POST /approvals/{id}`. Unset, it is the client id hop-0 intake expects for the run's root agent. Set it to a client the agent does not control, such as the approval page's own OAuth client, so that an ID token the agent can get for itself cannot approve its calls. When a loaded policy carries `@obligation("approval")` and this is unset, the server logs a warning at startup and after every policy reload, and refuses to start when `[server] listen` is not a loopback address (SR-64), unless `allow_unset_client_id` is set. |
| `allow_unset_client_id` | false | Start with `client_id` unset off loopback although a loaded policy asks for approvals. The default refuses, because an agent that can get ID tokens for its user (silent re-authentication, a refresh token with `openid`) could then approve its own gated calls, and the audit record would show `by: user`. Set it only where the agent cannot obtain ID tokens for the user by itself; the warning is still logged. |

## `[[actor_trust]]`

Issuers of workload identities whose JWTs are accepted as the RFC 8693 `actor_token` of an exchange. Give each entry exactly one key source: `jwks_url` (with `issuer`), or `spiffe_trust_domain` with `spiffe_bundle_url`. Neither is discovered. Hop 0 (IdP intake) still authenticates the agent with `[[agents]]` client credentials.

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | | Exact `iss` the token must carry. Required with `jwks_url`. Optional with `spiffe_trust_domain`, because JWT-SVIDs often have no `iss`; when set, it is required and checked. |
| `jwks_url` | | JWKS of a generic JWT issuer. |
| `spiffe_trust_domain` | | SPIFFE trust domain, for example `example.org`. The token's `sub` must be a SPIFFE ID in it. |
| `spiffe_bundle_url` | | The trust domain's bundle endpoint (SPIRE server `federation.bundle_endpoint`). It serves a JWKS; keys with `use` = `jwt-svid` verify JWT-SVIDs, `x509-svid` keys are ignored. |
| `audience` | | The `aud` the token must carry, as a string or in an array. Use a value no other service accepts, such as the attenuo server's URL. |
| `subject_to_agent` | `"sub"` | How `sub` becomes an agent id. `"sub"`: `sub` itself (a whole SPIFFE ID). `"spiffe_path"`: the SPIFFE ID's path without the leading `/` (`spiffe://example.org/agents/coder` is `agents/coder`); needs `spiffe_trust_domain`. A table `{ "<sub>" = "<agent id>" }`: only listed subjects are accepted. The result must equal the exchange's `actor`. |
| `allowed_algs` | `RS256`, `ES256`, `EdDSA` | Accepted signature algorithms. HMAC is refused. |
| `jwks_ttl_seconds` | `300` | How long a fetched key set is used. An unknown `kid` triggers one refetch, at most every 30 seconds. |
| `clock_skew_seconds` | `60` | Leeway for `exp`, `nbf` and `iat`. |

An actor token authenticates one exchange: its `jti` (or, without one, its signed content) goes through the replay cache until `exp`. The child token never outlives the actor token's `exp`.

## `[[upstreams]]`

One table per MCP server, using streamable HTTP.

| Key | Meaning |
| --- | --- |
| `name` | Mount name, served at `/mcp/<name>`. It is the `server` part of capabilities and of action ids. ASCII letters, digits, `_`, `.`, `-`; `attenuo` is reserved. |
| `url` | Upstream MCP endpoint. |

## `[admin]`

| Key | Meaning |
| --- | --- |
| `token` | Static bearer for `/admin/*`. With no token configured, admin routes answer 403 `admin_disabled`. Do not expose `/admin` publicly. |

## `[[idps]]`

Trusted identity providers for hop 0. Only these issuers are accepted at `POST /token`.

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | | The IdP issuer URL. |
| `client_ids` | `{}` | Table of agent id to the client id registered for it at the IdP. An ID token must have that value in `aud` (and in `azp` when `aud` has several values or `azp` is present), or it is refused with `credential_audience_mismatch`. An agent with no entry must have a client id equal to its agent id; the server logs a warning at startup for each such agent. |
| `audience` | | Deprecated and ignored for ID tokens. Parsed so old configs load; a warning is logged when set. |
| `jwks_url` | discovery | JWKS location. Otherwise `jwks_uri` from `<issuer>/.well-known/openid-configuration`. |
| `allowed_algs` | `RS256`, `ES256`, `EdDSA` | Accepted signature algorithms. HMAC is refused. |
| `attribute_claims` | `email`, `groups`, `amr` | Claims copied into `originating_user.attributes`. `mfa` is always derived from `amr`. |
| `jwks_ttl_seconds` | `300` | How long a fetched key set is used. |
| `clock_skew_seconds` | `60` | Leeway for `exp`, `iat` and `nbf`. |

## `[[agents]]`

Agents (OAuth clients) that may present user credentials at `POST /token`. With none configured, all IdP intake is rejected.

| Key | Meaning |
| --- | --- |
| `id` | Client id. Must match the `actor` if one is sent. |
| `secret_sha256` | SHA-256 of the client secret, in hex. Make it with `printf %s "$SECRET" \| sha256sum`. |

## `[[root_grants]]`

The most a root token may carry.

| Key | Meaning |
| --- | --- |
| `issuer` | Issuer of the users this applies to. |
| `agent` | The agent that holds the root token. |
| `subject` | Optional. Pins the entry to one user. A pinned entry wins over an unpinned one. |
| `capabilities` | List of `server:tool` strings. Requests are attenuated against this. |
| `attributes` | Used only by the development root mint. IdP intake takes attributes from the verified token. |
| `may_act` | Optional list of agent ids: the RFC 8693 `may_act` of root tokens minted under this grant, so only these agents may exchange them. A request may narrow it with its own `may_act`, never widen it (`may_act_exceeds_grant`). |

With no matching entry, no root token is issued.

## `[proxy]`

| Key | Default | Meaning |
| --- | --- | --- |
| `stream_recheck_seconds` | `2` | How often a long-lived response stream (the `GET` listen stream, or a `POST` answered over SSE) is re-checked against lease state and token expiry. At the first failure the stream ends, after a final SSE event with JSON-RPC error `-32001` and `data.reason` (`lease_revoked`, `token_expired`, ...). At least 1. |
| `require_listed_tools` | `true` | Deny (`-32003`, reason `tool_not_listed`, audited) a `tools/call` whose exact name the upstream never returned from `tools/list` and the catalog does not know. Stops an upstream that resolves names case-insensitively from running `delete_repo` for `Delete_Repo` (SR-25). A `tools/call` name outside the name rule is always denied with `invalid_name`. |
| `max_upstream_body_bytes` | `16777216` (16 MiB) | Largest upstream body the proxy buffers: a JSON response it filters or merges replies into, or one SSE event. Over it: `502`, JSON-RPC `-32005`, reason `upstream_body_too_large` (an SSE stream ends instead). At least 1. |
| `max_request_body_bytes` | `4194304` (4 MiB) | Largest client request body, read after authentication. Over it: `413`, reason `request_too_large`. At least 1. |
| `session_ttl_seconds` | `3600` | Idle lifetime of an `Mcp-Session-Id` binding. At least 1. |
| `max_sessions` | `100000` | Most live session bindings. Expired ones are reclaimed as new ones arrive; when every slot is live, the response that would bind a new session is replaced by `503`, JSON-RPC `-32006`, reason `session_registry_full`, `Retry-After: 30`. Live bindings are never evicted (SR-36). At least 1. |
| `max_sessions_per_principal` | `64` | Most live session bindings one principal holds. The principal is the chain's root lease: one user's root grant, shared by every agent it delegates to. Only live bindings count (expired ones are reclaimed first; a `DELETE` frees one). One more gets `429`, JSON-RPC `-32007`, reason `too_many_sessions`, `Retry-After: 30`, while other principals keep opening sessions (SR-49). When the proxy refuses a session for this reason or for `max_sessions`, it sends the upstream an MCP `DELETE` for the session the upstream just created (best effort, logged on failure). At least 1. |

## `[dev]`

| Key | Default | Meaning |
| --- | --- | --- |
| `allow_root_mint` | `false` | Mounts `POST /admin/root-token`, which mints root tokens for a user nobody verified. Development only. The server logs a warning when it is on. |

## `[metrics]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Serve Prometheus text on a separate listener. |
| `listen` | `127.0.0.1:9100` | Address of the metrics listener. No authentication, so keep it on loopback or a private network. |
| `allow_public` | `false` | Without it, the server refuses to start when `enabled` and `listen` is not a loopback address. With it, the server starts and logs a warning. |

## `[admin_ui]`

The admin console, on its own opt-in listener so it never shares an origin with `/mcp/{server}`. It serves the embedded console under `/admin/ui/` (`/` redirects there) and the admin API under `/admin/*`, behind the same `[admin] token`. Every response carries a strict `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and same-origin `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy`; API answers also carry `Cache-Control: no-store`. No CORS headers are ever sent. `POST /admin/root-token` is never mounted here, whatever `[dev]` says.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Start the console listener. Without the section there is no console. |
| `listen` | `127.0.0.1:9101` | Address of the console listener. Keep it on loopback and reach it over an SSH tunnel. |
| `allow_public` | `false` | Without it, the server refuses to start when `enabled` and `listen` is not a loopback address. With it, the server starts and logs a warning, and `[admin] token` must then pass the strength check that a public `[server] listen` needs. |
| `allow_write` | `false` | Also mount `POST /admin/leases/{id}/revoke` and `POST /admin/policies/reload` on the console listener; they require `Content-Type: application/json` there (415 otherwise). Without it those paths are 404 on this listener, so the console is read-only by the server's rule. The read routes, always mounted, are `GET /admin/audit`, `/admin/audit/entries/{seq}`, `/admin/audit/records/{id}`, `/admin/audit/checkpoints`, `/admin/audit/verify`, `/admin/audit/checkpoint` (which signs a checkpoint of the head when it has none) and `/admin/audit/export`; `GET /admin/leases/{id}` and `/admin/leases/{id}/tree`; `GET /admin/policies` and `/admin/policies/check`; and the `POST /admin/policies/evaluate` dry run (JSON `Content-Type` required). The main listener keeps every admin route either way. See [the admin console guide](../guides/admin-console.md). |
