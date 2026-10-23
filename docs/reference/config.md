# Configuration keys

The server reads one TOML file: `onbehalf-server --config <file>` or `ONBEHALF_CONFIG=<file>`. Unknown keys are rejected at start-up. Relative paths resolve against the working directory.

The annotated source of truth is [config/example.toml](https://github.com/7Mudit/onbehalf/blob/main/config/example.toml). Never use its example admin token or agent secret for anything real. [Deploying](../guides/deploying.md) covers what to change before you expose a server.

## `[server]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:8080` | Address to bind. |
| `public_url` | from the `Host` header | Externally visible base URL, used in `/.well-known/authzen-configuration`. |

## `[issuer]`

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | `http://127.0.0.1:8080` | The `iss` of tokens. Also the `aud` an ID-JAG must carry. |
| `audience` | `onbehalf` | The `aud` of issued tokens. |
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
| `legacy_bare_actions` | `false` | **Deprecated.** Evaluate with the pre-2026-10-23 action ids, `Action::"<tool>"`, instead of `Action::"<server>/<tool>"`. A bare action matches that tool on every server (SR-13). Logged as a warning at start; `onbehalf policy lint` lists bare actions. |

The built-in user attributes `mfa` (bool), `roles` (set of string), `tenant` and `email` are always declared.

### `[policy.catalog.<server>.<tool>]`

| Key | Meaning |
| --- | --- |
| `readonly` | Boolean. Tests as `resource.readonly` in policies. |
| `sensitive` | Boolean. Tests as `resource.sensitive` in policies. |
| `inputs` | Table of argument name to type. Used to validate `context.input.*`. |

Every action a policy names must be in the catalog: the table `[policy.catalog.github.read_file]` declares `Action::"github/read_file"`.

Server and tool names follow one rule everywhere (catalog, `[[upstreams]]`, capabilities, `tools/call`): 1 to 128 ASCII letters, digits, `_`, `.` or `-`, compared case-sensitively and never normalized. A tool key may also be an MCP method name made of such segments joined by `/` (`"resources/read"`), which is how the proxy authorizes methods other than `tools/call`. The server refuses to start with a catalog or grant that breaks the rule.

## `[audit]`

| Key | Default | Meaning |
| --- | --- | --- |
| `sqlite_path` | none | Audit log and lease registry. `:memory:` keeps both in memory and loses them on exit. |
| `checkpoint_every` | 1000 | Sign a checkpoint every this many entries. 0 turns the count trigger off. |
| `checkpoint_interval_seconds` | 300 | Also sign one this often, if entries arrived since the last. 0 turns the timer off. Whichever trigger fires first writes the checkpoint. |
| `durability` | `"normal"` | `"normal"` or `"full"`: SQLite `synchronous` for a file-backed store, which always runs in WAL mode. `normal` does not sync on commit; `full` syncs every commit. Lease revocations always sync. Ignored for `:memory:`. See below. |

**Durability.** With `"normal"` a decision that was answered survives the server process crashing or being killed, because the commit is in the operating system's page cache. If the machine loses power or the kernel crashes before SQLite's next sync (at a WAL checkpoint), the newest decisions can be lost. What survives is always a prefix of the log: an entry is never half-written, the database is never corrupt, and `audit verify` still passes, with the head at an earlier `seq`. A signed checkpoint you shipped off the host for a lost entry will then show the truncation, as it should. Lease revocations are always committed with `synchronous=FULL`, so a revoked lease cannot come back after a power failure; lease registrations and renewals follow the setting. Choose `"full"` when losing the last moments of the record on power failure is not acceptable; it costs one `fsync` per audit commit (see [performance](../design/performance.md)).

Checkpoints are signed with the issuer key and verified against the JWKS; see [Audit log](../concepts/audit-log.md#signed-checkpoints).

## `[authzen]`

| Key | Default | Meaning |
| --- | --- | --- |
| `allow_unsigned_chain` | `false` | Accept `subject.properties.chain` without a bearer token from an authenticated `[[peps]]` entry. Every hop must match what the server issued. |
| `max_batch` | 64 | Most evaluations one `POST /access/v1/evaluations` may carry. More is refused with 400 `batch_too_large` before anything is decided or audited. Must be at least 1. |

## `[token]`

How the caller of an exchange (hop n to n+1) proves it is the `actor` it names.

| Key | Default | Meaning |
| --- | --- | --- |
| `require_actor_auth` | `true` | The actor must authenticate with a method `actor_auth` accepts. When `false`, `actor` is asserted (the server warns at start-up), but credentials that are sent are still checked. |
| `actor_auth` | `"either"` | `"secret"`: `[[agents]]` client credentials only; an `actor_token` is refused with `actor_token_not_accepted`. `"actor_token"`: an `actor_token` from an `[[actor_trust]]` issuer only; client credentials are refused with `client_auth_not_accepted`, and the server will not start without an `[[actor_trust]]` entry. `"either"`: both are accepted, and when both are sent both are checked. |

## `[[actor_trust]]`

Issuers of workload identities whose JWTs are accepted as the RFC 8693 `actor_token` of an exchange. Give each entry exactly one key source: `jwks_url` (with `issuer`), or `spiffe_trust_domain` with `spiffe_bundle_url`. Neither is discovered. Hop 0 (IdP intake) still authenticates the agent with `[[agents]]` client credentials.

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | | Exact `iss` the token must carry. Required with `jwks_url`. Optional with `spiffe_trust_domain`, because JWT-SVIDs often have no `iss`; when set, it is required and checked. |
| `jwks_url` | | JWKS of a generic JWT issuer. |
| `spiffe_trust_domain` | | SPIFFE trust domain, for example `example.org`. The token's `sub` must be a SPIFFE ID in it. |
| `spiffe_bundle_url` | | The trust domain's bundle endpoint (SPIRE server `federation.bundle_endpoint`). It serves a JWKS; keys with `use` = `jwt-svid` verify JWT-SVIDs, `x509-svid` keys are ignored. |
| `audience` | | The `aud` the token must carry, as a string or in an array. Use a value no other service accepts, such as the onbehalf server's URL. |
| `subject_to_agent` | `"sub"` | How `sub` becomes an agent id. `"sub"`: `sub` itself (a whole SPIFFE ID). `"spiffe_path"`: the SPIFFE ID's path without the leading `/` (`spiffe://example.org/agents/coder` is `agents/coder`); needs `spiffe_trust_domain`. A table `{ "<sub>" = "<agent id>" }`: only listed subjects are accepted. The result must equal the exchange's `actor`. |
| `allowed_algs` | `RS256`, `ES256`, `EdDSA` | Accepted signature algorithms. HMAC is refused. |
| `jwks_ttl_seconds` | `300` | How long a fetched key set is used. An unknown `kid` triggers one refetch, at most every 30 seconds. |
| `clock_skew_seconds` | `60` | Leeway for `exp`, `nbf` and `iat`. |

An actor token authenticates one exchange: its `jti` (or, without one, its signed content) goes through the replay cache until `exp`. The child token never outlives the actor token's `exp`.

## `[[upstreams]]`

One table per MCP server, using streamable HTTP.

| Key | Meaning |
| --- | --- |
| `name` | Mount name, served at `/mcp/<name>`. It is the `server` part of capabilities and of action ids. ASCII letters, digits, `_`, `.`, `-`; `onbehalf` is reserved. |
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
