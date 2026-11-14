# HTTP endpoints

All routes the server mounts, from the route table in `crates/attenuo-server/src/lib.rs` and the proxy router. What may change before 1.0, and how a change is announced, is in [API compatibility](api-compatibility.md). Errors on non-MCP routes look like `{"error": "<error>", "code": "<code>", "detail": "<text>"}`; every error carries a stable `code`, listed under [Errors](#errors). The codes for `/token` are explained in [design/server.md](../design/server.md#error-codes).

A 401 for a bearer token (`/token/renew`, AuthZEN, `/admin/*`) is `{"error": "unauthorized", "code": "<reason>", "detail": "<reason>", "error_description": "<reason>"}`, where the reason is one of `missing_token`, `invalid_token` or `token_expired`. Why a token did not verify (wrong key, audience, issuer, malformed) is logged at debug level and never returned. A token bound to a key (DPoP, below) adds `dpop_required` and `invalid_dpop_proof`. The same goes for a JWKS the server cannot fetch (503 `temporarily_unavailable`, sub-code `jwks_unavailable`): the URL and the transport error are logged, not returned. A hop-0 credential (ID token or ID-JAG) refused at `POST /token` is `400 invalid_grant` with the sub-code (`audience_mismatch`, `unknown_kid`, ...) as both `detail` and `error_description`; the verifier's message, which names the issuer, the audience or the `kid`, is logged at debug level. A refused `actor_token` is answered the same way, as `400 invalid_request` with its `actor_token_...` sub-code in both fields.

A request the server cannot read is refused in the same shape on every non-MCP route, the console listener included: a query parameter that does not parse (`?from=abc`, `?preview=maybe`) or a path parameter that does not parse or is not UTF-8 once percent-decoded (`/admin/audit/entries/abc`) is 400 `invalid_request`, and a body that is not JSON is 400 `invalid_request`. A body over 2 MiB is 413 `request_too_large`. `detail` names the parameter and the expected type (`the path parameter `seq` is not a valid u64`) and never repeats the value sent. The main listener reads a JSON body whatever its `Content-Type`; only `POST /token` uses it, to choose between a form and JSON. The console listener requires `Content-Type: application/json` on a `POST` (415 `unsupported_media_type` otherwise). At the MCP proxy a server name that is not UTF-8 (`/mcp/%FF`) is HTTP 400 with JSON-RPC `-32600` and `id: null`.

An HTTP/1 answer sent before the request body was read to its end carries `Connection: close`, and the server closes the connection after it. Most refusals are decided on the headers alone: a missing or bad token on `/mcp/{server}` (401, `use_dpop_nonce` included), a declared body over `[proxy] max_request_body_bytes` (413), and a missing admin bearer (401). A client sends its retry on a new connection. Answers to requests whose body was read, and to requests with no body, keep the connection open. HTTP/2 answers never carry the header.

## Errors

Every error the server or its proxy sends carries a stable `code`: snake_case ASCII, documented below, and never reworded, so a client may match on it. The texts (`detail`, `message`) are for people and may change in any release. A code that a later release stops sending is announced as described in [API compatibility](api-compatibility.md). There are three shapes, one per kind of route:

- **REST** (every route except `/mcp/{server}`, the AuthZEN routes and the console listener included). `error` is the OAuth-style error (RFC 6749 §5.2, RFC 6750 §3.1) and stays as it was; `code` is the precise code: the specific reason of the refusal, which is `error_description` when the answer has one, and otherwise either a reason with no `error_description` (a refused renewal's `lease_revoked`, for example) or, when no more specific reason exists, `error` itself:

  ```json
  {"error": "invalid_grant", "code": "audience_mismatch", "detail": "audience_mismatch", "error_description": "audience_mismatch"}
  ```

  ```json
  {"error": "invalid_grant", "code": "lease_revoked", "detail": "lease_revoked", "decision_id": "10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223"}
  ```

  ```json
  {"error": "invalid_request", "code": "invalid_request", "detail": "the query parameter `limit` is not a valid u32"}
  ```

- **JSON-RPC** (the MCP proxy at `/mcp/{server}`). The number in `error.code` is the JSON-RPC error code; the stable code is `data.code`. Where `data.reason` is present it is the same string, and it stays:

  ```json
  {"jsonrpc": "2.0", "id": 7, "error": {"code": -32003, "message": "attenuo: denied: policy_deny", "data": {"code": "policy_deny", "reason": "policy_deny", "decision_id": "10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223"}}}
  ```

  An error the upstream sent is relayed unchanged and has no `data.code` from the proxy; an upstream error in the shape of the proxy's stream end is rewritten to `upstream_stream_end_shape` (see [MCP proxy](#mcp-proxy)).

- **AuthZEN** (`/access/v1/evaluation`, `/access/v1/evaluations`, `/access/v1/search/action`). A request the PDP refuses as a whole (no token, a malformed body, a batch too large, a search page token it did not issue) is answered in the REST shape. A batch entry that fails is a deny whose `context.error` carries `status`, `code` and `message`:

  ```json
  {"decision": false, "context": {"error": {"status": 400, "code": "invalid_request", "message": "each evaluation must be an object"}}}
  ```

  A decision is not an error: a denied evaluation is `{"decision": false, "context": {"reason": "policy_deny", ...}}`, with no `code`.

**`code` and `reason`.** A deny of the decision pipeline has a `reason` (in the audit record, in AuthZEN `context.reason`, in the proxy's `data.reason`). Every deny reason that reaches the wire is in the table below, marked in the "Deny `reason`" column, and the proxy's `data.code` for such a denial is the same string as `data.reason`. Reasons of allowed decisions (`policy_allow`, `capability_allow`) and of other audit records (`token_issued`, `lease_renewed`, `approval_granted`, ...) are not error codes. The audit reasons of refused exchanges (`exchange_widening`, `exchange_replayed`, ...) are audit-only; the 400 that answers the exchange carries the code in its own column of the table under [Token](#token).

**Deprecated machine fields.** Before `code` existed, the precise code was read from `error_description` and, on a 401 and a refused hop-0 credential or `actor_token`, from `detail`. Both still carry it, and keep it at least until the next minor release (see [API compatibility](api-compatibility.md)), but RFC 6749 means `error_description` for people, so read `code` instead. The CLI, the SDKs and the console read `code`, falling back to the old fields for a server that does not send it.

The table is generated from `attenuo_core::error_codes::ERROR_CODES`, the one place the server keeps every code with its HTTP status, its `error` member and its JSON-RPC number; a test fails when this page, or a code named in the sources, differs from it. "REST status" lists each status the code is sent with, and the `error` member when it is not the code itself. "JSON-RPC" lists the number and the HTTP status of the answer that carries it (200 for an error inside a JSON-RPC response or an SSE event).

<!-- error-codes:start (generated from attenuo_core::error_codes; see crates/attenuo-server/tests/error_codes.rs) -->
| `code` | REST status (`error`) | JSON-RPC (HTTP status) | Deny `reason` | Meaning |
| --- | --- | --- | --- | --- |
| `actor_mismatch` | 400 `invalid_request` |  |  | The authenticated agent or actor token is not the request's `actor`. |
| `actor_not_permitted` | 400 `invalid_request` |  |  | The actor is not in the parent token's `may_act`. |
| `actor_token_audience_mismatch` | 400 `invalid_request` |  |  | The actor token's audience is not this server. |
| `actor_token_bad_signature` | 400 `invalid_request` |  |  | The actor token's signature does not verify. |
| `actor_token_expired` | 400 `invalid_request` |  |  | The actor token has expired, or expires now. |
| `actor_token_invalid_spiffe_id` | 400 `invalid_request` |  |  | The actor token's subject is not a valid SPIFFE id. |
| `actor_token_malformed` | 400 `invalid_request` |  |  | The actor token is not a well-formed JWT. |
| `actor_token_missing_claim` | 400 `invalid_request` |  |  | The actor token lacks a required claim. |
| `actor_token_missing_kid` | 400 `invalid_request` |  |  | The actor token names no `kid`. |
| `actor_token_not_accepted` | 400 `invalid_request` |  |  | `[token] actor_auth` does not accept actor tokens. |
| `actor_token_not_yet_valid` | 400 `invalid_request` |  |  | The actor token is not valid yet. |
| `actor_token_required` | 401 `invalid_client` |  |  | `[token] actor_auth` requires an actor token. |
| `actor_token_typ_mismatch` | 400 `invalid_request` |  |  | The actor token's `typ` header is not accepted. |
| `actor_token_type_unsupported` | 400 `invalid_request` |  |  | `actor_token_type` is not `urn:ietf:params:oauth:token-type:jwt`. |
| `actor_token_unknown_kid` | 400 `invalid_request` |  |  | The actor token's `kid` is not in its issuer's keys. |
| `actor_token_unmapped_subject` | 400 `invalid_request` |  |  | The actor token's subject maps to no agent. |
| `actor_token_unsupported_alg` | 400 `invalid_request` |  |  | The actor token's algorithm is not accepted. |
| `actor_token_untrusted_issuer` | 400 `invalid_request` |  |  | The actor token's issuer is not an `[[actor_trust]]` entry. |
| `admin_credential_expired` | 401 `unauthorized` |  |  | The admin bearer is an `[[admin.operators]]` credential whose `expires_at` has passed. |
| `admin_disabled` | 403 |  |  | The admin API is turned off. |
| `admin_role_insufficient` | 403 |  |  | The admin credential's role is below the one the route needs; the message names the role needed. |
| `agent_token_refused` | 403 |  |  | A delegation token cannot decide an approval. |
| `already_refunded` | 409 |  |  | The budget charge was already refunded. |
| `approval_expired` | 409 |  |  | The approval, or the lease it is bound to, has expired. |
| `approval_invalid` |  | `-32003` (200) | yes | A presented approval token does not verify, is for another call, or names an approval that is no longer granted. |
| `approval_not_pending` | 409 |  |  | The approval is already decided. |
| `approval_required` |  | `-32008` (200) | yes | The policy asks a person to approve this exact call first. |
| `approval_token_not_accepted` | 400 `invalid_request` |  |  | An AuthZEN action search carries `context.approval_token`; an approval token is spent only by the one decision it names. |
| `attribute_fixed_by_grant` | 403 |  |  | The root grant fixes this attribute; the request may not set it. |
| `attribute_type_mismatch` |  | `-32003` (200) | yes | An originating-user attribute does not have its declared type. |
| `audience_mismatch` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential's audience is not this server. |
| `audit_error` |  | `-32003` (200) | yes | The decision could not be written to the audit log (fail closed). |
| `bad_signature` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential's signature does not verify. |
| `batch_too_large` | 400 |  |  | An AuthZEN batch has more entries than `[authzen] max_batch`. |
| `budget_error` |  | `-32003` (200) | yes | The run-limit counters could not be read or written (fail closed). |
| `budget_exhausted` |  | `-32003` (200) | yes | The call would exceed a run limit of the token. |
| `capability_denied` |  | `-32003` (200) | yes | The token's capabilities do not permit the call. |
| `chain_mismatch` | 400 |  |  | The chain in the body is not the bearer token's chain. |
| `chain_not_issued` | 403 |  |  | A PEP's unsigned body chain was not issued by this server. |
| `chain_too_deep` | 400 `invalid_scope` |  |  | An exchange's chain would be deeper than `[issuer] max_depth`. |
| `charge_pruned` | 410 |  |  | The budget charge of the decision was pruned. |
| `check_unavailable` | 409 |  |  | The policy check cannot run in this configuration. |
| `client_assertion_audience_mismatch` | 401 `invalid_client` |  |  | The client assertion's `aud` is not exactly this server's issuer identifier (`[issuer] issuer`). |
| `client_assertion_expired` | 401 `invalid_client` |  |  | The client assertion has expired. |
| `client_assertion_lifetime_too_long` | 401 `invalid_client` |  |  | The client assertion's `exp` is further ahead than `[token] client_assertion_max_lifetime_seconds`. |
| `client_assertion_malformed` | 401 `invalid_client` |  |  | The client assertion is not a well-formed JWT, or its `typ` names another kind of token. |
| `client_assertion_missing_claim` | 401 `invalid_client` |  |  | The client assertion lacks `exp` or `jti`. |
| `client_assertion_not_yet_valid` | 401 `invalid_client` |  |  | The client assertion's `nbf` or `iat` is in the future. |
| `client_assertion_replayed` | 401 `invalid_client` |  |  | The client assertion (its `jti`) was already used. |
| `client_assertion_subject_mismatch` | 401 `invalid_client` |  |  | The client assertion's `iss` and `sub` are not both the client id, or differ from the request's client id. |
| `client_assertion_type_unsupported` | 400 `invalid_request` |  |  | `client_assertion_type` is not `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`. |
| `client_assertion_unsupported_alg` | 401 `invalid_client` |  |  | The client assertion's `alg` is not one the server accepts (RS256, ES256, EdDSA). |
| `client_auth_missing` | 401 `invalid_client` |  |  | No client credentials were sent. |
| `client_auth_not_accepted` | 400 `invalid_request` |  |  | `[token] actor_auth` does not accept client credentials. |
| `client_authentication_failed` | 401 `invalid_client` |  |  | The client id or secret is wrong, the client has no credential of the kind sent, or a client assertion is not signed by one of the client's keys (unknown client, unknown `kid`, a key of another algorithm, a bad signature: one answer). |
| `client_id_mismatch` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential was issued to another client. |
| `config_unreadable` | 500 `server_error` |  |  | The config file the server was started with cannot be read, so the operators were not reloaded; the cause is in the server log only. |
| `credential_audience_mismatch` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The ID token was not issued to the presenting agent: its `aud` or `azp` names another client. |
| `credential_expired` | 400 `invalid_grant` |  |  | The hop-0 credential expires before the token could be issued. |
| `credential_pop_mismatch` | 400 `invalid_grant` |  |  | The DPoP proof is by another key than the one the ID-JAG is bound to (`cnf.jkt`). |
| `credential_pop_required` | 400 `invalid_grant` |  |  | The ID-JAG is bound to a key (`cnf`) and the request has no DPoP proof that this server checks. |
| `dpop_replay_cache_full` | 503 `temporarily_unavailable` | `-32006` (503) |  | Too many DPoP proofs are in flight; retry later. |
| `dpop_required` | 401 | `-32001` (401) |  | The token is bound to a key and no DPoP proof was sent. |
| `duplicate_actor` | 400 `invalid_request` |  |  | The `actor` is already in the chain. |
| `expired` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential has expired. |
| `id_jag_ceiling_empty` | 400 `invalid_scope` |  |  | An ID-JAG from an issuer with `[idps.id_jag_ceiling]`: its `resource`, `scope` and `authorization_details` claims leave nothing of the root grant (each names only what is unmapped, of an unknown type, or not in the grant). |
| `input_type_mismatch` |  | `-32003` (200) | yes | A call argument does not have the type the catalog declares. |
| `invalid_agent` | 400 `invalid_grant` |  |  | The agent id of the token to mint is empty (an exchange's `actor`, or `agent` at `POST /admin/root-token`). |
| `invalid_capability` | 400 `invalid_grant`, 400 `invalid_scope` |  |  | A requested capability is not one a call can have: a server or tool name that breaks the naming rules, or a malformed limit (sent with `error` `invalid_grant`); or a shorthand that is not `server:tool` (a form `scope` at `POST /token`, `capabilities` at `POST /admin/root-token`; sent with `error` `invalid_scope`). |
| `invalid_chain` | 400, 400 `invalid_request` |  |  | The chain in the body does not validate (`POST /admin/policies/evaluate`, or a PEP's unsigned chain at AuthZEN, sent with `error` `invalid_request`). |
| `invalid_client` | 401 |  |  | Client authentication failed. |
| `invalid_cursor` | 400 |  |  | The paging cursor (or an AuthZEN search's `page.token`) is malformed or belongs to another list, order or query. |
| `invalid_dpop_proof` | 401 | `-32001` (401) |  | The DPoP proof does not verify, is replayed, or is for another key, method or URL. |
| `invalid_grant` | 400 |  |  | The grant (subject token, lease, credential) is not valid. |
| `invalid_host` | 400 |  |  | The `Host` header is not a loopback name and `[server] public_url` is unset. |
| `invalid_name` |  | `-32003` (200) | yes | The call's server or tool name breaks the naming rules. |
| `invalid_page` | 400 `invalid_request` |  |  | An AuthZEN search's `page` is not an object, its `token` not a string, or its `limit` not an integer of at least 1. |
| `invalid_params` |  | `-32602` (200) |  | The JSON-RPC params of a decided method are not valid. |
| `invalid_request` | 400 | `-32600` (400) |  | The request is malformed: a missing or invalid parameter or body. |
| `invalid_scope` | 400 |  |  | A subject token whose own chain widens a hop or is deeper than `[issuer] max_depth`; a request that asks for more is `scope_exceeds_parent`, `chain_too_deep` or `scope_exceeds_grant`. |
| `invalid_search_resource` | 400 `invalid_request` |  |  | An AuthZEN action search's `resource` names no MCP server (`resource.properties.server`, or a `resource.id` without `/`). |
| `invalid_subject` | 400 `invalid_grant` |  |  | The user subject of the root token to mint is empty. |
| `invalid_token` | 401 `unauthorized`, 400 | `-32001` (401) |  | The token is malformed, not issued here, or does not verify. |
| `jwks_unavailable` | 503 `temporarily_unavailable`, 401 `invalid_token` |  |  | The issuer's keys cannot be fetched; retry later. |
| `label_error` |  | `-32003` (200) | yes | The call's result could not be recorded, so it is withheld. |
| `lease_error` |  | `-32001` (401), `-32003` (200) | yes | The lease store could not be read (fail closed). |
| `lease_expired` | 400 `invalid_grant` | `-32001` (401), `-32001` (200), `-32003` (200) | yes | A lease of the chain has expired (at `POST /token` and `POST /token/renew`, an ancestor lease of the token). |
| `lease_revoked` | 409, 400 `invalid_grant` | `-32001` (401), `-32001` (200), `-32003` (200) | yes | A lease of the chain (at `POST /token` and `POST /token/renew`, the token's own lease or an ancestor's), or the one an approval is bound to, has been revoked. |
| `lease_unknown` | 400 `invalid_grant` | `-32001` (401), `-32001` (200), `-32003` (200) | yes | A lease of the chain is unknown to the lease store (fail closed); at `POST /token` and `POST /token/renew`, the token's own lease or an ancestor's. |
| `limit_arg_invalid` |  | `-32003` (200) | yes | The call lacks an argument a run limit counts, or has a value it cannot count. |
| `limit_split_at_root` | 400 `invalid_scope` |  |  | The hop-0 request (an IdP credential at `POST /token`, or `POST /admin/root-token`) has two capabilities that take their limits from the same limited capability of the root grant or of the ID-JAG's claims; ask for one capability with a `one_of` or wider constraint instead. |
| `malformed_client_auth` | 401 `invalid_client` |  |  | The HTTP Basic credentials are malformed. |
| `malformed_request` | 400 `invalid_request` |  |  | The token request is missing a field or has an invalid one (at `POST /token`, also a body that is not JSON or a well-formed form). |
| `malformed_token` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential is not a well-formed JWT. |
| `may_act_exceeds_grant` | 400 `invalid_request` |  |  | `may_act` names agents the grant does not allow. |
| `missing_claim` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential lacks a required claim. |
| `missing_kid` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential names no `kid`. |
| `missing_token` | 401 `unauthorized` | `-32001` (401) |  | No credential was sent. |
| `multiple_client_auth` | 400 `invalid_request` |  |  | Client credentials were sent in more than one way (HTTP Basic and the body, or a secret and a client assertion). |
| `no_agents_configured` | 401 `invalid_client` |  |  | No `[[agents]]` are configured, so no agent can authenticate. |
| `no_capabilities_requested` | 400 `invalid_request` |  |  | The token request (`POST /token`, `POST /admin/root-token`) asks for no capability. |
| `no_lifetime_left` | 400 `invalid_request` |  |  | The new token would expire immediately. |
| `no_peps_configured` | 401 `invalid_client` |  |  | No `[[peps]]` are configured, so no PEP can authenticate. |
| `no_root_grant` | 403, 400 `invalid_scope` |  |  | No `[[root_grants]]` entry covers the agent and user. |
| `not_found` | 404 |  |  | The resource does not exist, or is not visible to the caller. |
| `not_yet_valid` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential is not valid yet. |
| `one_of_too_long` | 400 `invalid_scope` |  |  | A requested capability (an exchange, a hop-0 request, `POST /admin/root-token`) has a `one_of` constraint with more than 1,024 values. |
| `operators_invalid` | 422 |  |  | The reloaded `[[admin.operators]]` list is not TOML or breaks a startup rule; the operators in force are unchanged. |
| `operators_no_admin` | 422 |  |  | The reloaded `[[admin.operators]]` list would leave no unexpired credential with role `admin`; the operators in force are unchanged. |
| `overloaded` | 503 `temporarily_unavailable` | `-32006` (503) |  | `[limits] max_in_flight` requests are already running; retry after `Retry-After`. |
| `parse_error` |  | `-32700` (400) |  | The body is not JSON. |
| `policy_deny` |  | `-32003` (200) | yes | The Cedar policy denies the call. |
| `policy_error` |  | `-32003` (200) | yes | The call could not be evaluated safely (fail closed). |
| `policy_invalid` | 422 |  |  | The policy set does not parse or validate. |
| `rate_limited` | 429 | `-32007` (429) |  | A rate limit is used up; retry after `Retry-After`. |
| `reload_unavailable` | 409 |  |  | The policy, or the admin operators, cannot be reloaded in this configuration (no policy file; a server not started from a config file). |
| `replay_cache_full` | 503 `temporarily_unavailable` |  |  | Too many single-use credentials are in flight; retry later. |
| `replay_store_unavailable` | 503 `temporarily_unavailable` |  |  | The use of a single-use credential could not be recorded, so it is refused (fail closed); retry later. |
| `replayed` | 400 `invalid_grant` |  |  | The credential or delegation was already used. |
| `request_timeout` | 408, 503 `temporarily_unavailable` |  |  | The body did not arrive in time (408), or the route did not answer in time (503). |
| `request_too_large` | 413 | `-32600` (413) |  | The request body is over the size limit. |
| `reserved_agent` | 400 `invalid_request` |  |  | The `actor` is the reserved agent `attenuo`. |
| `reserved_subject` | 400 `invalid_request`, 400 `invalid_grant` |  |  | The subject is reserved. |
| `scope_exceeds_grant` | 400 `invalid_scope` |  |  | The hop-0 request (an IdP credential at `POST /token`, or `POST /admin/root-token`) asks for more than the root grant allows. |
| `scope_exceeds_id_jag` | 400 `invalid_scope` |  |  | An ID-JAG from an issuer with `[idps.id_jag_ceiling]`: the request is within the root grant but asks for more than the ID-JAG's own claims allow. |
| `scope_exceeds_parent` | 400 `invalid_scope` |  |  | An exchange asks for more than the subject token holds. |
| `server_error` | 500 |  |  | An internal error; the cause is in the server log only. |
| `session_mismatch` |  | `-32003` (403) |  | The `Mcp-Session-Id` belongs to another principal. |
| `session_registry_full` |  | `-32006` (503) |  | No free session slot (`[proxy] max_sessions`). |
| `session_unknown` |  | `-32600` (404) |  | The `Mcp-Session-Id` is not bound; start a new session. |
| `tenant_mismatch` | 400 `invalid_grant` |  |  | The ID-JAG's `tenant` is not the `[[idps]] tenant` of its issuer. |
| `token_expired` | 401 `unauthorized`, 400 `invalid_grant` | `-32001` (401), `-32001` (200) |  | The token verified but has expired (a bearer, or at `POST /token` the subject token or a hop of its chain). |
| `too_many_capabilities` | 400 `invalid_scope` |  |  | A request (an exchange, a hop-0 request, `POST /admin/root-token`) asks for more than 1,024 capabilities, more than one token may hold. |
| `too_many_constraints` | 400 `invalid_scope` |  |  | A request (an exchange, a hop-0 request, `POST /admin/root-token`) has more than 1,024 argument constraints over all its capabilities. |
| `too_many_one_of_values` | 400 `invalid_scope` |  |  | A request (an exchange, a hop-0 request, `POST /admin/root-token`) has more than 1,024 `one_of` values over all its capabilities. |
| `too_many_pending_approvals` | 429 |  |  | The run already has the maximum number of pending approvals. |
| `too_many_sessions` |  | `-32007` (429) |  | The principal holds `[proxy] max_sessions_per_principal` live sessions. |
| `tool_not_in_catalog` |  | `-32003` (200) | yes | The tool is not in the catalog and unknown tools are denied. |
| `tool_not_listed` |  | `-32003` (200) | yes | The upstream never listed the tool and the catalog does not know it. |
| `ttl_out_of_range` | 400 `invalid_grant` |  |  | The requested lifetime gives no representable expiry (`POST /admin/root-token`; an exchange clamps it to the parent's instead). |
| `typ_mismatch` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential's `typ` header does not match its kind. |
| `unknown_kid` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential's `kid` is not in its issuer's keys. |
| `unknown_server` |  | `-32004` (404) |  | No `[[upstreams]]` entry has this name. |
| `unsupported_alg` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential's signing algorithm is not accepted. |
| `unsupported_grant_type` | 400 |  |  | The `grant_type` is not supported. |
| `unsupported_media_type` | 415 |  |  | The console listener requires `Content-Type: application/json`. |
| `unsupported_token_type` | 400 `invalid_request` |  |  | The `subject_token_type` is not supported (neither the JWT URN of an exchange nor a hop-0 credential type). |
| `untrusted_issuer` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential's issuer is not an `[[idps]]` entry. |
| `upstream_body_too_large` |  | `-32005` (502) |  | An upstream body the proxy buffers is over `[proxy] max_upstream_body_bytes`. |
| `upstream_invalid_response` |  | `-32005` (502) |  | The upstream's answer is not one the proxy can filter or label. |
| `upstream_not_event_stream` |  | `-32005` (502) |  | The upstream answered a `GET` with something other than an event stream. |
| `upstream_stream_end_shape` |  | `-32005` (200) |  | The upstream sent an error in the shape of the proxy's stream end; the original is in `data.upstream_error`. |
| `upstream_timeout` |  | `-32005` (504) |  | The upstream did not answer in time; it may have acted on the request. |
| `upstream_unreachable` |  | `-32005` (502) |  | The upstream could not be reached; nothing was sent. |
| `use_dpop_nonce` | 401 | `-32001` (401) |  | The DPoP proof lacks the current server nonce; retry with `DPoP-Nonce`. |
| `wrong_user` | 403 |  |  | The ID token is another user's. |
<!-- error-codes:end -->

## Paging

Every route that returns a list a client may need to read past one answer pages the same way: `GET /admin/audit`, `GET /admin/audit/checkpoints` and `GET /admin/approvals`.

- **Request.** `limit` is the page size; `cursor` is the `next_cursor` of the previous page, sent back unchanged with the same filters (and `order`, where there is one). Leave `cursor` out for the first page.
- **Answer.** The items (`entries`, `checkpoints` or `approvals`) and `next_cursor`: a string for the next page, or `null` when there is nothing after this one. A page can hold fewer than `limit` items, even none, while `next_cursor` is set (a filtered audit page reads a bounded range of the log): keep following it until it is `null`.
- **Limits.** Each route documents its default and maximum `limit`. A `limit` of 0 or above the maximum is 400 `invalid_request`; it is not clamped.
- **Cursors are opaque.** Do not build or parse one; its encoding may change. A cursor that is malformed, was issued by another list route or for the other `order`, or comes from another format version is 400 `invalid_cursor`, with a `detail` that says which and never repeats the cursor. A cursor does not expire: it holds a position, not a server-side session, and still works after the item it points past has been removed.
- **Stable under writes.** The cursor holds a keyset position (an audit or checkpoint `seq`, or the approval's position in the store), never an offset. An approval's position is above that of every approval created before it and is never given again, also after approvals are removed or pruned, so a new approval never sorts below a cursor a client holds. Items appended or created while a client pages do not shift the items it has not read yet, so every item that existed when paging started is returned exactly once. Newest-first lists show new items only on a fresh first page; the oldest-first audit list returns entries appended before it reaches the head, once each.

The cursor is the unpadded base64url form of 11 bytes: a format version, the list it belongs to, the direction it pages in, and the position. It carries no subject, filter value or query, and it has no integrity tag: every list route is an admin route whose caller may read the whole list anyway, so a forged cursor could only start a page at another position the caller could reach by paging. What the server checks is that the cursor is well-formed and belongs to this route and order.

Action search (`POST /access/v1/search/action`) pages with AuthZEN's `page.token` / `page.next_token` instead, a longer token of the same format version: the 11 bytes, whose position is an offset into the candidate tools, followed by truncated SHA-256 digests of the delegation chain, the MCP server and the canonical `context` the token was issued for. Send it back with the same `subject`, `resource` and `context`; `page.limit` may change. A token sent with another chain, server or `context` is 400 `invalid_cursor`, and `detail` says which differs. The digests hold no request data and are no integrity tag either: the server recomputes them from the request it is sent with, so they only tie a token to its query ([AuthZEN action search](authzen.md#action-search)).

Two routes are not paged this way. `GET /admin/audit/export` streams a whole range (`from`, `to`) in one answer, because the export's header, hash chain and checkpoints are verified as one file; cut it into ranges instead. `GET /admin/leases/{lease_id}/tree` returns a bounded snapshot of one lease tree (`max_nodes`, `truncated`) next to a count of the whole subtree; a breadth-first walk has no stable key to resume from, and the revoke it previews acts on the whole tree anyway.

## DPoP (sender-constrained tokens)

Optional, RFC 9449. See [Binding tokens to keys](../guides/binding-tokens-to-keys.md) and [RFC-0001 section 4.1](../spec/rfc-0001-attenuo.md#41-sender-constrained-tokens-dpop).

- **Binding.** A `DPoP` header (one proof by an Ed25519 or P-256 key, for this method and URL) on `POST /token` or `POST /admin/root-token` binds the new token to the key: its `cnf.jkt` is the key's thumbprint and the response says `"token_type": "DPoP"`. A child of a bound token is always bound. To bind it to a key other than the parent's, the body adds `subject_token_dpop`, the sign-off: a proof by the parent's key with `ath` of `subject_token`, `child_jkt` (the new key's thumbprint) and `child_actor` (the `actor`). See [Binding tokens to keys](../guides/binding-tokens-to-keys.md).
- **Use.** A bound token is accepted only with a `DPoP` proof by its key that carries `ath`, on every route that takes a token: `/mcp/{server}`, `/token/renew`, `/access/v1/evaluation(s)`, `/access/v1/search/action` and `/token` (as `subject_token`). Send `Authorization: DPoP <token>`; `Bearer` is also accepted.
- **Nonces.** With `[token] dpop_nonce = "required"`, every response to a request with a `DPoP` header, and every `WWW-Authenticate: DPoP` challenge, carries `DPoP-Nonce: <nonce>`. A `DPoP` header proof must carry the latest one in its `nonce` claim; the exchange sign-off needs none.
- **Errors.** 401 `dpop_required` (no proof where one is needed), `invalid_dpop_proof` (wrong key, method, URL or `ath`, `iat` outside `[token] dpop_max_age_seconds`, replayed `jti`, bad signature, several `DPoP` headers) or `use_dpop_nonce` (a valid proof without a current server nonce; retry with the response's `DPoP-Nonce`), with `WWW-Authenticate: DPoP error="…", algs="EdDSA ES256"`. The proxy uses JSON-RPC `-32001` with the same `data.reason`. A full replay cache is 503 `temporarily_unavailable` with `error_description` `dpop_replay_cache_full`.
- `htu` is `[server] public_url` plus the path, or `http://<Host>` plus the path when `public_url` is unset. The query is not compared.

Every route of the main listener is subject to [`[limits]`](config.md#limits): a request that finds `max_in_flight` requests already running is `503` `temporarily_unavailable` with `error_description` `overloaded` and `Retry-After: 1` (never `/healthz` or `/readyz`); a body that does not arrive within `request_body_timeout_seconds` is `408` `request_timeout`; a route other than `/mcp/{server}` and `/admin/*` that does not answer within `request_timeout_seconds` is `503` with `error_description` `request_timeout` and `Retry-After: 1`. With the rate limits on, `POST /token` over `token_requests_per_minute` (per agent) or `token_unauthenticated_requests_per_minute` (per peer address), and `POST /access/v1/search/action` over `authzen_search_requests_per_minute` (per run, the chain's root lease, also for a PEP's unsigned chain), are `429` `rate_limited` with `Retry-After`; AuthZEN evaluation and batch evaluation are not rate limited (each decision is audited). When the per-peer table is full, a request from an address not in it that carries client credentials is authenticated first: an agent that authenticates is served, and anything else gets the same `429` (see [`[limits]`](config.md#limits)). Headers that take longer than `header_read_timeout_seconds` to arrive get the connection closed. The SDKs raise the `503` as Python `Unavailable` / TypeScript `UnavailableError` and the `429` as `RateLimited` / `RateLimitedError`, with `reason` and the `Retry-After` seconds, never as a denial; the `408` stays a plain `ApiError`. They retry `overloaded` and `rate_limited` only when the client is built with `max_retries` / `maxRetries`, never `request_timeout`.

## Client authentication

An agent (on `POST /token`) or a PEP (on the AuthZEN endpoints) proves who it is in one of two ways, decided by what its `[[agents]]` or `[[peps]]` entry holds ([config](config.md#agents)):

- **Client secret.** `client_id` / `client_secret` in the body (`pep_id` / `pep_secret` for a PEP), or HTTP Basic. The entry holds `secret_sha256`.
- **Client assertion** (`private_key_jwt`, RFC 7523 §2.2). The body carries `client_assertion_type` = `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, a JWT the client signs with a private key whose public half is in the entry's `jwks`. `client_id` (or `pep_id`) may be sent too and must then equal the assertion's `sub`. The CLI makes one with `attenuo token exchange --client-key`, the SDKs with `DpopKey.client_assertion` / `clientAssertion`.

A request uses one way only: Basic and a body credential, or a secret and an assertion, is 400 `invalid_request` / `multiple_client_auth` (RFC 6749 §2.3). Sending only one of the two assertion fields is `malformed_request`; another `client_assertion_type` is 400 `client_assertion_type_unsupported`.

A request with no credential at all (no secret, no assertion, and at `POST /token` no `actor_token`) is 401 `invalid_client` (RFC 6749 §5.2), with `WWW-Authenticate: Basic realm="attenuo"`: `client_auth_missing`, or `actor_token_required` when `[token] actor_auth = "actor_token"`. Both are decided before any agent or PEP is looked up, so the answer is the same for a known and an unknown client id or `actor` (SR-110).

An assertion is accepted when all of this holds, checked in this order:

| Check | Refusal (`error_description`) |
| --- | --- |
| a compact JWS whose `typ`, if present, is not that of another token kind (`attenuo+jwt`, `at+jwt`, `dpop+jwt`, `oauth-id-jag+jwt`) | `client_assertion_malformed` |
| `iss` and `sub` are both the client id (and equal `client_id` when it is sent) | `client_assertion_subject_mismatch` |
| `alg` is RS256, ES256 or EdDSA, and `kid`, if present, is a string | `client_assertion_unsupported_alg`, `client_assertion_malformed` |
| the client exists and has `jwks`; `kid` names one of its keys (it may be left out only when the entry has one key); that key is for `alg`; and the signature verifies with it | `client_authentication_failed` |
| `aud` is `[issuer] issuer`: that string, or an array holding only it | `client_assertion_audience_mismatch` |
| `exp` and `jti` are present, `jti` at most 256 bytes | `client_assertion_missing_claim` |
| `exp` has not passed and is at most `[token] client_assertion_max_lifetime_seconds` ahead; `nbf` and `iat`, if present, are not in the future; all with `[token] client_assertion_clock_skew_seconds` of leeway | `client_assertion_expired`, `client_assertion_lifetime_too_long`, `client_assertion_not_yet_valid` |
| the `jti` has not been used by this client before | `client_assertion_replayed` |

All of them are 401 `invalid_client` with `WWW-Authenticate: Basic realm="attenuo"`, as a wrong secret is. The answer never echoes the assertion. Until the signature has verified, a caller holding none of the client's keys learns nothing about the entry: an unknown client id, an entry without `jwks`, an unknown `kid`, a key of another algorithm and a bad signature are one answer, `client_authentication_failed` with the same `detail`, as an unknown id or a wrong secret is on the secret path (SR-110). The specific reason is in the server's log at debug level (`client assertion refused`, `reason` = `unknown_client`, `client_without_keys`, `unknown_kid`, `key_alg_mismatch` or `bad_signature`). The checks after the signature keep their own codes, because only a holder of the key can reach them and they say what to fix. The checks before the lookup (`typ`, `iss` and `sub`, `alg`, a `kid` that is not a string) do not depend on whether the client exists. The `aud` rule is strict on purpose: the token endpoint URL is not accepted, so an assertion made for one server cannot be replayed at another that shares a URL prefix or proxy (the audience-injection concern behind RFC 7523bis). The `jti` is recorded in the replay store (`used_credentials`, the store DPoP proofs and actor tokens use) until `exp` plus the skew, so it stays spent across a restart; it is spent when the client authenticates, even if the request is then refused for another reason, so send a fresh assertion with every request. Two refusals come before that and leave the assertion unspent, because the client is told to send the same request again: `429` `rate_limited` from `[limits] token_requests_per_minute`, and a `DPoP` header proof that is refused (`use_dpop_nonce` under `[token] dpop_nonce = "required"`, or `invalid_dpop_proof`). A full or unavailable replay store is 503, as for DPoP.

The method shows in the server log and in the audit record's arguments: `agent_auth` at hop 0 and `actor_auth` at later hops are `client_secret`, `private_key_jwt`, `actor_token`, or `actor_token+client_secret` / `actor_token+private_key_jwt` with `[token] actor_auth = "either"` (and `none` for an unauthenticated later hop when `[token] require_actor_auth = false`).

## Public

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | Liveness. Never touches storage. |
| `GET /readyz` | none | Readiness. Checks the audit store and the lease store, and whether the last audit append failed. 200 `{"ready":true,"checks":{"audit":"ok","audit_append":"ok","leases":"ok"}}` or 503 with `"error"` for the failing check and no error text. `checks.audit_append` is `"error"` from a failed audit append (a full disk, for example, while reads still work) until the next append succeeds, or for at most 30 s when no append is made after it; no probe is written. With `[audit.sink]` the body also has `"degraded"` and `checks.checkpoint_sink` (`"ok"` or `"degraded"`); a degraded sink is a 503 only with `fail_readiness = true`. With `[approvals.notify]` it also has `checks.approval_notifier` (`"ok"` or `"degraded"`), which sets `"degraded"` but never makes the answer a 503. |
| `GET /.well-known/jwks.json` | none | Public keys for token verification, including retired keys. |
| `GET /.well-known/authzen-configuration` | none | AuthZEN discovery (AuthZEN 1.0 section 9): `policy_decision_point`, `access_evaluation_endpoint`, `access_evaluations_endpoint` and `search_action_endpoint`, and nothing else; no subject or resource search endpoints, which are not served, and no `capabilities` or `signed_metadata` ([why](authzen.md#discovery)). Public metadata: no credential is needed and an `Authorization` header is ignored ([why](authzen.md#discovery)). The URLs are built from `[server] public_url`. Without it (loopback only) from `Host`, which must be `localhost`, `127.0.0.1` or `[::1]`; anything else is 400 `invalid_host`. |

## Token

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /token` | agent client credentials (a secret or a [client assertion](#client-authentication)) at hop 0; at later hops the parent token, plus the actor's client credentials or an `actor_token` | RFC 8693 token exchange, as a form or JSON. Hop 0 takes an OIDC ID token or an ID-JAG. Later hops take a parent delegation token and `authorization_details`. Optional `may_act` (agent ids) sets who may exchange the new token next. A `DPoP` header binds the new token to a key (`token_type` `DPoP`); `subject_token_dpop` is the parent key's sign-off, naming the new key and `actor`, when the parent is bound to another key. |
| `POST /token/renew` | bearer delegation token (and a DPoP proof if it is bound) | Extend the lease of the token's last hop. Returns `{lease, expires_at, expires_in}`. A refusal of a token that verified is audited (below). |

A capability may carry run `limits` (`calls`, `sum: {arg, max}`, `calls_per: {arg, max}`, `distinct: {arg, max}`; [run limits](../design/server.md#run-limits)). `distinct` allows at most `max` different values of `arg`. `calls_per` and `distinct` may add `"derive": "host"` to count the host of a URL argument instead of the whole value (`{"arg": "url", "derive": "host", "max": 2}`). A value with no scheme is a bare host and is read as `http://` followed by the value, so `www.example.com/x` counts host `www.example.com` and `localhost:8080` counts `localhost`. A child must keep every limit of the parent capability that covers it, on the same argument and derivation, at most as large (`calls: m` also satisfies a parent's `calls_per` or `distinct` with `max >= m`); one it leaves out or asks larger is filled in or lowered (a `sum`, `calls_per` or `distinct` over another argument or derivation is refused as not covered), and its `calls` and `sum` are lowered further to what the parent hop has left. An unknown limit kind or derivation does not parse: 400 `invalid_request` (at `POST /token`, with `code` `malformed_request`). A limit that parses but is malformed (`derive` on a `sum`, an empty `arg`, a `max` over the cap) is 400 `invalid_grant` with `code` `invalid_capability`.

A later-hop request authenticates its `actor` with `client_id` / `client_secret` (or HTTP Basic), with a client assertion (`client_assertion_type` and `client_assertion`, [above](#client-authentication)), or with `actor_token` and `actor_token_type` = `urn:ietf:params:oauth:token-type:jwt` (RFC 8693 §2.1): a workload-identity JWT, such as a SPIFFE JWT-SVID, from an `[[actor_trust]]` issuer. `[token] actor_auth` decides which are accepted: `"secret"` means client credentials, a secret or an assertion according to what the agent's entry holds. An actor token works for one exchange, and the child expires no later than it does. If the parent token carries `may_act`, the `actor` must be listed (`actor_not_permitted` otherwise). `may_act` on the request sets the new token's own list: absent means any authenticated agent may exchange the new token (it does not inherit the parent's list), and `[]` means none may.

**Refused exchanges are audited.** When the subject token verified (signature, issuer, audience, expiry, chain) and so did its DPoP proof, a refusal the request caused is a `deny` record against the parent's chain: server `attenuo`, tool `token.exchange`, kind `decision`, the parent's subject, agents, leases and `chain_id`. The 400 carries the record id in `X-Attenuo-Decision-Id` and as `decision_id` in the body:

```json
{"error": "invalid_scope", "code": "scope_exceeds_parent", "detail": "delegation chain is invalid: ...", "decision_id": "10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223"}
```

| Refusal | `error` / `error_description` | `code` | Audit `reason` |
| --- | --- | --- | --- |
| asks for more than the parent holds | `invalid_scope` | `scope_exceeds_parent` | `exchange_widening` |
| chain deeper than `[issuer] max_depth` | `invalid_scope` | `chain_too_deep` | `exchange_too_deep` |
| actor not in the parent's `may_act` | `invalid_request` / `actor_not_permitted` | `actor_not_permitted` | `exchange_actor_not_permitted` |
| authenticated agent or actor token is not `actor` | `invalid_request` / `actor_mismatch` | `actor_mismatch` | `exchange_actor_mismatch` |
| `actor` already in the chain | `invalid_request` / `duplicate_actor` | `duplicate_actor` | `exchange_duplicate_actor` |
| `actor` is `attenuo` | `invalid_request` / `reserved_agent` | `reserved_agent` | `exchange_reserved_agent` |
| actor token expires now | `invalid_request` / `actor_token_expired`, `no_lifetime_left` | the same | `exchange_no_lifetime_left` |
| parent already delegated to this actor, or actor token reused | `invalid_grant` / `replayed` | `replayed` | `exchange_replayed` |
| a requested capability has an invalid name or limit | `invalid_grant` | `invalid_capability` | `exchange_invalid_capability` |
| `actor` is empty (possible only without actor authentication) | `invalid_grant` | `invalid_agent` | `exchange_refused` |
| parent lease revoked, expired or unknown | `invalid_grant` | `lease_revoked`, `lease_expired`, `lease_unknown` | the same |

A parent whose lease is not live is answered with the lease reason as `code`, and `detail` names it too (`subject token cannot delegate: lease_revoked (...)`); there is no `error_description`. Not recorded, a server log line only: a malformed request, failed client or actor-token authentication, a subject token or DPoP proof that does not verify (so an anonymous caller cannot write to the log, SR-18), and server errors. A subject token that verified but has expired (or a hop of its chain has) is 400 `invalid_grant` with `code` `token_expired`; any other subject token that does not verify is 400 `invalid_grant` with `code` `invalid_grant`. A body that is not JSON or a well-formed form, a repeated form parameter, or a field that is missing or does not parse is 400 `invalid_request` with `code` `malformed_request` and no `error_description` (hop-0 intake sends the same code, and for a field also as `error_description`), and a form `scope` entry that is not `server:tool` is 400 `invalid_scope` with `code` `invalid_capability`. A request with no capability is 400 `invalid_request` with `code` `no_capabilities_requested`, and a `subject_token_type` other than the JWT URN (and not a hop-0 credential type) is 400 `invalid_request` with `code` `unsupported_token_type`. A `requested_ttl_seconds` beyond the parent's expiry is not a refusal: the child is clamped to the parent. A refused exchange uses up nothing: the parent can still delegate once to that actor, an actor token can be presented again, and no run limit is charged; only its DPoP proof (its `jti`) is spent. It is counted in `decisions_total{decision="deny",reason}`.

**Refused renewals are audited.** When the token of a `POST /token/renew` verified (signature, issuer, audience, expiry, chain) and so did its DPoP proof, a refusal is a `deny` record against the token's chain: server `attenuo`, tool `lease.renew` (the tool of a successful renewal, so `audit export --tool lease.renew --decision deny` lists the refused ones), kind `decision`, and the arguments digest of `{lease, ancestor, dpop_bound}`. The 400 carries the id in `X-Attenuo-Decision-Id` and `decision_id`:

| Refusal | `error` | `code` and audit `reason` |
| --- | --- | --- |
| the token's own lease, or an ancestor's, is revoked | `invalid_grant` | `lease_revoked` |
| an ancestor lease has expired (stopped renewing) | `invalid_grant` | `lease_expired` |
| the token's own lease, or an ancestor's, is unknown to the lease store | `invalid_grant` | `lease_unknown` |

```json
{"error": "invalid_grant", "code": "lease_revoked", "detail": "lease_revoked", "decision_id": "10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223"}
```

Branch on `code`. `detail` is the bare reason for the token's own lease and `an ancestor lease is not live: <reason>` for an ancestor's; it is text for people and may change.

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

The three AuthZEN endpoints echo a request's `X-Request-ID` header on the response, whatever its status (AuthZEN 1.0 section 10.1.3). What of the AuthZEN specification is implemented, extended and left out, with the conformance fixtures that check it: [AuthZEN conformance](authzen.md).

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /access/v1/evaluation` | bearer token, or a trusted PEP | AuthZEN evaluation. Same pipeline as the proxy, run limits included: an allowed evaluation is charged as a proxied call is, and its answer carries `context.budget` (`limited`, `calls_remaining`, `amount_remaining`, `destination_new`) when a limit matched, `context.charged` when it was charged, `context.limit` on `budget_exhausted`, `context.untrusted_args` (`[{arg, seq, kind}]`, as in the proxy's error data) when an argument matched an untrusted result of the run, and `context.usage` (`{calls, amount, destination_seen}`, plus `user_window` when it is not all zero, as in the proxy's error data) for a destructive tool or one with an `outbound` catalog input; an allowed evaluation is counted in the run's usage, and anything the PEP sends under `context.usage` is ignored. `context.diagnostics` is filled only for callers `[authzen] diagnostics` allows: by default a `[[peps]]` entry, which can authenticate next to a bearer token with `pep_id` and `pep_secret` in the body, or with a top-level `client_assertion_type` and `client_assertion` ([client authentication](#client-authentication)). |
| `POST /access/v1/evaluations` | same | AuthZEN batch: top-level `subject`, `action`, `resource`, `context` are defaults and each entry of `evaluations` overrides them. Answers `{"evaluations": [{decision, context}, ...]}`, one per entry, each decided and audited like a single evaluation. At most `[authzen] max_batch` entries (default 64): more is 400 `batch_too_large`. Without `evaluations`, or with an empty one, the request is a single evaluation and is answered with a single `{decision, context}` (AuthZEN 1.0 section 7.1). `options.evaluations_semantic` (AuthZEN 1.0 section 7.1.2.1) is `execute_all` (default: every entry decided and answered), `deny_on_first_deny` (entries decided in order, stopping after the first deny; an entry that fails counts as a deny) or `permit_on_first_permit` (stopping after the first permit). A stopped batch answers only the entries it decided, so `evaluations` is shorter than the request; the entries after the stop are not decided, charged or audited. Any other value is 400 `invalid_request` before anything is decided. A PEP's client assertion goes at the top level and covers the whole batch (its `jti` is spent once per HTTP request); one inside an entry is that entry's `malformed_request`. |
| `POST /access/v1/search/action` | same | AuthZEN action search (AuthZEN 1.0 section 8): `{subject, resource, context, page}` with no `action`; the resource is the MCP server, named by `resource.properties.server` or by a `resource.id` without `/`. Answers `{"page": {"next_token", "count"}, "results": [{"name": <tool>, "properties": {"server": <server>}}, ...]}`: the `[policy] catalog` tools of that server that the token's capabilities name, in name order, that the pipeline would allow now for this caller and context, each of which `POST /access/v1/evaluation` with the same subject, resource and context decides `true` while the run's state is unchanged. No reasons, policy ids or diagnostics. Nothing is written: no audit record, no charge to run limits or usage, no approval taken or requested, so an approval-gated tool is never a result; `context.approval_token` is 400 `approval_token_not_accepted`. A dead lease gives no results. One page evaluates at most `page.limit` candidates (default and maximum `[authzen] max_batch`; a larger `limit` is clamped, 0 is 400 `invalid_page`), so a page can hold fewer results, even none, while `next_token` is set; `next_token` is `""` after the last page. Send it back as `page.token` with the same `subject`, `resource` and `context` (`page.limit` may change); a token this route did not issue, or issued for another chain, server or `context`, is 400 `invalid_cursor`. A resource that names no server is 400 `invalid_search_resource`. With `[limits] authzen_search_requests_per_minute` set, a run's searches over it in its minute are 429 `rate_limited` with `Retry-After`, counted after authentication and before anything is evaluated; evaluations are not counted. [Why and what is left out](authzen.md#action-search). |

## MCP proxy

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp/{server}` | bearer delegation token | Send an MCP request to the upstream called `server`. `tools/call` and similar methods are decided first. List answers keep only what the token's capabilities could permit; with `[proxy] list_filter = "policy"`, `tools/list` also leaves out tools the policy denies for every possible call of this token (a hidden tool can still be called, and is decided as usual). |
| `GET /mcp/{server}` | bearer delegation token | The streamable HTTP listen stream, after the lease check; resumable with `Last-Event-ID`. List answers on it are filtered and answers to allowed calls labelled, like `POST` answers. Ended (and recorded as `stream.end`, at most once per chain and reason per 60 s) when the lease is revoked or the token expires. |
| `DELETE /mcp/{server}` | bearer delegation token | Passthrough session close, after the lease check. |

A denial is a JSON-RPC error with code `-32003`, carrying `reason` and `decision_id`. A call that a policy sends for approval (reason `approval_required`) gets `-32008` instead, with `reason`, `decision_id`, `call_hash` (SHA-256 of the RFC 8785 JSON of `{server, tool, arguments}`), `approval_id` and `expires_at`, and is not forwarded. Once the approval is granted, the identical call from the same hop is allowed once (see [Approvals](#approvals)); or the retry carries the grant's signed approval token in `params._meta["dev.attenuo/approval"]`, which the proxy removes before the upstream and which does not count as an argument (see [Approval tokens](#approval-tokens)). A token that does not verify, is for another call, hop, run or key, or names an approval that is no longer granted gets `-32003` with reason `approval_invalid`. `approval_id` is absent if the server could not open an approval: the store failed, or the run already has 32 approvals pending for hops whose lease is not revoked (AuthZEN diagnostics `too many pending approvals for this run`). When an argument of the call copies a value or span of an untrusted result of the run (output labelling phase 2), the `-32008` data, and the data of every `-32003` denial the decision pipeline reaches once the run's leases are found live (`capability_denied`, `policy_deny`, `tool_not_in_catalog`, `budget_exhausted`, `approval_invalid` and the other decided reasons, `audit_error` included), add `untrusted_args: [{arg, seq, kind}]`: the argument, the `seq` of the `tool_result` record it matched (absent for kind `unreadable`) and the kind (`leaf`, `entity`, `kgram`, or `unreadable` when the run's index could not be read or the call's arguments carry more than 8,000 fingerprints in all). A lease denial (`lease_revoked`, `lease_expired`, `lease_unknown`) never carries it: the arguments are not matched then. Nor do the denials the proxy makes without asking the pipeline: a name it refuses up front (`invalid_name`, `tool_not_listed`), `label_error` and `session_mismatch`. A call over a run limit gets `-32003` with reason `budget_exhausted` and `data.limit: {hop, kind, arg, max, used}` (`arg` absent for `calls`, written `url#host` for a derived value; for `distinct`, `used` is how many values the limit has seen); `budget_error` means the counters could not be read or written, and `limit_arg_invalid` that the call lacks an argument a limit counts, or has a value it cannot count (a `sum` needs a non-negative integer, a `"derive": "host"` limit a URL of a special scheme or a bare host with a host and no backslash, whitespace or control character, and a `calls_per` or `distinct` list at most 256 values). No policy or approval passes these. For a call to a tool the catalog marks destructive or gives an `outbound` input, the `-32008` and `-32003` data also carry `usage: {calls, amount, destination_seen}`, the run's usage of the tool before this call as the policy saw it (`context.usage`): allowed calls of this server and tool by every hop of the run, the sum of the catalog's `amount` input over them, and whether the catalog's `destination` value, or a value of an `outbound` input, was seen in one of them. When some loaded policy reads a per-user window (run limits phase 3), `usage` also carries `user_window: {hour: {calls, amount}, day: {calls, amount}}`, the originating user's usage of the tool across all their runs in the current UTC hour and day; it is left out when all its figures are zero, which is also what a kind the server does not keep reads as. The decision record carries the same figures as `usage`, omitted for other tools; its `usage.user_window` names only the kinds the server keeps, each as `{start, calls, amount}` with `start` the window's start in Unix seconds UTC, and is absent when none is kept. If the answer to an allowed call cannot be recorded in the audit log, the agent gets `-32003` with reason `label_error` and the call's `decision_id` instead of the answer. A missing or bad token is HTTP 401 with `-32001` and `data.reason` set to `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce` or, for a lease that is no longer live, `lease_revoked`, `lease_expired` or `lease_unknown`. A request refused for its lease without a per-call decision (`initialize`, `tools/list`, `ping`, `resources/unsubscribe`, the other allowlisted methods, notifications, `GET` and `DELETE`) is also a `deny` record with that reason, the token's subject and chain, the proxied server, and `tool` set to the method (`http.POST` for a notification, `http.GET`, `http.DELETE`); its 401 carries the record's id in `X-Attenuo-Decision-Id` and `data.decision_id`. These records are bounded like listen-stream ends: the first refusal per delegation chain, tool and reason in `[proxy] record_window_seconds` (default 60 s) is recorded, and a retry within the window is still a 401 but writes no record, carries the first record's id (both are left out in the moment before a concurrent first record is written) and is counted in `audit_records_suppressed_total`. A refusal whose record could not be written (a failed audit append) names no decision id and opens no window, so the next one is recorded (SR-81). Refused exchanges and renewals, and `tools/call` denials, are recorded every time. A token that does not verify writes no record. An open stream (the `GET` listen stream, or a streamed answer) whose leases stop being live or whose token expires is ended within `[proxy] stream_recheck_seconds`: an SSE stream's last event is a JSON-RPC error with `id: null`, code `-32001`, `data.reason` (`lease_revoked`, `lease_expired`, `lease_unknown`, `token_expired`) and `data.decision_id`, the id of a `deny` record of tool `stream.end` with the session's hash tag. On the `GET` listen stream that record is written for the first such end per delegation chain and reason in `[proxy] record_window_seconds` (default 60 s); later ends in the window carry the same `decision_id` and are counted in `audit_records_suppressed_total` instead of recorded. A stream the client drops or the upstream ends writes no record; `GET` listen streams are counted by how they ended in `proxy_streams_ended_total`. An upstream the proxy cannot reach (connection refused, or not connected within `[proxy] upstream_connect_timeout_seconds`, default 5) is HTTP 502 with `-32005` and `data.reason` `upstream_unreachable`; the upstream URL and transport error are only logged. Nothing was sent, so a retry is safe. An upstream that accepts the request but does not send its response headers, or the rest of a JSON body the proxy must read (to filter a list or record a result), within `[proxy] upstream_response_timeout_seconds` (default 30) of sending is HTTP 504 with `-32005` and `data.reason` `upstream_timeout`. It is a separate reason because the request did reach the upstream, which may have acted on it: retry a call with side effects only if it is idempotent. A stream (SSE, the `GET` listen stream) whose headers arrived in time is never cut by that deadline. An upstream that answers a `GET` with a success status but not `text/event-stream` is HTTP 502 with `-32005` and `data.reason` `upstream_not_event_stream` (MCP allows only an SSE stream or `405` there); `405` and error answers to a `GET` are relayed. Allowed responses carry `X-Attenuo-Decision-Id`.

Other refusals of the proxy. Each also carries its stable code in `data.code` (listed under [Errors](#errors)); where the table says `data.reason` none, `data` holds only `code`: `unknown_server`, `session_unknown`, `invalid_request` and `parse_error`.

| HTTP status | JSON-RPC code | `data.reason` | When |
| --- | --- | --- | --- |
| 404 | `-32004` | none | no `[[upstreams]]` entry is called `server` |
| 404 | `-32600` | none | the `Mcp-Session-Id` is not bound (unknown or expired); start a new session |
| 400 | `-32600` | none | more than one `Mcp-Session-Id` header, or one that is not visible ASCII |
| 403 | `-32003` | `session_mismatch` | the session belongs to another principal; audited, with `X-Attenuo-Decision-Id` |
| 400 | `-32700` / `-32600` | none | the body is not JSON / not a JSON-RPC object or a non-empty batch |
| 413 | `-32600` | `request_too_large` | the body is over `[proxy] max_request_body_bytes` |
| 502 | `-32005` | `upstream_body_too_large` | an upstream body the proxy buffers is over `[proxy] max_upstream_body_bytes` |
| 503 | `-32006` | `session_registry_full` | no free session slot (`[proxy] max_sessions`), with `Retry-After: 30` |
| 429 | `-32007` | `too_many_sessions` | the principal holds `[proxy] max_sessions_per_principal` live sessions, with `Retry-After: 30` |
| 429 | `-32007` | `rate_limited` | the run (root lease) used up `[limits] mcp_requests_per_minute`, with `Retry-After` until its minute ends; counted after the token verified, never recorded |
| 503 | `-32006` | `overloaded` | `[limits] max_in_flight` requests are already being handled, with `Retry-After: 1` |

## Approvals

A call gated with `@obligation("approval")` gets an `approval_id` in its `-32008` error. A person decides it through one of these routes; the agent's own delegation token can read it but never decide it.

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /approvals/{id}` | an OIDC ID token of the run's originating user (`Authorization: Bearer`) | Body `{"decision": "grant" \| "decline"}`. Answers the approval as below. |
| `GET /approvals/{id}` | that user's ID token, or a delegation token of the same run whose leases are live (with a DPoP proof when bound) | The approval. Anyone else, including a hop whose lease was revoked or has expired, gets 404. |
| `GET /admin/approvals?chain_id&state&limit&cursor` | admin | Approvals newest first, optionally of one run (`chain_id`, the first hop's lease) and in one state; both filters apply before `limit`. `{"approvals": [...], "next_cursor": ...}`, paged as in [Paging](#paging): `limit` default 100, at most 500. Every approval is reachable. |
| `GET /admin/approvals/{id}` | admin | One approval. |
| `POST /admin/approvals/{id}` | admin, role `operator` or `admin` | Body as above; decides as the operator (`by = "operator"`, `approver.subject` the operator's subject). Also on the console listener with `[admin_ui] allow_write = true`. |

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
| `sub`, `by` | the approver (`sub` of the user, or `urn:attenuo:admin` for `[admin] token` and `urn:attenuo:admin:<name>` for a named operator), and `user` or `operator` |
| `chain_id`, `lease` | the run (its first hop's lease) and the lease of the hop that made the call |
| `ch` | the call hash, as in the `-32008` data |
| `iat`, `exp`, `jti` | when it was granted, the approval's `expires_at`, the approval id |
| `cnf.jkt` | the calling hop's key thumbprint, present only when its token is DPoP-bound |

Every answer for one grant carries the same token. To use it, retry the call with `"_meta": {"dev.attenuo/approval": "<token>"}` in the `tools/call` params (AuthZEN: `context.approval_token`). The server checks the signature, `typ` and `exp`, then that `chain_id`, `lease`, `ch` and `cnf.jkt` are the call's run, the calling hop's lease, the call hash and the hop's key binding, then consumes the approval named by `jti` once. Anything else is denied with `approval_invalid`; a value that is not a string is `-32602` at the proxy and 400 at AuthZEN. The consuming decision record has `approval: {id, by, presented: "token"}`. An external PEP can verify the token offline against the JWKS (`attenuo approval verify`, or the SDKs' `verify_approval_token` / `verifyApprovalToken`); only the server knows whether it was used already.

| Status | `error` | When |
| --- | --- | --- |
| 400 | `invalid_request` | `decision` is not `grant` or `decline` |
| 400 | `invalid_grant` (`error_description` `replayed`) | the ID token was already used to decide an approval |
| 401 | `unauthorized` (`error_description` `missing_token`) | no bearer |
| 401 | `invalid_token` (`detail` and `error_description` both carry the sub-code: `expired`, `audience_mismatch`, ...; the verifier's message is logged at debug level, never returned) | the ID token failed verification |
| 403 | `agent_token_refused` | a delegation token on `POST /approvals/{id}` |
| 403 | `wrong_user` | the ID token belongs to someone other than the run's originating user |
| 404 | `not_found` | unknown approval, or a delegation token of another run |
| 409 | `approval_not_pending`, `approval_expired`, `lease_revoked` | already decided or used, past `expires_at`, or the lease it is bound to is no longer live |
| 503 | `temporarily_unavailable` (`error_description` `replay_cache_full` or `replay_store_unavailable`) | the ID token's single use could not be recorded (too many in flight, or a database error); nothing was decided, retry |

## Admin

All admin routes need `Authorization: Bearer <admin token>`: the `[admin] token` or the token of an `[[admin.operators]]` entry ([config](config.md#admin), [ADR-0016](../decisions/0016-admin-operators.md)). They answer 401 without a bearer or with one that matches no credential (`missing_token`, `invalid_token`), 401 `admin_credential_expired` for an operator's token whose `expires_at` has passed (all three with `WWW-Authenticate: Bearer realm="attenuo-admin"`), 403 `admin_disabled` when no admin credential is configured, and 403 `admin_role_insufficient` when the credential's role is below the route's (`detail` names the role needed, never the token). Every admin answer, errors included, carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

Each route needs at least one role; a role includes the ones below it. The table is `attenuo_server::operators::ROUTE_ROLES`, and a route missing from it needs `admin`.

| Role | Routes |
| --- | --- |
| `viewer` | `GET /admin/whoami`, `GET /admin/leases/{lease_id}`, `GET /admin/leases/{lease_id}/tree`, every `GET /admin/audit...` route (`/admin/audit/checkpoint` included: it signs a checkpoint of the head when there is none, which records no new fact), `GET /admin/policies`, `GET /admin/policies/check`, `POST /admin/policies/evaluate` (a dry run that writes nothing), `GET /admin/approvals`, `GET /admin/approvals/{id}` |
| `operator` | `POST /admin/leases/{lease_id}/revoke`, `POST /admin/leases/revoke` (its `?preview=true` dry run included), `POST /admin/approvals/{id}` |
| `admin` | `POST /admin/budgets/refund`, `POST /admin/policies/reload`, `POST /admin/operators/reload`, `POST /admin/root-token` |

`[admin] token` is the operator `admin` with role `admin`. The audit log records an admin action with `originating_subject` `urn:attenuo:admin` for `[admin] token`, as before operators existed, and `urn:attenuo:admin:<name>` for a named operator; an approval decided by an operator has that subject as `approver.subject` and as the approval token's `sub`.

Where they are served: on the main listener by default; with `[admin] listen` set, on that listener only, and the main listener then answers every `/admin/...` path exactly as it answers an unknown path (404 with an empty body, whatever the method and bearer), so it does not reveal that an admin API exists. The admin listener serves these routes and nothing else (`/healthz` and `/readyz` stay on the main listener). Off a loopback `[server] listen` the server does not start with the admin routes on the main listener unless `[admin] serve_on_main_listener = true` ([config](config.md#admin)). The console listener (`[admin_ui]`) serves its own subset either way.

| Method and path | Purpose |
| --- | --- |
| `GET /admin/whoami` | The credential that sent the request, `{"name": "<operator>", "role": "viewer" \| "operator" \| "admin", "expires_at": "<RFC 3339>" \| null}` (`expires_at` is the operator entry's, null when it has none); `[admin] token` is `{"name": "admin", "role": "admin", "expires_at": null}`. Reads nothing else and records nothing. Also on the console listener. |
| `GET /admin/leases/{lease_id}` | Lease state. |
| `POST /admin/leases/{lease_id}/revoke` | Revoke the lease and all descendants. Body `{"reason": "..."}` (optional). Answers `{lease_id, revoked, reason, audit_id}`: `revoked` counts the leases that changed, `audit_id` is the `admin.lease.revoke` record (null when it could not be written; the revocation stands). The SDKs return it: Python `revoke_lease(...).audit_id`, TypeScript `(await revokeLease(...)).auditId`. |
| `POST /admin/leases/revoke?preview` | Revoke every lease of one originating user, one delegation chain or the chain that opened one MCP session, each with its descendants, in one transaction; `preview=true` is a dry run. See [Revoke by user or chain](#revoke-by-user-or-chain) and [Revoke by session](#revoke-by-session). |
| `GET /admin/leases/{lease_id}/tree?max_nodes` | The lease, its descendants and its ancestors, and how many leases a revoke would change now. Read-only; see [Lease tree](#lease-tree). 404 for an unknown lease. |
| `GET /admin/audit` | Audit entries, oldest first or with `order=desc` newest first, `{entries, next_cursor, head}` (`head` is the newest `seq`), paged as in [Paging](#paging): `limit` default 100, at most 1000. `from` and `to` select a `seq` range. Filters are below. |
| `GET /admin/audit/entries/{seq}` | One entry with its context, `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}` (below). 404 when there is no entry at `seq`. |
| `GET /admin/audit/records/{id}` | The same for the entry whose record id is `id`: the UUID that proxy denials and AuthZEN answers return as `decision_id`. 400 if `id` is not a UUID, 404 if no record has it. |
| `GET /admin/audit/checkpoints?limit&cursor` | Stored checkpoints, newest first, `{checkpoints, next_cursor}`; each is `{seq, head_hash, at, kid, signature}`. Paged as in [Paging](#paging): `limit` default 100, at most 1000. Read-only: it never signs, unlike `/admin/audit/checkpoint`. |
| `GET /admin/audit/verify` | Walk the whole hash chain, verify every checkpoint signature against the JWKS, and report `{entries, ok, first_bad_seq, checkpoints, last_signed_seq, unsigned_tail, bad_checkpoints}`. |
| `GET /admin/audit/checkpoint` | The signed checkpoint of the head, `{seq, head_hash, at, kid, signature}` (signing it now if the head has none). For keeping outside the host. `hash` repeats `head_hash` for older clients. |
| `GET /admin/audit/export?from&to` | Entries `from..=to` (default: the whole log) and the checkpoints in that range, streamed as `application/x-ndjson`: a `header` line, `entry` lines, then `checkpoint` lines. Verify offline with `attenuo audit verify --file`. `kind`, `chain_id`, `tool` and `decision` keep only the matching entries; the header then has a `filter` member naming them and the file cannot be verified. The SDKs take the same four: Python `audit_export(kind=, chain_id=, tool=, decision=)`, TypeScript `auditExport(from, to, { kind, chainId, tool, decision })`. 400 if `from` is 0 or `to < from`, for an unknown kind or decision, more than one kind, or an empty filter value. |
| `POST /admin/policies/reload` | Re-read the policy file. On failure the old policy stays. |
| `POST /admin/operators/reload` | Re-read `[[admin.operators]]`, and nothing else, from the config file the server was started with, and swap them in at once. See [Operators reload](#operators-reload). Also on the console listener with `[admin_ui] allow_write = true`. |
| `GET /admin/policies` | The policy set in force: file path, its `sha256` and `loaded_at` (startup or last successful reload), `policy_ids`, validation `warnings`, and `policies: [{id, text}]`. |
| `GET /admin/policies/check` | Lint the policy file as it is on disk now against the running schema, with line and column for each issue, and say whether it differs from the loaded one. Loads nothing, audits nothing. 409 `check_unavailable` without `policy.policies_path`. |
| `POST /admin/policies/evaluate` | Dry run: what the loaded policies decide for one call, given a token or a chain, and optionally the run-limit state to assume (`budget`). No lease check, no charge, no audit record, no decision metric. |
| `POST /admin/budgets/refund` | Body `{"decision_id": "<uuid>", "reason": "..."}`: give back to every run-limit counter what that decision charged, once, for an allowed call whose effect did not happen. Answers `{decision_id, refunded, reason, audit_id}` (`refunded` counts the token-limit counters credited; the run usage and the per-user windows the decision charged are returned too (each window to the window it was charged to, even one that has ended) but not counted, so a call that charged only usage answers 0; a `distinct` value is freed, and counted, only when no other unrefunded decision used it, SR-62) and appends an `admin.budget.refund` record. When there is nothing to refund, the audit log says why: 410 `charge_pruned` when the decision's record shows a run-limit charge whose charge-log entry was pruned, 404 `not_found` for a decision that charged nothing or an unknown id, 409 `already_refunded`; see [Budget refund](#budget-refund). Also on the console listener with `[admin_ui] allow_write = true`. |
| `POST /admin/root-token` | Development root mint. Mounted only when `[dev] allow_root_mint = true`, which refuses to start when the admin API's listener (`[admin] listen`, else `[server] listen`) is not a loopback address. |

### Console listener

The console listener (`[admin_ui] enabled = true`, [config](config.md#adminui)) serves the console's own files besides the admin routes above that it mounts. They need no bearer: the page asks for the admin token and sends it with each API call. Each file answers with `Cache-Control: no-cache` and a SHA-256 `ETag`, and `If-None-Match` with 304. An unknown file is 404 `not_found`.

| Method and path | Purpose |
| --- | --- |
| `GET /admin/ui/` | The console page. |
| `GET /admin/ui/{file}` | A file of the console (script, style sheet, icon). |
| `GET /` | Redirects (303) to `/admin/ui/`. |
| `GET /admin/ui` | Redirects (303) to `/admin/ui/`. |
| `GET /favicon.svg` | The favicon, the same file as `/admin/ui/favicon.svg`. |

### Operators reload

`POST /admin/operators/reload` (role `admin`, no body) re-reads the `[[admin.operators]]` array from the config file the server was started with (`--config` or `ATTENUO_CONFIG`), checks it with the startup rules ([config](config.md#adminoperators)) against the `[admin] token` in force, and puts it in force in one step. `[admin] token` (and `ATTENUO_ADMIN_TOKEN`) and the rest of the file are not reloaded, nor checked: only the operators are read, though the file must be TOML. Reloads run one at a time.

It answers `{"added": [...], "removed": [...], "changed": [...], "audit_id": "<uuid>"}`: operator names, never a digest, `changed` meaning a different role, `token_sha256` or `expires_at`. The `admin.operators.reload` audit record names the caller as `originating_subject` and has `{path, added, removed, changed}` as its arguments (kept as their digest, as for every record). A refused reload is recorded as a `deny` whose `reason` is the refusal's code.

- The caller's own entry may be removed or demoted: the request that does it completes, and the caller's next request is checked against the new list. Requests admitted before the swap complete as admitted.
- 422 `operators_no_admin`: the new list would leave no credential with role `admin` that has not expired (there is no `[admin] token` and no such operator). Refused so that a typo cannot lock everyone out until a restart.
- 422 `operators_invalid`: the file is not TOML, or an entry breaks a startup rule (a name, a duplicate, a digest, the `[admin] token` digest, an `expires_at` that does not parse, an unknown key or role). `detail` says which, and never quotes the file.
- 409 `reload_unavailable`: the server was not started from a config file (a program that builds its config in code and calls `serve`).
- 500 `config_unreadable`: the file cannot be read; the cause is in the server log only.

On every refusal the operators in force are unchanged. An entry whose `expires_at` has already passed is accepted, with a warning naming it, and its token is refused.

### Budget refund

`POST /admin/budgets/refund` works from the charge log, which keeps what each allowed call charged until `[leases] run_state_retention_seconds` after its run's leases are gone. When the charge log has no entry for `decision_id`, the server looks the decision up in the audit log, which is append-only and keeps every decision record, and answers by what the record shows:

| Status | `error` | When | `detail` |
| --- | --- | --- | --- |
| 410 | `charge_pruned` | an allowed decision whose record carries `budget` (it charged run-limit counters): its charge-log entry can only have gone by run-state pruning, so the charge, refunded or not, can no longer be refunded | ``the charge of decision `<id>` was pruned: its run's leases are gone and the charge is older than [leases] run_state_retention_seconds, so it can no longer be refunded (its audit record keeps what it charged)`` |
| 410 | `charge_pruned` | an allowed decision whose record carries `usage.user_window` but no `budget`: it charged per-user windows, which are deleted only by `[leases] user_window_retention_seconds` after their window ended, never at revocation | ``the per-user window charge of decision `<id>` was pruned: its window ended longer ago than [leases] user_window_retention_seconds, so it can no longer be refunded (its audit record keeps what the windows held)`` |
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

When the proxy binds a new MCP session (the upstream assigns an `Mcp-Session-Id`, normally in its answer to `initialize`), the server records the session's SHA-256, the upstream server name and the chain id of the caller (`RunState::record_session`; SQLite table `lease_sessions`). Only a request whose token and DPoP proof verified and whose leases are live can open a session, so nothing else can write a binding. The raw id is never stored; the session tag in audit records and logs is the first 12 hex characters of the same hash. A binding is write-once per session and server: the first chain is kept. It is deleted once its chain's root lease is revoked, or has been expired for longer than `[leases] session_retention_seconds` (default 86400), by a background pass every minute (see [config](config.md#leases)); a pruned session then resolves like one the server never saw.

`{"session": "<id>"}` hashes the id, looks up the chains recorded for it (one per upstream the session was opened with, normally one) and then behaves as `chain_id` for each of them, preview included. The answer's `selector` is `{"session_tag": "...", "chain_ids": [...]}`, never the raw id. A session the server has no record of (a wrong id, or one opened before the server recorded sessions) resolves to `chain_ids: []` and matches nothing: a 200 with empty lists, as for an unknown `chain_id`. The proxy's next request on a revoked session's chain is refused (HTTP 401 `lease_revoked` for `initialize`, `ping`, `tools/list` and session `GET`s; a `-32003` denial for `tools/call`).

### Lease tree

`GET /admin/leases/{lease_id}/tree` is a dry run of `POST /admin/leases/{lease_id}/revoke`: it shows what the revocation would reach and changes nothing (no lease row, no audit record).

- `nodes`: the lease first, then every lease delegated from it, breadth-first (each level in id order). At most `max_nodes` (default 1000, clamped to 1..10000); `truncated` is `true` when the cap cut the list short.
- `ancestors`: the leases it was delegated from, nearest first, ending at `root`, the chain's first hop. `root` is also the `chain_id` of the chain's audit records. Empty for a root lease.
- `would_revoke`: the leases in the whole subtree that are not revoked yet, counted with the same query the revocation runs, so it is the `revoked` count a revoke sent now would return. It ignores `max_nodes`.
- Per lease: the registry row (`parent`, `expires_at`, `revoked_at`, `revoke_reason`), `active` now, and from the audit record that issued it (`root_token` or `exchange`) the `agent` it was issued to, `issued_at` and `issued_seq`. These three are `null` when no issuance record is found.
- Per lease, `chain_id` and `subject`: the chain id, which is the same as `root` for every lease of the tree and is what `POST /admin/leases/revoke` takes as `chain_id`; and the originating user's subject the server recorded when it issued the lease, which that route takes as `user`. `subject` is `null` for a lease registered before the server recorded subjects. The subjects of the whole tree are read with one store call. `subject` is the IdP's `sub`, so treat it as untrusted text.
- Per lease, `budget`: the hop's run limits and what is left of them, `null` when the hop has no limits and nothing was charged under its lease. `{recorded, limits, usage}`: `recorded` says the server kept the hop's limits when it issued the token (a lease issued by an older server has counters but no `max`); `limits` has one entry per limit, `{cap, server, tool, kind, arg, max, used, remaining}` (`arg` is `null` for `calls` and `url#host` for a derived value; `used` is calls, the sum, for `distinct` the values seen, and for `calls_per` the most calls any one value has had, with `values` the number of values seen; `remaining` is `max - used`); `usage`, on a run's root lease, is the run's usage per destructive or outbound tool, `{tool, calls, amount, destinations}`. Value hashes are never shown. Calls are charged to every hop, so the smallest `remaining` along the chain is what a lease can still spend.
- `user_windows`: the per-user windows ([run limits phase 3](../design/run-limits-phase3.md)) of the run's originating user, read at `root`, for the tools the run used. `{windows, truncated}`: `windows` has one entry per tool in the root lease's `budget.usage` and per window kind a loaded policy reads (`context.usage.user_window.<kind>`), ordered by tool and then `hour` before `day`, each `{tool, kind, start, calls, amount}`. `start` is the start of the window that holds the current time, RFC 3339 in UTC; `calls` and `amount` are what every run of that user (the same issuer and subject) was allowed in that window, this run and the others. The list is empty when the run has no run usage (none yet, or the run was revoked, which deletes run usage but never a window) or no policy reads a window. It holds at most 10000 entries, the tree's node cap; `truncated` is `true` when it was cut there. `user_windows` is `null` for a run whose root lease was issued before the server recorded the originating user's issuer (schema version 4): a window is keyed by issuer and subject, and the server never guesses an issuer. The answer shows neither the issuer nor the keyed digest the store files windows under; the user is the `subject` already on the nodes. Reading the tree charges nothing.

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
  "truncated": false,
  "user_windows": {"truncated": false, "windows": [
    {"tool": "bank/send_money", "kind": "day", "start": "2026-10-23T00:00:00Z",
     "calls": 3, "amount": 120}]}
}
```

### Querying the audit log

`GET /admin/audit` takes these optional filters. Each is an exact match, never a pattern: `%` and `_` are ordinary characters, and `agent=l1` does not match an agent called `l10`. Filters combine with AND.

| Parameter | Keeps entries whose record has |
| --- | --- |
| `kind` | one of these kinds, comma-separated: `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin` |
| `decision` | `allow` or `deny` |
| `reason` | this `reason` (`policy_deny`, `lease_revoked`, ...) |
| `subject` | this `originating_subject` |
| `agent` | this agent among its `agents` |
| `lease` | this lease among its `leases` |
| `server`, `tool` | this `server`, this `tool` |
| `chain_id` | this `chain_id` (the lease id of the chain's first hop) |
| `since`, `until` | `at` in `[since, until)`, both RFC 3339 times |

Range and order:

- `from` and `to` (inclusive `seq`s, by default the whole log) select a range, as on `GET /admin/audit/export`. They are filters, not page links: send the same values with each cursor.
- `order=asc` (the default) reads the range oldest first; `order=desc` newest first. A cursor works only with the `order` it was issued for.
- Paging is as in [Paging](#paging). Oldest first, `next_cursor` is null once the page reached the head as it was when the page was read; to follow the log, ask again later with `from` just above the last `seq` seen (`attenuo audit tail --follow` does this).
- A filtered page reads at most 50,000 seqs (`agent`, `lease`, `since` and `until` cannot use an index). It can therefore come back short, even empty, with `next_cursor` set: keep following it until it is null. Unfiltered pages are never cut short.

An unknown `kind` or `decision`, a time that is not RFC 3339, an empty value, an unknown `order`, `from` or `to` of 0, `to` below `from`, or the removed `before` is a 400 `invalid_request`; a bad cursor is 400 `invalid_cursor`. The renewal history of a lease, for example, is `kind=lease_renew&lease=<id>`.

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
- An optional `usage`, `{"calls": 1, "amount": 10, "destination_seen": true}` (each member optional, 0 or false; the numbers non-negative integers), sets `context.usage` for the dry run; `user_window: {"hour": {"calls": n, "amount": n}, "day": {...}}` inside it sets the per-user windows (each kind and member optional, 0). Without it, the run's usage of a destructive tool, with its user's windows for the kinds a loaded policy reads, or of one with an `outbound` catalog input, is read from the store (all zero for any other tool), unless the server keeps no run usage at all (no loaded policy reads `context.usage`, the catalog names no `amount` or `destination`, and `[policy] track_usage` is not `true`): then the figures are zero and `usage.source` is `untracked`. With a `budget` (below) and no `usage`, the figures are zero and nothing is read. Anything else in `usage` is a 400 `invalid_request`.
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
| `telemetry_spans_dropped_total` | counter | none | Finished spans dropped before export (`[telemetry]`): the span queue was full or export had shut down. Always 0 with telemetry off. |
| `telemetry_export_failures_total` | counter | none | OTLP export requests that failed or timed out; their spans are not retried. |
| `leases_pruned_total` | counter | none | Leases deleted from the registry (with their recorded users and bindings) because every lease of their run was revoked or expired longer ago than `[leases] retention_seconds`. |
| `run_state_pruned_total` | counter | `kind` (`counters`, `charges`, `approvals`, `user_window`) | Run state deleted by `[leases] run_state_retention_seconds` once the leases it belongs to were gone from the registry: run-limit and run-usage counters, charge-log entries (one per charged decision) and approvals; and, as `user_window`, per-user window rows (windows and their logged charges) deleted by `[leases] user_window_retention_seconds` once their window had ended. |
| `audit_append_errors_total` | counter | none | Audit log appends that failed. |
| `audit_append_shed_total` | counter | `cause` (`queue_full`, `timeout`) | Audit appends that failed instead of waiting for the writer: `[audit] append_queue_max` appends were already waiting, or no answer came within `[audit] append_timeout_seconds`. Each denied its decision with `audit_error`. |
| `audit_checkpoints_total` | counter | none | Signed audit checkpoints written. |
| `audit_checkpoint_last_timestamp_seconds` | gauge | none | Unix time this process wrote the newest signed audit checkpoint; 0 when none. |
| `audit_sink_delivered_total` | counter | none | Signed checkpoints delivered off the host by `[audit.sink]`. |
| `audit_sink_failures_total` | counter | none | Deliveries by `[audit.sink]` that failed and will be retried. |
| `audit_sink_dropped_total` | counter | none | Checkpoints dropped from a full `[audit.sink]` queue before delivery. |
| `audit_sink_queue_depth` | gauge | none | Checkpoints waiting in the `[audit.sink]` queue. |
| `audit_sink_oldest_undelivered_timestamp_seconds` | gauge | none | Unix time the oldest undelivered checkpoint was queued; 0 when none. |
| `approval_notify_delivered_total` | counter | none | Approval notifications delivered by `[approvals.notify]`. |
| `approval_notify_failures_total` | counter | none | Approval notification deliveries that failed; each is retried until `max_attempts`. |
| `approval_notify_dropped_total` | counter | none | Approval notifications not delivered: dropped from a full queue, failed on every attempt, or not watched for expiry because 10,000 pending approvals already were. |
| `approval_notify_queue_depth` | gauge | none | Approval notifications waiting in the `[approvals.notify]` queue. |
| `approval_notify_outbox_rows` | gauge | none | Approval notifications stored in the outbox and not yet delivered or given up. Restored from the database at start. |
| `audit_wal_checkpoints_total` | counter | `result` (`complete`, `incomplete`, `error`) | Background WAL checkpoint rounds: `complete` left nothing in the WAL, `incomplete` left frames behind (a reader or the writer was in the way; the next commit starts another round). |
| `audit_wal_locked_passes_total` | counter | none | WAL catch-up passes run holding the store's lock, each pausing appends briefly (only when the WAL passes 64 MB under load). |
| `audit_wal_backstops_total` | counter | none | WAL checkpoints the audit writer ran itself because the WAL outgrew the backstop (128 MB): the background thread fell behind. |
| `audit_wal_presyncs_total` | counter | `file` (`wal`, `db`) | Syncs run off the request path: `wal` ahead of a signed checkpoint, `db` before a locked pass. |
| `audit_wal_frames` | gauge | none | Frames in the WAL at the last checkpoint pass. |
| `audit_wal_last_complete_timestamp_seconds` | gauge | none | Unix time the last complete WAL checkpoint round finished; 0 before the first. |
| `requests_shed_total` | counter | none | Requests answered `503` `overloaded` because `[limits] max_in_flight` requests were already being handled. `/healthz` and `/readyz` are never shed. |
| `requests_rate_limited_total` | counter | `limit` (`token`, `token_unauthenticated`, `mcp`, `authzen_search`), `cause` (`limit`, `table_full`) | Requests answered `429` by a `[limits]` rate limit: per agent, per peer address, per run, action searches per run; `table_full` when a new caller met `rate_limit_max_keys` callers inside their minute (for the per-peer limit, one that then authenticated no agent). |
| `request_timeouts_total` | counter | `kind` (`body`, `handler`) | Requests past a `[limits]` deadline: the body did not arrive within `request_body_timeout_seconds`, or no answer within `request_timeout_seconds`. |
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
| `taint_matches_total` | counter | `decision` (`allow`, `deny`) | Decisions on calls in a tainted run (destructive calls, or every call when a loaded policy reads `context.args_contain_untrusted` or `context.untrusted_args`) with at least one argument found in the run's untrusted results (or not checkable because the span index could not be read). |
| `proxy_streams_ended_total` | counter | `cause` (`token_expired`, `lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, `lease_other`, `recheck_unavailable`, `recheck_failed`, `client_disconnect`, `upstream_eof`, `upstream_error`) | `GET` listen streams the proxy relayed, counted once each when they end: cut by the re-check (the lease and token causes are also `stream.end` records, the `recheck_*` ones are not), dropped by the client, or finished or broken by the upstream. Streamed `POST` answers are not counted. |
| `audit_records_suppressed_total` | counter | `tool` (`stream.end`, or a lease refusal's `initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, `resources/unsubscribe`, `logging/setLevel`, `http.POST`, `http.GET`, `http.DELETE`), `reason` (`token_expired`, `lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, `lease_other`) | Records not written because the first record of the same delegation chain, tool and reason within `[proxy] record_window_seconds` (default 60 s) stands for them: listen-stream ends (`stream.end`, all six series always present) and lease refusals of requests without a per-call decision (a series appears once counted). Tool-call decisions, refused exchanges and renewals are never suppressed. |
| `proxy_list_entries_hidden_total` | counter | `reason` (`policy`, `not_in_catalog`, `invalid_name`) | `tools/list` entries the policy screen hid under `[proxy] list_filter = "policy"` (ADR-0011): no call to the tool could be allowed for the chain, the catalog lacks it under `unknown_tools = "deny"`, or its name breaks the name rule. All three series always present; zero with the default `list_filter`. Not audited: nothing was decided. |
| `run_lock_wait_seconds` | histogram | none | Time a decision waited for its run's lock (SR-55), from 1 us to 1 s, five buckets per decade. Only decisions on a hop with run limits or on a tool that keeps run usage take it, so `run_lock_wait_seconds_count` is the number of guarded decisions. |

The `audit_wal_*` series appear only when the background WAL checkpointer runs (a file-backed store with `[audit] wal_checkpoint_seconds` above 0, the default). Soft limits (a policy over `context.usage` or `context.budget` that asks for an approval) are not told apart from other `approval_required` decisions: the reason is the same and the deciding policy ids are not labels.
