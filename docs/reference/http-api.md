# HTTP endpoints

All routes the server mounts, from the route table in `crates/attenuo-server/src/lib.rs` and the proxy router. What may change before 1.0, and how a change is announced, is in [API compatibility](api-compatibility.md). Errors on non-MCP routes look like `{"error": "<error>", "code": "<code>", "detail": "<text>"}`; every error carries a stable `code`, listed under [Errors](#errors). The codes for `/token` are explained in [design/server.md](../design/server.md#error-codes).

A 401 for a bearer token (`/token/renew`, AuthZEN, `/admin/*`) is `{"error": "unauthorized", "code": "<reason>", "detail": "<reason>", "error_description": "<reason>"}`, where the reason is one of `missing_token`, `invalid_token` or `token_expired`. Why a token did not verify (wrong key, audience, issuer, malformed) is logged at debug level and never returned. A token bound to a key (DPoP, below) adds `dpop_required` and `invalid_dpop_proof`. A token bound to a TLS client certificate (below) adds `client_certificate_required`, `client_certificate_mismatch` and `dpop_with_certificate_binding`, as `{"error": "invalid_token", "code": "<reason>", ...}`. The same goes for a JWKS the server cannot fetch (503 `temporarily_unavailable`, sub-code `jwks_unavailable`): the URL and the transport error are logged, not returned. A hop-0 credential (ID token or ID-JAG) refused at `POST /token` is `400 invalid_grant` with the sub-code (`audience_mismatch`, `unknown_kid`, ...) as both `detail` and `error_description`; the verifier's message, which names the issuer, the audience or the `kid`, is logged at debug level. A refused `actor_token` is answered the same way, as `400 invalid_request` with its `actor_token_...` sub-code in both fields.

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
| `agents_invalid` | 422 |  |  | The reloaded config file does not parse, or its `[[agents]]` or `[[peps]]` break a startup rule; the agents and peps in force are unchanged. |
| `agents_reload_empties` | 422 |  |  | The reloaded config file has no `[[agents]]` (or no `[[peps]]`) while some are in force, as an empty or cut-off file has; refused unless `allow_empty` is sent. The agents and peps in force are unchanged. |
| `already_refunded` | 409 |  |  | The budget charge was already refunded. |
| `approval_expired` | 409 |  |  | The approval, or the lease it is bound to, has expired. |
| `approval_invalid` |  | `-32003` (200) | yes | A presented approval token does not verify, is for another call, or names an approval that is no longer granted. |
| `approval_not_pending` | 409 |  |  | The approval is already decided. |
| `approval_required` |  | `-32008` (200) | yes | The policy asks a person to approve this exact call first. |
| `approval_token_not_accepted` | 400 `invalid_request` |  |  | An AuthZEN action search carries `context.approval_token`; an approval token is spent only by the one decision it names. |
| `argument_case_mismatch` |  | `-32003` (200) | yes | A top-level call argument name differs only in case from a name the decision reads for the tool (its catalog entry, a constraint or run limit of a capability that covers it, a loaded policy), which an upstream that ignores case would read as that name. |
| `attribute_fixed_by_grant` | 403 |  |  | The root grant fixes this attribute; the request may not set it. |
| `attribute_type_mismatch` |  | `-32003` (200) | yes | An originating-user attribute does not have its declared type. |
| `audience_mismatch` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential's audience is not this server. |
| `audit_error` |  | `-32003` (200) | yes | The decision could not be written to the audit log (fail closed). |
| `audit_pruned` | 410 |  |  | The audit entries asked for were pruned (`[audit.retention]`); the body names the boundary. |
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
| `client_cert_header_malformed` | 400 `invalid_request` |  |  | On the `[server.forwarded_client_cert]` listener, `Client-Cert` or `Client-Cert-Chain` is not a well-formed RFC 9440 header: not one byte sequence, parameters, a repeated line, bad base64, too large, too many intermediates, a chain without a leaf, or not a certificate. |
| `client_cert_header_not_accepted` | 400 `invalid_request` |  |  | A `Client-Cert` or `Client-Cert-Chain` header was sent to a listener other than the `[server.forwarded_client_cert]` listener, while that section is set. |
| `client_certificate_mismatch` | 401 `invalid_token` | `-32001` (401) |  | The token is bound to a TLS client certificate (`cnf.x5t#S256`) and the request shows another certificate. |
| `client_certificate_required` | 401 `invalid_token` | `-32001` (401) |  | The token is bound to a TLS client certificate (`cnf.x5t#S256`) and the request shows none: a plain-HTTP listener, a TLS connection without a client certificate, or the gateway route. |
| `client_certificate_revocation_unknown` | 401 `invalid_client`, 401 `invalid_token` |  |  | A CA-issued TLS client certificate (`tls_client_auth`) whose entry has `tls_client_crl_paths` cannot be shown not revoked: the CRL of a CA in its path is stale under `tls_client_crl_stale = "refuse"`, or missing under `tls_client_crl_missing = "refuse"`. For a token bound to such a certificate, also any other failure of the entry's check (an expired certificate, a path that no longer builds). |
| `client_certificate_revoked` | 401 `invalid_client`, 401 `invalid_token` |  |  | A CA-issued TLS client certificate (`tls_client_auth`), or a CA certificate in its path, is listed by the CRL of its issuer in the entry's `tls_client_crl_paths`: at client authentication, and for a token bound to that certificate. |
| `client_crl_older` | 422 |  |  | An agents reload would put a CRL of a CA in force that is older than the one in force (an earlier `thisUpdate`, or a smaller or missing `cRLNumber`); the agents and peps in force are unchanged. |
| `client_id_mismatch` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential was issued to another client. |
| `config_file_mismatch` | 422 |  |  | The reloaded config file's `[issuer]` (its key files aside) or `[audit]` differs from the running config, so it may be another server's file; refused unless `allow_mismatch` is sent. The agents and peps, or the keys, in force are unchanged. |
| `config_unreadable` | 500 `server_error` |  |  | The config file the server was started with cannot be read, so the operators, the agents and peps, or the keys were not reloaded; the cause is in the server log only. |
| `credential_audience_mismatch` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The ID token was not issued to the presenting agent: its `aud` or `azp` names another client. |
| `credential_expired` | 400 `invalid_grant` |  |  | The hop-0 credential expires before the token could be issued. |
| `credential_pop_mismatch` | 400 `invalid_grant` |  |  | The DPoP proof is by another key than the one the ID-JAG is bound to (`cnf.jkt`). |
| `credential_pop_required` | 400 `invalid_grant` |  |  | The ID-JAG is bound to a key (`cnf`) and the request has no DPoP proof that this server checks. |
| `credential_type_not_accepted` | 400 `invalid_grant` |  |  | The credential's issuer is an `[[idps]]` entry whose `credentials` does not list this kind (an ID token or an ID-JAG). |
| `dpop_liveness_stale` | 503 `temporarily_unavailable` | `-32006` (503) |  | The server cannot keep its liveness marker ahead of its clock (a database write fails), so it accepts no DPoP proof; retry later. |
| `dpop_replay_cache_full` | 503 `temporarily_unavailable` | `-32006` (503) |  | Too many DPoP proofs are in flight; retry later. |
| `dpop_required` | 401 | `-32001` (401) |  | The token is bound to a key and no DPoP proof was sent. |
| `dpop_with_certificate_binding` | 400 `invalid_request`, 401 `invalid_token` | `-32001` (401) |  | A DPoP proof (or the `DPoP` scheme) came with a token that is bound to a TLS client certificate, or with a `POST /token` request whose new token is bound to one: a token has one binding. |
| `duplicate_actor` | 400 `invalid_request` |  |  | The `actor` is already in the chain. |
| `expired` | 400 `invalid_grant`, 401 `invalid_token` |  |  | The credential has expired. |
| `ext_authz_ambiguous_body` |  | `-32600` (400) |  | A gateway forwarded a body with a duplicate member, two member names that differ only in case, or a number not written as it is read (`/ext-authz/v1/mcp/{server}`). |
| `ext_authz_batch_unsupported` |  | `-32600` (400) |  | A gateway forwarded a JSON-RPC batch, which `/ext-authz/v1/mcp/{server}` does not decide. |
| `ext_authz_body_incomplete` |  | `-32600` (403) |  | A gateway did not send the whole body (`x-envoy-auth-partial-body` is not `false`). |
| `ext_authz_dpop_url_unset` |  | `-32001` (401) |  | A DPoP proof came through a gateway route whose `[[ext_authz]]` entry has no `dpop_url`. |
| `ext_authz_unauthenticated` |  | `-32001` (403) |  | A request to `/ext-authz/v1/mcp/{server}` lacks the `[[ext_authz]]` entry's gateway secret. |
| `forwarded_peer_not_trusted` | 403 |  |  | A connection to the `[server.forwarded_client_cert]` listener came from an address that is not in `trusted_peers`; every request on it is refused, before routing. |
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
| `key_duplicate` | 422 |  |  | A keys reload: two of the key files hold the same key (the signing key listed in `previous_key_paths` too, or a retired key twice); the message names both files and the `kid`. The keys in force are unchanged. |
| `key_file_invalid` | 422 |  |  | A keys reload: a key file holds no Ed25519 key of the kind wanted (a key of another type or curve, a public key as the signing key, no PEM block, a damaged one); the message names the file, never its content. The keys in force are unchanged. |
| `key_file_unreadable` | 422 |  |  | A keys reload: a key file named in `[issuer]` cannot be read (missing, no permission, not text); the message names the file. The keys in force are unchanged. |
| `keys_config_invalid` | 422 |  |  | A keys reload: the config file does not parse, or sets no `[issuer] private_key_pem_path` (a reload never generates a key). The keys in force are unchanged. |
| `keys_reload_drops_audit_key` | 422 |  |  | A keys reload would leave out of the verifying keys a key that signed an audit checkpoint or anchor the log holds, or that signs them now, so `audit verify` would fail; refused unless `allow_drop_audit_key` is sent. The keys in force are unchanged. |
| `keys_reload_drops_current` | 422 |  |  | A keys reload names a new signing key and leaves the current one out of `previous_key_paths`, so every token it signed would stop verifying at once; refused unless `allow_drop_current` is sent. The keys in force are unchanged. |
| `label_error` |  | `-32003` (200) | yes | The call's result could not be recorded, so it is withheld. |
| `lease_error` |  | `-32001` (401), `-32003` (200) | yes | The lease store could not be read (fail closed). |
| `lease_expired` | 400 `invalid_grant` | `-32001` (401), `-32001` (200), `-32003` (200) | yes | A lease of the chain has expired (at `POST /token` and `POST /token/renew`, an ancestor lease of the token). |
| `lease_revoked` | 409, 400 `invalid_grant` | `-32001` (401), `-32001` (200), `-32003` (200) | yes | A lease of the chain (at `POST /token` and `POST /token/renew`, the token's own lease or an ancestor's), or the one an approval is bound to, has been revoked. |
| `lease_unknown` | 400 `invalid_grant` | `-32001` (401), `-32001` (200), `-32003` (200) | yes | A lease of the chain is unknown to the lease store (fail closed); at `POST /token` and `POST /token/renew`, the token's own lease or an ancestor's. |
| `limit_arg_invalid` |  | `-32003` (200) | yes | The call lacks an argument a run limit counts, or has a value it cannot count. |
| `limit_conflict_at_root` | 400 `invalid_scope` |  |  | The hop-0 request (an IdP credential at `POST /token`, or `POST /admin/root-token` when `[[root_grants]]` is set) has a capability under one or more limited capabilities of the root grant or of the ID-JAG's claims (each covers its calls), and their limits, or its own and theirs, set one kind of limit on different arguments, which one capability cannot carry together; ask for a capability fewer of them cover. A conflict with the request's own limit is `scope_exceeds_grant` (or `scope_exceeds_id_jag`) instead when attenuation clamps the capability to the limited capability it conflicts with (SR-132). |
| `limit_split_at_root` | 400 `invalid_scope` |  |  | The hop-0 request (an IdP credential at `POST /token`, or `POST /admin/root-token` when `[[root_grants]]` is set) has two capabilities under the same limited capability of the root grant or of the ID-JAG's claims (it covers the calls of both, whether or not it is the one each takes its limits from); ask for one capability with a `one_of` or wider constraint instead. |
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
| `prune_archive_mismatch` | 409 |  |  | The archive a prune request describes (`from`, `through_hash`) is not the prefix the prune removes, or not the one a repeated prune was made with. |
| `prune_conflict` | 409 |  |  | The log was already pruned through this seq with another archive digest. |
| `prune_disabled` | 409 |  |  | `[audit.retention] prune` is `"off"`: the audit log is not pruned. |
| `prune_in_progress` | 409 |  |  | The rows of an earlier prune are still being deleted. |
| `prune_live_run` | 409 |  |  | A run still in the lease registry has entries at or below the requested boundary. |
| `prune_not_at_checkpoint` | 409 |  |  | The requested boundary is not a signed checkpoint that matches the log. |
| `prune_too_recent` | 409 |  |  | The entry at the requested boundary is younger than `[audit.retention] min_age_seconds`. |
| `rate_limited` | 429 | `-32007` (429) |  | A rate limit is used up; retry after `Retry-After`. |
| `reload_unavailable` | 409 |  |  | The policy, the admin operators, the agents and peps, or the issuer keys cannot be reloaded in this configuration (no policy file; a server not started from a config file). |
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
| `sink_behind` | 409 |  |  | The checkpoint sink is degraded or has not delivered the checkpoint at the requested boundary. |
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

Every route that returns a list a client may need to read past one answer pages the same way: `GET /admin/audit`, `GET /admin/audit/checkpoints`, `GET /admin/audit/anchors` and `GET /admin/approvals`.

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
- **Errors.** 401 `dpop_required` (no proof where one is needed), `invalid_dpop_proof` (wrong key, method, URL or `ath`, `iat` more than `[token] dpop_max_age_seconds` behind or `dpop_future_skew_seconds` ahead of the server's clock, `iat` from before a restart, replayed `jti`, bad signature, several `DPoP` headers) or `use_dpop_nonce` (a valid proof without a current server nonce; retry with the response's `DPoP-Nonce`), with `WWW-Authenticate: DPoP error="…", algs="EdDSA ES256"`. The proxy uses JSON-RPC `-32001` with the same `data.reason`. A full replay cache is 503 `temporarily_unavailable` with `error_description` `dpop_replay_cache_full`; a server that cannot write its liveness marker answers 503 `dpop_liveness_stale`.
- `htu` is `[server] public_url` plus the path, or `http://<Host>` plus the path when `public_url` is unset. The query is not compared.

### Certificate-bound tokens

Optional, RFC 8705 section 3, off by default (`[token] tls_client_certificate_bound_access_tokens`). See [binding tokens to a TLS client certificate](../guides/binding-tokens-to-keys.md#binding-tokens-to-a-tls-client-certificate) and [ADR-0022](../decisions/0022-certificate-bound-tokens.md).

- **Binding.** With the setting on, a token `POST /token` issues to an agent that authenticated with its TLS client certificate is bound to it: `cnf` is `{"x5t#S256": "<base64url SHA-256 of the certificate>"}` and the response says `"token_type": "Bearer"`. A `cnf` holds one binding: a token is never bound to a key and a certificate. A `DPoP` header on such a request is 400 `invalid_request` / `dpop_with_certificate_binding`. A child of a certificate-bound token is bound to the same certificate; the exchange must show that certificate and carry no `DPoP` header and no `subject_token_dpop`.
- **Use.** A certificate-bound token is accepted only on a request whose verified client certificate (attenuo's own handshake, or the forwarding listener's `Client-Cert` from a trusted peer) is the same one, on every route that takes a token: `/mcp/{server}`, `/token/renew`, `/access/v1/evaluation(s)`, `/access/v1/search/action`, `GET /approvals/{id}` and `/token` (as `subject_token`). Send `Authorization: Bearer <token>` and no `DPoP` header. `/ext-authz/v1/mcp/{server}` sees no agent certificate and refuses such tokens.
- **Errors.** 401 `invalid_token` with `code` `client_certificate_required` (no certificate on the request), `client_certificate_mismatch` (another certificate) or `dpop_with_certificate_binding` (a `DPoP` header or the `DPoP` scheme). When the bound certificate carries the name of an `[[agents]]` entry with CRL files, it must also pass that entry's check: else `client_certificate_revoked` or `client_certificate_revocation_unknown` (on `/mcp/{server}`, `client_certificate_required`); see [CRL files](config.md#crl-files). The proxy uses JSON-RPC `-32001` with the same `data.reason`. At `POST /token`, a certificate-bound `subject_token` without its certificate, or with another one, is 401 too, on purpose: a key-bound `subject_token` without its proof is 401 `dpop_required` there, and the two bindings answer alike. A `DPoP` header or `subject_token_dpop` with a certificate-bound `subject_token` is 400 `invalid_request` / `dpop_with_certificate_binding`, as at issue: the request asks for a second binding. None of these use up a client assertion: they are decided before it is recorded.

Every route of the main listener is subject to [`[limits]`](config.md#limits): a request that finds `max_in_flight` requests already running is `503` `temporarily_unavailable` with `error_description` `overloaded` and `Retry-After: 1` (never `/healthz` or `/readyz`); a body that does not arrive within `request_body_timeout_seconds` is `408` `request_timeout`; a route other than `/mcp/{server}` and `/admin/*` that does not answer within `request_timeout_seconds` is `503` with `error_description` `request_timeout` and `Retry-After: 1`. With the rate limits on, `POST /token` over `token_requests_per_minute` (per agent) or `token_unauthenticated_requests_per_minute` (per peer address), and `POST /access/v1/search/action` over `authzen_search_requests_per_minute` (per run, the chain's root lease, also for a PEP's unsigned chain), are `429` `rate_limited` with `Retry-After`; AuthZEN evaluation and batch evaluation are not rate limited (each decision is audited). When the per-peer table is full, a request from an address not in it that carries client credentials is authenticated first: an agent that authenticates is served, and anything else gets the same `429` (see [`[limits]`](config.md#limits)). Headers that take longer than `header_read_timeout_seconds` to arrive get the connection closed. The SDKs raise the `503` as Python `Unavailable` / TypeScript `UnavailableError` and the `429` as `RateLimited` / `RateLimitedError`, with `reason` and the `Retry-After` seconds, never as a denial; the `408` stays a plain `ApiError`. They retry `overloaded` and `rate_limited` only when the client is built with `max_retries` / `maxRetries`, never `request_timeout`.

## Client authentication

An agent (on `POST /token`) or a PEP (on the AuthZEN endpoints) proves who it is in one of four ways, decided by what its `[[agents]]` or `[[peps]]` entry holds ([config](config.md#agents)):

- **Client secret.** `client_id` / `client_secret` in the body (`pep_id` / `pep_secret` for a PEP), or HTTP Basic. The entry holds `secret_sha256`.
- **Client assertion** (`private_key_jwt`, RFC 7523 §2.2). The body carries `client_assertion_type` = `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, a JWT the client signs with a private key whose public half is in the entry's `jwks`, or in the key set the client publishes at the entry's `jwks_url` ([keys from a URL](config.md#keys-from-a-url)). `client_id` (or `pep_id`) may be sent too and must then equal the assertion's `sub`. The CLI makes one with `attenuo token exchange --client-key`, the SDKs with `DpopKey.client_assertion` / `clientAssertion`.
- **TLS client certificate** (`self_signed_tls_client_auth`, RFC 8705 §2.2). The client sends a self-signed certificate in the TLS handshake of attenuo's own listener (`[server.tls] client_certificates = "optional"`) and names itself with `client_id` (`pep_id` for a PEP) in the body, with no secret, no Basic header and no assertion. The entry holds the certificate's SHA-256 in `tls_client_cert_sha256` ([TLS client certificates](config.md#tls-client-certificates)). The CLI sends one with `--tls-client-cert` and `--tls-client-key` ([CLI](cli.md#global-options)). The Python and TypeScript SDKs send one with `tls_client_cert` and `tls_client_key` (TypeScript: `tlsClientCert` and `tlsClientKey`) ([identity providers](../guides/identity-providers.md#tls-client-certificates)).
- **TLS client certificate from a CA** (`tls_client_auth`, RFC 8705 §2.1). The same request, but the certificate is issued by a CA. The entry holds the CA file in `tls_client_ca_pem_path` and the name the certificate must carry in `tls_client_auth_san_uri` (such as a SPIFFE ID) or `tls_client_auth_san_dns` ([TLS client certificates from a CA](config.md#tls-client-certificates-from-a-ca)). The client sends its intermediate CA certificates in the handshake too.

A request uses one way only: Basic and a body credential, or a secret and an assertion, is 400 `invalid_request` / `multiple_client_auth` (RFC 6749 §2.3). A certificate on the connection is not a second credential: when the request also carries a secret, Basic or an assertion, that one decides and the certificate is ignored, so a wrong secret is refused even if the certificate is pinned. Sending only one of the two assertion fields is `malformed_request`; another `client_assertion_type` is 400 `client_assertion_type_unsupported`.

A request with no credential at all (no secret, no assertion, and at `POST /token` no `actor_token`) is 401 `invalid_client` (RFC 6749 §5.2), with `WWW-Authenticate: Basic realm="attenuo"`: `client_auth_missing`, or `actor_token_required` when `[token] actor_auth = "actor_token"`. Both are decided before any agent or PEP is looked up, so the answer is the same for a known and an unknown client id or `actor` (SR-110).

An assertion is accepted when all of this holds, checked in this order:

| Check | Refusal (`error_description`) |
| --- | --- |
| a compact JWS whose `typ`, if present, is not that of another token kind (`attenuo+jwt`, `at+jwt`, `dpop+jwt`, `oauth-id-jag+jwt`) | `client_assertion_malformed` |
| `iss` and `sub` are both the client id (and equal `client_id` when it is sent) | `client_assertion_subject_mismatch` |
| `alg` is RS256, ES256 or EdDSA, and `kid`, if present, is a string | `client_assertion_unsupported_alg`, `client_assertion_malformed` |
| the client exists and has `jwks` or `jwks_url` (whose key set can be fetched); `kid` names one of its keys (it may be left out only when the set has one key); that key is for `alg`; and the signature verifies with it | `client_authentication_failed` |
| `aud` is `[issuer] issuer`: that string, or an array holding only it | `client_assertion_audience_mismatch` |
| `exp` and `jti` are present, `jti` at most 256 bytes | `client_assertion_missing_claim` |
| `exp` has not passed and is at most `[token] client_assertion_max_lifetime_seconds` ahead; `nbf` and `iat`, if present, are not in the future; all with `[token] client_assertion_clock_skew_seconds` of leeway | `client_assertion_expired`, `client_assertion_lifetime_too_long`, `client_assertion_not_yet_valid` |
| the `jti` has not been used by this client before | `client_assertion_replayed` |

All of them are 401 `invalid_client` with `WWW-Authenticate: Basic realm="attenuo"`, as a wrong secret is. The answer never echoes the assertion. Until the signature has verified, a caller holding none of the client's keys learns nothing about the entry: an unknown client id, an entry without keys, an unknown `kid`, a key of another algorithm, a bad signature and a `jwks_url` whose key set cannot be fetched (or is refused) are one answer, `client_authentication_failed` with the same `detail`, as an unknown id or a wrong secret is on the secret path (SR-110). The specific reason is in the server's log at debug level (`client assertion refused`, `reason` = `unknown_client`, `client_without_keys`, `unknown_kid`, `key_alg_mismatch`, `bad_signature` or `jwks_unavailable`). A key set that cannot be fetched is also logged at warn level, `client JWKS unavailable`, with the client, the URL and the cause, once per failed fetch. At the AuthZEN endpoints a PEP's key set is fetched only after the bearer has been checked, so a request with a bad bearer, or with none while `[authzen] allow_unsigned_chain` is off, makes no fetch. So a client whose URL is down gets a 401, not the 503 `jwks_unavailable` an IdP's keys get: a 503 would tell any caller which ids exist and take their keys from a URL. The checks after the signature keep their own codes, because only a holder of the key can reach them and they say what to fix. The checks before the lookup (`typ`, `iss` and `sub`, `alg`, a `kid` that is not a string) do not depend on whether the client exists. The `aud` rule is strict on purpose: the token endpoint URL is not accepted, so an assertion made for one server cannot be replayed at another that shares a URL prefix or proxy (the audience-injection concern behind RFC 7523bis). The `jti` is recorded in the replay store (`used_credentials`, the store that ID tokens, ID-JAGs, actor tokens and exchanges use; DPoP proofs are not kept there) until `exp` plus the skew, so it stays spent across a restart; it is spent when the client authenticates, even if the request is then refused for another reason, so send a fresh assertion with every request. Two refusals come before that and leave the assertion unspent, because the client is told to send the same request again: `429` `rate_limited` from `[limits] token_requests_per_minute`, and a `DPoP` header proof that is refused (`use_dpop_nonce` under `[token] dpop_nonce = "required"`, `invalid_dpop_proof`, or 503 `dpop_liveness_stale`). A full or unavailable replay store is 503, as for DPoP.

A self-signed certificate is accepted when the entry `client_id` (or `pep_id`) names lists its SHA-256 in `tls_client_cert_sha256`, and the certificate is usable as a client certificate at that moment: within its dates, not a CA certificate, `clientAuth` in its extended key usage if it has one, and signed by its own key. The thumbprints are compared in constant time, and an unknown id makes the same comparisons. Every refusal is one answer, 401 `invalid_client` / `client_authentication_failed` with the same `detail`, as an unknown id or a wrong secret (SR-110). The reason is logged at debug level only (`TLS client certificate refused`, `reason` = `unknown_client`, `no_certificate_settings`, `thumbprint_mismatch`, `certificate_expired`, `certificate_not_yet_valid` or `certificate_not_usable`). A request that names a client and carries a certificate counts as one with client credentials for `[limits] token_unauthenticated_requests_per_minute` on a full table (SR-109). The certificate comes from attenuo's own handshake (`[server.tls]`), or, on the [`[server.forwarded_client_cert]`](config.md#serverforwardedclientcert) listener only, from the RFC 9440 `Client-Cert` and `Client-Cert-Chain` headers a trusted proxy sends (see [Forwarded certificates](#forwarded-certificates) below). `X-Forwarded-Client-Cert` and similar headers are never read. The token is not bound to the certificate: it is a bearer or DPoP-bound token as before.

A certificate from a CA is accepted when the entry `client_id` (or `pep_id`) names has `tls_client_ca_pem_path`, the certificate chains to one of that file's CAs through the intermediates the client sent, it is usable for client authentication at that moment (its dates and those of the intermediates, not a CA certificate, `clientAuth` in its extended key usage if it has one), and it carries the entry's name: the `tls_client_auth_san_uri` exactly (for a SPIFFE ID, as its only URI SAN), or the `tls_client_auth_san_dns` without regard to case and never through a wildcard. A certificate that also carries the name of another entry of the same list (agents or PEPs) is refused; an agent and a PEP may share a name. The subject DN, IP and e-mail names are not matched. There is no OCSP check, and CRLs are checked only from the entry's [CRL files](config.md#crl-files). Every refusal is the same answer as above, except a CRL refusal for a certificate whose path and name match the entry: `client_certificate_revoked` (a CRL lists it, or a CA in its path) or `client_certificate_revocation_unknown` (a CRL it needs is stale or missing), logged at info level. The debug log line `TLS client certificate refused` has `reason` = `chain_invalid`, `certificate_expired`, `certificate_not_yet_valid`, `certificate_not_usable`, `uri_san_count`, `san_mismatch`, `certificate_names_several_clients` or `too_many_intermediates`, and the certificate's names, escaped.

The client may send at most 4 certificates after its own; with more, the certificate is refused (`too_many_intermediates`). The chain check costs CPU before the client is authenticated, on certificates the client chose. What bounds it: the 4; of those, only one per subject is used, and copies of the client's certificate and self-issued ones are dropped, so each step of the path has at most one intermediate to try; at most 16 CAs in the file; rustls-webpki's own limit of 100 signature checks per check; and the answer is kept per connection, for the CA file in force and the name, until the earliest `notAfter` of the certificates kept. A request on a new connection pays the check again. On the forwarding listener the answer is kept per certificate instead, under the same rules, for requests that forward exactly the same certificate and intermediates (at most 256 certificates, the oldest dropped first). `[limits] token_unauthenticated_requests_per_minute` is off by default and does not cover the AuthZEN endpoints a PEP calls, so it does not bound this cost; `[limits] max_in_flight` bounds how many run at once. Checking a chain takes longer than refusing an unknown id, so the time of the answer can show which ids have a CA file; the answer itself is the same.

The method shows in the server log and in the audit record's arguments: `agent_auth` at hop 0 and `actor_auth` at later hops are `client_secret`, `private_key_jwt`, `self_signed_tls_client_auth`, `tls_client_auth`, `actor_token`, or `actor_token+client_secret` / `actor_token+private_key_jwt` / `actor_token+self_signed_tls_client_auth` / `actor_token+tls_client_auth` with `[token] actor_auth = "either"` (and `none` for an unauthenticated later hop when `[token] require_actor_auth = false`). A request authenticated by a certificate (either kind) also carries `client_cert` = `{"x5t#S256": "<base64url SHA-256>", "source": "tls"}` in those arguments (`"source": "forwarded"` for a certificate from the forwarding listener); other records digest exactly as before. An issuance that bound the new token to the certificate also carries `"cert_bound": true` in its arguments and in the record.

### Forwarded certificates

With [`[server.forwarded_client_cert]`](config.md#serverforwardedclientcert) set, attenuo opens one more plain-HTTP listener for a TLS-terminating proxy ([ADR-0021](../decisions/0021-forwarded-client-certificates.md), [deploying](../guides/deploying.md#forwarded-client-certificates)). It serves only `POST /token`, `POST /token/renew`, `POST /access/v1/evaluation`, `POST /access/v1/evaluations`, `POST /access/v1/search/action`, `/mcp/{server}`, `/approvals/{id}`, `GET /.well-known/jwks.json`, `GET /.well-known/authzen-configuration`, `GET /healthz` and `GET /readyz`. Every other path, `/admin/*` and `/ext-authz/v1/mcp/{server}` included, answers 404 with an empty body there, for every method, as an unknown path does.

- A connection from a TCP peer address not in `trusted_peers` gets 403 `forwarded_peer_not_trusted` for every request, before routing, with `Connection: close`. `X-Forwarded-For` and `Forwarded` play no part.
- On that listener, `Client-Cert` (one RFC 8941 byte sequence) and the optional `Client-Cert-Chain` (a list of at most 4 byte sequences) are read and then removed from the request. Anything not well formed, an empty `Client-Cert` too, is 400 `invalid_request` / `client_cert_header_malformed`, with one fixed `detail` that never repeats the header. A good certificate then goes through exactly the checks above, with the same answers.
- On every other listener (main, admin, console, metrics), a request with either header is 400 `invalid_request` / `client_cert_header_not_accepted`. Without the section, the headers are ignored as before.
- The 400 and 403 refusals are logged at warn level with the peer address, at most once per 10 seconds each; the rest at debug.
- `[limits] token_unauthenticated_requests_per_minute` counts there in one bucket per proxy address. Over its limit, `/token` is `429` up front, except a request whose only credentials are a forwarded certificate and `client_id` (no secret, assertion, Basic credentials or actor token): it runs, and is `429` afterwards if the certificate authenticated nobody.

## Public

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | Liveness. Never touches storage. |
| `GET /readyz` | none | Readiness. Checks the audit store and the lease store, and whether the last audit append failed. 200 `{"ready":true,"checks":{"audit":"ok","audit_append":"ok","leases":"ok"}}` or 503 with `"error"` for the failing check and no error text. `checks.audit_append` is `"error"` from a failed audit append (a full disk, for example, while reads still work) until the next append succeeds, or for at most 30 s when no append is made after it; no probe is written. With `[audit.sink]` the body also has `"degraded"` and `checks.checkpoint_sink` (`"ok"` or `"degraded"`); a degraded sink is a 503 only with `fail_readiness = true`. With `[approvals.notify]` it also has `checks.approval_notifier` (`"ok"` or `"degraded"`), which sets `"degraded"` but never makes the answer a 503, and with `[leases.notify]` `checks.lease_notifier` on the same rule. Right after a quick restart, while the DPoP restart fence refuses proofs made now (at most about 21 s with the defaults), it is a 503 with `checks.dpop_restart_fence` `"fenced"`; the member is absent otherwise. |
| `GET /.well-known/jwks.json` | none | Public keys for token verification, including retired keys. |
| `GET /.well-known/authzen-configuration` | none | AuthZEN discovery (AuthZEN 1.0 section 9): `policy_decision_point`, `access_evaluation_endpoint`, `access_evaluations_endpoint` and `search_action_endpoint`, and nothing else; no subject or resource search endpoints, which are not served, and no `capabilities` or `signed_metadata` ([why](authzen.md#discovery)). Public metadata: no credential is needed and an `Authorization` header is ignored ([why](authzen.md#discovery)). The URLs are built from `[server] public_url`. Without it (loopback only) from `Host`, which must be `localhost`, `127.0.0.1` or `[::1]`; anything else is 400 `invalid_host`. |

## Token

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /token` | agent client credentials (a secret, a [client assertion](#client-authentication) or a TLS client certificate) at hop 0; at later hops the parent token, plus the actor's client credentials or an `actor_token` | RFC 8693 token exchange, as a form or JSON. Hop 0 takes an OIDC ID token or an ID-JAG. Later hops take a parent delegation token and `authorization_details`. Optional `may_act` (agent ids) sets who may exchange the new token next. A `DPoP` header binds the new token to a key (`token_type` `DPoP`); `subject_token_dpop` is the parent key's sign-off, naming the new key and `actor`, when the parent is bound to another key. With [certificate-bound tokens](#certificate-bound-tokens) on, an agent that authenticated with its certificate gets a token bound to it (`token_type` `Bearer`). |
| `POST /token/renew` | bearer delegation token (and a DPoP proof if it is bound) | Extend the lease of the token's last hop. Returns `{lease, expires_at, expires_in}`. A refusal of a token that verified is audited (below). |

A capability may carry run `limits` (`calls`, `sum: {arg, max}`, `calls_per: {arg, max}`, `distinct: {arg, max}`; [run limits](../design/server.md#run-limits)). `distinct` allows at most `max` different values of `arg`. `calls_per` and `distinct` may add `"derive": "host"` to count the host of a URL argument instead of the whole value (`{"arg": "url", "derive": "host", "max": 2}`). A value with no scheme is a bare host and is read as `http://` followed by the value, so `www.example.com/x` counts host `www.example.com` and `localhost:8080` counts `localhost`. A child must keep every limit of the parent capability that covers it, on the same argument and derivation, at most as large (`calls: m` also satisfies a parent's `calls_per` or `distinct` with `max >= m`); one it leaves out or asks larger is filled in or lowered (a `sum`, `calls_per` or `distinct` over another argument or derivation is refused as not covered), and its `calls` and `sum` are lowered further to what the parent hop has left. An unknown limit kind or derivation does not parse: 400 `invalid_request` (at `POST /token`, with `code` `malformed_request`). A limit that parses but is malformed (`derive` on a `sum`, an empty `arg`, a `max` over the cap) is 400 `invalid_grant` with `code` `invalid_capability`.

A later-hop request authenticates its `actor` with `client_id` / `client_secret` (or HTTP Basic), with a client assertion (`client_assertion_type` and `client_assertion`, [above](#client-authentication)), with `client_id` alone over a connection with a pinned TLS client certificate, or with `actor_token` and `actor_token_type` = `urn:ietf:params:oauth:token-type:jwt` (RFC 8693 §2.1): a workload-identity JWT, such as a SPIFFE JWT-SVID, from an `[[actor_trust]]` issuer. `[token] actor_auth` decides which are accepted: `"secret"` means client credentials, a secret, an assertion or a certificate according to what the agent's entry holds. A `client_id` sent over a connection with a certificate counts as client credentials, also next to an actor token. Under `"actor_token"` such a request is refused (`client_auth_not_accepted`). Under `"either"` both are checked, so with a certificate that is not pinned for that `client_id` the request is refused (`client_authentication_failed`) even though the actor token is good. A client that uses an actor token should leave `client_id` out, or not present a certificate. An actor token works for one exchange, and the child expires no later than it does. If the parent token carries `may_act`, the `actor` must be listed (`actor_not_permitted` otherwise). `may_act` on the request sets the new token's own list: absent means any authenticated agent may exchange the new token (it does not inherit the parent's list), and `[]` means none may.

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
| the request is over a size bound (1,024 capabilities, argument constraints or `one_of` values in all, 1,024 values in a `one_of`) | `invalid_scope` | `too_many_capabilities`, `too_many_constraints`, `too_many_one_of_values`, `one_of_too_long` | `exchange_invalid_capability` |
| `actor` is empty (possible only without actor authentication) | `invalid_grant` | `invalid_agent` | `exchange_refused` |
| parent lease revoked, expired or unknown | `invalid_grant` | `lease_revoked`, `lease_expired`, `lease_unknown` | the same |

A parent whose lease is not live is answered with the lease reason as `code`, and `detail` names it too (`subject token cannot delegate: lease_revoked (...)`); there is no `error_description`. Not recorded, a server log line only: a malformed request, failed client or actor-token authentication, a subject token or DPoP proof that does not verify (so an anonymous caller cannot write to the log, SR-18), and server errors. A subject token that verified but has expired (or a hop of its chain has) is 400 `invalid_grant` with `code` `token_expired`; any other subject token that does not verify is 400 `invalid_grant` with `code` `invalid_grant`. A body that is not JSON or a well-formed form, a repeated form parameter, or a field that is missing or does not parse is 400 `invalid_request` with `code` `malformed_request` and no `error_description` (hop-0 intake sends the same code, and for a field also as `error_description`), and a form `scope` entry that is not `server:tool` is 400 `invalid_scope` with `code` `invalid_capability`. A request with no capability is 400 `invalid_request` with `code` `no_capabilities_requested`, and a `subject_token_type` other than the JWT URN (and not a hop-0 credential type) is 400 `invalid_request` with `code` `unsupported_token_type`. A `requested_ttl_seconds` beyond the parent's expiry is not a refusal: the child is clamped to the parent. A refused exchange uses up nothing: the parent can still delegate once to that actor, an actor token can be presented again, and no run limit is charged; only its DPoP proof (its `jti`) is spent. It is counted in `decisions_total{decision="deny",reason}`.

**Refused renewals are audited.** When the token of a `POST /token/renew` verified (signature, issuer, audience, expiry, chain) and so did its DPoP proof, a refusal is a `deny` record against the token's chain: server `attenuo`, tool `lease.renew` (the tool of a successful renewal, so `audit export --tool lease.renew --decision deny` lists the refused ones), kind `decision`, and the arguments digest of `{lease, ancestor, dpop_bound}` (with `"cert_bound": true` added for a certificate-bound token). The 400 carries the id in `X-Attenuo-Decision-Id` and `decision_id`:

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
| `POST /access/v1/evaluation` | bearer token, or a trusted PEP | AuthZEN evaluation. Same pipeline as the proxy, run limits included: an allowed evaluation is charged as a proxied call is, and its answer carries `context.budget` (`limited`, `calls_remaining`, `amount_remaining`, `destination_new`) when a limit matched, `context.charged` when it was charged, `context.limit` on `budget_exhausted`, `context.untrusted_args` (`[{arg, seq, kind}]`, as in the proxy's error data) when an argument matched an untrusted result of the run, and `context.usage` (`{calls, amount, destination_seen}`, plus `user_window` when it is not all zero, as in the proxy's error data) for a destructive tool or one with an `outbound` catalog input; an allowed evaluation is counted in the run's usage, and anything the PEP sends under `context.usage` is ignored. `context.diagnostics` is filled only for callers `[authzen] diagnostics` allows: by default a `[[peps]]` entry, which can authenticate next to a bearer token with `pep_id` and `pep_secret` in the body, or with a top-level `client_assertion_type` and `client_assertion`, or with `pep_id` alone over a connection with its pinned TLS client certificate ([client authentication](#client-authentication)). |
| `POST /access/v1/evaluations` | same | AuthZEN batch: top-level `subject`, `action`, `resource`, `context` are defaults and each entry of `evaluations` overrides them. Answers `{"evaluations": [{decision, context}, ...]}`, one per entry, each decided and audited like a single evaluation. At most `[authzen] max_batch` entries (default 64): more is 400 `batch_too_large`. Without `evaluations`, or with an empty one, the request is a single evaluation and is answered with a single `{decision, context}` (AuthZEN 1.0 section 7.1). `options.evaluations_semantic` (AuthZEN 1.0 section 7.1.2.1) is `execute_all` (default: every entry decided and answered), `deny_on_first_deny` (entries decided in order, stopping after the first deny; an entry that fails counts as a deny) or `permit_on_first_permit` (stopping after the first permit). A stopped batch answers only the entries it decided, so `evaluations` is shorter than the request; the entries after the stop are not decided, charged or audited. Any other value is 400 `invalid_request` before anything is decided. A PEP's client assertion goes at the top level and covers the whole batch (its `jti` is spent once per HTTP request); one inside an entry is that entry's `malformed_request`. |
| `POST /access/v1/search/action` | same | AuthZEN action search (AuthZEN 1.0 section 8): `{subject, resource, context, page}` with no `action`; the resource is the MCP server, named by `resource.properties.server` or by a `resource.id` without `/`. Answers `{"page": {"next_token", "count"}, "results": [{"name": <tool>, "properties": {"server": <server>}}, ...]}`: the `[policy] catalog` tools of that server that the token's capabilities name, in name order, that the pipeline would allow now for this caller and context, each of which `POST /access/v1/evaluation` with the same subject, resource and context decides `true` while the run's state is unchanged. No reasons, policy ids or diagnostics. Each answered search writes one audit record of kind `search` (tool `authzen.search`, reason `search_answered`, `search: {evaluated, permitted}`; a failed append is 500 and answers nothing), and nothing else: no charge to run limits or usage, no approval taken or requested, so an approval-gated tool is never a result; `context.approval_token` is 400 `approval_token_not_accepted`. A dead lease gives no results. One page evaluates at most `page.limit` candidates (default and maximum `[authzen] max_batch`; a larger `limit` is clamped, 0 is 400 `invalid_page`), so a page can hold fewer results, even none, while `next_token` is set; `next_token` is `""` after the last page. Send it back as `page.token` with the same `subject`, `resource` and `context` (`page.limit` may change); a token this route did not issue, or issued for another chain, server or `context`, is 400 `invalid_cursor`. A resource that names no server is 400 `invalid_search_resource`. With `[limits] authzen_search_requests_per_minute` set, a run's searches over it in its minute are 429 `rate_limited` with `Retry-After`, counted after authentication and before anything is evaluated, and write no record; evaluations are not counted. [Why and what is left out](authzen.md#action-search). |

The three endpoints check the bearer token first. A bad bearer is 401 `invalid_token` (or `token_expired`), and the PEP's fields are not looked at. Only the checks of the request's shape that come first (a body that is not JSON, a batch's size and `options`, a search's `page` and server) can answer before it. With no bearer, a PEP may call only under `[authzen] allow_unsigned_chain`. When that setting is off, a request with no bearer is always 401 `unauthorized` with `error_description` `missing_token`, before the PEP's fields (`pep_id`, `pep_secret`, `client_assertion`) or the entries are read. So, with no bearer and the setting off, some requests that used to get another answer now get this 401:

- a request whose PEP fields are wrong: 400 `multiple_client_auth` (a secret and an assertion), 400 `malformed_request` (a bad `client_assertion_type`, say), or 401 `invalid_client` (a wrong secret or assertion);
- a body that is not an evaluation request (400 `invalid_request`);
- a batch whose entries all failed before this check, or a `deny_on_first_deny` batch that stopped at such an entry: it used to be 200, with `decision: false` for each entry.

This is stricter, never more permissive: none of these requests was ever allowed. A valid client assertion in such a request is not spent, so the PEP can send it again with a bearer. A PEP's keys at a `jwks_url` are fetched only after the bearer check has passed.

## MCP proxy

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp/{server}` | bearer delegation token | Send an MCP request to the upstream called `server`. `tools/call` and similar methods are decided first. List answers keep only what the token's capabilities could permit; with `[proxy] list_filter = "policy"`, `tools/list` also leaves out tools the policy denies for every possible call of this token (a hidden tool can still be called, and is decided as usual). |
| `GET /mcp/{server}` | bearer delegation token | The streamable HTTP listen stream, after the lease check; resumable with `Last-Event-ID`. List answers on it are filtered and answers to allowed calls labelled, like `POST` answers. Ended (and recorded as `stream.end`, at most once per chain and reason per 60 s) when the lease is revoked or the token expires. |
| `DELETE /mcp/{server}` | bearer delegation token | Passthrough session close, after the lease check. |

A message that an upstream matching member names without regard to case (Go's `encoding/json`) could read as another message is refused with `-32600` `invalid_request` and never forwarded (SR-133): an object anywhere in it with two member names that differ only in case (`path` and `Path`), or a member of the message or of its `params` that is a JSON-RPC or MCP name in another case (`Method`, `Name`). In a batch only that entry is refused; a notification is dropped. A single argument name in another case (`Path` alone) is valid JSON-RPC and is decided: it is denied with `-32003` `argument_case_mismatch`, and recorded, when it differs only in case from a name the decision reads for the tool (see the [catalog reference](config.md#policycatalogservertool)).

A denial is a JSON-RPC error with code `-32003`, carrying `reason` and `decision_id`. A call that a policy sends for approval (reason `approval_required`) gets `-32008` instead, with `reason`, `decision_id`, `call_hash` (SHA-256 of the RFC 8785 JSON of `{server, tool, arguments}`), `approval_id` and `expires_at`, and is not forwarded. Once the approval is granted, the identical call from the same hop is allowed once (see [Approvals](#approvals)); or the retry carries the grant's signed approval token in `params._meta["dev.attenuo/approval"]`, which the proxy removes before the upstream and which does not count as an argument (see [Approval tokens](#approval-tokens)). A token that does not verify, is for another call, hop, run or key, or names an approval that is no longer granted gets `-32003` with reason `approval_invalid`. `approval_id` is absent if the server could not open an approval: the store failed, or the run already has 32 approvals pending for hops whose lease is not revoked (AuthZEN diagnostics `too many pending approvals for this run`). When an argument of the call copies a value or span of an untrusted result of the run (output labelling phase 2), the `-32008` data, and the data of every `-32003` denial the decision pipeline reaches once the run's leases are found live (`capability_denied`, `policy_deny`, `tool_not_in_catalog`, `budget_exhausted`, `approval_invalid` and the other decided reasons, `audit_error` included), add `untrusted_args: [{arg, seq, kind}]`: the argument, the `seq` of the `tool_result` record it matched (absent for kind `unreadable`) and the kind (`leaf`, `entity`, `kgram`, or `unreadable` when the run's index could not be read or the call's arguments carry more than 8,000 fingerprints in all). A lease denial (`lease_revoked`, `lease_expired`, `lease_unknown`) never carries it: the arguments are not matched then. Nor do the denials the proxy makes without asking the pipeline: a name it refuses up front (`invalid_name`, `tool_not_listed`), `label_error` and `session_mismatch`. A call over a run limit gets `-32003` with reason `budget_exhausted` and `data.limit: {hop, kind, arg, max, used}` (`arg` absent for `calls`, written `url#host` for a derived value; for `distinct`, `used` is how many values the limit has seen); `budget_error` means the counters could not be read or written, and `limit_arg_invalid` that the call lacks an argument a limit counts, or has a value it cannot count (a `sum` needs a non-negative integer, a `"derive": "host"` limit a URL of a special scheme or a bare host with a host and no backslash, whitespace or control character, and a `calls_per` or `distinct` list at most 256 values). No policy or approval passes these. For a call to a tool the catalog marks destructive or gives an `outbound` input, the `-32008` and `-32003` data also carry `usage: {calls, amount, destination_seen}`, the run's usage of the tool before this call as the policy saw it (`context.usage`): allowed calls of this server and tool by every hop of the run, the sum of the catalog's `amount` input over them, and whether the catalog's `destination` value, or a value of an `outbound` input, was seen in one of them. When some loaded policy reads a per-user window (run limits phase 3), `usage` also carries `user_window: {hour: {calls, amount}, day: {calls, amount}}`, the originating user's usage of the tool across all their runs in the current UTC hour and day; it is left out when all its figures are zero, which is also what a kind the server does not keep reads as. The decision record carries the same figures as `usage`, omitted for other tools; its `usage.user_window` names only the kinds the server keeps, each as `{start, calls, amount}` with `start` the window's start in Unix seconds UTC, and is absent when none is kept. If the answer to an allowed call cannot be recorded in the audit log, the agent gets `-32003` with reason `label_error` and the call's `decision_id` instead of the answer. A missing or bad token is HTTP 401 with `-32001` and `data.reason` set to `missing_token`, `invalid_token`, `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce`, `client_certificate_required`, `client_certificate_mismatch`, `dpop_with_certificate_binding` or, for a lease that is no longer live, `lease_revoked`, `lease_expired` or `lease_unknown`. A request refused for its lease without a per-call decision (`initialize`, `tools/list`, `ping`, `resources/unsubscribe`, the other allowlisted methods, notifications, `GET` and `DELETE`) is also a `deny` record with that reason, the token's subject and chain, the proxied server, and `tool` set to the method (`http.POST` for a notification, `http.GET`, `http.DELETE`); its 401 carries the record's id in `X-Attenuo-Decision-Id` and `data.decision_id`. These records are bounded like listen-stream ends: the first refusal per delegation chain, tool and reason in `[proxy] record_window_seconds` (default 60 s) is recorded, and a retry within the window is still a 401 but writes no record, carries the first record's id (both are left out in the moment before a concurrent first record is written) and is counted in `audit_records_suppressed_total`. A refusal whose record could not be written (a failed audit append) names no decision id and opens no window, so the next one is recorded (SR-81). Refused exchanges and renewals, and `tools/call` denials, are recorded every time. A token that does not verify writes no record. An open stream (the `GET` listen stream, or a streamed answer) whose leases stop being live or whose token expires is ended within `[proxy] stream_recheck_seconds`: an SSE stream's last event is a JSON-RPC error with `id: null`, code `-32001`, `data.reason` (`lease_revoked`, `lease_expired`, `lease_unknown`, `token_expired`) and `data.decision_id`, the id of a `deny` record of tool `stream.end` with the session's hash tag. On the `GET` listen stream that record is written for the first such end per delegation chain and reason in `[proxy] record_window_seconds` (default 60 s); later ends in the window carry the same `decision_id` and are counted in `audit_records_suppressed_total` instead of recorded. A stream the client drops or the upstream ends writes no record; `GET` listen streams are counted by how they ended in `proxy_streams_ended_total`. An upstream the proxy cannot reach (connection refused, or not connected within `[proxy] upstream_connect_timeout_seconds`, default 5) is HTTP 502 with `-32005` and `data.reason` `upstream_unreachable`; the upstream URL and transport error are only logged. Nothing was sent, so a retry is safe. An upstream that accepts the request but does not send its response headers, or the rest of a JSON body the proxy must read (to filter a list or record a result), within `[proxy] upstream_response_timeout_seconds` (default 30) of sending is HTTP 504 with `-32005` and `data.reason` `upstream_timeout`. It is a separate reason because the request did reach the upstream, which may have acted on it: retry a call with side effects only if it is idempotent. A stream (SSE, the `GET` listen stream) whose headers arrived in time is never cut by that deadline. An upstream that answers a `GET` with a success status but not `text/event-stream` is HTTP 502 with `-32005` and `data.reason` `upstream_not_event_stream` (MCP allows only an SSE stream or `405` there); `405` and error answers to a `GET` are relayed. Allowed responses carry `X-Attenuo-Decision-Id`.

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

## Gateway external authorization

Mounted only when `[[ext_authz]]` has an entry ([configuration](config.md#extauthz)); otherwise these paths are unknown. An external gateway (agentgateway's HTTP `extAuthz` mode, [guide](../guides/agentgateway.md)) sends the agent's request here and forwards it to the MCP server only on a 2xx answer. The decision is the proxy's own for `POST /mcp/{server}` ([design](../design/agentgateway-ext-authz.md)), with the gateway's position taken into account.

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /ext-authz/v1/mcp/{server}` | `X-Attenuo-Gateway-Secret` of the `[[ext_authz]]` entry of `server`, then the agent's delegation token as forwarded | Decide the one JSON-RPC message in the body as the proxy would. 200 with no body when the proxy would forward it (with `X-Attenuo-Decision-Id` when a call was decided); otherwise the proxy's own answer. |
| `GET /ext-authz/v1/mcp/{server}` | same | The listen stream: 200 when the token verifies and its lease is live, as the proxy checks before forwarding a `GET`. |
| `DELETE /ext-authz/v1/mcp/{server}` | same | Session close: as `GET`. |

A token bound to a TLS client certificate is refused here with 401 `client_certificate_required`: the connection is the gateway's, not the agent's. Every request must carry `x-envoy-auth-partial-body: false`, which the gateway sets when it sends the whole body. `Mcp-Session-Id` is ignored, and the decided call has no session. Answers that differ from the proxy's:

| HTTP status | JSON-RPC code | `data.code` | When |
| --- | --- | --- | --- |
| 403 | `-32003`, `-32008`, `-32602` | the proxy's | the proxy would have answered the message itself with this error inside a 200 (a denial, an approval request, invalid params); the body is the same JSON-RPC error |
| 403 | `-32001` | `ext_authz_unauthenticated` | `X-Attenuo-Gateway-Secret` is missing, sent twice, or not the secret of this server's entry; checked first, nothing is decided or recorded |
| 403 | `-32600` | `ext_authz_body_incomplete` | `x-envoy-auth-partial-body` is missing or not exactly `false` |
| 401 | `-32001` | `ext_authz_dpop_url_unset` | the request has a `DPoP` header and the entry has no `dpop_url` |
| 400 | `-32600` | `ext_authz_ambiguous_body` | an object has two members of one name or two whose names differ only in case, a member of the message or its `params` is a JSON-RPC or MCP name in another case (`Method`), or a number is not written as serde_json reads it (`1e3`, `1.50`, `0.10000000000000001`, an integer beyond 64 bits) |
| 400 | `-32600` | `ext_authz_batch_unsupported` | the body is a JSON-RPC batch; nothing is decided |
| 404 | `-32004` | `unknown_server` | no `[[ext_authz]]` entry is called `server` |

A DPoP proof must name the entry's `dpop_url` and the forwarded method; it is used once, as at the proxy. The other refusals (no or bad token, a dead lease, `request_too_large`, `parse_error`, `rate_limited`) are the proxy's, with the same status and body. `HEAD` is answered as `GET`, as at `/mcp/{server}`. Other methods get 405 with no body. Two answers differ from `/mcp/{server}` because the route is not under `/mcp/`: over `[limits] max_in_flight` it is the 503 `temporarily_unavailable` body of the other routes, not `-32006` `overloaded`, and `[limits] request_timeout_seconds` bounds its handler. Both are non-2xx, so the gateway denies.

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
| `viewer` | `GET /admin/whoami`, `GET /admin/leases/{lease_id}`, `GET /admin/leases/{lease_id}/tree`, `GET /admin/audit`, `GET /admin/audit/verify`, `GET /admin/audit/entries/{seq}`, `GET /admin/audit/records/{id}`, `GET /admin/audit/checkpoints`, `GET /admin/audit/checkpoint` (it signs a checkpoint of the head when there is none, which records no new fact), `GET /admin/audit/export`, `GET /admin/policies`, `GET /admin/policies/check`, `POST /admin/policies/evaluate` (a dry run that writes nothing), `GET /admin/approvals`, `GET /admin/approvals/{id}` |
| `operator` | `POST /admin/leases/{lease_id}/revoke`, `POST /admin/leases/revoke` (its `?preview=true` dry run included), `POST /admin/approvals/{id}` |
| `admin` | `POST /admin/budgets/refund`, `POST /admin/policies/reload`, `POST /admin/operators/reload`, `POST /admin/agents/reload`, `POST /admin/keys/reload`, `POST /admin/root-token`, and the audit retention routes `GET /admin/audit/prune/plan`, `POST /admin/audit/prune` and `GET /admin/audit/anchors` |

`[admin] token` is the operator `admin` with role `admin`. The audit log records an admin action with `originating_subject` `urn:attenuo:admin` for `[admin] token`, as before operators existed, and `urn:attenuo:admin:<name>` for a named operator; an approval decided by an operator has that subject as `approver.subject` and as the approval token's `sub`.

Where they are served: on the main listener by default; with `[admin] listen` set, on that listener only, and the main listener then answers every `/admin/...` path exactly as it answers an unknown path (404 with an empty body, whatever the method and bearer), so it does not reveal that an admin API exists. The admin listener serves these routes and nothing else (`/healthz` and `/readyz` stay on the main listener). Off a loopback `[server] listen` the server does not start with the admin routes on the main listener unless `[admin] serve_on_main_listener = true` ([config](config.md#admin)). The console listener (`[admin_ui]`) serves its own subset either way.

| Method and path | Purpose |
| --- | --- |
| `GET /admin/whoami` | The credential that sent the request, `{"name": "<operator>", "role": "viewer" \| "operator" \| "admin", "expires_at": "<RFC 3339>" \| null}` (`expires_at` is the operator entry's, null when it has none); `[admin] token` is `{"name": "admin", "role": "admin", "expires_at": null}`. Reads nothing else and records nothing. Also on the console listener, where the answer has one more member, `console`: `{"allow_write": <bool>, "audit_prune": "off" \| "manual" \| "auto"}`, that listener's `[admin_ui] allow_write` and `[audit.retention] prune`. The console reads it at login to know whether to offer its write actions and whether to show the automatic prune. |
| `GET /admin/leases/{lease_id}` | Lease state. |
| `POST /admin/leases/{lease_id}/revoke` | Revoke the lease and all descendants. Body `{"reason": "..."}` (optional). Answers `{lease_id, revoked, reason, audit_id}`: `revoked` counts the leases that changed, `audit_id` is the `admin.lease.revoke` record (null when it could not be written; the revocation stands). The SDKs return it: Python `revoke_lease(...).audit_id`, TypeScript `(await revokeLease(...)).auditId`. |
| `POST /admin/leases/revoke?preview` | Revoke every lease of one originating user, one delegation chain or the chain that opened one MCP session, each with its descendants, in one transaction; `preview=true` is a dry run. See [Revoke by user or chain](#revoke-by-user-or-chain) and [Revoke by session](#revoke-by-session). |
| `GET /admin/leases/{lease_id}/tree?max_nodes` | The lease, its descendants and its ancestors, and how many leases a revoke would change now. Read-only; see [Lease tree](#lease-tree). 404 for an unknown lease. |
| `GET /admin/audit` | Audit entries, oldest first or with `order=desc` newest first, `{entries, next_cursor, head, first}` (`head` is the newest `seq`, `first` the first retained `seq`: 1, or one above the boundary of a [prune](#audit-retention)), paged as in [Paging](#paging): `limit` default 100, at most 1000. `from` and `to` select a `seq` range; a range or cursor below `first` is not refused, it starts (oldest first) or ends (newest first) at `first`. Filters are below. |
| `GET /admin/audit/entries/{seq}` | One entry with its context, `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}` (below). 404 when there is no entry at `seq`; 410 `audit_pruned` when `seq` was pruned, with `pruned_through`, `prune_seq` (the prune record) and `first` in the body. |
| `GET /admin/audit/records/{id}` | The same for the entry whose record id is `id`: the UUID that proxy denials and AuthZEN answers return as `decision_id`. 400 if `id` is not a UUID, 404 if no record has it. A record id carries no time, so after a prune a pruned id is a 404 too; the message then names the boundary and says the record may be in the prune's archive. |
| `GET /admin/audit/checkpoints?limit&cursor` | Stored checkpoints, newest first, `{checkpoints, next_cursor}`; each is `{seq, head_hash, at, kid, signature}`. Paged as in [Paging](#paging): `limit` default 100, at most 1000. Read-only: it never signs, unlike `/admin/audit/checkpoint`. |
| `GET /admin/audit/verify` | Walk the whole hash chain, verify every checkpoint signature against the JWKS, and report `{entries, ok, first_bad_seq, checkpoints, last_signed_seq, unsigned_tail, bad_checkpoints, pruned_through, anchors, bad_anchors}`. After a prune the walk starts at the newest anchor: `pruned_through` is its boundary (null for a log never pruned), `anchors` counts the anchors checked, and `bad_anchors` lists the ones that failed, `{through_seq, reason}`; `entries` counts retained entries. A log whose first row is not seq 1 and that has no valid anchor naming it is `ok: false` at its first row. |
| `GET /admin/audit/checkpoint` | The signed checkpoint of the head, `{seq, head_hash, at, kid, signature}` (signing it now if the head has none). For keeping outside the host. `hash` repeats `head_hash` for older clients. |
| `GET /admin/audit/export?from&to` | Entries `from..=to` (default: the whole log) and the checkpoints in that range, streamed as `application/x-ndjson`: a `header` line, `entry` lines, then `checkpoint` lines. Verify offline with `attenuo audit verify --file`. `kind`, `chain_id`, `tool` and `decision` keep only the matching entries; the header then has a `filter` member naming them and the file cannot be verified. The SDKs take the same four: Python `audit_export(kind=, chain_id=, tool=, decision=)`, TypeScript `auditExport(from, to, { kind, chainId, tool, decision })`. 400 if `from` is 0 or `to < from`, for an unknown kind or decision, more than one kind, or an empty filter value. After a prune `from` defaults to the first retained seq, a `from` or `to` at or below the boundary is 410 `audit_pruned`, and an export from the first retained seq has the signed anchor as the header's `anchor` member: `attenuo audit verify --file` then checks that the file continues it and reports `from_anchor: true` (a verifier that does not know the member verifies the file as a window). |
| `GET /admin/audit/prune/plan?through&before` | With `[audit.retention] prune = "manual"` or `"auto"`: the largest boundary the guards allow at or below `through` (a seq) or for entries older than `before` (RFC 3339), the head when neither is given. With `"auto"`, also the automatic prune's settings and last run (`auto`). See [Audit retention](#audit-retention). Reads only. Also on the console listener (role `admin` there too), which shows `auto` on its Verify page; the two routes below are not. |
| `POST /admin/audit/prune` | With `[audit.retention] prune = "manual"` or `"auto"`: prune the log through a boundary, body `{"through": <seq>, "archive_sha256": "<hex>"}`. See [Audit retention](#audit-retention). |
| `GET /admin/audit/anchors?limit&cursor` | The signed anchors of past prunes, newest first, `{anchors, next_cursor}`, each `{through_seq, through_hash, prune_seq, prune_entry_hash, previous_through_seq, archive_sha256, at, kid, signature, state}`. Paged as in [Paging](#paging): `limit` default 50, at most 500. Empty for a log never pruned, whatever `prune` is. |
| `POST /admin/policies/reload` | Re-read the policy file. On failure the old policy stays. |
| `POST /admin/operators/reload` | Re-read `[[admin.operators]]`, and nothing else, from the config file the server was started with, and swap them in at once. See [Operators reload](#operators-reload). Also on the console listener with `[admin_ui] allow_write = true`, where the console's Reload page uses it. |
| `POST /admin/agents/reload` | Re-read `[[agents]]` and `[[peps]]` from the config file the server was started with, check them as startup does, and swap both in at once. Tokens already issued are not revoked. Body `{}`, or `allow_empty` / `allow_mismatch`. See [Agents reload](#agents-reload). Also on the console listener with `[admin_ui] allow_write = true`. |
| `POST /admin/keys/reload` | Re-read the key files named by `[issuer] private_key_pem_path` and `previous_key_paths` in the config file, and swap in the new signing key and verifying keys at once. Body `{}`, or `allow_drop_current` / `allow_drop_audit_key` / `allow_mismatch`. See [Keys reload](#keys-reload). Also on the console listener with `[admin_ui] allow_write = true`. |
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

### Agents reload

`POST /admin/agents/reload` (role `admin`) re-reads the config file the server was started with (`--config` or `ATTENUO_CONFIG`), parses it as startup does (with the `ATTENUO__...` [environment overrides](config.md#environment-overrides)), checks `[[agents]]` and `[[peps]]` with the startup rules ([config](config.md#agents)) against the other settings in force, and puts both lists in force in one step. Only these two lists are applied. Reloads run one at a time.

The body is empty, `{}`, or overrides of two refusals: `{"allow_empty": true}` accepts a file that leaves a list empty while the server has entries in it, and `{"allow_mismatch": true}` accepts a file whose `[issuer]` or `[audit]` differs from the running config. An unknown field is a 400. The SDKs wrap it: Python `AdminClient.agents_reload(allow_empty=False, allow_mismatch=False)` returns an `AgentsReload`, TypeScript `AdminClient.agentsReload({ allowEmpty, allowMismatch })` resolves to one.

It answers:

```json
{
  "agents": {"count": 3, "sha256": "<64 hex>", "added": ["tester"], "removed": ["coder"], "changed": ["reviewer"]},
  "peps": {"count": 1, "sha256": "<64 hex>", "added": [], "removed": [], "changed": []},
  "restart_needed": ["[[root_grants]]"],
  "warnings": [],
  "restart_warnings": [],
  "audit_id": "<uuid>"
}
```

- `count` is the number of entries now in force. `added`, `removed` and `changed` are ids; `changed` means a different `secret_sha256`, `jwks`, `jwks_url`, `jwks_ttl_seconds` (the value in force: writing the default 300 is no change), `ca_pem_path`, `tls_client_cert_sha256` (as a set), `tls_client_ca_pem_path`, `tls_client_auth_san_uri` or `tls_client_auth_san_dns` (without regard to case), or a `ca_pem_path` or `tls_client_ca_pem_path` file whose bytes changed, or a change of `tls_client_crl_paths`, `tls_client_crl_issuer_pem_path`, `tls_client_crl_stale` or `tls_client_crl_missing`, or of the bytes of one of those files.
- `sha256` is the SHA-256 (lowercase hex) of the list's canonical form: a JSON array with one `[id, secret_sha256, thumbprints]` array per entry, sorted by id, written compactly (no spaces). `secret_sha256` is the entry's digest in lowercase, or `null`; `thumbprints` is the sorted list of the RFC 7638 SHA-256 thumbprints (base64url) of the entry's `jwks` keys, `[]` without keys. An entry with `jwks_url` has four more members: `[id, secret_sha256, [], jwks_url, jwks_ttl_seconds, ca_pem_path, ca_pem_sha256]`, with the URL and the path as written, the TTL in force (300 when unset), and the lowercase hex SHA-256 of the `ca_pem_path` file's bytes as the reload read them; the path and its digest are `null` without `ca_pem_path`. An entry without `jwks_url` keeps three members, so a list without `jwks_url` has the same digest as before the setting existed. An entry with `tls_client_cert_sha256` has one more member after those, `{"tls_client_cert_sha256": [<sorted thumbprints>]}`. An entry with `tls_client_ca_pem_path` has one more member instead, `{"tls_client_ca_pem_path": <path as written>, "tls_client_ca_pem_sha256": <SHA-256 of the file's bytes as the reload read them>, "tls_client_auth_san_uri" or "tls_client_auth_san_dns": <the name; a DNS name in lower case>}`; with `tls_client_crl_paths` that member also has `"tls_client_crls": {"tls_client_crl_paths": [<paths as written>], "tls_client_crl_sha256": [<SHA-256 of each file's bytes>], "tls_client_crl_issuer_pem_path": <path>, "tls_client_crl_issuer_pem_sha256": <SHA-256>, "tls_client_crl_stale": <"refuse" or "allow">, "tls_client_crl_missing": <"allow" or "refuse">}`, the two issuer members only with `tls_client_crl_issuer_pem_path`. Entries without them have no such member, so their digest is as before. The keys at the URL are not in the digest, because they change without a reload. It holds no secret and no key, and lets you show later which lists a reload put in force, by computing it from a copy of the file.
- `restart_needed` names each other section of the file (`[server]`, `[[root_grants]]`, ...) whose values differ from the ones in force. They are not applied; a restart applies them. `[[admin.operators]]` and the key files of `[issuer]` (`private_key_pem_path`, `previous_key_paths`) are not compared: `POST /admin/operators/reload` and `POST /admin/keys/reload` reload them. An empty list means the file matches the running config apart from the two lists.
- `warnings` are the startup warnings the new lists raise, such as an `[[idps]]` entry with no `client_ids` entry for a new agent, or no agents at all, and one for each removed agent that can still get a new token another way: by name when `[token] require_actor_auth = false`, or with an actor token when an `[[actor_trust]]` entry can map a workload to its id. Changing either setting takes a restart. One more warning says when the file's `[issuer] private_key_pem_path` or `previous_key_paths` differ from the key files in force: this reload does not apply them, a keys reload does. Ids in a warning are escaped, so a control character cannot forge a log line.
- `restart_warnings` say that the file's own settings, which a restart would apply, would refuse these lists (for example `[authzen] allow_unsigned_chain = true` with no `[[peps]]`). The lists were checked against the settings in force and put in force anyway.
- The `admin.agents.reload` audit record names the caller as `originating_subject` and has `{path, agents, peps, restart_needed}` as its arguments, the middle two as in the answer, `sha256` included. Like every record, it keeps the arguments only as their digest. A 422 refusal is recorded as a `deny` whose `reason` is the refusal's code; the 400 `invalid_request`, 409 `reload_unavailable` and 500 `config_unreadable` are not audited.

What changes when:

- Each request authenticates against one snapshot: it sees both old lists or both new ones, never a mix. A request admitted before the swap completes with the lists it was admitted with.
- From the next request on, a removed agent or PEP, an old secret and an old key are refused (401 `invalid_client` / `client_authentication_failed`), and an added one, a new secret and a new key are accepted. A removed agent may still get new tokens through the routes the warnings name.
- Tokens and leases already issued are not revoked. A token issued to a removed agent keeps working, and `POST /token/renew` keeps renewing it, until it expires or its lease is revoked: `POST /admin/leases/{lease_id}/revoke` or `POST /admin/leases/revoke` (`attenuo lease revoke`). To contain a compromised agent, reload and revoke.
- The per-agent `[limits] token_requests_per_minute` window and the record of used client assertions (`jti`) are kept by id, so a rotation resets neither.

Refusals (on every one, both lists in force are unchanged):

- 422 `agents_invalid`: the file does not parse as the server's config (not TOML, an unknown key, a wrong type), or a list breaks a startup rule (an empty or duplicate id, the reserved id `attenuo`, a `secret_sha256` that is not 64 hex characters, an entry with neither a secret nor keys, a `jwks` the server refuses, or no `[[peps]]` while `[authzen] allow_unsigned_chain = true`). `detail` is the message startup would give, followed by `; the agents and peps in force are unchanged`. When the rule is one in force that the file changes, the message adds `(a rule in force; the file changes it, which needs a restart)`. A TOML error names its line, and its key and table when it can, but never quotes the file or a value from it.
- 422 `agents_reload_empties`: the file has no `[[agents]]` or no `[[peps]]` while the server has some in force, as an empty or cut-off file has. Checked first. Send `allow_empty` to empty them.
- 422 `client_crl_older`: a CRL file would put a CRL of a CA in force that is older than the one in force now: an earlier `thisUpdate`, a smaller `cRLNumber`, or no `cRLNumber` while the one in force has one ([CRL files](config.md#crl-files)). The same file again is accepted. A CRL that cannot be used (unreadable, signed by another key, stale under `tls_client_crl_stale = "refuse"`) is `agents_invalid`.
- 422 `config_file_mismatch`: the file's `[issuer]` (its key files aside) or `[audit]` differs from the running config, so it may be another server's file. Send `allow_mismatch` to reload its lists anyway; the two sections are still not applied.
- 400 `invalid_request`: the body is not the JSON object above.
- 409 `reload_unavailable`: the server was not started from a config file.
- 500 `config_unreadable`: the file cannot be read; the cause is in the server log only.
- 500 `server_error`: the file could not be compared with the config in force. This is not expected; nothing is applied, since the mismatch check could not be made.

### Keys reload

`POST /admin/keys/reload` (role `admin`) rotates the token signing key without a restart. It re-reads the config file the server was started with, as the agents reload does, and takes from it only `[issuer] private_key_pem_path` and `previous_key_paths`: the paths as the file on disk gives them now. An environment variable still wins over the file, as at startup: while `ATTENUO__ISSUER__PRIVATE_KEY_PEM_PATH` is set, editing that line in the file does nothing, and `warnings` says so. It reads those key files and puts the new signing key and the new set of verifying keys in force in one step. Reloads run one at a time.

A reload reads key files more strictly than startup. It never generates a key, so the file must set `private_key_pem_path` and the file must exist. Each key file must be a regular file (a link to one is fine) of at most 64 KiB. Each key may be listed once: the signing key listed in `previous_key_paths` too, or one retired key in two files (a private and a public one), is refused.

The body is empty, `{}`, or overrides of three refusals: `{"allow_drop_current": true}`, `{"allow_drop_audit_key": true}` and `{"allow_mismatch": true}`. An unknown field is a 400. The SDKs wrap it: Python `AdminClient.keys_reload(allow_drop_current=False, allow_drop_audit_key=False, allow_mismatch=False)` returns a `KeysReload`, TypeScript `AdminClient.keysReload({ allowDropCurrent, allowDropAuditKey, allowMismatch })` resolves to one.

It answers key ids (`kid`) only, never a key or a file's content:

```json
{
  "signing_kid": "<new kid>",
  "previous_signing_kid": "<old kid>",
  "changed": true,
  "verifying_kids": ["<new kid>", "<old kid>"],
  "added": ["<new kid>"],
  "removed": [],
  "audit_signing_kid": "<new kid>",
  "kept_until_restart": [],
  "restart_needed": [],
  "warnings": [],
  "audit_id": "<uuid>"
}
```

- `changed` is false when the file names the same keys as before. Nothing is swapped then.
- `verifying_kids` is the set the JWKS now lists: the signing key first, then the retired keys in file order. `added` and `removed` compare it with the set before.
- `audit_signing_kid` is the key that signs audit checkpoints and prune anchors from now on: the new signing key.
- `kept_until_restart` names what stays keyed by the key the server started with, once the signing key is another one: `[token] dpop_nonce` (the DPoP nonces) and the subject digests of `[telemetry]` and `[logging] redact_subjects`, each only when it is on. A restart re-keys them.
- `restart_needed` names each other section of the file whose values differ from the ones in force, as for the agents reload. They are not applied. The other keys of `[issuer]` (`issuer`, `audience`, `max_depth`, the lifetimes) are part of `[issuer]` here and are never changed by this reload.
- `warnings` say what was dropped: tokens signed by each key in `removed`, or rooted under it (their `ou_kid` names it), no longer verify; and, when `allow_drop_audit_key` was needed, audit checkpoints and anchors of a dropped key no longer verify against the JWKS. One more warning says when an environment variable set a key path, so the file's line was not used.
- The `admin.keys.reload` audit record has `{path, signing_kid, previous_signing_kid, changed, verifying_kids, added, removed, restart_needed}` as its arguments, kept as their digest. A 422 refusal is recorded as a `deny` whose `reason` is the refusal's code, with `path` and, for the two drop refusals, the kids involved. The 400, 409 and 500 are not audited.

What follows the reload:

- Every request takes one snapshot of the keys and uses it to the end. A token exchange verifies the parent, signs the child and reads it back with the same keys, even if a reload runs meanwhile.
- New tokens, children of an exchange and approval tokens are signed with the new key and carry its `kid`. Tokens signed by a key in `verifying_kids` keep verifying, as long as the key their `ou_kid` names is there too, at `POST /token`, `POST /token/renew`, the MCP proxy, AuthZEN and the approval routes. The proxy's cache of verified tokens is tied to the keys that verified them, so it never answers for a key that was dropped. A child token keeps the `ou_kid` of its root (the key that signed the user block at the root). So dropping a retired key also ends the children signed by a kept key but rooted under the dropped one.
- `GET /.well-known/jwks.json` lists `verifying_kids` at once.
- Audit checkpoints and prune anchors signed from now on carry the new `kid`. Those signed before keep theirs and verify as long as their key stays in `previous_key_paths`. `GET /admin/audit/verify`, `attenuo audit verify --jwks` and the shipped envelopes of `[audit.sink]` all check by `kid`. The `keys_reload_drops_audit_key` check below only sees the checkpoints and anchors the live log still holds. Archives (`attenuo audit prune --archive`), exports and checkpoints already shipped to `[audit.sink]` can be signed by older keys it does not see. Save a copy of `GET /.well-known/jwks.json` with each archive or export, or keep the old public key in `previous_key_paths`, so they can still be checked.
- Not reloaded: the DPoP nonce key and the subject digest key (see `kept_until_restart`). They are never published or checked by anyone else. Rekeying them on a reload would refuse every nonce already handed out and break the join of logs and traces by digest. After a key compromise, restart to re-key them too. The `[leases.notify]` and `[approvals.notify]` webhook signatures use their own secrets, not the issuer key.
- With several replicas, each one reloads its own keys: send the request to each.

Refusals (on every one, the keys in force are unchanged):

- 422 `keys_config_invalid`: the file does not parse as the server's config, or it sets no `[issuer] private_key_pem_path`. A TOML error names its line but never quotes the file.
- 422 `config_file_mismatch`: the file's `[issuer]` (its key files aside) or `[audit]` differs from the running config, so it may be another server's file. Send `allow_mismatch` to reload its keys anyway.
- 422 `key_file_unreadable`: a key file cannot be read (missing, no permission, not UTF-8 text). The message names the file.
- 422 `key_file_invalid`: a key file is not a regular file, is larger than 64 KiB, or holds no Ed25519 key of the kind wanted: a key of another type or curve, a public key as the signing key, an encrypted or OpenSSH key, a certificate, no PEM block, or a damaged one. The message names the file and the kind of fault, with the parser's reason when there is one (such as `invalid PEM base64`), never the content.
- 422 `key_duplicate`: two files hold the same key. The message names both files and the `kid`.
- 422 `keys_reload_drops_current`: the new signing key differs from the current one, and the current one is not in `previous_key_paths`. Every live token would stop verifying at once. List the current key file in `previous_key_paths`, or send `allow_drop_current` (for a key compromise).
- 422 `keys_reload_drops_audit_key`: the new verifying keys leave out a key that signed an audit checkpoint or prune anchor the log still holds, or the key that signs them now. `audit verify` would then report them as signed by an unknown key. Keep its file in `previous_key_paths`, or send `allow_drop_audit_key`. Dropping the current key always needs both overrides: the current key is the one that signs audit checkpoints now.
- 400 `invalid_request`: the body is not the JSON object above.
- 409 `reload_unavailable`: the server was not started from a config file.
- 500 `config_unreadable`: the config file cannot be read; the cause is in the server log only.
- 500 `server_error`: the file could not be compared with the config in force. This is not expected; nothing is applied, since the mismatch check could not be made.

### Budget refund

`POST /admin/budgets/refund` works from the charge log, which keeps what each allowed call charged until `[leases] run_state_retention_seconds` after its run's leases are gone. When the charge log has no entry for `decision_id`, the server looks the decision up in the audit log, which is append-only and keeps every decision record unless the log was pruned past it (`[audit.retention]`; the 404 then names the boundary), and answers by what the record shows:

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

`{"session": "<id>"}` hashes the id, looks up the chains recorded for it (one per upstream the session was opened with, normally one) and then behaves as `chain_id` for each of them, preview included. The answer's `selector` is `{"session_tag": "...", "chain_ids": [...]}`, never the raw id. A session the server has no record of (a wrong id, or one opened before the server recorded sessions) resolves to `chain_ids: []` and matches nothing: a 200 with empty lists, as for an unknown `chain_id`. The proxy's next request on a revoked session's chain is refused (HTTP 401 `lease_revoked` for `initialize`, `ping`, `tools/list` and session `GET`s; a `-32003` denial for `tools/call`). There is no selector for the session tag that audit records and logs show: it is a 48-bit prefix of the hash, so it can match more than one session. Revoke by the raw id, or by the `chain_id` of the record.

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
| `kind` | one of these kinds, comma-separated: `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin`, `search` |
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

### Audit retention

With `[audit.retention] prune = "manual"` or `"auto"` ([config](config.md#auditretention), [ADR-0015](../decisions/0015-audit-retention.md)) the admin may prune the oldest part of the log. With `"auto"` the server also prunes on its own, through the same plan and the same prune (see [the automatic prune](#the-automatic-prune) below). With `prune = "off"`, the default, both routes below answer 409 `prune_disabled` and the log is never pruned. The SDKs wrap the three routes: Python `audit_prune_plan(through=, before=)`, `audit_prune(through, archive_sha256=, from_=, through_hash=)` and `audit_anchors(cursor=, limit=)`, TypeScript `auditPrunePlan({ through, before })`, `auditPrune(through, { archiveSha256, from, throughHash })` and `auditAnchors({ cursor, limit })`.

`GET /admin/audit/prune/plan?through=<seq>` (or `?before=<RFC 3339>`, or neither for the head) answers the largest boundary B the guards allow at or below the request:

```json
{
  "from": 1,
  "through": 1000000,
  "entries": 1000000,
  "checkpoint": {"seq": 1000000, "head_hash": "...", "at": "...", "kid": "...", "signature": "..."},
  "at": "2026-07-30T23:59:58Z",
  "guards": {"requested": 1000150, "before": null, "min_age_cutoff": "2026-08-24T12:00:00Z",
             "live_run_seq": 1000123, "sink_delivered_through": 1041000, "sink_degraded": false,
             "in_progress": false, "anchor_undelivered": false,
             "limited_by": "prune_not_at_checkpoint"},
  "anchor": null,
  "auto": null
}
```

`through` is null when nothing can be pruned. `limited_by` says what set `through` below the request: the refusal code of a guard (see the table below), or `"before"` when it was the `before` time asked for, which is not a refusal. `anchor_undelivered` is true while `[audit.sink]` has not delivered the anchor of the previous prune, which holds the next one (`sink_behind`). The archive of that prune is the export `from..=through`: export it, verify it with `attenuo audit verify --file`, and keep it off the host before pruning.

`POST /admin/audit/prune` with `{"through": B, "archive_sha256": "<64 hex>", "from": F, "through_hash": "<64 hex>"}` commits the prune in one transaction: the signed checkpoint of the head (if it has none), the prune record (`admin`, tool `admin.audit.prune`, its arguments `{through_seq, through_hash, previous_through_seq, archive_sha256}`), the signed anchor, and the checkpoint of the prune record. With `[audit.sink]` the two checkpoints and the anchor are queued for shipping. The members after `through` are optional, for compatibility, but a client should always send them: `archive_sha256` is the SHA-256 of the archive file's bytes, signed into the anchor; `from` is the archive's first seq and `through_hash` its last entry hash. Only with `from` and `through_hash` does the server know that the archive covers what it prunes: the transaction refuses with `prune_archive_mismatch` unless `from` is the log's first retained seq at that moment and `through_hash` the entry hash at B. Without them, an archive of `1001..=2000` with `through: 2000` would prune `1..=1000` archived nowhere. `attenuo audit prune` sends all three. It answers:

```json
{"prune_seq": 1041231, "pruned_through": 1000000, "anchor": {...},
 "checkpoint_before": {...}, "checkpoint_after": {...}, "deleting": true,
 "shipped": {"queued": true, "delivered_through": 1041000,
             "anchor_shipped_at": null, "anchor_pending": true},
 "already": false}
```

`shipped` is null without `[audit.sink]`. `queued` says whether this call queued the anchor (and, for a new prune, the two checkpoints); `delivered_through` is the highest checkpoint seq the sink has delivered since the server started; `anchor_shipped_at` is when the sink delivered the anchor (null until then), and `anchor_pending` whether it is queued and not yet delivered. The anchor is never dropped from a full queue, and it is queued again at start-up while `anchor_shipped_at` is null. A repeated request for a prune whose anchor is neither delivered nor queued queues it again. If the running server delivered the anchor but the delivery is not recorded, the repeat records it and does not ship the anchor a second time.

From then on every read starts at B + 1. The rows at or below B are deleted afterwards, in transactions of `[audit.retention] batch_rows`, by the maintenance task; a restart resumes them, and the anchor's `state` goes from `deleting` to `done`. Repeating a request that succeeded (the same `archive_sha256`, and `from` and `through_hash` that match the stored anchor when given) answers 200 with the stored anchor and `"already": true`. The guards, each a 409 with nothing written:

| Code | Refused when |
| --- | --- |
| `prune_not_at_checkpoint` | B has no stored checkpoint, or its `head_hash` is not the entry's hash |
| `prune_too_recent` | the entry at B is younger than `min_age_seconds` |
| `prune_live_run` | a run whose root lease is still in the lease registry has an entry at or below B |
| `sink_behind` | `[audit.sink]` is degraded, has not delivered the checkpoint at B or a later one since the server started, or has not delivered the anchor of the previous prune |
| `prune_in_progress` | the rows of an earlier prune are still being deleted |
| `prune_conflict` | B was already pruned with another `archive_sha256` |
| `prune_archive_mismatch` | `from` is not the first retained seq, or `through_hash` is not the entry hash at B; for a repeat of a prune that succeeded, they differ from the stored anchor (`previous_through_seq + 1`, or 1, and `through_hash`) |

A `through` below the current boundary is 410 `audit_pruned`, with `pruned_through`, `prune_seq` and `first` as on every other 410 `audit_pruned`; 400 `invalid_request` for a malformed body, a `through` of 0 or an `archive_sha256` that is not 64 lower-case hex digits.

#### The automatic prune

With `prune = "auto"` the plan's `auto` member is `{keep_seconds, interval_seconds, max_entries_per_run, archive_dir, last_run}`; it is null with `"manual"`. `archive_dir` is the configured directory, or null when the server keeps no archive. `last_run` is null until the server has run one since it started, then:

```json
{"at": "2026-11-22T10:00:00Z", "outcome": "pruned", "reason": "ok",
 "through": 120000, "prune_seq": 250013, "detail": null,
 "archive": "audit-00000000000000000001-00000000000000120000.jsonl"}
```

`outcome` is `pruned`, `skipped` or `failed`. `reason` is `ok` for a prune. For a skipped run it is the code of the guard that stopped it (the table above, or `audit_pruned` when nothing past the boundary is at a checkpoint), `nothing_to_prune`, `concurrent_prune` when another prune changed the log during the run, or `clock_jump` when the wall clock moved more than an hour away from the monotonic clock since the last run. For a failed run it is `verify_failed` (the entries it would prune do not verify, so they are kept), `archive_write_failed` (the archive file could not be written), `archive_exists` (a file of the archive's name is there and is not this prefix's archive; it is never replaced), `archive_verify_failed` (the archive file does not verify when read back), `error` (the store failed) or `panic`. `through` is the boundary it pruned or tried, `prune_seq` the prune record's seq, `detail` more words for a skip or a failure, and `archive` the archive file's name in `archive_dir` when the run got that far. The plan itself is still the admin's: its age floor is `min_age_seconds`, not `keep_seconds`.

Each run plans with only entries older than its cutoff old enough: `keep_seconds` before the earliest of now, the newest entry that is not a prune record, and the wall time at start plus the monotonic time since ([configuration reference](config.md#auditretention)), at most `max_entries_per_run` entries, and verifies the entries from the log's start to the boundary (the chain, every checkpoint and the anchors, as `GET /admin/audit/verify` does). With `archive_dir` it then writes those entries as an export file and verifies the file ([config](config.md#auditretention)). Only then does it prune, with the plan's first seq and the boundary's hash as `from` and `through_hash`, so a prune that something else made in between refuses it. The prune record's `originating_subject` is `urn:attenuo:retention`. The anchor's `archive_sha256` is the archive file's SHA-256, or null without `archive_dir`. The runs are counted in `audit_auto_prune_runs_total{outcome, reason}` ([metrics](#metrics)).

#### After a prune

After a prune, `GET /admin/audit/verify` checks the newest anchor's signature, the checkpoint at B and the prune record, and walks the chain from B + 1. A log whose first rows were deleted without a valid anchor (by someone with write access to the file but no key) reports `ok: false` at its first row, as before. `GET /admin/audit/anchors` lists every anchor, newest first, each with its `state` and `shipped_at`. An export that is streaming when a prune commits above its position ends with an error instead of a file with a gap (export again from the new first seq), and a verify whose walk overlaps a prune's deletes walks once more from a new snapshot when the anchors changed.

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
| `decisions_total` | counter | `decision` (`allow`, `deny`), `reason` | Decision records by outcome and reason code: pipeline decisions (MCP proxy and AuthZEN) and the requests the proxy refuses and records before a decision. `reason` is one of `policy_allow`, `policy_deny`, `policy_error`, `approval_required`, `approval_invalid`, `capability_denied`, `tool_not_in_catalog`, `attribute_type_mismatch`, `input_type_mismatch`, `argument_case_mismatch`, `invalid_name`, `tool_not_listed`, `session_mismatch`, `budget_exhausted`, `budget_error`, `limit_arg_invalid`, `lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, `audit_error`, and for a refused token exchange `exchange_widening`, `exchange_too_deep`, `exchange_actor_not_permitted`, `exchange_actor_mismatch`, `exchange_duplicate_actor`, `exchange_reserved_agent`, `exchange_no_lifetime_left`, `exchange_replayed`, `exchange_invalid_capability`, `exchange_refused`. A lease refusal of `initialize` or another undecided request, of an exchange's parent, or of a renewal, counts under its lease reason. Unauthenticated requests (bad token, DPoP) are not counted here. |
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
| `audit_db_size_bytes` | gauge | none | Size of the SQLite database file of the audit log and lease registry (`page_count * page_size`), the WAL not included. Read at each scrape when the store is not busy, else the last value read; 0 before the first. |
| `audit_db_free_bytes` | gauge | none | Bytes of that file on SQLite's free list (`freelist_count * page_size`): space that deletes, a prune's among them, freed and new rows reuse. The server never shrinks the file; `attenuo audit compact` does, with the server stopped. |
| `audit_pruned_entries_total` | counter | none | Audit entries deleted by prunes of the log (`[audit.retention]`). |
| `audit_prune_last_timestamp_seconds` | gauge | none | Unix time of the newest prune of the audit log, manual or automatic (its anchor's `at`), read from the file at start; 0 for a log never pruned. |
| `audit_auto_prune_runs_total` | counter | `outcome` (`pruned`, `skipped`, `failed`), `reason` | Runs of the automatic prune (`[audit.retention] prune = "auto"`). `reason` is `ok` for a prune, a guard code (`prune_too_recent`, `sink_behind`, ...), `nothing_to_prune`, `concurrent_prune` or `clock_jump` for a skip, and `verify_failed`, `archive_write_failed`, `archive_exists`, `archive_verify_failed`, `error` or `panic` for a failure ([the automatic prune](#the-automatic-prune)). A series appears once counted. |
| `audit_auto_prune_last_run_timestamp_seconds` | gauge | none | Unix time the automatic prune last ran, whatever its outcome; 0 before the first run. |
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
| `lease_notify_delivered_total` | counter | none | `lease.revoked` notices delivered by `[leases.notify]`. |
| `lease_notify_failures_total` | counter | none | `lease.revoked` notice deliveries that failed; each is retried until `max_attempts`. |
| `lease_notify_dropped_total` | counter | none | `lease.revoked` notices not delivered: dropped from a full queue, or failed on every attempt. |
| `lease_notify_queue_depth` | gauge | none | `lease.revoked` notices waiting in the `[leases.notify]` queue. |
| `lease_notify_outbox_rows` | gauge | none | `lease.revoked` notices stored in the outbox and not yet delivered or given up. Restored from the database at start. |
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
