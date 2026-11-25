//! The stable error codes the server and its proxy answer with, in one table.
//!
//! Every error body the server sends names one of these codes:
//!
//! - **REST** (every route but `/mcp/{server}`, the AuthZEN routes included):
//!   `{"error": <OAuth-style error>, "code": <code>, "detail": <text>}`, plus
//!   `error_description` where one is set. `code` is the refusal's specific reason: a reason
//!   the route names (sent with no `error_description`), else `error_description` when the
//!   answer has one, else `error` when no more specific reason exists.
//! - **JSON-RPC** (the MCP proxy): `{"error": {"code": <number>, "message": <text>,
//!   "data": {"code": <code>, ...}}}`. Where `data.reason` is present it equals `data.code`.
//! - **AuthZEN batch entry**: `{"decision": false, "context": {"error": {"status", "code",
//!   "message"}}}`.
//!
//! A code is never reworded: a client may match on it. The texts (`detail`, `message`) are for
//! people and may change in any release. A code that is also a decision `reason` (a deny of
//! the decision pipeline, recorded in the audit log and returned as AuthZEN `context.reason`)
//! is marked [`ErrorCode::reason`]; for those the code and the reason are the same string.
//!
//! The server and the proxy check each answer against this table in debug builds, and the
//! server's tests check that every code a source file names is listed here, that no code is
//! listed twice, and that the list in `docs/reference/http-api.md` matches it.

/// One REST form of a code: the HTTP status and the `error` member sent with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rest {
    /// HTTP status.
    pub status: u16,
    /// The `error` member (an OAuth 2.0 error code where one fits).
    pub error: &'static str,
}

/// One JSON-RPC form of a code: the error number and the HTTP status of the answer that
/// carries it (200 for an error inside a JSON-RPC response or an SSE event).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonRpc {
    /// JSON-RPC `error.code`.
    pub number: i64,
    /// HTTP status of the answer.
    pub status: u16,
}

/// One stable error code and every form it is sent in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode {
    /// The code: snake_case ASCII, never reworded.
    pub code: &'static str,
    /// The REST answers that carry it (also the AuthZEN routes' error answers).
    pub rest: &'static [Rest],
    /// The proxy's JSON-RPC errors that carry it as `data.code`.
    pub jsonrpc: &'static [JsonRpc],
    /// Also a deny `reason` of the decision pipeline (audit `reason`, AuthZEN
    /// `context.reason` of a `decision: false`, JSON-RPC `data.reason`).
    pub reason: bool,
    /// What it means, in a sentence, for the reference docs.
    pub meaning: &'static str,
}

use crate::jsonrpc::{
    CODE_APPROVAL_REQUIRED as APPROVAL, CODE_DENIED as DENIED,
    CODE_INVALID_PARAMS as INVALID_PARAMS, CODE_INVALID_REQUEST as INVALID_REQUEST,
    CODE_PARSE_ERROR as PARSE, CODE_TOO_MANY as TOO_MANY, CODE_UNAUTHORIZED as UNAUTHORIZED,
    CODE_UNAVAILABLE as UNAVAILABLE, CODE_UNKNOWN_SERVER as UNKNOWN_SERVER,
    CODE_UPSTREAM as UPSTREAM,
};

const fn r(status: u16, error: &'static str) -> Rest {
    Rest { status, error }
}

const fn j(number: i64, status: u16) -> JsonRpc {
    JsonRpc { number, status }
}

const fn e(
    code: &'static str,
    rest: &'static [Rest],
    jsonrpc: &'static [JsonRpc],
    meaning: &'static str,
) -> ErrorCode {
    ErrorCode {
        code,
        rest,
        jsonrpc,
        reason: false,
        meaning,
    }
}

/// A code that is also a deny `reason` of the decision pipeline.
const fn d(
    code: &'static str,
    rest: &'static [Rest],
    jsonrpc: &'static [JsonRpc],
    meaning: &'static str,
) -> ErrorCode {
    ErrorCode {
        code,
        rest,
        jsonrpc,
        reason: true,
        meaning,
    }
}

const BAD_REQUEST: &[Rest] = &[r(400, "invalid_request")];
const BAD_GRANT: &[Rest] = &[r(400, "invalid_grant")];
const BAD_CLIENT: &[Rest] = &[r(401, "invalid_client")];
const BEARER: &[Rest] = &[r(401, "unauthorized")];
/// A refused hop-0 credential at `POST /token`, or a refused ID token at the approval routes.
const CREDENTIAL: &[Rest] = &[r(400, "invalid_grant"), r(401, "invalid_token")];
const UNAVAILABLE_503: &[Rest] = &[r(503, "temporarily_unavailable")];
const DENY: &[JsonRpc] = &[j(DENIED, 200)];
/// A lease that is no longer live: the proxy's 401, the end event of a cut stream, or a call
/// denied by the pipeline.
const LEASE: &[JsonRpc] = &[j(UNAUTHORIZED, 401), j(UNAUTHORIZED, 200), j(DENIED, 200)];
const NONE: &[Rest] = &[];
const NO_RPC: &[JsonRpc] = &[];

/// Every stable error code, sorted by code.
#[rustfmt::skip]
pub const ERROR_CODES: &[ErrorCode] = &[
    e("actor_mismatch", BAD_REQUEST, NO_RPC, "The authenticated agent or actor token is not the request's `actor`."),
    e("actor_not_permitted", BAD_REQUEST, NO_RPC, "The actor is not in the parent token's `may_act`."),
    e("actor_token_audience_mismatch", BAD_REQUEST, NO_RPC, "The actor token's audience is not this server."),
    e("actor_token_bad_signature", BAD_REQUEST, NO_RPC, "The actor token's signature does not verify."),
    e("actor_token_expired", BAD_REQUEST, NO_RPC, "The actor token has expired, or expires now."),
    e("actor_token_invalid_spiffe_id", BAD_REQUEST, NO_RPC, "The actor token's subject is not a valid SPIFFE id."),
    e("actor_token_malformed", BAD_REQUEST, NO_RPC, "The actor token is not a well-formed JWT."),
    e("actor_token_missing_claim", BAD_REQUEST, NO_RPC, "The actor token lacks a required claim."),
    e("actor_token_missing_kid", BAD_REQUEST, NO_RPC, "The actor token names no `kid`."),
    e("actor_token_not_accepted", BAD_REQUEST, NO_RPC, "`[token] actor_auth` does not accept actor tokens."),
    e("actor_token_not_yet_valid", BAD_REQUEST, NO_RPC, "The actor token is not valid yet."),
    e("actor_token_required", BAD_CLIENT, NO_RPC, "`[token] actor_auth` requires an actor token."),
    e("actor_token_typ_mismatch", BAD_REQUEST, NO_RPC, "The actor token's `typ` header is not accepted."),
    e("actor_token_type_unsupported", BAD_REQUEST, NO_RPC, "`actor_token_type` is not `urn:ietf:params:oauth:token-type:jwt`."),
    e("actor_token_unknown_kid", BAD_REQUEST, NO_RPC, "The actor token's `kid` is not in its issuer's keys."),
    e("actor_token_unmapped_subject", BAD_REQUEST, NO_RPC, "The actor token's subject maps to no agent."),
    e("actor_token_unsupported_alg", BAD_REQUEST, NO_RPC, "The actor token's algorithm is not accepted."),
    e("actor_token_untrusted_issuer", BAD_REQUEST, NO_RPC, "The actor token's issuer is not an `[[actor_trust]]` entry."),
    e("admin_credential_expired", BEARER, NO_RPC, "The admin bearer is an `[[admin.operators]]` credential whose `expires_at` has passed."),
    e("admin_disabled", &[r(403, "admin_disabled")], NO_RPC, "The admin API is turned off."),
    e("admin_role_insufficient", &[r(403, "admin_role_insufficient")], NO_RPC, "The admin credential's role is below the one the route needs; the message names the role needed."),
    e("agent_token_refused", &[r(403, "agent_token_refused")], NO_RPC, "A delegation token cannot decide an approval."),
    e("agents_invalid", &[r(422, "agents_invalid")], NO_RPC, "The reloaded config file does not parse, or its `[[agents]]` or `[[peps]]` break a startup rule; the agents and peps in force are unchanged."),
    e("agents_reload_empties", &[r(422, "agents_reload_empties")], NO_RPC, "The reloaded config file has no `[[agents]]` (or no `[[peps]]`) while some are in force, as an empty or cut-off file has; refused unless `allow_empty` is sent. The agents and peps in force are unchanged."),
    e("already_refunded", &[r(409, "already_refunded")], NO_RPC, "The budget charge was already refunded."),
    e("approval_expired", &[r(409, "approval_expired")], NO_RPC, "The approval, or the lease it is bound to, has expired."),
    d("approval_invalid", NONE, DENY, "A presented approval token does not verify, is for another call, or names an approval that is no longer granted."),
    e("approval_not_pending", &[r(409, "approval_not_pending")], NO_RPC, "The approval is already decided."),
    d("approval_required", NONE, &[j(APPROVAL, 200)], "The policy asks a person to approve this exact call first."),
    e("approval_token_not_accepted", BAD_REQUEST, NO_RPC, "An AuthZEN action search carries `context.approval_token`; an approval token is spent only by the one decision it names."),
    d("argument_case_mismatch", NONE, DENY, "A top-level call argument name differs only in case from a name the decision reads for the tool (its catalog entry, a constraint or run limit of a capability that covers it, a loaded policy), which an upstream that ignores case would read as that name."),
    e("attribute_fixed_by_grant", &[r(403, "attribute_fixed_by_grant")], NO_RPC, "The root grant fixes this attribute; the request may not set it."),
    d("attribute_type_mismatch", NONE, DENY, "An originating-user attribute does not have its declared type."),
    e("audience_mismatch", CREDENTIAL, NO_RPC, "The credential's audience is not this server."),
    d("audit_error", NONE, DENY, "The decision could not be written to the audit log (fail closed)."),
    e("audit_pruned", &[r(410, "audit_pruned")], NO_RPC, "The audit entries asked for were pruned (`[audit.retention]`); the body names the boundary."),
    e("bad_signature", CREDENTIAL, NO_RPC, "The credential's signature does not verify."),
    e("batch_too_large", &[r(400, "batch_too_large")], NO_RPC, "An AuthZEN batch has more entries than `[authzen] max_batch`."),
    d("budget_error", NONE, DENY, "The run-limit counters could not be read or written (fail closed)."),
    d("budget_exhausted", NONE, DENY, "The call would exceed a run limit of the token."),
    d("capability_denied", NONE, DENY, "The token's capabilities do not permit the call."),
    e("chain_mismatch", &[r(400, "chain_mismatch")], NO_RPC, "The chain in the body is not the bearer token's chain."),
    e("chain_not_issued", &[r(403, "chain_not_issued")], NO_RPC, "A PEP's unsigned body chain was not issued by this server."),
    e("chain_too_deep", &[r(400, "invalid_scope")], NO_RPC, "An exchange's chain would be deeper than `[issuer] max_depth`."),
    e("charge_pruned", &[r(410, "charge_pruned")], NO_RPC, "The budget charge of the decision was pruned."),
    e("check_unavailable", &[r(409, "check_unavailable")], NO_RPC, "The policy check cannot run in this configuration."),
    e("client_assertion_audience_mismatch", BAD_CLIENT, NO_RPC, "The client assertion's `aud` is not exactly this server's issuer identifier (`[issuer] issuer`)."),
    e("client_assertion_expired", BAD_CLIENT, NO_RPC, "The client assertion has expired."),
    e("client_assertion_lifetime_too_long", BAD_CLIENT, NO_RPC, "The client assertion's `exp` is further ahead than `[token] client_assertion_max_lifetime_seconds`."),
    e("client_assertion_malformed", BAD_CLIENT, NO_RPC, "The client assertion is not a well-formed JWT, or its `typ` names another kind of token."),
    e("client_assertion_missing_claim", BAD_CLIENT, NO_RPC, "The client assertion lacks `exp` or `jti`."),
    e("client_assertion_not_yet_valid", BAD_CLIENT, NO_RPC, "The client assertion's `nbf` or `iat` is in the future."),
    e("client_assertion_replayed", BAD_CLIENT, NO_RPC, "The client assertion (its `jti`) was already used."),
    e("client_assertion_subject_mismatch", BAD_CLIENT, NO_RPC, "The client assertion's `iss` and `sub` are not both the client id, or differ from the request's client id."),
    e("client_assertion_type_unsupported", BAD_REQUEST, NO_RPC, "`client_assertion_type` is not `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`."),
    e("client_assertion_unsupported_alg", BAD_CLIENT, NO_RPC, "The client assertion's `alg` is not one the server accepts (RS256, ES256, EdDSA)."),
    e("client_auth_missing", BAD_CLIENT, NO_RPC, "No client credentials were sent."),
    e("client_auth_not_accepted", BAD_REQUEST, NO_RPC, "`[token] actor_auth` does not accept client credentials."),
    e("client_authentication_failed", BAD_CLIENT, NO_RPC, "The client id or secret is wrong, the client has no credential of the kind sent, or a client assertion is not signed by one of the client's keys (unknown client, unknown `kid`, a key of another algorithm, a bad signature: one answer)."),
    e("client_cert_header_malformed", BAD_REQUEST, NO_RPC, "On the `[server.forwarded_client_cert]` listener, `Client-Cert` or `Client-Cert-Chain` is not a well-formed RFC 9440 header: not one byte sequence, parameters, a repeated line, bad base64, too large, too many intermediates, a chain without a leaf, or not a certificate."),
    e("client_cert_header_not_accepted", BAD_REQUEST, NO_RPC, "A `Client-Cert` or `Client-Cert-Chain` header was sent to a listener other than the `[server.forwarded_client_cert]` listener, while that section is set."),
    e("client_certificate_mismatch", &[r(401, "invalid_token")], &[j(UNAUTHORIZED, 401)], "The token is bound to a TLS client certificate (`cnf.x5t#S256`) and the request shows another certificate."),
    e("client_certificate_required", &[r(401, "invalid_token")], &[j(UNAUTHORIZED, 401)], "The token is bound to a TLS client certificate (`cnf.x5t#S256`) and the request shows none: a plain-HTTP listener, a TLS connection without a client certificate, or the gateway route."),
    e("client_id_mismatch", CREDENTIAL, NO_RPC, "The credential was issued to another client."),
    e("config_file_mismatch", &[r(422, "config_file_mismatch")], NO_RPC, "The reloaded config file's `[issuer]` (its key files aside) or `[audit]` differs from the running config, so it may be another server's file; refused unless `allow_mismatch` is sent. The agents and peps, or the keys, in force are unchanged."),
    e("config_unreadable", &[r(500, "server_error")], NO_RPC, "The config file the server was started with cannot be read, so the operators, the agents and peps, or the keys were not reloaded; the cause is in the server log only."),
    e("credential_audience_mismatch", CREDENTIAL, NO_RPC, "The ID token was not issued to the presenting agent: its `aud` or `azp` names another client."),
    e("credential_expired", BAD_GRANT, NO_RPC, "The hop-0 credential expires before the token could be issued."),
    e("credential_pop_mismatch", BAD_GRANT, NO_RPC, "The DPoP proof is by another key than the one the ID-JAG is bound to (`cnf.jkt`)."),
    e("credential_pop_required", BAD_GRANT, NO_RPC, "The ID-JAG is bound to a key (`cnf`) and the request has no DPoP proof that this server checks."),
    e("credential_type_not_accepted", BAD_GRANT, NO_RPC, "The credential's issuer is an `[[idps]]` entry whose `credentials` does not list this kind (an ID token or an ID-JAG)."),
    e("dpop_liveness_stale", UNAVAILABLE_503, &[j(UNAVAILABLE, 503)], "The server cannot keep its liveness marker ahead of its clock (a database write fails), so it accepts no DPoP proof; retry later."),
    e("dpop_replay_cache_full", UNAVAILABLE_503, &[j(UNAVAILABLE, 503)], "Too many DPoP proofs are in flight; retry later."),
    e("dpop_required", &[r(401, "dpop_required")], &[j(UNAUTHORIZED, 401)], "The token is bound to a key and no DPoP proof was sent."),
    e("dpop_with_certificate_binding", &[r(400, "invalid_request"), r(401, "invalid_token")], &[j(UNAUTHORIZED, 401)], "A DPoP proof (or the `DPoP` scheme) came with a token that is bound to a TLS client certificate, or with a `POST /token` request whose new token is bound to one: a token has one binding."),
    e("duplicate_actor", BAD_REQUEST, NO_RPC, "The `actor` is already in the chain."),
    e("expired", CREDENTIAL, NO_RPC, "The credential has expired."),
    e("ext_authz_ambiguous_body", NONE, &[j(INVALID_REQUEST, 400)], "A gateway forwarded a body with a duplicate member, two member names that differ only in case, or a number not written as it is read (`/ext-authz/v1/mcp/{server}`)."),
    e("ext_authz_batch_unsupported", NONE, &[j(INVALID_REQUEST, 400)], "A gateway forwarded a JSON-RPC batch, which `/ext-authz/v1/mcp/{server}` does not decide."),
    e("ext_authz_body_incomplete", NONE, &[j(INVALID_REQUEST, 403)], "A gateway did not send the whole body (`x-envoy-auth-partial-body` is not `false`)."),
    e("ext_authz_dpop_url_unset", NONE, &[j(UNAUTHORIZED, 401)], "A DPoP proof came through a gateway route whose `[[ext_authz]]` entry has no `dpop_url`."),
    e("ext_authz_unauthenticated", NONE, &[j(UNAUTHORIZED, 403)], "A request to `/ext-authz/v1/mcp/{server}` lacks the `[[ext_authz]]` entry's gateway secret."),
    e("forwarded_peer_not_trusted", &[r(403, "forwarded_peer_not_trusted")], NO_RPC, "A connection to the `[server.forwarded_client_cert]` listener came from an address that is not in `trusted_peers`; every request on it is refused, before routing."),
    e("id_jag_ceiling_empty", &[r(400, "invalid_scope")], NO_RPC, "An ID-JAG from an issuer with `[idps.id_jag_ceiling]`: its `resource`, `scope` and `authorization_details` claims leave nothing of the root grant (each names only what is unmapped, of an unknown type, or not in the grant)."),
    d("input_type_mismatch", NONE, DENY, "A call argument does not have the type the catalog declares."),
    e("invalid_agent", BAD_GRANT, NO_RPC, "The agent id of the token to mint is empty (an exchange's `actor`, or `agent` at `POST /admin/root-token`)."),
    e("invalid_capability", &[r(400, "invalid_grant"), r(400, "invalid_scope")], NO_RPC, "A requested capability is not one a call can have: a server or tool name that breaks the naming rules, or a malformed limit (sent with `error` `invalid_grant`); or a shorthand that is not `server:tool` (a form `scope` at `POST /token`, `capabilities` at `POST /admin/root-token`; sent with `error` `invalid_scope`)."),
    e("invalid_chain", &[r(400, "invalid_chain"), r(400, "invalid_request")], NO_RPC, "The chain in the body does not validate (`POST /admin/policies/evaluate`, or a PEP's unsigned chain at AuthZEN, sent with `error` `invalid_request`)."),
    e("invalid_client", BAD_CLIENT, NO_RPC, "Client authentication failed."),
    e("invalid_cursor", &[r(400, "invalid_cursor")], NO_RPC, "The paging cursor (or an AuthZEN search's `page.token`) is malformed or belongs to another list, order or query."),
    e("invalid_dpop_proof", &[r(401, "invalid_dpop_proof")], &[j(UNAUTHORIZED, 401)], "The DPoP proof does not verify, is replayed, or is for another key, method or URL."),
    e("invalid_grant", BAD_GRANT, NO_RPC, "The grant (subject token, lease, credential) is not valid."),
    e("invalid_host", &[r(400, "invalid_host")], NO_RPC, "The `Host` header is not a loopback name and `[server] public_url` is unset."),
    d("invalid_name", NONE, DENY, "The call's server or tool name breaks the naming rules."),
    e("invalid_page", BAD_REQUEST, NO_RPC, "An AuthZEN search's `page` is not an object, its `token` not a string, or its `limit` not an integer of at least 1."),
    e("invalid_params", NONE, &[j(INVALID_PARAMS, 200)], "The JSON-RPC params of a decided method are not valid."),
    e("invalid_request", BAD_REQUEST, &[j(INVALID_REQUEST, 400)], "The request is malformed: a missing or invalid parameter or body."),
    e("invalid_scope", &[r(400, "invalid_scope")], NO_RPC, "A subject token whose own chain widens a hop or is deeper than `[issuer] max_depth`; a request that asks for more is `scope_exceeds_parent`, `chain_too_deep` or `scope_exceeds_grant`."),
    e("invalid_search_resource", BAD_REQUEST, NO_RPC, "An AuthZEN action search's `resource` names no MCP server (`resource.properties.server`, or a `resource.id` without `/`)."),
    e("invalid_subject", BAD_GRANT, NO_RPC, "The user subject of the root token to mint is empty."),
    e("invalid_token", &[r(401, "unauthorized"), r(400, "invalid_token")], &[j(UNAUTHORIZED, 401)], "The token is malformed, not issued here, or does not verify."),
    e("jwks_unavailable", &[r(503, "temporarily_unavailable"), r(401, "invalid_token")], NO_RPC, "The issuer's keys cannot be fetched; retry later."),
    e("key_duplicate", &[r(422, "key_duplicate")], NO_RPC, "A keys reload: two of the key files hold the same key (the signing key listed in `previous_key_paths` too, or a retired key twice); the message names both files and the `kid`. The keys in force are unchanged."),
    e("key_file_invalid", &[r(422, "key_file_invalid")], NO_RPC, "A keys reload: a key file holds no Ed25519 key of the kind wanted (a key of another type or curve, a public key as the signing key, no PEM block, a damaged one); the message names the file, never its content. The keys in force are unchanged."),
    e("key_file_unreadable", &[r(422, "key_file_unreadable")], NO_RPC, "A keys reload: a key file named in `[issuer]` cannot be read (missing, no permission, not text); the message names the file. The keys in force are unchanged."),
    e("keys_config_invalid", &[r(422, "keys_config_invalid")], NO_RPC, "A keys reload: the config file does not parse, or sets no `[issuer] private_key_pem_path` (a reload never generates a key). The keys in force are unchanged."),
    e("keys_reload_drops_audit_key", &[r(422, "keys_reload_drops_audit_key")], NO_RPC, "A keys reload would leave out of the verifying keys a key that signed an audit checkpoint or anchor the log holds, or that signs them now, so `audit verify` would fail; refused unless `allow_drop_audit_key` is sent. The keys in force are unchanged."),
    e("keys_reload_drops_current", &[r(422, "keys_reload_drops_current")], NO_RPC, "A keys reload names a new signing key and leaves the current one out of `previous_key_paths`, so every token it signed would stop verifying at once; refused unless `allow_drop_current` is sent. The keys in force are unchanged."),
    d("label_error", NONE, DENY, "The call's result could not be recorded, so it is withheld."),
    d("lease_error", NONE, &[j(UNAUTHORIZED, 401), j(DENIED, 200)], "The lease store could not be read (fail closed)."),
    d("lease_expired", BAD_GRANT, LEASE, "A lease of the chain has expired (at `POST /token` and `POST /token/renew`, an ancestor lease of the token)."),
    d("lease_revoked", &[r(409, "lease_revoked"), r(400, "invalid_grant")], LEASE, "A lease of the chain (at `POST /token` and `POST /token/renew`, the token's own lease or an ancestor's), or the one an approval is bound to, has been revoked."),
    d("lease_unknown", BAD_GRANT, LEASE, "A lease of the chain is unknown to the lease store (fail closed); at `POST /token` and `POST /token/renew`, the token's own lease or an ancestor's."),
    d("limit_arg_invalid", NONE, DENY, "The call lacks an argument a run limit counts, or has a value it cannot count."),
    e("limit_conflict_at_root", &[r(400, "invalid_scope")], NO_RPC, "The hop-0 request (an IdP credential at `POST /token`, or `POST /admin/root-token` when `[[root_grants]]` is set) has a capability under one or more limited capabilities of the root grant or of the ID-JAG's claims (each covers its calls), and their limits, or its own and theirs, set one kind of limit on different arguments, which one capability cannot carry together; ask for a capability fewer of them cover. A conflict with the request's own limit is `scope_exceeds_grant` (or `scope_exceeds_id_jag`) instead when attenuation clamps the capability to the limited capability it conflicts with (SR-132)."),
    e("limit_split_at_root", &[r(400, "invalid_scope")], NO_RPC, "The hop-0 request (an IdP credential at `POST /token`, or `POST /admin/root-token` when `[[root_grants]]` is set) has two capabilities under the same limited capability of the root grant or of the ID-JAG's claims (it covers the calls of both, whether or not it is the one each takes its limits from); ask for one capability with a `one_of` or wider constraint instead."),
    e("malformed_client_auth", BAD_CLIENT, NO_RPC, "The HTTP Basic credentials are malformed."),
    e("malformed_request", BAD_REQUEST, NO_RPC, "The token request is missing a field or has an invalid one (at `POST /token`, also a body that is not JSON or a well-formed form)."),
    e("malformed_token", CREDENTIAL, NO_RPC, "The credential is not a well-formed JWT."),
    e("may_act_exceeds_grant", BAD_REQUEST, NO_RPC, "`may_act` names agents the grant does not allow."),
    e("missing_claim", CREDENTIAL, NO_RPC, "The credential lacks a required claim."),
    e("missing_kid", CREDENTIAL, NO_RPC, "The credential names no `kid`."),
    e("missing_token", BEARER, &[j(UNAUTHORIZED, 401)], "No credential was sent."),
    e("multiple_client_auth", BAD_REQUEST, NO_RPC, "Client credentials were sent in more than one way (HTTP Basic and the body, or a secret and a client assertion)."),
    e("no_agents_configured", BAD_CLIENT, NO_RPC, "No `[[agents]]` are configured, so no agent can authenticate."),
    e("no_capabilities_requested", BAD_REQUEST, NO_RPC, "The token request (`POST /token`, `POST /admin/root-token`) asks for no capability."),
    e("no_lifetime_left", BAD_REQUEST, NO_RPC, "The new token would expire immediately."),
    e("no_peps_configured", BAD_CLIENT, NO_RPC, "No `[[peps]]` are configured, so no PEP can authenticate."),
    e("no_root_grant", &[r(403, "no_root_grant"), r(400, "invalid_scope")], NO_RPC, "No `[[root_grants]]` entry covers the agent and user."),
    e("not_found", &[r(404, "not_found")], NO_RPC, "The resource does not exist, or is not visible to the caller."),
    e("not_yet_valid", CREDENTIAL, NO_RPC, "The credential is not valid yet."),
    e("one_of_too_long", &[r(400, "invalid_scope")], NO_RPC, "A requested capability (an exchange, a hop-0 request, `POST /admin/root-token`) has a `one_of` constraint with more than 1,024 values."),
    e("operators_invalid", &[r(422, "operators_invalid")], NO_RPC, "The reloaded `[[admin.operators]]` list is not TOML or breaks a startup rule; the operators in force are unchanged."),
    e("operators_no_admin", &[r(422, "operators_no_admin")], NO_RPC, "The reloaded `[[admin.operators]]` list would leave no unexpired credential with role `admin`; the operators in force are unchanged."),
    e("overloaded", UNAVAILABLE_503, &[j(UNAVAILABLE, 503)], "`[limits] max_in_flight` requests are already running; retry after `Retry-After`."),
    e("parse_error", NONE, &[j(PARSE, 400)], "The body is not JSON."),
    d("policy_deny", NONE, DENY, "The Cedar policy denies the call."),
    d("policy_error", NONE, DENY, "The call could not be evaluated safely (fail closed)."),
    e("policy_invalid", &[r(422, "policy_invalid")], NO_RPC, "The policy set does not parse or validate."),
    e("prune_archive_mismatch", &[r(409, "prune_archive_mismatch")], NO_RPC, "The archive a prune request describes (`from`, `through_hash`) is not the prefix the prune removes, or not the one a repeated prune was made with."),
    e("prune_conflict", &[r(409, "prune_conflict")], NO_RPC, "The log was already pruned through this seq with another archive digest."),
    e("prune_disabled", &[r(409, "prune_disabled")], NO_RPC, "`[audit.retention] prune` is `\"off\"`: the audit log is not pruned."),
    e("prune_in_progress", &[r(409, "prune_in_progress")], NO_RPC, "The rows of an earlier prune are still being deleted."),
    e("prune_live_run", &[r(409, "prune_live_run")], NO_RPC, "A run still in the lease registry has entries at or below the requested boundary."),
    e("prune_not_at_checkpoint", &[r(409, "prune_not_at_checkpoint")], NO_RPC, "The requested boundary is not a signed checkpoint that matches the log."),
    e("prune_too_recent", &[r(409, "prune_too_recent")], NO_RPC, "The entry at the requested boundary is younger than `[audit.retention] min_age_seconds`."),
    e("rate_limited", &[r(429, "rate_limited")], &[j(TOO_MANY, 429)], "A rate limit is used up; retry after `Retry-After`."),
    e("reload_unavailable", &[r(409, "reload_unavailable")], NO_RPC, "The policy, the admin operators, the agents and peps, the issuer keys or the TLS certificate cannot be reloaded in this configuration (no policy file; a server not started from a config file; no `[server.tls]`)."),
    e("replay_cache_full", UNAVAILABLE_503, NO_RPC, "Too many single-use credentials are in flight; retry later."),
    e("replay_store_unavailable", UNAVAILABLE_503, NO_RPC, "The use of a single-use credential could not be recorded, so it is refused (fail closed); retry later."),
    e("replayed", BAD_GRANT, NO_RPC, "The credential or delegation was already used."),
    e("request_timeout", &[r(408, "request_timeout"), r(503, "temporarily_unavailable")], NO_RPC, "The body did not arrive in time (408), or the route did not answer in time (503)."),
    e("request_too_large", &[r(413, "request_too_large")], &[j(INVALID_REQUEST, 413)], "The request body is over the size limit."),
    e("reserved_agent", BAD_REQUEST, NO_RPC, "The `actor` is the reserved agent `attenuo`."),
    e("reserved_subject", &[r(400, "invalid_request"), r(400, "invalid_grant")], NO_RPC, "The subject is reserved."),
    e("scope_exceeds_grant", &[r(400, "invalid_scope")], NO_RPC, "The hop-0 request (an IdP credential at `POST /token`, or `POST /admin/root-token`) asks for more than the root grant allows."),
    e("scope_exceeds_id_jag", &[r(400, "invalid_scope")], NO_RPC, "An ID-JAG from an issuer with `[idps.id_jag_ceiling]`: the request is within the root grant but asks for more than the ID-JAG's own claims allow."),
    e("scope_exceeds_parent", &[r(400, "invalid_scope")], NO_RPC, "An exchange asks for more than the subject token holds."),
    e("server_error", &[r(500, "server_error")], NO_RPC, "An internal error; the cause is in the server log only."),
    e("session_mismatch", NONE, &[j(DENIED, 403)], "The `Mcp-Session-Id` belongs to another principal."),
    e("session_registry_full", NONE, &[j(UNAVAILABLE, 503)], "No free session slot (`[proxy] max_sessions`)."),
    e("session_unknown", NONE, &[j(INVALID_REQUEST, 404)], "The `Mcp-Session-Id` is not bound; start a new session."),
    e("sink_behind", &[r(409, "sink_behind")], NO_RPC, "The checkpoint sink is degraded or has not delivered the checkpoint at the requested boundary."),
    e("tenant_mismatch", BAD_GRANT, NO_RPC, "The ID-JAG's `tenant` is not the `[[idps]] tenant` of its issuer."),
    e("tls_certificate_expired", &[r(422, "tls_certificate_expired")], NO_RPC, "A TLS certificate reload: the first certificate of `[server.tls] cert_pem_path` has expired (its `notAfter` is in the past). The certificate in force is unchanged."),
    e("tls_certificate_not_yet_valid", &[r(422, "tls_certificate_not_yet_valid")], NO_RPC, "A TLS certificate reload: the first certificate of `[server.tls] cert_pem_path` is not valid yet (its `notBefore` is in the future). The certificate in force is unchanged."),
    e("tls_file_invalid", &[r(422, "tls_file_invalid")], NO_RPC, "A TLS certificate reload: a `[server.tls]` file can be read but not used (empty, not PEM, no certificate, a private key in the certificate file, no key or more than one private key of any kind, a key or certificate rustls cannot use, dates that cannot be read, a first certificate that is a CA, or a chain of more than 10 certificates or 64 KiB of DER). The message names the setting, never the path or the content. The certificate in force is unchanged."),
    e("tls_file_unreadable", &[r(422, "tls_file_unreadable")], NO_RPC, "A TLS certificate reload: a `[server.tls]` file cannot be read (missing, no permission, not a regular file, too large), or the key file's owner or mode is refused as at startup. The message names the setting, never the path. The certificate in force is unchanged."),
    e("tls_key_mismatch", &[r(422, "tls_key_mismatch")], NO_RPC, "A TLS certificate reload: the private key of `[server.tls] key_pem_path` does not belong to the first certificate of `cert_pem_path`. The certificate in force is unchanged."),
    e("token_expired", &[r(401, "unauthorized"), r(400, "invalid_grant")], &[j(UNAUTHORIZED, 401), j(UNAUTHORIZED, 200)], "The token verified but has expired (a bearer, or at `POST /token` the subject token or a hop of its chain)."),
    e("too_many_capabilities", &[r(400, "invalid_scope")], NO_RPC, "A request (an exchange, a hop-0 request, `POST /admin/root-token`) asks for more than 1,024 capabilities, more than one token may hold."),
    e("too_many_constraints", &[r(400, "invalid_scope")], NO_RPC, "A request (an exchange, a hop-0 request, `POST /admin/root-token`) has more than 1,024 argument constraints over all its capabilities."),
    e("too_many_one_of_values", &[r(400, "invalid_scope")], NO_RPC, "A request (an exchange, a hop-0 request, `POST /admin/root-token`) has more than 1,024 `one_of` values over all its capabilities."),
    e("too_many_pending_approvals", &[r(429, "too_many_pending_approvals")], NO_RPC, "The run already has the maximum number of pending approvals."),
    e("too_many_sessions", NONE, &[j(TOO_MANY, 429)], "The principal holds `[proxy] max_sessions_per_principal` live sessions."),
    d("tool_not_in_catalog", NONE, DENY, "The tool is not in the catalog and unknown tools are denied."),
    d("tool_not_listed", NONE, DENY, "The upstream never listed the tool and the catalog does not know it."),
    e("ttl_out_of_range", BAD_GRANT, NO_RPC, "The requested lifetime gives no representable expiry (`POST /admin/root-token`; an exchange clamps it to the parent's instead)."),
    e("typ_mismatch", CREDENTIAL, NO_RPC, "The credential's `typ` header does not match its kind."),
    e("unknown_kid", CREDENTIAL, NO_RPC, "The credential's `kid` is not in its issuer's keys."),
    e("unknown_server", NONE, &[j(UNKNOWN_SERVER, 404)], "No `[[upstreams]]` entry has this name."),
    e("unsupported_alg", CREDENTIAL, NO_RPC, "The credential's signing algorithm is not accepted."),
    e("unsupported_grant_type", &[r(400, "unsupported_grant_type")], NO_RPC, "The `grant_type` is not supported."),
    e("unsupported_media_type", &[r(415, "unsupported_media_type")], NO_RPC, "The console listener requires `Content-Type: application/json`."),
    e("unsupported_token_type", BAD_REQUEST, NO_RPC, "The `subject_token_type` is not supported (neither the JWT URN of an exchange nor a hop-0 credential type)."),
    e("untrusted_issuer", CREDENTIAL, NO_RPC, "The credential's issuer is not an `[[idps]]` entry."),
    e("upstream_body_too_large", NONE, &[j(UPSTREAM, 502)], "An upstream body the proxy buffers is over `[proxy] max_upstream_body_bytes`."),
    e("upstream_invalid_response", NONE, &[j(UPSTREAM, 502)], "The upstream's answer is not one the proxy can filter or label."),
    e("upstream_not_event_stream", NONE, &[j(UPSTREAM, 502)], "The upstream answered a `GET` with something other than an event stream."),
    e("upstream_stream_end_shape", NONE, &[j(UPSTREAM, 200)], "The upstream sent an error in the shape of the proxy's stream end; the original is in `data.upstream_error`."),
    e("upstream_timeout", NONE, &[j(UPSTREAM, 504)], "The upstream did not answer in time; it may have acted on the request."),
    e("upstream_unreachable", NONE, &[j(UPSTREAM, 502)], "The upstream could not be reached; nothing was sent."),
    e("use_dpop_nonce", &[r(401, "use_dpop_nonce")], &[j(UNAUTHORIZED, 401)], "The DPoP proof lacks the current server nonce; retry with `DPoP-Nonce`."),
    e("wrong_user", &[r(403, "wrong_user")], NO_RPC, "The ID token is another user's."),
];

/// The table entry of `code`, if it has one.
pub fn lookup(code: &str) -> Option<&'static ErrorCode> {
    ERROR_CODES
        .binary_search_by(|e| e.code.cmp(code))
        .ok()
        .map(|i| &ERROR_CODES[i])
}

/// Does the table list `code` as a REST answer with this status and `error`?
pub fn is_rest(code: &str, status: u16, error: &str) -> bool {
    lookup(code).is_some_and(|e| {
        e.rest
            .iter()
            .any(|r| r.status == status && r.error == error)
    })
}

/// Does the table list `code` as a JSON-RPC error with this number?
pub fn is_jsonrpc(code: &str, number: i64) -> bool {
    lookup(code).is_some_and(|e| e.jsonrpc.iter().any(|j| j.number == number))
}

/// Is `code` snake_case ASCII (lower-case letters, digits and single underscores, starting
/// with a letter)?
pub fn is_well_formed(code: &str) -> bool {
    let b = code.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.last() != Some(&b'_')
        && !code.contains("__")
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sorted and without duplicates (so [`lookup`]'s binary search works and no two entries
    /// collide), every code well formed, and every entry sent in at least one form.
    #[test]
    fn table_is_sorted_unique_and_complete() {
        for w in ERROR_CODES.windows(2) {
            assert!(
                w[0].code < w[1].code,
                "`{}` and `{}`: the table must be sorted by code with no duplicates",
                w[0].code,
                w[1].code
            );
        }
        for e in ERROR_CODES {
            assert!(is_well_formed(e.code), "`{}` is not snake_case", e.code);
            assert!(
                !e.rest.is_empty() || !e.jsonrpc.is_empty(),
                "`{}` is sent in no form",
                e.code
            );
            for r in e.rest {
                assert!((400..600).contains(&r.status), "`{}`: {}", e.code, r.status);
                assert!(is_well_formed(r.error), "`{}`: {}", e.code, r.error);
            }
            assert!(
                !e.meaning.is_empty() && e.meaning.ends_with('.'),
                "`{}`",
                e.code
            );
            for (i, r) in e.rest.iter().enumerate() {
                assert!(!e.rest[..i].contains(r), "`{}` lists {r:?} twice", e.code);
            }
            for (i, j) in e.jsonrpc.iter().enumerate() {
                assert!(
                    !e.jsonrpc[..i].contains(j),
                    "`{}` lists {j:?} twice",
                    e.code
                );
            }
            assert_eq!(lookup(e.code), Some(e));
        }
        assert_eq!(lookup("no_such_code"), None);
    }

    /// A REST `error` that is itself a code names the same condition: it is listed, with that
    /// status, as a form of its own entry, so that `code == error` is valid for an answer with
    /// no `error_description` and no more specific reason.
    #[test]
    fn every_rest_error_member_is_a_code_of_its_own() {
        for e in ERROR_CODES {
            for r in e.rest {
                if r.error == "unauthorized" || r.error == "temporarily_unavailable" {
                    // Always sent with a sub-code in `error_description`.
                    continue;
                }
                assert!(
                    lookup(r.error).is_some(),
                    "`{}`: its `error` `{}` is not a code",
                    e.code,
                    r.error
                );
            }
        }
    }

    #[test]
    fn well_formed() {
        assert!(is_well_formed("lease_revoked"));
        assert!(is_well_formed("a1"));
        assert!(!is_well_formed(""));
        assert!(!is_well_formed("Lease"));
        assert!(!is_well_formed("_x"));
        assert!(!is_well_formed("x_"));
        assert!(!is_well_formed("a__b"));
        assert!(!is_well_formed("id-jag"));
    }
}
