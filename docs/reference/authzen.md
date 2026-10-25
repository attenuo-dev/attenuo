# AuthZEN conformance

Attenuo's decision endpoint follows the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html) (final, January 2026). This page lists what of that specification the server implements, what it adds, and what it leaves out. It was checked against `crates/attenuo-server/src/routes/authzen.rs`, `crates/attenuo-policy/src/authzen.rs` and `crates/attenuo-server/src/routes/wellknown.rs`. Section numbers below are the specification's.

The conformance fixtures in `crates/attenuo-server/tests/fixtures/authzen/` exercise every row marked as implemented. Each fixture is a JSON request and the answer the server must give, with a `_note` naming the section it covers. `crates/attenuo-server/tests/authzen_conformance.rs` runs them all against one server. It compares the status and the whole answer exactly. The only tolerance is for values that are random or depend on the clock: `decision_id`, `approval_id`, `call_hash`, `expires_at`, and the server's own URL in discovery.

The endpoints and their configuration are also listed in the [HTTP API reference](http-api.md#decision) and the [configuration reference](config.md#authzen).

## Implemented

| Specification | Attenuo |
| --- | --- |
| 5.1 to 5.4, 6.1: request of `subject` (`type`, `id`, `properties`), `action` (`name`, `properties`), `resource` (`type`, `id`, `properties`) and an optional `context` | `POST /access/v1/evaluation`. `subject`, `action` and `resource` are required; if one is missing, or one of its required members is, the answer is 400 `invalid_request`. |
| 5.5, 6.2: answer of a boolean `decision` and an optional `context` object | Always `{"decision": <bool>, "context": {...}}`. A deny is 200 with `decision: false`, never an HTTP error. |
| 7.1, 7.1.1, 7.2: `POST /access/v1/evaluations` with an `evaluations` array; top-level `subject`, `action`, `resource` and `context` are defaults that each entry overrides, and may be left out when every entry has them; answers come back in request order as `{"evaluations": [...]}` with no top-level `decision` | Implemented. At most `[authzen] max_batch` entries (default 64); more is 400 `batch_too_large` before anything is decided. |
| 7.1: a batch request with no `evaluations`, or an empty one, behaves like a single evaluation | Implemented: it is decided as one evaluation and answered as one, `{decision, context}`. |
| 7.1.2.1: `options.evaluations_semantic`, default `execute_all` | `execute_all`, sent or left out, is the only semantic supported. See below for the other two. |
| 7.2.1: an entry that cannot be evaluated is closed (`decision: false`) and says why in its `context` | `{"decision": false, "context": {"error": {"status", "code", "message"}}}`, following the spec's non-normative `{status, message}` example with Attenuo's error code added. The other entries are still decided. A failed authentication refuses the whole request instead (401 or 403). |
| 9: discovery at `GET /.well-known/authzen-configuration` | `policy_decision_point` and `access_evaluation_endpoint` (both required) and `access_evaluations_endpoint`. The base is `[server] public_url`; without it, which is allowed only on a loopback listener, the base is `http://<Host>` and `Host` must be a loopback name. |
| 10.1: HTTPS `POST` with JSON bodies at the default paths `/access/v1/evaluation` and `/access/v1/evaluations` | Implemented. The server listens on plain HTTP and is expected behind TLS termination in production ([deploying](../guides/deploying.md)). |
| 10.1.2: 400, 401, 403 and 500 for failed requests | 400 for a malformed request, 401 for a missing or bad credential, 403 `chain_not_issued` for an unsigned body chain that this server did not issue, 500 for internal errors. 503 can also occur (a JWKS that cannot be fetched, a full DPoP replay cache). |
| 10.1.3: when the request carries `X-Request-ID`, the answer MUST carry the same value | Implemented on both evaluation endpoints, for successful and refused requests alike. A request without one gets none. |

## Extensions

These are allowed by the specification (5.5.1 lets the answer's `context` hold any object), but a generic AuthZEN client will not know them.

- **Who may call.** The specification leaves PEP authentication open (11.2). Attenuo requires the agent's delegation token as the bearer (`Authorization: Bearer <token>`, or `DPoP <token>` with a proof for a key-bound token) and decides for that token's chain. The body may repeat the chain in `subject.properties.chain`; if it does, it must equal the token's chain (400 `chain_mismatch`). With `[authzen] allow_unsigned_chain = true`, a `[[peps]]` entry may instead send an unsigned chain in the body, authenticating with HTTP Basic or `pep_id` and `pep_secret` in the body, and every hop must match a lease this server issued (403 `chain_not_issued` otherwise).
- **Subject.** `subject.type` must be `agent`; any other type is 400 `invalid_request`. An empty `subject.id` is filled in with the chain's current agent. A non-empty one must be that agent (400 otherwise).
- **Action and resource.** `action.name` is the tool. The MCP server comes from `action.properties.server`, else `resource.properties.server`, else the part of `resource.id` before `/<tool>`. `resource.type` is not checked; the convention is `tool`, with `resource.id` set to `<server>/<tool>`.
- **Request context.** `context.input` holds the tool's arguments and becomes Cedar's `context.input`. `context.session_id` becomes Cedar's `context.session_id`. `context.approval_token` carries a signed approval token ([approval tokens](http-api.md#approval-tokens)); anything other than a string is 400. No other member reaches Cedar: the server takes run usage, budgets and labels from its own state, and ignores what a PEP sends under `context.usage` or `context.budget`.
- **Answer context.** Always `reason` (an Attenuo reason code such as `policy_allow`, `policy_deny`, `capability_denied`, `lease_revoked`, `budget_exhausted`, `approval_required`, `approval_invalid`, `tool_not_in_catalog`), `policy_ids` (the Cedar policies that decided), `diagnostics` (empty unless `[authzen] diagnostics` allows the caller) and `decision_id` (the id of the audit record). Depending on the call, also `call_hash`, `approval_id` and `expires_at` (approval required), `approval` (an approval was used), `budget`, `charged` and `limit` (run limits), `usage` (destructive tools) and `untrusted_args` (output labelling). The [HTTP API reference](http-api.md#decision) describes each one.
- **Side effects.** An evaluation is a real decision, the same as a call through the proxy. It is written to the audit log, an allowed evaluation is charged to the run's limits and counted in its usage, and a granted approval is used up. Use the admin dry run `POST /admin/policies/evaluate` to ask without these effects.
- **Error bodies.** Refused requests answer with a JSON object, `{"error": "<code>", "detail": "<text>"}`, and add `error_description` on a 401. The specification's table describes the body as "an error message string"; the object form matches the rest of Attenuo's API.

## Not implemented

- **Search APIs (section 8).** `/access/v1/search/subject`, `/access/v1/search/resource` and `/access/v1/search/action` are not served, and discovery leaves out their endpoint parameters, which signals that they are not supported (9.1.1). Note that 10.1 also says a client SHOULD fall back to the default path when a parameter is absent; such a client gets 404 from Attenuo.
- **`deny_on_first_deny` and `permit_on_first_permit` (7.1.2.1).** They are refused with 400 `invalid_request` before anything is decided. Supporting them would mean stopping after the first matching entry and returning the shorter list.
- **Discovery capabilities and signed metadata (9.1.2, 9.1.3).** `capabilities` and `signed_metadata` are not published.
- **`Content-Type` (10.1).** Requests are not refused for a missing or different `Content-Type`; the body is parsed as JSON whatever the header says.
- **HTTPS-only identifiers (9).** On a loopback listener without `[server] public_url`, `policy_decision_point` is an `http://` URL. That is meant for local development only.
