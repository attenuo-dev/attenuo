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
| 7.1.2.1: `options.evaluations_semantic`, default `execute_all` | `execute_all` (sent or left out), `deny_on_first_deny` and `permit_on_first_permit`. See [batch semantics](#batch-semantics). Any other value, or one that is not a string, is 400 `invalid_request` before anything is decided. |
| 7.2.1: an entry that cannot be evaluated is closed (`decision: false`) and says why in its `context` | `{"decision": false, "context": {"error": {"status", "code", "message"}}}`, following the spec's non-normative `{status, message}` example with Attenuo's error code added. The other entries are still decided. A failed authentication refuses the whole request instead (401 or 403). |
| 9, 9.1.1, 9.2: discovery at `GET /.well-known/authzen-configuration` | `policy_decision_point` and `access_evaluation_endpoint` (both required) and `access_evaluations_endpoint`, without authentication. See [discovery](#discovery). |
| 10.1: HTTPS `POST` with JSON bodies at the default paths `/access/v1/evaluation` and `/access/v1/evaluations` | Implemented. The server listens on plain HTTP and is expected behind TLS termination in production ([deploying](../guides/deploying.md)). |
| 10.1.2: 400, 401, 403 and 500 for failed requests | 400 for a malformed request, 401 for a missing or bad credential, 403 `chain_not_issued` for an unsigned body chain that this server did not issue, 500 for internal errors. 503 can also occur (a JWKS that cannot be fetched, a full DPoP replay cache). |
| 10.1.3: when the request carries `X-Request-ID`, the answer MUST carry the same value | Implemented on both evaluation endpoints, for successful and refused requests alike. A request without one gets none. |

## Batch semantics

Section 7.1.2.1 defines three values for `options.evaluations_semantic` on `POST /access/v1/evaluations`:

- `execute_all` (the default): every entry is decided and answered, in request order.
- `deny_on_first_deny`: "deny on first denial (or failure)", short-circuiting like `&&`. Entries are decided in order and the batch stops after the first entry answered `decision: false`. An entry that cannot be evaluated (7.2.1, answered with `context.error`) is a failure and stops the batch too.
- `permit_on_first_permit`: the converse, like `||`. Entries are decided in order and the batch stops after the first entry answered `decision: true`. A failed entry is not a permit and does not stop it.

**Entries after the stop are left out, not answered as denied.** The specification's text does not say this in so many words, but its examples do: three requests under `deny_on_first_deny` get two answers (permit, then the deny), and three under `permit_on_first_permit` get one. Attenuo follows the examples, so `evaluations` in the answer holds exactly the entries that were decided, in request order, ending with the one that stopped the batch. The i-th answer still belongs to the i-th request (7.2). A PEP that gets fewer answers than it sent knows the batch stopped, and the last answer says why.

Entries that were not decided have no side effects: no audit record, no charge to the run's limits, no approval used. Each decided entry is audited exactly as under `execute_all`. Authentication failures still refuse the whole request (401 or 403) before or instead of any answer, and `[authzen] max_batch` counts the entries sent, not the ones decided.

The answer to the deciding entry keeps Attenuo's own `context` (`reason` such as `policy_deny`, `policy_ids`, `decision_id`, ...). The specification's non-normative example puts `"reason": "deny_on_first_deny"` there instead; Attenuo does not overwrite the policy reason, which is what the audit record says.

Fixtures: `evaluations-deny-on-first-deny.json`, `evaluations-permit-on-first-permit.json` and `evaluations-semantics.json`. `stopped_batch_audits_only_what_it_ran` in `authzen_conformance.rs` checks that a stopped batch leaves one audit record per answered entry, with the answer's `decision_id`, and none for the rest.

## Discovery

`GET /.well-known/authzen-configuration` serves the PDP metadata document of section 9, at the well-known path of 9.2, answering a `GET` (9.2.1) with 200 and `Content-Type: application/json` (9.2.2):

```json
{
  "policy_decision_point": "https://attenuo.example",
  "access_evaluation_endpoint": "https://attenuo.example/access/v1/evaluation",
  "access_evaluations_endpoint": "https://attenuo.example/access/v1/evaluations"
}
```

- **Members (9.1.1).** `policy_decision_point` and `access_evaluation_endpoint` are required; `access_evaluations_endpoint` is optional and present because the batch endpoint is served. `search_subject_endpoint`, `search_action_endpoint` and `search_resource_endpoint` are left out because the Search APIs are not served: an absent parameter tells the PEP the PDP does not support that API. `capabilities` (9.1.2) and `signed_metadata` (9.1.3) are not published. Nothing else is in the document.
- **Base URL.** `[server] public_url`, so `policy_decision_point` is the identifier a PEP configured and 9.2.3's identity check passes. Without it, which is allowed only on a loopback listener, the base is `http://<Host>` and `Host` must be `localhost`, `127.0.0.1` or `[::1]` (400 `invalid_host` otherwise), so a forged `Host` cannot end up in a document a shared cache serves to others (SR-19).
- **No authentication, by decision.** The specification does not protect the metadata endpoint: its 9.2.1 example request carries no credential, and 11.8 relies on TLS at the hosting site for the integrity of unsigned metadata. A PEP also needs the document before it can know where to send credentials. So discovery is public like `/.well-known/jwks.json`: it takes no credential and ignores an `Authorization` header (an invalid bearer gets the same document, not a 401). That is safe because the document holds only the server's public base URL and the two fixed endpoint paths, all of which any caller of the API already knows: no policy, tenant, lease, key, configuration or version information, and it does not vary with the caller.

Fixture: `metadata.json` (no credential, and an invalid bearer; the comparison is exact, so an extra member fails it). The `Host` checks are tested in `security_low.rs`.

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
- **Discovery capabilities and signed metadata (9.1.2, 9.1.3).** `capabilities` and `signed_metadata` are not published.
- **`Content-Type` (10.1).** Requests are not refused for a missing or different `Content-Type`; the body is parsed as JSON whatever the header says.
- **HTTPS-only identifiers (9).** On a loopback listener without `[server] public_url`, `policy_decision_point` is an `http://` URL. That is meant for local development only.
