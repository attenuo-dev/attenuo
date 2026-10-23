# HTTP endpoints

All routes the server mounts, from the route table in `crates/onbehalf-server/src/lib.rs` and the proxy router. Errors on non-MCP routes look like `{"error": "<code>", "detail": "<text>"}`. The codes for `/token` are listed in [design/server.md](../design/server.md#error-codes).

## Public

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | Liveness. Never touches storage. |
| `GET /readyz` | none | Readiness. Checks the audit store and the lease store. 200 or 503. |
| `GET /.well-known/jwks.json` | none | Public keys for token verification, including retired keys. |
| `GET /.well-known/authzen-configuration` | none | AuthZEN discovery: decision point and evaluation endpoint URLs. |

## Token

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /token` | agent client credentials at hop 0, parent token at later hops | RFC 8693 token exchange, as a form or JSON. Hop 0 takes an OIDC ID token or an ID-JAG. Later hops take a parent delegation token and `authorization_details`. |
| `POST /token/renew` | bearer delegation token | Extend the lease of the token's last hop. Returns `{lease, expires_at, expires_in}`. |

## Decision

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /access/v1/evaluation` | bearer token, or a trusted PEP | AuthZEN evaluation. Same pipeline as the proxy. |

## MCP proxy

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /mcp/{server}` | bearer delegation token | Send an MCP request to the upstream called `server`. `tools/call` and similar methods are decided first. |
| `GET /mcp/{server}` | bearer delegation token | Passthrough for the streamable HTTP event stream, after the lease check. |
| `DELETE /mcp/{server}` | bearer delegation token | Passthrough session close, after the lease check. |

A denial is a JSON-RPC error with code `-32003`, carrying `reason` and `decision_id`. A missing or bad token is HTTP 401 with `-32001`. Allowed responses carry `X-Onbehalf-Decision-Id`.

## Admin

All admin routes need `Authorization: Bearer <admin token>`. They answer 401 without it and 403 `admin_disabled` when no admin token is configured.

| Method and path | Purpose |
| --- | --- |
| `GET /admin/leases/{lease_id}` | Lease state. |
| `POST /admin/leases/{lease_id}/revoke` | Revoke the lease and all descendants. |
| `GET /admin/audit` | Audit entries in ascending `seq` order, paged with `from` and `limit`. |
| `GET /admin/audit/verify` | Walk the whole hash chain and report. |
| `GET /admin/audit/checkpoint` | The head `{seq, hash}`, for keeping outside the host. |
| `POST /admin/policies/reload` | Re-read the policy file. On failure the old policy stays. |
| `POST /admin/root-token` | Development root mint. Mounted only when `[dev] allow_root_mint = true`. |

## Metrics

`GET /metrics` is served by a separate listener, never on the proxy port. It is enabled with `[metrics] enabled = true`, has no authentication and returns Prometheus text format 0.0.4.
