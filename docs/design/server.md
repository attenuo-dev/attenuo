# onbehalf-server: request pipeline

- Status: implemented (v0)
- Crate: `crates/onbehalf-server`
- Related: [RFC-0001](../spec/rfc-0001-onbehalf.md) §4–§7, [ADR-0004](../decisions/0004-rust-workspace-layout.md)

The server is wiring. It holds no authorization logic of its own: tokens come from `onbehalf-token`, decisions from `onbehalf-policy`, leases and the audit log from `onbehalf-audit`, MCP framing from `onbehalf-proxy`. The one piece of composition that matters for security is `authz::Pipeline`, and both enforcement paths go through it.

## Components in the process

| Piece | Type | Shared as |
|---|---|---|
| Issuer and verifier | `onbehalf_token::Issuer`, `Verifier` | one Ed25519 key, loaded from or generated at `issuer.private_key_pem_path` |
| Policy engine | `onbehalf_policy::PolicyEngine` | `Arc<RwLock<_>>`, swapped in place by `POST /admin/policies/reload` |
| Lease registry | `onbehalf_audit::SqliteLeaseStore` | `Arc`, same SQLite file as the log |
| Audit log | `onbehalf_audit::SqliteAudit` | `Arc` |
| Pipeline | `authz::Pipeline` | `Arc`, used by the proxy's `ServerAuthorizer` and by the AuthZEN handler |
| Proxy | `onbehalf_proxy::router` | mounted at `/mcp/{server}` |

## The decision pipeline

`Pipeline::decide(chain, call, now)` runs these steps for every `tools/call` and every AuthZEN evaluation. The chain has already been verified (token signature, originating-user signature, structure, expiry) by the caller.

1. **Leases.** `LeaseStore::check_all(chain.leases(), now)`. Every hop's lease must be known, unrevoked and `expires_at > now`, so a lease that its holder stopped renewing denies the call while the JWT is still valid. If not, the decision is deny, with reason `lease_revoked`, `lease_expired` or `lease_unknown` (checked in that order), or `lease_error` if the store cannot be read.
2. **Policy.** `PolicyEngine::authorize`: the capability stage (`capability_denied`), then Cedar (`policy_allow`, `policy_deny`, `policy_error`).
3. **Audit.** `DecisionRecord::new(now, decision, reason, chain, call, policy_ids)` is appended to the hash-chained log, and its id becomes the decision id the client sees (`X-Onbehalf-Decision-Id`, the JSON-RPC error's `data.decision_id`, or AuthZEN `context.decision_id`). If the append fails, the decision becomes deny with reason `audit_error`: an action that cannot be recorded does not happen.

Lease and audit failures fail closed. Revocation reaches the next request: there is no lease cache in v0, so the TTL-bounded cache in RFC-0001 §6 is a later optimisation. Requests that carry no per-call decision (`tools/list`, `initialize`, `ping`, the other allowlisted methods, `GET`/`DELETE` session requests) run the same lease check through `Authorizer::check_active` and get HTTP 401 (JSON-RPC `-32001`, message ending in the reason, for example `lease inactive: lease_revoked`) instead of a decision. Those checks are not audited, since no call was decided.

## MCP method coverage

The proxy turns every request that can read data or cause an effect into a `ToolCall` and sends it through `Pipeline::decide`, so capabilities, Cedar policy and the audit log treat a resource read like a tool call. `server` is always the `/mcp/{server}` name.

| JSON-RPC method | `ToolCall.tool` | `ToolCall.arguments` |
|---|---|---|
| `tools/call` | `params.name` | `params.arguments` (or `{}`) |
| `resources/read` | `resources/read` | `{ "uri": params.uri }` |
| `resources/subscribe` | `resources/subscribe` | `{ "uri": params.uri }` |
| `prompts/get` | `prompts/get` | `{ "name": params.name, "arguments": params.arguments or {} }` |
| `completion/complete` | `completion/complete` | `params` as sent |
| any other method outside the allowlist | the method name | `params` as sent (or `{}`) |

Forwarded after authentication and the lease check, with no decision: `initialize`, `ping`, `tools/list` (response filtered), `resources/list`, `resources/templates/list`, `prompts/list`, `logging/setLevel`, `notifications/*`, and messages without a `method` (client replies to server requests). The default is deny: an unknown method such as `sampling/createMessage` or `resources/unsubscribe` passes only if a capability and the policy permit a tool named after it. A request missing `params.name` or `params.uri` where the mapping needs one is answered with `-32602` and is not forwarded.

A capability grants these like a tool: `github:resources/read` with constraint `uri` prefix `file:///public/` allows reads under that prefix; `github:prompts/get` allows prompts. A broad `github:*` capability covers all of them, which is a reason to prefer narrow grants. The Cedar action is the method name, so catalog entries and policies for `resources/read` use that string. The `resources/list` and `prompts/list` results are not filtered (v0).

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent (MCP client)
    participant P as Proxy /mcp/{server}
    participant V as Verifier
    participant L as LeaseStore
    participant E as PolicyEngine (Cedar)
    participant G as AuditSink
    participant U as Upstream MCP server

    A->>P: POST tools/call, Authorization: Bearer <token>
    P->>V: verify(token, now)
    alt invalid or expired token
        V-->>P: TokenError
        P-->>A: HTTP 401, JSON-RPC -32001
    end
    V-->>P: DelegationChain
    P->>L: check_all(chain.leases(), now)
    alt a lease is revoked, expired or unknown
        L-->>P: inactive
        P->>G: append(DecisionRecord deny lease_*)
        P-->>A: JSON-RPC -32003 {reason, decision_id}
    else all leases active
        L-->>P: active
        P->>E: authorize(chain, call, now)
        E-->>P: Outcome {decision, reason, policy_ids}
        P->>G: append(DecisionRecord)
        G-->>P: entry (seq, hash)
        alt allow
            P->>U: forward tools/call (no onbehalf token)
            U-->>P: result
            P-->>A: result + X-Onbehalf-Decision-Id
        else deny
            P-->>A: JSON-RPC -32003 {reason, decision_id}
        end
    end
```

`POST /access/v1/evaluation` takes the same path from step 3 onward. With a bearer token, the chain comes from the verified token (a chain also present in the body must match it). Without one, the chain in `subject.properties.chain` is taken as asserted by the calling PEP, checked structurally, and still has to pass the lease check, so a chain this server never issued is denied with `lease_unknown`. The body chain carries no signatures, so the endpoint should only be reachable by trusted PEPs unless they send the bearer.

## Token issuance

```mermaid
sequenceDiagram
    autonumber
    participant C as Parent agent
    participant T as POST /token
    participant V as Verifier
    participant L as LeaseStore
    participant I as Issuer
    participant G as AuditSink

    C->>T: RFC 8693 exchange (form or JSON): subject_token, actor, authorization_details
    T->>V: verify(subject_token)
    V-->>T: parent chain (or 400 invalid_grant)
    T->>L: check_all(parent leases)
    alt parent lease inactive
        T-->>C: 400 invalid_grant "subject token cannot delegate: lease_revoked"
    end
    T->>I: ExchangeRequest::execute (attenuation, depth, expiry clamp)
    I-->>T: child token (or 400 invalid_scope / invalid_grant)
    T->>L: register(child lease, parent = parent's last lease, expires_at)
    T->>G: append(allow, token_issued, onbehalf / token.exchange)
    T-->>C: {access_token, issued_token_type, token_type, expires_in, lease}
```

Because the child lease is registered under the parent's, revoking any lease revokes every lease delegated from it, and the child's next call fails the lease step. Even without the cascade, the child's chain lists every ancestor lease, so a revoked ancestor is caught directly.

### Audit convention for issuance

The audit crate stores decision records only. An issuance is recorded as a decision record with:

| Field | Value |
|---|---|
| `decision` | `allow` |
| `reason` | `token_issued` |
| `server` | `onbehalf` |
| `tool` | `token.exchange` for `/token`, `token.root` for the dev root mint |
| chain fields | the **new** chain, so `agents` and `leases` include the new hop |
| `arguments_digest` | digest of `{actor, requested, parent_lease}` (root: `{agent, requested}`) |

If that append fails, the new lease is revoked before the error is returned, so an unrecorded token is unusable. Failed exchanges are not audited in v0.

## Hop 0: the dev root mint

RFC-0001 §4 has hop 0 minted from a verified IdP credential (OIDC ID token or ID-JAG). That intake is not built yet. `POST /admin/root-token` (module `routes::dev_root`) stands in for it: the admin bearer asserts the user and agent, nothing about the user is verified, and when `[[root_grants]]` is configured the request must match a grant and stay within its capabilities. Replace it before any real deployment.

## Lease renewal

`POST /token/renew` with `Authorization: Bearer <delegation token>` and no body extends the lease of the token's last hop.

```mermaid
sequenceDiagram
    autonumber
    participant C as Agent
    participant R as POST /token/renew
    participant V as Verifier
    participant L as LeaseStore
    participant G as AuditSink

    C->>R: Bearer <token>
    R->>V: verify(token, now)
    alt invalid or expired token
        R-->>C: 401 unauthorized
    end
    R->>L: check_all(ancestor leases)
    alt an ancestor is revoked, expired or unknown
        R-->>C: 400 invalid_grant (lease_revoked / lease_expired / lease_unknown)
    end
    R->>R: new = max(current, min(now + lease_interval, token exp, parent lease expiry))
    R->>L: renew(lease, new, now)
    alt own lease revoked or unknown
        R-->>C: 400 invalid_grant
    end
    R->>G: append(allow, lease_renewed, onbehalf / lease.renew)
    R-->>C: {lease, expires_at, expires_in}
```

Own-lease expiry is not an error: a lapsed but unrevoked lease is revived, provided the token has not expired and the ancestors are live. If the audit append fails the previous expiry is restored and the call fails. `[issuer] lease_interval_seconds` (default 300, must be positive) sets the interval used at issuance and renewal. Agents should renew at a fraction of it, for example every interval / 3.

## Errors

Non-MCP endpoints answer errors as `{"error": "<code>", "detail": "<text>"}` with a matching status. `/token` uses OAuth codes (`invalid_request`, `unsupported_grant_type`, `invalid_grant`, `invalid_scope`). Admin endpoints answer 401 without the admin bearer and 403 `admin_disabled` when no admin token is configured. MCP routes keep the proxy's JSON-RPC errors (`-32001` unauthenticated, `-32003` denied).

## Known limits (v0)

- Admin authentication is one static bearer.
- The `actor` in an exchange is asserted, not authenticated (`actor_token` is not checked).
- No `kid` in token headers; the JWKS has one key and rotation is manual.
- SQLite calls run on the async worker threads; fine at demo load, to be moved to `spawn_blocking` or a pool.
- No lease cache and no push channel: every request reads the registry, and external PEPs using the AuthZEN endpoint learn of revocation only by asking.
- Failed renewals are not audited (only successful ones).
- `resources/list`, `resources/templates/list` and `prompts/list` results are not filtered by capability.
