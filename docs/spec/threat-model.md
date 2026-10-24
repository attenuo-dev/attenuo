# Threat model

- Status: draft
- Date: 2026-10-22
- Related: [RFC-0001](rfc-0001-attenuo.md), [incident list](../research/incidents-2025-2026.md), [ADR-0001](../decisions/0001-separate-enforcement-layer.md)

## Assets

1. **Originating-user identity and consent**: which human a run acts for, and what they allowed.
2. **Capabilities**: the set of (server, tool, argument constraints) each hop may exercise.
3. **Data reachable through tools**: private repos, mailboxes, tenant records.
4. **The decision log**: the only record that distinguishes agent actions from user actions.
5. **Signing keys and lease state** inside attenuo.

## Trust boundaries

```
 [IdP] ──creds──▶ [agent client] ──MCP + token──▶ [attenuo proxy/PDP] ──MCP──▶ [MCP server] ──▶ [upstream API]
   trusted          UNTRUSTED                      TRUSTED (reference monitor)    UNTRUSTED
```

- **Agent client (and the LLM driving it): untrusted.** It may be prompt-injected, buggy, or malicious. It can send any MCP message and any token it holds.
- **Sub-agents: untrusted.** Each is a separate workload with its own credential; a parent cannot vouch for a child's behaviour, only bound its authority.
- **MCP server: untrusted.** It may be a typosquat, a poisoned tool description, or a legitimate server with a vulnerability. It receives only what the proxy forwards.
- **attenuo: trusted reference monitor.** Its correctness is the security argument. It must be small, fail closed, and have its invariants property-tested.
- **IdP: trusted for authentication only.** It is not trusted to express per-tool or per-argument authorization.
- **Policy author and log verifier: trusted.** Policies are code; they get review and tests.

## Attacker capabilities

An attacker may do any of the following; attenuo's guarantees must hold anyway.

- A1. Inject instructions into any content the agent reads (issues, emails, web pages, tool descriptions, tool results).
- A2. Control a sub-agent fully, including crafting arbitrary exchange requests.
- A3. Publish or compromise an MCP server the client connects to.
- A4. Replay or forward any token observed on the wire or in logs.
- A5. Request capabilities broader than the parent holds, or deeper chains than allowed.
- A6. Keep a run alive after the user has withdrawn consent.
- A7. Read the audit log after the fact and attempt to alter or truncate it.

Out of scope: compromise of attenuo's host or signing keys, compromise of the IdP, side channels, denial of service against attenuo itself.

## Incident mapping

Sources: [AuthZed timeline](https://authzed.com/blog/timeline-mcp-breaches), [Practical DevSecOps roundup](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/). Properties are as defined in [RFC-0001 §2](rfc-0001-attenuo.md#2-guaranteed-properties).

| Incident | Root cause | Would have blocked or limited | Would not have prevented |
|---|---|---|---|
| **GitHub MCP prompt injection leak** (May 2025): injected issue text drove the agent to read private repos with an over-privileged PAT and post salary data publicly | A1 + over-broad credential | **P3**: argument-level policy restricts `repo` to the public repos the task needs; **P2**: the coding sub-agent's caps exclude private repos; **P4**: deny recorded with originating user | The injection itself; a user who deliberately grants private-repo read to the run |
| **Asana MCP cross-tenant exposure** (Jun 2025): users could see other tenants' data through the MCP server | Server-side isolation bug | **P1 + P3**: every call carries a verified originating user and the policy can require `arguments.workspace ∈ user.workspaces`; **P4**: forensic record of which user's run touched which workspace | A server that ignores the forwarded context and queries the wrong tenant internally; attenuo cannot see inside the server |
| **Smithery path traversal** (Oct 2025): leaked a hosting-platform token controlling 3,000+ apps | Broad static platform credential, server vuln | **P2/P3** limit what an agent could do *through attenuo* with that server; **P4** records the attempts | The traversal and the token leak themselves; attenuo does not protect a server's own secrets or host |
| **whatsapp-mcp tool poisoning** (Apr 2025): a second server's poisoned tool description made the agent exfiltrate message history, evading DLP | A1 via tool description + cross-tool flow | **P3**: `send_message` constrained to known recipients, or denied for depth > 0; **P2**: the messaging capability never granted to the run that reads other servers; **P4**: the exfil call is logged with the agent and user named | Exfiltration to an allowed recipient; cross-tool information-flow labelling is an [open question](rfc-0001-attenuo.md#9-open-questions) |
| **Malicious "Postmark MCP Server"** (Sep 2025): npm package BCC'd every email to the attacker | A3, supply chain | **P3**: a policy that pins `bcc`/`cc` to allowed domains blocks the added recipient if it is passed as an argument; **P4** shows which runs used the server | A server that adds the BCC inside its own code after receiving a clean request. attenuo sees arguments, not server behaviour; this is a sandbox/egress problem |
| **mcp-remote RCE** (CVE-2025-6514, Jul 2025, CVSS 9.6, 437,000+ downloads): malicious server URL executed commands on the client | Client-side parsing bug | Nothing directly. Indirectly, a compromised client still holds only attenuated, short-leased tokens (**P2, P4**), so blast radius through tools is bounded and revocable | Code execution on the client host |
| **MCP Inspector unauthenticated RCE** (CVE-2025-49596, Jun 2025) and **nginx-ui MCP endpoint skipped auth** (CVE-2026-33032, Mar 2026) | Missing authentication on an endpoint | Not applicable: these are servers exposed without any auth. attenuo requires a verified token on every call it proxies (**P1**) but cannot protect endpoints reached around it | Direct access to the vulnerable endpoint |
| **MCP STDIO transport design flaw** (Apr 2026, 10 CVEs, 150M+ downloads): configuration became OS commands | Local process model | Not applicable. STDIO servers run in the client's process tree; attenuo's proxy covers streamable HTTP | Local command execution |

## What attenuo does not prevent

Stated plainly so nobody relies on it for these.

- **Legitimate-but-harmful reads.** If policy permits an agent to read a document, attenuo cannot stop the server, or the agent, from sending that content somewhere else through a channel attenuo does not mediate. Exfiltration of permitted data needs egress control and information-flow labels.
- **Server-internal misbehaviour.** A server that receives a clean request and then does something extra (BCC, extra API calls, logging to a third party) is invisible to argument-level policy. That is the sandbox layer's job, which is a stated non-goal ([ADR-0001](../decisions/0001-separate-enforcement-layer.md)).
- **Prompt injection.** attenuo does not detect injected instructions. It assumes the agent is compromised and bounds the damage.
- **Over-permissive policy.** If the policy author permits everything, every property still holds and nothing is protected. The attenuation rule bounds children relative to parents; it does not bound the root.
- **Bypass routes.** Tools reached without going through the proxy (local STDIO servers, direct API keys in the agent's environment, 79% of servers pass keys via environment variables per [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)) are outside the monitor.
- **Compromise of attenuo.** Keys, lease store and log live in the trusted base. Hash chaining detects tampering after the fact. An attacker who holds the host and the issuer key can rewrite the log and sign new checkpoints over it; only checkpoints that left the host earlier catch that. With `[audit.sink]` each checkpoint is shipped when it is signed, and `audit verify --file --checkpoints` reports any one signed again after shipping (SR-21). What remains: entries after the last shipped checkpoint, checkpoints still queued when the host is taken (the queue is bounded and the sink can be down), and a sink whose credentials allow overwriting or deleting.

## Residual risks to track

- Checkpoint sink lag (SR-21). The window in which a host compromise can rewrite history undetected is the time from an entry to the delivery of the next checkpoint covering it: up to `checkpoint_every` entries or `checkpoint_interval_seconds`, plus queue and retry delay while the sink is down. Watch `audit_sink_oldest_undelivered_timestamp_seconds`, `audit_sink_dropped_total` and the `/readyz` `degraded` flag; set `fail_readiness = true` where a server must not run with its checkpoints stuck on the host.
- Token theft within a lease TTL window, for tokens that are not bound to a key. Bound tokens (DPoP, [RFC-0001 section 4.1](rfc-0001-attenuo.md#41-sender-constrained-tokens-dpop)) are useless without the holder's private key; an attacker who also takes the key is still in scope only up to the token's capabilities and lease.
- The approval token is readable by every hop of its run. `GET /approvals/{id}` answers any delegation token of the same run whose leases are live (with a DPoP proof when bound; a revoked hop gets 404, SR-60), and every answer about a granted approval carries `approval_token`. A sub-agent that learns an approval id can therefore fetch the token, but cannot spend it: the token names the calling hop's lease and, for a bound hop, its key (`cnf.jkt`), the server consumes the approval once against that binding, and the call hash pins the exact arguments. What the channel does leak is that the call was approved, and by whom, to agents the operator may not have told. Keep approval TTLs short (default 120 s), and treat the approval id like the token.
- Who may approve. With `[approvals] client_id` unset, an ID token whose audience is the run's root agent's own client id decides at `POST /approvals/{id}`. Each ID token is used once and the one redeemed at hop 0 is refused, but a root agent that can get fresh ID tokens for its user (silent re-authentication, a refresh token) can approve its own gated calls, and the record says `by: user`. Set `client_id` to the approval page's own client wherever approvals matter. When a loaded policy carries `@obligation("approval")` and `client_id` is unset, the server warns at startup and after every policy reload, and refuses to start off a loopback listener unless `[approvals] allow_unset_client_id = true` (SR-64). A loopback server, or one with the override, still accepts the agent's own client.
- Run limits count JSON values, not what a tool makes of them. `calls_per`, `distinct` and the catalog `destination` compare the canonical JSON of a value: aliases of one recipient (case, whitespace, plus-addressing) are different values, and a comma-separated string, a nested list or an object is one value even when the tool fans it out. Aliases cannot get past `distinct` or a rule that asks on a new destination, but they do get past `calls_per` and rules that ask on a repeat. `"derive": "host"` follows the WHATWG URL parser and refuses strings with a backslash, whitespace or a control character, on which common HTTP clients disagree with it (SR-56), and finds a host only in a URL of a special scheme (`http`, `https`, `ws`, `wss`, `ftp`, `file`), since any other scheme has an opaque host that is not normalised (FZ2-2); subdomains of one domain are still different hosts. In run usage a value with no host counts as itself, wrapped so that it never equals a host, so each different unparseable value is a new destination (SR-63); a rule that asks on a repeat notices only an exact repeat of one. Pin argument formats with constraints where a limit depends on them (SR-65, SR-66).
- Refunds of `distinct` charges. A refund frees a value only when no other unrefunded decision used it, so refunding the call that first reached a value does not reopen it while a later call that also reached it stands (SR-62). Charge rows written before that fix do not record later uses of a seen value, so on a store upgraded mid-run a refund can still free such a value once.
- Policy limits over run usage are exact within one server process: a per-run lock covers the read of `context.usage` and `context.budget` through the charge (SR-55). Two servers on one store would not share it. With `[policy] track_usage = "auto"`, usage is kept only while a loaded policy can read it, so a usage policy loaded mid-run counts only the calls made since; set `track_usage = true` where usage policies may be added to live runs (SR-68).
- Other processes on the store. The server's SQLite file may be read by other processes (an operator's `sqlite3`, a backup tool) only through SQLite, which coordinates through file locks; nothing in the server may open and close the database file itself, since that drops the process's locks (SR-58). Copy a live store with SQLite's backup API, not `cp`.
- Audit volume from revoked tokens. A request refused for a revoked, expired or unknown lease is a `deny` record even when it carries no per-call decision (`initialize`, `tools/list`, `GET`), so whoever holds a revoked but unexpired token can add one record per request until the token's `exp`, as `tools/call` with that token always could. Tokens that fail verification add nothing (SR-18), so the volume is bounded by tokens attenuo issued and their lifetimes; there is no per-token rate limit on the log. Watch `decisions_total{decision="deny",reason="lease_revoked"}`.
- Policy-cache or lease-cache staleness longer than one TTL under partition (fail closed when the lease store is unreachable).
- Constraint-algebra gaps that let an argument slip past `⊑` (property tests over the attenuation rule; fuzz the matcher).
- Audit loss on power failure at the default `[audit] durability = "normal"`. A decision is answered (and an allowed call forwarded) once its record is committed, but a `normal` commit is not synced, so a power failure or kernel crash can lose the newest records of calls that did run. The surviving log is a clean prefix and verifies. A process crash loses nothing, and revocations are always synced. Use `durability = "full"` where the audit trail must cover every executed call (SR-48, [deploy guide](../guides/deploying.md)).
