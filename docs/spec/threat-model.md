# Threat model

- Status: draft
- Date: 2026-10-22
- Related: [RFC-0001](rfc-0001-onbehalf.md), [incident list](../research/incidents-2025-2026.md), [ADR-0001](../decisions/0001-separate-enforcement-layer.md)

## Assets

1. **Originating-user identity and consent**: which human a run acts for, and what they allowed.
2. **Capabilities**: the set of (server, tool, argument constraints) each hop may exercise.
3. **Data reachable through tools**: private repos, mailboxes, tenant records.
4. **The decision log**: the only record that distinguishes agent actions from user actions.
5. **Signing keys and lease state** inside onbehalf.

## Trust boundaries

```
 [IdP] ──creds──▶ [agent client] ──MCP + token──▶ [onbehalf proxy/PDP] ──MCP──▶ [MCP server] ──▶ [upstream API]
   trusted          UNTRUSTED                      TRUSTED (reference monitor)    UNTRUSTED
```

- **Agent client (and the LLM driving it): untrusted.** It may be prompt-injected, buggy, or malicious. It can send any MCP message and any token it holds.
- **Sub-agents: untrusted.** Each is a separate workload with its own credential; a parent cannot vouch for a child's behaviour, only bound its authority.
- **MCP server: untrusted.** It may be a typosquat, a poisoned tool description, or a legitimate server with a vulnerability. It receives only what the proxy forwards.
- **onbehalf: trusted reference monitor.** Its correctness is the security argument. It must be small, fail closed, and have its invariants property-tested.
- **IdP: trusted for authentication only.** It is not trusted to express per-tool or per-argument authorization.
- **Policy author and log verifier: trusted.** Policies are code; they get review and tests.

## Attacker capabilities

An attacker may do any of the following; onbehalf's guarantees must hold anyway.

- A1. Inject instructions into any content the agent reads (issues, emails, web pages, tool descriptions, tool results).
- A2. Control a sub-agent fully, including crafting arbitrary exchange requests.
- A3. Publish or compromise an MCP server the client connects to.
- A4. Replay or forward any token observed on the wire or in logs.
- A5. Request capabilities broader than the parent holds, or deeper chains than allowed.
- A6. Keep a run alive after the user has withdrawn consent.
- A7. Read the audit log after the fact and attempt to alter or truncate it.

Out of scope: compromise of onbehalf's host or signing keys, compromise of the IdP, side channels, denial of service against onbehalf itself.

## Incident mapping

Sources: [AuthZed timeline](https://authzed.com/blog/timeline-mcp-breaches), [Practical DevSecOps roundup](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/). Properties are as defined in [RFC-0001 §2](rfc-0001-onbehalf.md#2-guaranteed-properties).

| Incident | Root cause | Would have blocked or limited | Would not have prevented |
|---|---|---|---|
| **GitHub MCP prompt injection leak** (May 2025): injected issue text drove the agent to read private repos with an over-privileged PAT and post salary data publicly | A1 + over-broad credential | **P3**: argument-level policy restricts `repo` to the public repos the task needs; **P2**: the coding sub-agent's caps exclude private repos; **P4**: deny recorded with originating user | The injection itself; a user who deliberately grants private-repo read to the run |
| **Asana MCP cross-tenant exposure** (Jun 2025): users could see other tenants' data through the MCP server | Server-side isolation bug | **P1 + P3**: every call carries a verified originating user and the policy can require `arguments.workspace ∈ user.workspaces`; **P4**: forensic record of which user's run touched which workspace | A server that ignores the forwarded context and queries the wrong tenant internally; onbehalf cannot see inside the server |
| **Smithery path traversal** (Oct 2025): leaked a hosting-platform token controlling 3,000+ apps | Broad static platform credential, server vuln | **P2/P3** limit what an agent could do *through onbehalf* with that server; **P4** records the attempts | The traversal and the token leak themselves; onbehalf does not protect a server's own secrets or host |
| **whatsapp-mcp tool poisoning** (Apr 2025): a second server's poisoned tool description made the agent exfiltrate message history, evading DLP | A1 via tool description + cross-tool flow | **P3**: `send_message` constrained to known recipients, or denied for depth > 0; **P2**: the messaging capability never granted to the run that reads other servers; **P4**: the exfil call is logged with the agent and user named | Exfiltration to an allowed recipient; cross-tool information-flow labelling is an [open question](rfc-0001-onbehalf.md#9-open-questions) |
| **Malicious "Postmark MCP Server"** (Sep 2025): npm package BCC'd every email to the attacker | A3, supply chain | **P3**: a policy that pins `bcc`/`cc` to allowed domains blocks the added recipient if it is passed as an argument; **P4** shows which runs used the server | A server that adds the BCC inside its own code after receiving a clean request. onbehalf sees arguments, not server behaviour; this is a sandbox/egress problem |
| **mcp-remote RCE** (CVE-2025-6514, Jul 2025, CVSS 9.6, 437,000+ downloads): malicious server URL executed commands on the client | Client-side parsing bug | Nothing directly. Indirectly, a compromised client still holds only attenuated, short-leased tokens (**P2, P4**), so blast radius through tools is bounded and revocable | Code execution on the client host |
| **MCP Inspector unauthenticated RCE** (CVE-2025-49596, Jun 2025) and **nginx-ui MCP endpoint skipped auth** (CVE-2026-33032, Mar 2026) | Missing authentication on an endpoint | Not applicable: these are servers exposed without any auth. onbehalf requires a verified token on every call it proxies (**P1**) but cannot protect endpoints reached around it | Direct access to the vulnerable endpoint |
| **MCP STDIO transport design flaw** (Apr 2026, 10 CVEs, 150M+ downloads): configuration became OS commands | Local process model | Not applicable. STDIO servers run in the client's process tree; onbehalf's proxy covers streamable HTTP | Local command execution |

## What onbehalf does not prevent

Stated plainly so nobody relies on it for these.

- **Legitimate-but-harmful reads.** If policy permits an agent to read a document, onbehalf cannot stop the server, or the agent, from sending that content somewhere else through a channel onbehalf does not mediate. Exfiltration of permitted data needs egress control and information-flow labels.
- **Server-internal misbehaviour.** A server that receives a clean request and then does something extra (BCC, extra API calls, logging to a third party) is invisible to argument-level policy. That is the sandbox layer's job, which is a stated non-goal ([ADR-0001](../decisions/0001-separate-enforcement-layer.md)).
- **Prompt injection.** onbehalf does not detect injected instructions. It assumes the agent is compromised and bounds the damage.
- **Over-permissive policy.** If the policy author permits everything, every property still holds and nothing is protected. The attenuation rule bounds children relative to parents; it does not bound the root.
- **Bypass routes.** Tools reached without going through the proxy (local STDIO servers, direct API keys in the agent's environment, 79% of servers pass keys via environment variables per [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)) are outside the monitor.
- **Compromise of onbehalf.** Keys, lease store and log live in the trusted base. Hash chaining detects tampering after the fact; it does not prevent an attacker with write access from truncating the log unless checkpoints are anchored externally.

## Residual risks to track

- Token theft within a lease TTL window, for tokens that are not bound to a key. Bound tokens (DPoP, [RFC-0001 section 4.1](rfc-0001-onbehalf.md#41-sender-constrained-tokens-dpop)) are useless without the holder's private key; an attacker who also takes the key is still in scope only up to the token's capabilities and lease.
- Policy-cache or lease-cache staleness longer than one TTL under partition (fail closed when the lease store is unreachable).
- Constraint-algebra gaps that let an argument slip past `⊑` (property tests over the attenuation rule; fuzz the matcher).
