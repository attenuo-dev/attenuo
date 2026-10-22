# MCP and agent security incidents, 2025-2026

- Date: 2026-10-22
- Related: [threat model](../spec/threat-model.md) (maps each to onbehalf's properties)

Primary compilation: [AuthZed, "A timeline of MCP breaches"](https://authzed.com/blog/timeline-mcp-breaches), whose conclusion is that "over-privilege is the central risk." Additional CVEs from the [Practical DevSecOps 2026 roundup](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/). Dates are as given in those sources. Percentage "X% of servers vulnerable" statistics are deliberately omitted; they come from scanners with high false-positive rates ([Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)).

| Date | Incident | Class | Source |
|---|---|---|---|
| Apr 2025 | **whatsapp-mcp tool poisoning**: a poisoned tool description on a second server made the agent exfiltrate WhatsApp message history, "evading DLP tooling" | Cross-tool information flow, over-privilege | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| May 2025 | **GitHub MCP prompt injection**: injected issue content plus an over-privileged PAT leaked private repository data and salary information | Prompt injection + over-broad credential | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Jun 2025 | **Asana MCP cross-tenant data exposure** | Missing tenant isolation | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Jun 2025 | **MCP Inspector unauthenticated RCE**, CVE-2025-49596, CVSS 9.4 | Missing auth on a local endpoint | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Jul 2025 | **mcp-remote client-side RCE**, CVE-2025-6514, CVSS 9.6, 437,000+ downloads | Client vulnerability | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Aug 2025 | **Anthropic Filesystem MCP sandbox/symlink escape**, CVE-2025-53109 (CVSS 8.4) and CVE-2025-53110 (7.3) | Isolation bypass | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Aug 2025 | **Cursor "MCPoison"** CVE-2025-54136 (CVSS 7.2) and **"CurXecute"** CVE-2025-54135 | Client config trust | [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/) |
| Sep 2025 | **Malicious "Postmark MCP Server"** npm package BCC'd all outgoing email to the attacker | Supply chain, server-internal misbehaviour | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Sep 2025 | **Flowise** CVE-2025-59528 | Server vulnerability | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Oct 2025 | **Smithery path traversal** leaked a Fly.io token controlling 3,000+ apps | Over-broad platform credential | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Oct 2025 | **Framelink Figma MCP** CVE-2025-53967 | Server vulnerability | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Jan 2026 | **gemini-mcp-tool** CVE-2026-0755, CVSS 9.8, unauthenticated RCE | Missing auth | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Jan 2026 | **Anthropic Git MCP server** CVE-2025-68143/68144/68145 | Server vulnerability | [Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/) |
| Feb 2026 | **Cloned Oura MCP repository** distributing the StealC infostealer | Supply chain | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Mar 2026 | **nginx-ui "MCPwn"** CVE-2026-33032, CVSS 9.8, MCP endpoint skipped auth, ~2,600 exposed instances, actively exploited | Missing auth | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |
| Apr 2026 | **MCP STDIO transport design flaw**: "configuration become OS commands", 10 CVEs across LettaAI, LangFlow, Windsurf, LangChain adapters, Flowise, "affects over 150 million downloads" | Local process model | [AuthZed](https://authzed.com/blog/timeline-mcp-breaches) |

## Adjacent (non-MCP) agent incidents cited for the injection class

- **EchoLeak**, CVE-2025-32711: bypassed Microsoft's injection classifier, link redaction and CSP ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)).
- **ForcedLeak** against Salesforce Agentforce, CVSS 9.4: exfiltrated data to an expired domain still on an allowlist ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)).
- Prompt-injection mitigations remain probabilistic: Anthropic's Aug 2025 browser-agent data showed autonomous-mode attack success falling from 23.6% to 11.2% after mitigations, not to zero ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). HackerOne reported a 540% surge in prompt-injection reports (Oct 2025) ([Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)).

## Guidance and taxonomies that reference these incidents

- **NSA**, "Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation" (May 2026): design for boundaries, validate inputs, sandbox tools, sign messages, log every call, scan for unapproved servers ([Equixly](https://equixly.com/blog/2026/06/04/mapping-nsa-s-mcp-guidance-to-the-owasp-mcp-top-10-how-to-test-for-the-risks/)).
- **OWASP MCP Top 10** (beta): MCP02 Privilege Escalation via Scope Creep, MCP07 Authentication and Authorization, MCP08 Lack of Audit and Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Over-sharing ([Equixly](https://equixly.com/blog/2026/06/04/mapping-nsa-s-mcp-guidance-to-the-owasp-mcp-top-10-how-to-test-for-the-risks/), [OWASP](https://owasp.org/projects/mcp-top-10)).
- **Gartner** (relayed): more than 50% of successful attacks on AI agents through 2029 will exploit access-control issues ([Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)).
- **Credential hygiene baseline** (Astrix, Oct 2025, 5,200+ servers, relayed): 88% of servers require credentials, 53% use static API keys or PATs, 8.5% use OAuth, 79% pass keys via environment variables ([Practical DevSecOps](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)).

## Four root-cause clusters

1. Over-broad tokens and no attenuation: GitHub, Smithery, WhatsApp.
2. No isolation or tenant boundary: Asana, Filesystem server, STDIO flaw, nginx-ui.
3. Supply chain and unverified servers: Postmark, Oura clone, Flowise.
4. No audit or detection of cross-tool information flow: WhatsApp.

onbehalf targets clusters 1 and 4 directly and gives cluster 2 attribution and argument-level containment; cluster 3 needs a sandbox and registry layer that is out of scope ([threat model](../spec/threat-model.md)).

## Caveats

- The NSA document, Gartner notes and OWASP Agentic Top 10 text were not fetched directly in the underlying research; they are relayed through the linked secondary sources.
- Raw advisories for individual CVEs were not fetched; the CVE ids and scores are as reported by the AuthZed and Practical DevSecOps compilations.
