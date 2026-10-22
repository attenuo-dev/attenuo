# Related work

- Date: 2026-10-22
- Related: [RFC-0001](../spec/rfc-0001-onbehalf.md), [standards](standards.md), [ADR-0002](../decisions/0002-cedar-for-policy.md)

## Research systems

### AgentGate (NeurIPS 2026)

"A runtime authorization layer for LLM agents" that "separates the decision to choose an action from the decision to permit it." Every tool call goes through an MCP wrapper where a policy engine checks trust levels, workflow prerequisites, mutually exclusive permissions, and where security-sensitive arguments came from; approved requests get "short-lived, budget-limited capability tokens"; delegation is limited to "session-bound parent-child chains, where permissions can only be narrowed"; the core is formalised in Dafny with seven proven properties. Attack success on AgentDojo and InjecAgent is reduced in every setting, "reaching zero with GPT-5.4," with utility within 4.18 percentage points of native agents ([NeurIPS 2026](https://neurips.cc/virtual/2026/168219)).

- **Shared with onbehalf:** per-call authorization at the MCP boundary, narrowing-only delegation, capability tokens, argument provenance as policy input.
- **Where onbehalf differs:** AgentGate's chains are session-bound within one runtime. onbehalf's are cross-service and cross-workload (RFC 8693 exchange between separately credentialed agents), carry a verified originating user from an external IdP, support revocation into in-flight runs via leases, and write a hash-chained log. onbehalf should adopt AgentGate's evaluation frame (AgentDojo/InjecAgent, attack success vs. utility) so results are comparable.

### SandScope / MCP-SandboxScan (arXiv 2601.01241)

Runs MCP tools under WASI or drives unmodified stdio servers, treats LLM-visible fields as sinks; controlled-benchmark precision 1.000, recall 0.889, F1 0.941; of 100 real repositories only 35 completed dynamic scans; 886 of 1,127 tools (78.6%) declare a security-sensitive capability. Stated future work: "full network syscall instrumentation," encrypted/compressed leaks, multi-turn flows ([arXiv 2601.01241](https://arxiv.org/html/2601.01241)).

- **Relevance:** measurement, not enforcement. It shows most tools declare sensitive capabilities, which is the case for argument-level policy, and it leaves open a larger-scale measurement of delegation and credential patterns across public servers that onbehalf's proxy could support.

### Lattice refinement for consent-driven MCP authorization (arXiv 2605.11360)

Addresses the structure of consent for MCP authorization as a lattice of options ([arXiv 2605.11360](https://arxiv.org/pdf/2605.11360)). Relevant to the "cardinality" challenge (consent flows do not scale to short-lived agent sessions) raised at [QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole). onbehalf's capability sets form a lattice under `⊑`, which may let consent be expressed once at the root and refined per hop.

### Cedar (arXiv 2403.04651) and Zanzibar

Cedar's design paper (sound-and-complete logical encoding, Lean model) is the precedent for analysable policy ([arXiv 2403.04651](https://arxiv.org/abs/2403.04651v2)). Zanzibar is the canonical ReBAC design and the source of SpiceDB/OpenFGA ([Google Zanzibar](https://en.wikipedia.org/wiki/Google_Zanzibar)). onbehalf composes both; see [ADR-0002](../decisions/0002-cedar-for-policy.md).

## Industry reference implementations

### AWS "least-privilege authorization in multi-agent AI chains using Cedar" (Jul 2026)

Three Cedar layers (agent-to-tool, agent-to-agent with delegation depth and a `containsAll` capability-subset check, originating-user role/MFA); principal is always the agent, with the user carried in `context.originating_user` signed by HMAC-SHA256; RFC 8693 token exchange issues a scoped on-behalf-of token per hop; audit as OCSF 99001 events to CloudWatch ([AWS Security Blog](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/), [code](https://github.com/aws-samples/sample-cedar-agentic-ai-authorization)).

Gaps named in the source or visible in the sample:

- No ReBAC.
- No revocation; "S3-backed policy hot-reload" is suggested as future work.
- No token binding.
- Agent attributes are read from the request payload; "production deployments must validate these against an authoritative source."
- The originating user is integrity-protected by a detached HMAC rather than by the token signature.
- Depth rules are internally inconsistent (one layer permits ≤ 3 hops; a scenario denies at 6 via a hard limit of 5).
- AgentCore Policy, the productised form, needed a **second language, Dogwood**, for session-scoped temporal policies ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/), [Dogwood](https://sph.sh/en/posts/dogwood-temporal-policy-language/)).

onbehalf keeps the Cedar request shape and the per-hop exchange, moves the originating user into a signed token claim, enforces attenuation in code before policy, adds leases for revocation, and plans ReBAC by composition.

### AgentGateway (Linux Foundation)

Announced by the Linux Foundation on 25 Aug 2025, created by Solo.io, contributors from AWS, Cisco, IBM, Microsoft, Red Hat and others; Rust with a TypeScript UI; Apache 2.0, ~5.4k stars; MCP and A2A, JWT/API key/OAuth auth, "fine-grained RBAC with a CEL policy engine," OpenTelemetry, rate limiting, guardrail integrations ([Linux Foundation](https://www.linuxfoundation.org/press/linux-foundation-welcomes-agentgateway-project-to-accelerate-ai-agent-adoption-while-maintaining-security-observability-and-governance), [agentgateway](https://github.com/agentgateway/agentgateway)). A question about a per-tool authorization standard on the AAIF overview went "without a clear answer" ([DEV Community](https://dev.to/mgonzalezo/the-open-source-agentic-ai-stack-what-aaif-projects-do-and-how-to-contribute-24be)).

- **Relationship:** complementary. AgentGateway is the proxy shell; onbehalf is a PDP it can call via AuthZEN, and the source of delegation tokens. onbehalf's own proxy exists for deployments without a gateway and for tests.

### Other open-source MCP gateways

From a vendor-written survey ([Maxim AI](https://www.getmaxim.ai/articles/best-open-source-mcp-gateway-for-secure-ai-agent-access-2026/)), so treat specifics as claims to verify:

- **Bifrost** (Go, Apache 2.0): token exchange, HMAC-signed audit logs, guardrails and RBAC are enterprise-only.
- **Docker MCP Gateway**: `--block-secrets` DLP; "does not publish multi-tenant caller authentication or per-user tool scoping."
- **Microsoft MCP Gateway** (.NET 8): "per-user upstream credentials and payload inspection are not published."
- **IBM ContextForge** (Python): no published payload inspection.
- **Obot**: Sentry component in beta.
- None of the five documents prompt-injection defence.

Common gap across all of them and onbehalf's reason to exist as a separate component: none carries an originating user across hops, attenuates per hop, or exposes argument-level policy with a tamper-evident log.

### Proprietary reference architectures

Cloudflare's enterprise MCP architecture (Apr 2026) covers OAuth via Access, MCP Server Portals, portal DLP, JSON-RPC body inspection, shadow-MCP detection; all proprietary, with internal prompt-injection handling undescribed and local servers uncovered ([Cloudflare](https://blog.cloudflare.com/enterprise-mcp/)). Identity vendors shipping agent identity: Okta Agent SSO (ID-JAG), Descope (ID-JAG, SPIFFE, mTLS), Microsoft Entra Agent ID (no ID-JAG), Google Cloud Agent Identity, ServiceNow AI Passport (AIMS/WIMSE) ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)). These are issuers; onbehalf consumes what they issue and stays neutral across them, which matters because gateways already have to validate four token types at once ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)).

## Practitioner statements of the gap

- Cerbos (Aug 2026): no standard slot for the originating user across hops; cross-org delegation "genuinely unsolved"; obligations and withdrawal unaddressed ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).
- Anthropic's MCP auth lead (QCon, Mar 2026): granularity, attribution, information leakage, cardinality; RAR, XAA, SPIFFE each partial ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)).
- Archestra (mid-2026): audit cannot distinguish agent from user actions; teams want per-tool policy, not per-server allow/deny ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)).
