# Standards onbehalf builds on

- Date: 2026-10-22
- Related: [RFC-0001](../spec/rfc-0001-onbehalf.md), [related work](related-work.md)

Each entry: what it is, what it gives onbehalf, what gap remains. Status as reported in the cited sources on the date above; drafts move, so re-check before quoting.

## MCP authorization, revision 2026-07-28

Release candidate 21 May 2026, final 28 Jul 2026; maintainers called it "the largest revision of the protocol since launch." MCP servers are formally OAuth 2.1 resource servers and MUST implement Protected Resource Metadata (RFC 9728); clients MUST implement Resource Indicators (RFC 8707); Client ID Metadata Documents replace Dynamic Client Registration, which is "deprecated and retained only for backward compatibility"; also issuer verification per RFC 9207, refresh-token guidance, scope accumulation during step-up, and `application_type` declaration ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)). Sampling was removed from core ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)). Enterprise-Managed Authorization (built on ID-JAG) is an enterprise extension ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)).

- **Gives us:** a settled token-on-the-wire model. onbehalf's proxy can assume a bearer token with a resource indicator, and can itself be the "resource" the client targets.
- **Gap:** authorization is optional and server-level; "whether a specific tool call is allowed for a specific user is left to the server or a gateway" ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). No slot for the originating user across hops ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). OAuth 2.1 itself is still an IETF draft (draft-ietf-oauth-v2-1-13) ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

## RFC 8693, OAuth 2.0 Token Exchange

Defines the `urn:ietf:params:oauth:grant-type:token-exchange` grant, `subject_token`/`actor_token`, and the `act` (nested actor chain) and `may_act` (who may later act for this subject) JWT claims. Cerbos calls it "the right primitive" for delegation that "does not fully close the gap" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). AWS's multi-agent sample issues a scoped on-behalf-of token per hop with it ([AWS Security Blog](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/)). Spec text: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693).

- **Gives us:** the exchange endpoint shape and the `act` chain, used as-is in [RFC-0001 §4](../spec/rfc-0001-onbehalf.md#4-token-exchange).
- **Gap:** says nothing about what claims the exchanged token may carry relative to its parent. Attenuation (`cap` narrowing), the originating-user block (`obo`) and leases are onbehalf additions layered on it.

## ID-JAG (Identity Assertion JWT Authorization Grant) and Cross-App Access

Okta's Cross-App Access was adopted by the IETF OAuth WG in September 2025 and folded into MCP as an enterprise authorization extension; Okta Agent SSO (GA 24 Aug 2026) and Descope (15 Oct 2026) ship it; Microsoft Entra Agent ID and ServiceNow do not ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)). The draft is at -04, expiring 22 Nov 2026; the IETF agentproto WG is "active but contested"; vendors build on different subsets (ID-JAG, AIMS, WIMSE), "so no single standards-compliant stack is guaranteed to interoperate" ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)).

- **Gives us:** an IdP-issued assertion that names the user and the target resource, which is the cleanest hop-0 input for `originating_user`.
- **Gap:** single hop, single trust domain, issued by the IdP for one resource; nothing about hops after the first, attenuation, or revocation. onbehalf treats ID-JAG as one of several hop-0 credential types and must track the draft as it changes.

## RFC 9396, Rich Authorization Requests (RAR)

Replaces flat scope strings with a structured `authorization_details` array. Named by Anthropic's MCP auth lead as one of the candidate pieces for granularity, together with draft RAR metadata extensions, with the caveat that "none of these fully solve the problem alone" ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)). Spec text: [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396).

- **Gives us:** the wire shape for requesting a capability set at exchange time (`type: "mcp_tool"`, server, tool, constraints).
- **Gap:** no semantics for subset or narrowing between requests; onbehalf defines `⊑` over the `mcp_tool` type itself.

## OpenID AuthZEN Authorization API and the COAZ-MCP binding

AuthZEN reached final specification status in January 2026. It standardises a PEP-to-PDP request of subject, action, resource, context. A draft "COAZ Binding for the Model Context Protocol - Draft 1" profiles it for MCP tool authorization ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

- **Gives us:** the request/response shape for `/access/v1/evaluation`, so any gateway or server that speaks AuthZEN can call onbehalf as a PDP without a custom client. Also the frame for putting arguments, originating user, depth and session in `context`.
- **Gap:** no obligations/withdrawal semantics in most implementations ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)); nothing about delegation chains. The MCP binding is Draft 1; field names may move. No OSS implementation of AuthZEN + COAZ-MCP end to end was found in the notes.

## Cedar

Rust-implemented authorization language with a sound-and-complete logical encoding enabling precise analysis; modelled in Lean with proven properties; principal/action/resource/context model with default deny and `forbid` overriding `permit` ([arXiv 2403.04651](https://arxiv.org/abs/2403.04651v2)). Used by AWS AgentCore Policy (GA 3 Mar 2026) with the tool name as action and arguments as `context.input` ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)).

- **Gives us:** in-process argument-aware policy evaluation and a path to policy analysis. See [ADR-0002](../decisions/0002-cedar-for-policy.md).
- **Gap:** no native ReBAC; temporal/session constraints led AWS to a second language (Dogwood); no notion of delegation depth or attenuation. These are handled outside the language in onbehalf.

## SPIFFE / SPIRE

Workload identity: each workload gets a SPIFFE ID and an X.509 or JWT SVID from a local agent. Named at QCon as a candidate piece for agent attribution ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)); Descope's gateway uses SPIFFE workload identity and mTLS ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)).

- **Gives us:** a stable, verifiable `actor` identity for each agent and sub-agent (the `actor_token` in an exchange), and a possible `cnf` binding for hop tokens.
- **Gap:** identifies the workload, not the human or the delegation. Many agent runtimes do not run a SPIRE agent, so onbehalf must also accept other actor credentials (OAuth client credentials, signed client assertions).

## What remains unowned after composing all of the above

Carrying a verified originating user across N hops, monotonic attenuation of structured capabilities per hop, per-call argument policy reachable by any PEP, revocation that reaches in-flight runs, and an audit record that names agent and user separately. Each standard above supplies one piece; none specifies their composition. That composition is [RFC-0001](../spec/rfc-0001-onbehalf.md).
