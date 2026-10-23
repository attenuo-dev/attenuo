# ADR-0002: Cedar as the policy language, with ReBAC composed from outside

- Status: accepted
- Date: 2026-10-22

## Context

Per-call authorization ([RFC-0001 §5](../spec/rfc-0001-attenuo.md#5-per-call-authorization)) needs a language that can see tool arguments, the originating user, chain depth and time, that evaluates in-process at tool-call rates, and whose policies can be analysed rather than only tested. Candidates: Cedar, OPA/Rego, CEL.

- **Cedar** is a Rust-implemented language whose design "supports a logical encoding that is both sound and complete, which enables precise policy analysis"; the authors modelled it in Lean and proved properties ([arXiv 2403.04651](https://arxiv.org/abs/2403.04651v2)). It is the engine AWS uses for agent tool-call policy: AgentCore Policy builds the request from the caller's JWT, the tool name as action and the arguments as `context.input` ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)), and AWS's multi-agent delegation sample layers Cedar over RFC 8693 ([AWS Security Blog](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/)). Default-deny with explicit `forbid` overriding `permit` matches a reference monitor.
- **OPA/Rego** is general and widely deployed, but its stewardship moved to Apple-employed maintainers in August 2025 and the Enterprise OPA repository was reportedly archived in June 2026 ([OPA blog](https://www.openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371), [Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). Rego is Turing-incomplete but not designed for SMT-based analysis, and `opa eval` cold latency was measured at ~13 ms as a process ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)); an embedded Go runtime is not natural from Rust.
- **CEL** is what AgentGateway uses for "fine-grained RBAC" ([agentgateway](https://github.com/agentgateway/agentgateway)). It is an expression language, not a policy language: no principal/action/resource model, no permit/forbid composition, no schema-based validation or analysis.

Cedar alone has known gaps for agents. AWS needed a second language, Dogwood, for session-scoped temporal constraints ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/), [Dogwood](https://sph.sh/en/posts/dogwood-temporal-policy-language/)), an HMAC side-channel for the originating user, and left ReBAC and revocation as future work ([AWS Security Blog](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/)).

## Decision

Use Cedar (`cedar-policy` 4.x) as the only policy language exposed to policy authors. Address the gaps outside the language rather than by adding a second one:

- **Delegation and attenuation** are enforced by `attenuo-core` before policy runs, as a predicate over the token lineage; policy can further restrict by `context.chain.depth` but cannot widen.
- **Originating user** arrives in the token's `chain.originating_user` claim, covered by the issuer's `ou_sig` signature (checked by `attenuo-token` before policy runs), and is projected into `context.originating_user`.
- **Temporal and session constraints** are expressed with Cedar's `datetime`/`duration` extension and `context.session_id` and `context.now_unix`, plus leases for liveness; if that proves insufficient the fallback is a small set of built-in temporal predicates in the request builder, not a new language.
- **Revocation** is a lease check outside policy ([RFC-0001 §6](../spec/rfc-0001-attenuo.md#6-revocation-via-leases)).
- **Request shape** follows AuthZEN so the same evaluation is reachable by external PEPs ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

## ReBAC composition note

Relationship questions ("is this repo owned by the user's team?") are not Cedar's strength and should not be encoded as flat attribute lists. The plan is composition, not reimplementation: a `RelationResolver` trait in `attenuo-policy` fetches the relationships relevant to a request from a Zanzibar-style store (SpiceDB or OpenFGA) and materialises them as Cedar entity parents and attributes before evaluation, so policies write `resource in principal.owned_repos`-style conditions ([Google Zanzibar](https://en.wikipedia.org/wiki/Google_Zanzibar)). Two constraints follow:

1. Resolved relationships are cached no longer than one lease TTL, so revoking a relationship and revoking a lease have the same worst-case latency.
2. The resolver is read-only and failure closes: if the graph is unreachable, policies that depend on relationships evaluate with empty sets and therefore deny.

The composition's consistency semantics (what snapshot the graph is read at relative to the decision) is an open question in the RFC and a candidate for a later ADR.

## Consequences

- Positive: in-process evaluation in Rust with no sidecar; schema validation catches malformed policies; SMT analysis of policies is possible later.
- Positive: policy authors learn one language, and it is the one the largest cloud uses for the same job.
- Negative: Cedar's entity model needs a request-builder layer; building the right entity slice per call is where latency will go.
- Negative: no Cedar-native ReBAC; correctness of the resolver projection must be tested.
- Negative: teams already standardised on Rego have to translate.

## Alternatives considered

- **Rego via a sidecar or WASM**: rejected for ecosystem uncertainty, extra process hop, and weaker analysability.
- **CEL only**: rejected; it would reproduce AgentGateway's RBAC rather than add argument-level policy with a permit/forbid model.
- **A custom DSL with delegation as a first-class construct**: tempting, because delegation is where the hard semantics live, but a new language costs adoption and analysis tooling. Delegation is instead enforced in core code with a stated invariant and property tests.
- **Cedar + Dogwood (AWS's pairing)**: rejected; two languages for one decision doubles the surface authors must reason about.
