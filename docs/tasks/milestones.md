# Milestones

Technical milestones for the first 90 days. Tasks in [board.md](board.md); properties P1-P4 as defined in [RFC-0001 §2](../spec/rfc-0001-attenuo.md#2-guaranteed-properties).

## Day 30 (2026-11-21): v0.1, one real chain end to end

- Multi-hop delegation works: agent → sub-agent → tool, each hop an RFC 8693 exchange, each token's `cap` provably `⊑` its parent's.
- The proxy enforces an argument-aware Cedar decision on every `tools/call` to one real MCP server (Filesystem or GitHub).
- Hash-chained SQLite audit log with a standalone verifier.
- The GitHub MCP over-privileged-PAT scenario is reproduced and blocked, as an integration test and a recorded demo.
- A reproducible AgentDojo / InjecAgent run comparing attack success and utility between a no-policy baseline and attenuo enforcement, in the same frame AgentGate uses ([NeurIPS 2026](https://neurips.cc/virtual/2026/168219)).
- Exit criteria: P1, P2, P3 hold in integration tests; P4's audit half holds; CI green with clippy `-D warnings`.

## Day 60 (2026-12-21): revocation, PDP interface, stated invariants

- Leases: renewal, revocation by user/session/chain/token, descendant revocation, proxy cache bounded by TTL; integration test proving a revoked ancestor denies the next call within one TTL. P4 complete.
- AuthZEN `POST /access/v1/evaluation` exposed with conformance fixtures, so any PEP can use attenuo as a PDP ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).
- Hop 0 from OIDC ID tokens and ID-JAG assertions; interop notes filed against the ID-JAG draft ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)).
- Written statement of the attenuation invariant (capability set at hop n+1 is a subset of hop n, under composition) with a first machine-checked sketch in Lean or Dafny, following the Cedar and AgentGate precedent ([arXiv 2403.04651](https://arxiv.org/abs/2403.04651v2), [NeurIPS 2026](https://neurips.cc/virtual/2026/168219)).
- Latency and throughput benchmarks published in the repo.

## Day 90 (2027-01-20): gateway integration and measurement

- AgentGateway integration as its external policy decision point ([agentgateway](https://github.com/agentgateway/agentgateway)).
- `RelationResolver` with a SpiceDB-backed implementation; ReBAC conditions usable from Cedar policies ([ADR-0002](../decisions/0002-cedar-for-policy.md)).
- Sender-constrained hop tokens behind a feature flag.
- A measurement study of delegation and credential patterns across public MCP servers, extending SandScope's 35-repository coverage ([arXiv 2601.01241](https://arxiv.org/html/2601.01241)).
- Write-up of design, invariants and evaluation suitable for a preprint; docs vault updated to match the shipped code.
