# attenuo

<p class="tagline">Delegation-aware authorization for tool-using AI agents: every tool call is checked against what the user delegated.</p>

<p class="author">[Name, affiliation, e-mail]</p>

<!--
Researcher brief, one A4 page. Build with docs/brief/build.sh.
Every number has an HTML comment naming the file it comes from.
-->

## Problem

An agent that calls tools for a user usually holds one broad credential, so when injected content steers it, nothing outside the agent refuses the harmful call. A survey of 16 MCP incidents from 2025 and 2026 <!-- docs/report/attenuo-2026-11.md, Introduction (docs/research/incidents-2025-2026.md) --> includes an injected issue that made an assistant publish a user's private repositories through the GitHub MCP server, and a leaked platform token that controlled more than 3,000 applications. <!-- docs/report/attenuo-2026-11.md, Introduction --> In each case the agent held more authority than its task needed, and no component checked each call.

## What attenuo is

attenuo is a self-hosted server and MCP proxy, written in Rust, that sits between agent clients and tool servers. A user's login is exchanged (RFC 8693) for a delegation token that carries the verified user and every agent in the chain, and each exchange can only narrow capabilities, argument constraints, lifetime and depth. Every proxied call is checked against each hop's lease, the chain's capabilities and run limits, and a Cedar policy that sees the call's arguments; revoking a lease cuts off that hop and all its descendants on their next call. Every decision is appended to a hash-chained log with signed checkpoints that a third party can verify offline.

## Evidence

| Measure | Result |
|---|---|
| Injection suite, test split: attack calls allowed, direct (no attenuo) vs attenuo | 38/38 vs 7/38 <!-- evaluation/injection-suite/results/2026-11-05-final-main.md --> |
| Test split: benign calls denied by attenuo | 3/29 <!-- evaluation/injection-suite/results/2026-11-05-final-main.md --> |
| Test split, attenuo plus output labels and a one-call limit on non-reads (scripted approver) | 1/38 attack calls allowed, 3/29 benign denied <!-- docs/report/attenuo-2026-11.md, Table 2, row "+ labels and calls: 1"; evaluation/injection-suite/results/2026-11-05-final-main.md --> |
| Added latency per proxied call, median | 0.4 to 0.8 ms, 1 to 3 hops, shared 4-core container <!-- docs/design/performance.md; README.md --> |
| Tests passing | 1,161 Rust, 322 Python SDK, 242 TypeScript SDK <!-- README.md, "Tests and fuzzing"; docs/report/attenuo-2026-11.md, Implementation --> |
| Internal security review, 7 passes | 84 findings, 5 High; all fixed except 11 accepted Low/Info and 1 open Info <!-- docs/report/attenuo-2026-11.md, Table 4 and "Security review" --> |
| Size | 64,529 lines of Rust in `src/`, 39,278 in tests <!-- docs/report/attenuo-2026-11.md, Table 1 --> |

The test split's 26 synthetic cases are replayed with no model, <!-- docs/report/attenuo-2026-11.md, Evaluation --> and the cases, policies and approver were written by attenuo's authors, so these figures check the implementation, not how often a real injected agent would be stopped. On the public AgentDojo benchmark, a replay of each attack's calls with no model landed 592/609 attacks without attenuo and 15/609 under grants derived from each task's known solution; with real models no attack succeeded either way. <!-- docs/research/agentdojo-plan-2026-11-05.md, "Replay on all suites" and "Four models on one sample"; docs/report/attenuo-2026-11.md, "External benchmark: AgentDojo" -->

## Open research questions

- **An independent evaluation with a model in the loop.** Our AgentDojo runs use oracle grants and our own policies. What would a credible evaluation need: grants from a planner that sees only the prompt, an adaptive attacker, a corpus by people who have not read the policies?
- **The approver in the loop.** Output labelling turns most remaining misses into approval requests (71 on dev). <!-- docs/report/attenuo-2026-11.md, Open questions --> How often do people grant them unread, and which signals make a request decidable? This needs a user study.
- **Policy-aware listing and the reach of the narrowing relation.** Is hiding a tool by Cedar partial evaluation sound for the policies agents use, and where should the line sit between what tokens can delegate and what only policy can deny?

## What I am looking for

I am looking for a supervisor for MS research on one of these three questions. The repository, the full technical report and a one-command script that reproduces the injection-suite numbers are available on request. Repository: [link]. Report: [link].
