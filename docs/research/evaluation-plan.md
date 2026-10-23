# Evaluation plan

- Status: draft plan, no results yet
- Date: 2026-10-22
- Related: [RFC-0001](../spec/rfc-0001-onbehalf.md), [threat model](../spec/threat-model.md), [incidents](incidents-2025-2026.md), [related work](related-work.md), [performance notes](../design/performance.md)

This document describes how to measure whether onbehalf does what the RFC claims, in a form that can be written up as a workshop paper or as the evaluation chapter of a Master's thesis. It is a plan, not a result. Nothing here has been run yet. Numbers quoted from other papers are as those papers report them.

The RFC states four properties (P1 to P4). The threat model says what onbehalf does not do: it does not detect prompt injection, it assumes the agent is compromised and bounds the damage. The evaluation therefore asks a bounded question. If an agent is successfully injected, how often does attenuated delegation plus per-call policy stop the harmful tool call, how much legitimate work does it break, and what does it cost?

## 1. Research questions

**RQ1. Effectiveness and utility.** Does attenuated delegation plus per-call, argument-aware Cedar policy reduce the attack success rate (ASR) of injection-driven tool misuse on public benchmarks, without a large drop in task success on the benign tasks? Null hypotheses: (a) full enforcement does not lower ASR relative to scope-only enforcement; (b) full enforcement lowers utility by more than 5 percentage points relative to no enforcement (a non-inferiority test, margin chosen in section 5).

**RQ2. Overhead.** What latency does onbehalf add to a `tools/call`, at p50 and p99, end to end (token verification, lease lookup, Cedar evaluation, audit append, extra network hop), and how does it change with chain depth, policy size and concurrency? The micro-benchmarks in [performance.md](../design/performance.md) cover only the Cedar decision and the attenuation check; they are a lower bound.

**RQ3. Expressiveness.** How often do benchmark tasks need a capability that a static scope model cannot express? "Static scope" means a per-server or per-tool allow-list fixed when the token is issued, as in OAuth scopes. The question has three parts: (a) for what share of benign tasks does a tool-level scope separate the legitimate calls from the injected calls; (b) for what share does it additionally need argument constraints of the kind the capability model supports (`equals`, `one_of`, `prefix`); (c) for what share does the right constraint depend on data that only appears during the run (for example "reply to whoever wrote the last email"), which neither scopes nor today's constraints can express.

**RQ4 (secondary). Audit usefulness.** For each blocked or allowed call in a benchmark run, does the hash-chained log contain enough to reconstruct which agent, acting for which user, made the call and which policy decided it? This is checked mechanically (field completeness, chain verification, replay) and is a sanity check, not a headline result.

RQ1 and RQ3 are the core of a thesis chapter. RQ2 is a short, self-contained measurement. RQ4 is a paragraph.

## 2. Benchmarks and the threat model they exercise

The table says what each suite measures, as stated by its authors, and which of onbehalf's attacker capabilities (A1 to A7 in the [threat model](../spec/threat-model.md)) it exercises. Counts were read from the arXiv abstracts on 2026-10-22; check the version you download, because these suites change between releases.

| Suite | What it measures (per its authors) | Size as published | Maps to | Notes for this plan |
|---|---|---|---|---|
| **AgentDojo** ([paper](https://arxiv.org/abs/2406.13352), [NeurIPS 2024 D&B](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract.html), [code](https://github.com/ethz-spylab/agentdojo)) | A dynamic, extensible environment for prompt injection attacks and defenses against tool-using agents. Each case pairs a benign user task with an injection task, and the environment is stateful so success is checked on state, not text. | 97 realistic tasks, 629 security test cases (arXiv v3). Suites include workspace, slack, travel and banking [verify against the version used]. | A1 (injection through tool results). | Primary benchmark. Records utility without attack, utility under attack and ASR, so all three arms of RQ1 fit. Ships its own defenses (for example a tool filter) that serve as reference points. |
| **InjecAgent** ([paper](https://arxiv.org/abs/2403.02691), [Findings of ACL 2024](https://aclanthology.org/2024.findings-acl.624/)) | Indirect prompt injection against tool-integrated agents, split into attacks that harm the user directly and attacks that steal private data. | 1,054 test cases, 17 user tools, 62 attacker tools; 30 agents tested; ReAct GPT-4 attacked about 24% of the time, as reported. | A1. | Static test cases with simulated tool outputs, no live state. Good for a cheap, wide ASR sweep. It has no utility metric on benign tasks, so it cannot answer the false-deny part of RQ1 on its own. |
| **ASB, Agent Security Bench** ([paper](https://arxiv.org/abs/2410.02644), [ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/5750f91d8fb9d5c02bd8ad2c3b44456b-Abstract-Conference.html)) | Attacks and defenses across stages of an agent: system prompt, user prompt, tool use, memory. Includes a metric for the utility/security balance. | 10 scenarios, 10 agents, over 400 tools, 27 attack and defense types in total (10 prompt-injection attacks, 1 memory poisoning, 1 Plan-of-Thought backdoor, 4 mixed, 11 defenses), 13 LLM backbones; highest average ASR reported 84.30%. | A1 for the observation-prompt-injection and mixed attacks. Memory poisoning and backdoor attacks act on the agent, not on the tool boundary. | Use the tool-use attack subsets only. Say in the paper which subsets were excluded and why: onbehalf bounds tool calls and cannot affect memory or prompt-level attacks. |
| **MCP-SafetyBench** ([paper](https://arxiv.org/abs/2512.15163)) | Safety of LLMs working with real MCP servers: task success and attack success per run, over attacks grouped by origin (MCP server, MCP host, user). | 245 test cases built on real MCP servers, adapted from MCP-Universe; five domains (browser automation, financial analysis, location navigation, repository management, web search); 20 attack types. Overall ASR from 29.80% to 48.16% depending on model, as reported. | A1, A3 (a hostile or poisoned server). | The closest fit to onbehalf's deployment shape because the tools are already MCP. Server-origin and host-origin attacks need care: host-side attacks act before the proxy sees anything, so report them separately as out of scope rather than as failures. |
| **MCPTox** ([paper](https://arxiv.org/abs/2508.14925), [AAAI](https://ojs.aaai.org/index.php/AAAI/article/view/40895)) | Tool poisoning: malicious instructions in tool metadata (descriptions), not in tool outputs. | 45 live MCP servers, 353 tools, 1,348 malicious test cases, 10 risk categories, 20 agents; highest ASR reported 72.8%. | A1 via tool description, A3. | Tests the whatsapp-mcp shape from the [incident list](incidents-2025-2026.md). Poisoning works by getting the agent to call a different, legitimate tool with bad arguments, which is what argument policy can catch. A poisoned description that only changes how a permitted call is made is not caught. |
| **MCPSecBench** ([paper](https://arxiv.org/abs/2508.13220)) | A systematic benchmark and playground over MCP attack surfaces. | 4 attack surfaces, 17 attack types; reports that all surfaces yielded compromises and that existing protections had average success under 30%, as stated. | A1 to A3, plus protocol and client-side attacks. | Most of its attack surface (client, transport, server implementation) is outside onbehalf. Use it for a coverage table: which attack types are in scope, which are not, and why. Run only the in-scope subset. |

**What counts as in scope.** An attack is in scope only if the harmful effect passes through a `tools/call` that the proxy mediates. Attacks on the model, the memory store, the host process, the STDIO transport or the MCP server's own code are out of scope, in line with the "What onbehalf does not prevent" section of the threat model. The paper must report in-scope and out-of-scope counts per suite so a reader can see the denominator. Silently dropping cases would inflate the result.

**Caveat on what these suites prove.** ASR on a fixed attack set shows resistance to those attacks, not security. An adaptive attacker who knows the policy can aim at the calls the policy permits. Section 7 adds a small adaptive-attack step for that reason.

## 3. Experimental design

### 3.1 Arms

All arms run the same agent, model, prompts and tasks. Only the enforcement layer changes.

| Arm | Description | What it isolates |
|---|---|---|
| **A0. No enforcement** | The agent talks to the tool server directly, or through the proxy with a pass-through policy. | Baseline utility and ASR. |
| **A1. Scope-only** | Delegation tokens with tool-level capabilities (`server:tool`, no argument constraints) and no extra Cedar rules beyond the capability stage. Equivalent to per-tool OAuth scopes. | What static scoping alone buys. |
| **A2. onbehalf full** | Attenuated tokens with argument constraints, plus the per-call Cedar policy, leases and audit. | The contribution under test. |
| **A2-d (ablations)** | A2 with (i) no sub-agent delegation (single hop), (ii) delegation but no Cedar rules (constraints in the token only), (iii) Cedar rules but wide tokens. | Which mechanism does the work. |
| **R (reference)** | The benchmark's own defenses where available, for example AgentDojo's built-in defenses, and AgentGate's published numbers [as reported on its [NeurIPS 2026 page](https://neurips.cc/virtual/2026/168219); not independently reproduced]. | Context only. Not a head-to-head claim unless AgentGate is rerun in the same harness. |

A0 versus A1 versus A2 is the main comparison. A1 is the arm that answers "is argument-level policy necessary, or are scopes enough".

### 3.2 Factors and repetitions

- Models: at least two closed-weight models and one open-weight model, to avoid a result that depends on one model's habits. Fix versions and record them.
- Temperature 0 where the API allows it; otherwise k = 5 repeats per case. LLM calls are not deterministic even at temperature 0, so repeats are required either way for the model-dependent metrics.
- Attacks: the default attack of each suite, plus one adaptive attack (section 7).
- Delegation topology: single agent, and a planner with one or two sub-agents. AgentDojo and InjecAgent are single-agent benchmarks; the multi-hop condition is created by the harness (section 4.3) and must be labelled as a harness construction, not a property of the benchmark.

### 3.3 Metrics

| Metric | Definition | Where |
|---|---|---|
| **Attack success rate (ASR)** | Share of (user task, injection task) cases where the attacker's goal is achieved, as judged by each suite's own checker. For AgentDojo this is a state check. | RQ1 |
| **Utility (task success)** | Share of benign user tasks completed, with no attack present. Reported separately from utility under attack. | RQ1 |
| **Utility under attack** | Share of user tasks still completed when an injection is present. Separates "blocked the attack" from "broke the task". | RQ1 |
| **False-deny rate** | Share of calls on the ground-truth path of a benign, successful run that onbehalf denied. Computed per call from the audit log and per task. A task can fail without a false deny (model error) and a false deny can be recovered from (the agent retries differently), so report both the call-level and the task-level rate. | RQ1 |
| **Denial breakdown** | Denials by reason code (`capability_denied`, `policy_deny`, `lease_revoked`, ...), split into correct (attack call) and incorrect (benign call). | RQ1, RQ3 |
| **Added latency, p50 and p99** | Per-call difference between proxied and direct calls to the same upstream, plus the absolute proxied latency. | RQ2 |
| **Policy size** | Lines of Cedar, number of policies, number of capabilities per token, and token size in bytes, per task and per suite. Also the effort to produce them (section 4.4). | RQ1, RQ3 |
| **Expressibility class** | For each benign task, the least expressive model that separates its legitimate calls from the injected calls: tool scope, argument constraint, or run-time data (section 5.3). | RQ3 |
| **Audit completeness** | Share of audited decisions with all required fields; chain verification result. | RQ4 |

ASR must always be reported next to utility. A policy that denies everything has an ASR of zero.

### 3.4 Calls that reach the upstream

Count the `tools/call` requests that reach the upstream server in each arm, and the subset that match an injection task's goal. In the demo, "three denied calls never left onbehalf" is the kind of statement to make quantitative.

## 4. Harness: wrapping the benchmarks with the MCP proxy

### 4.1 Shape

```
 benchmark runner (AgentDojo / InjecAgent / ASB / MCP-SafetyBench)
        |  user task + attack; model API calls
        v
   agent loop  --tools/call (JSON-RPC)-->  onbehalf-proxy  --tools/call-->  suite MCP server
   (planner, sub-agents hold                 |  token verify, lease,         (stateful environment,
    their own delegation tokens)             |  capability stage, Cedar,      injection payloads live
                                             |  audit append                  in tool results)
                                             v
                                       audit log (SQLite)  -->  metrics extractor
```

The agent never holds the upstream credential. Each suite's tools are exposed by an MCP server that onbehalf proxies, the same arrangement as `[[upstreams]]` in `config/example.toml`.

### 4.2 Per suite

- **MCP-SafetyBench, MCPTox, MCPSecBench:** the tools are already MCP servers. Point `[[upstreams]]` at them and have the harness's MCP client connect to `POST /mcp/{upstream}` with a bearer token instead of to the server. Little adapter code.
- **AgentDojo:** tools are Python functions over an in-process environment. Write one adapter that serves a suite's `FunctionsRuntime` as an MCP server (one server process per episode, so environment state is isolated and can be inspected by the suite's own utility and security checks afterwards), and one pipeline element that replaces direct function execution with an HTTP call to the proxy. The injection mechanism (placeholders in environment data that appear in tool results) is unchanged, so the benchmark's attack logic is untouched.
- **InjecAgent:** test cases supply simulated tool responses, so a thin MCP server returns the recorded response for the user tool and logs whether the agent then issues the attacker tool call. The proxy sees that second call and decides it.
- **ASB:** use the tool-use attack subsets, with the same simulated-tool pattern as InjecAgent.

The adapter and the shared result schema live in a separate harness repository so the benchmarks' licences and dependencies do not enter the onbehalf workspace. Pin benchmark versions by commit hash.

### 4.3 Token minting per episode

```python
# pseudocode, one episode
user = "alice"                                  # fixed synthetic user per suite
policy = policy_for(task, arm, split)           # section 4.4; written to a per-episode Cedar file
srv = start_onbehalf(policy, upstream=suite_mcp(task.environment))
root = srv.token_root(user, agent="planner", caps=caps_for(task, arm))
for sub in task.subagents_if_any:               # multi-hop condition only
    sub.token = srv.token_exchange(root, actor=sub.name, caps=narrow(root.caps, sub.role))
run_agent(task, attack, tools=mcp_client(srv, token=...))
record(task, outcome=suite_checker(env), audit=srv.audit_dump(), latency=client_timers)
srv.stop()
```

Notes:

- Use `[dev] allow_root_mint` only inside the harness, on a loopback address, and say so in the paper. It means user authentication is not under test. The OIDC intake path is covered by its own tests and is not part of this evaluation.
- Episodes must not share an audit database, or the audit-completeness check and per-episode denial counts get mixed.
- For the multi-hop condition, sub-agent roles are assigned by a fixed rule per suite (for example, a "reader" that gets read tools and a "writer" that gets send tools), declared before any runs. They are not tuned to the results.

### 4.4 Dataset and policy generation

Policies are the main experimenter degree of freedom. If they are written after looking at the attacks, the ASR result is meaningless. The plan fixes how policies come into being.

1. **Splits.** Split each suite's user tasks into a development split (about 30%) and a held-out test split (about 70%), stratified by suite, before writing any policy. Generators and hand-written policy templates are tuned on the development split only. Report test-split numbers.
2. **Policy sources, from least to most knowledge of the task.**
   - **G0, suite-level static policy.** Written once per suite by hand with no per-task knowledge, for example "send only to addresses in the user's contacts", "read only repositories with the user's prefix". The realistic floor.
   - **G1, task-prompt synthesis.** An LLM drafts capabilities and Cedar rules from the user's task text and the tool catalogue only, then `onbehalf policy lint` and a schema check run, and a human reviews against a written rubric. This models a user or operator describing the job in words. Record the model, prompt, review time and the rate of edits made.
   - **G2, oracle from ground truth.** Capabilities and constraints derived mechanically from the ground-truth call lists of the user tasks (AgentDojo provides these). This is an upper bound on what a perfect operator could write, not a deployable approach. Never present G2 numbers as the headline.
3. **Scope-only arm (A1).** Derived from the same source by dropping all argument constraints and all Cedar rules, so A1 and A2 differ only in the thing under test.
4. **Policy tests.** Every generated policy is run through `onbehalf policy test` against two auto-generated sets: the ground-truth calls of the user task (must be allowed) and the injection task's calls (should be denied). Failures in the first set are logged as false denies before any model run, which makes it possible to separate policy-authoring error from model behaviour.
5. **Policy size.** Measure for each source. If G2 is small but G1 needs careful review, that is a result about usability, and a limitation on RQ1.

The per-episode policy files, the generation prompts and the review rubric are released with the harness.

## 5. Statistical plan

### 5.1 Unit of analysis and pairing

The unit is the case: a (user task, injection task, model, repeat) tuple for ASR, and a (user task, model, repeat) tuple for utility. All arms run the identical cases, so comparisons are paired.

### 5.2 Tests and intervals

- **ASR and utility, two arms:** exact McNemar test on discordant pairs (case-level, aggregating repeats by majority vote and also reporting the any-success variant), with a paired difference and a 95% Wilson-based interval for each rate. For three arms, run the pairwise tests and correct with Holm's method.
- **Pooled across models:** a mixed-effects logistic regression with arm as a fixed effect and random intercepts for user task and for model, to avoid treating the same task as independent observations. Report the arm odds ratios with intervals. Use cluster-robust errors by user task if the mixed model does not converge.
- **Non-inferiority on utility:** the claim "utility is not materially reduced" is tested as non-inferiority against a margin of 5 percentage points (the AgentGate paper reports utility within 4.18 points of native agents on its benchmarks; using a similar margin keeps the comparison honest). Declare a lower one-sided 95% bound on the A2 minus A0 difference above minus 5 points as non-inferior. The margin is set here, before any run.
- **Small denominators:** AgentDojo has 97 user tasks. At an A0 utility near 0.8, a 95% interval on a single model's utility is roughly plus or minus 8 points. State this in the paper; it means small utility differences cannot be resolved per model and the pooled analysis carries the weight. Do not report per-suite differences as findings unless the interval excludes zero.
- **ASR near zero:** if A2 shows zero successes, report the rule-of-three upper bound (3/n) rather than "0%".
- **Multiple benchmarks:** treat each benchmark as its own family. Do not pool ASR across benchmarks.
- **Pre-registration:** write the arms, metrics, margins, splits and analysis scripts into the harness repository, tag it, then run the test split. Changes after that go into a labelled deviations list.

### 5.3 RQ3 analysis

RQ3 needs no model runs. For every benign task with a ground-truth call list, and every injection task in the same suite:

1. Extract the ground-truth tool calls and arguments for the user task and the injection task.
2. Classify the user task by the weakest model that allows the user's calls and denies the injection's calls:
   - **S (scope):** a tool-level allow-list separates them (the injection uses a tool the user task does not need).
   - **C (constraint):** the tools overlap but a constraint in the supported algebra (`equals`, `one_of`, `prefix` on a named argument) separates them.
   - **D (data-dependent):** the separating value is only known from earlier tool output, or the constraint needs numeric ranges, regexes or nested objects, which the current model does not have (RFC section 3.1).
   - **N (none):** no argument-level rule separates them, for example the injected call is identical to a legitimate one.
3. Two coders label a random 20% sample independently; report Cohen's kappa and resolve disagreements before labelling the rest.
4. Report the S, C, D, N shares per suite with Wilson intervals, and the share of injection tasks that reuse a tool the user task needs (the quantity that determines whether scope-only can work at all).

The paper should state plainly that D and N cases bound what the current design can do, and that these are the cases where information-flow labelling (RFC section 9, open question 5) would be needed.

## 6. Overhead measurement (RQ2)

Run separately from the LLM experiments, because model latency would swamp the signal.

- **Harness.** A first version exists: `crates/onbehalf-bench` and `scripts/bench-e2e.sh` (method and a first run in [performance.md](../design/performance.md#end-to-end-proxy-versus-direct), results in `docs/design/bench/`). It covers direct versus proxy, chain depth 1 and 3, allow and the two kinds of deny, 1, 8 and 32 clients, and memory versus file audit, with closed-loop load, one run per cell and an audit-chain check at the end. Still to add for the study: open-loop arrival rates, at least 5 runs per condition with bootstrap intervals, policy sizes up to 1,000, 64 clients, the stage breakdown, and a quiet two-machine setup.
- **Setup.** A stub MCP upstream that returns a fixed response (the proxy crate already has a fake MCP server) on one machine, the proxy on another or on isolated cores, and a load generator. Record CPU model, kernel, governor, Rust toolchain, build profile and onbehalf commit hash. Pin CPU frequency where possible.
- **Conditions.** Direct to upstream; through the proxy with a pass-through policy; through the proxy with the default policy; chain depths 1 to 4; policy sizes from 1 to 1,000 policies; 1, 8 and 64 concurrent callers.
- **Method.** Open-loop load at fixed arrival rates (to avoid coordinated omission), a warm-up period that is discarded, at least 5 independent runs per condition, latencies in an HDR histogram. Report p50, p99 and p99.9 with bootstrap confidence intervals over runs, and the added latency as the paired difference to the direct condition at the same arrival rate.
- **Components.** The end-to-end figure is decomposed using tracing spans: token verification, lease lookup, capability stage, Cedar, audit append, upstream hop. The [performance notes](../design/performance.md) already say the SQLite stores are serialised behind a mutex and that this will matter under concurrency; this experiment measures how much.
- **In context.** Also report the added latency as a fraction of the model-call and tool-call latency seen in the benchmark runs, since that is what an agent user experiences.
- **Throughput limit.** Find the arrival rate at which p99 doubles relative to the lowest rate (the knee), per condition.

## 7. Adaptive attack check

Fixed attack sets are written against agents, not against a particular policy. A small additional step:

- Take the A2 policy for a sample of tasks and give an attacker (an LLM with the policy text, the tool catalogue and the user task, but no model weights) a budget of attempts to craft an injection whose goal call is permitted by the policy yet still harmful, for example sending to an allowed recipient with attacker-influenced content.
- Report how many attempts succeeded, and classify each as inside the threat model (a permitted harmful call) or a bypass of enforcement (which would be a bug, filed through [SECURITY.md](https://github.com/7Mudit/onbehalf/blob/main/SECURITY.md)).
- Expect successes of the first kind. Documenting them is part of the result: it measures how much the policy author's precision matters, and it ties to the "legitimate-but-harmful reads" limitation.

## 8. Threats to validity

- **Policy-author effect.** Results depend on the policies. Mitigated by splits, policy sources G0 to G2 and by reporting G1 as the headline, but not removed.
- **Benchmark fit.** AgentDojo, InjecAgent and ASB were not designed around a delegation proxy. The multi-hop topology is imposed by the harness, and the MCP adapters change how tools are called. A reader could argue the adapter alters agent behaviour; check by comparing A0-direct against A0-through-proxy utility.
- **Benchmark contamination and drift.** Models may have seen the public benchmarks. Suites change across versions. Pin versions; avoid claiming absolute ASR numbers beyond the pinned version.
- **Model nondeterminism and API drift.** Repeats and recorded model identifiers help; provider changes during the study can still shift results. Log API model strings and dates.
- **Construct validity of ASR.** Each suite defines success in its own way (state check versus string match). Do not compare ASR levels across suites.
- **Selection of in-scope cases.** Section 2 requires reporting excluded cases; the reader can recompute with them in.
- **Single implementation.** One prototype, pre-alpha, v0. Results describe this implementation and policy model, not delegation-based authorization in general.

## 9. Timeline (90 days)

Day 0 is the start of the work; weeks are counted from there.

| Weeks | Work | Output |
|---|---|---|
| 1 to 2 | Freeze this plan and write down the arms, splits, metrics and margins. Pin benchmark versions. Build the harness skeleton: per-episode server start-up, token minting, audit dump, result schema. Run MCP-SafetyBench or a subset through the proxy in pass-through mode as the first end-to-end check. | Tagged harness repository with the pre-registered plan |
| 3 to 4 | AgentDojo adapter (FunctionsRuntime as MCP server, pipeline element). Verify A0-direct against A0-through-proxy utility. Write G0 policies for two suites. | A0 results on AgentDojo; adapter tests |
| 5 to 6 | RQ3 static classification on all suites, with two coders. Policy generators G1 and G2, `policy test` gate. | RQ3 tables; policy corpus |
| 7 to 8 | Main runs on the development split to debug; then lock policies and run the held-out test split for A0, A1, A2 and ablations on AgentDojo. | RQ1 results for the primary benchmark |
| 9 | InjecAgent and in-scope ASB subsets; MCP-SafetyBench and MCPTox runs; coverage table for MCPSecBench. | RQ1 results, second family |
| 10 | Overhead experiments (section 6) on dedicated hardware. | RQ2 results |
| 11 | Adaptive attack check; audit completeness check (RQ4); analysis scripts rerun from raw logs. | Remaining results |
| 12 | Write-up: figures, tables, threats to validity, deviations list. Release harness, policies and logs. | Workshop paper draft or thesis chapter draft |
| 13 | Buffer for reruns after fixes, and internal review. | Submission-ready draft |

The slip risk is the AgentDojo adapter and the LLM budget. If weeks 3 to 6 run over, cut the ASB and MCPTox runs first and keep AgentDojo, InjecAgent and RQ3, which together carry the argument.

LLM cost is estimated from the case counts: AgentDojo has 629 security cases plus 97 benign tasks per model per arm per repeat, so an arm with 3 models, 5 repeats and 4 enforcement variants is roughly 3 x 5 x 4 x 726, about 43,000 episodes before InjecAgent. Estimate the cost per episode from a pilot of 20 episodes in week 3 and reduce repeats or models if the budget requires; do this before committing to the matrix.

## 10. Limitations of the plan

- It evaluates tool-call enforcement. It says nothing about the model-level, memory or host-level attacks that some of these suites include.
- onbehalf does not do information-flow control. Cases where the harm is a permitted read followed by a permitted write to an allowed destination are, by design, not stopped, and the adaptive step is expected to find some.
- The capability algebra is small (`equals`, `one_of`, `prefix`). Tasks needing ranges or run-time data show up as class D in RQ3 and as false denies or missed attacks in RQ1. That is a finding about the current design, and it may change if the algebra grows.
- Hop 0 is minted through the development endpoint in the harness, so identity-provider intake and the P1 guarantee (verified originating user) are not evaluated here.
- Revocation (P4) is only exercised in a small scripted test, not under the benchmarks, because none of the suites models a user withdrawing consent mid-run. A mid-run revocation experiment (revoke at a random step, count calls that reach the upstream afterward) is a possible extension.
- Overhead numbers describe one build on one hardware setup, in a pre-alpha implementation.
- The AgentGate comparison is by published numbers unless the system is rerun in the same harness.

## 11. Open items

- Confirm suite names and task counts against the exact AgentDojo version pinned for the study.
- Decide the model list and the LLM budget after the week-3 pilot.
- Check each benchmark's licence before redistributing any of its data in the harness repository.
- Decide whether the harness lives under the same GitHub organisation as onbehalf or separately.
