# AgentDojo evaluation plan, 2026-11-05

This plan puts attenuo under a public prompt-injection benchmark with a real model making the decisions. The [injection suite](../evaluation/injection-suite.md) replays calls we wrote ourselves. So it can't answer the first question a reader will ask: does this hold when a model chooses the calls, on a test someone else built?

The plan has three steps:

1. A small baseline pilot on Claude Haiku 5.5, to replace the cost estimates here with measurements.
2. A free replay of each benchmark attack's own tool calls through attenuo, which needs no model.
3. The full arms, once the pilot's cost per run is known.

No benchmark has run yet. Facts about the benchmark come from `agentdojo` 0.1.35 as installed from PyPI, read locally, unless a line says otherwise. All costs are estimates.

## What the benchmark measures

AgentDojo ([arXiv 2406.13352](https://arxiv.org/abs/2406.13352), Debenedetti et al.) gives an agent a user task in a simulated environment and hides an attacker's instruction in the data its tools return. A run ends with checks against the environment's final state, so the score doesn't depend on what the agent says it did or on attenuo's own audit log.

| Number | Runs it comes from | Meaning |
| --- | --- | --- |
| Benign utility | each user task, no attack | The agent finished the task. |
| Utility under attack | each user task paired with each injection task | The agent still finished the user's task with the injection present. |
| Attack success rate | same pairs | The environment shows the attacker's goal was reached. |

A defense that blocks everything scores a perfect attack success rate and no utility, so the benchmark exposes that trade. We report all three numbers for every arm.

## Suites

Counts are from benchmark version `v1.2.2`, the newest the package loads. A pair is one user task with one injection task.

| Suite | User tasks | Injection tasks | Pairs | Tools | Mean ground-truth calls per task | Most calls in a task |
| --- | --- | --- | --- | --- | --- | --- |
| workspace | 40 | 14 | 560 | 24 | 2.1 | 6 |
| travel | 20 | 7 | 140 | 28 | 6.2 | 18 |
| banking | 16 | 9 | 144 | 11 | 2.1 | 5 |
| slack | 21 | 5 | 105 | 11 | 4.7 | 9 |
| Total | 97 | | 949 | | | |

The paper's abstract says 97 tasks and 629 security test cases. Version `v1` has 6 workspace injection tasks, which gives 629. Version `v1.2` raised that to 14, which gives 949. Cite the version whenever citing a count.

## How tools and defenses are defined

Tools are Python functions, not MCP tools. Each takes typed arguments plus dependencies from the task's environment object and changes that object directly. A `FunctionsRuntime` calls them through `run_function(env, name, kwargs)` and returns a result and an error string. A call that fails doesn't end the run: the error goes back to the model as the tool result.

An agent is a pipeline of elements that all implement `query(query, runtime, env, messages, extra_args)`. The standard one is:

```text
SystemMessage, InitQuery, LLM, ToolsExecutionLoop([ToolsExecutor, LLM])
```

The bundled defenses (`tool_filter`, `transformers_pi_detector`, `spotlighting_with_delimiting`, `repeat_user_prompt`) are arrangements of these elements. Replacing `ToolsExecutor` is therefore the supported way to put something between the model and the tools. Custom pipelines run through the Python API (`benchmark_suite_with_injections`, which accepts lists of user and injection tasks).

## Models

The plan uses `claude-haiku-5-5` for the pilot and `claude-sonnet-5-5` for the real run. The package can't select either from its command line, and three things need handling in a custom pipeline:

- Model selection. The CLI's `--model` is an enum holding only Claude 3 ids. The entry point is `python -m agentdojo.scripts.benchmark`, and the package installs no `agentdojo` console script. We build the pipeline ourselves around `AnthropicLLM(client, model=...)`.
- Temperature. `AnthropicLLM` sends `temperature=0.0` by default, and both models reject non-default values. Passing `temperature=None` leaves it out. Runs can't be pinned to temperature 0, so repeat runs may differ, and the report has to say so.
- Attack text and output length. `important_instructions`, the attack we plan to use, looks up the model's name in `MODEL_NAMES` and raises if it isn't there, so we add both ids mapped to `Claude`. `max_tokens` defaults to 1024, which is low with adaptive thinking on, so we raise it to 4096.

How `AnthropicLLM` replays thinking blocks on these models is untested. The pilot's first run will show whether it needs a small subclass.

## Cost estimate

Prices are the first-party rates per million tokens: Haiku 5.5 $0.10 input and $0.50 output, Sonnet 5.5 $2 and $10.

The input size comes from a local replay, with no model and no API call, of each user task's ground-truth calls. For each model turn we added up the tool schemas plus the conversation so far, then converted at 4 characters per token. Two assumptions sit on top of that, and neither is measured:

- Input is doubled, because a real model takes extra turns and the injected text adds length.
- Output is 300 tokens per turn, which includes thinking.

A run below is one benign task or one attack pair. One arm runs all of them.

| Suite | Runs per arm | Input tokens per run | Output tokens per run | Haiku per arm | Sonnet per arm |
| --- | --- | --- | --- | --- | --- |
| workspace | 600 | 24,700 | 930 | $1.76 | $35.18 |
| travel | 160 | 59,100 | 2,160 | $1.12 | $22.36 |
| banking | 160 | 8,200 | 930 | $0.21 | $4.11 |
| slack | 126 | 12,300 | 1,710 | $0.26 | $5.25 |
| Total | 1,046 | | | $3.35 | $66.90 |

Treat these as good to within a factor of about three. Thinking tokens are the largest unknown. The longest travel tasks may also pass 100K input tokens, where Haiku 5.5 costs more ($0.50 and $2.50). `AnthropicLLM` sets no cache breakpoints. Sonnet 5.5 cache reads are $0.20 per million tokens against $2 for input, and each turn resends the whole conversation. A subclass that adds prompt caching is worth measuring before a Sonnet run.

The budget is $168.50. Every arm on Haiku is affordable. Two full Sonnet arms come to about $134 before any error in this estimate, which is too close, so the real run should start from the options under "Decisions needed".

## How attenuo goes between the agent and the tools

There are two ways in.

| | AuthZEN call from the pipeline | MCP proxy with a shim |
| --- | --- | --- |
| Path | `POST /access/v1/evaluation`, then `run_function` if allowed | `POST /mcp/{suite}`, attenuo forwards to a shim, the shim calls `run_function` |
| Tokens, leases, Cedar, run limits | Yes, the [reference](../reference/http-api.md#decision) says it is the same pipeline, run limits included | Yes |
| Output labels | No, as far as the docs say: attenuo never sees the tool result | Yes, the proxy records each result and taints the run |
| Tool list filtering | No | Yes |
| New code | Executor only | Executor and shim |

AuthZEN is the cheapest, but it can't run the labels arm. Labels are the best result on the injection suite: 1 of 77 attack calls allowed against 15 of 77 without them ([final results](../../evaluation/injection-suite/results/2026-11-05-final-main.md), scripted approver). The proxy is also the deployment we describe to readers. The plan uses the proxy.

### The adapter

- `AttenuoToolsExecutor` replaces `ToolsExecutor`. It keeps the same list-argument parsing, sends each call as a JSON-RPC `tools/call` to the proxy, and formats results with the same YAML formatter. The baseline arm keeps the stock executor unchanged.
- The MCP shim is a small HTTP server in the same Python process. It answers `tools/list` from the suite's tool signatures and `tools/call` through `run_function` on the current run's environment. Runs are sequential, so one reference to the current environment is enough.
- Denials. A `-32003` denial becomes a tool result error, as a failed call does in the stock executor, so the model sees the refusal and carries on. A `-32008` approval request goes to the scripted approver below.
- One run, one delegation. Each benchmark run gets a new root token, so taint and limits can't leak between runs.
- Generated config. A script writes `[policy.catalog.<suite>.<tool>]` from each suite's signatures. Tool names that only read become `readonly = true`, by a rule written down and reviewed by hand. The other tools stay `destructive`, and tool outputs stay `untrusted`, which are the catalog's defaults.

The catalog's input types are `string`, `long`, `bool` and `set<...>`, and that leaves a gap: `send_money`'s `amount` is a Python `float`, and floats aren't declarable. An undeclared argument can't be tested in a typed policy. Before writing the banking policy we need to check how `amount` limits and undeclared arguments treat a value like `12.5`. Lists such as `send_email`'s `recipients` should map to `set<string>`, which also needs a test.

### Arms

| Arm | What it adds | Reason |
| --- | --- | --- |
| A0 baseline | Stock pipeline, no attenuo | The numbers everything is compared to. |
| A1 suite policy | One broad grant and one Cedar policy per suite, written from tool signatures | What a deployer can do without knowing the task. |
| A2 task grants | A1 plus a capability grant for each user task | What delegation adds. |
| A3 labels | A2 plus approval on destructive calls after untrusted output | The labelling result, under a real model. |

The hard question in A2 is who writes each task's grant. The ground truth gives the exact calls a task needs, so a grant derived from it is an oracle and an upper bound, and has to be labelled as one. A realistic version has a planner model propose the grant from the user's prompt, before any tool output exists. That costs more and may hurt utility. We run the oracle first and add the planner only if the oracle's result justifies it.

### Output labels and the approver

The injections sit in tool results: email bodies, file contents, web pages, transaction subjects. That is exactly what labels mark. Every suite tool is `output = "untrusted"` by default, so the first read taints the run, and almost every later destructive call asks for approval.

The benchmark has no human, so an approver has to be scripted, and it largely decides A3's utility. We report two bounds:

- Decline all is the pessimistic bound for utility.
- Approve only calls in the task's ground truth is an optimistic stand-in for a careful person.

Argument-level taint (phase 2 of the [labelling design](../design/output-labelling.md)) could gate less often. It is worth an arm only if A3's approval rate is high. Phase 3 of that design, labelled values in the SDKs, names this adapter as its measurement and stays out of scope here.

### Run limits

A [run limit](../design/run-limits.md) caps what one delegated run can do: how many calls, how much in total, how many distinct destinations. Limits fit attacks such as a second payment to a permitted payee. A limit needs a number that comes from the task, so it belongs with A2 and uses the same oracle. On the injection suite the frozen limit rule cost utility: 13 of 130 benign calls denied against 3 of 130 for the full arm. So it stays a separate arm if we run it.

## A free number first

Each injection task also has a ground truth: the calls that would reach the attacker's goal. Replaying those through each attenuo arm needs no model and costs nothing. It answers a narrower question, namely whether this call would have been stopped had a model obeyed.

That matters because of a likely outcome. Current Claude models may resist these attacks well on their own, and then A0's attack success rate is low and any arm has little left to reduce. A low difference in that case would say more about the model than about attenuo, and the replay is the number that still shows what enforcement holds. We report both and say which is which. The replay can't replace the model runs, because it says nothing about utility.

## Rules that keep the result honest

- The policies, the grant rule and the catalog rule are committed before the first enforced run, and aren't changed after seeing results.
- Tuning is limited to the pilot's tasks, and those tasks are reported separately from the rest.
- Unfavourable results are reported, including lost utility.
- Scoring stays the benchmark's own, unmodified. Any change to the pipeline is listed.
- Only one attack is planned at first, `important_instructions`. That is not worst-case evaluation, and an adaptive attacker who knows attenuo is in place is out of scope, so the report states both limits.

## InjecAgent

[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) has 1,054 test cases over 17 user tools and 62 attacker tools. Attacks are direct harm and data stealing, in `base` and `enhanced` settings, and attack success is reported as ASR-valid and ASR-all. This comes from its README; we haven't read its code, and the README doesn't say whether tools execute. Its setup looks like a single injected tool response, not a multi-step task, so it says less about delegation and we'd have less to enforce. AgentDojo comes first. We reconsider InjecAgent after A0 and A2.

## The pilot

The pilot runs after the key check, which has passed:

It uses the workspace suite, because workspace holds 600 of the 1,046 runs per arm and so sets the total. It takes 5 user tasks, with and without 2 injection tasks, for 5 benign runs and 10 attack runs. It is A0 only, on `claude-haiku-5-5`, with `important_instructions`.

The estimate above puts it at about $0.04, and it stops if spend reaches a few dollars. It reports the three numbers, input and output tokens per run including thinking, and the credit balance before and after. Those go into a follow-up to this document, and the estimate table gets replaced.

Five tasks is too few to say anything about the model's robustness. The pilot checks that the pipeline works and what it costs.

## Decisions needed

1. Sonnet scope. Every arm on Haiku is about $13. For Sonnet, A0 and one enforced arm in full is about $134, which leaves little margin. Pending the pilot's numbers, we recommend banking, slack and travel in full ($32 per arm) with a sample of workspace pairs. Add prompt caching if the pilot shows it helps.
2. Planner grants. Whether to pay for a realistic planner on top of the oracle in A2.
