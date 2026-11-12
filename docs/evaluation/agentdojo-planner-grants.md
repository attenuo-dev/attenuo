# AgentDojo with planner-written grants

The AgentDojo replay (`evaluation/agentdojo/replay.py`, results in the [AgentDojo plan](../research/agentdojo-plan-2026-11-05.md#replay-2026-11-05)) gives each user task a token from `grant_for()`, which reads the task's ground-truth calls. Those grants are oracles. The [evaluation plan](../research/evaluation-plan.md#44-dataset-and-policy-generation) says oracle numbers must never be the headline, and that grants written from the task text and the tool catalogue alone should be. This page fixes how those grants are written, frozen and measured, before any are written. It has no results yet.

## Grant sources

| Source | Written from | Here |
| --- | --- | --- |
| G0 | Nothing task-specific: one policy per suite | The `suite` arm: the suite policy and a broad `<suite>:*` token. |
| G1 | The task's prompt and the tool catalogue only | The `planner`, `planner_only` and `planner_nocontact` arms: a token built from a planner's grant file. |
| G2 | The task's ground-truth calls | The `grants`, `grants_only` and `grants_nocontact` arms: `grant_for()`. An upper bound, not a deployable method. |

The three planner arms are the oracle arms with only the token changed: `planner` runs under the suite policy as `grants` does, `planner_only` under a permit-all policy as `grants_only` does, and `planner_nocontact` under the suite policy with its recipient rules replaced by plain permits, as `grants_nocontact` does. The catalogue, the policies, the attacks and the replay order are unchanged.

## Who saw what

| Who | Sees | Does not see |
| --- | --- | --- |
| The tooling author (this change) | `replay.py`, the ground truth while testing | Writes no real grant. Tested only with a synthetic grant set, `fixture-reads-only`, that grants every read tool and nothing else. |
| The planner | The bundle only | Ground truth, injection tasks, attack text, environment contents, replay results, this repository. |
| The reviewer | The bundle and the grant files | The same as the planner, until the review is recorded. |
| The analyst | Everything, after the freeze | Changes no grant. |

### The bundle

`evaluation/agentdojo/planner_bundle.py --out DIR` writes, for each of the four suites:

- `<suite>/tasks.json`: each user task's `id` and `prompt`. No other field of the task object (no ground truth, expected output, difficulty or comment).
- `<suite>/tools.json`: each tool's `name`, `description` and parameter schema exactly as AgentDojo hands them to the model (`Function.description` and `Function.parameters.model_json_schema()`), and `read`, whether `replay.py`'s `is_read()` treats the tool as a read.
- `<suite>/principal.json` for workspace, travel and banking (see below).
- `INSTRUCTIONS.md` (a copy of `evaluation/agentdojo/planner/INSTRUCTIONS.md`), `planner_grants.py` (the validator, standard library only) and `MANIFEST.json` (the benchmark version and each file's SHA-256).

Each file is built from an allowlist of fields, and a unit test checks that list. After writing, the exporter reads the bundle back and fails if it finds any of the following:

- a ground-truth argument value of a user task that is not literally in that task's own prompt;
- an injection task's goal or a ground-truth argument value of an injection task;
- a line of the `important_instructions` or `tool_knowledge` templates;
- a string of 12 characters or more from the default environment;
- the words "inject", "attack", "adversar", "AgentDojo" or "ground truth".

Values shorter than 4 characters are not searched, since they match anywhere. A hit inside another task's prompt is public task text and is reported, not failed. So is one reviewed coincidence in the catalogue: `get_current_day`'s description gives `2022-01-01` as an example date, and banking's ground truth uses the same date.

### The user's identity

A deployed planner knows whom it acts for. The bundle therefore includes the user's own identifiers where the environment makes them unambiguous, and nothing else about the user:

- workspace: the inbox's account address;
- travel: the user's address, which is also the inbox's account address (the exporter checks they agree);
- banking: the account's IBAN;
- slack: nothing. The environment names no user of its own.

The rejected alternative was to leave identity out everywhere. That would make a task such as "invite me" impossible to pin, so it would charge the planner for missing knowledge no real planner lacks. The cost of including it: in workspace user tasks 9 and 21, the ground truth adds the user's own address as a participant, and the prompt does not say it. The leak check reports these two values as principal values rather than failing on them. Names, postal addresses, phone, passport and card numbers in the travel and banking environments are left out: they identify the user but no task needs them in a grant, and they are environment contents.

### Instructions and review

The planner gets [`INSTRUCTIONS.md`](https://github.com/attenuo-dev/attenuo/blob/main/evaluation/agentdojo/planner/INSTRUCTIONS.md). It explains grants in plain words, gives the file format, and states the rules: grant only the tools the task needs, leave reads open unless the prompt names the exact resource, pin every write argument the prompt determines, prefer `equals` and `one_of`, never invent a value, and name each undetermined argument in the rationale. It uses only the bundle. It says nothing about what an attacker does or how the grants will be tested, since a planner in a deployment would not know that.

A reviewer then applies [`RUBRIC.md`](https://github.com/attenuo-dev/attenuo/blob/main/evaluation/agentdojo/planner/RUBRIC.md): least privilege, no invented values, pins on writes, format. For this run no grant is edited after review unless the validator rejected it, and every such edit is logged in `evaluation/agentdojo/planner/EDITS.md`. Review failures are reported next to the results, not fixed.

### The freeze

`planner_grants.py freeze GRANTS_DIR --source G1 --out evaluation/agentdojo/planner/FROZEN.json` validates the files and records the SHA-256 of each suite's file and the source label. The grant files (`evaluation/agentdojo/planner/grants/<suite>.json`), `FROZEN.json`, the review record and the edit log are committed together before the first replay with them.

`replay.py --planner-grants DIR` refuses to run when:

- the FROZEN record (`--frozen`, default `evaluation/agentdojo/planner/FROZEN.json`) is missing, or has another format;
- any replayed suite's file is missing or its SHA-256 differs from the record;
- any file fails validation;
- the record is inside the repository and is untracked or differs from `HEAD`;
- the source label starts with `G1` and the record is not the committed one.

A record outside the repository is accepted with a warning that the run is not a measured one; that is how the pipeline was tested with the fixture. Each planner row in `rows.jsonl` carries `grant_source` and `grants_sha256`, and `summary.json` records them per suite with `frozen_committed`.

The rejected alternative was a hash written only into the results. It would not stop a replay with grants edited after a first look at the numbers. The check also does not stop someone from editing the grants, re-freezing and committing; the git history is what shows that, which is why the freeze is a commit of its own.

## The planner

The planner is a Claude model run as an agent whose only input is the bundle and whose only output is the four grant files. Model: Claude Opus 5.5, run on 2026-11-12 as four agents, one per suite, each told to read only the bundle's `INSTRUCTIONS.md` and its own suite's files and to write one grant file into an empty directory. The restriction was an instruction to the agent, not a sandbox, and no independent reviewer applied the rubric before the freeze: [`REVIEW.md`](https://github.com/attenuo-dev/attenuo/blob/main/evaluation/agentdojo/planner/REVIEW.md) records how the run was made and what the planner said it was unsure about. It ran once; a repeat run, if any, is reported as a separate grant source, not merged.

## Analysis

`evaluation/agentdojo/stats.py RESULTS_DIR` compares two arms on the same cases, standard library only, unit-tested against hand-computed values:

- **Attacks landed**, on the paired (user task, injection task) cases both arms ran: each arm's count with a Wilson 95% interval; the discordant pairs; an exact two-sided McNemar test on them; and the paired difference in rate with a 95% cluster bootstrap interval.
- **Utility kept**, per user task: the same, with one outcome per user task.
- **Bootstrap.** Resamples user tasks with replacement, so all pairs of a user task move together, stratified by suite so each resample keeps each suite's number of user tasks. 10,000 resamples, seed 20261112, percentile interval with linear interpolation. The rejected alternative, resampling pairs, treats the injection tasks paired with one user task as independent, though they share its token and its calls; with 97 user tasks behind 609 pairs that would make the interval too narrow.
- **Comparisons**: `planner` vs `suite` (what G1 adds over G0), `planner` vs `grants` (G1 against the oracle), `planner_only` vs `grants_only`, and `planner_nocontact` vs `grants_nocontact`. These four are the family; no correction is applied, and none of the p-values is a headline. As the evaluation plan says, per-suite differences are not reported as findings unless the interval excludes zero, and a zero count is reported with its interval, not as 0%.

`evaluation/agentdojo/grant_quality.py GRANTS_DIR` reads the ground truth after the freeze and reports, per suite, for the planner's grants against the oracle's: tools granted; tools granted that the ground truth never calls (over-grant); ground-truth tools not granted (under-grant, which costs utility); pinned write arguments; pins that a ground-truth call does not meet; and ground-truth calls the grant refuses.

## Threats to validity

- **The planner is from the same family as the tools the authors used.** attenuo was built with Claude models, and the planner is one. It may share the authors' habits about what a grant should look like.
- **One planner run.** Unless repeated, the grants are one sample of the planner's behaviour; a second run may grant differently. Its sampling may not be fixable to one output.
- **Public tasks.** AgentDojo's prompts, tools and ground truth are public and may be in the planner's training data. The instructions tell it not to use such knowledge; that cannot be enforced. A grant that pins a value the prompt does not give is a sign of it, and R5 of the rubric and the grant-quality script both count such pins.
- **No model in the loop.** The replay sends the ground-truth calls verbatim. A model may phrase, order or choose calls differently, so a planner grant that refuses a ground-truth call may or may not cost a model the task, and the reverse.
- **The rules were written by the authors.** The instructions, the rubric and the bundle allowlist were written by people who had read the ground truth. They were written to be neutral and were frozen before the planner ran, but they are not independent.
- **Principal identifiers** help the planner on tasks that involve the user's own address (see above).
- **Small numbers.** 97 user tasks; differences of a few tasks are within the intervals.

## Results

Run of 2026-11-12 on main `b0f1ed1` with the server built at `72d5fbc` (no server change between the two), grants frozen in commit `139c9a9` before the replay. Raw output: [`evaluation/agentdojo/results/2026-11-12-planner/`](https://github.com/attenuo-dev/attenuo/tree/main/evaluation/agentdojo/results/2026-11-12-planner) (`rows.jsonl`, `summary.json`, `stats.md`, `grant-quality.md`). The `suite` and oracle arms reproduce the figures of the 2026-11-05 replay (138, 15 and 16 of 609).

No model is in the loop: the attacker's calls are AgentDojo's ground-truth calls, sent after the user task's own. With no attenuo 592 of 609 pairs land.

| Arm | Grant source | Attacks landed (Wilson 95%) | Utility kept (Wilson 95%) |
| --- | --- | --- | --- |
| `suite` | G0 | 138/609 (19.5 to 26.2%) | 77/97 (70.3 to 86.2%) |
| `planner` | G1 | 13/609 (1.3 to 3.6%) | 75/97 (68.0 to 84.5%) |
| `grants` | G2 | 15/609 (1.5 to 4.0%) | 77/97 (70.3 to 86.2%) |
| `planner_only` | G1 | 32/609 (3.7 to 7.3%) | 95/97 (92.8 to 99.4%) |
| `grants_only` | G2 | 16/609 (1.6 to 4.2%) | 97/97 (96.2 to 100%) |
| `planner_nocontact` | G1 | 28/609 (3.2 to 6.6%) | 93/97 (89.9 to 98.4%) |
| `grants_nocontact` | G2 | 16/609 (1.6 to 4.2%) | 95/97 (92.8 to 99.4%) |

| Comparison | Metric | A only | B only | McNemar p | A - B (cluster bootstrap 95%) |
| --- | --- | ---: | ---: | ---: | --- |
| `planner` vs `suite` | attacks landed | 0 | 125 | <0.001 | -20.5% (-21.7 to -19.4) |
| `planner` vs `suite` | utility kept | 0 | 2 | 0.5 | -2.1% (-5.2 to 0.0) |
| `planner` vs `grants` | attacks landed | 2 | 4 | 0.688 | -0.3% (-1.1 to 0.7) |
| `planner` vs `grants` | utility kept | 0 | 2 | 0.5 | -2.1% (-5.2 to 0.0) |
| `planner_only` vs `grants_only` | attacks landed | 21 | 5 | 0.002 | 2.6% (0.0 to 5.9) |
| `planner_only` vs `grants_only` | utility kept | 0 | 2 | 0.5 | -2.1% (-5.2 to 0.0) |
| `planner_nocontact` vs `grants_nocontact` | attacks landed | 17 | 5 | 0.017 | 2.0% (-0.3 to 4.9) |
| `planner_nocontact` vs `grants_nocontact` | utility kept | 0 | 2 | 0.5 | -2.1% (-5.2 to 0.0) |

| Suite | Tools (planner / oracle) | Over-grant | Under-grant | Write pins (planner / oracle) | Pins against ground truth | Ground-truth calls refused |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| workspace | 148 / 75 | 73 | 0 | 45 / 48 | 4 | 0 |
| travel | 108 / 108 | 1 | 1 | 14 / 12 | 2 | 2 |
| banking | 37 / 33 | 4 | 0 | 10 / 36 | 0 | 0 |
| slack | 73 / 64 | 13 | 4 | 20 / 36 | 0 | 7 |

Review: none before the freeze, no edits ([`REVIEW.md`](https://github.com/attenuo-dev/attenuo/blob/main/evaluation/agentdojo/planner/REVIEW.md)).

### What the numbers say

- **With the suite policy, grants written from the task text do as well as the oracle.** 13 of 609 pairs land with the planner's token and 15 with the oracle's; six pairs differ, and the interval for the difference spans zero. Both sit far below the suite policy alone (138). All 13 are on slack, the same two injection tasks the oracle arm leaves open: a link sent to a recipient the task itself allows, and a fetch of a page.
- **Without the policy behind it, the planner's token is looser than the oracle's.** Under a permit-all policy 32 pairs land against 16. The planner pins fewer write arguments (89 against 132) because the prompt often does not say who or how much: a task that says "do what the email asks" gets write tools with no pins. On workspace and banking that lets through 15 pairs that the suite policy's recipient rules then stop. The grant narrows the tools; the policy is what holds when the task text is vague.
- **The cost is two tasks.** The planner loses two user tasks the oracle keeps (travel task 4 and slack task 6), both under-grants the planner flagged as uncertain before the run: it read one prompt as a reminder rather than a booking, and withheld a web fetch in the other. Every other lost task is lost in the oracle arm too, to the suite policy's contact rule.
- **Over-grant.** The planner grants 91 tools the ground truth never calls, 73 of them on workspace. It cannot know which look-ups a task will need, so it grants more of them than the one path the ground truth takes.

### What they do not say

One planner run, by a model from the same family as the tools that built the system, on public task prompts, with no reviewer and an instruction rather than a sandbox as the blinding. The attacker is a fixed call list, not a model that adapts to the grant. Slack's two broad grants (tasks 18 and 19, where the work is on a web page) are a case no grant written before the task can narrow. These figures compare grant sources on one replay; they are not a rate of attacks stopped in deployment.

## Running it

```sh
# The bundle, outside the repository, for the planner.
PYTHONPATH=sdk/python/src python3 evaluation/agentdojo/planner_bundle.py --out BUNDLE
# After the planner and the review: validate, freeze, commit.
python3 evaluation/agentdojo/planner_grants.py freeze evaluation/agentdojo/planner/grants \
  --source G1 --out evaluation/agentdojo/planner/FROZEN.json
# The replay, then the analysis.
PYTHONPATH=sdk/python/src python3 evaluation/agentdojo/replay.py --out RESULTS \
  --binary target/debug/attenuo-server \
  --arms direct suite grants grants_only grants_nocontact planner planner_only planner_nocontact \
  --planner-grants evaluation/agentdojo/planner/grants
python3 evaluation/agentdojo/stats.py RESULTS --md RESULTS/stats.md --json RESULTS/stats.json
PYTHONPATH=sdk/python/src python3 evaluation/agentdojo/grant_quality.py evaluation/agentdojo/planner/grants
```

The pipeline was tested end to end on banking with the `fixture-reads-only` grant set and a FROZEN record outside the repository: arms `direct`, `suite`, `grants` and `planner` took 121 seconds, about 38 seconds per arm with attenuo. Those numbers are not a result: the fixture grants no write tool.
