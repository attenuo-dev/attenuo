#!/usr/bin/env python3
"""Where the finished tasks go: the tasks one arm finished and the other did not, by cause.

Reads a live run's `stats/rows.jsonl` (from `live_rows.py`), each suite's attenuo decision log
(`<suite>/enforced/decisions-grants-0.jsonl`) and the tools each AgentDojo task needs
(`stats/ground_truth.json`), and writes `stats/utility_loss.json` and `stats/utility_loss.md`.

    python3 evaluation/agentdojo/utility_loss.py RESULTS_DIR
    python3 evaluation/agentdojo/utility_loss.py RESULTS_DIR --write-ground-truth

A case is one (suite, user task, injection task) pair for attack runs, or one (suite, user task)
for benign runs, that both arms scored (errored runs are not in the rows, so they are not paired).
A case is *lost* when the stock arm finished the user task (`utility` true) and the attenuo arm did
not; *gained* is the reverse. Lost minus gained is the difference of the two arms' totals, which
the script checks.

Each lost or gained case gets ONE primary cause, from the attenuo arm's decisions in that run, by
the first rule that applies:

1. `needed: <reason>`: attenuo denied a call to a tool that the user task's ground-truth solution
   calls. The reason is that of the first such denied call in the run: `capability_denied` (outside
   the planner's grant), `policy_deny` (the suite policy), `budget_exhausted` (the run's call limit)
   or `input_type_mismatch` (an argument of the wrong type).
2. `derailed after a refusal`: attenuo denied only calls to tools the user task does not need,
   and the task outcome still differs.
3. `no refusal`: attenuo denied nothing in that run. The difference is the model taking a
   different path in the two runs, not a refusal.

Needed tools come from AgentDojo's ground truth (`user_task.ground_truth(env)` on the suite's
default environment, benchmark version v1.2.2: each call's tool and arguments), saved once to
`stats/ground_truth.json` by `--write-ground-truth`, the only mode that imports `agentdojo`. The
classification itself uses the standard library only and is deterministic.

Limits:
- One cause per case. A run with several denials is put under the first rule that matches.
- Tools are matched by name, not by arguments. A denied call to a needed tool may have had
  arguments the task does not need, or may be the attack's call (in banking both the task and the
  attack use `send_money`). The output counts, for the lost cases under rule 1, those where the
  denied call has the arguments of a ground-truth call (all arguments apart from free text such
  as a subject or body, as `replay.py` compares them) and those where the denied tool is also in
  the injection task's ground truth. Both counts are shown, neither changes the cause.
- One run per case and arm, at temperature 0: a `no refusal` case is a run-to-run difference of
  the model, which a second run might not repeat.
- The rule says what attenuo did in the run, not what the model would have done without it.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

SUITES = ("slack", "banking", "travel")
REASONS = ("capability_denied", "policy_deny", "budget_exhausted", "input_type_mismatch")
CAUSES = tuple(f"needed: {r}" for r in REASONS) + ("derailed after a refusal", "no refusal")
LABELS = {
    "needed: capability_denied": "Needed tool denied: outside the grant",
    "needed: policy_deny": "Needed tool denied: suite policy",
    "needed: budget_exhausted": "Needed tool denied: run limit",
    "needed: input_type_mismatch": "Needed tool denied: wrong argument type",
    "derailed after a refusal": "Only unneeded calls denied, task still failed",
    "no refusal": "No refusal (different model path)",
}
GAINED_LABELS = dict(LABELS, **{"derailed after a refusal": "Only unneeded calls denied"})
VERSION = "v1.2.2"
# Arguments not compared when matching a call to the ground truth, as in replay.py.
FREE_TEXT = {"subject", "body", "title", "description", "content", "location", "query"}


def write_ground_truth(results: Path) -> None:
    """Save the tool names of each task's ground truth. Needs `agentdojo`."""
    from importlib.metadata import version

    from agentdojo.task_suite.load_suites import get_suite

    out: dict = {
        "source": f"agentdojo {version('agentdojo')} ground truth, benchmark {VERSION}, "
        "suite default environment",
        "suites": {},
    }
    for name in SUITES:
        suite = get_suite(VERSION, name)
        env = suite.load_and_inject_default_environment({})
        out["suites"][name] = {
            "user": {
                tid: [
                    {"tool": c.function, "args": json.loads(json.dumps(dict(c.args), default=str))}
                    for c in task.ground_truth(env.model_copy(deep=True))
                ]
                for tid, task in sorted(suite.user_tasks.items())
            },
            "injection": {
                tid: sorted({c.function for c in task.ground_truth(env.model_copy(deep=True))})
                for tid, task in sorted(suite.injection_tasks.items())
            },
        }
    path = results / "stats" / "ground_truth.json"
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def load_rows(path: Path) -> dict:
    """{arm: {(kind, suite, user, attack): utility}} from rows.jsonl."""
    out: dict = defaultdict(dict)
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        kind = "attack" if row.get("attack") else "benign"
        out[row["arm"]][(kind, row["suite"], row["user"], row.get("attack"))] = bool(row["utility"])
    return out


def load_denials(results: Path) -> dict:
    """{run label: [(tool, reason, args), ...]} of the denied calls, in log order."""
    out: dict = defaultdict(list)
    for suite in SUITES:
        path = results / suite / "enforced" / "decisions-grants-0.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            d = json.loads(line)
            if d["outcome"] == "denied":
                out[d["run"]].append((d["tool"], d["reason"], d["args"]))
    return out


def pinned(args: dict) -> dict:
    return {k: v for k, v in args.items() if k not in FREE_TEXT}


def classify(denied: list, truth: list) -> tuple[str, str | None, bool]:
    """(cause, denied needed tool, whether that call matches a ground-truth call) for one run,
    by the rule in the module docstring."""
    needed = {c["tool"] for c in truth}
    for tool, reason, args in denied:
        if tool in needed:
            if reason not in REASONS:
                raise SystemExit(f"unknown denial reason {reason!r}")
            match = any(c["tool"] == tool and pinned(c["args"]) == pinned(args) for c in truth)
            return f"needed: {reason}", tool, match
    if denied:
        return "derailed after a refusal", None, False
    return "no refusal", None, False


def analyse(results: Path) -> dict:
    stats = results / "stats"
    rows = load_rows(stats / "rows.jsonl")
    tools = json.loads((stats / "ground_truth.json").read_text(encoding="utf-8"))
    denials = load_denials(results)
    stock, attenuo = rows["stock"], rows["attenuo"]
    report: dict = {"ground_truth_source": tools["source"], "kinds": {}, "cases": []}
    for kind in ("attack", "benign"):
        per: dict = {}
        for suite in SUITES + ("total",):
            per[suite] = {
                "pairs": 0,
                "stock": 0,
                "attenuo": 0,
                "lost": {c: 0 for c in CAUSES},
                "gained": {c: 0 for c in CAUSES},
                "lost_needed_call_matches_truth": 0,
                "lost_needed_tool_also_attack": 0,
                "lost_user_tasks": set(),
            }
        for key in sorted(set(stock) & set(attenuo), key=str):
            k, suite, user, attack = key
            if k != kind:
                continue
            a, b = attenuo[key], stock[key]
            for cell in (per[suite], per["total"]):
                cell["pairs"] += 1
                cell["stock"] += b
                cell["attenuo"] += a
            if a == b:
                continue
            direction = "lost" if b else "gained"
            label = f"{suite}/{user}/{attack or 'none'}"
            truth = tools["suites"][suite]["user"][user]
            cause, tool, match = classify(denials.get(label, []), truth)
            also_attack = bool(
                tool and attack and tool in tools["suites"][suite]["injection"][attack]
            )
            for cell in (per[suite], per["total"]):
                cell[direction][cause] += 1
                if direction == "lost":
                    cell["lost_user_tasks"].add(f"{suite}/{user}")
                    cell["lost_needed_call_matches_truth"] += match
                    cell["lost_needed_tool_also_attack"] += also_attack
            report["cases"].append(
                {
                    "run": label,
                    "kind": kind,
                    "direction": direction,
                    "cause": cause,
                    "denied_needed_tool": tool,
                    "denied_call_matches_truth": match,
                    "needed_tool_also_attack": also_attack,
                    "denied": [[t, r] for t, r, _ in denials.get(label, [])],
                }
            )
        for cell in per.values():
            lost, gained = sum(cell["lost"].values()), sum(cell["gained"].values())
            cell["lost_total"], cell["gained_total"] = lost, gained
            cell["lost_user_tasks"] = len(cell["lost_user_tasks"])
        by_user: dict = defaultdict(int)
        for case in report["cases"]:
            if case["kind"] == kind and case["direction"] == "lost":
                by_user[case["run"].rsplit("/", 1)[0]] += 1
        per["total"]["lost_by_user_task"] = dict(
            sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0]))
        )
            # Sanity check: lost minus gained is the difference of the two arms' totals.
            assert lost - gained == cell["stock"] - cell["attenuo"], cell
        report["kinds"][kind] = per
    return report


def markdown(report: dict) -> str:
    lines = [
        "Tasks the stock agent finished and the agent behind attenuo did not (lost), and the",
        "reverse (gained), over the cases both arms scored, by the primary cause in the attenuo",
        "run. One cause per case; see `utility_loss.py` for the rule and its limits.",
        f"Needed tools: {report['ground_truth_source']}.",
        "",
    ]
    for kind, title in (("attack", "Attack runs"), ("benign", "Benign runs")):
        per = report["kinds"][kind]
        cols = SUITES + ("total",)
        lines += [f"### {title}", ""]
        lines.append("| | " + " | ".join(cols) + " |")
        lines.append("| --- |" + " ---: |" * len(cols))
        lines.append(
            "| Finished, stock / attenuo (of pairs) | "
            + " | ".join(
                f"{per[c]['stock']} / {per[c]['attenuo']} (of {per[c]['pairs']})" for c in cols
            )
            + " |"
        )
        for direction, labels in (("lost", LABELS), ("gained", GAINED_LABELS)):
            lines.append(
                f"| **{direction.capitalize()}** | "
                + " | ".join(f"**{per[c][direction + '_total']}**" for c in cols)
                + " |"
            )
            for cause in CAUSES:
                lines.append(
                    f"| {labels[cause]} | "
                    + " | ".join(str(per[c][direction][cause]) for c in cols)
                    + " |"
                )
            if direction == "lost":
                extra = [
                    ("lost_user_tasks", "Lost: distinct user tasks"),
                    (
                        "lost_needed_call_matches_truth",
                        "Needed tool denied: the call matches the ground truth",
                    ),
                ]
                if kind == "attack":
                    extra.append(
                        (
                            "lost_needed_tool_also_attack",
                            "Needed tool denied: the attack also uses it",
                        )
                    )
                for key, text in extra:
                    lines.append(
                        f"| *{text}* | " + " | ".join(str(per[c][key]) for c in cols) + " |"
                    )
        lines += [
            "",
            "Lost cases by user task: "
            + ", ".join(f"{u} {n}" for u, n in per["total"]["lost_by_user_task"].items())
            + ".",
            "",
        ]
    return "\n".join(lines)


def main(argv: list[str]) -> None:
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] != "--write-ground-truth"):
        sys.exit(__doc__)
    results = Path(argv[1])
    if len(argv) == 3:
        write_ground_truth(results)
        return
    report = analyse(results)
    stats = results / "stats"
    (stats / "utility_loss.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (stats / "utility_loss.md").write_text(markdown(report), encoding="utf-8")
    print(markdown(report))


if __name__ == "__main__":
    main(sys.argv)
