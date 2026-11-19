#!/usr/bin/env python3
"""Compare planner grants with the oracle grants and the ground truth, per suite.

Reads the ground truth, so it runs only after the planner's grants are frozen, and its output
never goes to the planner. For each user task, against the oracle grant that `replay.py`'s
`grant_for` builds from the same task's ground truth:

  tools           tools granted (planner, oracle)
  over_grant      tools the planner granted that the ground truth never calls
  under_grant     tools the ground truth calls that the planner did not grant (costs utility)
  write_pins      constrained arguments of write tools (planner, oracle)
  read_pins       constrained arguments of read tools (planner, oracle)
  pins_disagree   planner constraints on a write tool that a ground-truth call of that tool
                  does not meet (its value differs, or it leaves the argument out)
  calls_outside   ground-truth calls that no capability of the planner's grant permits

    PYTHONPATH=sdk/python/src python3 evaluation/agentdojo/grant_quality.py GRANTS_DIR
        [--suites ...] [--md OUT] [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import planner_grants
import replay
from agentdojo.task_suite.load_suites import get_suite

METRICS = (
    "tasks",
    "tools_planner",
    "tools_oracle",
    "over_grant",
    "under_grant",
    "write_pins_planner",
    "write_pins_oracle",
    "read_pins_planner",
    "read_pins_oracle",
    "pins_disagree",
    "gt_calls",
    "calls_outside",
)


def _same(a, b) -> bool:
    """JSON equality as the server's value_eq: numbers by value, a boolean never a number,
    lists in order."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def satisfied(constraint: dict, value) -> bool:
    """Does a value meet a constraint in the grant file's wire form?"""
    op, want = constraint["op"], constraint["value"]
    if op == "equals":
        return _same(value, want)
    if op == "one_of":
        return any(_same(value, w) for w in want)
    if op == "prefix":
        return isinstance(value, str) and value.startswith(want)
    if op == "range":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if isinstance(value, float) and not value.is_integer():
            return False
        return want.get("min", value) <= value <= want.get("max", value)
    raise ValueError(f"unknown op {op!r}")


def permits(cap: dict, tool: str, args: dict) -> bool:
    if cap["tool"] != tool:
        return False
    return all(a in args and satisfied(c, args[a]) for a, c in cap.get("constraints", {}).items())


def oracle_entry(truth) -> dict:
    """The oracle grant (replay.grant_for) in the grant file's form."""
    caps = []
    for cap in replay.grant_for(truth):
        caps.append(
            {"tool": cap.tool, "constraints": {k: c.to_json() for k, c in cap.constraints.items()}}
        )
    return {"capabilities": caps}


def task_quality(planner: dict, oracle: dict, truth) -> dict:
    p_tools = {c["tool"] for c in planner["capabilities"]}
    o_tools = {c["tool"] for c in oracle["capabilities"]}
    gt_tools = {c.function for c in truth}

    def pins(entry, read):
        return sum(
            len(c.get("constraints", {}))
            for c in entry["capabilities"]
            if replay.is_read(c["tool"]) == read
        )

    disagree = []
    for cap in planner["capabilities"]:
        if replay.is_read(cap["tool"]):
            continue
        for arg, c in cap.get("constraints", {}).items():
            calls = [dict(t.args) for t in truth if t.function == cap["tool"]]
            if any(arg not in a or not satisfied(c, a[arg]) for a in calls):
                disagree.append([cap["tool"], arg])
    outside = [
        t.function
        for t in truth
        if not any(permits(c, t.function, dict(t.args)) for c in planner["capabilities"])
    ]
    return {
        "tools_planner": len(p_tools),
        "tools_oracle": len(o_tools),
        "over_grant": sorted(p_tools - gt_tools),
        "under_grant": sorted(gt_tools - p_tools),
        "write_pins_planner": pins(planner, False),
        "write_pins_oracle": pins(oracle, False),
        "read_pins_planner": pins(planner, True),
        "read_pins_oracle": pins(oracle, True),
        "pins_disagree": disagree,
        "gt_calls": len(truth),
        "calls_outside": outside,
    }


def suite_quality(name: str, grants: dict) -> dict:
    replay.SUITE = name
    suite = get_suite(replay.VERSION, name)
    tasks, totals = {}, dict.fromkeys(METRICS, 0)
    for user in replay.by_id(suite.user_tasks):
        pre = suite.load_and_inject_default_environment({})
        truth = user.ground_truth(pre)
        q = task_quality(grants[user.ID], oracle_entry(truth), truth)
        tasks[user.ID] = q
        totals["tasks"] += 1
        for k in METRICS[1:]:
            v = q[k]
            totals[k] += len(v) if isinstance(v, list) else v
    return {"totals": totals, "tasks": tasks}


def markdown(by_suite: dict) -> str:
    head = "| Suite | " + " | ".join(METRICS) + " |\n"
    head += "| --- |" + " ---: |" * len(METRICS) + "\n"
    rows = []
    overall = dict.fromkeys(METRICS, 0)
    for name, q in by_suite.items():
        rows.append(f"| {name} | " + " | ".join(str(q["totals"][k]) for k in METRICS) + " |")
        for k in METRICS:
            overall[k] += q["totals"][k]
    rows.append("| all | " + " | ".join(str(overall[k]) for k in METRICS) + " |")
    return head + "\n".join(rows) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("grants", type=Path)
    parser.add_argument("--suites", nargs="+", default=list(replay.SUITES), choices=replay.SUITES)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    grants, problems = planner_grants.load_dir(args.grants, args.suites)
    if problems:
        raise SystemExit("invalid grants:\n  - " + "\n  - ".join(problems))
    by_suite = {name: suite_quality(name, grants[name]) for name in args.suites}
    table = markdown(by_suite)
    print(table, end="")
    if args.md:
        args.md.write_text(table)
    if args.json:
        args.json.write_text(json.dumps(by_suite, indent=2) + "\n")


if __name__ == "__main__":
    main()
