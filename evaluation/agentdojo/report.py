#!/usr/bin/env python3
"""Summarise a pilot.py output directory as JSON: per suite and per injection task.

Reads each run's log rather than what the runner returned. AgentDojo scores a run that failed on
a server error as utility false and security true, which would count an outage as a successful
attack, so a run with an error in its log is counted apart and left out of the rates.

    python evaluation/agentdojo/report.py DIR
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def number(task_id: str) -> int:
    return int(task_id.rsplit("_", 1)[1])


def main(out: Path) -> None:
    usage = defaultdict(lambda: dict(turns=0, input=0, output=0, thinking=0, dollars=0.0,
                                     stops=Counter(), longest_prompt=0))
    for path in out.glob("usage-*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            bucket = usage[row["task"].split("/", 1)[0]]
            bucket["turns"] += 1
            bucket["input"] += row["input_tokens"]
            bucket["output"] += row["output_tokens"]
            bucket["thinking"] += row["thinking_tokens"] or 0
            bucket["dollars"] += row["dollars"]
            bucket["stops"][row["stop_reason"]] += 1
            bucket["longest_prompt"] = max(bucket["longest_prompt"], row["input_tokens"])

    suites = defaultdict(lambda: dict(benign=[0, 0], attacked=[0, 0], landed=0, errors=[],
                                      by_injection=defaultdict(lambda: [0, 0])))
    for path in (out / "logs").rglob("*.json"):
        log = json.loads(path.read_text(encoding="utf-8"))
        # logs/<pipeline>/<suite>/<user task>/<attack or none>/<injection or none>.json
        suite_name, user_task, attack, injection = path.parts[-4:-1] + (path.stem,)
        suite = suites[suite_name]
        if log.get("error"):
            suite["errors"].append(f"{user_task}/{injection}")
            continue
        if attack == "none":
            suite["benign"][0] += bool(log["utility"])
            suite["benign"][1] += 1
        else:
            suite["attacked"][0] += bool(log["utility"])
            suite["attacked"][1] += 1
            suite["landed"] += bool(log["security"])
            suite["by_injection"][injection][0] += bool(log["security"])
            suite["by_injection"][injection][1] += 1

    report = {}
    for name, suite in sorted(suites.items()):
        spend = usage[name]
        report[name] = {
            "benign_utility": suite["benign"],
            "utility_under_attack": suite["attacked"],
            "attack_success": [suite["landed"], suite["attacked"][1]],
            "by_injection": {k: suite["by_injection"][k]
                             for k in sorted(suite["by_injection"], key=number)},
            "errors": suite["errors"],
            **{k: (dict(v) if isinstance(v, Counter) else v) for k, v in spend.items()},
        }
    report["total_dollars"] = sum(v["dollars"] for v in usage.values())
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
