#!/usr/bin/env python3
"""Turn the per-run logs of two live AgentDojo arms into `rows.jsonl` for `stats.py`.

A live run (`pilot.py` for the stock agent, `enforced.py` for the agent behind attenuo) leaves one
AgentDojo log per run. This reads those logs and writes one row per scored run, in the shape
`stats.py` reads: arm, suite, user, attack, and `utility` (benign runs) or `landed` plus
`utility` (attack runs). In an AgentDojo log `security` true means the injected goal was reached.

A run with an error in its log, or with a null score, is not a success and not a failure: it is
left out of the rows and counted in the summary printed at the end.

    python3 evaluation/agentdojo/live_rows.py OUT ARM=LOGS_DIR [ARM=LOGS_DIR ...]

`LOGS_DIR` is searched recursively for `*.json`; several directories may share one arm name.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def rows_of(arm: str, logs: Path, counts: Counter) -> list[dict]:
    rows = []
    for path in sorted(logs.rglob("*.json")):
        log = json.loads(path.read_text(encoding="utf-8"))
        if "user_task_id" not in log:
            continue
        attack = log.get("injection_task_id")
        kind = "attack" if attack else "benign"
        if (
            log.get("error")
            or log.get("utility") is None
            or (attack and log.get("security") is None)
        ):
            counts[(arm, log["suite_name"], kind, "errored")] += 1
            continue
        counts[(arm, log["suite_name"], kind, "scored")] += 1
        row = {
            "arm": arm,
            "suite": log["suite_name"],
            "user": log["user_task_id"],
            "attack": attack,
            "utility": bool(log["utility"]),
        }
        if attack:
            row["landed"] = bool(log["security"])
        rows.append(row)
    return rows


def main(argv: list[str]) -> None:
    if len(argv) < 3 or any("=" not in a for a in argv[2:]):
        sys.exit(__doc__)
    out = Path(argv[1])
    counts: Counter = Counter()
    rows: list[dict] = []
    for spec in argv[2:]:
        arm, _, logs = spec.partition("=")
        rows += rows_of(arm, Path(logs), counts)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "rows.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    summary: dict = {}
    for (arm, suite, kind, state), n in sorted(counts.items()):
        summary.setdefault(arm, {}).setdefault(suite, {}).setdefault(kind, {})[state] = n
    for row in rows:
        cell = summary[row["arm"]][row["suite"]]["attack" if row["attack"] else "benign"]
        cell["utility"] = cell.get("utility", 0) + row["utility"]
        if row["attack"]:
            cell["landed"] = cell.get("landed", 0) + row["landed"]
            per = cell.setdefault("by_attack", {}).setdefault(
                row["attack"], {"scored": 0, "landed": 0}
            )
            per["scored"] += 1
            per["landed"] += row["landed"]
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv)
