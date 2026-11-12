#!/usr/bin/env python3
"""Paired statistics for two arms of an AgentDojo replay. Standard library only.

Reads `rows.jsonl` from a replay results directory. For each comparison A vs B:

- attacks landed: the (suite, user task, injection task) pairs both arms ran. Each arm's count
  with a Wilson 95% interval; the discordant pairs (landed in A only, in B only); an exact
  two-sided McNemar test on them; and the paired difference in rate, A minus B, with a 95%
  cluster bootstrap interval that resamples user tasks (all pairs of a user task move
  together), stratified by suite, 10,000 resamples from a fixed seed, percentile method;
- benign utility kept: the same per user task (one outcome per user task, so the bootstrap
  resamples single outcomes, stratified by suite).

    python3 evaluation/agentdojo/stats.py RESULTS_DIR [--compare A:B ...] [--md OUT] [--json OUT]

With no `--compare`, DEFAULT_COMPARISONS are run where both arms are in the results.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

Z95 = 1.959963984540054
SEED = 20261112
RESAMPLES = 10_000
DEFAULT_COMPARISONS = (
    ("planner", "suite"),
    ("planner", "grants"),
    ("planner_only", "grants_only"),
    ("planner_nocontact", "grants_nocontact"),
)


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials, or None when n is 0."""
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def mcnemar_exact(b: int, c: int) -> float:
    """Exact two-sided McNemar p-value: twice the binomial(b + c, 1/2) tail at min(b, c),
    capped at 1. With no discordant pair it is 1."""
    n = b + c
    if n == 0:
        return 1.0
    tail = Fraction(sum(math.comb(n, i) for i in range(min(b, c) + 1)), 2**n)
    return float(min(Fraction(1), 2 * tail))


def quantile(sorted_values: list[float], q: float) -> float:
    """Linear interpolation between order statistics (type 7, as numpy's default)."""
    if not sorted_values:
        raise ValueError("no values")
    pos = (len(sorted_values) - 1) * q
    lo = math.floor(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def cluster_bootstrap(
    clusters: dict[tuple, list[tuple[int, int]]],
    resamples: int = RESAMPLES,
    seed: int = SEED,
) -> tuple[float, float] | None:
    """95% percentile interval of the paired rate difference mean(a - b), resampling clusters
    with replacement within each stratum. `clusters` maps (stratum, cluster id) to the cluster's
    (a, b) outcomes, each 0 or 1. None when there are no outcomes."""
    strata: dict = defaultdict(list)
    for (stratum, _), outcomes in sorted(clusters.items(), key=lambda kv: repr(kv[0])):
        strata[stratum].append((sum(a - b for a, b in outcomes), len(outcomes)))
    if not any(n for s in strata.values() for _, n in s):
        return None
    rng = random.Random(seed)
    groups = [strata[k] for k in sorted(strata, key=repr)]
    diffs = []
    for _ in range(resamples):
        total, count = 0, 0
        for group in groups:
            for _ in range(len(group)):
                d, n = group[rng.randrange(len(group))]
                total += d
                count += n
        diffs.append(total / count if count else 0.0)
    diffs.sort()
    return (quantile(diffs, 0.025), quantile(diffs, 0.975))


def compare(
    outcomes_a: dict[tuple, int],
    outcomes_b: dict[tuple, int],
    resamples: int = RESAMPLES,
    seed: int = SEED,
) -> dict:
    """Paired comparison on the keys both arms have. A key is (suite, user, ...): the cluster
    is (suite, user) and the stratum the suite."""
    keys = sorted(set(outcomes_a) & set(outcomes_b), key=repr)
    n = len(keys)
    a = sum(outcomes_a[k] for k in keys)
    b = sum(outcomes_b[k] for k in keys)
    only_a = sum(1 for k in keys if outcomes_a[k] and not outcomes_b[k])
    only_b = sum(1 for k in keys if outcomes_b[k] and not outcomes_a[k])
    both = sum(1 for k in keys if outcomes_a[k] and outcomes_b[k])
    clusters: dict = defaultdict(list)
    for k in keys:
        clusters[(k[0], (k[0], k[1]))].append((outcomes_a[k], outcomes_b[k]))
    return {
        "n": n,
        "unpaired_a": len(set(outcomes_a) - set(keys)),
        "unpaired_b": len(set(outcomes_b) - set(keys)),
        "clusters": len(clusters),
        "a": a,
        "b": b,
        "a_rate": a / n if n else None,
        "b_rate": b / n if n else None,
        "a_wilson95": wilson(a, n),
        "b_wilson95": wilson(b, n),
        "both": both,
        "only_a": only_a,
        "only_b": only_b,
        "neither": n - both - only_a - only_b,
        "mcnemar_p": mcnemar_exact(only_a, only_b),
        "diff": (a - b) / n if n else None,
        "diff_ci95": cluster_bootstrap(clusters, resamples, seed),
        "bootstrap": {"resamples": resamples, "seed": seed, "unit": "user task", "by": "suite"},
    }


def load(results: Path) -> tuple[dict, dict]:
    """`(landed, utility)`: by arm, {(suite, user, attack): 0/1} and {(suite, user): 0/1}."""
    landed: dict = defaultdict(dict)
    utility: dict = defaultdict(dict)
    with (results / "rows.jsonl").open() as f:
        for line in f:
            row = json.loads(line)
            arm, suite, user = row["arm"], row["suite"], row["user"]
            if row.get("attack") is None:
                utility[arm][(suite, user)] = int(bool(row["utility"]))
            else:
                landed[arm][(suite, user, row["attack"])] = int(bool(row["landed"]))
    return landed, utility


def _pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def _ci(ci) -> str:
    return "n/a" if ci is None else f"[{100 * ci[0]:.1f}, {100 * ci[1]:.1f}]"


def _p(p: float) -> str:
    return f"{p:.3g}" if p >= 0.001 else "<0.001"


def markdown(results: list[dict]) -> str:
    head = (
        "| Metric | A | B | n | A count (Wilson 95%) | B count (Wilson 95%) | A only | B only "
        "| McNemar p | A - B (bootstrap 95%) |\n"
        "| --- | --- | --- | ---: | --- | --- | ---: | ---: | ---: | --- |\n"
    )
    lines = []
    for r in results:
        s = r["stats"]
        lines.append(
            f"| {r['metric']} | {r['a']} | {r['b']} | {s['n']} "
            f"| {s['a']}/{s['n']} {_ci(s['a_wilson95'])} "
            f"| {s['b']}/{s['n']} {_ci(s['b_wilson95'])} "
            f"| {s['only_a']} | {s['only_b']} | {_p(s['mcnemar_p'])} "
            f"| {_pct(s['diff'])} {_ci(s['diff_ci95'])} |"
        )
    return head + "\n".join(lines) + "\n"


def run(results: Path, comparisons, resamples=RESAMPLES, seed=SEED) -> tuple[list, list]:
    landed, utility = load(results)
    out, skipped = [], []
    for a, b in comparisons:
        if a not in utility or b not in utility:
            skipped.append(f"{a} vs {b}: arm not in results")
            continue
        out.append(
            {
                "metric": "attacks landed",
                "a": a,
                "b": b,
                "stats": compare(landed[a], landed[b], resamples, seed),
            }
        )
        out.append(
            {
                "metric": "utility kept",
                "a": a,
                "b": b,
                "stats": compare(utility[a], utility[b], resamples, seed),
            }
        )
    return out, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--compare", nargs="+", metavar="A:B")
    parser.add_argument("--resamples", type=int, default=RESAMPLES)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    comparisons = (
        [tuple(c.split(":", 1)) for c in args.compare] if args.compare else DEFAULT_COMPARISONS
    )
    out, skipped = run(args.results, comparisons, args.resamples, args.seed)
    table = markdown(out)
    print(table, end="")
    for s in skipped:
        print(f"skipped: {s}")
    if args.md:
        args.md.write_text(table)
    if args.json:
        args.json.write_text(json.dumps({"comparisons": out, "skipped": skipped}, indent=2) + "\n")


if __name__ == "__main__":
    main()
