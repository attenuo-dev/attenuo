"""Compare the per-arm result rows of two injection-suite result files.

    python3 evaluation/injection-suite/compare_results.py BASELINE.md NEW.md

The rows compared are the table rows that start with ``| attenuo`` or ``| Suite policy``
(the "Arms compared" tables), each tagged with the split heading it sits under. Prints a
unified diff of the two sets of rows and exits 1 if any row differs, else prints a
REPRODUCED line and exits 0. Exit 2 means a file has no such rows (wrong file, or the
report format changed).

The "Problems" lists (what run.py reports and exits 1 for) are compared the same way: a
problem the baseline also has is a known one and is only counted, a new or a missing one
is a difference.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

ROW_PREFIXES = ("| attenuo", "| Suite policy")


def arm_rows(text: str) -> list[str]:
    """The per-arm rows of a result .md, in file order, each prefixed with its split heading."""
    rows: list[str] = []
    split = ""
    for line in text.splitlines():
        if line.startswith("## "):
            split = line[3:].strip()
        elif line.startswith(ROW_PREFIXES):
            rows.append(f"[{split}] {line.rstrip()}")
    return rows


def problem_lines(text: str) -> list[str]:
    """The bullet lines of every "### Problems" section, each prefixed with its split heading."""
    out: list[str] = []
    split, inside = "", False
    for line in text.splitlines():
        if line.startswith("## "):
            split, inside = line[3:].strip(), False
        elif line.startswith("### "):
            inside = line.strip() == "### Problems"
        elif inside and line.startswith("- "):
            out.append(f"[{split}] problem: {line[2:].rstrip()}")
    return out


def compare(baseline: Path, new: Path, label: str | None = None) -> tuple[int, str]:
    """Return (exit code, text to print). ``label`` names the baseline in the REPRODUCED line."""
    old_text, new_text = baseline.read_text(), new.read_text()
    old_rows, new_rows = arm_rows(old_text), arm_rows(new_text)
    for path, rows in ((baseline, old_rows), (new, new_rows)):
        if not rows:
            return 2, f"no arm rows found in {path}"
    n_rows = len(new_rows)
    old_probs, new_probs = problem_lines(old_text), problem_lines(new_text)
    old_rows, new_rows = old_rows + old_probs, new_rows + new_probs
    if old_rows == new_rows:
        known = (
            f"{len(new_probs)} problem(s) reported by run.py, the same as in the baseline\n"
            if new_probs
            else ""
        )
        return 0, f"{known}REPRODUCED: {n_rows} arm rows identical to {label or baseline}"
    diff = list(
        difflib.unified_diff(
            old_rows, new_rows, fromfile=str(baseline), tofile=str(new), lineterm=""
        )
    )
    body = diff[2:]  # without the ---/+++ file header
    gone = sum(1 for d in body if d.startswith("-"))
    added = sum(1 for d in body if d.startswith("+"))
    summary = (
        f"DIFFERS from {baseline}: {gone} line(s) only in the baseline, {added} only in the new run"
    )
    return 1, "\n".join([*diff, summary])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("baseline", type=Path, help="the committed result .md (the reference)")
    ap.add_argument("new", type=Path, help="the result .md of the run to check")
    ap.add_argument("--label", help="name for the baseline in the REPRODUCED line")
    a = ap.parse_args(argv)
    code, out = compare(a.baseline, a.new, a.label)
    print(out, file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
