#!/usr/bin/env python3
"""Check that the tracked tree is safe and current enough to be public.

Catches the things that crept in before the first public release:

- absolute paths from a developer machine or a build container;
- personal identifiers and references to the maintainer's private notes;
- the project's old name outside the files that record the rename;
- `<domain>`-style contact placeholders, beyond the known pending ones;
- files that must never be committed (exported reading guides, daily working logs under
  docs/log/, the pre-release launch checklist, anything under docs/guide/ such as the
  codebase walkthrough, the task board and milestones under docs/tasks/);
- pages under docs/ that are personal planning, listed in docs/SUMMARY.md;
- an ADR whose front matter or status line has an unknown status;
- a security review pass under docs/research/ that docs/status.md does not link.

Exits 1 on any failure. Tracked files only (`git ls-files`).

    python3 scripts/check-public-hygiene.py
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Files that may name the old project name: they record the rename itself, or are
# dated records (review passes, benchmark outputs) written before it.
OLD_NAME_OK = re.compile(
    r"^(docs/research/|docs/design/bench/|docs/design/rename-plan\.md$"
    r"|scripts/(test_)?rename\.py$|CHANGELOG\.md$|docs/release/0\.1\.0\.md$|\.gitleaks\.toml$)"
)
OLD_NAME = re.compile(r"onbehalf", re.IGNORECASE)

ABSOLUTE_PATH = re.compile(r"/home/claude\b|/tmp/claude|/root/\.|/Users/[A-Za-z][A-Za-z0-9_.-]*/|/mnt/project-files\b")
PERSONAL = re.compile(r"muditk441|onbehalf-private|Mudit[’']s|\bMudit (asked|said|chose|wants)", re.IGNORECASE)

PLACEHOLDER = re.compile(r"[a-z]+@<domain>")
# Placeholders the maintainer still has to fill in; each needs a real address first.
PLACEHOLDER_PENDING: set[str] = set()
# Pages that talk about the placeholder rather than use it.
PLACEHOLDER_MENTION_OK = re.compile(r"^docs/research/")

# Internal working documents that left the repository before it went public: the daily working
# logs, the launch checklist, the codebase walkthrough and any other page under docs/guide/
# (exported reading guides there are also gitignored), and the task board and milestones under
# docs/tasks/. The CHANGELOG and pull request descriptions are the record of a change; the
# design notes, ADRs and reference pages say what is open.
NEVER_TRACKED = re.compile(r"^(docs/guide/|docs/log/|docs/tasks/|docs/launch-checklist\.md$)")
PRIVATE_PAGES = (
    "project/research-readiness-plan.md",
    "brief/attenuo-one-page.md",
    "launch-checklist.md",
    "](log/",
    "](guide/",
    "](tasks/",
)
ADR_STATUSES = {"proposed", "accepted", "rejected", "deprecated", "superseded"}

TEXT_SUFFIXES = {
    ".md", ".toml", ".yml", ".yaml", ".py", ".sh", ".rs", ".ts", ".js", ".json",
    ".html", ".css", ".txt", ".cedar", ".cjs", ".mjs", ".svg", ".cast", ".ini", ".cfg", "",
}


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True)
    return [p for p in out.stdout.decode().split("\0") if p]


def main() -> int:
    problems = []
    warnings = []
    files = tracked()

    for rel in files:
        if NEVER_TRACKED.search(rel):
            problems.append(f"{rel}: must never be committed (working notes or an exported guide)")
            continue
        path = ROOT / rel
        if path.suffix not in TEXT_SUFFIXES or not path.is_file():
            continue
        if rel == "scripts/check-public-hygiene.py":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if ABSOLUTE_PATH.search(line):
                problems.append(f"{rel}:{n}: absolute machine path")
            if PERSONAL.search(line):
                problems.append(f"{rel}:{n}: personal identifier or private-notes reference")
            if OLD_NAME.search(line) and not OLD_NAME_OK.search(rel):
                problems.append(f"{rel}:{n}: old project name")
            if PLACEHOLDER.search(line):
                if PLACEHOLDER_MENTION_OK.search(rel):
                    pass
                elif rel in PLACEHOLDER_PENDING:
                    warnings.append(f"{rel}:{n}: contact placeholder still pending")
                else:
                    problems.append(f"{rel}:{n}: contact placeholder")

    summary = (ROOT / "docs/SUMMARY.md").read_text(encoding="utf-8")
    for page in PRIVATE_PAGES:
        if page in summary:
            problems.append(f"docs/SUMMARY.md: lists private page {page}")

    for adr in sorted((ROOT / "docs/decisions").glob("[0-9][0-9][0-9][0-9]-*.md")):
        if adr.name.startswith("0000-"):
            continue
        head = adr.read_text(encoding="utf-8").splitlines()[:6]
        status = None
        for line in head:
            m = re.match(r"^(?:-\s*)?[Ss]tatus:\s*([A-Za-z]+)", line.strip())
            if m:
                status = m.group(1).lower()
                break
        if status not in ADR_STATUSES:
            problems.append(f"docs/decisions/{adr.name}: status {status!r} not one of {sorted(ADR_STATUSES)}")

    # The README's Status section is a summary; the status page lists every review pass.
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "docs/status.md" not in readme:
        problems.append("README.md: does not link docs/status.md")
    status_page = (ROOT / "docs/status.md").read_text(encoding="utf-8")
    for review in sorted((ROOT / "docs/research").glob("security-review-*.md")):
        if f"research/{review.name}" not in status_page:
            problems.append(f"docs/status.md: does not link security review {review.name}")

    for w in warnings:
        print(f"warning: {w}")
    for p in problems:
        print(p)
    if problems:
        print(f"{len(problems)} problem(s)")
        return 1
    print(f"public hygiene: {len(files)} tracked files checked, no problems")
    return 0


if __name__ == "__main__":
    sys.exit(main())
