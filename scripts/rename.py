#!/usr/bin/env python3
"""Rename the project: every spelling of the working name, in contents and in paths.

    python3 scripts/rename.py --to <newname> [--dry-run] [--apply] [--root DIR]

Without --apply nothing is written (a dry run is the default). The name is replaced
case-aware, so one pass covers all of these:

    onbehalf   crates (onbehalf-core, onbehalf_core::), binaries, the Python package and
               its directory, the npm scope (@onbehalf/sdk), Docker image paths, URNs
               (urn:onbehalf:), signing contexts (onbehalf-checkpoint-v1, onbehalf-ou-v2),
               headers (x-onbehalf-*), JSON-RPC prefixes ("onbehalf: "), metric names, the
               GitHub slug 7Mudit/onbehalf, the mdBook title, file and directory names
    Onbehalf   OnbehalfClient, OnbehalfError, prose
    ONBEHALF   ONBEHALF_ADMIN_TOKEN and the other env vars

Prose "on behalf of" (with a space) is a different phrase and is never touched.

Policy (see docs/design/rename-plan.md):
  * everything is rewritten except the files below;
  * docs/log/** and docs/research/** are history: contents are kept, a one-line note is
    added under the title, and only Markdown link targets are rewritten so links to
    renamed files keep working;
  * lockfiles are not edited (regenerate them; the commands are printed);
  * this script, its test and docs/design/rename-plan.md keep the old name by design;
  * .git, target, node_modules, dist, .bin, .claude, book and caches are skipped, as is
    everything git ignores;
  * --keep-legacy-contexts leaves the signing contexts, the audit export format id and
    the urn:onbehalf: prefix alone (a stopgap for deployments that already issued tokens;
    the verifiers must then accept both, see the plan).
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

OLD = "onbehalf"
SKIP_DIRS = {".git", "target", "node_modules", "dist", ".bin", ".claude", "book",
             "__pycache__", ".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
LOCKFILES = {
    "Cargo.lock": "cargo update -w   # or: cargo generate-lockfile",
    "package-lock.json": "npm install --package-lock-only",
    "npm-shrinkwrap.json": "npm install --package-lock-only",
    "yarn.lock": "yarn install",
    "pnpm-lock.yaml": "pnpm install --lockfile-only",
    "uv.lock": "uv lock",
    "poetry.lock": "poetry lock",
    "Pipfile.lock": "pipenv lock",
    "pdm.lock": "pdm lock",
}
# Keep the old name, by design: tooling and the plan describe the old strings.
SELF_EXCLUDED = {"scripts/rename.py", "scripts/test_rename.py", "docs/design/rename-plan.md"}
HISTORICAL = ("docs/log/", "docs/research/")
LEGACY = r"onbehalf-checkpoint-v\d+|onbehalf-ou-(?:v\d+)?|onbehalf-audit-export[-/]\w+|urn:onbehalf:"
NOTE_MARK = "<!-- renamed-note -->"
CATEGORIES = [
    ("env var", r"ONBEHALF_"),
    ("signing context / format id", r"onbehalf-(checkpoint|ou|audit-export)"),
    ("URN", r"urn:onbehalf:"),
    ("HTTP header", r"x-onbehalf-"),
    ("GitHub slug / URL", r"7mudit/onbehalf|onbehalf\.(example|test)"),
    ("crate / module path", r"onbehalf[-_]"),
    ("message prefix", r"onbehalf: "),
    ("CamelCase type", r"Onbehalf[A-Z]"),
]


def case_like(word, new):
    if word.isupper():
        return new.upper()
    if word[0].isupper():
        return new[0].upper() + new[1:]
    return new


def make_sub(new, keep_legacy):
    pat = re.compile((f"(?P<keep>{LEGACY})|" if keep_legacy else "") + "(?P<hit>(?i:" + OLD + "))")

    def sub(text, counter=None):
        def r(m):
            if m.groupdict().get("keep"):
                if counter is not None:
                    counter["kept legacy"] += 1
                return m.group(0)
            word = m.group("hit")
            if counter is not None:
                counter[word if word in (OLD, OLD.upper(), OLD.capitalize()) else "mixed"] += 1
                ctx = text[max(0, m.start() - 8): m.end() + 12]
                for label, rx in CATEGORIES:
                    if re.search(rx, ctx, 0 if label == "env var" else re.I):
                        counter["cat:" + label] += 1
                        break
            return case_like(word, new)
        return pat.sub(r, text)
    return sub


def list_files(root):
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
                             capture_output=True, check=True).stdout
        files = [f for f in out.decode().split("\0") if f and (root / f).is_file()]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for d, dirs, fs in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            files += [str((Path(d) / f).relative_to(root)) for f in fs]
    return sorted(f for f in files if not set(Path(f).parts[:-1]) & SKIP_DIRS)


def historical(rel):
    return rel.startswith(HISTORICAL)


def add_note(text, new, today):
    if NOTE_MARK in text:
        return text
    note = [NOTE_MARK,
            f"> Note ({today}): this project was renamed from `{OLD}` to `{new}`. "
            "This historical document keeps the old name."]
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("# "):
            return "\n".join(lines[: i + 1] + [""] + note + lines[i + 1:])
    return "\n".join(note) + "\n\n" + text


def fix_link_targets(text, sub):
    return re.sub(r"(\]\()([^)]*)(\))", lambda m: m.group(1) + sub(m.group(2)) + m.group(3), text)


CHANGELOG_ENTRY = ("- BREAKING: the project was renamed from `{old}` to `{new}`. Crate, binary, package and "
                   "image names, environment variables (`{NEW}_*`), the `x-{new}-decision-id` header, "
                   "the `{new}: ` JSON-RPC message prefix and the signing contexts changed with it; "
                   "see `docs/design/rename-plan.md` for the compatibility notes.\n")


def add_changelog(text, new):
    if f"renamed from `{OLD}`" in text:
        return text
    entry = CHANGELOG_ENTRY.format(old=OLD, new=new, NEW=new.upper())
    m = re.search(r"^## \[Unreleased\][^\n]*\n", text, re.M)
    if not m:
        return text
    nxt = re.search(r"^## \[", text[m.end():], re.M)
    end = m.end() + nxt.start() if nxt else len(text)
    ch = re.search(r"^### Changed[^\n]*\n\n?", text[m.end():end], re.M)
    if ch:
        p = m.end() + ch.end()
        return text[:p] + entry + text[p:]
    return text[:m.end()] + "\n### Changed\n\n" + entry + text[m.end():]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--to", required=True, help="new name, lowercase, e.g. creance")
    ap.add_argument("--dry-run", action="store_true", help="report only (the default)")
    ap.add_argument("--apply", action="store_true", help="write the changes")
    ap.add_argument("--keep-legacy-contexts", action="store_true",
                    help="leave signing contexts, export format id and urn: prefix unchanged")
    ap.add_argument("--force", action="store_true", help="apply even if the git tree is dirty")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    a = ap.parse_args()
    if a.apply and a.dry_run:
        ap.error("--apply and --dry-run are exclusive")
    new = a.to
    if not re.fullmatch(r"[a-z][a-z0-9]{1,30}", new):
        ap.error("--to must be lowercase letters and digits (valid as a crate, npm, PyPI and Python name)")
    if new == OLD:
        ap.error("the new name equals the old one")
    root = Path(a.root).resolve()
    apply = a.apply
    if apply and not a.force:
        st = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True)
        if st.returncode == 0 and st.stdout.strip():
            sys.exit("refusing to apply on a dirty git tree (commit first, or pass --force)")

    today = datetime.date.today().isoformat()
    sub = make_sub(new, a.keep_legacy_contexts)
    counts = Counter()
    changed, noted, binary, locks, untouched = [], [], [], [], []
    files = list_files(root)

    for rel in files:
        p = root / rel
        if p.name in LOCKFILES:
            if OLD in p.read_bytes().decode("utf-8", "replace").lower():
                locks.append(rel)
            continue
        if rel in SELF_EXCLUDED:
            untouched.append(rel + "  (keeps the old name by design)")
            continue
        raw = p.read_bytes()
        try:
            if b"\0" in raw:
                raise UnicodeDecodeError("utf-8", b"", 0, 1, "binary")
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            if OLD.encode() in raw.lower():
                binary.append(rel)
            continue
        if historical(rel):
            out = add_note(fix_link_targets(text, sub), new, today)
            if OLD in text.lower():
                untouched.append(rel + "  (text kept, note added)")
            if out != text:
                noted.append(rel)
                if apply:
                    p.write_bytes(out.encode())
            continue
        c = Counter()
        out = sub(text, c)
        if rel == "CHANGELOG.md":
            out = add_changelog(out, new)
        if out != text:
            counts.update(c)
            changed.append(rel)
            if apply:
                p.write_bytes(out.encode())

    # paths: directories and files whose names contain the old name, deepest first
    paths = set()
    for rel in files:
        parts = Path(rel).parts
        for i in range(1, len(parts) + 1):
            if OLD in parts[i - 1].lower():
                paths.add(Path(*parts[:i]))
    renames = []
    for old in sorted(paths, key=lambda q: (-len(q.parts), str(q))):
        if str(old) in SELF_EXCLUDED:
            continue
        tgt = old.with_name(sub(old.name))
        renames.append((old, tgt))
        if apply:
            if (root / tgt).exists():
                sys.exit(f"cannot rename {old}: {tgt} exists")
            (root / old).rename(root / tgt)

    total = sum(v for k, v in counts.items() if not k.startswith(("cat:", "kept")))
    print(f"{'APPLIED' if apply else 'DRY RUN'}: {OLD} -> {new}   (root {root})")
    print(f"files scanned:         {len(files)}")
    print(f"paths renamed:         {len(renames)} (directories and files)")
    for o, t in sorted(renames, key=lambda x: str(x[0])):
        print(f"    {o} -> {t}")
    print(f"files rewritten:       {len(changed)}")
    print(f"occurrences replaced:  {total}  "
          f"({OLD}: {counts[OLD]}, {OLD.capitalize()}: {counts[OLD.capitalize()]}, "
          f"{OLD.upper()}: {counts[OLD.upper()]}, other case: {counts['mixed']})")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        if k.startswith("cat:"):
            print(f"    {k[4:]:30} {v}")
    if counts["kept legacy"]:
        print(f"legacy strings kept (--keep-legacy-contexts): {counts['kept legacy']}")
    print(f"historical files given a note or link-target fixes: {len(noted)}")
    print("deliberately not touched:")
    for u in untouched:
        print(f"    {u}")
    for b in binary:
        print(f"    {b}  (binary / not UTF-8, mentions the name)")
    print(f"    skipped dirs: {', '.join(sorted(SKIP_DIRS))} and anything git ignores")
    if locks:
        print("lockfiles NOT edited, regenerate after the rename:")
        for lk in locks:
            d = str(Path(lk).parent)
            print(f"    {lk:45} (cd {d} && {LOCKFILES[Path(lk).name]})")
    print("then: cargo fmt --all (import order changes), full test run, update launch drafts, "
          "work through the checklist in docs/design/rename-plan.md")
    if apply:
        left = [r for r in files if (root / r).exists() and not historical(r) and r not in SELF_EXCLUDED
                and Path(r).name not in LOCKFILES
                and OLD in (root / r).read_bytes().decode("utf-8", "ignore").lower()]
        print(f"files still mentioning the old name outside the policy: {len(left)}")
        for r in left[:20]:
            print(f"    {r}")


if __name__ == "__main__":
    main()
