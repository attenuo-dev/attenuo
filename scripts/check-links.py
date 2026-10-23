#!/usr/bin/env python3
"""Check relative links in the repository's Markdown files.

Verifies that every relative link target exists and, for links into a Markdown
file, that the #anchor matches a heading. External (http/https/mailto) links
are not fetched. Exits 1 if any link is broken.

    python3 scripts/check-links.py [paths...]     # default: whole repo
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "target", "node_modules", ".obsidian", ".claude"}
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")
_cache = {}


def slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    h = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading.strip().lower())
    h = re.sub(r"[`*_]", "", h)
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(path: Path) -> set:
    if path not in _cache:
        out, seen, fence = set(), {}, False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if FENCE.match(line):
                fence = not fence
                continue
            m = None if fence else re.match(r"^#{1,6}\s+(.*?)\s*#*$", line)
            if m:
                s = slug(m.group(1))
                n = seen.get(s, 0)
                seen[s] = n + 1
                out.add(s if n == 0 else f"{s}-{n}")
        _cache[path] = out
    return _cache[path]


def md_files(args):
    if args:
        return [Path(a).resolve() for a in args]
    return [p for p in ROOT.rglob("*.md")
            if not SKIP_DIRS & set(p.relative_to(ROOT).parts)]


def main() -> int:
    bad = 0
    for md in sorted(md_files(sys.argv[1:])):
        fence = False
        rel = md.relative_to(ROOT)
        for no, line in enumerate(md.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if FENCE.match(line):
                fence = not fence
                continue
            if fence:
                continue
            line = re.sub(r"`[^`]*`", "", line)  # ignore inline code
            for m in LINK.finditer(line):
                target = m.group(1)
                if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith("//"):
                    continue
                file_part, _, frag = target.partition("#")
                dest = md if not file_part else (md.parent / file_part.split("?")[0])
                if not dest.exists():
                    print(f"{rel}:{no}: missing file: {target}")
                    bad += 1
                elif frag and dest.suffix == ".md" and frag.lower() not in anchors(dest):
                    print(f"{rel}:{no}: missing anchor: {target}")
                    bad += 1
    print(f"{bad} broken link(s)" if bad else "all relative links ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
