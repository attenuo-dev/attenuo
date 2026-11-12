#!/usr/bin/env python3
"""Check relative links in the repository's Markdown files.

Verifies that every relative link target exists and, for links into a Markdown
file, that the #anchor matches a heading. External (http/https/mailto) links
are not fetched.

A page that is in the mdBook site (listed in the book's SUMMARY.md) may not
link relatively to a file outside the book's source directory (`src` in
book.toml, `docs/`): the site only contains that directory, so such a link
works on GitHub but is a 404 on the site. Link to those files with a full
GitHub URL instead (https://github.com/attenuo-dev/attenuo/blob/main/<path>,
or tree/main/ for a directory). Pages that are not in the book keep relative
links.

Exits 1 if any link is broken.

    python3 scripts/check-links.py [--root DIR] [paths...]     # default: whole repo
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GITHUB = "https://github.com/attenuo-dev/attenuo"
# Book pages that still link out of the book. They are reported as warnings
# until their owners convert them; remove an entry once its page is clean.
LEAVES_BOOK_PENDING: set[str] = set()
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


def book_src() -> Path:
    """The book's source directory: `src` in book.toml, `docs` by default."""
    src = "src"
    toml = ROOT / "book.toml"
    if toml.exists():
        m = re.search(r'^\s*src\s*=\s*"([^"]*)"', toml.read_text(encoding="utf-8"), re.M)
        if m:
            src = m.group(1)
    return (ROOT / src).resolve()


def book_pages(src: Path) -> set:
    """The pages mdBook renders: every file SUMMARY.md links to."""
    summary = src / "SUMMARY.md"
    if not summary.exists():
        return set()
    pages = set()
    for m in LINK.finditer(summary.read_text(encoding="utf-8")):
        target = m.group(1).partition("#")[0]
        if target and not re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            pages.add((src / target).resolve())
    return pages


def github_url(dest: Path, frag: str) -> str:
    kind = "tree" if dest.is_dir() else "blob"
    url = f"{GITHUB}/{kind}/main/{dest.relative_to(ROOT).as_posix()}"
    return f"{url}#{frag}" if frag else url


def main() -> int:
    global ROOT
    args = sys.argv[1:]
    if args[:1] == ["--root"]:
        ROOT = Path(args[1]).resolve()
        args = args[2:]
    src = book_src()
    in_book = book_pages(src)
    bad = 0
    for md in sorted(md_files(args)):
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
                    continue
                dest = dest.resolve()
                if md in in_book and dest != src and src not in dest.parents:
                    msg = (f"{rel}:{no}: leaves the book: {target} is not under "
                           f"{src.relative_to(ROOT).as_posix()}/ on the site; "
                           f"use {github_url(dest, frag)}")
                    if rel.as_posix() in LEAVES_BOOK_PENDING:
                        print(f"warning: {msg}")
                    else:
                        print(msg)
                        bad += 1
                    continue
                if frag and dest.suffix == ".md" and frag.lower() not in anchors(dest):
                    print(f"{rel}:{no}: missing anchor: {target}")
                    bad += 1
    print(f"{bad} broken link(s)" if bad else "all relative links ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
