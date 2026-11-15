"""Every public name of the package is listed in the README.

``sdk/python/README.md`` has a section "Everything the package exports" with one table row per
name of ``attenuo.__all__``. These tests fail when a name is exported without a row there, and
when an exported class gains a public method that the README never shows in code (a fenced
block or an inline code span), so the reference cannot fall behind the package again.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

import attenuo

README = Path(__file__).resolve().parents[1] / "README.md"
SECTION = "## Everything the package exports"


def readme() -> str:
    return README.read_text(encoding="utf-8")


def export_section(text: str) -> str:
    start = text.find(f"\n{SECTION}\n")
    assert start >= 0, f"README has no {SECTION!r} section"
    end = text.find("\n## ", start + 1)
    return text[start : end if end >= 0 else len(text)]


def code_text(text: str) -> str:
    """The README's fenced blocks and inline code spans, where a method is shown in use."""
    fenced = re.findall(r"^```[\w-]*\n(.*?)^```", text, re.S | re.M)
    prose = re.sub(r"^```[\w-]*\n.*?^```", "", text, flags=re.S | re.M)
    return "\n".join(fenced + re.findall(r"`([^`\n]+)`", prose))


def listed(section: str) -> set[str]:
    """The names in the first column of the section's table (a row may list several)."""
    names = set()
    for cell in re.findall(r"^\|([^|\n]*)\|", section, re.M):
        names.update(re.findall(r"`([A-Za-z_]\w*)", cell))
    return names


def public_methods(cls: type) -> set[str]:
    """Methods, class methods and static methods that ``cls`` or an SDK base class defines."""
    out = set()
    for base in cls.__mro__:
        if not base.__module__.startswith("attenuo"):
            continue
        for name, value in vars(base).items():
            if name.startswith("_"):
                continue
            if inspect.isfunction(value) or isinstance(value, (classmethod, staticmethod)):
                out.add(name)
    return out


CLASSES = [
    getattr(attenuo, n)
    for n in attenuo.__all__
    if isinstance(getattr(attenuo, n), type) and not issubclass(getattr(attenuo, n), BaseException)
]
METHODS = sorted({(c.__name__, m) for c in CLASSES for m in public_methods(c)})


def test_the_method_set_is_not_empty() -> None:
    # A change to how methods are found must not make the test below vacuous.
    names = {m for _, m in METHODS}
    assert {"exchange", "call_tool", "operators_reload", "aclose", "parse"} <= names


def test_every_export_has_a_row() -> None:
    rows = listed(export_section(readme()))
    missing = [n for n in attenuo.__all__ if n not in rows]
    assert not missing, f"exported but not listed under {SECTION!r} in {README.name}: {missing}"


def test_every_row_is_an_export() -> None:
    """A row for a name the package no longer exports is caught too."""
    rows = listed(export_section(readme()))
    assert rows, "no rows found"
    stale = sorted(rows - set(attenuo.__all__))
    assert not stale, f"listed under {SECTION!r} but not in attenuo.__all__: {stale}"


@pytest.mark.parametrize(("cls", "method"), METHODS, ids=lambda v: str(v))
def test_every_public_method_is_shown(cls: str, method: str) -> None:
    code = code_text(readme())
    assert re.search(rf"(?<![\w]){re.escape(method)}(?![\w])", code), (
        f"{cls}.{method} is public but appears in no code of {README.name}"
    )
