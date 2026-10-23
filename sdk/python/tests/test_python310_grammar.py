"""The package supports Python 3.10 (``requires-python``, CI matrix): no newer syntax."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_sources_parse_with_the_python_310_grammar() -> None:
    files = sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "tests").rglob("*.py"))
    assert files
    for f in files:
        ast.parse(f.read_text(encoding="utf-8"), filename=str(f), feature_version=(3, 10))
