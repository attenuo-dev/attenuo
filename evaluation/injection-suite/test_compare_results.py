"""Tests for compare_results.py. None of them needs the server."""

from __future__ import annotations

from pathlib import Path

import pytest

import compare_results

BASE = """\
# Injection suite results, x

## Split `dev`

| Arm | Attack calls allowed | Attack calls that reached the upstream | Benign calls denied |
|---|---:|---:|---:|
| No attenuo (direct to upstream) | 77/77 (100%, 95-100%) | 77/77 (100%) | 0/130 (0%, 0-3%) |
| Suite policy with the root token (no attenuation) | 28/77 (36%) | 28/77 (36%) | 3/130 (2%) |
| attenuo full | 15/77 (19%) | 15/77 (19%) | 3/130 (2%) |

## Split `test`

| attenuo full | 7/38 (18%) | 7/38 (18%) | 3/29 (10%) |
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


def test_identical_rows_reproduce(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = _write(tmp_path, "a.md", BASE)
    # Lines other than the arm rows (title, commit, other tables) may differ freely.
    b = _write(tmp_path, "b.md", BASE.replace("results, x", "results, y") + "\nextra\n")
    assert compare_results.main([str(a), str(b), "--label", "base.md"]) == 0
    assert "REPRODUCED: 3 arm rows identical to base.md" in capsys.readouterr().out


def test_changed_row_is_a_diff(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = _write(tmp_path, "a.md", BASE)
    b = _write(tmp_path, "b.md", BASE.replace("7/38 (18%)", "8/38 (21%)", 1))
    assert compare_results.main([str(a), str(b)]) == 1
    err = capsys.readouterr().err
    assert "-[Split `test`] | attenuo full | 7/38 (18%)" in err
    assert "+[Split `test`] | attenuo full | 8/38 (21%)" in err
    assert "1 line(s) only in the baseline, 1 only in the new run" in err


def test_problems_must_match_too(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    probs = "\n### Problems\n\n- attenuo t-banking-02#1 send_money: expected deny/policy\n"
    a = _write(tmp_path, "a.md", BASE + probs)
    # The same known problem in both files: reproduced, and the problem is counted.
    assert compare_results.main([str(a), str(_write(tmp_path, "b.md", BASE + probs))]) == 0
    assert "1 problem(s) reported by run.py, the same as" in capsys.readouterr().out
    # A problem the baseline does not have, or one that went away, is a difference.
    assert compare_results.compare(a, _write(tmp_path, "c.md", BASE))[0] == 1
    extra = probs + "- attenuo t-banking-03#2 send_money: reached the upstream\n"
    assert compare_results.compare(a, _write(tmp_path, "d.md", BASE + extra))[0] == 1


def test_rows_are_tagged_by_split(tmp_path: Path) -> None:
    # The same row under another split heading is a difference, not a match.
    a = _write(tmp_path, "a.md", BASE)
    b = _write(tmp_path, "b.md", BASE.replace("## Split `test`", "## Split `dev`"))
    assert compare_results.compare(a, b)[0] == 1
    # A file with no arm rows at all is an error of its own.
    assert compare_results.compare(a, _write(tmp_path, "c.md", "nothing\n"))[0] == 2
