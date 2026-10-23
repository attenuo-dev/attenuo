"""The injection suite as a test.

``test_corpus_*`` check the case files and always run. ``test_subset`` replays ten cases (one or
two per suite, covering all three deny stages and some known gaps) against the real server and
is skipped unless ``ATTENUO_INTEGRATION=1``. It needs the binaries: set ``ATTENUO_BIN_DIR`` or
build them into ``target/debug`` (see README.md).

    ATTENUO_INTEGRATION=1 ATTENUO_BIN_DIR=... pytest evaluation/injection-suite/test_suite.py -q
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any

import pytest

import harness

SUBSET = (
    "workspace-04",
    "workspace-05",
    "workspace-06",
    "workspace-11",
    "banking-02",
    "banking-04",
    "slack-07",
    "travel-05",
    "github-01",
    "github-07",
)


def test_corpus_loads_and_is_big_enough() -> None:
    suites = harness.load_corpus()
    cases = [c for s in suites for c in s.cases]
    assert len(cases) >= 40
    assert {s.name for s in suites} >= {"workspace", "banking", "travel", "slack", "github"}
    stages = {c.stage for case in cases for c in case.calls if c.stage}
    assert stages == {"capability", "policy", "lease"}


def test_corpus_capabilities_build() -> None:
    for s in harness.load_corpus():
        for case in s.cases:
            for constrained in (True, False):
                caps = harness.capabilities(s, case, constraints=constrained)
                assert caps, case.id


@pytest.fixture(scope="module")
def result() -> dict[str, Any]:
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    suites = []
    for s in harness.load_corpus():
        s.cases = [c for c in s.cases if c.id in SUBSET]
        if s.cases:
            suites.append(s)
    assert sum(len(s.cases) for s in suites) == len(SUBSET)
    return harness.run(suites)


@pytest.mark.integration
def test_subset_matches_expectations(result: dict[str, Any]) -> None:
    calls = [c for c in result["calls"] if c["arm"] == "attenuo"]
    wrong = [c for c in calls if not c["as_expected"]]
    assert not wrong, wrong
    assert {c["stage"] for c in calls if c["stage"]} == {"capability", "policy", "lease"}


@pytest.mark.integration
def test_subset_denied_calls_never_reach_upstream(result: dict[str, Any]) -> None:
    for c in result["calls"]:
        if c["outcome"] == "deny":
            assert not c["reached_upstream"], c
        if c["arm"] == "direct":
            assert c["outcome"] == "allow" and c["reached_upstream"], c


@pytest.mark.integration
def test_subset_audit(result: dict[str, Any]) -> None:
    for arm, a in result["audit"].items():
        assert not a["decisions_unmatched"], arm
        assert a["cli_verify_exit"] == 0, a["cli_verify_output"]
        assert a["offline_verify_exit"] == 0, a["offline_verify_output"]


GARBAGE_ENV = {
    "ATTENUO_ADMIN_TOKEN": "garbage-from-another-server",
    "ATTENUO_SERVER": "http://127.0.0.1:9",
    "ATTENUO_TOKEN": "garbage",
    "ATTENUO_CONFIG": "/nonexistent/server.toml",
}


def test_inherited_attenuo_env_is_dropped_with_one_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for k, v in GARBAGE_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("ATTENUO_BIN_DIR", "/keep/me")
    dropped = harness.ignore_inherited_env()
    assert dropped == sorted(GARBAGE_ENV)
    assert not any(k in os.environ for k in GARBAGE_ENV)
    assert os.environ["ATTENUO_BIN_DIR"] == "/keep/me"
    err = capsys.readouterr().err
    assert err.count("warning:") == 1 and "ATTENUO_ADMIN_TOKEN" in err
    assert harness.ignore_inherited_env() == []
    assert capsys.readouterr().err == ""


@pytest.mark.integration
def test_subset_passes_with_garbage_attenuo_env_exported() -> None:
    """A child run with another server's variables exported still passes (was a 401)."""
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    child = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"{__file__}::test_subset_matches_expectations",
            f"{__file__}::test_subset_audit",
        ],
        env={**os.environ, **GARBAGE_ENV},
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert child.returncode == 0, child.stdout + child.stderr
