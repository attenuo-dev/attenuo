"""The injection suite as a test.

``test_corpus_*`` check the case files and always run. ``test_subset`` replays ten cases (one or
two per suite, covering all three deny stages and some known gaps) against the real server and
is skipped unless ``ATTENUO_INTEGRATION=1``. It needs the binaries: set ``ATTENUO_BIN_DIR`` or
build them into ``target/debug`` (see README.md).

    ATTENUO_INTEGRATION=1 ATTENUO_BIN_DIR=... pytest evaluation/injection-suite/test_suite.py -q
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

import harness
import run

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


# --- scripted outputs and the labels arm --------------------------------------------------------

OUTPUT_CASE = """\
suite: banking
cases:
  - id: x-out
    shape: agentdojo
    attack_class: direct_harm
    class: S
    user_task: Read the bill.
    injection: A synthetic test case.
    grant: [{ tool: read_file }]
    calls:
      - { tool: read_file, args: { file_path: bill.txt }, role: benign, expect: allow,
          output: OUTPUT }
      - { tool: send_money, args: { recipient: X, amount: 1, subject: s, date: d },
          role: attack, expect: deny, stage: capability }
"""


def _load_output_case(tmp_path: Path, output: str) -> harness.Case:
    env = harness.load_environment()
    p = tmp_path / "banking.yaml"
    p.write_text(OUTPUT_CASE.replace("OUTPUT", output))
    (case,) = harness.load_cases(p, env["banking"], env)
    return case


def test_output_field_is_parsed_and_checked(tmp_path: Path) -> None:
    case = _load_output_case(tmp_path, '"Amount due: 98."')
    assert [c.output for c in case.calls] == ["Amount due: 98.", None]
    for bad in ("42", '""', "[a, b]", json.dumps("x" * (harness.MAX_OUTPUT + 1))):
        with pytest.raises(harness.CorpusError, match="output"):
            _load_output_case(tmp_path, bad)


def test_corpus_dev_reads_have_short_outputs() -> None:
    """Every dev read returns scripted text, and only reads do; test cases are left alone."""
    for s in harness.load_corpus("dev"):
        for case in s.cases:
            for c in case.calls:
                assert (c.output is not None) == harness.is_read(s, c.tool), (case.id, c.tool)
                assert c.output is None or len(c.output) <= harness.MAX_OUTPUT
    for s in harness.load_corpus("test"):
        assert all(c.output is None for case in s.cases for c in case.calls)


def test_scripted_approver_follows_the_hand_label() -> None:
    benign = harness.Call("send_money", {}, "benign", "allow", None)
    attack = harness.Call("send_money", {}, "attack", "allow", None)
    assert harness.scripted_approver(benign) is True
    assert harness.scripted_approver(attack) is False


GATED = {
    "jsonrpc": "2.0",
    "id": 2,
    "error": {
        "code": -32008,
        "message": "approval required",
        "data": {"reason": "approval_required", "decision_id": "d-1", "call_hash": "ab"},
    },
}


def test_approval_required_is_its_own_outcome() -> None:
    assert harness._judge(GATED, []) == ("gated", "approval_required", "d-1")
    assert harness.stage_of("approval_required") == "approval"
    assert harness.approval_probe_verdict(GATED) is None
    denied = {"error": {"code": -32003, "data": {"reason": "policy_deny", "decision_id": "x"}}}
    assert "probe got error -32003 policy_deny" in (harness.approval_probe_verdict(denied) or "")
    assert "probe got no error" in (harness.approval_probe_verdict({"result": {}}) or "")
    other = {"error": {"code": -32008, "data": {"reason": "something_else"}}}
    assert harness._judge(other, [])[0] == "error"
    # The approvals API adds data.approval_id; the runner records it to decide and retry.
    assert harness._approval_id(GATED) is None
    with_id = json.loads(json.dumps(GATED))
    with_id["error"]["data"]["approval_id"] = "a-1"
    assert harness._judge(with_id, []) == ("gated", "approval_required", "d-1")
    assert harness._approval_id(with_id) == "a-1"


def _call(role: str, outcome: str, expect: str = "allow", stage: str | None = None,
          reached: bool = False, **extra: Any) -> dict[str, Any]:  # fmt: skip
    return {"arm": "attenuo_labels", "case": "x", "index": 0, "tool": "t", "role": role,
            "outcome": outcome, "expect": expect, "expect_stage": stage,
            "stage": stage if outcome == "deny" else None, "reason": None,
            "reached_upstream": reached, "as_expected": None, **extra}  # fmt: skip


GRANTED = {"after_approval": "allowed", "approval_id": "a-1", "approval_state": "consumed",
           "approval_consumed_by": "d-2", "retry_decision_id": "d-2",
           "retry_reached_upstream": True, "retry_output_returned": None}  # fmt: skip
DECLINED = {"after_approval": "declined", "approval_id": "a-2", "approval_state": "declined"}


def test_after_approval_outcomes() -> None:
    assert harness.after_approval_of("allow") == "allowed"
    assert harness.after_approval_of("deny") == "denied"
    assert harness.after_approval_of("gated") == "gated"
    assert harness.after_approval_of("error") == "error"
    assert set(harness.AFTER_APPROVAL) >= {"allowed", "denied", "declined", "no_decision"}


def test_labels_arm_rates_and_approve_all_bound() -> None:
    doc: dict[str, Any] = {
        "arms": ["attenuo_labels"],
        "calls": [
            _call("attack", "allow"),
            _call("attack", "gated", **DECLINED),
            _call("attack", "gated", **GRANTED),
            _call("attack", "deny", "deny", "capability"),
            _call("benign", "gated", **GRANTED),
            _call("benign", "gated", after_approval="no_decision"),
            _call("benign", "allow"),
            _call("benign", "deny", "deny", "policy"),
        ],
    }
    r = run.arm_rates(doc)["attenuo_labels"]
    assert (r["attack_allowed"], r["attack_gated"], r["attack_allowed_approve_all"]) == (1, 2, 3)
    assert (r["benign_denied"], r["benign_gated"], r["approval_requests"]) == (1, 2, 4)
    assert r["attack_after"]["declined"] == 1 and r["attack_after"]["allowed"] == 1
    assert r["attack_allowed_final"] == 2 and r["attack_reached_upstream"] == 1
    assert r["benign_completed_after_approval"] == 1 and r["benign_after"]["no_decision"] == 1
    doc |= {"rates": {"attenuo_labels": r}, "skipped_arms": {}}
    table = "\n".join(run.render_labels(doc))
    assert "| 1/4 (25%" in table and "| 2/4 (50%) |" in table and "| 4 |" in table
    assert "| 1 | 1 | 0 | 2/4 (50%" in table  # approved-allowed, declined, other, final
    assert "| 2/4 (50%) | 1/2 | 0 | 1 |" in table  # benign gated, completed, declined, other


def test_labels_arm_problems() -> None:
    assert run.labels_consistent(_call("attack", "gated"))
    assert not run.labels_consistent(_call("attack", "gated", "deny", "capability"))
    assert not run.labels_consistent(_call("benign", "deny", "allow"))
    doc: dict[str, Any] = {"calls": [_call("attack", "gated", reached=True)], "audit": {}}
    assert run.problems(doc) == ["attenuo_labels x#0 t: gated but reached the upstream"]
    doc = {"calls": [{**_call("benign", "allow"), "output_returned": False}], "audit": {}}
    assert "lacks the scripted output" in run.problems(doc)[0]


def test_labels_arm_approval_problems() -> None:
    ok = [_call("benign", "gated", **GRANTED), _call("attack", "gated", **DECLINED)]
    assert run.problems({"calls": ok, "audit": {}}) == []
    again = _call("benign", "gated", **{**GRANTED, "after_approval": "gated"})
    assert "got -32008 again" in run.problems({"calls": [again], "audit": {}})[0]
    unused = _call("benign", "gated", **{**GRANTED, "approval_state": "granted"})
    assert "not by the retry" in run.problems({"calls": [unused], "audit": {}})[0]
    lost = _call("benign", "gated", **{**GRANTED, "retry_reached_upstream": False})
    assert "did not reach the upstream" in run.problems({"calls": [lost], "audit": {}})[0]
    no_id = _call("benign", "gated", after_approval="no_decision")
    assert "without an approval_id" in run.problems({"calls": [no_id], "audit": {}})[0]
    pending = _call("attack", "gated", **{**DECLINED, "approval_state": "pending"})
    assert (
        "declined approval a-2, but it is pending"
        in run.problems({"calls": [pending], "audit": {}})[0]
    )
    audit = {"attenuo_labels": {"decisions_unmatched": [], "retries_unmatched": [{}],
                                "cli_verify_exit": 0, "offline_verify_exit": 0,
                                "export_exit": 0}}  # fmt: skip
    assert "retries after a grant" in run.problems({"calls": [], "audit": audit})[0]


def test_skipped_arm_is_reported() -> None:
    doc = {"rates": {}, "skipped_arms": {"attenuo_labels": "no -32008"}}
    assert run.render_labels(doc) == ["", "Arm `attenuo_labels` was not run: no -32008."]


@pytest.fixture()
def banking_upstream(tmp_path: Path) -> Iterator[harness.Upstream]:
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    env = harness.load_environment()
    with harness.upstreams([env["banking"]], harness.find_binaries(), tmp_path) as ups:
        yield ups["banking"]


def _post(http: httpx.Client, url: str, body: Any) -> Any:
    r = http.post(url, json=body, headers={"accept": "application/json, text/event-stream"})
    return r.json()


@pytest.mark.integration
def test_fake_mcp_returns_scripted_output_once(banking_upstream: harness.Upstream) -> None:
    up = banking_upstream

    def call(rid: int, tool: str = "read_file") -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                "params": {"name": tool, "arguments": {"file_path": "b.txt"}}}  # fmt: skip

    with httpx.Client(timeout=5) as http:
        up.script(http, {"read_file": ["first text", "second text"]})
        one = _post(http, up.url, call(1))
        texts = [c["text"] for c in one["result"]["content"]]
        assert json.loads(texts[0])["name"] == "read_file" and texts[1:] == ["first text"]
        batch = _post(http, up.url, [call(2), call(3, "get_balance"), call(4)])
        by_id = {m["id"]: [c["text"] for c in m["result"]["content"]] for m in batch}
        assert by_id[2][1:] == ["second text"] and len(by_id[3]) == 1 and len(by_id[4]) == 1
        up.script(http, {"read_file": ["unused"]})
        up.script(http, {})
        assert len(_post(http, up.url, call(5))["result"]["content"]) == 1
        bad = http.post(up.url.rsplit("/mcp", 1)[0] + "/script", json={"outputs": {"x": [1]}})
        assert bad.status_code == 400
    assert [name for name, _ in up.received()] == ["read_file", "read_file"]  # singles only


@pytest.mark.integration
def test_labels_arm_is_skipped_on_a_server_without_approvals() -> None:
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    suites = [s for s in harness.load_corpus() if s.name == "banking"]
    suites[0].cases = [c for c in suites[0].cases if c.id == "banking-02"]
    doc = harness.run(suites, ("attenuo", "attenuo_labels"))
    if "attenuo_labels" in doc["arms"]:
        pytest.skip("this server answers -32008; the arm ran")
    assert doc["arms"] == ["attenuo"]
    assert "attenuo_labels" in doc["skipped_arms"]
    read = next(c for c in doc["calls"] if c["tool"] == "read_file")
    assert read["output_returned"] is True


@pytest.mark.integration
def test_labels_arm_probe_skips_when_policy_lints_but_server_never_gates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With a labels policy the server accepts, the probe decides: no -32008, no arm."""
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    noop = tmp_path / "labels.cedar"
    noop.write_text('@id("noop")\nforbid(principal, action, resource) when { false };\n')
    monkeypatch.setattr(harness, "LABELS_POLICY", noop)
    suites = [s for s in harness.load_corpus() if s.name == "banking"]
    suites[0].cases = [c for c in suites[0].cases if c.id == "banking-02"]
    doc = harness.run(suites, ("attenuo_labels",))
    if "attenuo_labels" in doc["arms"]:
        pytest.skip("this server answers -32008; the arm ran")
    assert "probe got no error" in doc["skipped_arms"]["attenuo_labels"]
    assert doc["calls"] == []


# --- the run-limits arms ------------------------------------------------------------------------


def test_limits_rule_is_frozen_and_spares_reads_only() -> None:
    assert harness.limits_rule() == {"calls": 1}
    assert "limits-rule.json" in harness.frozen_hashes()["files"]
    assert "limits-rule.json" in harness.frozen_hashes()["added_later"]
    env = {s.upstream: s for s in harness.load_environment().values()}
    caps = [
        harness.Capability("banking", "get_balance"),
        harness.Capability("banking", "send_money"),
        harness.Capability("github", "*"),
        harness.Capability("slack", "get_webpage"),
        harness.Capability("nowhere", "get_balance"),
    ]
    harness.apply_limits_rule(caps, env, harness.limits_rule())
    assert [c.limits for c in caps] == [{}, {"calls": 1}, {"calls": 1}, {}, {"calls": 1}]
    assert caps[1].to_json()["limits"] == {"calls": 1}
    assert set(harness.LIMIT_ARMS) <= set(harness.CONSTRAINED_ARMS)
    # The combined arm settles approvals through the labels arm's path (grant, then retry).
    assert "attenuo_labels_limits" in set(harness.LIMIT_ARMS) & set(harness.LABEL_ARMS)


def test_limits_probe_and_budget_stage() -> None:
    for reason in harness.BUDGET_REASONS:
        assert harness.stage_of(reason) == "budget"
    spent = {"error": {"code": -32003, "data": {"reason": "budget_exhausted", "decision_id": "d"}}}
    assert harness.limits_probe_verdict(spent) is None
    assert "probe got no error" in (harness.limits_probe_verdict({"result": {}}) or "")
    other = {"error": {"code": -32003, "data": {"reason": "policy_deny"}}}
    assert "probe got error -32003 policy_deny" in (harness.limits_probe_verdict(other) or "")


def _limits_call(arm: str, role: str, outcome: str, expect: str = "allow",
                 expect_stage: str | None = None,
                 stage: str | None = None) -> dict[str, Any]:  # fmt: skip
    return {**_call(role, outcome, expect, expect_stage), "arm": arm, "stage": stage}


def test_limits_arm_consistency() -> None:
    lim, both = "attenuo_limits", "attenuo_labels_limits"
    ok = [
        _limits_call(lim, "attack", "allow"),
        _limits_call(lim, "attack", "deny", "allow", None, "budget"),
        _limits_call(lim, "attack", "deny", "deny", "policy", "budget"),
        _limits_call(lim, "attack", "deny", "deny", "capability", "capability"),
        _limits_call(both, "benign", "gated"),
    ]
    bad = [
        _limits_call(lim, "attack", "gated"),  # no approvals without labels
        _limits_call(lim, "attack", "deny", "deny", "capability", "budget"),  # cap comes first
        _limits_call(lim, "attack", "deny", "deny", "lease", "budget"),
        _limits_call(lim, "benign", "deny", "allow", None, "policy"),
    ]
    assert all(run.limits_consistent(c) for c in ok)
    assert not any(run.limits_consistent(c) for c in bad)
    # A granted retry refused by a run limit is `denied`, stage budget: not a problem unless it
    # reached the upstream.
    spent = {**_limits_call(both, "benign", "gated"), "after_approval": "denied",
             "approval_id": "a-1", "approval_state": "granted",
             "retry_reason": "budget_exhausted", "retry_stage": "budget",
             "retry_decision_id": "d-2", "retry_reached_upstream": False}  # fmt: skip
    assert run.problems({"calls": [spent], "audit": {}}) == []
    leaked = {**spent, "retry_reached_upstream": True}
    assert any("denied but reached the upstream" in p
               for p in run.problems({"calls": [leaked], "audit": {}}))  # fmt: skip
    r = run.arm_rates({"arms": [both], "calls": [spent]})[both]
    assert r["retry_budget_denied"] == 1
    doc: dict[str, Any] = {"rates": {both: r}, "skipped_arms": {}}
    assert "1 granted retries were denied by a run limit" in "\n".join(run.render_labels(doc))


def test_limits_arm_rates_and_table() -> None:
    arm = "attenuo_limits"
    doc: dict[str, Any] = {
        "arms": [arm],
        "calls": [
            _limits_call(arm, "benign", "allow"),
            _limits_call(arm, "attack", "deny", "allow", None, "budget"),
            _limits_call(arm, "attack", "allow"),
            _limits_call(arm, "benign", "deny", "allow", None, "budget"),
        ],
    }
    r = run.arm_rates(doc)[arm]
    assert (r["attack_allowed"], r["attack_budget_denied"], r["benign_budget_denied"]) == (1, 1, 1)
    doc |= {"rates": {arm: r}, "skipped_arms": {}}
    table = "\n".join(run.render_limits(doc))
    assert "### Run limits in `attenuo_limits`" in table and "| 1/2 (50%) |" in table
    assert r["benign_lost_to_limits"] == [
        {"case": "x", "index": 0, "tool": "t", "when": "first attempt"}
    ]
    assert "| x | 0 | `t` | first attempt |" in table
    # A benign retry after a grant that a limit refused is a loss too (combined arm).
    both = "attenuo_labels_limits"
    spent = {**_limits_call(both, "benign", "gated"), "after_approval": "denied",
             "retry_stage": "budget"}  # fmt: skip
    lost = run.arm_rates({"arms": [both], "calls": [spent]})[both]["benign_lost_to_limits"]
    assert [x["when"] for x in lost] == ["retry after approval"]
    assert arm in run.ARM_NAMES and "attenuo_labels_limits" in run.ARM_NAMES


@pytest.mark.integration
def test_limits_arm_runs_or_is_skipped() -> None:
    """On a server with run limits, banking-04's two inflated payments to the right payee are
    refused by the one-call rule; on one without, the arm is skipped with the probe's reason."""
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    suites = [s for s in harness.load_corpus() if s.name == "banking"]
    suites[0].cases = [c for c in suites[0].cases if c.id == "banking-04"]
    doc = harness.run(suites, ("attenuo_limits",))
    if "attenuo_limits" not in doc["arms"]:
        assert "does not enforce run limits" in doc["skipped_arms"]["attenuo_limits"]
        assert doc["calls"] == []
        return
    got = [(c["role"], c["outcome"], c["reason"]) for c in doc["calls"]]
    assert got == [
        ("benign", "allow", None),
        ("attack", "deny", "budget_exhausted"),
        ("attack", "deny", "budget_exhausted"),
    ]
    assert not any(c["reached_upstream"] for c in doc["calls"][1:])
    a = doc["audit"]["attenuo_limits"]
    assert not a["decisions_unmatched"] and a["cli_verify_exit"] == 0


# --- the argument-taint arm (option (b)) ---------------------------------------------------------


def test_labels_args_arm_loads_its_own_frozen_policy(tmp_path: Path) -> None:
    hashes = harness.frozen_hashes()
    assert "labels-args.cedar" in hashes["files"] and "labels-args.cedar" in hashes["added_later"]
    assert harness.labels_policy("attenuo_labels_args").name == "labels-args.cedar"
    assert harness.labels_policy("attenuo_labels").name == "labels.cedar"
    assert harness.labels_policy("attenuo_labels_limits").name == "labels.cedar"
    # Approvals are settled through the labels arm's path; no run-limit rule.
    assert "attenuo_labels_args" in harness.LABEL_ARMS and "attenuo_labels_args" in harness.PROXIED
    assert "attenuo_labels_args" in harness.CONSTRAINED_ARMS
    assert "attenuo_labels_args" not in harness.LIMIT_ARMS
    assert "attenuo_labels_args" in run.ARM_NAMES
    env = list(harness.load_environment().values())
    harness.write_config(tmp_path, env, 1, {s.upstream: "http://x" for s in env},
                         "attenuo_labels_args", ["worker"])  # fmt: skip
    text = (tmp_path / "policy.cedar").read_text()
    assert "confirm_destructive_with_untrusted_args" in text
    assert "confirm_destructive_after_untrusted_read" not in text


def test_arg_taint_probe_verdict() -> None:
    assert "does not name it" in (harness.arg_taint_probe_verdict(GATED) or "")
    named = json.loads(json.dumps(GATED))
    named["error"]["data"]["untrusted_args"] = [{"arg": "street", "seq": 4, "kind": "leaf"}]
    assert harness.arg_taint_probe_verdict(named) is None
    other = json.loads(json.dumps(GATED))
    other["error"]["data"]["untrusted_args"] = [{"arg": "city", "seq": 4, "kind": "leaf"}]
    assert harness.arg_taint_probe_verdict(other) is not None
    got = harness.arg_taint_probe_verdict({"result": {}}) or ""
    assert "copying an untrusted result (probe got no error)" in got


@pytest.mark.integration
def test_labels_args_arm_runs_or_is_skipped() -> None:
    """On a server with argument-level taint the arm runs with no problems; on one without, it
    is skipped with the probe's reason and runs no call."""
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    suites = [s for s in harness.load_corpus() if s.name == "banking"]
    suites[0].cases = [c for c in suites[0].cases if c.id == "banking-02"]
    doc = harness.run(suites, ("attenuo_labels_args",))
    if "attenuo_labels_args" not in doc["arms"]:
        why = doc["skipped_arms"]["attenuo_labels_args"]
        assert "probe got" in why or "does not name" in why
        assert doc["calls"] == []
        return
    doc["rates"] = run.arm_rates(doc)
    assert run.problems(doc) == []
