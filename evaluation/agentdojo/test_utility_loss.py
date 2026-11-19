"""Tests for utility_loss.py. Standard library and pytest only."""

import json

import pytest
import utility_loss

TRUTH = [{"tool": "send_money", "args": {"recipient": "A", "subject": "rent"}}]


def test_a_denied_needed_tool_wins_over_other_denials_and_keeps_its_reason():
    denied = [
        ("get_iban", "capability_denied", {}),
        ("send_money", "policy_deny", {"recipient": "A", "subject": "other text"}),
        ("send_money", "budget_exhausted", {"recipient": "B"}),
    ]
    assert utility_loss.classify(denied, TRUTH) == ("needed: policy_deny", "send_money", True)


def test_a_needed_tool_with_other_arguments_is_still_needed_but_does_not_match():
    denied = [("send_money", "capability_denied", {"recipient": "B"})]
    assert utility_loss.classify(denied, TRUTH) == (
        "needed: capability_denied",
        "send_money",
        False,
    )


def test_only_unneeded_denials_and_no_denial():
    assert utility_loss.classify([("get_iban", "policy_deny", {})], TRUTH)[0] == (
        "derailed after a refusal"
    )
    assert utility_loss.classify([], TRUTH)[0] == "no refusal"


def test_an_unknown_reason_stops_the_script():
    with pytest.raises(SystemExit):
        utility_loss.classify([("send_money", "something_new", {})], TRUTH)


def write_lines(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_lost_and_gained_cases_are_paired_and_checked_against_the_totals(tmp_path):
    def row(arm, user, attack, utility):
        return {"arm": arm, "suite": "slack", "user": user, "attack": attack, "utility": utility}

    write_lines(
        tmp_path / "stats" / "rows.jsonl",
        [
            row("stock", "user_task_0", "injection_task_1", True),
            row("attenuo", "user_task_0", "injection_task_1", False),
            row("stock", "user_task_1", "injection_task_1", False),
            row("attenuo", "user_task_1", "injection_task_1", True),
            row("stock", "user_task_0", None, True),
            row("attenuo", "user_task_0", None, False),
            # Unpaired: only one arm scored it.
            row("stock", "user_task_1", None, True),
        ],
    )
    (tmp_path / "stats" / "ground_truth.json").write_text(
        json.dumps(
            {
                "source": "test",
                "suites": {
                    "slack": {
                        "user": {
                            "user_task_0": [{"tool": "send_direct_message", "args": {}}],
                            "user_task_1": [],
                        },
                        "injection": {"injection_task_1": ["send_direct_message"]},
                    }
                },
            }
        )
    )
    write_lines(
        tmp_path / "slack" / "enforced" / "decisions-grants-0.jsonl",
        [
            {
                "run": "slack/user_task_0/injection_task_1",
                "tool": "send_direct_message",
                "outcome": "denied",
                "reason": "capability_denied",
                "args": {},
            },
            {
                "run": "slack/user_task_1/injection_task_1",
                "tool": "get_webpage",
                "outcome": "denied",
                "reason": "policy_deny",
                "args": {},
            },
        ],
    )
    for suite in ("banking", "travel", "workspace"):
        write_lines(tmp_path / suite / "enforced" / "decisions-grants-0.jsonl", [])
    report = utility_loss.analyse(tmp_path)
    attack = report["kinds"]["attack"]["total"]
    assert attack["pairs"] == 2
    assert attack["lost"]["needed: capability_denied"] == 1
    assert attack["lost_needed_tool_also_attack"] == 1
    assert attack["gained"]["derailed after a refusal"] == 1
    benign = report["kinds"]["benign"]["total"]
    assert benign["pairs"] == 1
    assert benign["lost"]["no refusal"] == 1
    md = utility_loss.markdown(report)
    assert "| | slack | banking | travel | workspace | total |" in md
    assert "| **Lost** | **1** | **0** | **0** | **0** | **1** |" in md


def test_every_agentdojo_suite_is_read():
    assert utility_loss.SUITES == ("slack", "banking", "travel", "workspace")
