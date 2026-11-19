"""grant_quality.py's matching and per-task counts, on synthetic calls."""

from types import SimpleNamespace

import pytest

gq = pytest.importorskip("grant_quality", reason="needs agentdojo installed")


def call(function, **args):
    return SimpleNamespace(function=function, args=args)


@pytest.mark.parametrize(
    "constraint, value, ok",
    [
        ({"op": "equals", "value": "a"}, "a", True),
        ({"op": "equals", "value": "a"}, "A", False),
        ({"op": "equals", "value": 100}, 100.0, True),
        ({"op": "equals", "value": 1}, True, False),
        ({"op": "equals", "value": ["a", "b"]}, ["b", "a"], False),
        ({"op": "one_of", "value": ["x", "y"]}, "y", True),
        ({"op": "prefix", "value": "ab"}, "abc", True),
        ({"op": "prefix", "value": "ab"}, 12, False),
        ({"op": "range", "value": {"max": 10}}, 10, True),
        ({"op": "range", "value": {"max": 10}}, 9.5, False),
        ({"op": "range", "value": {"min": 1}}, 0, False),
    ],
)
def test_satisfied_mirrors_the_server(constraint, value, ok):
    assert gq.satisfied(constraint, value) is ok


def test_task_quality_counts_over_under_and_disagreeing_pins():
    truth = [
        call("get_things"),
        call("send_money", recipient="X1", amount=10.0, subject="rent"),
    ]
    planner = {
        "capabilities": [
            {"tool": "get_things"},
            {"tool": "read_file"},
            {
                "tool": "send_money",
                "constraints": {
                    "recipient": {"op": "equals", "value": "X2"},
                    "amount": {"op": "equals", "value": 10},
                },
            },
        ]
    }
    oracle = gq.oracle_entry(truth)
    q = gq.task_quality(planner, oracle, truth)
    assert q["tools_planner"] == 3 and q["tools_oracle"] == 2
    assert q["over_grant"] == ["read_file"]
    assert q["under_grant"] == []
    assert q["write_pins_planner"] == 2
    assert q["write_pins_oracle"] == 2  # recipient and amount; subject is free text
    assert q["pins_disagree"] == [["send_money", "recipient"]]
    assert q["calls_outside"] == ["send_money"]
    assert q["gt_calls"] == 2


def test_a_missing_tool_is_under_grant_and_its_calls_are_outside():
    truth = [call("get_things"), call("update_thing", id="7")]
    planner = {"capabilities": [{"tool": "get_things"}]}
    q = gq.task_quality(planner, gq.oracle_entry(truth), truth)
    assert q["under_grant"] == ["update_thing"]
    assert q["calls_outside"] == ["update_thing"]
    assert q["pins_disagree"] == []
