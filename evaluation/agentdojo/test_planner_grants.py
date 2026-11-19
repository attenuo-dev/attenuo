"""The planner grant format: validation, freeze and conversion to SDK capabilities. The
catalogue here is synthetic, so these tests read nothing of the benchmark's tasks."""

import json

import planner_grants as pg
import pytest

CATALOG = {
    "tasks": ["t_0", "t_1"],
    "tools": {
        "find": {"read": True, "parameters": {"properties": {"q": {"type": "string"}}}},
        "send": {
            "read": False,
            "parameters": {
                "$defs": {"Mode": {"enum": ["r", "rw"], "type": "string"}},
                "properties": {
                    "to": {"items": {"type": "string"}, "type": "array"},
                    "amount": {"type": "number"},
                    "count": {"type": "integer"},
                    "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "mode": {"$ref": "#/$defs/Mode"},
                    "url": {"type": "string"},
                },
            },
        },
    },
}


def entry(*caps, rationale="Because the prompt says so."):
    return {"capabilities": list(caps), "rationale": rationale}


def valid():
    return {
        "t_0": entry({"tool": "find"}),
        "t_1": entry(
            {"tool": "find"},
            {
                "tool": "send",
                "constraints": {
                    "to": {"op": "equals", "value": ["a@example.org"]},
                    "amount": {"op": "one_of", "value": [10, 12.5]},
                    "count": {"op": "range", "value": {"max": 3}},
                    "note": {"op": "prefix", "value": "Re: "},
                    "mode": {"op": "equals", "value": "r"},
                },
                "limits": {"calls": 1, "distinct": {"arg": "url", "max": 1, "derive": "host"}},
            },
        ),
    }


def test_a_valid_file_has_no_problems():
    assert pg.check_suite(valid(), CATALOG, "s") == []


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda g: g.pop("t_1"), "s/t_1: no entry"),
        (lambda g: g.update(t_9=entry({"tool": "find"})), "s/t_9: not a user task"),
        (lambda g: g["t_0"].update(rationale=""), "rationale must be a non-empty string"),
        (lambda g: g["t_0"].update(capabilities=[]), "capabilities must be a non-empty list"),
        (lambda g: g["t_0"].update(extra=1), "unknown keys ['extra']"),
        (lambda g: g["t_0"]["capabilities"].append({"tool": "nope"}), "unknown tool 'nope'"),
        (lambda g: g["t_0"]["capabilities"].append({"tool": "find_*"}), "unknown tool"),
        (
            lambda g: g["t_0"]["capabilities"].append({"tool": "send", "server": "x"}),
            "unknown keys ['server']",
        ),
    ],
)
def test_structural_problems_are_reported(mutate, expected):
    grants = valid()
    mutate(grants)
    problems = pg.check_suite(grants, CATALOG, "s")
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize(
    "arg, constraint, expected",
    [
        ("missing", {"op": "equals", "value": 1}, "has no argument 'missing'"),
        ("to", {"op": "equals", "value": "a@example.org"}, "does not fit 'to'"),
        ("to", {"op": "equals", "value": [1]}, "does not fit 'to'"),
        ("amount", {"op": "equals", "value": "10"}, "does not fit 'amount'"),
        ("amount", {"op": "equals", "value": True}, "does not fit 'amount'"),
        ("count", {"op": "equals", "value": 1.5}, "does not fit 'count'"),
        ("mode", {"op": "equals", "value": "x"}, "does not fit 'mode'"),
        ("amount", {"op": "one_of", "value": []}, "non-empty list"),
        ("amount", {"op": "one_of", "value": [1, "2"]}, "do not fit 'amount'"),
        ("count", {"op": "prefix", "value": "1"}, "prefix needs a string argument"),
        ("url", {"op": "prefix", "value": ""}, "non-empty string"),
        ("url", {"op": "range", "value": {"max": 1}}, "range needs a number argument"),
        ("count", {"op": "range", "value": {}}, "must be"),
        ("count", {"op": "range", "value": {"max": 1.5}}, "must be integers"),
        ("count", {"op": "range", "value": {"min": 3, "max": 1}}, "min greater than max"),
        ("count", {"op": "regex", "value": "x"}, "unknown op 'regex'"),
        ("count", {"equals": 1}, '{"op": ..., "value": ...}'),
    ],
)
def test_constraint_problems_are_reported(arg, constraint, expected):
    grants = valid()
    grants["t_0"]["capabilities"] = [{"tool": "send", "constraints": {arg: constraint}}]
    problems = pg.check_suite(grants, CATALOG, "s")
    assert any(expected in p for p in problems), problems


@pytest.mark.parametrize(
    "limits, expected",
    [
        ({}, "non-empty object"),
        ({"calls": -1}, "limits.calls"),
        ({"calls": True}, "limits.calls"),
        ({"rate": 1}, "unknown limit kind 'rate'"),
        ({"sum": {"arg": "url", "max": 1}}, "limits.sum needs a number argument"),
        ({"sum": {"arg": "count", "max": 1, "derive": "host"}}, "arg and max only"),
        ({"distinct": {"arg": "nope", "max": 1}}, "unknown argument 'nope'"),
        ({"distinct": {"arg": "count", "max": 1, "derive": "host"}}, "derive must be"),
        ({"calls_per": {"arg": "url", "max": -2}}, "max must be an integer"),
    ],
)
def test_limit_problems_are_reported(limits, expected):
    grants = valid()
    grants["t_0"]["capabilities"] = [{"tool": "send", "limits": limits}]
    problems = pg.check_suite(grants, CATALOG, "s")
    assert any(expected in p for p in problems), problems


def test_conversion_goes_through_the_sdk_wire_form():
    from attenuo import Capability, Equals, OneOf, Prefix, Range

    caps = pg.to_capabilities(valid()["t_1"], "s")
    assert [c.to_json()["tool"] for c in caps] == ["find", "send"]
    assert caps[0] == Capability("s", "find")
    send = caps[1]
    assert send.constraints == {
        "to": Equals(["a@example.org"]),
        "amount": OneOf(10, 12.5),
        "count": Range(max=3),
        "note": Prefix("Re: "),
        "mode": Equals("r"),
    }
    assert send.limits == {"calls": 1, "distinct": {"arg": "url", "max": 1, "derive": "host"}}


def write_dir(tmp_path, grants_by_suite):
    for suite, grants in grants_by_suite.items():
        (tmp_path / f"{suite}.json").write_text(json.dumps(grants))


def test_freeze_and_check_frozen(tmp_path):
    write_dir(tmp_path, {"s": valid()})
    frozen = pg.freeze(tmp_path, ["s"], "fixture-reads-only")
    assert frozen["format"] == pg.FROZEN_FORMAT
    assert frozen["files"]["s.json"] == pg.sha256_file(tmp_path / "s.json")
    assert pg.check_frozen(frozen, tmp_path, ["s"]) == []
    (tmp_path / "s.json").write_text(json.dumps(valid()) + " ")
    assert "does not match its frozen SHA-256" in pg.check_frozen(frozen, tmp_path, ["s"])[0]
    assert "no hash for t.json" in pg.check_frozen(frozen, tmp_path, ["t"])[0]
    assert "format" in pg.check_frozen({"format": "x"}, tmp_path, ["s"])[0]


def test_the_fixture_grants_reads_only_and_is_labelled():
    fixture = pg.fixture(CATALOG)
    assert set(fixture) == {"t_0", "t_1"}
    for e in fixture.values():
        assert e["capabilities"] == [{"tool": "find"}]
        assert "SYNTHETIC FIXTURE" in e["rationale"]
    assert pg.check_suite(fixture, CATALOG, "s") == []


def test_the_command_line_validates_against_a_bundle(tmp_path, capsys):
    bundle = tmp_path / "bundle"
    (bundle / "workspace").mkdir(parents=True)
    tasks = [{"id": t, "prompt": "p"} for t in CATALOG["tasks"]]
    tools = [
        {"name": n, "description": "", "parameters": t["parameters"], "read": t["read"]}
        for n, t in CATALOG["tools"].items()
    ]
    (bundle / "workspace" / "tasks.json").write_text(json.dumps(tasks))
    (bundle / "workspace" / "tools.json").write_text(json.dumps(tools))
    grants = tmp_path / "grants"
    grants.mkdir()
    write_dir(grants, {"workspace": valid()})
    args = ["validate", str(grants), "--bundle", str(bundle), "--suites", "workspace"]
    assert pg.main(args) == 0
    bad = valid()
    bad["t_0"]["capabilities"] = [{"tool": "nope"}]
    write_dir(grants, {"workspace": bad})
    assert pg.main(args) == 1
    assert "unknown tool 'nope'" in capsys.readouterr().err
    out = tmp_path / "FROZEN.json"
    write_dir(grants, {"workspace": valid()})
    freeze = ["freeze", str(grants), "--bundle", str(bundle), "--suites", "workspace"]
    assert pg.main([*freeze, "--source", "fixture-reads-only", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["source"] == "fixture-reads-only"
