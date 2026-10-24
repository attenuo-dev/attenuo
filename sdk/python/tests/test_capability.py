from __future__ import annotations

import pytest

from attenuo import ArgLimit, Capability, Equals, Limits, OneOf, Prefix
from attenuo.capability import capabilities_to_json


def test_plain_capability_omits_constraints() -> None:
    assert Capability("github", "read_file").to_json() == {"server": "github", "tool": "read_file"}


def test_prefix_matches_rust_cli_shape() -> None:
    cap = Capability("github", "read_file", repo=Prefix("alice/public-"))
    assert cap.to_json() == {
        "server": "github",
        "tool": "read_file",
        "constraints": {"repo": {"op": "prefix", "value": "alice/public-"}},
    }


def test_one_of_and_equals() -> None:
    cap = Capability(
        "github",
        "create_issue",
        repo=OneOf("a/b", "c/d"),
        dry_run=Equals(True),
        n=3,
        label=OneOf(["x"]),
    )
    c = cap.to_json()["constraints"]
    assert c["repo"] == {"op": "one_of", "value": ["a/b", "c/d"]}
    assert c["dry_run"] == {"op": "equals", "value": True}
    assert c["n"] == {"op": "equals", "value": 3}  # bare values mean Equals
    assert c["label"] == {"op": "one_of", "value": ["x"]}


def test_round_trip_and_equality() -> None:
    cap = Capability("s", "t", a=Prefix("p"), b=OneOf(1, 2), c=Equals({"k": [1]}))
    assert Capability.from_json(cap.to_json()) == cap
    assert Capability("s", "t") != Capability("s", "u")
    assert len({cap, Capability.from_json(cap.to_json())}) == 1


def test_parse_and_str() -> None:
    assert Capability.parse("github:read_*") == Capability("github", "read_*")
    assert str(Capability("github", "read_file")) == "github:read_file"
    for bad in ("nocolon", "github:", ":tool", ""):
        with pytest.raises(ValueError):
            Capability.parse(bad)
    with pytest.raises(ValueError):
        Capability("", "x")


def test_unknown_op_rejected() -> None:
    with pytest.raises(ValueError):
        Capability.from_json(
            {"server": "s", "tool": "t", "constraints": {"a": {"op": "regex", "value": "x"}}}
        )


def test_normalize_mixed_inputs() -> None:
    out = capabilities_to_json(
        [
            "github:read_file,github:create_issue",
            Capability("github", "delete", repo=Prefix("x/")),
            {"server": "a", "tool": "b"},
        ]
    )
    assert [(c["server"], c["tool"]) for c in out] == [
        ("github", "read_file"),
        ("github", "create_issue"),
        ("github", "delete"),
        ("a", "b"),
    ]
    assert capabilities_to_json("github:*") == [{"server": "github", "tool": "*"}]
    assert capabilities_to_json(Capability("a", "b")) == [{"server": "a", "tool": "b"}]


def test_limits_round_trip_and_unknown_kinds_are_refused() -> None:
    cap = Capability("banking", "send_money").with_limits(
        calls=1, sum=("amount", 10), calls_per=("recipient", 1)
    )
    wire = {
        "server": "banking",
        "tool": "send_money",
        "limits": {
            "calls": 1,
            "sum": {"arg": "amount", "max": 10},
            "calls_per": {"arg": "recipient", "max": 1},
        },
    }
    assert cap.to_json() == wire
    assert Capability.from_json(wire) == cap
    # Raw dicts keep their limits when normalized (they used to be dropped).
    assert capabilities_to_json([wire]) == [wire]
    assert "limits" not in Capability("banking", "send_money").to_json()
    for bad in (
        {"window": {"arg": "to", "max": 1}},
        {"calls": -1},
        {"calls": 1.5},
        {"sum": {"arg": "amount"}},
        {"sum": {"arg": "url", "max": 1, "derive": "host"}},
        {"distinct": {"arg": "url", "max": 1, "derive": "path"}},
        {"distinct": {"arg": "", "max": 1}},
        {"calls_per": {"arg": "to", "max": 1, "extra": 1}},
        {"distinct": {"arg": "to", "max": 2**63}},
    ):
        with pytest.raises(ValueError):
            Capability.from_json({"server": "b", "tool": "t", "limits": bad})


def test_distinct_and_derived_limits_are_typed() -> None:
    cap = Capability("web", "get_webpage").with_limits(
        calls=5, distinct=ArgLimit("url", 2, derive="host")
    )
    wire = {
        "server": "web",
        "tool": "get_webpage",
        "limits": {"calls": 5, "distinct": {"arg": "url", "max": 2, "derive": "host"}},
    }
    assert cap.to_json() == wire
    assert Capability.from_json(wire) == cap
    assert capabilities_to_json([wire]) == [wire]
    typed = cap.typed_limits
    assert typed == Limits(calls=5, distinct=ArgLimit("url", 2, "host"))
    assert typed.distinct is not None and typed.distinct.counted == "url#host"
    # Tuples work too, with or without a derivation, and a whole Limits can be passed.
    same = Capability("web", "get_webpage").with_limits(calls=5, distinct=("url", 2, "host"))
    assert same == cap
    assert Capability("web", "get_webpage").with_limits(typed) == cap
    per = Capability("mail", "send").with_limits(calls_per=("to", 1), distinct=("to", 3))
    assert per.to_json()["limits"] == {
        "calls_per": {"arg": "to", "max": 1},
        "distinct": {"arg": "to", "max": 3},
    }
    assert Capability("a", "b").typed_limits.is_empty()
    with pytest.raises(ValueError):
        Capability("a", "b").with_limits(sum=("url", 1, "host"))
    with pytest.raises(ValueError):
        Capability("a", "b").with_limits(typed, calls_per=("to", 1))
    with pytest.raises(ValueError):
        ArgLimit("url", 1, "path")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ArgLimit("url", -1)
