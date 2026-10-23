from __future__ import annotations

import pytest

from onbehalf import Capability, Equals, OneOf, Prefix
from onbehalf.capability import capabilities_to_json


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
