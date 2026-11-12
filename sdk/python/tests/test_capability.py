from __future__ import annotations

import pytest

from attenuo import (
    ArgLimit,
    Capability,
    Equals,
    Limits,
    OneOf,
    PathPrefix,
    Prefix,
    Range,
    path_problem,
)
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


def test_path_prefix_matches_rust_shape_and_round_trips() -> None:
    cap = Capability("fs", "read_file", path=PathPrefix("/workspace/"), dir=PathPrefix("docs"))
    assert cap.to_json()["constraints"] == {
        "dir": {"op": "path_prefix", "value": "docs"},
        "path": {"op": "path_prefix", "value": "/workspace/"},
    }
    assert Capability.from_json(cap.to_json()) == cap
    assert Capability.from_json(cap.to_json()).constraints["path"] == PathPrefix("/workspace/")
    assert PathPrefix("/w").to_json() != Prefix("/w").to_json()


@pytest.mark.parametrize(
    ("path", "why"),
    [
        ("", "is empty"),
        ("/workspace/../etc", "holds a `.` or `..` segment"),
        ("/workspace/..", "holds a `.` or `..` segment"),
        ("./src", "holds a `.` or `..` segment"),
        ("/workspace/.", "holds a `.` or `..` segment"),
        ("/workspace//a", "holds an empty segment (`//`)"),
        ("//workspace", "holds an empty segment (`//`)"),
        ("C:\\work", "holds a backslash"),
        ("/w\x00", "holds a control character"),
        ("/w\tx", "holds a control character"),
        ("/w\x7f", "holds a control character"),
        ("/w\x85", "holds a control character"),
        ("/w/%2e%2e", "holds a percent-encoded `.`, `/` or `\\`"),
        ("/w/%2E", "holds a percent-encoded `.`, `/` or `\\`"),
        ("/w%2Fx", "holds a percent-encoded `.`, `/` or `\\`"),
        ("/w%5cx", "holds a percent-encoded `.`, `/` or `\\`"),
        (
            "/w/%252e",
            "holds a percent escape that is itself percent-encoded (`%25` and two hex digits)",
        ),
        ("/w/\uff0e\uff0e", "holds a character that normalises to `.`, `/` or `\\`"),
        ("/w\uff0fx", "holds a character that normalises to `.`, `/` or `\\`"),
    ],
)
def test_path_prefix_refuses_what_the_server_refuses(path: str, why: str) -> None:
    assert path_problem(path) == why
    with pytest.raises(ValueError, match="a path_prefix constraint's path"):
        PathPrefix(path)
    with pytest.raises(ValueError):
        Capability.from_json(
            {"server": "s", "tool": "t", "constraints": {"p": {"op": "path_prefix", "value": path}}}
        )


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/workspace",
        "/workspace/",
        "docs",
        "a/b/",
        "~/x",
        "/a%20b",
        "/...",
        "/caf\u00e9",
        "/100%25",
    ],
)
def test_path_prefix_accepts_plain_paths(path: str) -> None:
    assert path_problem(path) is None
    assert PathPrefix(path).to_json() == {"op": "path_prefix", "value": path}


def test_path_prefix_value_must_be_a_string() -> None:
    with pytest.raises(ValueError):
        PathPrefix(1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Capability.from_json(
            {"server": "s", "tool": "t", "constraints": {"p": {"op": "path_prefix", "value": 1}}}
        )


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


def test_range_serializes_like_the_server() -> None:
    cap = Capability("banking", "send_money", amount=Range(0, 2000), fee=Range(max=5))
    c = cap.to_json()["constraints"]
    assert c["amount"] == {"op": "range", "value": {"min": 0, "max": 2000}}
    assert c["fee"] == {"op": "range", "value": {"max": 5}}  # a missing bound is omitted
    assert Range(min=-3).to_json() == {"op": "range", "value": {"min": -3}}
    assert Capability.from_json(cap.to_json()) == cap
    assert Range(7, 7).to_json()["value"] == {"min": 7, "max": 7}


def test_range_is_validated_on_both_paths() -> None:
    bad: list[tuple[tuple[object, ...], dict[str, object]]] = [
        ((), {}),  # no bound
        ((3, 2), {}),  # min > max
        ((1.5,), {}),  # not an integer
        (("1",), {}),
        ((True,), {}),  # a bool is not a bound
        ((), {"max": 2**63}),  # beyond a Cedar Long
    ]
    for args, kwargs in bad:
        with pytest.raises(ValueError):
            Range(*args, **kwargs)  # type: ignore[arg-type]
    for value in [
        {},
        {"min": 3, "max": 2},
        {"min": 0, "maximum": 10},  # a typo is refused, not read as no upper bound
        [0, 10],
        {"max": 10.5},
    ]:
        with pytest.raises(ValueError):
            Capability.from_json(
                {"server": "s", "tool": "t", "constraints": {"n": {"op": "range", "value": value}}}
            )
