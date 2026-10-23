"""Capabilities and argument constraints, serialized exactly as the Rust ``Capability`` is.

``Capability("github", "read_file", repo=Prefix("alice/public-"))`` becomes::

    {"server": "github", "tool": "read_file",
     "constraints": {"repo": {"op": "prefix", "value": "alice/public-"}}}

``constraints`` is omitted when empty. ``server`` and ``tool`` are an exact name, ``*``, or a
prefix glob such as ``read_*``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Equals:
    """The argument must equal this JSON value exactly."""

    value: Any

    def to_json(self) -> dict[str, Any]:
        return {"op": "equals", "value": self.value}


@dataclass(frozen=True, init=False)
class OneOf:
    """The argument must equal one of these JSON values."""

    values: tuple[Any, ...]

    def __init__(self, *values: Any) -> None:
        # OneOf(["a", "b"]) is accepted as well as OneOf("a", "b").
        if len(values) == 1 and isinstance(values[0], (list, tuple, set, frozenset)):
            values = tuple(values[0])
        object.__setattr__(self, "values", tuple(values))

    def to_json(self) -> dict[str, Any]:
        return {"op": "one_of", "value": list(self.values)}


@dataclass(frozen=True)
class Prefix:
    """The argument must be a string starting with ``value``."""

    value: str

    def to_json(self) -> dict[str, Any]:
        return {"op": "prefix", "value": self.value}


Constraint = Equals | OneOf | Prefix


def constraint_from_json(obj: dict[str, Any]) -> Constraint:
    op = obj.get("op")
    value = obj.get("value")
    if op == "equals":
        return Equals(value)
    if op == "one_of":
        return OneOf(*list(value or []))
    if op == "prefix":
        return Prefix(str(value))
    raise ValueError(f"unknown constraint op {op!r}")


class Capability:
    """``server:tool`` plus optional per-argument constraints.

    Constraints are keyword arguments. A bare value is shorthand for ``Equals``::

        Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))
    """

    __slots__ = ("constraints", "server", "tool")

    server: str
    tool: str
    constraints: dict[str, Constraint]

    def __init__(self, server: str, tool: str, **constraints: Any) -> None:
        if not server or not tool:
            raise ValueError("a capability needs a non-empty server and tool")
        self.server = server
        self.tool = tool
        self.constraints = {
            k: v if isinstance(v, (Equals, OneOf, Prefix)) else Equals(v)
            for k, v in constraints.items()
        }

    @classmethod
    def parse(cls, text: str) -> Capability:
        """``"github:read_file"`` -> ``Capability("github", "read_file")``."""
        server, sep, tool = text.strip().partition(":")
        if not sep or not server or not tool:
            raise ValueError(f"capability {text!r} must look like 'server:tool'")
        return cls(server, tool)

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> Capability:
        cap = cls(obj["server"], obj["tool"])
        cap.constraints = {
            k: constraint_from_json(v) for k, v in (obj.get("constraints") or {}).items()
        }
        return cap

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"server": self.server, "tool": self.tool}
        if self.constraints:
            out["constraints"] = {k: c.to_json() for k, c in sorted(self.constraints.items())}
        return out

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Capability) and self.to_json() == other.to_json()

    def __hash__(self) -> int:
        return hash((self.server, self.tool, tuple(sorted(self.constraints))))

    def __repr__(self) -> str:
        cs = "".join(f", {k}={c!r}" for k, c in sorted(self.constraints.items()))
        return f"Capability({self.server!r}, {self.tool!r}{cs})"

    def __str__(self) -> str:
        if not self.constraints:
            return f"{self.server}:{self.tool}"
        cs = ",".join(f"{k}={c.to_json()}" for k, c in sorted(self.constraints.items()))
        return f"{self.server}:{self.tool}{{{cs}}}"


CapabilityLike = Capability | str | dict[str, Any]


def capabilities_to_json(caps: Iterable[CapabilityLike] | CapabilityLike) -> list[dict[str, Any]]:
    """Normalize capabilities (objects, ``"server:tool"`` strings, or raw dicts) to wire JSON.

    A comma-separated string such as ``"github:read_file,github:create_issue"`` is split, like
    the CLI's ``--cap``.
    """
    items: list[CapabilityLike]
    items = [caps] if isinstance(caps, (Capability, str, dict)) else list(caps)
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, Capability):
            out.append(item.to_json())
        elif isinstance(item, dict):
            out.append(Capability.from_json(item).to_json())
        else:
            out.extend(Capability.parse(part).to_json() for part in item.split(",") if part.strip())
    return out
