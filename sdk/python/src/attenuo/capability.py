"""Capabilities and argument constraints, serialized exactly as the Rust ``Capability`` is.

``Capability("github", "read_file", repo=Prefix("alice/public-"))`` becomes::

    {"server": "github", "tool": "read_file",
     "constraints": {"repo": {"op": "prefix", "value": "alice/public-"}}}

``constraints`` is omitted when empty. ``server`` and ``tool`` are an exact name, ``*``, or a
prefix glob such as ``read_*``.

Run limits (ADR-0010) ride along as ``limits``, omitted when empty::

    Capability("banking", "send_money").with_limits(calls=1, sum=("amount", 10))
    # {"server": "banking", "tool": "send_money",
    #  "limits": {"calls": 1, "sum": {"arg": "amount", "max": 10}}}
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


LIMIT_KINDS = ("calls", "sum", "calls_per")


def _limits_from_json(obj: Any) -> dict[str, Any]:
    """Check a ``limits`` object: only ``calls`` (an integer >= 0) and ``sum`` / ``calls_per``
    (``{"arg": str, "max": int >= 0}``). A kind this SDK does not know is refused, as the
    server refuses it, rather than dropped."""
    if obj is None:
        return {}
    if not isinstance(obj, dict):
        raise ValueError("limits must be an object")
    out: dict[str, Any] = {}
    for kind, value in obj.items():
        if kind == "calls":
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("limits.calls must be an integer >= 0")
            out[kind] = value
        elif kind in ("sum", "calls_per"):
            ok = (
                isinstance(value, dict)
                and set(value) == {"arg", "max"}
                and isinstance(value["arg"], str)
                and value["arg"]
                and isinstance(value["max"], int)
                and not isinstance(value["max"], bool)
                and value["max"] >= 0
            )
            if not ok:
                raise ValueError(f'limits.{kind} must be {{"arg": str, "max": int >= 0}}')
            out[kind] = {"arg": value["arg"], "max": value["max"]}
        else:
            raise ValueError(f"unknown limit kind {kind!r} (one of {', '.join(LIMIT_KINDS)})")
    return out


class Capability:
    """``server:tool`` plus optional per-argument constraints and run limits.

    Constraints are keyword arguments. A bare value is shorthand for ``Equals``::

        Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))

    Limits are set with :meth:`with_limits`.
    """

    __slots__ = ("constraints", "limits", "server", "tool")

    server: str
    tool: str
    constraints: dict[str, Constraint]
    limits: dict[str, Any]

    def __init__(self, server: str, tool: str, **constraints: Any) -> None:
        if not server or not tool:
            raise ValueError("a capability needs a non-empty server and tool")
        self.server = server
        self.tool = tool
        self.constraints = {
            k: v if isinstance(v, (Equals, OneOf, Prefix)) else Equals(v)
            for k, v in constraints.items()
        }
        self.limits = {}

    def with_limits(
        self,
        calls: int | None = None,
        sum: tuple[str, int] | None = None,
        calls_per: tuple[str, int] | None = None,
    ) -> Capability:
        """Set run limits (ADR-0010) and return ``self``: at most ``calls`` matched calls, a
        total of at most ``sum[1]`` over argument ``sum[0]``, at most ``calls_per[1]`` calls per
        value of argument ``calls_per[0]``."""
        raw: dict[str, Any] = {}
        if calls is not None:
            raw["calls"] = calls
        if sum is not None:
            raw["sum"] = {"arg": sum[0], "max": sum[1]}
        if calls_per is not None:
            raw["calls_per"] = {"arg": calls_per[0], "max": calls_per[1]}
        self.limits = _limits_from_json(raw)
        return self

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
        cap.limits = _limits_from_json(obj.get("limits"))
        return cap

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"server": self.server, "tool": self.tool}
        if self.constraints:
            out["constraints"] = {k: c.to_json() for k, c in sorted(self.constraints.items())}
        if self.limits:
            out["limits"] = dict(self.limits)
        return out

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Capability) and self.to_json() == other.to_json()

    def __hash__(self) -> int:
        return hash((self.server, self.tool, tuple(sorted(self.constraints))))

    def __repr__(self) -> str:
        cs = "".join(f", {k}={c!r}" for k, c in sorted(self.constraints.items()))
        lim = f".with_limits({self.limits!r})" if self.limits else ""
        return f"Capability({self.server!r}, {self.tool!r}{cs}){lim}"

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
