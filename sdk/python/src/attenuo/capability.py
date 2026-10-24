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

``distinct`` bounds how many different values an argument may take, and ``calls_per`` and
``distinct`` can count the host of a URL argument instead of the whole value::

    Capability("web", "get_webpage").with_limits(distinct=ArgLimit("url", 2, derive="host"))
    # {"server": "web", "tool": "get_webpage",
    #  "limits": {"distinct": {"arg": "url", "max": 2, "derive": "host"}}}

A child token is attenuated by passing such capabilities to ``Client.exchange``. The server
keeps a child's figures no larger than its parent's (it lowers larger ones, and fills in a
limit the child leaves out), and charges every call to every hop.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal


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


LIMIT_KINDS = ("calls", "sum", "calls_per", "distinct")

#: What a ``calls_per`` or ``distinct`` limit may count instead of the argument itself.
#: ``"host"``: the host of a URL argument (lowercased, without port or user info), so two pages
#: of one site are one value. A value with no host cannot be counted and the call is refused.
Derive = Literal["host"]
DERIVATIONS: tuple[str, ...] = ("host",)

# The most a limit may allow: Cedar's largest Long, as on the server.
MAX_LIMIT = 2**63 - 1


@dataclass(frozen=True)
class ArgLimit:
    """A limit on one argument: the ``sum``, ``calls_per`` or ``distinct`` of a :class:`Limits`.

    ``max`` is a total for ``sum``, calls per value for ``calls_per`` and values for
    ``distinct``. ``derive="host"`` (``calls_per`` and ``distinct`` only) counts the host of a
    URL argument; records and errors then name the argument ``url#host``."""

    arg: str
    max: int
    derive: Derive | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.arg, str) or not self.arg:
            raise ValueError("a limit's arg must be a non-empty string")
        if not isinstance(self.max, int) or isinstance(self.max, bool):
            raise ValueError("a limit's max must be an integer")
        if not 0 <= self.max <= MAX_LIMIT:
            raise ValueError(f"a limit's max must be between 0 and {MAX_LIMIT}")
        if self.derive is not None and self.derive not in DERIVATIONS:
            raise ValueError(
                f"unknown derivation {self.derive!r} (one of {', '.join(DERIVATIONS)})"
            )

    @property
    def counted(self) -> str:
        """What the limit counts as the server names it: ``arg``, or ``arg#host``."""
        return f"{self.arg}#{self.derive}" if self.derive else self.arg

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"arg": self.arg, "max": self.max}
        if self.derive is not None:
            out["derive"] = self.derive
        return out

    @classmethod
    def from_json(cls, kind: str, value: Any) -> ArgLimit:
        allowed = {"arg", "max"} if kind == "sum" else {"arg", "max", "derive"}
        if not isinstance(value, dict) or not {"arg", "max"} <= set(value) <= allowed:
            shape = '{"arg": str, "max": int >= 0}'
            if kind != "sum":
                shape = '{"arg": str, "max": int >= 0, "derive"?: "host"}'
            raise ValueError(f"limits.{kind} must be {shape}")
        try:
            return cls(value["arg"], value["max"], value.get("derive"))
        except ValueError as e:
            raise ValueError(f"limits.{kind}: {e}") from None


ArgLimitLike = ArgLimit | tuple[str, int] | tuple[str, int, Derive | None]


def _arg_limit(kind: str, v: ArgLimitLike) -> ArgLimit:
    if isinstance(v, ArgLimit):
        lim = v
    elif isinstance(v, tuple) and len(v) in (2, 3):
        lim = ArgLimit(*v)
    else:
        raise ValueError(f"{kind} must be an ArgLimit or an (arg, max[, derive]) tuple")
    if kind == "sum" and lim.derive is not None:
        raise ValueError("a sum counts the argument itself and takes no derive")
    return lim


@dataclass(frozen=True)
class Limits:
    """The run limits of one capability (ADR-0010), every member optional.

    - ``calls``: at most this many allowed calls matched by the capability.
    - ``sum``: the sum of an integer argument over those calls is at most ``max``.
    - ``calls_per``: at most ``max`` calls per value of an argument (each list element counts).
    - ``distinct``: at most ``max`` different values of an argument (each list element counts).

    The figures are a ceiling in the signed token; what has been spent lives on the server.
    """

    calls: int | None = None
    sum: ArgLimit | None = None
    calls_per: ArgLimit | None = None
    distinct: ArgLimit | None = None

    def __post_init__(self) -> None:
        c = self.calls
        if c is not None and (
            not isinstance(c, int) or isinstance(c, bool) or not 0 <= c <= MAX_LIMIT
        ):
            raise ValueError("limits.calls must be an integer >= 0")
        if self.sum is not None and self.sum.derive is not None:
            raise ValueError("a sum counts the argument itself and takes no derive")

    def is_empty(self) -> bool:
        return (
            self.calls is None
            and self.sum is None
            and self.calls_per is None
            and self.distinct is None
        )

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.calls is not None:
            out["calls"] = self.calls
        for kind in ("sum", "calls_per", "distinct"):
            lim = getattr(self, kind)
            if lim is not None:
                out[kind] = lim.to_json()
        return out

    @classmethod
    def from_json(cls, obj: Any) -> Limits:
        """Read a ``limits`` object. A kind or derivation this SDK does not know is refused, as
        the server refuses it, rather than dropped."""
        if obj is None:
            return cls()
        if not isinstance(obj, dict):
            raise ValueError("limits must be an object")
        unknown = [k for k in obj if k not in LIMIT_KINDS]
        if unknown:
            raise ValueError(f"unknown limit kind {unknown[0]!r} (one of {', '.join(LIMIT_KINDS)})")
        calls = obj.get("calls")
        if "calls" in obj and (not isinstance(calls, int) or isinstance(calls, bool) or calls < 0):
            raise ValueError("limits.calls must be an integer >= 0")
        args = {
            kind: ArgLimit.from_json(kind, obj[kind])
            for kind in ("sum", "calls_per", "distinct")
            if kind in obj
        }
        return cls(calls=calls, **args)


def _limits_from_json(obj: Any) -> dict[str, Any]:
    """Check a ``limits`` object (see :meth:`Limits.from_json`) and return its wire form."""
    return Limits.from_json(obj).to_json()


class Capability:
    """``server:tool`` plus optional per-argument constraints and run limits.

    Constraints are keyword arguments. A bare value is shorthand for ``Equals``::

        Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))

    Limits are set with :meth:`with_limits`, and read back typed with :attr:`typed_limits`.
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
        calls: int | Limits | None = None,
        sum: ArgLimitLike | None = None,
        calls_per: ArgLimitLike | None = None,
        distinct: ArgLimitLike | None = None,
    ) -> Capability:
        """Set run limits (ADR-0010) and return ``self``, replacing any set before: at most
        ``calls`` matched calls, a total of at most ``sum[1]`` over argument ``sum[0]``, at most
        ``calls_per[1]`` calls per value of argument ``calls_per[0]``, and at most
        ``distinct[1]`` different values of argument ``distinct[0]``.

        Each argument limit is an ``(arg, max)`` tuple or an :class:`ArgLimit`;
        ``ArgLimit("url", 2, derive="host")`` (or ``("url", 2, "host")``) counts URL hosts.
        A whole :class:`Limits` may be passed instead, as the only argument."""
        if isinstance(calls, Limits):
            if sum is not None or calls_per is not None or distinct is not None:
                raise ValueError("pass either a Limits or keyword limits, not both")
            self.limits = calls.to_json()
            return self
        self.limits = Limits(
            calls=calls,
            sum=None if sum is None else _arg_limit("sum", sum),
            calls_per=None if calls_per is None else _arg_limit("calls_per", calls_per),
            distinct=None if distinct is None else _arg_limit("distinct", distinct),
        ).to_json()
        return self

    @property
    def typed_limits(self) -> Limits:
        """The capability's run limits as a :class:`Limits` (empty when it has none)."""
        return Limits.from_json(self.limits)

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
