"""Capabilities and argument constraints, serialized exactly as the Rust ``Capability`` is.

``Capability("github", "read_file", repo=Prefix("alice/public-"))`` becomes::

    {"server": "github", "tool": "read_file",
     "constraints": {"repo": {"op": "prefix", "value": "alice/public-"}}}

For a file path use ``PathPrefix``, which compares by ``/`` segment and refuses ``..``:
``Capability("fs", "read_file", path=PathPrefix("/workspace"))`` admits
``/workspace/a.txt`` but not ``/workspace/../etc/passwd`` or ``/workspace-secrets/x``, which a
``Prefix("/workspace")`` admits.

``Capability("banking", "send_money", amount=Range(0, 2000))`` bounds an integer argument,
both ends inclusive: ``{"amount": {"op": "range", "value": {"min": 0, "max": 2000}}}``.

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

import re
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
    """The argument must be a string starting with ``value``.

    A plain string comparison: ``Prefix("/workspace/")`` admits ``/workspace/../etc/passwd``.
    For file paths use :class:`PathPrefix`."""

    value: str

    def to_json(self) -> dict[str, Any]:
        return {"op": "prefix", "value": self.value}


_ENCODED_SEPARATORS = ("%2e", "%2f", "%5c")
# Characters that NFKC or Windows best-fit conversion turn into `.`, `/` or `\` (SR-105);
# the server's `attenuo_core::LOOKALIKE_SEPARATORS`.
_LOOKALIKE_SEPARATORS = frozenset(
    "\u2024\u2025\u2026\ufe19\ufe30\ufe52\ufe68\uff0e\uff0f\uff3c\u2044\u2215\u29f8"
)
_DOUBLE_ENCODED = re.compile(r"%25[0-9A-Fa-f]{2}")


def path_problem(path: str) -> str | None:
    """Why ``path`` is not a plain path as ``path_prefix`` reads one, or ``None`` when it is.

    The server refuses, rather than normalises, a value or a ``path_prefix`` path that is empty
    or holds a backslash, a control character, a percent-encoded ``.``, ``/`` or ``\\``
    (``%2e``, ``%2f``, ``%5c``, any case), a percent escape that is itself encoded (``%25``
    and two hex digits), a character that normalises to ``.``, ``/`` or ``\\`` (such as
    U+FF0E or U+FF0F), an empty segment (``//``) or a ``.`` or ``..`` segment."""
    if not path:
        return "is empty"
    if "\\" in path:
        return "holds a backslash"
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in path):
        return "holds a control character"
    lowered = path.lower()
    if any(e in lowered for e in _ENCODED_SEPARATORS):
        return "holds a percent-encoded `.`, `/` or `\\`"
    if _DOUBLE_ENCODED.search(path):
        return "holds a percent escape that is itself percent-encoded (`%25` and two hex digits)"
    if any(c in _LOOKALIKE_SEPARATORS for c in path):
        return "holds a character that normalises to `.`, `/` or `\\`"
    if "//" in path:
        return "holds an empty segment (`//`)"
    body = path.removeprefix("/").removesuffix("/")
    if body and any(seg in (".", "..") for seg in body.split("/")):
        return "holds a `.` or `..` segment"
    return None


@dataclass(frozen=True)
class PathPrefix:
    """The argument must be a path at or below ``value``, compared by ``/`` segment.

    ``PathPrefix("/workspace")`` admits ``/workspace`` and ``/workspace/a/b.txt``, not
    ``/workspace-secrets/x``. The server refuses a value with a ``.`` or ``..`` segment, an empty
    segment, a backslash, a control character or a percent-encoded ``.``, ``/`` or ``\\``
    (``/workspace/../etc/passwd`` included) rather than normalising it. A trailing ``/`` on
    ``value`` asks for something below it: ``PathPrefix("/workspace/")`` does not admit
    ``/workspace`` itself. An absolute ``value`` admits only absolute paths, a relative one only
    relative paths. ``value`` must itself be a plain path (:func:`path_problem`); the
    constructor raises ``ValueError`` otherwise, as the server would refuse it."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise ValueError("a path_prefix constraint's path must be a string")
        problem = path_problem(self.value)
        if problem is not None:
            raise ValueError(f"a path_prefix constraint's path {problem}")

    def to_json(self) -> dict[str, Any]:
        return {"op": "path_prefix", "value": self.value}


# The bounds of a Cedar Long, which is what a range bound and a ranged argument are.
_LONG_MIN = -(2**63)
_LONG_MAX = 2**63 - 1


def _is_long(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and _LONG_MIN <= v <= _LONG_MAX


@dataclass(frozen=True)
class Range:
    """The argument must be an integer between ``min`` and ``max``, both inclusive.

    A missing bound is unbounded on that side; at least one is required, and ``min <= max``:
    ``Range(0, 2000)``, ``Range(max=2000)``. The server reads the argument as Cedar does: an
    integer, or a float with no fractional part (``5.0`` is ``5``); anything else, a fraction
    or a numeric string, is outside every range. Serialized as
    ``{"op": "range", "value": {"min": 0, "max": 2000}}``, a missing bound omitted."""

    min: int | None = None
    max: int | None = None

    def __post_init__(self) -> None:
        if self.min is None and self.max is None:
            raise ValueError("a range constraint needs min, max or both")
        for name in ("min", "max"):
            v = getattr(self, name)
            if v is not None and not _is_long(v):
                raise ValueError(f"a range constraint's {name} must be a 64-bit integer")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(
                f"a range constraint's min {self.min} is greater than its max {self.max}"
            )

    def to_json(self) -> dict[str, Any]:
        value: dict[str, int] = {}
        if self.min is not None:
            value["min"] = self.min
        if self.max is not None:
            value["max"] = self.max
        return {"op": "range", "value": value}


Constraint = Equals | OneOf | Prefix | PathPrefix | Range


def constraint_from_json(obj: dict[str, Any]) -> Constraint:
    op = obj.get("op")
    value = obj.get("value")
    if op == "equals":
        return Equals(value)
    if op == "one_of":
        return OneOf(*list(value or []))
    if op == "prefix":
        return Prefix(str(value))
    if op == "path_prefix":
        if not isinstance(value, str):
            raise ValueError("a path_prefix constraint's path must be a string")
        return PathPrefix(value)
    if op == "range":
        # As the server reads it: an object with integer members min and/or max, nothing else.
        if not isinstance(value, dict) or not set(value) <= {"min", "max"}:
            raise ValueError('a range constraint\'s value must be {"min"?: int, "max"?: int}')
        return Range(value.get("min"), value.get("max"))
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

    Constraints are keyword arguments, one per argument. A bare value is shorthand for
    ``Equals``::

        Capability("github", "create_issue", repo=OneOf("acme/api", "acme/web"))
        Capability("banking", "send_money", amount=Range(0, 2000))

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
            k: v if isinstance(v, (Equals, OneOf, Prefix, PathPrefix, Range)) else Equals(v)
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
