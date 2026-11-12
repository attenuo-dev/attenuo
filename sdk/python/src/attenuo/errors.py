"""Exceptions raised by the SDK.

``Denied`` is a *decision*, not a failure: the server understood the call and said no. Branch
on ``Denied.reason`` (``capability_denied``, ``policy_deny``, ``lease_revoked`` ...), not on the
message text.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

import httpx


class AttenuoError(Exception):
    """Base class for every error the SDK raises, transport failures included."""


class TransportError(AttenuoError, httpx.TransportError):
    """The request got no answer: the connection was refused or dropped, a timeout ran out, a
    proxy or TLS handshake failed. ``__cause__`` is the ``httpx`` error.

    It is also an ``httpx.TransportError``, so ``except httpx.TransportError`` (or
    ``httpx.RequestError``, ``httpx.HTTPError``) written before the SDK wrapped these errors
    still catches it; a handler for one subclass, such as ``httpx.ConnectError``, now needs
    ``isinstance(e.__cause__, httpx.ConnectError)``.
    """

    def __init__(self, message: str, *, request: httpx.Request | None = None) -> None:
        super().__init__(message, request=request)


LimitKind = Literal["calls", "sum", "calls_per", "distinct"]


@dataclass(frozen=True)
class BudgetLimit:
    """One run-limit counter: ``hop`` (position in the chain, root 0), ``kind``, ``arg`` (the
    counted argument as the limit names it, ``arg#host`` for a derived one; ``None`` for
    ``calls``), ``used`` (calls or summed amount; for ``calls_per`` the calls with this value;
    for ``distinct`` how many values the limit has seen) and ``max``.

    The ``limit`` of a ``budget_exhausted`` refusal (:attr:`Denied.limit`) or dry run has this
    shape, and so does an entry of :attr:`StatedBudget.limits`, where ``max`` is optional (when
    given it must equal the limit's). A refusal's ``limit`` can be stated back as it came."""

    hop: int
    kind: LimitKind
    used: int
    arg: str | None = None
    max: int | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"hop": self.hop, "kind": self.kind, "used": self.used}
        if self.arg is not None:
            out["arg"] = self.arg
        if self.max is not None:
            out["max"] = self.max
        return out


@dataclass(frozen=True)
class WindowUsage:
    """A per-user window's figures: allowed ``calls`` of the tool and the sum of its
    ``amount`` input over them."""

    calls: int
    amount: int


@dataclass(frozen=True)
class UserWindow:
    """The originating user's usage of a tool across all their runs in the current UTC
    ``hour`` and ``day`` (run limits phase 3)."""

    hour: WindowUsage
    day: WindowUsage


@dataclass(frozen=True)
class RunUsage:
    """The run's usage of a destructive tool, or of one with an ``outbound`` catalog input,
    before the refused call, as the policy saw it (``context.usage``): allowed ``calls`` of
    this server and tool by every hop of the run, the sum of the catalog's ``amount`` input
    over them, and whether the catalog's destination was seen in one of them.
    ``user_window`` is ``None`` when the server left it out (all its figures zero)."""

    calls: int
    amount: int
    destination_seen: bool
    user_window: UserWindow | None = None


@dataclass(frozen=True)
class UntrustedArg:
    """An argument of the call that copies a value or span of an untrusted result of the run:
    ``arg`` names it, ``seq`` is the ``tool_result`` audit record it matched (``None`` for
    kind ``unreadable``), ``kind`` is ``leaf``, ``entity``, ``kgram`` or ``unreadable``."""

    arg: str
    kind: str
    seq: int | None = None


def _int(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def budget_limit_from_json(v: Any) -> BudgetLimit | None:
    """A :class:`BudgetLimit` from its JSON form; ``None`` when ``v`` is not an object."""
    if not isinstance(v, dict):
        return None
    arg, mx = v.get("arg"), v.get("max")
    return BudgetLimit(
        hop=_int(v.get("hop")),
        kind=str(v.get("kind", "")),  # type: ignore[arg-type]
        used=_int(v.get("used")),
        arg=None if arg is None else str(arg),
        max=mx if isinstance(mx, int) and not isinstance(mx, bool) else None,
    )


def _window(v: Any) -> WindowUsage:
    w = v if isinstance(v, dict) else {}
    return WindowUsage(calls=_int(w.get("calls")), amount=_int(w.get("amount")))


def run_usage_from_json(v: Any) -> RunUsage | None:
    """A :class:`RunUsage` from the ``usage`` of a refusal; ``None`` when ``v`` is not an
    object."""
    if not isinstance(v, dict):
        return None
    uw = v.get("user_window")
    return RunUsage(
        calls=_int(v.get("calls")),
        amount=_int(v.get("amount")),
        destination_seen=v.get("destination_seen") is True,
        user_window=UserWindow(_window(uw.get("hour")), _window(uw.get("day")))
        if isinstance(uw, dict)
        else None,
    )


def untrusted_args_from_json(v: Any) -> list[UntrustedArg]:
    """The ``untrusted_args`` of a refusal; entries that are not objects are skipped."""
    if not isinstance(v, list):
        return []
    out = []
    for item in v:
        if not isinstance(item, dict):
            continue
        seq = item.get("seq")
        out.append(
            UntrustedArg(
                arg=str(item.get("arg", "")),
                kind=str(item.get("kind", "")),
                seq=seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
            )
        )
    return out


class ApiError(AttenuoError):
    """The server answered a non-success status with ``{"error": ..., "detail": ...}``.

    ``decision_id`` is the audit record of a refusal the server recorded (a refused token
    exchange or renewal, a proxy 401 for a lease that is no longer live), else ``None``. It is
    taken from the body only when the ``X-Attenuo-Decision-Id`` header names the same id, the
    proof the proxy gives for its own records (an upstream's answer it relays never carries
    that header).
    """

    def __init__(
        self,
        status: int,
        error: str,
        detail: str = "",
        description: str | None = None,
        decision_id: str | None = None,
    ) -> None:
        self.status = status
        self.error = error
        self.detail = detail
        self.description = description
        self.decision_id = decision_id
        text = f"server answered {status}: {error}"
        if detail:
            text += f": {detail}"
        super().__init__(text)


class Unauthorized(ApiError):
    """HTTP 401: the bearer is missing, malformed, expired or not ours (JSON-RPC ``-32001``).

    Branch on ``reason``, the server's stable code: ``missing_token``, ``invalid_token``,
    ``token_expired``, ``dpop_required``, ``invalid_dpop_proof``, ``use_dpop_nonce``, and from
    the proxy also ``lease_revoked``, ``lease_expired`` or ``lease_unknown`` (the token's lease
    is no longer live). It is the proxy's ``data.reason``, or for a REST route the ``error``
    (``dpop_required`` ...) or, when that is the generic ``unauthorized``, its
    ``error_description``. ``"unauthorized"`` when the answer names no reason. ``error`` keeps
    what it always held: ``"unauthorized"`` for every proxy 401. ``data`` is the proxy's
    JSON-RPC error ``data`` (``{}`` for a REST route). A lease refusal the proxy recorded
    carries the record's id in ``decision_id``.
    """

    def __init__(
        self,
        status: int,
        error: str,
        detail: str = "",
        description: str | None = None,
        decision_id: str | None = None,
        reason: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(status, error, detail, description, decision_id)
        if not reason:
            if error and error not in ("unauthorized", "http_error"):
                reason = error
            else:
                reason = description or "unauthorized"
        self.reason = reason
        self.data: dict[str, Any] = data if data is not None else {}


class RpcError(AttenuoError):
    """A JSON-RPC error that is not a denial (unknown upstream, upstream down, ...)."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"JSON-RPC error {code}: {message}")


class Denied(AttenuoError):
    """The proxy denied a call (JSON-RPC ``-32003``).

    ``reason`` is the stable code from the server; ``decision_id`` is the id of the audit record.
    ``data`` is the error's whole ``data`` object, and the members the server adds are also
    typed:

    - ``limit``: the run limit a ``budget_exhausted`` call would take past its ``max``, as a
      :class:`BudgetLimit`; else ``None``.
    - ``usage``: for a tool the catalog marks destructive or gives an ``outbound`` input, the
      run's usage before this call as a :class:`RunUsage` (with ``user_window`` when a policy
      reads per-user windows and a figure is not zero); else ``None``.
    - ``untrusted_args``: the arguments that copy an untrusted result of the run, as
      :class:`UntrustedArg` values (empty when the server sent none).
    """

    def __init__(
        self,
        reason: str,
        decision_id: str | None = None,
        message: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        self.reason = reason
        self.decision_id = decision_id
        self.data: dict[str, Any] = data if data is not None else {}
        self.limit = budget_limit_from_json(self.data.get("limit"))
        self.usage = run_usage_from_json(self.data.get("usage"))
        self.untrusted_args = untrusted_args_from_json(self.data.get("untrusted_args"))
        self.message = message or f"attenuo: denied: {reason}"
        text = f"{self.message} (decision {decision_id})" if decision_id else self.message
        super().__init__(text)


class ApprovalRequired(Denied):
    """A policy held the call for an approval (JSON-RPC ``-32008``).

    It is a :class:`Denied` with ``reason == "approval_required"``, so code that already catches
    ``Denied`` keeps working. ``approval_id`` names the pending approval: show it to the user,
    who grants it with their own sign-in (``POST /approvals/{id}``), or an operator grants it.
    Then retry the identical call once (``Client.wait_for_approval`` and
    ``Client.call_tool_with_approval`` do this). ``approval_id`` is ``None`` when the server
    could not open an approval, among others when the run already has as many pending
    approvals as the server keeps for one run (32; its diagnostic is ``"too many pending
    approvals for this run"``). The call is then simply denied, and ``call_tool_with_approval``
    raises this error at once, without calling ``on_approval``. ``expires_at`` is when the
    approval lapses; ``call_hash`` is the RFC 8785 hash of the call it is bound to. ``data``,
    ``usage`` and ``untrusted_args`` are set as on :class:`Denied`.
    """

    def __init__(
        self,
        decision_id: str | None,
        approval_id: str | None,
        expires_at: datetime | None = None,
        call_hash: str | None = None,
        message: str = "",
        data: dict[str, Any] | None = None,
    ) -> None:
        self.approval_id = approval_id
        self.expires_at = expires_at
        self.call_hash = call_hash
        super().__init__(
            "approval_required", decision_id, message or "attenuo: approval required", data
        )


class ApprovalNotGranted(AttenuoError):
    """Waiting for an approval ended without a grant.

    ``state`` is ``declined`` (the user or operator said no), ``expired`` (nobody decided in
    time), ``consumed`` (a retry already used the grant) or ``timeout`` (the wait's own
    ``timeout`` ran out while the approval was still pending).
    """

    def __init__(self, approval_id: str, state: str) -> None:
        self.approval_id = approval_id
        self.state = state
        super().__init__(f"approval {approval_id} was not granted: {state}")


class VerificationError(AttenuoError):
    """A token failed local verification (bad signature, expired, wrong issuer, ...)."""


class RefreshError(AttenuoError):
    """The token refresher gave up: the token cannot be kept alive.

    ``reason`` is a stable code: ``lease_revoked`` (the lease was revoked, or the server no
    longer knows it), ``lease_lost`` (an ancestor lease lapsed), ``token_expired`` (the token
    reached ``exp`` before a refresh succeeded), ``refused`` (the server permanently refused a
    renewal or exchange, for example ``invalid_scope`` or a replayed subject token), or
    ``key_mismatch`` (the new token is not bound to the DPoP key of the old one). The message
    never contains a token; ``__cause__`` is the underlying error, if any.
    """

    def __init__(self, reason: str, message: str = "") -> None:
        self.reason = reason
        super().__init__(f"token refresh failed: {reason}" + (f": {message}" if message else ""))
