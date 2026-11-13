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


def _stable_code_of(data: Any) -> str | None:
    """The stable code of a JSON-RPC error's ``data``: ``data["code"]``, or for a server older
    than the ``code`` member ``data["reason"]``, else ``None`` (no ``data`` object, or neither
    member a non-empty string)."""
    if not isinstance(data, dict):
        return None
    for key in ("code", "reason"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return None


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


class TransportTimeout(TransportError, httpx.TimeoutException):
    """A :class:`TransportError` because a timeout ran out: the client's ``timeout`` (connect,
    read, write or pool; ``__cause__`` is the ``httpx.TimeoutException``), or a streamed call's
    total ``deadline`` (no ``__cause__``). It is also an ``httpx.TimeoutException``.

    Branch on it to retry a slow call without retrying a refused connection, for instance.
    """


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
    """The server answered a non-success status with ``{"error": ..., "code": ...,
    "detail": ...}``.

    ``code`` is the server's stable machine-readable code (``invalid_request``,
    ``audience_mismatch``, ``token_expired``, ...; the list is in the HTTP reference under
    "Errors"): branch on it, never on ``detail``, which is text for people and may change.
    For a server that sends no ``code`` it is the ``error_description`` sub-code, or else
    ``error``. ``error`` is the OAuth-style error (``invalid_grant``, ``unauthorized``, ...) and
    ``description`` the ``error_description``, which is deprecated as a machine field.
    ``stable_code`` is the same string as ``code``, under the name :class:`RpcError` and
    :class:`Denied` use, so one attribute reads the stable code of every error the server
    answered with.

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
        code: str | None = None,
    ) -> None:
        self.status = status
        self.error = error
        self.detail = detail
        self.description = description
        self.decision_id = decision_id
        self.code: str = code or description or error
        text = f"server answered {status}: {error}"
        if detail:
            text += f": {detail}"
        super().__init__(text)

    @property
    def stable_code(self) -> str:
        """The server's stable code: the same string as ``code``."""
        return self.code


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
    carries the record's id in ``decision_id``. ``code`` is the stable code of the answer (see
    :class:`ApiError`); for a proxy 401 it equals ``reason``.
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
        code: str | None = None,
    ) -> None:
        super().__init__(status, error, detail, description, decision_id, code)
        if not reason:
            if error and error not in ("unauthorized", "http_error"):
                reason = error
            else:
                reason = description or "unauthorized"
        self.reason = reason
        if not code:
            self.code = reason
        self.data: dict[str, Any] = data if data is not None else {}


def _data_code(data: dict[str, Any] | None) -> str | None:
    """``data["code"]`` when it is a non-empty string, else ``None``."""
    value = data.get("code") if data is not None else None
    return value if isinstance(value, str) and value else None


class Unavailable(ApiError):
    """HTTP 503 from the server itself: it refused the request for its own load or state, not
    for anything about the request or its token. It is not a :class:`Denied`, nor an
    :class:`Unauthorized`: no decision was made, so code that catches denials does not catch it.

    ``reason`` is the server's stable code: on a REST route the ``error_description`` of its
    ``temporarily_unavailable`` answer, on ``/mcp/{server}`` the ``data.reason`` of JSON-RPC
    ``-32006``. ``code`` (and ``stable_code``) is the proxy's ``data.code`` when it sends one
    (the same string as ``data.reason``), else ``reason``. ``retry_after`` is the
    ``Retry-After`` header in whole seconds, ``None`` when it is missing or not a number.
    ``status`` is 503 and ``error`` is ``"temporarily_unavailable"``; ``data`` is the proxy's
    JSON-RPC error ``data`` (``{}`` for a REST route).

    - ``overloaded``: ``[limits] max_in_flight`` requests were already running. The request was
      refused before any work (no decision, no audit record, nothing sent upstream), so it is
      safe to retry after ``retry_after``. The client's ``max_retries`` retries it.
    - ``request_timeout`` (REST routes): no answer within ``[limits] request_timeout_seconds``.
      The handler may have done its work (an issued token, a decision and its audit record), so
      it is never retried for you.
    - Others: ``jwks_unavailable``, ``dpop_replay_cache_full`` and, on the proxy,
      ``session_registry_full`` (the upstream answered ``initialize`` and the proxy then closed
      that session). Not retried for you.

    On ``/mcp/{server}`` a ``-32006`` counts as the proxy's own only with a ``Retry-After``
    header, which the proxy sets on its refusals and never relays from an upstream; without it,
    it stays an :class:`RpcError`, as an upstream's error.
    """

    def __init__(
        self,
        reason: str,
        retry_after: int | None = None,
        detail: str = "",
        data: dict[str, Any] | None = None,
        status: int = 503,
    ) -> None:
        super().__init__(
            status, "temporarily_unavailable", detail, reason, code=_data_code(data) or reason
        )
        self.reason = reason
        self.retry_after = retry_after
        self.data: dict[str, Any] = data if data is not None else {}


class RateLimited(ApiError):
    """HTTP 429: the caller is over a rate limit of the server. It is not a :class:`Denied`, nor
    an :class:`Unauthorized`: the token is good and no decision was made, so code that catches
    denials does not catch it.

    ``reason`` is the server's stable code: ``error_description`` on a REST route, the
    ``data.reason`` of JSON-RPC ``-32007`` on ``/mcp/{server}``. ``code`` (and ``stable_code``)
    is the proxy's ``data.code`` when it sends one, else ``reason``. ``retry_after`` is the
    ``Retry-After`` header in whole seconds (until the caller's minute ends), ``None`` when it is
    missing or not a number. ``status`` is 429 and ``error`` is ``"rate_limited"``; ``data`` is
    the proxy's JSON-RPC error ``data`` (``{}`` for a REST route).

    - ``rate_limited``: ``POST /token`` over ``[limits] token_requests_per_minute`` (per agent)
      or ``token_unauthenticated_requests_per_minute`` (per address), or ``/mcp/{server}`` over
      ``mcp_requests_per_minute`` (per run). The request was refused before the server did the
      work (no token issued, no decision, no audit record, nothing sent upstream), so it is safe
      to retry after ``retry_after``. The client's ``max_retries`` retries it.
    - ``too_many_sessions`` (proxy): the principal holds ``[proxy] max_sessions_per_principal``
      live sessions; the upstream answered ``initialize`` and the proxy then closed that
      session. Close a session first; not retried for you.

    On ``/mcp/{server}`` a ``-32007`` counts as the proxy's own only with a ``Retry-After``
    header (see :class:`Unavailable`).
    """

    def __init__(
        self,
        reason: str,
        retry_after: int | None = None,
        detail: str = "",
        data: dict[str, Any] | None = None,
        status: int = 429,
    ) -> None:
        super().__init__(status, "rate_limited", detail, reason, code=_data_code(data) or reason)
        self.reason = reason
        self.retry_after = retry_after
        self.data: dict[str, Any] = data if data is not None else {}


class RpcError(AttenuoError):
    """A JSON-RPC error that is not a denial (unknown upstream, upstream down, ...).

    ``code`` is the JSON-RPC error number (``-32002``, ``-32005``, ...). ``stable_code`` is the
    server's stable machine-readable code (``unknown_server``, ``upstream_unreachable``, ...;
    the list is in the HTTP reference under "Errors"): ``data["code"]``, or ``data["reason"]``
    for a server that sends no ``code``, else ``None``. Branch on it, not on ``message``. An
    error the proxy relays from the upstream keeps the upstream's own ``data``, so its
    ``stable_code`` is whatever the upstream put there, often ``None``.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data
        self.stable_code: str | None = _stable_code_of(data)
        super().__init__(f"JSON-RPC error {code}: {message}")


class Denied(AttenuoError):
    """The proxy denied a call (JSON-RPC ``-32003``).

    ``reason`` is the stable code from the server; ``decision_id`` is the id of the audit record.
    ``stable_code`` is the stable code under the name :class:`ApiError` and :class:`RpcError`
    share: ``data["code"]``, or ``data["reason"]`` for an older server, else ``reason``; for a
    denial the server sends it is the same string as ``reason``. ``data`` is the error's whole
    ``data`` object, and the members the server adds are also typed:

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
        self.stable_code: str = _stable_code_of(self.data) or reason
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
