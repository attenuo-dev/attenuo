"""Exceptions raised by the SDK.

``Denied`` is a *decision*, not a failure: the server understood the call and said no. Branch
on ``Denied.reason`` (``capability_denied``, ``policy_deny``, ``lease_revoked`` ...), not on the
message text.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


class AttenuoError(Exception):
    """Base class for every error the SDK raises on purpose."""


class ApiError(AttenuoError):
    """The server answered a non-success status with ``{"error": ..., "detail": ...}``."""

    def __init__(
        self,
        status: int,
        error: str,
        detail: str = "",
        description: str | None = None,
    ) -> None:
        self.status = status
        self.error = error
        self.detail = detail
        self.description = description
        text = f"server answered {status}: {error}"
        if detail:
            text += f": {detail}"
        super().__init__(text)


class Unauthorized(ApiError):
    """HTTP 401: the bearer is missing, malformed, expired or not ours (JSON-RPC ``-32001``)."""


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
    """

    def __init__(self, reason: str, decision_id: str | None = None, message: str = "") -> None:
        self.reason = reason
        self.decision_id = decision_id
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
    approval lapses; ``call_hash`` is the RFC 8785 hash of the call it is bound to.
    """

    def __init__(
        self,
        decision_id: str | None,
        approval_id: str | None,
        expires_at: datetime | None = None,
        call_hash: str | None = None,
        message: str = "",
    ) -> None:
        self.approval_id = approval_id
        self.expires_at = expires_at
        self.call_hash = call_hash
        super().__init__("approval_required", decision_id, message or "attenuo: approval required")


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
