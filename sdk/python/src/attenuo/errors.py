"""Exceptions raised by the SDK.

``Denied`` is a *decision*, not a failure: the server understood the call and said no. Branch
on ``Denied.reason`` (``capability_denied``, ``policy_deny``, ``lease_revoked`` ...), not on the
message text.
"""

from __future__ import annotations

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
