"""Signed approval tokens: offline verification for an external PEP (output labelling, ADR-0009).

When an approval is granted, the server's answer carries ``approval_token``: a compact JWS with
header ``typ`` ``attenuo-approval+jwt``, signed with the issuer key that signs delegation tokens
(same ``kid``, same JWKS). Its claims bind it to one call of one hop of one run:

``iss``, ``aud``
    the issuer, as in a delegation token
``sub``, ``by``
    the approver's subject, and ``user`` or ``operator``
``chain_id``, ``lease``
    the delegation run and the lease of the hop that made the call
``ch``
    the call hash, :func:`call_hash`
``iat``, ``exp``, ``jti``
    when it was granted, the approval's expiry, the approval id
``cnf.jkt``
    the calling hop's key thumbprint, when its token is DPoP-bound

An agent retries the call with the token in ``params._meta["dev.attenuo/approval"]``
(:data:`META_APPROVAL_KEY`); :meth:`attenuo.Client.call_tool_with_approval` does this. The
server's approval record is what makes it single use: :func:`verify_approval_token` proves the
grant was made, not that it has not been used.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import EllipsisType
from typing import Any

import rfc8785

from .errors import AttenuoError, VerificationError
from .token import _b64url_decode, _check_ed25519_signature

APPROVAL_TOKEN_TYPE = "attenuo-approval+jwt"
"""Header ``typ`` of an approval token."""

META_APPROVAL_KEY = "dev.attenuo/approval"
"""The ``params._meta`` key that carries an approval token on a retried call."""


@dataclass(frozen=True)
class ApprovalClaims:
    """The verified claims of an approval token."""

    approval_id: str
    """``jti``."""
    approver: str
    """``sub``: the user's subject, or ``urn:attenuo:admin`` for an operator."""
    by: str
    """``user`` or ``operator``."""
    chain_id: str
    lease: str
    call_hash: str
    """``ch``."""
    issued_at: datetime
    expires_at: datetime
    jkt: str | None
    """``cnf.jkt``, or ``None`` for a bearer hop."""
    issuer: str
    audience: str
    raw: dict[str, Any] = field(repr=False)


def call_hash(server: str, tool: str, arguments: dict[str, Any] | None = None) -> str:
    """The hash an approval is bound to: SHA-256, hex, of the RFC 8785 canonical JSON of
    ``{"server", "tool", "arguments"}``, as the server computes it (``ToolCall::call_hash``).
    ``_meta`` is not an argument and is never part of it."""
    canonical = rfc8785.dumps({"server": server, "tool": tool, "arguments": arguments or {}})
    return hashlib.sha256(canonical).hexdigest()


def _decode(part: str, what: str) -> dict[str, Any]:
    try:
        value = json.loads(_b64url_decode(part))
    except ValueError as e:
        raise VerificationError(f"approval token {what} is not JSON: {e}") from e
    if not isinstance(value, dict):
        raise VerificationError(f"approval token {what} is not an object")
    return value


def _time(value: Any, claim: str) -> datetime:
    if not isinstance(value, int) or isinstance(value, bool):
        raise VerificationError(f"missing or non-integer {claim} claim")
    return datetime.fromtimestamp(value, tz=timezone.utc)


def verify_approval_token(
    token: str,
    jwks: dict[str, Any],
    *,
    chain_id: str | None = None,
    lease: str | None = None,
    call_hash: str | None = None,
    jkt: str | EllipsisType | None = ...,
    issuer: str | None = None,
    audience: str | None = None,
    now: float | None = None,
) -> ApprovalClaims:
    """Verify an approval token offline against the issuer's JWKS and return its claims.

    Checks the EdDSA signature (key chosen by ``kid``), header ``typ``, ``exp`` against ``now``
    (default: the clock), ``iss``/``aud`` when given, and each binding that is given:
    ``chain_id`` (the call's run), ``lease`` (the calling hop's lease), ``call_hash`` (see
    :func:`call_hash`) and ``jkt`` (the calling hop's key thumbprint; pass ``None`` for a bearer
    hop, whose token must then carry no ``cnf``; leave it out to skip the check). Raises
    :class:`~attenuo.VerificationError` on any failure. Needs the ``verify`` extra.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise VerificationError("not a JWT: expected three dot-separated parts")
    try:
        header = _decode(parts[0], "header")
        claims = _decode(parts[1], "payload")
    except AttenuoError as e:
        raise VerificationError(str(e)) from e
    _check_ed25519_signature(token.strip(), header, jwks)
    if header.get("typ") != APPROVAL_TOKEN_TYPE:
        raise VerificationError(f"typ is {header.get('typ')!r}, expected {APPROVAL_TOKEN_TYPE!r}")
    expires_at = _time(claims.get("exp"), "exp")
    current = datetime.now(timezone.utc).timestamp() if now is None else now
    if expires_at.timestamp() <= current:
        raise VerificationError("approval token expired")
    strings = {}
    for claim in ("iss", "aud", "sub", "by", "chain_id", "lease", "ch", "jti"):
        value = claims.get(claim)
        if not isinstance(value, str):
            raise VerificationError(f"missing {claim} claim")
        strings[claim] = value
    cnf = claims.get("cnf")
    token_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if cnf is not None and not isinstance(token_jkt, str):
        raise VerificationError("cnf has no jkt")
    checks: list[tuple[str, str | None, str | None]] = [
        ("iss", issuer, strings["iss"]),
        ("aud", audience, strings["aud"]),
        ("chain_id", chain_id, strings["chain_id"]),
        ("lease", lease, strings["lease"]),
        ("ch", call_hash, strings["ch"]),
    ]
    for claim, want, got in checks:
        if want is not None and got != want:
            raise VerificationError(f"{claim} is {got!r}, expected {want!r}")
    if not isinstance(jkt, EllipsisType) and token_jkt != jkt:
        raise VerificationError(f"cnf.jkt is {token_jkt!r}, expected {jkt!r}")
    return ApprovalClaims(
        approval_id=strings["jti"],
        approver=strings["sub"],
        by=strings["by"],
        chain_id=strings["chain_id"],
        lease=strings["lease"],
        call_hash=strings["ch"],
        issued_at=_time(claims.get("iat"), "iat"),
        expires_at=expires_at,
        jkt=token_jkt,
        issuer=strings["iss"],
        audience=strings["aud"],
        raw=claims,
    )
