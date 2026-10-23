"""Delegation tokens: decoding without verification, and local Ed25519 verification.

A delegation token is a compact JWS (``typ`` ``onbehalf+jwt``, ``alg`` ``EdDSA``) whose claims
carry the delegation ``chain``: the originating user and one hop per agent, each with its
capabilities, expiry and lease id. :func:`decode_token` reads those claims **without checking
anything**. Use :func:`verify_token` (or ``Client.inspect(jwt, verify=True)``) to check the
signature against the server's JWKS.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .capability import Capability
from .errors import OnbehalfError, VerificationError

TOKEN_TYPE = "onbehalf+jwt"

_FRACTION = re.compile(r"\.(\d+)")


def parse_time(text: str) -> datetime:
    """Parse an RFC 3339 timestamp, including the 9-digit fractions the server writes."""
    t = text.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    t = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), t, count=1)
    dt = datetime.fromisoformat(t)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _b64url_decode(part: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError) as e:
        raise OnbehalfError(f"not base64url: {e}") from e


@dataclass(frozen=True)
class User:
    """The originating user: who the whole chain acts for."""

    subject: str
    issuer: str
    authenticated_at: datetime
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Hop:
    """One delegation step."""

    agent: str
    capabilities: tuple[Capability, ...]
    issued_at: datetime
    expires_at: datetime
    lease: str


@dataclass(frozen=True)
class Chain:
    """Who the chain is for, and each agent that acted for them (root first)."""

    user: User
    hops: tuple[Hop, ...]

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def current_agent(self) -> str:
        return self.hops[-1].agent

    @property
    def leases(self) -> tuple[str, ...]:
        return tuple(h.lease for h in self.hops)

    @property
    def agents(self) -> tuple[str, ...]:
        return tuple(h.agent for h in self.hops)


def chain_from_json(obj: dict[str, Any]) -> Chain:
    u = obj["originating_user"]
    user = User(
        subject=u["subject"],
        issuer=u["issuer"],
        authenticated_at=parse_time(u["authenticated_at"]),
        attributes=dict(u.get("attributes") or {}),
    )
    hops = tuple(
        Hop(
            agent=h["agent"],
            capabilities=tuple(Capability.from_json(c) for c in h["capabilities"]),
            issued_at=parse_time(h["issued_at"]),
            expires_at=parse_time(h["expires_at"]),
            lease=h["lease"],
        )
        for h in obj["hops"]
    )
    return Chain(user=user, hops=hops)


@dataclass(frozen=True)
class Token:
    """A delegation token plus what it says.

    ``chain`` and ``claims`` are decoded from the JWT and are **not trusted** unless
    ``verified`` is true (set by ``inspect(..., verify=True)``). ``lease`` is the lease of the
    last hop; revoke it to stop this agent and everything delegated from it.

    ``str(token)`` is the JWT; ``repr`` does not print it.
    """

    jwt: str = field(repr=False)
    lease: str
    expires_at: datetime
    chain: Chain
    claims: dict[str, Any] = field(repr=False, compare=False, default_factory=dict)
    header: dict[str, Any] = field(repr=False, compare=False, default_factory=dict)
    verified: bool = field(default=False, compare=False)

    def __str__(self) -> str:
        return self.jwt

    @property
    def subject(self) -> str:
        """The originating user's subject."""
        return self.chain.user.subject

    @property
    def agent(self) -> str:
        """The agent this token was issued to (the last hop)."""
        return self.chain.current_agent

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        return self.chain.hops[-1].capabilities

    @property
    def expires_in(self) -> float:
        """Seconds until the token expires (negative once it has)."""
        return (self.expires_at - datetime.now(timezone.utc)).total_seconds()


def decode_token(jwt: str, lease: str | None = None) -> Token:
    """Decode a delegation token. **Nothing is verified**: this is whatever the sender wrote."""
    jwt = jwt.strip()
    parts = jwt.split(".")
    if len(parts) != 3:
        raise OnbehalfError("not a JWT: expected three dot-separated parts")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
    except ValueError as e:
        raise OnbehalfError(f"JWT is not JSON: {e}") from e
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OnbehalfError("JWT header and payload must be JSON objects")
    try:
        chain = chain_from_json(claims["chain"])
        exp = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
    except (KeyError, TypeError, ValueError) as e:
        raise OnbehalfError(
            f"payload is not an onbehalf delegation token (bad or missing {e})"
        ) from e
    if not chain.hops:
        raise OnbehalfError("token chain has no hops")
    return Token(
        jwt=jwt,
        lease=lease or chain.hops[-1].lease,
        expires_at=exp,
        chain=chain,
        claims=claims,
        header=header,
    )


def _act_agents(act: Any) -> list[str]:
    """``act`` nests the current agent outermost; return root first."""
    out: list[str] = []
    while isinstance(act, dict):
        out.append(str(act.get("sub")))
        act = act.get("act")
    return out[::-1]


def verify_token(
    jwt: str,
    jwks: dict[str, Any],
    *,
    issuer: str | None = None,
    audience: str | None = None,
    now: float | None = None,
) -> Token:
    """Verify ``jwt`` against a JWKS document and return the decoded, verified token.

    Checks: ``alg`` is ``EdDSA``, the Ed25519 signature (key chosen by ``kid`` when the header
    has one, else the first Ed25519 key), ``typ``, ``exp``, ``iss``/``aud`` (pinned when given,
    otherwise only required to be present), and that ``sub`` and ``act`` agree with ``chain``.
    The detached ``ou_sig`` over the user block is not checked here; the server checks it on
    every request. Needs the ``verify`` extra (``cryptography``).
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise OnbehalfError(
            "verifying a token needs the 'cryptography' package: pip install 'onbehalf[verify]'"
        ) from e

    tok = decode_token(jwt)
    if tok.header.get("alg") != "EdDSA":
        raise VerificationError(f"unsupported alg {tok.header.get('alg')!r}, expected EdDSA")
    kid = tok.header.get("kid")
    keys = [
        k
        for k in jwks.get("keys", [])
        if k.get("kty") == "OKP"
        and k.get("crv") == "Ed25519"
        and (kid is None or k.get("kid") == kid)
    ]
    if not keys:
        raise VerificationError(f"JWKS has no Ed25519 key{f' with kid {kid!r}' if kid else ''}")
    try:
        raw = _b64url_decode(keys[0]["x"])
        if len(raw) != 32:
            raise VerificationError(f"JWK x is {len(raw)} bytes, expected 32")
        public = Ed25519PublicKey.from_public_bytes(raw)
        head_b64, payload_b64, sig_b64 = jwt.strip().split(".")
        public.verify(_b64url_decode(sig_b64), f"{head_b64}.{payload_b64}".encode("ascii"))
    except InvalidSignature as e:
        raise VerificationError("signature does not match the server's key") from e
    except (KeyError, OnbehalfError, ValueError) as e:
        raise VerificationError(f"bad JWKS key: {e}") from e

    c = tok.claims
    if c.get("typ") != TOKEN_TYPE:
        raise VerificationError(f"unexpected token type {c.get('typ')!r}")
    if int(c["exp"]) <= (time.time() if now is None else now):
        raise VerificationError("token expired")
    for claim, want in (("iss", issuer), ("aud", audience)):
        if not isinstance(c.get(claim), str):
            raise VerificationError(f"missing {claim} claim")
        if want is not None and c[claim] != want:
            raise VerificationError(f"{claim} is {c[claim]!r}, expected {want!r}")
    if c.get("sub") != tok.chain.user.subject:
        raise VerificationError("sub does not match the chain's originating user")
    if _act_agents(c.get("act")) != list(tok.chain.agents):
        raise VerificationError("act does not match the chain's agents")
    return Token(
        jwt=tok.jwt,
        lease=tok.lease,
        expires_at=tok.expires_at,
        chain=tok.chain,
        claims=tok.claims,
        header=tok.header,
        verified=True,
    )
