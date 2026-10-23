from __future__ import annotations

import pytest

from onbehalf import OnbehalfError, VerificationError, decode_token, verify_token
from onbehalf.capability import Prefix
from onbehalf.token import parse_time

from .helpers import Signer, b64


def test_decode_chain() -> None:
    s = Signer()
    jwt = s.mint(
        ("planner", "coder"),
        caps=[
            {
                "server": "github",
                "tool": "read_file",
                "constraints": {"repo": {"op": "prefix", "value": "a/"}},
            }
        ],
    )
    t = decode_token(jwt)
    assert t.subject == "alice"
    assert t.agent == "coder"
    assert t.chain.agents == ("planner", "coder")
    assert t.chain.depth == 2
    assert t.lease == "lease-1"
    assert t.capabilities[0].constraints["repo"] == Prefix("a/")
    assert t.chain.user.authenticated_at.microsecond == 500000
    assert t.chain.hops[0].issued_at.tzinfo is not None
    assert not t.verified
    assert 800 < t.expires_in <= 900
    assert str(t) == jwt
    assert jwt not in repr(t)


def test_decode_rejects_garbage() -> None:
    for bad in ("nope", "a.b", "a.b.c.d", "a.b.c", f"{b64(b'{}')}.{b64(b'{}')}.sig"):
        with pytest.raises(OnbehalfError):
            decode_token(bad)


def test_parse_time_nanoseconds() -> None:
    assert parse_time("2026-10-22T22:22:40.733780689Z").microsecond == 733780
    assert parse_time("2026-10-22T22:22:40Z").second == 40
    assert parse_time("2026-10-22T22:22:40.5+00:00").microsecond == 500000


def test_verify_ok() -> None:
    s = Signer()
    t = verify_token(s.mint(("a", "b")), s.jwks, issuer="http://ob.test", audience="onbehalf")
    assert t.verified
    assert t.agent == "b"


def test_verify_wrong_key_and_tamper() -> None:
    s, other = Signer(), Signer()
    jwt = s.mint()
    with pytest.raises(VerificationError, match="signature"):
        verify_token(jwt, other.jwks)
    head, payload, sig = jwt.split(".")
    forged = b64(__import__("base64").urlsafe_b64decode(payload + "==").replace(b"alice", b"mallo"))
    with pytest.raises(VerificationError, match="signature"):
        verify_token(f"{head}.{forged}.{sig}", s.jwks)


def test_verify_claims() -> None:
    s = Signer()
    with pytest.raises(VerificationError, match="expired"):
        verify_token(s.mint(exp_delta=-5), s.jwks)
    with pytest.raises(VerificationError, match="aud"):
        verify_token(s.mint(), s.jwks, audience="other")
    with pytest.raises(VerificationError, match="iss"):
        verify_token(s.mint(), s.jwks, issuer="other")
    with pytest.raises(VerificationError, match="token type"):
        verify_token(s.mint(claims={"typ": "JWT"}), s.jwks)
    with pytest.raises(VerificationError, match="sub"):
        verify_token(s.mint(claims={"sub": "bob"}), s.jwks)
    with pytest.raises(VerificationError, match="act"):
        verify_token(s.mint(("a", "b"), claims={"act": {"sub": "b"}}), s.jwks)
    with pytest.raises(VerificationError, match="alg"):
        verify_token(s.mint(header={"alg": "HS256"}), s.jwks)


def test_verify_key_selection() -> None:
    s = Signer()
    jwt = s.mint(header={"kid": "k1"})
    assert verify_token(jwt, s.jwks).verified
    with pytest.raises(VerificationError, match="kid"):
        verify_token(s.mint(header={"kid": "zzz"}), s.jwks)
    with pytest.raises(VerificationError, match="no Ed25519"):
        verify_token(jwt, {"keys": []})
