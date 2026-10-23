"""Sender-constrained tokens: DPoP proofs (RFC 9449).

A token bound to a key carries ``cnf.jkt``, the RFC 7638 thumbprint of that key, and the
server accepts it only with a DPoP proof made by the key for each request. Give a client a
``dpop_key`` and it does this for you: every request carries a proof, exchanges bind the new
token to the key, and bound tokens are sent as ``Authorization: DPoP <token>``.

Keys are private JWKs: Ed25519 (``{"kty": "OKP", "crv": "Ed25519", "x": ..., "d": ...}``, what
``attenuo key gen --dpop`` writes) or P-256 (``{"kty": "EC", "crv": "P-256", ...}``). Signing
needs the ``cryptography`` package (``pip install 'attenuo[dpop]'``).

**Server nonces** (RFC 9449 §8). A server with ``[token] dpop_nonce = "required"`` wants a
``nonce`` it issued in every proof. It sends the current one in a ``DPoP-Nonce`` response header
and refuses a proof without it with ``use_dpop_nonce``. The clients keep the latest nonce they
were sent (:class:`NonceCache`), put it in every proof, and retry a request once when the server
answers ``use_dpop_nonce``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

from .errors import AttenuoError

#: ``typ`` of a DPoP proof.
PROOF_TYPE = "dpop+jwt"
#: Sign-off claim naming the new token's key thumbprint.
SIGN_OFF_CHILD_JKT = "child_jkt"
#: Sign-off claim naming the new token's agent.
SIGN_OFF_CHILD_ACTOR = "child_actor"
#: Response header carrying the server's current DPoP nonce.
NONCE_HEADER = "DPoP-Nonce"
#: ``error`` of a refusal asking for a proof with the server's nonce.
USE_DPOP_NONCE = "use_dpop_nonce"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def access_token_hash(token: str) -> str:
    """``ath``: base64url of the SHA-256 of the token."""
    return _b64(hashlib.sha256(token.encode("ascii")).digest())


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint of an Ed25519 or P-256 JWK (private members are ignored)."""
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        members: dict[str, Any] = {"crv": crv, "kty": kty, "x": jwk["x"]}
    elif kty == "EC" and crv == "P-256":
        members = {"crv": crv, "kty": kty, "x": jwk["x"], "y": jwk["y"]}
    else:
        raise AttenuoError(f"unsupported DPoP key type {kty!r} / curve {crv!r}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return _b64(hashlib.sha256(canonical.encode()).digest())


def _crypto() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise AttenuoError(
            "DPoP keys need the `cryptography` package: pip install 'attenuo[dpop]'"
        ) from e
    return ec, ed25519


class DpopKey:
    """A DPoP private key that signs proofs (``EdDSA`` or ``ES256``)."""

    def __init__(self, jwk: dict[str, Any]) -> None:
        ec, ed25519 = _crypto()
        if "d" not in jwk:
            raise AttenuoError("a DPoP key must be a private JWK (with `d`)")
        kty, crv = jwk.get("kty"), jwk.get("crv")
        if kty == "OKP" and crv == "Ed25519":
            self._key: Any = ed25519.Ed25519PrivateKey.from_private_bytes(_unb64(jwk["d"]))
            self.alg = "EdDSA"
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            x = _b64(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
            if jwk.get("x", x) != x:
                raise AttenuoError("DPoP key: `x` does not match `d`")
            self.public_jwk: dict[str, Any] = {"kty": "OKP", "crv": "Ed25519", "x": x}
        elif kty == "EC" and crv == "P-256":
            d = int.from_bytes(_unb64(jwk["d"]), "big")
            self._key = ec.derive_private_key(d, ec.SECP256R1())
            nums = self._key.public_key().public_numbers()
            x, y = _b64(nums.x.to_bytes(32, "big")), _b64(nums.y.to_bytes(32, "big"))
            if (jwk.get("x", x), jwk.get("y", y)) != (x, y):
                raise AttenuoError("DPoP key: `x`/`y` do not match `d`")
            self.alg = "ES256"
            self.public_jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
        else:
            raise AttenuoError(f"unsupported DPoP key type {kty!r} / curve {crv!r}")
        self._private = dict(jwk)
        #: RFC 7638 thumbprint: the ``cnf.jkt`` of tokens bound to this key.
        self.thumbprint = jwk_thumbprint(self.public_jwk)

    def __repr__(self) -> str:
        return f"DpopKey(alg={self.alg!r}, jkt={self.thumbprint!r})"

    @classmethod
    def generate(cls) -> DpopKey:
        """A fresh Ed25519 key."""
        _, ed25519 = _crypto()
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        key = ed25519.Ed25519PrivateKey.generate()
        d = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        x = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls({"kty": "OKP", "crv": "Ed25519", "x": _b64(x), "d": _b64(d)})

    @classmethod
    def load(cls, path: str | Path) -> DpopKey:
        """Read a private JWK file (for example one ``attenuo key gen --dpop`` wrote)."""
        return cls(json.loads(Path(path).read_text()))

    @classmethod
    def of(cls, key: DpopKey | dict[str, Any] | None) -> DpopKey | None:
        """Accept a key, a private JWK, or ``None``."""
        if key is None or isinstance(key, DpopKey):
            return key
        return cls(key)

    def private_jwk(self) -> dict[str, Any]:
        """The private JWK, for storage. Secret."""
        return {**self.public_jwk, "d": self._private["d"]}

    def proof(
        self,
        method: str,
        url: str,
        access_token: str | None = None,
        *,
        iat: int | None = None,
        nonce: str | None = None,
    ) -> str:
        """A proof for one request: ``htm`` = ``method``, ``htu`` = ``url`` without query or
        fragment, a fresh ``jti``, ``ath`` when ``access_token`` (a bound token sent with the
        request) is given, and ``nonce`` (the server's latest ``DPoP-Nonce``) when given."""
        claims: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": url.split("#", 1)[0].split("?", 1)[0],
            "iat": int(time.time()) if iat is None else iat,
        }
        if access_token is not None:
            claims["ath"] = access_token_hash(access_token)
        if nonce is not None:
            claims["nonce"] = nonce
        return self.sign(claims)

    def sign_off(
        self,
        url: str,
        subject_token: str,
        child_jkt: str,
        actor: str,
        *,
        iat: int | None = None,
    ) -> str:
        """The ``subject_token_dpop`` sign-off of an exchange: a proof by the subject token's key
        that also names the new token's key (``child_jkt``) and agent (``child_actor``), so it
        is consent to delegate to that key and agent only. The parent's holder makes it and hands
        it to the sub-agent; the parent's key never leaves the parent's process."""
        claims: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": "POST",
            "htu": url.split("#", 1)[0].split("?", 1)[0],
            "iat": int(time.time()) if iat is None else iat,
            "ath": access_token_hash(subject_token),
            SIGN_OFF_CHILD_JKT: child_jkt,
            SIGN_OFF_CHILD_ACTOR: actor,
        }
        return self.sign(claims)

    def sign(self, claims: dict[str, Any]) -> str:
        """Sign arbitrary proof claims with a DPoP header (for tests and special cases)."""
        header = {"typ": PROOF_TYPE, "alg": self.alg, "jwk": self.public_jwk}
        signing = (
            f"{_b64(json.dumps(header, separators=(',', ':')).encode())}."
            f"{_b64(json.dumps(claims, separators=(',', ':')).encode())}"
        )
        if self.alg == "EdDSA":
            sig = self._key.sign(signing.encode())
        else:
            ec, _ = _crypto()
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

            r, s = decode_dss_signature(self._key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing}.{_b64(sig)}"


def token_jkt(token: str) -> str | None:
    """``cnf.jkt`` of a token, read without verification; ``None`` for a bearer token."""
    try:
        claims = json.loads(_unb64(token.split(".")[1]))
    except (IndexError, ValueError):
        return None
    cnf = claims.get("cnf") if isinstance(claims, dict) else None
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    return jkt if isinstance(jkt, str) else None


def presented(
    token: str, key: DpopKey | None, method: str, url: str, nonce: str | None = None
) -> dict[str, str]:
    """``Authorization`` (and ``DPoP``) headers to present ``token`` for a request."""
    if key is None:
        return {"authorization": f"Bearer {token}"}
    return {"authorization": f"DPoP {token}", "dpop": key.proof(method, url, token, nonce=nonce)}


class NonceCache:
    """The latest ``DPoP-Nonce`` a server sent (RFC 9449 §8), for the next proof."""

    def __init__(self) -> None:
        #: The nonce to put in the next proof, or ``None`` before the server sent one.
        self.value: str | None = None

    def update(self, response: httpx.Response) -> bool:
        """Remember ``response``'s ``DPoP-Nonce``. True when the response refused the proof
        with ``use_dpop_nonce`` and gave a nonce: the request should be retried, once, with a
        new proof carrying it."""
        nonce = response.headers.get(NONCE_HEADER)
        if nonce:
            self.value = nonce
        return bool(nonce) and is_use_dpop_nonce(response)


def is_use_dpop_nonce(response: httpx.Response) -> bool:
    """Did the server refuse the proof for want of its nonce? A 401 with
    ``WWW-Authenticate: DPoP error="use_dpop_nonce"`` (resource servers, and attenuo's own
    routes), or a 400 or 401 whose JSON ``error`` is ``use_dpop_nonce`` (authorization
    servers)."""
    if response.status_code not in (400, 401):
        return False
    if USE_DPOP_NONCE in response.headers.get("www-authenticate", ""):
        return True
    try:
        body = response.json()
    except Exception:  # not JSON, or a streamed body that was not read
        return False
    return isinstance(body, dict) and body.get("error") == USE_DPOP_NONCE


def exchange_proofs(
    url: str,
    subject_token: str,
    key: DpopKey | None,
    subject_key: DpopKey | None,
    actor: str,
    nonce: str | None = None,
) -> tuple[str | None, str | None]:
    """The ``DPoP`` header and the ``subject_token_dpop`` sign-off of an exchange.

    ``key`` binds the new token; its proof covers the subject token when the subject token is
    bound to the same key. ``subject_key`` is the subject token's key when the new token is
    bound to another one: its sign-off names ``key`` and ``actor`` (see
    :meth:`DpopKey.sign_off`), so it consents to that delegation only. ``nonce`` goes in the
    header proof only: the server does not ask for one in the sign-off.
    """
    parent = token_jkt(subject_token)
    header = None
    if key is not None:
        same = parent is not None and parent == key.thumbprint
        header = key.proof("POST", url, subject_token if same else None, nonce=nonce)
    sign_off = None
    if subject_key is not None:
        if key is None:
            raise AttenuoError("subject_dpop_key needs a dpop_key to bind the new token to")
        if parent is not None and parent != subject_key.thumbprint:
            raise AttenuoError("subject_dpop_key is not the key the subject token is bound to")
        sign_off = subject_key.sign_off(url, subject_token, key.thumbprint, actor)
    return header, sign_off
