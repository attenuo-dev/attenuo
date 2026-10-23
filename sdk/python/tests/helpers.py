"""Build delegation tokens by hand for unit tests."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hop(
    agent: str, caps: list[dict[str, Any]], lease: str, ttl: int = 900, at: float | None = None
) -> dict[str, Any]:
    now = int(time.time() if at is None else at)
    fmt = "%Y-%m-%dT%H:%M:%S.123456789Z"
    return {
        "agent": agent,
        "capabilities": caps,
        "issued_at": time.strftime(fmt, time.gmtime(now)),
        "expires_at": time.strftime(fmt, time.gmtime(now + ttl)),
        "lease": lease,
    }


class Signer:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(raw)}]}

    def mint(
        self,
        agents: tuple[str, ...] = ("planner",),
        *,
        subject: str = "alice",
        caps: list[dict[str, Any]] | None = None,
        exp_delta: int = 900,
        claims: dict[str, Any] | None = None,
        header: dict[str, Any] | None = None,
        at: float | None = None,
    ) -> str:
        caps = caps if caps is not None else [{"server": "github", "tool": "*"}]
        hops = [hop(a, caps, f"lease-{i}", exp_delta, at) for i, a in enumerate(agents)]
        now = int(time.time() if at is None else at)
        act: dict[str, Any] | None = None
        for a in agents:
            act = {"sub": a, **({"act": act} if act else {})}
        payload: dict[str, Any] = {
            "iss": "http://ob.test",
            "aud": "attenuo",
            "sub": subject,
            "act": act,
            "jti": "jti-1",
            "iat": now,
            "exp": now + exp_delta,
            "typ": "attenuo+jwt",
            "ou_sig": "sig",
            "chain": {
                "originating_user": {
                    "subject": subject,
                    "issuer": "https://idp.example",
                    "authenticated_at": "2026-10-23T09:00:00.5Z",
                },
                "hops": hops,
            },
        }
        payload.update(claims or {})
        head = {"alg": "EdDSA", "typ": "JWT", **(header or {})}
        signing = f"{b64(json.dumps(head).encode())}.{b64(json.dumps(payload).encode())}"
        return f"{signing}.{b64(self.key.sign(signing.encode()))}"


def token_response(jwt: str, lease: str = "lease-0", expires_in: int = 900) -> dict[str, Any]:
    return {
        "access_token": jwt,
        "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_type": "Bearer",
        "expires_in": expires_in,
        "lease": lease,
    }
