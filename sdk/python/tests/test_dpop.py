"""DPoP (RFC 9449, SR-24): keys, proofs, and the client putting them on the wire."""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from onbehalf import Client, DpopKey, OnbehalfError
from onbehalf.dpop import access_token_hash, jwk_thumbprint
from onbehalf.mcp import TokenAuth

from .helpers import Signer, token_response
from .test_client import Recorder, call, make, rpc_ok  # noqa: F401  (pytest fixture)

BASE = "http://ob.test"


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify(proof: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Check a proof's signature with its own header key; return (header, claims)."""
    h, p, s = proof.split(".")
    header, claims = json.loads(unb64(h)), json.loads(unb64(p))
    assert header["typ"] == "dpop+jwt"
    jwk, sig, data = header["jwk"], unb64(s), f"{h}.{p}".encode()
    assert "d" not in jwk
    if header["alg"] == "EdDSA":
        Ed25519PublicKey.from_public_bytes(unb64(jwk["x"])).verify(sig, data)
    else:
        assert header["alg"] == "ES256"
        nums = ec.EllipticCurvePublicNumbers(
            int.from_bytes(unb64(jwk["x"]), "big"),
            int.from_bytes(unb64(jwk["y"]), "big"),
            ec.SECP256R1(),
        )
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        nums.public_key().verify(der, data, ec.ECDSA(hashes.SHA256()))
    return header, claims


def test_thumbprint_matches_rfc8037() -> None:
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_keys_round_trip_and_sign_both_algorithms(tmp_path: Any) -> None:
    ed = DpopKey.generate()
    assert DpopKey(ed.private_jwk()).thumbprint == ed.thumbprint
    path = tmp_path / "k.jwk"
    path.write_text(json.dumps(ed.private_jwk()))
    assert DpopKey.load(path).thumbprint == ed.thumbprint
    p256 = DpopKey(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        }
    )
    for key in (ed, p256):
        header, claims = verify(key.proof("post", f"{BASE}/mcp/github?x=1#f", "tok"))
        assert jwk_thumbprint(header["jwk"]) == key.thumbprint
        assert claims["htm"] == "POST"
        assert claims["htu"] == f"{BASE}/mcp/github"
        assert claims["ath"] == access_token_hash("tok")
        assert abs(claims["iat"] - time.time()) < 5 and claims["jti"]
    with pytest.raises(OnbehalfError):
        DpopKey(ed.public_jwk)
    with pytest.raises(OnbehalfError):
        DpopKey({**ed.private_jwk(), "x": DpopKey.generate().public_jwk["x"]})


def bound(s: Signer, jkt: str, agents: tuple[str, ...] = ("planner",)) -> str:
    return s.mint(agents, claims={"cnf": {"jkt": jkt}})


async def test_client_attaches_proofs_and_binds_on_exchange(make: Any) -> None:  # noqa: F811
    s, key, parent_key = Signer(), DpopKey.generate(), DpopKey.generate()
    child = bound(s, key.thumbprint, ("planner", "coder"))

    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/token":
            return httpx.Response(200, json=token_response(child, "lease-1"))
        if r.url.path == "/token/renew":
            return httpx.Response(
                200, json={"lease": "l", "expires_at": "2030-01-01T00:00:00Z", "expires_in": 5}
            )
        return rpc_ok({"content": []})

    client, rec = make(handler, dpop_key=key.private_jwk())

    # Unbound parent: the header proof binds the child and covers nothing.
    tok = await call(client, "exchange", s.mint(), "coder", ["github:read_file"])
    assert tok.dpop_jkt == key.thumbprint
    _, claims = verify(rec.last.headers["dpop"])
    assert claims["htu"] == f"{BASE}/token" and "ath" not in claims
    assert "subject_token_dpop" not in rec.body()

    # Parent bound to the same key: the proof covers it.
    parent = bound(s, key.thumbprint)
    await call(client, "exchange", parent, "coder", ["github:read_file"])
    header, claims = verify(rec.last.headers["dpop"])
    assert claims["ath"] == access_token_hash(parent)
    assert jwk_thumbprint(header["jwk"]) == key.thumbprint

    # Parent bound to another key: its holder signs off in the body.
    other = bound(s, parent_key.thumbprint)
    await call(
        client, "exchange", other, "coder", ["github:read_file"], subject_dpop_key=parent_key
    )
    header, claims = verify(rec.body()["subject_token_dpop"])
    assert jwk_thumbprint(header["jwk"]) == parent_key.thumbprint
    assert claims["ath"] == access_token_hash(other)
    # SR-40: the sign-off names the new token's key and agent.
    assert claims["child_jkt"] == key.thumbprint and claims["child_actor"] == "coder"
    with pytest.raises(OnbehalfError):
        await call(client, "exchange", other, "coder", ["github:read_file"], subject_dpop_key=key)

    # A sign-off made by the parent's holder elsewhere is passed through as it is.
    detached = parent_key.sign_off(f"{BASE}/token", other, key.thumbprint, "coder")
    await call(
        client, "exchange", other, "coder", ["github:read_file"], subject_token_dpop=detached
    )
    assert rec.body()["subject_token_dpop"] == detached
    with pytest.raises(OnbehalfError):
        await call(
            client,
            "exchange",
            other,
            "coder",
            ["github:read_file"],
            subject_dpop_key=parent_key,
            subject_token_dpop=detached,
        )

    # Every use of a token carries a proof for that request.
    await call(client, "call_tool", child, "github", "read_file", {})
    await call(client, "renew", child)
    for r in rec.requests[-2:]:
        assert r.headers["authorization"] == f"DPoP {child}"
        _, claims = verify(r.headers["dpop"])
        assert claims["htu"] == str(r.url) and claims["ath"] == access_token_hash(child)


def test_client_without_a_key_sends_bearer_only() -> None:
    rec = Recorder(lambda r: rpc_ok({"content": []}))
    with Client(BASE, transport=httpx.MockTransport(rec)) as ob:
        ob.call_tool("a.b.c", "github", "read_file")
    assert rec.last.headers["authorization"] == "Bearer a.b.c"
    assert "dpop" not in rec.last.headers


def test_token_auth_adds_a_proof_per_request() -> None:
    key = DpopKey.generate()
    rec = Recorder(lambda r: httpx.Response(200))
    auth = TokenAuth(lambda: "a.b.c", dpop_key=key)
    with httpx.Client(transport=httpx.MockTransport(rec), auth=auth) as http:
        http.post(f"{BASE}/mcp/github")
        http.get(f"{BASE}/mcp/github")
    proofs = [verify(r.headers["dpop"])[1] for r in rec.requests]
    assert [p["htm"] for p in proofs] == ["POST", "GET"]
    assert proofs[0]["jti"] != proofs[1]["jti"]
    assert rec.last.headers["authorization"] == "DPoP a.b.c"
