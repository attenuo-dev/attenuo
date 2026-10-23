"""DPoP (RFC 9449, SR-24): keys, proofs, and the client putting them on the wire."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from attenuo import AdminClient, AsyncAdminClient, AttenuoError, Client, DpopKey, Unauthorized
from attenuo.dpop import access_token_hash, jwk_thumbprint
from attenuo.mcp import TokenAuth

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
    with pytest.raises(AttenuoError):
        DpopKey(ed.public_jwk)
    with pytest.raises(AttenuoError):
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
    with pytest.raises(AttenuoError):
        await call(client, "exchange", other, "coder", ["github:read_file"], subject_dpop_key=key)

    # A sign-off made by the parent's holder elsewhere is passed through as it is.
    detached = parent_key.sign_off(f"{BASE}/token", other, key.thumbprint, "coder")
    await call(
        client, "exchange", other, "coder", ["github:read_file"], subject_token_dpop=detached
    )
    assert rec.body()["subject_token_dpop"] == detached
    with pytest.raises(AttenuoError):
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


class NonceServer:
    """A fake server that wants its current nonce in every proof (RFC 9449 §8).

    Refusals are the resource-server kind (401, ``WWW-Authenticate: DPoP
    error="use_dpop_nonce"``) except on ``/token``, which answers like an authorization server
    (400, JSON ``error``), so both are covered.
    """

    def __init__(self, ok: Callable[[httpx.Request], httpx.Response]) -> None:
        self.nonce = "n-1"
        self.ok = ok
        self.seen: list[str | None] = []  # the nonce of each request's proof

    def __call__(self, r: httpx.Request) -> httpx.Response:
        proof = r.headers.get("dpop")
        nonce = verify(proof)[1].get("nonce") if proof else None
        self.seen.append(nonce)
        if proof is not None and nonce != self.nonce:
            if r.url.path in ("/token", "/admin/root-token"):
                return httpx.Response(
                    400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": self.nonce}
                )
            return httpx.Response(
                401,
                json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "x"}},
                headers={
                    "WWW-Authenticate": 'DPoP error="use_dpop_nonce", algs="EdDSA ES256"',
                    "DPoP-Nonce": self.nonce,
                },
            )
        resp = self.ok(r)
        resp.headers["DPoP-Nonce"] = self.nonce
        return resp


def ok_for_every_route(child: str) -> Callable[[httpx.Request], httpx.Response]:
    def ok(r: httpx.Request) -> httpx.Response:
        if r.url.path in ("/token", "/admin/root-token"):
            return httpx.Response(200, json=token_response(child, "lease-1"))
        if r.url.path == "/token/renew":
            return httpx.Response(
                200, json={"lease": "l", "expires_at": "2030-01-01T00:00:00Z", "expires_in": 5}
            )
        if r.url.path == "/access/v1/evaluation":
            return httpx.Response(200, json={"decision": True})
        return rpc_ok({"content": []})

    return ok


async def test_client_caches_the_nonce_and_retries_once_on_use_dpop_nonce(
    make: Any,  # noqa: F811
) -> None:
    s, key = Signer(), DpopKey.generate()
    child = bound(s, key.thumbprint, ("planner", "coder"))
    server = NonceServer(ok_for_every_route(child))
    client, rec = make(server, dpop_key=key)

    # First request: no nonce yet, refused, retried once with the server's nonce.
    await call(client, "call_tool", child, "github", "read_file", {})
    assert server.seen == [None, "n-1"]
    first, retry = rec.requests
    assert verify(first.headers["dpop"])[1]["jti"] != verify(retry.headers["dpop"])[1]["jti"]
    assert retry.content == first.content

    # Later requests carry the cached nonce straight away, on every route.
    await call(client, "renew", child)
    await call(client, "authzen_evaluate", child, "github", "read_file", {})
    await call(client, "exchange", child, "reviewer", ["github:read_file"])
    assert server.seen[2:] == ["n-1", "n-1", "n-1"]

    # The server rolls its nonce: one more refusal (here the 400 of `/token`), one retry.
    server.nonce = "n-2"
    await call(client, "exchange", child, "reviewer", ["github:read_file"])
    assert server.seen[5:] == ["n-1", "n-2"]
    await call(client, "call_tool", child, "github", "read_file", {})
    assert server.seen[7:] == ["n-2"]


async def test_client_retries_only_once(make: Any) -> None:  # noqa: F811
    s, key = Signer(), DpopKey.generate()
    child = bound(s, key.thumbprint)
    server = NonceServer(ok_for_every_route(child))
    client, rec = make(server, dpop_key=key)
    counter = iter(range(100))

    def rotate(r: httpx.Request) -> httpx.Response:
        server.nonce = f"r-{next(counter)}"  # never the one the client just learned
        return server(r)

    rec.handler = rotate
    with pytest.raises(Unauthorized):
        await call(client, "renew", child)
    assert len(rec.requests) == 2


async def test_client_without_a_key_does_not_retry(make: Any) -> None:  # noqa: F811
    def refuse(r: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": "use_dpop_nonce"},
            headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "n"},
        )

    client, rec = make(refuse)
    with pytest.raises(Unauthorized):
        await call(client, "renew", "a.b.c")
    assert len(rec.requests) == 1


def test_token_auth_retries_with_the_servers_nonce() -> None:
    key = DpopKey.generate()
    server = NonceServer(lambda r: httpx.Response(200))
    rec = Recorder(server)
    auth = TokenAuth(lambda: "a.b.c", dpop_key=key)
    with httpx.Client(transport=httpx.MockTransport(rec), auth=auth) as http:
        assert http.post(f"{BASE}/mcp/github", json={"id": 1}).status_code == 200
        assert http.get(f"{BASE}/mcp/github").status_code == 200
    assert server.seen == [None, "n-1", "n-1"]
    assert rec.requests[1].content == rec.requests[0].content


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_admin_root_mint_retries_with_the_servers_nonce(kind: str) -> None:
    s, key = Signer(), DpopKey.generate()
    child = bound(s, key.thumbprint)
    server = NonceServer(ok_for_every_route(child))
    transport_rec = Recorder(server)
    if kind == "sync":
        with AdminClient(BASE, "t", transport=httpx.MockTransport(transport_rec)) as a:
            tok = a.mint_root_dev("alice", "https://idp", "planner", dpop_key=key)
            a.mint_root_dev("alice", "https://idp", "planner", dpop_key=key)
    else:
        async with AsyncAdminClient(BASE, "t", transport=httpx.MockTransport(transport_rec)) as a:
            tok = await a.mint_root_dev("alice", "https://idp", "planner", dpop_key=key)
            await a.mint_root_dev("alice", "https://idp", "planner", dpop_key=key)
    assert tok.dpop_jkt == key.thumbprint
    assert server.seen == [None, "n-1", "n-1"]


def test_proof_carries_a_nonce_only_when_given() -> None:
    key = DpopKey.generate()
    assert "nonce" not in verify(key.proof("POST", f"{BASE}/token"))[1]
    assert verify(key.proof("POST", f"{BASE}/token", nonce="abc"))[1]["nonce"] == "abc"
