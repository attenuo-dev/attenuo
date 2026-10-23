from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from onbehalf import (
    AdminClient,
    ApiError,
    AsyncAdminClient,
    Capability,
    OnbehalfError,
    Prefix,
    Unauthorized,
)

from .helpers import Signer, token_response

BASE = "http://ob.test"


@pytest.fixture(params=["sync", "async"])
def make(
    request: pytest.FixtureRequest,
) -> Callable[[Callable[[httpx.Request], httpx.Response]], tuple[Any, list[httpx.Request]]]:
    def build(
        handler: Callable[[httpx.Request], httpx.Response],
    ) -> tuple[Any, list[httpx.Request]]:
        seen: list[httpx.Request] = []

        def record(r: httpx.Request) -> httpx.Response:
            seen.append(r)
            return handler(r)

        cls = AdminClient if request.param == "sync" else AsyncAdminClient
        return cls(BASE, "adm", transport=httpx.MockTransport(record)), seen

    return build


async def call(client: Any, name: str, *args: Any, **kwargs: Any) -> Any:
    result = getattr(client, name)(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


async def test_revoke_lease(make: Any) -> None:
    client, seen = make(
        lambda r: httpx.Response(200, json={"lease_id": "L1", "revoked": 2, "reason": "demo"})
    )
    res = await call(client, "revoke_lease", "L1", "demo")
    assert (seen[-1].method, seen[-1].url.path) == ("POST", "/admin/leases/L1/revoke")
    assert seen[-1].headers["authorization"] == "Bearer adm"
    assert json.loads(seen[-1].content) == {"reason": "demo"}
    assert (res.lease_id, res.revoked, res.reason) == ("L1", 2, "demo")
    await call(client, "revoke_lease", "L1")
    assert json.loads(seen[-1].content) == {}


async def test_lease_status(make: Any) -> None:
    body = {
        "lease_id": "L1", "active": False, "parent": None, "expires_at": "2026-10-23T10:00:00Z",
        "revoked_at": "2026-10-23T09:00:00Z", "revoke_reason": "demo",
    }  # fmt: skip
    client, seen = make(lambda r: httpx.Response(200, json=body))
    st = await call(client, "lease_status", "L1")
    assert seen[-1].url.path == "/admin/leases/L1"
    assert not st.active and st.revoke_reason == "demo"

    client, _ = make(
        lambda r: httpx.Response(404, json={"error": "not_found", "detail": "unknown lease"})
    )
    with pytest.raises(ApiError) as e:
        await call(client, "lease_status", "nope")
    assert e.value.status == 404


def _entry(seq: int, decision: str = "allow") -> dict[str, Any]:
    return {
        "seq": seq,
        "hash": "h",
        "record": {
            "id": f"id{seq}",
            "decision": decision,
            "reason": "r",
            "tool": "t",
            "server": "s",
        },
    }


async def test_audit_page_and_tail(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/admin/audit/checkpoint":
            return httpx.Response(200, json={"seq": 7, "hash": "abc"})
        q = dict(r.url.params)
        start = int(q["from"])
        entries = [_entry(s) for s in range(start, 8)][: int(q["limit"])]
        return httpx.Response(200, json={"entries": entries, "next": None, "head": 7})

    client, seen = make(handler)
    entries = await call(client, "audit_tail", 3)
    # the head comes from GET /admin/audit; the checkpoint endpoint (which signs) is not used
    assert all(r.url.path == "/admin/audit" for r in seen)
    assert [e.seq for e in entries] == [5, 6, 7]
    assert entries[0].id == "id5" and entries[0].decision == "allow" and entries[0].tool == "t"
    assert dict(seen[-1].url.params) == {"from": "5", "limit": "1000"}
    assert await call(client, "audit_head") == 7
    entries = await call(client, "audit_tail", 100)
    assert entries[0].seq == 1 and len(entries) == 7
    page, nxt = await call(client, "audit", 2, 2)
    assert nxt is None and page[0].seq == 2
    assert (await call(client, "audit_checkpoint")) == {"seq": 7, "hash": "abc"}
    assert seen[-1].url.path == "/admin/audit/checkpoint"


async def test_audit_tail_follows_next(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        assert not r.url.path.endswith("checkpoint")
        q = r.url.params
        start = int(q["from"])
        if q["limit"] == "1":
            return httpx.Response(200, json={"entries": [_entry(1)], "next": 2, "head": 3})
        if start == 1:
            return httpx.Response(
                200, json={"entries": [_entry(1), _entry(2)], "next": 3, "head": 3}
            )
        return httpx.Response(200, json={"entries": [_entry(3)], "next": None, "head": 3})

    client, _ = make(handler)
    assert [e.seq for e in await call(client, "audit_tail", 10)] == [1, 2, 3]


async def test_audit_head_empty_log_and_missing_field(make: Any) -> None:
    client, _ = make(lambda r: httpx.Response(200, json={"entries": [], "next": None, "head": 0}))
    assert await call(client, "audit_head") == 0
    assert await call(client, "audit_tail", 5) == []
    client, _ = make(lambda r: httpx.Response(200, json={"entries": [], "next": None}))
    assert await call(client, "audit_head") == 0


async def _collect(client: Any, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    it = client.audit_export(*args, **kwargs)
    if hasattr(it, "__aiter__"):
        return [x async for x in it]
    return list(it)


async def test_audit_export_streams_jsonl(make: Any) -> None:
    body = (
        '{"type":"header","format":"onbehalf-audit-export/1","from":1,"to":2}\n'
        '{"type":"entry","seq":1}\n\n'
        '{"type":"checkpoint","seq":2}\n'
    )
    client, seen = make(lambda r: httpx.Response(200, text=body))
    lines = await _collect(client, 1, 2)
    assert [x["type"] for x in lines] == ["header", "entry", "checkpoint"]
    assert seen[-1].url.path == "/admin/audit/export"
    assert dict(seen[-1].url.params) == {"from": "1", "to": "2"}
    await _collect(client)
    assert dict(seen[-1].url.params) == {"from": "1"}


async def test_audit_export_errors(make: Any) -> None:
    client, _ = make(lambda r: httpx.Response(401, json={"error": "unauthorized"}))
    with pytest.raises(ApiError):
        await _collect(client)
    client, _ = make(lambda r: httpx.Response(200, text="not json\n"))
    with pytest.raises(OnbehalfError):
        await _collect(client)


async def test_audit_verify(make: Any) -> None:
    client, seen = make(
        lambda r: httpx.Response(200, json={"entries": 5, "ok": True, "first_bad_seq": None})
    )
    rep = await call(client, "audit_verify")
    assert seen[-1].url.path == "/admin/audit/verify"
    assert rep.ok and rep.entries == 5 and rep.first_bad_seq is None
    client, _ = make(
        lambda r: httpx.Response(200, json={"entries": 5, "ok": False, "first_bad_seq": 3})
    )
    rep = await call(client, "audit_verify")
    assert not rep.ok and rep.first_bad_seq == 3


async def test_policy_reload(make: Any) -> None:
    client, seen = make(
        lambda r: httpx.Response(200, json={"policy_ids": ["a", "b"], "warnings": ["w"]})
    )
    rep = await call(client, "policy_reload")
    assert (seen[-1].method, seen[-1].url.path) == ("POST", "/admin/policies/reload")
    assert rep.policy_ids == ["a", "b"] and rep.warnings == ["w"]
    client, _ = make(
        lambda r: httpx.Response(422, json={"error": "policy_invalid", "detail": "parse error"})
    )
    with pytest.raises(ApiError) as e:
        await call(client, "policy_reload")
    assert e.value.error == "policy_invalid"


async def test_mint_root_dev(make: Any) -> None:
    jwt = Signer().mint()
    client, seen = make(lambda r: httpx.Response(200, json=token_response(jwt, "root-lease")))
    tok = await call(
        client,
        "mint_root_dev",
        "alice",
        "https://idp.example",
        "planner",
        [Capability("github", "*", repo=Prefix("alice/"))],
        ttl_seconds=60,
        attributes={"mfa": True},
    )
    assert seen[-1].url.path == "/admin/root-token"
    assert json.loads(seen[-1].content) == {
        "subject": "alice",
        "issuer": "https://idp.example",
        "agent": "planner",
        "capabilities": [
            {
                "server": "github",
                "tool": "*",
                "constraints": {"repo": {"op": "prefix", "value": "alice/"}},
            }
        ],
        "ttl_seconds": 60,
        "attributes": {"mfa": True},
    }
    assert tok.lease == "root-lease" and tok.jwt == jwt

    await call(client, "mint_root_dev", "alice", "https://idp.example", "planner")
    assert set(json.loads(seen[-1].content)) == {"subject", "issuer", "agent"}

    await call(
        client, "mint_root_dev", "alice", "https://idp.example", "planner", may_act=["coder"]
    )
    assert json.loads(seen[-1].content)["may_act"] == {"sub": ["coder"]}
    await call(client, "mint_root_dev", "a", "i", "p", may_act=iter(["x", "y"]))
    assert json.loads(seen[-1].content)["may_act"] == {"sub": ["x", "y"]}
    # An empty list is sent: nobody may exchange the token.
    await call(client, "mint_root_dev", "a", "i", "p", may_act=[])
    assert json.loads(seen[-1].content)["may_act"] == {"sub": []}
    with pytest.raises(TypeError):
        await call(client, "mint_root_dev", "a", "i", "p", may_act="coder")
    with pytest.raises(ValueError):
        await call(client, "mint_root_dev", "a", "i", "p", may_act=[""])


async def test_admin_errors(make: Any) -> None:
    client, _ = make(
        lambda r: httpx.Response(
            401, json={"error": "unauthorized", "detail": "admin bearer token required"}
        )
    )
    with pytest.raises(Unauthorized):
        await call(client, "audit_verify")
    client, _ = make(lambda r: httpx.Response(404, text=""))
    with pytest.raises(ApiError) as e:
        await call(client, "mint_root_dev", "a", "i", "p")
    assert e.value.status == 404


def test_context_managers() -> None:
    with AdminClient(BASE, "t", transport=httpx.MockTransport(lambda r: httpx.Response(200))) as a:
        assert a.server_url == BASE
    with pytest.raises(ValueError):
        AdminClient("nope", "t")


async def test_async_context_manager() -> None:
    async with AsyncAdminClient(
        BASE, "t", transport=httpx.MockTransport(lambda r: httpx.Response(200))
    ) as a:
        assert a.server_url == BASE
