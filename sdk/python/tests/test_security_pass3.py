"""Regression tests for the 2026-10-23 security review, pass 3 (SR-31)."""

from __future__ import annotations

import json

import httpx
import pytest

from onbehalf import AdminClient, AsyncAdminClient, AsyncClient, Client

BASE = "http://ob.test"


def _recorder() -> tuple[list[httpx.Request], httpx.MockTransport]:
    seen: list[httpx.Request] = []

    def handle(r: httpx.Request) -> httpx.Response:
        seen.append(r)
        if r.url.path.startswith("/admin/leases/"):
            return httpx.Response(
                200,
                json={
                    "lease_id": "x",
                    "revoked": 1,
                    "reason": "r",
                    "active": False,
                    "expires_at": "2026-10-23T00:00:00Z",
                },
            )
        body = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
        return httpx.Response(200, json=body)

    return seen, httpx.MockTransport(handle)


def test_lease_ids_cannot_reach_other_admin_endpoints() -> None:
    """SR-31: a lease id read from an untrusted token stays inside its path segment."""
    seen, transport = _recorder()
    admin = AdminClient(BASE, "adm", transport=transport)
    admin.revoke_lease("x/../../policies/reload?")
    assert seen[-1].url.raw_path == b"/admin/leases/x%2F..%2F..%2Fpolicies%2Freload%3F/revoke"
    assert seen[-1].url.path.startswith("/admin/leases/")
    for bad in ("", ".", ".."):
        with pytest.raises(ValueError):
            admin.revoke_lease(bad)
        with pytest.raises(ValueError):
            admin.lease_status(bad)
    assert len(seen) == 1


def test_server_names_cannot_reach_other_endpoints() -> None:
    """SR-31: ``call_tool(server=...)`` cannot point the bearer at ``/token/renew`` etc."""
    seen, transport = _recorder()
    client = Client(BASE, token="t", transport=transport)
    client.call_tool(None, "github/../../token/renew", "read_file", {})
    assert seen[-1].url.raw_path == b"/mcp/github%2F..%2F..%2Ftoken%2Frenew"
    with pytest.raises(ValueError):
        client.call_tool(None, "..", "read_file", {})
    assert json.loads(seen[-1].content)["method"] == "tools/call"


async def test_async_clients_encode_too() -> None:
    seen, transport = _recorder()
    async with AsyncAdminClient(BASE, "adm", transport=transport) as admin:
        await admin.lease_status("a?b")
    async with AsyncClient(BASE, token="t", transport=transport) as client:
        await client.list_tools(None, "a#b")
    assert [r.url.raw_path for r in seen] == [b"/admin/leases/a%3Fb", b"/mcp/a%23b"]
