"""Calls held for an approval (JSON-RPC -32008): parsing, polling and the single retry."""

from __future__ import annotations

import base64
import inspect
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from attenuo import (
    ApiError,
    Approval,
    ApprovalNotGranted,
    ApprovalRequired,
    AsyncClient,
    Client,
    Denied,
    DpopKey,
    RpcError,
)

BASE = "http://ob.test"
APPROVAL_ID = "0f8e6c1a-4b7d-4f61-9a39-2f4f5b0e8d11"
Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture(params=["sync", "async"])
def make(request: pytest.FixtureRequest) -> Callable[..., tuple[Any, list[httpx.Request]]]:
    def build(handler: Handler, **kw: Any) -> tuple[Any, list[httpx.Request]]:
        seen: list[httpx.Request] = []

        def record(r: httpx.Request) -> httpx.Response:
            seen.append(r)
            return handler(r)

        cls = Client if request.param == "sync" else AsyncClient
        return cls(BASE, transport=httpx.MockTransport(record), **kw), seen

    return build


async def call(client: Any, name: str, *args: Any, **kwargs: Any) -> Any:
    result = getattr(client, name)(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


def gated(approval_id: str | None = APPROVAL_ID, header: str = "dec-1") -> httpx.Response:
    data: dict[str, Any] = {
        "reason": "approval_required",
        "decision_id": "dec-1",
        "call_hash": "ab" * 32,
    }
    if approval_id is not None:
        data["approval_id"] = approval_id
        data["expires_at"] = "2026-10-24T10:02:00.123456789Z"
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32008, "message": "attenuo: approval required", "data": data},
    }
    return httpx.Response(200, json=body, headers={"x-attenuo-decision-id": header})


def allowed() -> httpx.Response:
    body = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "done"}]}}
    return httpx.Response(200, json=body, headers={"x-attenuo-decision-id": "dec-2"})


def approval(state: str, expired: bool = False, **extra: Any) -> httpx.Response:
    body = {
        "approval_id": APPROVAL_ID,
        "state": state,
        "expired": expired,
        "chain_id": "lease-0",
        "lease": "lease-0",
        "call_hash": "ab" * 32,
        "call": {"server": "github", "tool": "delete_repo", "arguments": {"repo": "alice/site"}},
        "labels": [{"source": "github/read_web", "seq": 3}],
        "decision_id": "dec-1",
        "subject": "alice",
        "issuer": "https://idp.example",
        "agents": ["planner"],
        "created_at": "2026-10-24T10:00:00Z",
        "expires_at": "2026-10-24T10:02:00Z",
        **extra,
    }
    return httpx.Response(200, json=body)


async def test_gated_call_raises_approval_required(make: Any) -> None:
    client, _ = make(lambda r: gated())
    with pytest.raises(ApprovalRequired) as e:
        await call(client, "call_tool", "TOK", "github", "delete_repo", {"repo": "alice/site"})
    err = e.value
    assert isinstance(err, Denied)
    assert err.reason == "approval_required"
    assert err.decision_id == "dec-1"
    assert err.approval_id == APPROVAL_ID
    assert err.call_hash == "ab" * 32
    assert err.expires_at is not None and err.expires_at.minute == 2

    # The server could not open an approval: still a denial, with no id to wait for.
    client, _ = make(lambda r: gated(approval_id=None))
    with pytest.raises(ApprovalRequired) as e2:
        await call(client, "call_tool", "TOK", "github", "delete_repo")
    assert e2.value.approval_id is None


async def test_upstream_forged_32008_is_an_rpc_error(make: Any) -> None:
    client, _ = make(lambda r: gated(header="another-decision"))
    with pytest.raises(RpcError) as e:
        await call(client, "call_tool", "TOK", "github", "delete_repo")
    assert not isinstance(e.value, Denied)
    assert e.value.code == -32008


async def test_get_approval(make: Any) -> None:
    client, seen = make(lambda r: approval("granted", approver={"subject": "alice", "by": "user"}))
    a = await call(client, "get_approval", APPROVAL_ID, "TOK")
    assert isinstance(a, Approval)
    assert (a.state, a.usable, a.server, a.tool) == ("granted", True, "github", "delete_repo")
    assert a.arguments == {"repo": "alice/site"}
    assert a.approver == {"subject": "alice", "by": "user"}
    req = seen[-1]
    assert req.method == "GET"
    assert req.url.path == f"/approvals/{APPROVAL_ID}"
    assert req.headers["authorization"] == "Bearer TOK"

    # Ids are one path segment.
    with pytest.raises(ValueError):
        await call(client, "get_approval", "..", "TOK")

    client, _ = make(lambda r: httpx.Response(404, json={"error": "not_found", "detail": "x"}))
    with pytest.raises(ApiError) as e:
        await call(client, "get_approval", APPROVAL_ID, "TOK")
    assert e.value.status == 404


async def test_get_approval_with_dpop_signs_a_get(make: Any) -> None:
    key = DpopKey.generate()
    client, seen = make(lambda r: approval("pending"), dpop_key=key)
    await call(client, "get_approval", APPROVAL_ID, "TOK")
    req = seen[-1]
    assert req.headers["authorization"] == "DPoP TOK"
    proof = req.headers["dpop"].split(".")[1]
    claims = json.loads(_b64(proof))
    assert claims["htm"] == "GET"
    assert claims["htu"] == f"{BASE}/approvals/{APPROVAL_ID}"


def _b64(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


async def test_wait_for_approval_polls_until_granted(make: Any) -> None:
    answers = [approval("pending"), approval("pending"), approval("granted")]
    client, seen = make(lambda r: answers.pop(0))
    a = await call(client, "wait_for_approval", APPROVAL_ID, "TOK", interval=0)
    assert a.state == "granted"
    assert len(seen) == 3


@pytest.mark.parametrize(
    ("answer", "expired", "state"),
    [
        ("declined", False, "declined"),
        ("consumed", False, "consumed"),
        ("pending", True, "expired"),
        ("granted", True, "expired"),
    ],
)
async def test_wait_for_approval_stops_when_waiting_cannot_help(
    make: Any, answer: str, expired: bool, state: str
) -> None:
    client, _ = make(lambda r: approval(answer, expired=expired))
    with pytest.raises(ApprovalNotGranted) as e:
        await call(client, "wait_for_approval", APPROVAL_ID, "TOK", interval=0)
    assert (e.value.approval_id, e.value.state) == (APPROVAL_ID, state)


async def test_wait_for_approval_timeout(make: Any) -> None:
    client, _ = make(lambda r: approval("pending"))
    with pytest.raises(ApprovalNotGranted) as e:
        await call(client, "wait_for_approval", APPROVAL_ID, "TOK", timeout=0.05, interval=0.01)
    assert e.value.state == "timeout"


async def test_call_tool_with_approval_retries_the_identical_call_once(make: Any) -> None:
    answers = [gated(), approval("pending"), approval("granted"), allowed()]
    client, seen = make(lambda r: answers.pop(0))
    shown: list[str | None] = []
    result = await call(
        client,
        "call_tool_with_approval",
        "TOK",
        "github",
        "delete_repo",
        {"repo": "alice/site"},
        on_approval=lambda e: shown.append(e.approval_id),
        interval=0,
    )
    assert result.text == "done"
    assert shown == [APPROVAL_ID]
    posts = [r for r in seen if r.method == "POST"]
    assert len(posts) == 2
    first, retry = (json.loads(r.content) for r in posts)
    assert first["params"] == retry["params"]


async def test_call_tool_with_approval_gives_up_after_one_retry(make: Any) -> None:
    answers = [gated(), approval("granted"), gated()]
    client, _ = make(lambda r: answers.pop(0))
    with pytest.raises(ApprovalRequired):
        await call(client, "call_tool_with_approval", "TOK", "github", "delete_repo", interval=0)

    answers2 = [gated(), approval("declined")]
    client, seen = make(lambda r: answers2.pop(0))
    with pytest.raises(ApprovalNotGranted) as e:
        await call(client, "call_tool_with_approval", "TOK", "github", "delete_repo", interval=0)
    assert e.value.state == "declined"
    assert [r.method for r in seen] == ["POST", "GET"]

    # No approval id to wait for: the denial is raised as is.
    client, seen = make(lambda r: gated(approval_id=None))
    with pytest.raises(ApprovalRequired):
        await call(client, "call_tool_with_approval", "TOK", "github", "delete_repo")
    assert len(seen) == 1
