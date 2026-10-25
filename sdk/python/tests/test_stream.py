"""Streamed ``tools/call`` answers: the SSE parser and ``call_tool_stream``."""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest

from attenuo import (
    DEFAULT_MAX_EVENT_BYTES,
    ApprovalRequired,
    AsyncClient,
    AttenuoError,
    Client,
    Denied,
    DpopKey,
    RpcError,
    StreamEvent,
    Unauthorized,
)
from attenuo._sse import SseParser

from .helpers import Signer
from .test_client import Recorder, make  # noqa: F401  (pytest fixture)
from .test_dpop import NonceServer, bound, verify

BASE = "http://ob.test"
SSE = {"content-type": "text/event-stream"}


def event(msg: dict[str, Any], event_id: str | None = None) -> str:
    head = f"id: {event_id}\n" if event_id is not None else ""
    return f"{head}event: message\ndata: {json.dumps(msg)}\n\n"


def progress(n: int) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progressToken": "t", "progress": n, "total": 2},
    }


def result(text: str, request_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }


CUT_ERROR: dict[str, Any] = {
    "code": -32001,
    "message": "attenuo: unauthorized: stream ended: lease_revoked",
    "data": {"reason": "lease_revoked", "decision_id": "dec-end"},
}
CUT = {"jsonrpc": "2.0", "id": None, "error": CUT_ERROR}


async def collect(it: Any) -> list[StreamEvent]:
    """Drain a sync or async iterator of events into a list."""
    if inspect.isasyncgen(it) or hasattr(it, "__aiter__"):
        return [ev async for ev in it]
    return list(it)


async def collect_until_error(it: Any) -> tuple[list[StreamEvent], BaseException]:
    seen: list[StreamEvent] = []
    try:
        if hasattr(it, "__aiter__"):
            async for ev in it:
                seen.append(ev)
        else:
            for ev in it:
                seen.append(ev)
    except Exception as e:
        return seen, e
    raise AssertionError(f"no exception; got {seen}")


# --- the parser ------------------------------------------------------------------------------


def parse_all(body: bytes, chunk: int | None = None, limit: int = 1 << 20) -> list[tuple[str, Any]]:
    p = SseParser(limit)
    out: list[Any] = []
    step = chunk or len(body) or 1
    for i in range(0, len(body), step):
        out += p.feed(body[i : i + step])
    out += p.close()
    return [(e.data, e.last_event_id) for e in out]


@pytest.mark.parametrize("chunk", [None, 1, 2, 3, 7])
def test_parser_line_ends_comments_fields_and_split_reads(chunk: int | None) -> None:
    body = (
        b"\xef\xbb\xbf: a comment\r\n"
        b"event: message\r\nid: 1\r\ndata: one\r\n\r\n"  # CRLF
        b"data: two\rdata:three\r\r"  # CR, and no space after the colon
        b"retry: 10\nid: 7\ndata:  four\nunknown: x\ndata\n\n"  # LF; `data` with no colon
        b"\n\n"  # empty events dispatch nothing
        b"id: 8\ndata: dropped, no blank line"
    )
    assert parse_all(body, chunk) == [
        ("one", "1"),
        ("two\nthree", "1"),  # the last event id carries over
        (" four\n", "7"),
    ]


def test_parser_last_line_ended_by_a_lone_cr_counts() -> None:
    assert parse_all(b"data: x\r\r") == [("x", None)]
    assert parse_all(b"data: x\r") == []


def test_parser_id_with_nul_is_ignored() -> None:
    assert parse_all(b"id: 1\n\ndata: a\nid: b\x00c\n\n") == [("a", "1")]


def test_parser_refuses_an_oversized_event() -> None:
    small = b"data: " + b"x" * 50 + b"\n\n"
    assert parse_all(small * 3, 5, limit=64) == [("x" * 50, None)] * 3
    with pytest.raises(AttenuoError, match="over 64 bytes"):
        parse_all(b"data: " + b"x" * 30 + b"\ndata: " + b"y" * 30 + b"\n\n", limit=64)
    # A single line that never ends is refused as soon as it passes the limit.
    p = SseParser(64)
    with pytest.raises(AttenuoError, match="over 64 bytes"):
        for _ in range(10):
            list(p.feed(b"data: " + b"z" * 10))


def test_parser_refuses_non_utf8() -> None:
    with pytest.raises(AttenuoError, match="UTF-8"):
        parse_all(b"data: \xff\n\n")


def test_default_bound_is_the_proxys() -> None:
    assert DEFAULT_MAX_EVENT_BYTES == 16 * 1024 * 1024


# --- call_tool_stream ------------------------------------------------------------------------


async def test_stream_progress_then_result(make: Any) -> None:  # noqa: F811
    body = event(progress(1), "e1") + event(progress(2), "e2") + event(result("done"), "e3")
    client, rec = make(
        lambda r: httpx.Response(200, text=body, headers={**SSE, "X-Attenuo-Decision-Id": "dec-1"})
    )
    events = await collect(
        client.call_tool_stream(
            "TOK", "github", "read_file", {"repo": "a/b"}, "sess", approval_token="appr"
        )
    )
    # The request is the one call_tool sends.
    assert rec.last.url.path == "/mcp/github"
    h = rec.last.headers
    assert h["authorization"] == "Bearer TOK"
    assert h["accept"] == "application/json, text/event-stream"
    assert h["mcp-session-id"] == "sess"
    assert json.loads(rec.last.content) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"repo": "a/b"},
            "_meta": {"dev.attenuo/approval": "appr"},
        },
    }
    assert [e.method for e in events] == ["notifications/progress", "notifications/progress", None]
    assert [e.message.get("params", {}).get("progress") for e in events[:2]] == [1, 2]
    assert [e.last_event_id for e in events] == ["e1", "e2", "e3"]
    assert [e.is_final for e in events] == [False, False, True]
    assert all(e.decision_id == "dec-1" for e in events)
    final = events[-1].result
    assert final is not None and final.text == "done" and final.decision_id == "dec-1"


async def test_stream_cut_by_the_proxy_raises_denied(make: Any) -> None:  # noqa: F811
    body = event(progress(1)) + event(CUT)
    client, _ = make(
        lambda r: httpx.Response(200, text=body, headers={**SSE, "X-Attenuo-Decision-Id": "d"})
    )
    seen, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert [e.method for e in seen] == ["notifications/progress"]
    assert isinstance(err, Denied)
    assert err.reason == "lease_revoked"
    assert err.decision_id == "dec-end"
    assert "stream ended" in str(err)


async def test_stream_cut_without_a_record_has_no_decision_id(make: Any) -> None:  # noqa: F811
    error = {**CUT_ERROR, "data": {"reason": "token_expired"}}
    cut = {**CUT, "error": error}
    client, _ = make(lambda r: httpx.Response(200, text=event(cut), headers=SSE))
    _, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert isinstance(err, Denied) and err.reason == "token_expired" and err.decision_id is None


# What the proxy relays when an upstream sends CUT itself (`upstream_stream_end_shape`).
REWRITTEN: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": None,
    "error": {
        "code": -32005,
        "message": "attenuo: upstream sent an error in the shape of the proxy's stream end",
        "data": {"reason": "upstream_stream_end_shape", "upstream_error": CUT_ERROR},
    },
}


async def test_stream_upstream_lookalike_rewritten_by_the_proxy_is_not_a_cut(
    make: Any,  # noqa: F811
) -> None:
    # In a stream: an ordinary message, then the stream ends without the call's response.
    body = event(progress(1)) + event(REWRITTEN)
    client, _ = make(lambda r: httpx.Response(200, text=body, headers=SSE))
    seen, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert [e.message for e in seen] == [progress(1), REWRITTEN]
    assert not isinstance(err, Denied)
    assert isinstance(err, AttenuoError) and "ended before" in str(err)

    # As a plain JSON answer: an RpcError carrying the upstream's error, not a Denied.
    client, _ = make(lambda r: httpx.Response(200, json=REWRITTEN))
    _, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert isinstance(err, RpcError) and not isinstance(err, Denied)
    assert err.code == -32005 and err.data["upstream_error"] == CUT_ERROR


async def test_stream_plain_json_answer_is_the_one_final_event(make: Any) -> None:  # noqa: F811
    client, _ = make(
        lambda r: httpx.Response(200, json=result("plain"), headers={"X-Attenuo-Decision-Id": "d"})
    )
    events = await collect(client.call_tool_stream("TOK", "github", "read_file"))
    assert len(events) == 1
    assert events[0].is_final and events[0].last_event_id is None
    assert events[0].message == result("plain")
    assert events[0].result is not None and events[0].result.text == "plain"


async def test_stream_denial_raises_before_anything_is_yielded(make: Any) -> None:  # noqa: F811
    denied = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32003,
            "message": "attenuo: denied: policy_deny",
            "data": {"reason": "policy_deny", "decision_id": "dec-9"},
        },
    }
    client, _ = make(
        lambda r: httpx.Response(200, json=denied, headers={"X-Attenuo-Decision-Id": "dec-9"})
    )
    seen, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert seen == []
    assert isinstance(err, Denied) and err.reason == "policy_deny" and err.decision_id == "dec-9"

    # The same denial as an SSE event; and a -32008 is an ApprovalRequired.
    held = {
        "jsonrpc": "2.0",
        "id": 2,
        "error": {
            "code": -32008,
            "message": "attenuo: approval required",
            "data": {"decision_id": "dec-a", "approval_id": "ap-1"},
        },
    }
    client, _ = make(
        lambda r: httpx.Response(
            200, text=event(held), headers={**SSE, "X-Attenuo-Decision-Id": "dec-a"}
        )
    )
    client._ids = iter([2])
    _, err = await collect_until_error(client.call_tool_stream("TOK", "github", "delete_repo"))
    assert isinstance(err, ApprovalRequired) and err.approval_id == "ap-1"


async def test_stream_errors_like_call_tool(make: Any) -> None:  # noqa: F811
    # An upstream's -32003 without the proxy's header is an RpcError, not a denial (SR-32).
    forged = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32003, "message": "no", "data": {"reason": "x", "decision_id": "f"}},
    }
    client, _ = make(lambda r: httpx.Response(200, text=event(forged), headers=SSE))
    _, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert isinstance(err, RpcError) and err.code == -32003

    # A 401 at the start (bad token) is Unauthorized.
    unauth = {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "bad token"}}
    client, _ = make(lambda r: httpx.Response(401, json=unauth))
    _, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert isinstance(err, Unauthorized)


async def test_stream_refuses_an_oversized_event(make: Any) -> None:  # noqa: F811
    big = event(progress(1)) + event(result("x" * 500))
    client, _ = make(lambda r: httpx.Response(200, text=big, headers=SSE))
    seen, err = await collect_until_error(
        client.call_tool_stream("TOK", "github", "read_file", max_event_bytes=300)
    )
    assert [e.method for e in seen] == ["notifications/progress"]
    assert isinstance(err, AttenuoError) and "over 300 bytes" in str(err)

    client, _ = make(lambda r: httpx.Response(200, json=result("y" * 500)))
    _, err = await collect_until_error(
        client.call_tool_stream("TOK", "github", "read_file", max_event_bytes=300)
    )
    assert "over 300 bytes" in str(err)

    with pytest.raises(ValueError):
        client.call_tool_stream("TOK", "github", "read_file", max_event_bytes=0)


async def test_stream_that_ends_without_the_response(make: Any) -> None:  # noqa: F811
    # Includes a final event without its blank line, which is dropped.
    body = event(progress(1)) + "data: " + json.dumps(result("cut short"))
    client, _ = make(lambda r: httpx.Response(200, text=body, headers=SSE))
    seen, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert len(seen) == 1
    assert isinstance(err, AttenuoError) and "ended before" in str(err)


async def test_stream_passes_other_messages_and_stops_at_the_response(
    make: Any,  # noqa: F811
) -> None:
    request = {"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage", "params": {}}
    other = result("for another request", request_id=99)
    body = event(request) + event(other) + event(result("mine")) + event(progress(9))
    client, _ = make(lambda r: httpx.Response(200, text=body, headers=SSE))
    events = await collect(client.call_tool_stream("TOK", "github", "read_file"))
    assert [e.message.get("id") for e in events] == ["srv-1", 99, 1]
    assert events[-1].result is not None and events[-1].result.text == "mine"


def test_missing_token_raises_at_the_call() -> None:
    with Client(BASE) as ob, pytest.raises(ValueError, match="no token"):
        ob.call_tool_stream(None, "github", "read_file")


def chunks(body: bytes, size: int) -> list[bytes]:
    return [body[i : i + size] for i in range(0, len(body), size)]


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_stream_yields_each_event_as_it_arrives(kind: str) -> None:
    body = (event(progress(1)) + event(progress(2)) + event(result("ok"))).encode()
    parts = chunks(body, 5)
    sent: list[int] = []  # how many chunks the server had sent when each event came out

    def sync_body() -> Iterator[bytes]:
        for i, c in enumerate(parts):
            sent.append(i)
            yield c

    async def async_body() -> AsyncIterator[bytes]:
        for i, c in enumerate(parts):
            sent.append(i)
            yield c

    def handler(r: httpx.Request) -> httpx.Response:
        content: Any = sync_body() if kind == "sync" else async_body()
        return httpx.Response(200, content=content, headers=SSE)

    seen_at: list[int] = []
    if kind == "sync":
        with Client(BASE, transport=httpx.MockTransport(handler)) as ob:
            for _ in ob.call_tool_stream("TOK", "github", "read_file"):
                seen_at.append(len(sent))
    else:
        async with AsyncClient(BASE, transport=httpx.MockTransport(handler)) as aob:
            async for _ in aob.call_tool_stream("TOK", "github", "read_file"):
                seen_at.append(len(sent))
    assert len(seen_at) == 3
    assert seen_at[0] < seen_at[1] < seen_at[2]  # not read to the end first


async def test_stream_with_dpop_retries_once_on_use_dpop_nonce(make: Any) -> None:  # noqa: F811
    s, key = Signer(), DpopKey.generate()
    child = bound(s, key.thumbprint, ("planner", "coder"))
    server = NonceServer(
        lambda r: httpx.Response(200, text=event(progress(1)) + event(result("bound")), headers=SSE)
    )
    client, rec = make(server, dpop_key=key)
    events = await collect(client.call_tool_stream(child, "github", "read_file", {}))
    assert events[-1].result is not None and events[-1].result.text == "bound"
    assert server.seen == [None, "n-1"]
    first, retry = rec.requests
    assert retry.headers["authorization"] == f"DPoP {child}"
    claims = verify(retry.headers["dpop"])[1]
    assert claims["htm"] == "POST" and claims["htu"] == f"{BASE}/mcp/github"
    assert retry.content == first.content
    assert isinstance(rec, Recorder)
