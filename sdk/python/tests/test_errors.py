"""The error contract: what a 401, a denial, a REST error and a transport failure carry."""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest

from attenuo import (
    AdminClient,
    ApiError,
    ApprovalRequired,
    AsyncAdminClient,
    AsyncClient,
    AttenuoError,
    BudgetLimit,
    Client,
    Denied,
    DpopKey,
    RpcError,
    RunUsage,
    TransportError,
    TransportTimeout,
    Unauthorized,
    UntrustedArg,
    UserWindow,
    WindowUsage,
)

from .test_client import BASE, call, make, rpc_err  # noqa: F401  (pytest fixture)
from .test_stream import collect_until_error

DEC = "6f1c2d9e-0000-4000-8000-000000000001"
PROXY_401_REASONS = [
    "lease_revoked",
    "lease_expired",
    "lease_unknown",
    "dpop_required",
    "invalid_dpop_proof",
    "use_dpop_nonce",
    "token_expired",
    "invalid_token",
    "missing_token",
]


# --- K-1: a proxy 401 names its reason and record ------------------------------------------


@pytest.mark.parametrize("reason", PROXY_401_REASONS)
async def test_proxy_401_carries_the_reason(make: Any, reason: str) -> None:  # noqa: F811
    data = {"reason": reason, "decision_id": DEC}
    client, _ = make(
        lambda r: rpc_err(
            -32001,
            f"attenuo: unauthorized: {reason}",
            data,
            status=401,
            headers={"x-attenuo-decision-id": DEC},
        )
    )
    with pytest.raises(Unauthorized) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert e.value.reason == reason
    assert e.value.decision_id == DEC
    assert e.value.data == data
    # What it always held is unchanged.
    assert (e.value.status, e.value.error) == (401, "unauthorized")
    assert e.value.detail == f"attenuo: unauthorized: {reason}"


async def test_proxy_401_decision_id_needs_the_header(make: Any) -> None:  # noqa: F811
    """SR-32 for a 401: an id the header does not name may come from an upstream."""
    data = {"reason": "lease_revoked", "decision_id": DEC}
    for headers in (None, {"x-attenuo-decision-id": "another-id"}):
        client, _ = make(lambda r, h=headers: rpc_err(-32001, "m", data, status=401, headers=h))
        with pytest.raises(Unauthorized) as e:
            await call(client, "list_tools", "TOK", "github")
        assert e.value.reason == "lease_revoked"
        assert e.value.decision_id is None


async def test_a_minus_32001_inside_a_200_answer_keeps_no_reason(make: Any) -> None:  # noqa: F811
    """Only the proxy answers with HTTP 401; an upstream can put `-32001` in a 200 body."""
    data = {"reason": "lease_revoked", "decision_id": DEC}
    client, _ = make(lambda r: rpc_err(-32001, "m", data, status=200))
    with pytest.raises(Unauthorized) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert (e.value.reason, e.value.decision_id) == ("unauthorized", None)


async def test_proxy_401_without_data_is_plain_unauthorized(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: rpc_err(-32001, "who are you", status=401))
    with pytest.raises(Unauthorized) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert (e.value.reason, e.value.decision_id, e.value.data) == ("unauthorized", None, {})


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        # A bearer refused at a REST route: the reason is in `error_description` (and `detail`).
        (
            {
                "error": "unauthorized",
                "detail": "token_expired",
                "error_description": "token_expired",
            },
            "token_expired",
        ),
        # A DPoP refusal names itself in `error`.
        ({"error": "dpop_required", "detail": "a proof is required"}, "dpop_required"),
        ({"error": "invalid_dpop_proof", "detail": "x"}, "invalid_dpop_proof"),
    ],
)
async def test_rest_401_carries_the_reason(
    make: Any,  # noqa: F811
    body: dict[str, Any],
    reason: str,
) -> None:
    client, _ = make(lambda r: httpx.Response(401, json=body))
    with pytest.raises(Unauthorized) as e:
        await call(client, "renew", "TOK")
    assert e.value.reason == reason
    assert e.value.error == body["error"]
    assert e.value.data == {}


async def test_rest_401_that_is_not_json(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: httpx.Response(401, text="go away"))
    with pytest.raises(Unauthorized) as e:
        await call(client, "renew", "TOK")
    assert (e.value.error, e.value.reason) == ("http_error", "unauthorized")


# --- K-4: a REST error names its audit record ----------------------------------------------


async def test_api_error_carries_the_decision_id(make: Any) -> None:  # noqa: F811
    body = {"error": "invalid_scope", "detail": "delegation chain is invalid", "decision_id": DEC}
    client, _ = make(
        lambda r: httpx.Response(400, json=body, headers={"x-attenuo-decision-id": DEC})
    )
    with pytest.raises(ApiError) as e:
        await call(client, "exchange", "a.b.c", "coder", ["github:read_file"])
    assert e.value.decision_id == DEC
    assert e.value.error == "invalid_scope"
    assert not isinstance(e.value, Unauthorized)

    # Without the header the body's id is not trusted; a refusal without a record has none.
    for resp in (
        httpx.Response(400, json=body),
        httpx.Response(400, json={"error": "invalid_request", "detail": "x"}),
    ):
        client, _ = make(lambda r, resp=resp: resp)
        with pytest.raises(ApiError) as e2:
            await call(client, "exchange", "a.b.c", "coder", ["github:read_file"])
        assert e2.value.decision_id is None


# --- K-3: a denial keeps what the server says about it -------------------------------------


def denial(data: dict[str, Any], code: int = -32003) -> Any:
    return lambda r: rpc_err(
        code, "attenuo: denied", data, headers={"x-attenuo-decision-id": data["decision_id"]}
    )


async def test_denied_budget_exhausted_has_the_limit(make: Any) -> None:  # noqa: F811
    limit = {"hop": 1, "kind": "sum", "arg": "amount", "max": 100, "used": 90}
    data = {"reason": "budget_exhausted", "decision_id": DEC, "limit": limit}
    client, _ = make(denial(data))
    with pytest.raises(Denied) as e:
        await call(client, "call_tool", "TOK", "pay", "send", {"amount": 20})
    assert e.value.reason == "budget_exhausted"
    assert e.value.limit == BudgetLimit(hop=1, kind="sum", used=90, arg="amount", max=100)
    assert e.value.limit.to_json() == limit  # stated back as it came
    assert e.value.data == data
    assert e.value.usage is None and e.value.untrusted_args == []


async def test_denied_usage_and_untrusted_args(make: Any) -> None:  # noqa: F811
    data = {
        "reason": "policy_deny",
        "decision_id": DEC,
        "usage": {
            "calls": 3,
            "amount": 250,
            "destination_seen": True,
            "user_window": {"hour": {"calls": 1, "amount": 50}, "day": {"calls": 4, "amount": 900}},
        },
        "untrusted_args": [
            {"arg": "to", "seq": 41, "kind": "leaf"},
            {"arg": "body", "kind": "unreadable"},
        ],
    }
    client, _ = make(denial(data))
    with pytest.raises(Denied) as e:
        await call(client, "call_tool", "TOK", "mail", "send")
    assert e.value.usage == RunUsage(
        calls=3,
        amount=250,
        destination_seen=True,
        user_window=UserWindow(hour=WindowUsage(1, 50), day=WindowUsage(4, 900)),
    )
    assert e.value.untrusted_args == [
        UntrustedArg(arg="to", kind="leaf", seq=41),
        UntrustedArg(arg="body", kind="unreadable", seq=None),
    ]
    assert e.value.limit is None

    # Without per-user windows (all zero, so left out by the server).
    data2 = {**data, "usage": {"calls": 0, "amount": 0, "destination_seen": False}}
    client, _ = make(denial(data2))
    with pytest.raises(Denied) as e2:
        await call(client, "call_tool", "TOK", "mail", "send")
    assert e2.value.usage == RunUsage(0, 0, False, None)


async def test_approval_required_keeps_its_data(make: Any) -> None:  # noqa: F811
    data = {
        "reason": "approval_required",
        "decision_id": DEC,
        "call_hash": "ab" * 32,
        "approval_id": "appr-1",
        "expires_at": "2026-11-12T10:00:00Z",
        "untrusted_args": [{"arg": "repo", "seq": 7, "kind": "kgram"}],
        "usage": {"calls": 1, "amount": 0, "destination_seen": False},
    }
    client, _ = make(denial(data, code=-32008))
    with pytest.raises(ApprovalRequired) as e:
        await call(client, "call_tool", "TOK", "github", "delete_repo")
    assert (e.value.approval_id, e.value.call_hash) == ("appr-1", "ab" * 32)
    assert e.value.expires_at is not None
    assert e.value.untrusted_args == [UntrustedArg("repo", "kgram", 7)]
    assert e.value.usage == RunUsage(1, 0, False)
    assert e.value.data == data


def test_denied_tolerates_odd_shapes() -> None:
    d = Denied("x", "id", data={"limit": "no", "usage": [1], "untrusted_args": [3, {"arg": 1}]})
    assert d.limit is None and d.usage is None
    assert d.untrusted_args == [UntrustedArg(arg="1", kind="", seq=None)]
    # Positional construction as before keeps working.
    assert Denied("policy_deny", "id-1", "m").data == {}
    assert ApprovalRequired("id", "a").data == {}


async def test_forged_denial_data_is_not_typed(make: Any) -> None:  # noqa: F811
    """An upstream's own -32003 stays an RpcError: nothing in it becomes a typed field."""
    data = {"reason": "budget_exhausted", "decision_id": DEC, "limit": {"hop": 0}}
    client, _ = make(lambda r: rpc_err(-32003, "denied", data))
    with pytest.raises(RpcError) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert not isinstance(e.value, Denied)


# --- K-12: transport failures are AttenuoErrors ---------------------------------------------


def failing(exc: Exception) -> Any:
    def handler(r: httpx.Request) -> httpx.Response:
        raise exc

    return handler


@pytest.mark.parametrize(
    "exc",
    [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("bye")],
)
async def test_transport_failure_is_a_transport_error(make: Any, exc: Exception) -> None:  # noqa: F811
    client, _ = make(failing(exc))
    for name, args in (
        ("call_tool", ("TOK", "github", "read_file")),
        ("renew", ("TOK",)),
        ("jwks", ()),
    ):
        with pytest.raises(TransportError) as e:
            await call(client, name, *args)
        assert isinstance(e.value, AttenuoError)
        assert e.value.__cause__ is exc
        # Code written against httpx before keeps catching it.
        assert isinstance(e.value, httpx.TransportError)
        assert e.value.request.url.host == "ob.test"
        assert type(exc).__name__ in str(e.value)


class BrokenBody(httpx.SyncByteStream, httpx.AsyncByteStream):
    """Sends ``head``, then the connection drops."""

    def __init__(self, head: bytes) -> None:
        self.head = head

    def __iter__(self) -> Iterator[bytes]:
        yield self.head
        raise httpx.ReadError("connection reset")

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.head
        raise httpx.ReadError("connection reset")


async def test_transport_failure_while_streaming(make: Any) -> None:  # noqa: F811
    progress = b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
    client, _ = make(
        lambda r: httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=BrokenBody(progress)
        )
    )
    seen, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert [e.method for e in seen] == ["notifications/progress"]
    assert isinstance(err, TransportError)
    assert isinstance(err.__cause__, httpx.ReadError)


@pytest.mark.parametrize("cls", [AdminClient, AsyncAdminClient])
async def test_admin_transport_failure(cls: Any) -> None:
    exc = httpx.ConnectError("refused")
    client = cls(BASE, "adm", transport=httpx.MockTransport(failing(exc)))
    with pytest.raises(TransportError) as e:
        await call(client, "lease_status", "lease-1")
    assert e.value.__cause__ is exc


async def test_nonce_retry_still_works_and_its_failure_is_wrapped(make: Any) -> None:  # noqa: F811
    """The nonce retry looks at answers only: a refusal is retried with the nonce, and a
    failure of the retry is a TransportError."""
    sent: list[httpx.Request] = []

    def handler(r: httpx.Request) -> httpx.Response:
        sent.append(r)
        if len(sent) == 1:
            return httpx.Response(
                401,
                json={"error": "use_dpop_nonce"},
                headers={
                    "dpop-nonce": "n-1",
                    "www-authenticate": 'DPoP error="use_dpop_nonce"',
                },
            )
        raise httpx.RemoteProtocolError("Server disconnected without sending a response")

    client, _ = make(handler, dpop_key=DpopKey.generate())
    with pytest.raises(TransportError) as e:
        await call(client, "renew", "a.b.c")
    assert len(sent) == 2
    assert isinstance(e.value.__cause__, httpx.RemoteProtocolError)


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
    return port


async def test_connection_refused_by_a_real_socket() -> None:
    url = f"http://127.0.0.1:{closed_port()}"
    with Client(url, timeout=5) as ob, pytest.raises(TransportError) as e:
        ob.call_tool("TOK", "github", "read_file")
    assert isinstance(e.value.__cause__, httpx.ConnectError)
    async with AsyncClient(url, timeout=5) as aob:
        with pytest.raises(TransportError) as e2:
            await aob.renew("TOK")
    assert isinstance(e2.value.__cause__, httpx.ConnectError)


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectTimeout("c"),
        httpx.ReadTimeout("r"),
        httpx.WriteTimeout("w"),
        httpx.PoolTimeout("p"),
    ],
)
async def test_a_timeout_is_a_transport_timeout(make: Any, exc: Exception) -> None:  # noqa: F811
    client, _ = make(failing(exc))
    with pytest.raises(TransportTimeout) as e:
        await call(client, "renew", "TOK")
    assert isinstance(e.value, TransportError) and isinstance(e.value, AttenuoError)
    assert isinstance(e.value, httpx.TimeoutException)
    assert e.value.__cause__ is exc
    assert e.value.request.url.path == "/token/renew"


async def test_a_refused_connection_is_not_a_timeout(make: Any) -> None:  # noqa: F811
    client, _ = make(failing(httpx.ConnectError("refused")))
    with pytest.raises(TransportError) as e:
        await call(client, "renew", "TOK")
    assert not isinstance(e.value, TransportTimeout)
    assert not isinstance(e.value, httpx.TimeoutException)


async def test_a_read_timeout_while_streaming_is_a_transport_timeout(make: Any) -> None:  # noqa: F811
    class SlowBody(httpx.SyncByteStream, httpx.AsyncByteStream):
        def __iter__(self) -> Iterator[bytes]:
            yield b": keep-alive\n\n"
            raise httpx.ReadTimeout("no data")

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b": keep-alive\n\n"
            raise httpx.ReadTimeout("no data")

    client, _ = make(
        lambda r: httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=SlowBody()
        )
    )
    _, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file"))
    assert isinstance(err, TransportTimeout)
    assert isinstance(err.__cause__, httpx.ReadTimeout)
