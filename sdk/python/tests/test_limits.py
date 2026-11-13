"""The server's load refusals (``[limits]``): typed errors, and the opt-in retry of them."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from attenuo import (
    AdminClient,
    ApiError,
    AsyncAdminClient,
    AsyncClient,
    Client,
    Denied,
    DpopKey,
    RateLimited,
    RpcError,
    TransportError,
    Unauthorized,
    Unavailable,
    _retry,
)

from .helpers import Signer, token_response
from .test_client import BASE, call, make, rpc_err, rpc_ok  # noqa: F401  (pytest fixture)
from .test_dpop import verify
from .test_stream import SSE, collect, collect_until_error, event, result

DEC = "6f1c2d9e-0000-4000-8000-000000000001"


# --- the server's answers, as `crates/attenuo-server/src/limits.rs` and the proxy write them --


def rest_overloaded(retry_after: str | None = "1") -> httpx.Response:
    return httpx.Response(
        503,
        json={
            "error": "temporarily_unavailable",
            "detail": "the server is handling too many requests; retry later",
            "error_description": "overloaded",
        },
        headers={} if retry_after is None else {"retry-after": retry_after},
    )


def rest_handler_timeout() -> httpx.Response:
    return httpx.Response(
        503,
        json={
            "error": "temporarily_unavailable",
            "detail": "the request took too long to answer; retry later",
            "error_description": "request_timeout",
        },
        headers={"retry-after": "1"},
    )


def rest_body_timeout() -> httpx.Response:
    return httpx.Response(
        408,
        json={"error": "request_timeout", "detail": "the request body did not arrive in time"},
    )


def rest_rate_limited(retry_after: str | None = "42") -> httpx.Response:
    return httpx.Response(
        429,
        json={
            "error": "rate_limited",
            "detail": "too many token requests for this agent; retry later",
            "error_description": "rate_limited",
        },
        headers={} if retry_after is None else {"retry-after": retry_after},
    )


def mcp_overloaded(retry_after: str | None = "1", reason: str = "overloaded") -> httpx.Response:
    return rpc_err(
        -32006,
        f"attenuo: temporarily unavailable: {reason}",
        {"reason": reason},
        status=503,
        headers={} if retry_after is None else {"retry-after": retry_after},
    )


def mcp_rate_limited(
    retry_after: str | None = "17", reason: str = "rate_limited"
) -> httpx.Response:
    return rpc_err(
        -32007,
        "attenuo: too many requests for this run; retry later",
        {"reason": reason},
        status=429,
        headers={} if retry_after is None else {"retry-after": retry_after},
    )


def denial() -> httpx.Response:
    return rpc_err(
        -32003,
        "attenuo: denied: policy_deny",
        {"reason": "policy_deny", "decision_id": DEC},
        headers={"x-attenuo-decision-id": DEC},
    )


OK_TOOL = {"content": [{"type": "text", "text": "ok"}], "isError": False}


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the client's retry waits instead of sleeping; no jitter."""
    seen: list[float] = []

    async def asleep(s: float) -> None:
        seen.append(s)

    monkeypatch.setattr(_retry, "_sleep", seen.append)
    monkeypatch.setattr(_retry, "_asleep", asleep)
    monkeypatch.setattr(_retry, "_random", lambda: 0.0)
    return seen


# --- typed errors ----------------------------------------------------------------------------


async def test_rest_overloaded_is_unavailable(make: Any) -> None:  # noqa: F811
    client, rec = make(lambda r: rest_overloaded())
    with pytest.raises(Unavailable) as e:
        await call(client, "renew", "TOK")
    err = e.value
    assert (err.status, err.error, err.reason, err.retry_after) == (
        503,
        "temporarily_unavailable",
        "overloaded",
        1,
    )
    assert err.description == "overloaded"
    assert err.detail == "the server is handling too many requests; retry later"
    assert err.data == {}
    assert isinstance(err, ApiError)
    assert not isinstance(err, (Denied, Unauthorized, RateLimited))
    assert len(rec.requests) == 1  # no retry by default


async def test_rest_handler_timeout_is_unavailable_with_its_reason(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: rest_handler_timeout())
    with pytest.raises(Unavailable) as e:
        await call(client, "authzen_evaluate", "TOK", "github", "read_file")
    assert (e.value.reason, e.value.retry_after) == ("request_timeout", 1)


async def test_rest_body_timeout_stays_a_plain_api_error(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: rest_body_timeout())
    with pytest.raises(ApiError) as e:
        await call(client, "renew", "TOK")
    assert type(e.value) is ApiError
    assert (e.value.status, e.value.error) == (408, "request_timeout")


async def test_rest_rate_limited(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: rest_rate_limited("42"))
    with pytest.raises(RateLimited) as e:
        await call(client, "exchange", Signer().mint(), "coder", ["github:read_file"])
    err = e.value
    assert (err.status, err.error, err.reason, err.retry_after) == (
        429,
        "rate_limited",
        "rate_limited",
        42,
    )
    assert not isinstance(err, (Denied, Unauthorized, Unavailable))


async def test_other_rest_503s_are_unavailable_with_their_reason(make: Any) -> None:  # noqa: F811
    body = {
        "error": "temporarily_unavailable",
        "detail": "x",
        "error_description": "jwks_unavailable",
    }
    client, _ = make(lambda r: httpx.Response(503, json=body))
    with pytest.raises(Unavailable) as e:
        await call(client, "renew", "TOK")
    assert (e.value.reason, e.value.retry_after) == ("jwks_unavailable", None)


@pytest.mark.parametrize(
    "response",
    [
        lambda: httpx.Response(503, text="<html>Service Unavailable</html>"),
        lambda: httpx.Response(503, json={"error": "internal", "detail": "x"}),
        lambda: httpx.Response(429, text="slow down", headers={"retry-after": "5"}),
        lambda: httpx.Response(429, json={"error": "too_many", "detail": "a front proxy"}),
    ],
)
async def test_other_503_and_429_answers_stay_plain_api_errors(
    make: Any,  # noqa: F811
    response: Callable[[], httpx.Response],
) -> None:
    client, _ = make(lambda r: response())
    with pytest.raises(ApiError) as e:
        await call(client, "renew", "TOK")
    assert type(e.value) is ApiError


async def test_mcp_overloaded_is_unavailable(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: mcp_overloaded("1"))
    with pytest.raises(Unavailable) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    err = e.value
    assert (err.status, err.error, err.reason, err.retry_after) == (
        503,
        "temporarily_unavailable",
        "overloaded",
        1,
    )
    assert err.data == {"reason": "overloaded"}
    assert err.detail == "attenuo: temporarily unavailable: overloaded"
    assert not isinstance(err, (Denied, Unauthorized, RpcError))


async def test_mcp_rate_limited(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: mcp_rate_limited("17"))
    with pytest.raises(RateLimited) as e:
        await call(client, "list_tools", "TOK", "github")
    err = e.value
    assert (err.status, err.error, err.reason, err.retry_after) == (
        429,
        "rate_limited",
        "rate_limited",
        17,
    )
    assert err.data == {"reason": "rate_limited"}
    assert not isinstance(err, (Denied, Unauthorized, RpcError))


async def test_mcp_session_limits_are_typed_with_their_reason(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: mcp_rate_limited("30", "too_many_sessions"))
    with pytest.raises(RateLimited) as e:
        await call(client, "initialize", "TOK", "github")
    assert (e.value.reason, e.value.retry_after) == ("too_many_sessions", 30)
    client, _ = make(lambda r: mcp_overloaded("30", "session_registry_full"))
    with pytest.raises(Unavailable) as e2:
        await call(client, "initialize", "TOK", "github")
    assert (e2.value.reason, e2.value.retry_after) == ("session_registry_full", 30)


@pytest.mark.parametrize(
    "response",
    [
        # The proxy always sets Retry-After on its refusals: without it, an upstream's error.
        lambda: mcp_overloaded(retry_after=None),
        lambda: mcp_rate_limited(retry_after=None),
        # Not the status the proxy pairs with the code.
        lambda: rpc_err(-32006, "busy", {"reason": "overloaded"}, headers={"retry-after": "1"}),
        lambda: rpc_err(
            -32007, "x", {"reason": "rate_limited"}, status=503, headers={"retry-after": "1"}
        ),
    ],
)
async def test_mcp_refusal_without_the_proxys_marks_stays_an_rpc_error(
    make: Any,  # noqa: F811
    response: Callable[[], httpx.Response],
) -> None:
    client, _ = make(lambda r: response())
    with pytest.raises(RpcError) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert e.value.code in (-32006, -32007)


@pytest.mark.parametrize(
    ("status", "number", "data", "cls", "stable"),
    [
        (503, -32006, {"code": "overloaded", "reason": "overloaded"}, Unavailable, "overloaded"),
        (503, -32006, {"reason": "session_registry_full"}, Unavailable, "session_registry_full"),
        (503, -32006, {}, Unavailable, "temporarily_unavailable"),
        (
            429,
            -32007,
            {"code": "rate_limited", "reason": "rate_limited"},
            RateLimited,
            "rate_limited",
        ),
        (429, -32007, {"reason": "too_many_sessions"}, RateLimited, "too_many_sessions"),
    ],
)
async def test_proxy_load_refusal_stable_code(
    make: Any,  # noqa: F811
    status: int,
    number: int,
    data: dict[str, Any],
    cls: type[ApiError],
    stable: str,
) -> None:
    client, _ = make(
        lambda r: rpc_err(
            number, "attenuo: refused", data, status=status, headers={"retry-after": "1"}
        )
    )
    with pytest.raises(cls) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert e.value.stable_code == e.value.code == stable


def test_load_refusal_stable_code_prefers_data_code() -> None:
    assert Unavailable("overloaded", 1, "", {"code": "overloaded"}).stable_code == "overloaded"
    assert Unavailable("overloaded").stable_code == "overloaded"
    assert (
        RateLimited("rate_limited", data={"code": "too_many_sessions"}).code == "too_many_sessions"
    )


@pytest.mark.parametrize("value", ["soon", "1.5", "-1", "", " ", "Wed, 21 Oct 2026 07:28:00 GMT"])
async def test_malformed_retry_after_is_none(make: Any, value: str) -> None:  # noqa: F811
    client, _ = make(lambda r: rest_rate_limited(value))
    with pytest.raises(RateLimited) as e:
        await call(client, "renew", "TOK")
    assert e.value.retry_after is None
    client, _ = make(lambda r: mcp_overloaded(value))
    with pytest.raises(Unavailable) as e2:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert e2.value.retry_after is None


async def test_missing_retry_after_on_a_rest_route_is_none(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: rest_overloaded(None))
    with pytest.raises(Unavailable) as e:
        await call(client, "renew", "TOK")
    assert e.value.retry_after is None


async def test_retry_after_with_spaces_is_read(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: rest_rate_limited(" 7 "))
    with pytest.raises(RateLimited) as e:
        await call(client, "renew", "TOK")
    assert e.value.retry_after == 7


async def test_denials_and_401s_map_as_before(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: denial())
    with pytest.raises(Denied) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert (e.value.reason, e.value.decision_id) == ("policy_deny", DEC)
    client, _ = make(
        lambda r: rpc_err(-32001, "m", {"reason": "lease_revoked"}, status=401),
    )
    with pytest.raises(Unauthorized) as e2:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert e2.value.reason == "lease_revoked"


async def test_a_streamed_call_raises_the_refusal_before_any_event(make: Any) -> None:  # noqa: F811
    client, _ = make(lambda r: mcp_rate_limited("9"))
    seen, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file", {}))
    assert seen == []
    assert isinstance(err, RateLimited)
    assert err.retry_after == 9


@pytest.mark.parametrize("cls", [AdminClient, AsyncAdminClient])
async def test_admin_client_gets_the_typed_errors(cls: Any) -> None:
    client = cls(BASE, "adm", transport=httpx.MockTransport(lambda r: rest_overloaded()))
    with pytest.raises(Unavailable) as e:
        await call(client, "lease_status", "lease-1")
    assert e.value.reason == "overloaded"


# --- the opt-in retry ------------------------------------------------------------------------


def sequence(*responses: httpx.Response) -> Callable[[httpx.Request], httpx.Response]:
    """Answer with ``responses`` in order, then repeat the last one."""
    left = list(responses)

    def handler(r: httpx.Request) -> httpx.Response:
        return left.pop(0) if len(left) > 1 else left[0]

    return handler


async def test_retries_n_times_then_raises(make: Any, sleeps: list[float]) -> None:  # noqa: F811
    client, rec = make(lambda r: mcp_overloaded("1"), max_retries=3)
    with pytest.raises(Unavailable) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert e.value.reason == "overloaded"
    assert len(rec.requests) == 4
    assert sleeps == [1.0, 1.0, 1.0]


async def test_a_retry_that_succeeds_returns_the_answer(
    make: Any,  # noqa: F811
    sleeps: list[float],
) -> None:
    client, rec = make(
        sequence(mcp_rate_limited("3"), rpc_ok(OK_TOOL, {"x-attenuo-decision-id": DEC})),
        max_retries=2,
    )
    res = await call(client, "call_tool", "TOK", "github", "read_file", {"path": "a"})
    assert res.text == "ok"
    assert sleeps == [3.0]
    assert len(rec.requests) == 2
    # The same call both times.
    first, second = (json.loads(r.content) for r in rec.requests)
    assert first["params"] == second["params"] == {"name": "read_file", "arguments": {"path": "a"}}


async def test_rest_routes_are_retried_too(make: Any, sleeps: list[float]) -> None:  # noqa: F811
    child = Signer().mint(("planner", "coder"))
    client, rec = make(
        sequence(
            rest_overloaded("1"),
            rest_rate_limited("2"),
            httpx.Response(200, json=token_response(child, "lease-1")),
        ),
        max_retries=2,
    )
    tok = await call(client, "exchange", Signer().mint(), "coder", ["github:read_file"])
    assert tok.lease == "lease-1"
    assert sleeps == [1.0, 2.0]
    assert [r.url.path for r in rec.requests] == ["/token"] * 3


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch, sleeps: list[float]) -> list[float]:
    """A wall clock at 1,000,000 that the client's retry waits move forward; ``sleeps`` still
    records each wait. Returns a one-item list holding the time."""
    now = [1_000_000.0]

    def sleep(s: float) -> None:
        sleeps.append(s)
        now[0] += s

    async def asleep(s: float) -> None:
        sleep(s)

    monkeypatch.setattr(_retry, "_sleep", sleep)
    monkeypatch.setattr(_retry, "_asleep", asleep)
    monkeypatch.setattr(_retry, "_now", lambda: now[0])
    return now


def assertions_sent(rec: Any) -> list[str]:
    return [json.loads(r.content)["client_assertion"] for r in rec.requests]


async def test_an_exchange_resends_its_unexpired_client_assertion(
    make: Any,  # noqa: F811
    sleeps: list[float],
    clock: list[float],
) -> None:
    """A load refusal leaves the assertion unused (the server checks the limits first), so
    the retry sends the same one while it has not expired."""
    child = Signer().mint(("planner", "coder"))
    client, rec = make(
        sequence(
            rest_rate_limited("20"),
            rest_overloaded("1"),
            httpx.Response(200, json=token_response(child, "lease-1")),
        ),
        max_retries=3,
        max_retry_delay=60,
    )
    assertion = DpopKey.generate().client_assertion("coder", "https://a", iat=1_000_000)
    tok = await call(
        client, "exchange", Signer().mint(), "coder", "github:read_file", client_assertion=assertion
    )
    assert tok.lease == "lease-1"
    assert sleeps == [20.0, 1.0]
    assert assertions_sent(rec) == [assertion] * 3


async def test_an_exchange_does_not_resend_a_client_assertion_that_would_expire(
    make: Any,  # noqa: F811
    sleeps: list[float],
    clock: list[float],
) -> None:
    """The server would refuse an expired assertion (``client_assertion_expired``), so a wait
    that reaches its ``exp`` is not made: the refusal is raised for the caller to mint a new
    assertion. Here the first wait (30 s) fits the 60 s assertion, the second (30 s more,
    reaching ``exp`` exactly) does not."""
    client, rec = make(lambda r: rest_rate_limited("30"), max_retries=5, max_retry_delay=60)
    assertion = DpopKey.generate().client_assertion("coder", "https://a", iat=1_000_000)
    with pytest.raises(RateLimited) as e:
        await call(
            client,
            "exchange",
            Signer().mint(),
            "coder",
            "github:read_file",
            client_assertion=assertion,
        )
    assert e.value.retry_after == 30
    assert sleeps == [30.0]
    assert assertions_sent(rec) == [assertion] * 2

    # An assertion already past its `exp` by the client's clock is not sent again at all.
    rec.requests.clear()
    sleeps.clear()
    old = DpopKey.generate().client_assertion("coder", "https://a", iat=900_000)
    with pytest.raises(RateLimited):
        await call(
            client, "exchange", Signer().mint(), "coder", "github:read_file", client_assertion=old
        )
    assert sleeps == []
    assert len(rec.requests) == 1


async def test_an_exchange_without_a_readable_assertion_exp_retries_as_before(
    make: Any,  # noqa: F811
    sleeps: list[float],
    clock: list[float],
) -> None:
    """Without an ``exp`` the client can read, the server is left to judge the assertion; a
    secret is retried as before."""
    child = Signer().mint(("planner", "coder"))
    for auth in ({"client_assertion": "a.b.c"}, {"client_secret": "s"}):
        ok = httpx.Response(200, json=token_response(child, "lease-1"))
        client, _ = make(sequence(rest_rate_limited("50"), ok), max_retries=1, max_retry_delay=60)
        await call(client, "exchange", Signer().mint(), "coder", "github:read_file", **auth)
    assert sleeps == [50.0, 50.0]


@pytest.mark.parametrize(
    "claims,exp",
    [
        ({"exp": 1_000_060}, 1_000_060),
        ({"exp": 1_000_060.9}, 1_000_060),
        ({"exp": True}, None),
        ({"exp": "1000060"}, None),
        ({"exp": float("inf")}, None),
        ({}, None),
        ([1], None),
    ],
)
def test_assertion_expiry_reads_exp_without_verifying(claims: Any, exp: int | None) -> None:
    from attenuo import _wire

    def b64(v: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip("=")

    jwt = f"{b64({'alg': 'EdDSA'})}.{b64(claims)}.sig"
    assert _wire.assertion_expiry({"client_assertion": jwt}) == exp
    assert _wire.assertion_expiry({"client_assertion": "a.!.c"}) is None
    assert _wire.assertion_expiry({"client_assertion": "a.b"}) is None
    assert _wire.assertion_expiry({"client_secret": "s"}) is None


@pytest.mark.parametrize(
    "payload",
    [
        b'{"exp": 1' + b"0" * 400 + b"}",  # an int no float holds
        b'{"exp": -1' + b"0" * 400 + b"}",
        b"[" * 100_000 + b"]" * 100_000,  # deeper than Python's JSON decoder recurses
    ],
    ids=["huge", "huge-negative", "deep"],
)
def test_assertion_expiry_of_a_payload_it_cannot_use_is_none_sr113(payload: bytes) -> None:
    """An assertion the caller did not mint can carry any payload. One whose ``exp`` no
    deadline can be made of, or that the JSON decoder cannot read, is read as having no
    ``exp`` (the server judges it), instead of raising ``OverflowError`` after the request
    was sent or ``RecursionError`` before (SR-113)."""
    from attenuo import _retry, _wire

    part = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    exp = _wire.assertion_expiry({"client_assertion": f"e30.{part}.sig"})
    assert exp is None
    assert _retry.left_until(exp) is None


async def test_an_exchange_with_an_unusable_assertion_exp_gets_the_servers_answer_sr113(
    make: Any,  # noqa: F811
    sleeps: list[float],
    clock: list[float],
) -> None:
    """The deadline was computed on every answer, a success too, so an ``exp`` beyond the
    float range raised ``OverflowError`` whatever the server said (SR-113)."""
    child = Signer().mint(("planner", "coder"))
    part = base64.urlsafe_b64encode(b'{"exp": 1' + b"0" * 400 + b"}").decode().rstrip("=")
    ok = httpx.Response(200, json=token_response(child, "lease-1"))
    client, _ = make(sequence(rest_rate_limited("5"), ok), max_retries=1, max_retry_delay=60)
    tok = await call(
        client,
        "exchange",
        Signer().mint(),
        "coder",
        "github:read_file",
        client_assertion=f"e30.{part}.sig",
    )
    assert tok.lease == "lease-1"
    assert sleeps == [5.0]


@pytest.mark.parametrize(
    "name,args,path",
    [
        ("authzen_configuration", (), "/.well-known/authzen-configuration"),
        ("jwks", (), "/.well-known/jwks.json"),
    ],
)
async def test_unauthenticated_gets_are_retried(
    make: Any,  # noqa: F811
    sleeps: list[float],
    name: str,
    args: tuple[Any, ...],
    path: str,
) -> None:
    client, rec = make(sequence(rest_overloaded("1"), httpx.Response(200, json={})), max_retries=1)
    await call(client, name, *args)
    assert [r.url.path for r in rec.requests] == [path, path]
    assert sleeps == [1.0]


async def test_approval_decision_is_retried(make: Any, sleeps: list[float]) -> None:  # noqa: F811
    approval = {"approval_id": "ap-1", "state": "granted", "expired": False}
    client, rec = make(
        sequence(rest_overloaded("1"), httpx.Response(200, json=approval)), max_retries=1
    )
    got = await call(client, "grant_approval", "ap-1", "ID-TOKEN")
    assert got.approval_id == "ap-1"
    assert len(rec.requests) == 2
    assert all(r.headers["authorization"] == "Bearer ID-TOKEN" for r in rec.requests)


@pytest.mark.parametrize(
    "response,error",
    [
        (rest_handler_timeout, Unavailable),  # the handler may have done the work
        (rest_body_timeout, ApiError),
        (denial, Denied),
        (lambda: rpc_err(-32001, "m", {"reason": "invalid_token"}, status=401), Unauthorized),
        (lambda: mcp_rate_limited("30", "too_many_sessions"), RateLimited),
        (lambda: mcp_overloaded("30", "session_registry_full"), Unavailable),
        (lambda: mcp_overloaded(retry_after=None), RpcError),  # an upstream's own answer
        (lambda: httpx.Response(503, text="Service Unavailable"), ApiError),
    ],
)
async def test_only_load_refusals_are_retried(
    make: Any,  # noqa: F811
    sleeps: list[float],
    response: Callable[[], httpx.Response],
    error: type[Exception],
) -> None:
    client, rec = make(lambda r: response(), max_retries=3)
    with pytest.raises(error):
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert len(rec.requests) == 1
    assert sleeps == []


async def test_transport_errors_are_not_retried(make: Any, sleeps: list[float]) -> None:  # noqa: F811
    def handler(r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=r)

    client, rec = make(handler, max_retries=3)
    with pytest.raises(TransportError):
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert len(rec.requests) == 1


async def test_retry_after_over_the_cap_is_raised_at_once(
    make: Any,  # noqa: F811
    sleeps: list[float],
) -> None:
    client, rec = make(lambda r: mcp_rate_limited("45"), max_retries=3, max_retry_delay=30)
    with pytest.raises(RateLimited) as e:
        await call(client, "call_tool", "TOK", "github", "read_file")
    assert e.value.retry_after == 45
    assert len(rec.requests) == 1
    assert sleeps == []


async def test_missing_or_malformed_retry_after_waits_one_second(
    make: Any,  # noqa: F811
    sleeps: list[float],
) -> None:
    client, rec = make(
        sequence(rest_overloaded(None), rest_rate_limited("soon"), rest_overloaded("1")),
        max_retries=2,
    )
    with pytest.raises(Unavailable):
        await call(client, "renew", "TOK")
    assert sleeps == [1.0, 1.0]
    assert len(rec.requests) == 3


async def test_jitter_waits_longer_never_shorter_and_stays_under_the_cap(
    make: Any,  # noqa: F811
    sleeps: list[float],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_retry, "_random", lambda: 0.999)
    client, _ = make(
        sequence(rest_overloaded("1"), rest_rate_limited("9"), rest_overloaded("1")),
        max_retries=2,
        max_retry_delay=10,
    )
    with pytest.raises(Unavailable):
        await call(client, "renew", "TOK")
    assert 1.0 < sleeps[0] < 1.2
    assert sleeps[1] == 10.0  # 9 s plus up to 20 %, capped at max_retry_delay


async def test_each_retry_has_new_dpop_proofs(make: Any, sleeps: list[float]) -> None:  # noqa: F811
    client, rec = make(lambda r: mcp_overloaded("1"), max_retries=2, dpop_key=DpopKey.generate())
    with pytest.raises(Unavailable):
        await call(client, "call_tool", "TOK", "github", "read_file")
    jtis = {verify(r.headers["dpop"])[1]["jti"] for r in rec.requests}
    assert len(rec.requests) == 3
    assert len(jtis) == 3


async def test_a_streamed_call_is_retried_before_it_starts(
    make: Any,  # noqa: F811
    sleeps: list[float],
) -> None:
    sse = httpx.Response(200, headers=SSE, text=event(result("streamed")))
    client, rec = make(sequence(mcp_overloaded("1"), mcp_rate_limited("2"), sse), max_retries=2)
    events = await collect(client.call_tool_stream("TOK", "github", "read_file", {}))
    assert events[-1].result is not None
    assert events[-1].result.text == "streamed"
    assert sleeps == [1.0, 2.0]
    assert len(rec.requests) == 3


async def test_a_streamed_call_runs_out_of_retries(make: Any, sleeps: list[float]) -> None:  # noqa: F811
    client, rec = make(lambda r: mcp_overloaded("1"), max_retries=1)
    seen, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file", {}))
    assert (seen, type(err)) == ([], Unavailable)
    assert len(rec.requests) == 2


async def test_a_streamed_call_does_not_wait_past_its_deadline(
    make: Any,  # noqa: F811
    sleeps: list[float],
) -> None:
    client, rec = make(lambda r: mcp_rate_limited("5"), max_retries=3)
    _, err = await collect_until_error(
        client.call_tool_stream("TOK", "github", "read_file", {}, deadline=2.0)
    )
    assert isinstance(err, RateLimited)
    assert len(rec.requests) == 1
    assert sleeps == []


async def test_a_streamed_denial_is_not_retried(make: Any, sleeps: list[float]) -> None:  # noqa: F811
    client, rec = make(lambda r: denial(), max_retries=3)
    _, err = await collect_until_error(client.call_tool_stream("TOK", "github", "read_file", {}))
    assert isinstance(err, Denied)
    assert len(rec.requests) == 1


@pytest.mark.parametrize("cls", [Client, AsyncClient])
@pytest.mark.parametrize(
    "kw,exc",
    [
        ({"max_retries": -1}, ValueError),
        ({"max_retries": 11}, ValueError),
        ({"max_retries": True}, TypeError),
        ({"max_retries": 1.5}, TypeError),
        ({"max_retry_delay": 0}, ValueError),
        ({"max_retry_delay": 301}, ValueError),
    ],
)
def test_retry_options_are_checked(cls: Any, kw: dict[str, Any], exc: type[Exception]) -> None:
    with pytest.raises(exc):
        cls(BASE, **kw)
