"""Token refresher: schedule, failure policy and DPoP, on a fake clock (no sleeping)."""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from attenuo import (
    ApiError,
    AsyncClient,
    AsyncTokenRefresher,
    Client,
    DpopKey,
    RefreshError,
    Token,
    TokenRefresher,
    decode_token,
)
from attenuo.mcp import TokenAuth

from .helpers import Signer

BASE = "http://ob.test"
signer = Signer()


T0 = time.time()


class FakeClock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> float:
        return self.t


def mint(ttl: int = 100, *, jkt: str | None = None, at: float = T0) -> Token:
    claims: dict[str, Any] = {"cnf": {"jkt": jkt}} if jkt else {}
    raw = signer.mint(("planner", "coder"), exp_delta=ttl, claims=claims, at=at)
    return decode_token(raw)


class Server:
    """A renew endpoint whose answers the test scripts."""

    def __init__(self, clock: FakeClock, interval: int = 30) -> None:
        self.clock = clock
        self.interval = interval
        self.renewals = 0
        self.script: list[httpx.Response | Exception] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/token/renew"
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        self.renewals += 1
        exp = self.clock.t + self.interval
        return httpx.Response(
            200,
            json={
                "lease": "lease-1",
                "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)),
                "expires_in": self.interval,
            },
        )


def error(status: int, code: str, detail: str = "") -> httpx.Response:
    return httpx.Response(status, json={"error": code, "detail": detail})


def make(
    ttl: int = 100,
    *,
    interval: int = 30,
    exchange: Callable[[], Token] | None = None,
    token: Token | None = None,
    on_change: Callable[[Token], None] | None = None,
    **kw: Any,
) -> tuple[TokenRefresher, FakeClock, Server, list[Token], list[RefreshError]]:
    clock = FakeClock()
    server = Server(clock, interval)
    changes: list[Token] = []
    errors: list[RefreshError] = []
    client = Client(BASE, transport=httpx.MockTransport(server))
    r = TokenRefresher(
        client,
        token or mint(ttl),
        exchange or (lambda: mint(ttl, at=clock.t)),
        clock=clock,
        rng=random.Random(1),
        on_change=on_change or changes.append,
        on_error=errors.append,
        **kw,
    )
    return r, clock, server, changes, errors


def pick(tok: Token) -> Callable[[], Token]:
    return lambda: tok


def advance(r: TokenRefresher, clock: FakeClock, seconds: float) -> None:
    """Run the loop on the fake clock for ``seconds``, sleeping exactly as the thread would."""
    end = clock.t + seconds
    while clock.t < end:
        wait = r.tick()
        if wait is None:
            return
        clock.t = min(clock.t + max(wait, 0.001), end)
    r.tick()


def test_renews_at_a_third_of_the_lease_interval() -> None:
    r, clock, server, changes, _ = make(ttl=1000, interval=30, lease_interval=30)
    advance(r, clock, 9.9)
    assert server.renewals == 0
    advance(r, clock, 0.2)  # 10 s
    assert server.renewals == 1
    advance(r, clock, 30)  # 40 s: renewed again at 20 and 30
    assert server.renewals == 4
    assert not changes


def test_learns_the_interval_from_the_first_renewal() -> None:
    r, clock, server, _, _ = make(ttl=1000, interval=60)
    advance(r, clock, 0.001)
    assert server.renewals == 1  # right away
    advance(r, clock, 19.9)
    assert server.renewals == 1
    advance(r, clock, 0.2)  # 60 / 3 = 20 s
    assert server.renewals == 2


def test_exchanges_before_exp_with_default_margin() -> None:
    old = mint(100)
    new = mint(100, at=T0 + 80)
    r, clock, _, changes, errors = make(100, lease_interval=30, exchange=lambda: new, token=old)
    advance(r, clock, 79)  # margin = 20% of 100 s = 20 s: due at ~80 s
    assert r.token is old
    advance(r, clock, 3)
    assert r.token is new and changes == [new]
    assert not errors


def test_margin_has_a_floor_and_is_configurable() -> None:
    short, clock_a, *_ = make(10, lease_interval=100)
    assert short._core.exchange_at - clock_a.t == pytest.approx(5, abs=1.5)  # min 5 s margin
    tiny, clock_b, *_ = make(4, lease_interval=100)
    assert tiny._core.exchange_at - clock_b.t == pytest.approx(2, abs=1.5)  # at most half the life
    custom, clock_c, *_ = make(100, lease_interval=100, margin=50)
    assert custom._core.exchange_at - clock_c.t == pytest.approx(50, abs=1.5)


def test_current_token_getter_and_provider_for_token_auth() -> None:
    new = mint(100, at=T0 + 90)
    r, clock, *_ = make(100, lease_interval=30, exchange=lambda: new)
    old_jwt = str(r.token)
    auth = TokenAuth(r)
    req = httpx.Request("POST", f"{BASE}/mcp/github")
    assert next(auth.auth_flow(req)).headers["Authorization"] == f"Bearer {old_jwt}"
    advance(r, clock, 90)
    req2 = httpx.Request("POST", f"{BASE}/mcp/github")
    assert next(auth.auth_flow(req2)).headers["Authorization"] == f"Bearer {new.jwt}"


def test_transient_failures_back_off_with_jitter_then_recover() -> None:
    r, clock, server, _, errors = make(1000, lease_interval=30)
    server.script = [error(503, "temporarily_unavailable"), httpx.ConnectError("down")]
    waits: list[float] = []
    clock.t += 10
    for _ in range(3):
        before = clock.t
        wait = r.tick()
        assert wait is not None
        waits.append(wait)
        clock.t = before + wait
    # Full-jitter ceiling doubles from 1 s: first retry in [0.5, 1], second in [1, 2].
    assert 0.5 <= waits[0] <= 1.0
    assert 1.0 <= waits[1] <= 2.0
    assert server.renewals == 1  # the third attempt got through
    assert not errors and r.error is None


def test_backoff_is_capped() -> None:
    r, clock, server, _, _ = make(100_000, lease_interval=30)
    server.script = [error(503, "x")] * 12
    clock.t += 10
    last = 0.0
    for _ in range(12):
        last = r.tick() or 0.0
        clock.t += last
    assert 15 <= last <= 30


def test_lease_revoked_is_terminal_and_does_not_loop() -> None:
    r, clock, server, _, errors = make(1000, lease_interval=30)
    server.script = [error(400, "invalid_grant", "lease_revoked")]
    clock.t += 10
    assert r.tick() is None
    assert [e.reason for e in errors] == ["lease_revoked"]
    assert r.error is errors[0]
    assert isinstance(errors[0].__cause__, ApiError)
    assert r.tick() is None and len(errors) == 1  # nothing more is sent
    with pytest.raises(RefreshError):
        r()


@pytest.mark.parametrize(
    ("resp", "reason"),
    [
        (error(400, "invalid_grant", "lease_unknown"), "lease_revoked"),
        (error(400, "invalid_grant", "an ancestor lease is not live: lease_expired"), "lease_lost"),
        (error(401, "unauthorized", "token_expired"), "token_expired"),
        (error(401, "unauthorized", "invalid_token"), "refused"),
    ],
)
def test_renew_refusals_are_terminal(resp: httpx.Response, reason: str) -> None:
    r, clock, server, _, errors = make(1000, lease_interval=30)
    server.script = [resp]
    clock.t += 10
    r.tick()
    assert [e.reason for e in errors] == [reason]


def test_exchange_refusal_is_terminal_but_outage_is_not() -> None:
    attempts = {"n": 0}

    def exchange() -> Token:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ReadTimeout("slow")
        if attempts["n"] == 2:
            raise ApiError(400, "invalid_grant", "replayed")
        return mint(100)

    r, clock, _, changes, errors = make(100, lease_interval=30, exchange=exchange)
    clock.t += 85
    advance(r, clock, 5)
    assert attempts["n"] == 2 and not changes
    assert [e.reason for e in errors] == ["refused"]
    assert "replayed" not in str(errors[0])


def test_token_expiring_while_exchange_keeps_failing() -> None:
    def exchange() -> Token:
        raise httpx.ConnectError("down")

    r, clock, _, _, errors = make(30, lease_interval=300, exchange=exchange)
    advance(r, clock, 40)
    assert [e.reason for e in errors] == ["token_expired"]
    assert r.error is not None
    assert r.tick() is None


def test_dpop_replacement_must_use_the_same_key() -> None:
    key = DpopKey.generate()
    other = DpopKey.generate()
    bound = mint(100, jkt=key.thumbprint)
    ok = mint(100, jkt=key.thumbprint, at=T0 + 90)
    wrong = mint(100, jkt=other.thumbprint, at=T0 + 90)
    unbound = mint(100, at=T0 + 90)
    for replacement, adopted in ((ok, True), (wrong, False), (unbound, False)):
        r, clock, _, changes, errors = make(
            100, lease_interval=30, exchange=pick(replacement), token=bound
        )
        advance(r, clock, 95)
        assert (r.token is replacement) is adopted
        assert [e.reason for e in errors] == ([] if adopted else ["key_mismatch"])
        assert len(changes) == int(adopted)


def test_renewals_carry_the_dpop_proof_of_the_clients_key() -> None:
    key = DpopKey.generate()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={"lease": "l", "expires_at": "2099-01-01T00:00:00Z", "expires_in": 30},
        )

    clock = FakeClock()
    tok = mint(1000, jkt=key.thumbprint)
    client = Client(BASE, dpop_key=key, transport=httpx.MockTransport(handler))
    r = TokenRefresher(client, tok, lambda: tok, lease_interval=30, clock=clock)
    clock.t += 11
    r.tick()
    assert seen[0].headers["authorization"] == f"DPoP {tok.jwt}"
    assert seen[0].headers["dpop"].count(".") == 2


def test_nothing_is_logged_with_a_token(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="attenuo.refresh")
    new = mint(100, at=T0 + 80)
    r, clock, server, _, _ = make(100, lease_interval=30, exchange=lambda: new)
    old_jwt = r.token.jwt
    server.script = [error(503, "x")]
    advance(r, clock, 85)
    server.script = [error(400, "invalid_grant", "lease_revoked")]
    advance(r, clock, 40)
    text = caplog.text
    assert "giving up" in text and "token replaced" in text
    for jwt in (old_jwt, new.jwt):
        assert jwt not in text
        assert jwt.split(".")[1] not in text
        assert jwt not in repr(r._core.error)


def test_callback_exceptions_do_not_stop_the_refresher() -> None:
    new = mint(100, at=T0 + 80)

    def boom(_: Token) -> None:
        raise RuntimeError("secret " + new.jwt)

    r, clock, _, _, _ = make(100, lease_interval=30, exchange=lambda: new, on_change=boom)
    advance(r, clock, 90)
    assert r.token is new and r.error is None


def test_bad_arguments() -> None:
    with pytest.raises(ValueError):
        make(lease_interval=0)
    with pytest.raises(ValueError):
        make(margin=-1)


def test_thread_start_stop() -> None:
    # Real thread, real (short) waits only: far-off schedule, so stop() returns at once.
    r, _, _, _, _ = make(100_000, lease_interval=3000)
    with r:
        assert r._thread is not None and r._thread.is_alive()
    assert r._thread is not None and not r._thread.is_alive()


async def test_async_refresher_on_fake_clock() -> None:
    clock = FakeClock()
    calls = {"renew": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["renew"] += 1
        return httpx.Response(
            200, json={"lease": "l", "expires_at": "2099-01-01T00:00:00Z", "expires_in": 30}
        )

    new = mint(100, at=T0 + 81)

    async def exchange() -> Token:
        return new

    changes: list[Token] = []
    errors: list[RefreshError] = []
    client = AsyncClient(BASE, transport=httpx.MockTransport(handler))
    r = AsyncTokenRefresher(
        client,
        mint(100),
        exchange,
        lease_interval=30,
        clock=clock,
        on_change=changes.append,
        on_error=errors.append,
    )
    clock.t += 11
    assert await r.tick() is not None and calls["renew"] == 1
    clock.t += 70
    await r.tick()
    assert r.token is new and changes == [new]
    clock.t += 1000
    assert await r.tick() is None
    assert [e.reason for e in errors] == ["token_expired"]
    await client.aclose()


async def test_async_task_start_stop() -> None:
    client = AsyncClient(BASE, transport=httpx.MockTransport(lambda r: httpx.Response(500)))

    async def exchange() -> Token:
        return mint(100_000)

    async with AsyncTokenRefresher(client, mint(100_000), exchange, lease_interval=3000) as r:
        assert r._task is not None and not r._task.done()
    assert r._task is not None and r._task.done()
    await client.aclose()
