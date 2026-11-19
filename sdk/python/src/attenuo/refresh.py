"""Keep a delegation token alive: renew its lease and re-exchange before it expires.

A delegation token has two clocks. Its **lease** lapses unless renewed (``POST /token/renew``,
every ``[issuer] lease_interval_seconds`` at most), and the token itself has a hard ``exp`` that
renewal cannot move. :class:`TokenRefresher` (threads) and :class:`AsyncTokenRefresher`
(``asyncio``) run both for you:

* renew the lease at a third of the lease interval;
* before ``exp`` (``margin`` seconds early; default 20% of the lifetime, at least 5 s) call
  your ``exchange`` function for a replacement token;
* expose the current token through ``.token`` (and ``refresher()``, which is what
  ``attenuo.mcp.TokenAuth`` wants) and tell ``on_change`` about each replacement;
* retry failures with jittered exponential backoff, but stop with :class:`~attenuo.RefreshError`
  (``on_error``) when the lease is revoked, the server refuses for good, or the token expires.

**The exchange function.** The server lets a parent token delegate to a given actor once, so
re-running ``client.exchange(same_parent, ...)`` is refused as ``replayed``. ``exchange`` must
therefore bring a *fresh* subject token each time (a new parent from the planner, or a new IdP
credential at hop 0) and return the new :class:`~attenuo.Token`. It runs on the refresher's
thread (or event loop); give it the same client you use for calls.

**DPoP.** A bound token (``Token.dpop_jkt``) stays bound to the same key: renewals go through
your client, which signs with its ``dpop_key``, and a replacement whose ``dpop_jkt`` differs
from the current token's is rejected (``key_mismatch``) rather than adopted.

Tokens are never logged; log lines carry lease ids and reason codes only.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import threading
import time
from collections.abc import Awaitable, Callable
from types import TracebackType

from ._wire import Lease
from .client import AsyncClient, Client
from .errors import ApiError, RefreshError, Unauthorized
from .token import Token

log = logging.getLogger("attenuo.refresh")

MIN_MARGIN = 5.0
MARGIN_FRACTION = 0.2
MIN_SPACING = 1.0
BACKOFF_BASE = 1.0
BACKOFF_CAP = 30.0

_Clock = Callable[[], float]


_LEASE_GONE = ("lease_revoked", "lease_unknown")


def _terminal(kind: str, exc: Exception) -> RefreshError | None:
    """A permanent failure as a RefreshError, or None when retrying can help.

    Reads the server's stable code (``stable_code``) first. An older server sent ``code``
    ``invalid_grant`` for a refused renewal and the lease reason only in ``detail``, so ``detail``
    is the fallback when the code names no reason."""
    if isinstance(exc, ApiError):
        code = exc.stable_code
        legacy = f"{exc.error} {exc.detail}"
        if isinstance(exc, Unauthorized):
            expired = code == "token_expired" or "token_expired" in legacy
            reason = "token_expired" if expired else "refused"
        elif kind == "renew" and exc.status == 400 and exc.error == "invalid_grant":
            if code in _LEASE_GONE:
                gone = True
            elif code == "lease_expired":
                gone = False
            else:
                gone = any(r in legacy for r in _LEASE_GONE)
            reason = "lease_revoked" if gone else "lease_lost"
        elif 400 <= exc.status < 500 and exc.status not in (408, 429):
            reason = "refused"
        else:
            return None
        err = RefreshError(reason, f"{kind} answered {exc.status} {exc.error}")
        err.__cause__ = exc
        return err
    return None


class _Core:
    """The schedule and the failure policy, with no I/O: the sync and async classes drive it."""

    def __init__(
        self,
        token: Token,
        *,
        lease_interval: float | None,
        margin: float | None,
        clock: _Clock,
        rng: random.Random,
        on_change: Callable[[Token], None] | None,
        on_error: Callable[[RefreshError], None] | None,
    ) -> None:
        if lease_interval is not None and lease_interval <= 0:
            raise ValueError("lease_interval must be positive")
        if margin is not None and margin < 0:
            raise ValueError("margin must not be negative")
        self.token = token
        self.error: RefreshError | None = None
        self.on_change = on_change
        self.on_error = on_error
        self.clock = clock
        self.rng = rng
        self._fixed_margin = margin
        self.interval = lease_interval
        self._learned = lease_interval is None
        self.renew_at = 0.0  # unknown lease length: renew right away and learn it
        if lease_interval is not None:
            self.renew_at = clock() + lease_interval / 3
        self.exchange_at = self._exchange_time(token)
        self.fails = {"renew": 0, "exchange": 0}
        self.retry_at = {"renew": 0.0, "exchange": 0.0}

    # -- schedule --
    def _exchange_time(self, token: Token) -> float:
        exp = token.expires_at.timestamp()
        issued = token.chain.hops[-1].issued_at.timestamp()
        life = max(exp - issued, 0.0)
        margin = self._fixed_margin
        if margin is None:
            margin = max(MIN_MARGIN, MARGIN_FRACTION * life)
        return exp - min(margin, life / 2)

    def due(self, now: float) -> str | None:
        """The action to run now, or None. Sets ``self.error`` when the token has expired."""
        if self.error is not None:
            return None
        if now >= self.token.expires_at.timestamp():
            self.fail(RefreshError("token_expired", "the token reached exp"))
            return None
        if now >= max(self.exchange_at, self.retry_at["exchange"]):
            return "exchange"
        if now >= max(self.renew_at, self.retry_at["renew"]):
            return "renew"
        return None

    def delay(self, now: float) -> float | None:
        """Seconds until the next action or the token's expiry; None once finished."""
        if self.error is not None:
            return None
        exp = self.token.expires_at.timestamp()
        wake = min(
            max(self.exchange_at, self.retry_at["exchange"]),
            max(self.renew_at, self.retry_at["renew"]),
            exp,
        )
        return max(wake - now, 0.0)

    # -- outcomes --
    def renewed(self, now: float, lease: Lease) -> None:
        self.fails["renew"] = 0
        self.retry_at["renew"] = 0.0
        if self._learned and lease.expires_in > 0:
            self.interval = max(self.interval or 0.0, float(lease.expires_in))
        interval = self.interval if self.interval is not None else float(lease.expires_in)
        step = interval / 3
        if lease.expires_in > 0:
            step = min(step, lease.expires_in / 2)  # a lease capped by its parent or exp
        self.renew_at = now + max(step, 0.5)
        log.debug("lease %s renewed, %ss left", lease.lease, lease.expires_in)

    def exchanged(self, now: float, new: Token) -> bool:
        """Adopt ``new``; False (and terminal) when it is not bound to the same key."""
        if new.dpop_jkt != self.token.dpop_jkt:
            self.fail(RefreshError("key_mismatch", "the new token is not bound to the same key"))
            return False
        self.token = new
        self.fails["exchange"] = 0
        self.retry_at["exchange"] = 0.0
        # Never hot-loop on a provider that hands back a token that is already due.
        self.exchange_at = max(self._exchange_time(new), now + MIN_SPACING)
        # A fresh token comes with a fresh lease; renew a third of an interval from now.
        self.renew_at = now + (self.interval / 3 if self.interval else 0.0)
        self.fails["renew"] = 0
        self.retry_at["renew"] = 0.0
        log.info("token replaced, lease %s", new.lease)
        if self.on_change is not None:
            _callback(self.on_change, new)
        return True

    def failed(self, kind: str, now: float, exc: Exception) -> None:
        terminal = _terminal(kind, exc)
        if terminal is not None:
            self.fail(terminal)
            return
        self.fails[kind] += 1
        ceiling = min(BACKOFF_CAP, BACKOFF_BASE * 2 ** (self.fails[kind] - 1))
        wait = ceiling / 2 + self.rng.uniform(0, ceiling / 2)
        left = self.token.expires_at.timestamp() - now
        wait = min(wait, max(left / 2, 0.1))  # leave room for another try before exp
        self.retry_at[kind] = now + wait
        log.warning(
            "%s failed (%s), attempt %d, retry in %.1fs",
            kind,
            type(exc).__name__,
            self.fails[kind],
            wait,
        )

    def fail(self, err: RefreshError) -> None:
        if self.error is None:
            self.error = err
            log.error("giving up on lease %s: %s", self.token.lease, err.reason)
            if self.on_error is not None:
                _callback(self.on_error, err)


def _callback(fn: Callable[..., object], arg: object) -> None:
    try:
        fn(arg)
    except Exception as e:  # a bad callback must not kill the refresher
        log.error("refresh callback raised %s", type(e).__name__)


class TokenRefresher:
    """Keep ``token`` alive from a background thread.

    ``exchange()`` returns a replacement token (see the module docs: it needs a fresh subject
    token each time). ``lease_interval`` is the server's ``[issuer] lease_interval_seconds``;
    leave it ``None`` to learn it from the first renewal. ``margin`` is how many seconds before
    ``exp`` to re-exchange. ``on_change(token)`` and ``on_error(RefreshError)`` run on the
    refresher's thread.

    Use it as a context manager (``with TokenRefresher(...) as r:``) or call ``start()`` and
    ``stop()``. ``r.token`` is the current token, ``r()`` is the same as a provider for
    :class:`attenuo.mcp.TokenAuth`, and ``r.error`` is set once it has given up. ``tick()`` runs
    whatever is due and returns the seconds to wait; the thread is a loop around it, and tests
    drive it with a fake ``clock``.
    """

    def __init__(
        self,
        client: Client,
        token: Token,
        exchange: Callable[[], Token],
        *,
        lease_interval: float | None = None,
        margin: float | None = None,
        on_change: Callable[[Token], None] | None = None,
        on_error: Callable[[RefreshError], None] | None = None,
        clock: _Clock = time.time,
        rng: random.Random | None = None,
    ) -> None:
        self._client = client
        self._exchange = exchange
        self._core = _Core(
            token,
            lease_interval=lease_interval,
            margin=margin,
            clock=clock,
            rng=rng or random.Random(),
            on_change=on_change,
            on_error=on_error,
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def token(self) -> Token:
        return self._core.token

    @property
    def error(self) -> RefreshError | None:
        return self._core.error

    def __call__(self) -> Token:
        """The current token; raises ``RefreshError`` once the refresher has given up."""
        if self._core.error is not None:
            raise self._core.error
        return self._core.token

    def tick(self) -> float | None:
        """Run what is due once; return seconds until the next wake-up, or None when finished."""
        core = self._core
        now = core.clock()
        kind = core.due(now)
        if kind == "exchange":
            try:
                new = self._exchange()
            except Exception as e:
                core.failed("exchange", core.clock(), e)
            else:
                core.exchanged(core.clock(), new)
        elif kind == "renew":
            try:
                lease = self._client.renew(core.token)
            except Exception as e:
                core.failed("renew", core.clock(), e)
            else:
                core.renewed(core.clock(), lease)
        return core.delay(core.clock())

    def _run(self) -> None:
        while not self._stop.is_set():
            wait = self.tick()
            if wait is None:
                return
            self._stop.wait(wait)

    def start(self) -> TokenRefresher:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="attenuo-refresh", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join()

    def __enter__(self) -> TokenRefresher:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()


class AsyncTokenRefresher:
    """:class:`TokenRefresher` for ``asyncio``: ``exchange`` is a coroutine function, callbacks
    are plain functions, and the loop is a task started by ``start()`` (or ``async with``)."""

    def __init__(
        self,
        client: AsyncClient,
        token: Token,
        exchange: Callable[[], Awaitable[Token]],
        *,
        lease_interval: float | None = None,
        margin: float | None = None,
        on_change: Callable[[Token], None] | None = None,
        on_error: Callable[[RefreshError], None] | None = None,
        clock: _Clock = time.time,
        rng: random.Random | None = None,
    ) -> None:
        self._client = client
        self._exchange = exchange
        self._core = _Core(
            token,
            lease_interval=lease_interval,
            margin=margin,
            clock=clock,
            rng=rng or random.Random(),
            on_change=on_change,
            on_error=on_error,
        )
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @property
    def token(self) -> Token:
        return self._core.token

    @property
    def error(self) -> RefreshError | None:
        return self._core.error

    def __call__(self) -> Token:
        if self._core.error is not None:
            raise self._core.error
        return self._core.token

    async def tick(self) -> float | None:
        core = self._core
        kind = core.due(core.clock())
        if kind == "exchange":
            try:
                new = await self._exchange()
            except Exception as e:
                core.failed("exchange", core.clock(), e)
            else:
                core.exchanged(core.clock(), new)
        elif kind == "renew":
            try:
                lease = await self._client.renew(core.token)
            except Exception as e:
                core.failed("renew", core.clock(), e)
            else:
                core.renewed(core.clock(), lease)
        return core.delay(core.clock())

    async def _run(self) -> None:
        while not self._stop.is_set():
            wait = await self.tick()
            if wait is None:
                return
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), wait)

    def start(self) -> AsyncTokenRefresher:
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run())
        return self

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task

    async def __aenter__(self) -> AsyncTokenRefresher:
        return self.start()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()
