"""The opt-in retry of load refusals (``Client(..., max_retries=N)``), shared by the sync and
async clients.

Only the two refusals the server's ``[limits]`` make before doing any work are retried: 503
``overloaded`` and 429 ``rate_limited`` (:func:`attenuo._wire.retryable_refusal`). Never a
``request_timeout`` (the handler may have run), never a denial, never a transport error.
"""

from __future__ import annotations

import asyncio
import random
import time

import httpx

from . import _wire as w

DEFAULT_MAX_RETRY_DELAY = 10.0
"""The longest ``Retry-After`` the client waits out, in seconds, unless told otherwise."""
MAX_RETRIES_LIMIT = 10
MAX_RETRY_DELAY_LIMIT = 300.0
NO_RETRY_AFTER_DELAY = 1.0
"""What a retried refusal without a readable ``Retry-After`` waits."""
JITTER = 0.2
"""Each wait is up to this fraction longer than ``Retry-After``, so clients refused together do
not all come back in the same instant."""

# Indirections so tests can replace the clock without touching the ``time`` module.
_sleep = time.sleep
_asleep = asyncio.sleep
_random = random.random


class RetryPolicy:
    """``max_retries`` and ``max_retry_delay`` of a client, checked once."""

    def __init__(self, max_retries: int, max_retry_delay: float) -> None:
        if isinstance(max_retries, bool) or not isinstance(max_retries, int):
            raise TypeError("max_retries must be an int")
        if not 0 <= max_retries <= MAX_RETRIES_LIMIT:
            raise ValueError(f"max_retries must be between 0 and {MAX_RETRIES_LIMIT}")
        if not 0 < max_retry_delay <= MAX_RETRY_DELAY_LIMIT:
            raise ValueError(
                f"max_retry_delay must be more than 0 and at most {MAX_RETRY_DELAY_LIMIT:g} seconds"
            )
        self.max_retries = max_retries
        self.max_retry_delay = float(max_retry_delay)

    def delay(self, resp: httpx.Response, retries: int, left: float | None = None) -> float | None:
        """Seconds to wait before sending again, after ``retries`` retries already made; ``None``
        to hand ``resp`` back as it is. ``left`` is what remains of a streamed call's
        ``deadline``: a wait that would outlast it is not made. Reads ``resp``'s body when it is
        a 429 or 503."""
        if retries >= self.max_retries:
            return None
        refusal = w.retryable_refusal(resp)
        if refusal is None:
            return None
        base = NO_RETRY_AFTER_DELAY if refusal.retry_after is None else float(refusal.retry_after)
        if base > self.max_retry_delay:
            return None  # waiting less than the server asked would only be refused again
        wait = min(base * (1 + JITTER * _random()), self.max_retry_delay)
        if left is not None and wait >= left:
            return None
        return wait


def sleep(seconds: float) -> None:
    _sleep(seconds)


async def asleep(seconds: float) -> None:
    await _asleep(seconds)
