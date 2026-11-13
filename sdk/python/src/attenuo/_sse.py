"""An incremental ``text/event-stream`` parser and the streamed ``tools/call`` answer.

The parser follows the SSE rules of the WHATWG HTML standard: LF, CRLF and CR line ends,
``data:`` lines joined with ``\\n``, a blank line ends an event, comment lines (``:``) and the
``event:`` and ``retry:`` fields are ignored, ``id:`` sets the last event id (kept across events,
as the standard says, for ``Last-Event-ID``), and an event with no terminating blank line when
the stream ends is dropped. It refuses an event (or a single line) over ``max_event_bytes``.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, TypeGuard

import httpx

from . import _wire as w
from .errors import AttenuoError, Denied, RpcError, TransportTimeout

#: The default bound on one SSE event (or a plain JSON answer) of a streamed call: 16 MiB, the
#: proxy's ``[proxy] max_upstream_body_bytes`` default.
DEFAULT_MAX_EVENT_BYTES = 16 * 1024 * 1024

# The `data.reason` values the proxy's stream-end event carries (`end_event_recorded` in
# crates/attenuo-proxy/src/guard.rs): the token and lease reasons of the server's authorizer,
# and `unauthorized` for a re-check that failed for another reason. These are the reasons on
# the wire, not the `StreamEndCause` metric labels: `lease_other`, `recheck_unavailable` and
# `recheck_failed` never appear in an event.
_STREAM_END_REASONS = frozenset(
    {
        "token_expired",
        "lease_revoked",
        "lease_expired",
        "lease_unknown",
        "lease_error",
        "unauthorized",
    }
)
# `data.decision_id` of a stream-end event, when present: a UUID in its hyphenated form.
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

_LINE_END = re.compile(rb"\r\n|\r|\n")
_BOM = b"\xef\xbb\xbf"


def check_deadline(deadline: float | None) -> None:
    """Refuse a stream ``deadline`` that is not a positive, finite number of seconds."""
    if deadline is not None and not (deadline > 0 and math.isfinite(deadline)):
        raise ValueError("deadline must be a positive number of seconds")


class Deadline:
    """The optional total deadline of a streamed call (SR-82), counted from its creation.

    The idle timeout restarts on every read, so an upstream that sends a keep-alive comment
    every few seconds would hold the call open forever without it. :meth:`check` runs between
    reads and raises once the deadline has passed.
    """

    def __init__(self, seconds: float | None) -> None:
        self.seconds = seconds
        self.end = None if seconds is None else time.monotonic() + seconds

    def left(self) -> float | None:
        """Seconds until the deadline (``None`` without one)."""
        return None if self.end is None else self.end - time.monotonic()

    def check(self) -> None:
        if self.end is not None and time.monotonic() >= self.end:
            raise TransportTimeout(f"stream deadline of {self.seconds:g}s elapsed")


@dataclass(frozen=True)
class SseEvent:
    """One dispatched SSE event: its joined ``data`` and the last event id at that point."""

    data: str
    last_event_id: str | None


class SseParser:
    """Feed bytes as they arrive; get back the events they complete.

    Linear in the input (SR-82): each chunk is searched for line ends once, from its start, and
    the unfinished line is kept as a list of chunks joined once when its line end arrives, as the
    TypeScript parser does. Appending to one buffer and searching it again from the start on every
    chunk made a long line delivered in many small reads cost time quadratic in its length.
    """

    def __init__(self, max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES) -> None:
        if max_event_bytes <= 0:
            raise ValueError("max_event_bytes must be positive")
        self.max_event_bytes = max_event_bytes
        self.last_event_id: str | None = None
        self._head = b""  # the first bytes of the stream while they may still be a BOM
        self._parts: list[bytes] = []  # the unfinished line, no line end in it
        self._parts_len = 0
        self._cr = False  # the unfinished line was ended by a CR at the end of a read
        self._data: list[str] = []
        self._size = 0  # bytes of the lines of the event being read
        self._start = True  # a UTF-8 BOM may open the stream

    def feed(self, chunk: bytes) -> Iterator[SseEvent]:
        """The events ``chunk`` completes, each as soon as it is parsed (consume them all)."""
        if self._start:
            self._head += chunk
            if len(self._head) < len(_BOM) and _BOM.startswith(self._head):
                return
            chunk, self._head = self._head.removeprefix(_BOM), b""
            self._start = False
        pos = 0
        if self._cr and chunk:
            # A CR ended the last read: a LF opening this one is the rest of a CRLF.
            end = 2 if chunk.startswith(b"\n") else 1  # the line end's length
            line = self._pending()
            self._take(self._parts_len + end)
            self._parts, self._parts_len, self._cr = [], 0, False
            pos = end - 1
            event = self._line(line)
            if event is not None:
                yield event
        while True:
            m = _LINE_END.search(chunk, pos)
            if m is None:
                break
            if m.group() == b"\r" and m.end() == len(chunk):
                # A CR at the very end may be the first half of a CRLF: wait for the next chunk.
                self._cr = True
                break
            if self._parts:
                line = self._pending() + chunk[pos : m.start()]
                self._take(self._parts_len + m.end() - pos)
                self._parts, self._parts_len = [], 0
            else:
                line = chunk[pos : m.start()]
                self._take(m.end() - pos)
            event = self._line(line)
            pos = m.end()
            if event is not None:
                yield event
        rest = chunk[pos : len(chunk) - 1] if self._cr else chunk[pos:]
        if rest:
            self._parts.append(rest)
            self._parts_len += len(rest)
        if self._size + self._parts_len + int(self._cr) > self.max_event_bytes:
            raise self._too_big()

    def close(self) -> list[SseEvent]:
        """End of stream. A last line ended by a lone CR still counts; an event without its
        blank line is dropped."""
        out: list[SseEvent] = []
        if self._cr:
            event = self._line(self._pending())
            if event is not None:
                out.append(event)
        self._head = b""
        self._parts, self._parts_len, self._cr = [], 0, False
        self._data = []
        self._size = 0
        return out

    def _pending(self) -> bytes:
        parts = self._parts
        return parts[0] if len(parts) == 1 else b"".join(parts)

    def _take(self, n: int) -> None:
        self._size += n
        if self._size > self.max_event_bytes:
            raise self._too_big()

    def _too_big(self) -> AttenuoError:
        return AttenuoError(f"SSE event over {self.max_event_bytes} bytes refused")

    def _line(self, raw: bytes) -> SseEvent | None:
        if not raw:
            data, self._data, self._size = self._data, [], 0
            if not data:
                return None
            return SseEvent("\n".join(data), self.last_event_id)
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise AttenuoError("SSE stream is not UTF-8") from e
        if line.startswith(":"):
            return None
        name, sep, value = line.partition(":")
        if sep:
            value = value.removeprefix(" ")
        if name == "data":
            self._data.append(value)
        elif name == "id" and "\0" not in value:
            self.last_event_id = value
        # `event`, `retry` and unknown fields are ignored.
        return None


@dataclass(frozen=True)
class StreamEvent:
    """One JSON-RPC message of a streamed ``tools/call`` answer.

    ``message`` is the message as sent: a notification (``notifications/progress``,
    ``notifications/message``, ...), a request from the server, or the response to the call.
    ``last_event_id`` is the SSE last event id when the message arrived (what a client sends as
    ``Last-Event-ID`` to resume), ``None`` for a plain JSON answer or a stream without ids.
    ``decision_id`` is the proxy's ``X-Attenuo-Decision-Id`` for the call. ``result`` is set on
    the final event only: the call's :class:`~attenuo.ToolResult`.
    """

    message: dict[str, Any]
    last_event_id: str | None = None
    decision_id: str | None = None
    result: w.ToolResult | None = field(default=None, repr=False)

    @property
    def method(self) -> str | None:
        """The notification's or request's ``method``; ``None`` for a response."""
        m = self.message.get("method")
        return m if isinstance(m, str) else None

    @property
    def is_final(self) -> bool:
        """True for the event that carries the call's result (always the last one)."""
        return self.result is not None


def _is_stream_end(data: object) -> TypeGuard[dict[str, Any]]:
    """Is ``data`` what the proxy's stream-end event carries: a known ``reason``, and a
    ``decision_id`` that is absent or a UUID string?"""
    if not isinstance(data, dict):
        return False
    reason = data.get("reason")
    if not isinstance(reason, str) or reason not in _STREAM_END_REASONS:
        return False
    if "decision_id" not in data:
        return True
    decision_id = data["decision_id"]
    return isinstance(decision_id, str) and _UUID.fullmatch(decision_id) is not None


def stream_end_error(msg: dict[str, Any]) -> Denied | RpcError | None:
    """The proxy's last event on a stream it cut, as a :class:`Denied`; ``None`` for a message
    without the stream-end shape.

    The shape is a response (no ``method``) whose ``id`` is null or absent and whose error code
    is ``-32001``. A message of that shape is a cut only when ``data.reason`` is one the proxy
    sends and ``data.decision_id`` is absent or a UUID string: then it is a :class:`Denied` with
    that reason and id. Anything else of that shape is an :class:`RpcError` with code
    ``-32001``, which still ends the call, but not as a decision.

    This is belt-and-braces: the real guard is the proxy, which rewrites any upstream message of
    the stream-end shape to ``-32005`` ``upstream_stream_end_shape`` before it reaches the
    client. The proxy's ``X-Attenuo-Decision-Id`` header went out before the cut, so it cannot
    vouch for this decision id the way it does for a ``-32003``."""
    err = msg.get("error")
    if "method" in msg or msg.get("id") is not None or not isinstance(err, dict):
        return None
    if err.get("code") != w.CODE_UNAUTHORIZED:
        return None
    message = str(err.get("message", ""))
    data = err.get("data")
    if _is_stream_end(data):
        return Denied(data["reason"], data.get("decision_id"), message, data)
    return RpcError(w.CODE_UNAUTHORIZED, message, data)


class CallStream:
    """Turns the body of one ``tools/call`` response into :class:`StreamEvent` values.

    Feed SSE chunks to :meth:`feed` and call :meth:`finish` at the end, or hand a plain JSON body
    to :meth:`plain`. After the response to the call (result or error) ``done`` is set and later
    events are ignored. A JSON-RPC error raises what :meth:`Client.call_tool` raises; the proxy's
    stream-end event raises :class:`Denied`, and a message of its shape that is not one raises
    :class:`RpcError` (see :func:`stream_end_error`).
    """

    def __init__(self, resp: httpx.Response, request_id: int, max_event_bytes: int) -> None:
        self.resp = resp
        self.request_id = request_id
        self.decision_id: str | None = resp.headers.get(w.DECISION_ID_HEADER)
        self.parser = SseParser(max_event_bytes)
        self.done = False

    @property
    def sse(self) -> bool:
        return "event-stream" in self.resp.headers.get("content-type", "")

    def feed(self, chunk: bytes) -> Iterator[StreamEvent]:
        return self._events(self.parser.feed(chunk))

    def finish(self) -> Iterator[StreamEvent]:
        yield from self._events(self.parser.close())
        if not self.done:
            raise AttenuoError("stream ended before the tools/call response")

    def plain(self, body: bytes) -> list[StreamEvent]:
        """A whole body read at once (a JSON answer, or an error status): one final event, or
        the exception ``call_tool`` raises."""
        if len(body) > self.parser.max_event_bytes:
            raise AttenuoError(f"response over {self.parser.max_event_bytes} bytes refused")
        whole = httpx.Response(self.resp.status_code, headers=self.resp.headers, content=body)
        result, decision_id = w.rpc_result(whole)
        self.done = True
        msg = w.parse_rpc_body(whole.text, self.sse) or {}
        return [StreamEvent(msg, None, decision_id, w.tool_result(result, decision_id))]

    def _events(self, sse: Iterable[SseEvent]) -> Iterator[StreamEvent]:
        for ev in sse:
            if self.done:
                break
            if not ev.data.strip():
                continue
            try:
                msg = json.loads(ev.data)
            except ValueError as e:
                raise AttenuoError(f"SSE event is not JSON: {ev.data[:200]}") from e
            if not isinstance(msg, dict):
                raise AttenuoError(f"SSE event is not one JSON-RPC message: {ev.data[:200]}")
            yield self._message(msg, ev.last_event_id)

    def _message(self, msg: dict[str, Any], last_event_id: str | None) -> StreamEvent:
        is_response = "method" not in msg and ("result" in msg or "error" in msg)
        if not is_response:
            return StreamEvent(msg, last_event_id, self.decision_id)
        cut = stream_end_error(msg)
        if cut is not None:
            self.done = True
            raise cut
        if msg.get("id") != self.request_id:
            return StreamEvent(msg, last_event_id, self.decision_id)
        self.done = True
        result, decision_id = w.rpc_result(self.resp, msg)
        return StreamEvent(msg, last_event_id, decision_id, w.tool_result(result, decision_id))
