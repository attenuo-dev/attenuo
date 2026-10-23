"""Helpers for pointing an MCP client at onbehalf's proxy.

onbehalf mounts each upstream at ``<server_url>/mcp/<name>`` and speaks MCP Streamable HTTP
there. A client needs two things: that URL, and ``Authorization: Bearer <delegation token>`` on
every request (``initialize``, ``tools/list``, ``tools/call`` and the ``GET``/``DELETE`` session
requests). This module produces both and nothing else, so it works with any MCP client.

See ``examples/python-agent/mcp_client_example.py`` for the official ``mcp`` package.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from ._wire import MCP_ACCEPT, bearer, normalize_base
from .token import Token


def mcp_url(server_url: str, server: str) -> str:
    """The MCP endpoint for upstream ``server``: ``http://host:8080/mcp/github``."""
    return f"{normalize_base(server_url)}/mcp/{server}"


def mcp_headers(
    token: Token | str,
    session_id: str | None = None,
    *,
    content_headers: bool = False,
) -> dict[str, str]:
    """Headers an MCP client must send to onbehalf.

    By default only ``Authorization`` (and ``Mcp-Session-Id`` when given): MCP client libraries
    add ``Accept`` and ``Content-Type`` themselves. Pass ``content_headers=True`` for a raw HTTP
    client, which adds ``Accept: application/json, text/event-stream`` and
    ``Content-Type: application/json``.
    """
    h = {"Authorization": f"Bearer {bearer(token)}"}
    if session_id:
        h["Mcp-Session-Id"] = session_id
    if content_headers:
        h["Accept"] = MCP_ACCEPT
        h["Content-Type"] = "application/json"
    return h


class TokenAuth(httpx.Auth):
    """An ``httpx`` auth that asks ``provider`` for the current token on every request.

    Use it where the bearer must change over time (the token is re-exchanged, or replaced
    before it expires). ``provider`` returns the token or its JWT.

    This subclasses ``httpx.Auth``. If your MCP client uses a different HTTP library, build the
    same thing for that library; the logic is one line: set ``Authorization`` per request.
    """

    def __init__(self, provider: Callable[[], Token | str]) -> None:
        self._provider = provider

    def auth_flow(self, request: httpx.Request) -> Any:
        request.headers["Authorization"] = f"Bearer {bearer(self._provider())}"
        yield request
