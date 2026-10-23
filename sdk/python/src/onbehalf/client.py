"""Synchronous and asynchronous clients for the onbehalf server.

Both classes expose the same methods; the async one has ``await`` in front. They mirror what the
``onbehalf`` CLI does over HTTP: ``POST /token``, ``POST /token/renew``, ``POST /mcp/{server}``
and ``POST /access/v1/evaluation``.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from types import TracebackType
from typing import Any

import httpx

from . import _wire as w
from .capability import CapabilityLike
from .token import Token, decode_token, verify_token

DEFAULT_TIMEOUT = 30.0

_Caps = "Iterable[CapabilityLike] | CapabilityLike"


class Client:
    """Talk to an onbehalf server.

    ``token`` is an optional default bearer used by ``call_tool``, ``list_tools``, ``renew`` and
    ``authzen_evaluate`` when they are called without one. ``transport`` is for tests
    (``httpx.MockTransport``) or custom TLS/proxy setups.
    """

    def __init__(
        self,
        server_url: str,
        token: Token | str | None = None,
        timeout: float | httpx.Timeout | None = DEFAULT_TIMEOUT,
        *,
        transport: httpx.BaseTransport | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.server_url = w.normalize_base(server_url)
        self.token = token
        self._http = httpx.Client(
            base_url=self.server_url, timeout=timeout, transport=transport, headers=headers
        )
        self._ids = itertools.count(1)

    # -- lifecycle --
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- tokens --
    def exchange(
        self,
        subject_token: Token | str,
        actor: str,
        capabilities: Iterable[CapabilityLike] | CapabilityLike,
        ttl_seconds: int | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        subject_token_type: str | None = None,
        *,
        actor_token: str | None = None,
        may_act: Iterable[str] | None = None,
    ) -> Token:
        """RFC 8693 token exchange: trade ``subject_token`` for a narrower token held by ``actor``.

        For a hop n to n+1 exchange, ``subject_token`` is the parent delegation token and
        ``client_secret`` is the actor's ``[[agents]]`` secret (``client_id`` defaults to
        ``actor``); the server requires it unless ``[token] require_actor_auth = false``. For
        hop 0 (an IdP credential), pass ``client_id`` and ``client_secret`` of a registered
        agent, or its ``actor_token``; the subject token type then defaults to an OIDC ID token,
        or set ``subject_token_type`` to ``urn:ietf:params:oauth:token-type:id-jag`` for an
        ID-JAG.

        Instead of a client secret, either kind of request can authenticate the agent with
        ``actor_token``: a workload-identity JWT (for example a SPIFFE JWT-SVID) from an
        ``[[actor_trust]]`` issuer, sent with ``actor_token_type``
        ``urn:ietf:params:oauth:token-type:jwt``. Each actor token authenticates one request.
        ``may_act`` lists the agents allowed to exchange the new token next (RFC 8693 §4.4).

        Raises :class:`~onbehalf.ApiError` (``invalid_scope``, ``invalid_grant``, ...) on refusal.
        """
        body = w.exchange_body(
            subject_token,
            actor,
            capabilities,
            ttl_seconds,
            client_id,
            client_secret,
            subject_token_type,
            actor_token=actor_token,
            may_act=may_act,
        )
        return w.token_from_response(w.json_body(self._http.post("/token", json=body)))

    def renew(self, token: Token | str | None = None) -> w.Lease:
        """Extend the lease of the token's last hop (``POST /token/renew``)."""
        resp = self._http.post("/token/renew", headers=_auth(w.bearer(token, self.token)))
        return w.lease_from_response(w.json_body(resp))

    # -- MCP through the proxy --
    def _rpc(
        self,
        token: Token | str | None,
        server: str,
        method: str,
        params: dict[str, Any],
        session_id: str | None = None,
    ) -> tuple[dict[str, Any], str | None, httpx.Response]:
        resp = self._http.post(
            f"/mcp/{w.path_segment(server, 'server')}",
            headers=w.mcp_headers(w.bearer(token, self.token), session_id),
            json=w.rpc_request(method, params, next(self._ids)),
        )
        result, decision_id = w.rpc_result(resp)
        return result, decision_id, resp

    def initialize(
        self,
        token: Token | str | None,
        server: str,
        client_name: str = "onbehalf-python",
        protocol_version: str = "2025-06-18",
    ) -> str | None:
        """MCP ``initialize``; returns the ``Mcp-Session-Id`` the upstream assigned, if any."""
        params = {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "0"},
        }
        _, _, resp = self._rpc(token, server, "initialize", params)
        sid: str | None = resp.headers.get(w.SESSION_HEADER)
        return sid

    def call_tool(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> w.ToolResult:
        """``tools/call`` through the proxy. Raises :class:`~onbehalf.Denied` when refused."""
        result, decision_id, _ = self._rpc(
            token, server, "tools/call", {"name": tool, "arguments": arguments or {}}, session_id
        )
        return w.tool_result(result, decision_id)

    def list_tools(
        self, token: Token | str | None, server: str, session_id: str | None = None
    ) -> list[w.Tool]:
        """``tools/list``; the proxy shows only the tools this token may call."""
        result, _, _ = self._rpc(token, server, "tools/list", {}, session_id)
        return w.tools_from_result(result)

    # -- AuthZEN --
    def authzen_evaluate(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
    ) -> w.AuthzenDecision:
        """Ask for a decision without calling the tool. A deny is returned, not raised."""
        resp = self._http.post(
            "/access/v1/evaluation",
            headers=_auth(w.bearer(token, self.token)),
            json=w.authzen_body(server, tool, arguments),
        )
        return w.authzen_from_response(w.json_body(resp))

    # -- inspection --
    def jwks(self) -> dict[str, Any]:
        """``GET /.well-known/jwks.json``."""
        body = w.json_body(self._http.get("/.well-known/jwks.json"))
        return body if isinstance(body, dict) else {}

    def inspect(
        self,
        jwt: Token | str,
        verify: bool = False,
        *,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> Token:
        """Decode a delegation token; with ``verify=True`` also check its Ed25519 signature.

        Without ``verify`` nothing is checked and ``Token.verified`` is false. With it, the
        server's JWKS is fetched and :class:`~onbehalf.VerificationError` is raised on failure.
        """
        raw = jwt.jwt if isinstance(jwt, Token) else jwt
        if not verify:
            return decode_token(raw)
        return verify_token(raw, self.jwks(), issuer=issuer, audience=audience)


class AsyncClient:
    """The :class:`Client` API for ``asyncio``. Use ``async with`` or call ``aclose()``."""

    def __init__(
        self,
        server_url: str,
        token: Token | str | None = None,
        timeout: float | httpx.Timeout | None = DEFAULT_TIMEOUT,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.server_url = w.normalize_base(server_url)
        self.token = token
        self._http = httpx.AsyncClient(
            base_url=self.server_url, timeout=timeout, transport=transport, headers=headers
        )
        self._ids = itertools.count(1)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def exchange(
        self,
        subject_token: Token | str,
        actor: str,
        capabilities: Iterable[CapabilityLike] | CapabilityLike,
        ttl_seconds: int | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        subject_token_type: str | None = None,
        *,
        actor_token: str | None = None,
        may_act: Iterable[str] | None = None,
    ) -> Token:
        body = w.exchange_body(
            subject_token,
            actor,
            capabilities,
            ttl_seconds,
            client_id,
            client_secret,
            subject_token_type,
            actor_token=actor_token,
            may_act=may_act,
        )
        return w.token_from_response(w.json_body(await self._http.post("/token", json=body)))

    async def renew(self, token: Token | str | None = None) -> w.Lease:
        resp = await self._http.post("/token/renew", headers=_auth(w.bearer(token, self.token)))
        return w.lease_from_response(w.json_body(resp))

    async def _rpc(
        self,
        token: Token | str | None,
        server: str,
        method: str,
        params: dict[str, Any],
        session_id: str | None = None,
    ) -> tuple[dict[str, Any], str | None, httpx.Response]:
        resp = await self._http.post(
            f"/mcp/{w.path_segment(server, 'server')}",
            headers=w.mcp_headers(w.bearer(token, self.token), session_id),
            json=w.rpc_request(method, params, next(self._ids)),
        )
        result, decision_id = w.rpc_result(resp)
        return result, decision_id, resp

    async def initialize(
        self,
        token: Token | str | None,
        server: str,
        client_name: str = "onbehalf-python",
        protocol_version: str = "2025-06-18",
    ) -> str | None:
        params = {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "0"},
        }
        _, _, resp = await self._rpc(token, server, "initialize", params)
        sid: str | None = resp.headers.get(w.SESSION_HEADER)
        return sid

    async def call_tool(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> w.ToolResult:
        result, decision_id, _ = await self._rpc(
            token, server, "tools/call", {"name": tool, "arguments": arguments or {}}, session_id
        )
        return w.tool_result(result, decision_id)

    async def list_tools(
        self, token: Token | str | None, server: str, session_id: str | None = None
    ) -> list[w.Tool]:
        result, _, _ = await self._rpc(token, server, "tools/list", {}, session_id)
        return w.tools_from_result(result)

    async def authzen_evaluate(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
    ) -> w.AuthzenDecision:
        resp = await self._http.post(
            "/access/v1/evaluation",
            headers=_auth(w.bearer(token, self.token)),
            json=w.authzen_body(server, tool, arguments),
        )
        return w.authzen_from_response(w.json_body(resp))

    async def jwks(self) -> dict[str, Any]:
        body = w.json_body(await self._http.get("/.well-known/jwks.json"))
        return body if isinstance(body, dict) else {}

    async def inspect(
        self,
        jwt: Token | str,
        verify: bool = False,
        *,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> Token:
        raw = jwt.jwt if isinstance(jwt, Token) else jwt
        if not verify:
            return decode_token(raw)
        return verify_token(raw, await self.jwks(), issuer=issuer, audience=audience)


def _auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}
