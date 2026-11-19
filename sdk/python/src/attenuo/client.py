"""Synchronous and asynchronous clients for the attenuo server.

Both classes expose the same methods; the async one has ``await`` in front. They mirror what the
``attenuo`` CLI does over HTTP: ``POST /token``, ``POST /token/renew``, ``POST /mcp/{server}``,
``POST /access/v1/evaluation`` (and ``/evaluations``), ``GET`` and ``POST /approvals/{id}`` and
``DELETE /mcp/{server}``.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator
from types import TracebackType
from typing import Any

import httpx

from . import _retry
from . import _wire as w
from ._http import AsyncHttpClient, HttpClient
from ._retry import DEFAULT_MAX_RETRY_DELAY, RetryPolicy
from ._sse import DEFAULT_MAX_EVENT_BYTES, CallStream, Deadline, StreamEvent, check_deadline
from .capability import CapabilityLike
from .dpop import DpopKey, NonceCache, exchange_proofs, presented
from .errors import ApprovalNotGranted, ApprovalRequired, AttenuoError
from .token import Token, decode_token, verify_token

DEFAULT_TIMEOUT = 30.0

_Caps = "Iterable[CapabilityLike] | CapabilityLike"


class Client:
    """Talk to an attenuo server.

    ``token`` is an optional default bearer used by ``call_tool``, ``list_tools``, ``renew`` and
    ``authzen_evaluate`` when they are called without one. ``transport`` is for tests
    (``httpx.MockTransport``) or custom TLS/proxy setups.

    ``dpop_key`` (a :class:`~attenuo.dpop.DpopKey` or a private JWK dict) makes this client
    sender-constrained (DPoP, RFC 9449): every request carries a proof by the key, exchanges
    bind the new token to it, and tokens are sent as ``Authorization: DPoP <token>``. A token
    bound to a key is refused without proofs, so a copied token is useless on its own. When the
    server hands out DPoP nonces, the client keeps the latest one, puts it in every proof, and
    retries a request once when the server answers ``use_dpop_nonce``.

    ``max_retries`` (default 0: off) retries a request the server refused for its load before
    doing any work: 503 ``overloaded`` (:class:`~attenuo.Unavailable`) and 429 ``rate_limited``
    (:class:`~attenuo.RateLimited`). Each retry waits the answer's ``Retry-After`` (1 s when it
    has none), up to 20 % longer so refused clients spread out; a ``Retry-After`` over
    ``max_retry_delay`` seconds (default 10) is not waited out and the error is raised at once,
    so all retries of one call wait at most ``max_retries * max_retry_delay`` seconds. Every
    retry is a new request with new DPoP proofs; an exchange sends its ``client_assertion``
    again (a refused load leaves it unused), but not once it has expired: a wait that would
    reach the assertion's ``exp`` is not made and the refusal is raised at once. Nothing else
    is retried: not a ``request_timeout`` (the server may have done the work), not a denial,
    not an :class:`~attenuo.Unauthorized`, not a transport error. A streamed call is retried only
    before its stream starts, and not past its ``deadline``. When the retries run out, the last
    refusal is raised. ``max_retries`` is at most 10 and ``max_retry_delay`` at most 300.
    """

    def __init__(
        self,
        server_url: str,
        token: Token | str | None = None,
        timeout: float | httpx.Timeout | None = DEFAULT_TIMEOUT,
        *,
        transport: httpx.BaseTransport | None = None,
        headers: dict[str, str] | None = None,
        dpop_key: DpopKey | dict[str, Any] | None = None,
        max_retries: int = 0,
        max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
    ) -> None:
        self.server_url = w.normalize_base(server_url)
        self.token = token
        self._retry = RetryPolicy(max_retries, max_retry_delay)
        self.dpop_key = DpopKey.of(dpop_key)
        self._nonce = NonceCache()
        self._http = HttpClient(
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
        subject_dpop_key: DpopKey | dict[str, Any] | None = None,
        subject_token_dpop: str | None = None,
        client_assertion: str | None = None,
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
        Or, for an agent whose ``[[agents]]`` entry lists public keys (``jwks``), with
        ``client_assertion``: a ``private_key_jwt`` assertion (RFC 7523) made with
        ``DpopKey.client_assertion(agent_id, server_issuer)`` from the agent's private key; each
        one authenticates one request. ``client_secret`` and ``client_assertion`` are never
        sent together. The ``use_dpop_nonce`` retry and the ``max_retries`` retry of a load
        refusal send the same assertion again, which the server allows because those refusals
        leave it unused; the load retry is not made when its wait would reach the assertion's
        ``exp``, and :class:`~attenuo.RateLimited` (or :class:`~attenuo.Unavailable`) is raised
        instead. Then mint a new assertion and call again, or mint it with a ``lifetime`` that
        covers the waits (at most the server's ``client_assertion_max_lifetime_seconds``, 300 by
        default). Treat an assertion as spent after any other answer.
        ``may_act`` lists the agents allowed to exchange the new token next (RFC 8693 §4.4).

        With a ``dpop_key`` on the client, the new token is bound to it. When ``subject_token`` is
        bound to another key, the parent's holder must sign off on this delegation (a child of a
        bound token is always bound): it makes ``DpopKey.sign_off(token_url, subject_token,
        child_jkt, actor)`` with its key and hands the result to the sub-agent, which passes it
        as ``subject_token_dpop``. The sign-off names the new token's key and agent, so it is
        good for this delegation only. When one process holds both keys, pass the parent's key
        as ``subject_dpop_key`` instead and the sign-off is made here.

        Raises :class:`~attenuo.ApiError` (``invalid_scope``, ``invalid_grant``, ...) on refusal.
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
            client_assertion=client_assertion,
        )
        resp = self._post(
            "/token",
            lambda nonce: _exchange_dpop(
                self.server_url, self.dpop_key, body, subject_dpop_key, subject_token_dpop, nonce
            ),
            json=body,
            resend_until=w.assertion_expiry(body),
        )
        return w.token_from_response(w.json_body(resp))

    def _post(
        self, path: str, headers: Callable[[str | None], dict[str, str]], **kwargs: Any
    ) -> httpx.Response:
        return self._request("POST", path, headers, **kwargs)

    def _request(
        self,
        method: str,
        path: str,
        headers: Callable[[str | None], dict[str, str]],
        *,
        resend_until: float | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """``method path`` with ``headers(nonce)``; once more with the server's new nonce when
        it answers ``use_dpop_nonce``; again, with new headers, on a load refusal while
        ``max_retries`` allows and the wait ends before ``resend_until`` (:meth:`_retrying`)."""

        def send() -> httpx.Response:
            resp = self._http.request(method, path, headers=headers(self._nonce.value), **kwargs)
            if self.dpop_key is not None and self._nonce.update(resp):
                resp = self._http.request(
                    method, path, headers=headers(self._nonce.value), **kwargs
                )
                self._nonce.update(resp)
            return resp

        return self._retrying(send, resend_until)

    def _retrying(
        self, send: Callable[[], httpx.Response], resend_until: float | None = None
    ) -> httpx.Response:
        """``send()``, and again after a wait while it answers a load refusal the client's
        retry policy retries (``max_retries``). ``resend_until`` (Unix seconds) is when what
        ``send`` sends stops being good, a client assertion's ``exp``: a wait that would reach
        it is not made, and the refusal is handed back."""
        retries = 0
        while True:
            resp = send()
            wait = self._retry.delay(resp, retries, _retry.left_until(resend_until))
            if wait is None:
                return resp
            resp.close()
            _retry.sleep(wait)
            retries += 1

    def _auth(
        self, token: str, path: str, method: str = "POST"
    ) -> Callable[[str | None], dict[str, str]]:
        url = f"{self.server_url}{path}"
        return lambda nonce: presented(token, self.dpop_key, method, url, nonce)

    def renew(self, token: Token | str | None = None) -> w.Lease:
        """Extend the lease of the token's last hop (``POST /token/renew``)."""
        resp = self._post("/token/renew", self._auth(w.bearer(token, self.token), "/token/renew"))
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
        path = f"/mcp/{w.path_segment(server, 'server')}"
        jwt = w.bearer(token, self.token)
        auth = self._auth(jwt, path)
        resp = self._post(
            path,
            lambda nonce: {**w.mcp_headers(jwt, session_id), **auth(nonce)},
            json=w.rpc_request(method, params, next(self._ids)),
        )
        result, decision_id = w.rpc_result(resp)
        return result, decision_id, resp

    def initialize(
        self,
        token: Token | str | None,
        server: str,
        client_name: str = "attenuo-python",
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
        *,
        approval_token: str | None = None,
    ) -> w.ToolResult:
        """``tools/call`` through the proxy. Raises :class:`~attenuo.Denied` when refused.

        ``approval_token`` (from a granted :class:`~attenuo.Approval`) is sent in
        ``params._meta["dev.attenuo/approval"]``; the proxy removes it before the upstream."""
        result, decision_id, _ = self._rpc(
            token, server, "tools/call", w.call_params(tool, arguments, approval_token), session_id
        )
        return w.tool_result(result, decision_id)

    def call_tool_stream(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        approval_token: str | None = None,
        max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES,
        deadline: float | None = None,
    ) -> Iterator[StreamEvent]:
        """``tools/call`` with the answer read as it streams: an iterator of
        :class:`~attenuo.StreamEvent`, one per JSON-RPC message (progress and other
        notifications as they arrive, then the response, whose event has ``result`` set).

        The request is the one :meth:`call_tool` sends. A denial raises :class:`~attenuo.Denied`
        before anything is yielded; a stream the proxy cuts because the lease was revoked or
        expired, or the token expired, raises :class:`~attenuo.Denied` with that ``reason`` and
        the ``decision_id`` of the proxy's ``stream.end`` record; any other JSON-RPC error
        raises what :meth:`call_tool` raises. A plain JSON answer is yielded as the one final
        event. An SSE event (or a plain body) over ``max_event_bytes`` (default 16 MiB, the
        proxy's ``max_upstream_body_bytes`` default) raises :class:`~attenuo.AttenuoError`.
        The client's ``timeout`` applies per read, so a stream quiet for longer fails; leaving
        the loop early closes the connection once the iterator is closed or collected.
        ``deadline`` (seconds, default none) bounds the whole call from the request's start,
        so an upstream that sends only keep-alive comments cannot hold it open forever (SR-82):
        once it has passed, the next read raises :class:`~attenuo.AttenuoError` and the
        response is closed. It is checked between reads, so a silent upstream is still ended
        by the per-read ``timeout``."""
        path = f"/mcp/{w.path_segment(server, 'server')}"
        jwt = w.bearer(token, self.token)
        if max_event_bytes <= 0:
            raise ValueError("max_event_bytes must be positive")
        check_deadline(deadline)
        request_id = next(self._ids)
        params = w.call_params(tool, arguments, approval_token)
        body = w.rpc_request("tools/call", params, request_id)
        auth = self._auth(jwt, path)
        return self._stream(
            path,
            lambda nonce: {**w.mcp_headers(jwt, session_id), **auth(nonce)},
            body,
            request_id,
            max_event_bytes,
            deadline,
        )

    def _stream(
        self,
        path: str,
        headers: Callable[[str | None], dict[str, str]],
        body: dict[str, Any],
        request_id: int,
        max_event_bytes: int,
        deadline: float | None = None,
    ) -> Iterator[StreamEvent]:
        def send() -> httpx.Response:
            h = headers(self._nonce.value)
            req = self._http.build_request("POST", path, headers=h, json=body)
            resp = self._http.send(req, stream=True)
            if resp.status_code in (400, 401, 429, 503):
                resp.read()  # small; NonceCache and RetryPolicy look in it
            return resp

        def first() -> httpx.Response:
            resp = send()
            if self.dpop_key is not None and self._nonce.update(resp):
                resp.close()
                resp = send()
                self._nonce.update(resp)
            return resp

        expires = Deadline(deadline)
        retries = 0
        resp = first()
        # A load refusal is retried here, before anything of the stream has been yielded.
        while (wait := self._retry.delay(resp, retries, expires.left())) is not None:
            resp.close()
            _retry.sleep(wait)
            retries += 1
            resp = first()
        try:
            stream = CallStream(resp, request_id, max_event_bytes)
            if not (stream.sse and resp.is_success):
                data = bytearray()
                for chunk in resp.iter_bytes():
                    expires.check()
                    data += chunk
                    if len(data) > max_event_bytes:
                        break
                yield from stream.plain(bytes(data))
                return
            for chunk in resp.iter_bytes():
                expires.check()
                yield from stream.feed(chunk)
                if stream.done:
                    return
            yield from stream.finish()
        finally:
            resp.close()

    def list_tools(
        self, token: Token | str | None, server: str, session_id: str | None = None
    ) -> list[w.Tool]:
        """``tools/list``; the proxy shows only the tools this token may call."""
        result, _, _ = self._rpc(token, server, "tools/list", {}, session_id)
        return w.tools_from_result(result)

    def close_session(self, token: Token | str | None, server: str, session_id: str) -> bool:
        """End an MCP session (``DELETE /mcp/{server}`` with its ``Mcp-Session-Id``). ``True``
        when the upstream closed it, ``False`` when the upstream does not let clients close
        sessions (405). The proxy's refusals raise what a call would (an unknown session is an
        :class:`~attenuo.RpcError` with code ``-32600``)."""
        path, headers = _session_request(self._auth, token, self.token, server, session_id)
        return w.session_closed(self._request("DELETE", path, headers))

    # -- approvals --
    def get_approval(self, approval_id: str, token: Token | str | None = None) -> w.Approval:
        """``GET /approvals/{id}`` with a delegation token of the same run (or the user's ID
        token). Anyone else gets a 404 :class:`~attenuo.ApiError`."""
        path = f"/approvals/{w.path_segment(approval_id, 'approval_id')}"
        resp = self._request("GET", path, self._auth(w.bearer(token, self.token), path, "GET"))
        return w.approval_from_json(w.json_body(resp))

    def wait_for_approval(
        self,
        approval_id: str,
        token: Token | str | None = None,
        *,
        timeout: float | None = None,
        interval: float = 2.0,
    ) -> w.Approval:
        """Poll :meth:`get_approval` every ``interval`` seconds until the approval is granted.

        Returns the granted approval. Raises :class:`~attenuo.ApprovalNotGranted` when it is
        declined, expires, was already used, or ``timeout`` seconds pass first (without a
        ``timeout`` the wait ends when the approval expires on the server).
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            approval = self.get_approval(approval_id, token)
            if w.approval_ready(approval):
                return approval
            pause = interval
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise ApprovalNotGranted(approval_id, "timeout")
                pause = min(interval, left)
            time.sleep(pause)

    def call_tool_with_approval(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        on_approval: Callable[[ApprovalRequired], None] | None = None,
        timeout: float | None = None,
        interval: float = 2.0,
    ) -> w.ToolResult:
        """:meth:`call_tool`; when the call needs an approval (``-32008``), call
        ``on_approval`` (to show the user the approval id), wait for the grant, and retry the
        call once: with the grant's signed approval token in ``_meta`` when the server returned
        one, else identically. A second ``-32008``, a decline or an expiry is raised."""
        try:
            return self.call_tool(token, server, tool, arguments, session_id)
        except ApprovalRequired as e:
            if e.approval_id is None:
                raise
            if on_approval is not None:
                on_approval(e)
            granted = self.wait_for_approval(
                e.approval_id, token, timeout=timeout, interval=interval
            )
        return self.call_tool(
            token, server, tool, arguments, session_id, approval_token=granted.approval_token
        )

    def grant_approval(self, approval_id: str, id_token: str) -> w.Approval:
        """Grant a pending approval as the run's originating user (``POST /approvals/{id}``,
        ``by = "user"``); returns it. ``id_token`` is that user's OIDC ID token, sent as a
        plain bearer: a delegation token is refused (403 ``agent_token_refused``), another
        user's is 403 ``wrong_user``, and an ID token decides once (400 ``invalid_grant``
        after). 409 (``approval_not_pending``, ``approval_expired``, ``lease_revoked``) when
        it cannot be decided any more, 404 when it is unknown; all :class:`~attenuo.ApiError`
        (:class:`~attenuo.Unauthorized` for a 401)."""
        return self._decide(approval_id, id_token, "grant")

    def decline_approval(self, approval_id: str, id_token: str) -> w.Approval:
        """Decline a pending approval as the run's originating user; errors as
        :meth:`grant_approval`."""
        return self._decide(approval_id, id_token, "decline")

    def _decide(self, approval_id: str, id_token: str, decision: str) -> w.Approval:
        path = f"/approvals/{w.path_segment(approval_id, 'approval_id')}"
        h, body = w.id_token_headers(id_token), w.approval_decision_body(decision)
        resp = self._retrying(lambda: self._http.post(path, headers=h, json=body))
        return w.approval_from_json(w.json_body(resp))

    # -- AuthZEN --
    def authzen_evaluate(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
    ) -> w.AuthzenDecision:
        """Ask for a decision without calling the tool. A deny is returned, not raised."""
        resp = self._post(
            "/access/v1/evaluation",
            self._auth(w.bearer(token, self.token), "/access/v1/evaluation"),
            json=w.authzen_body(server, tool, arguments),
        )
        return w.authzen_from_response(w.json_body(resp))

    def authzen_evaluate_batch(
        self,
        token: Token | str | None,
        evaluations: Iterable[w.AuthzenEvaluationLike],
        *,
        semantic: str | None = None,
    ) -> list[w.AuthzenDecision]:
        """Decide several calls in one request (``POST /access/v1/evaluations``), each decided,
        charged and audited like :meth:`authzen_evaluate`. Returns one decision per call, in
        order; denies are returned, not raised.

        ``semantic`` is AuthZEN's ``evaluations_semantic``: ``execute_all`` (the server's
        default), ``deny_on_first_deny`` or ``permit_on_first_permit``. A batch stopped by it
        answers only the calls it decided, so the list can be shorter than ``evaluations``. A
        call the server could not decide is a deny whose ``error`` says why. More calls than
        ``[authzen] max_batch`` is an :class:`~attenuo.ApiError` (400 ``batch_too_large``)."""
        body = w.authzen_batch_body(evaluations, semantic)
        path = "/access/v1/evaluations"
        resp = self._post(path, self._auth(w.bearer(token, self.token), path), json=body)
        return w.authzen_batch_from_response(w.json_body(resp))

    def authzen_search_action(
        self,
        token: Token | str | None,
        server: str,
        arguments: dict[str, Any] | None = None,
        *,
        page_token: str | None = None,
        limit: int | None = None,
    ) -> w.AuthzenActionPage:
        """One page of AuthZEN action search (``POST /access/v1/search/action``): the tools the
        ``[policy] catalog`` lists for ``server`` that an evaluation with this token and
        ``arguments`` would allow now. Nothing is audited or charged, and no approval is taken,
        so an approval-gated tool is never a result.

        ``limit`` is how many catalogued tools the page evaluates (the server clamps it to
        ``[authzen] max_batch``); ``page_token`` is the ``next_token`` of the previous page, sent
        with the same arguments. :meth:`authzen_search_action_iter` follows it. Authentication,
        DPoP and retries are as for :meth:`authzen_evaluate`; a refusal raises
        :class:`~attenuo.ApiError` (400 ``invalid_search_resource`` for a ``server`` holding
        ``/``, 400 ``invalid_page`` or ``invalid_cursor`` for a bad page)."""
        path = "/access/v1/search/action"
        body = w.authzen_search_action_body(server, arguments, page_token, limit)
        resp = self._post(path, self._auth(w.bearer(token, self.token), path), json=body)
        return w.authzen_search_action_from_response(w.json_body(resp))

    def authzen_search_action_iter(
        self,
        token: Token | str | None,
        server: str,
        arguments: dict[str, Any] | None = None,
        *,
        limit: int | None = None,
    ) -> Iterator[w.AuthzenAction]:
        """Every result of :meth:`authzen_search_action`, following ``next_token`` until the
        last page. Pages lazily: stop iterating to stop asking."""
        page_token: str | None = None
        while True:
            page = self.authzen_search_action(
                token, server, arguments, page_token=page_token, limit=limit
            )
            yield from page.actions
            page_token = w.advance_cursor(page.next_token, page_token)
            if page_token is None:
                return

    def authzen_configuration(self) -> w.AuthzenConfiguration:
        """``GET /.well-known/authzen-configuration``: the AuthZEN discovery document. No
        credential is sent."""
        resp = self._retrying(lambda: self._http.get("/.well-known/authzen-configuration"))
        return w.authzen_configuration_from_json(w.json_body(resp))

    # -- inspection --
    def jwks(self) -> dict[str, Any]:
        """``GET /.well-known/jwks.json``."""
        body = w.json_body(self._retrying(lambda: self._http.get("/.well-known/jwks.json")))
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
        server's JWKS is fetched and :class:`~attenuo.VerificationError` is raised on failure.
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
        dpop_key: DpopKey | dict[str, Any] | None = None,
        max_retries: int = 0,
        max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
    ) -> None:
        self.server_url = w.normalize_base(server_url)
        self.token = token
        self._retry = RetryPolicy(max_retries, max_retry_delay)
        self.dpop_key = DpopKey.of(dpop_key)
        self._nonce = NonceCache()
        self._http = AsyncHttpClient(
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
        subject_dpop_key: DpopKey | dict[str, Any] | None = None,
        subject_token_dpop: str | None = None,
        client_assertion: str | None = None,
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
            client_assertion=client_assertion,
        )
        resp = await self._post(
            "/token",
            lambda nonce: _exchange_dpop(
                self.server_url, self.dpop_key, body, subject_dpop_key, subject_token_dpop, nonce
            ),
            json=body,
            resend_until=w.assertion_expiry(body),
        )
        return w.token_from_response(w.json_body(resp))

    async def _post(
        self, path: str, headers: Callable[[str | None], dict[str, str]], **kwargs: Any
    ) -> httpx.Response:
        return await self._request("POST", path, headers, **kwargs)

    async def _request(
        self,
        method: str,
        path: str,
        headers: Callable[[str | None], dict[str, str]],
        *,
        resend_until: float | None = None,
        **kwargs: Any,
    ) -> httpx.Response:

        async def send() -> httpx.Response:
            h = headers(self._nonce.value)
            resp = await self._http.request(method, path, headers=h, **kwargs)
            if self.dpop_key is not None and self._nonce.update(resp):
                h = headers(self._nonce.value)
                resp = await self._http.request(method, path, headers=h, **kwargs)
                self._nonce.update(resp)
            return resp

        return await self._retrying(send, resend_until)

    async def _retrying(
        self, send: Callable[[], Awaitable[httpx.Response]], resend_until: float | None = None
    ) -> httpx.Response:
        """:meth:`Client._retrying`."""
        retries = 0
        while True:
            resp = await send()
            wait = self._retry.delay(resp, retries, _retry.left_until(resend_until))
            if wait is None:
                return resp
            await resp.aclose()
            await _retry.asleep(wait)
            retries += 1

    def _auth(
        self, token: str, path: str, method: str = "POST"
    ) -> Callable[[str | None], dict[str, str]]:
        url = f"{self.server_url}{path}"
        return lambda nonce: presented(token, self.dpop_key, method, url, nonce)

    async def renew(self, token: Token | str | None = None) -> w.Lease:
        resp = await self._post(
            "/token/renew", self._auth(w.bearer(token, self.token), "/token/renew")
        )
        return w.lease_from_response(w.json_body(resp))

    async def _rpc(
        self,
        token: Token | str | None,
        server: str,
        method: str,
        params: dict[str, Any],
        session_id: str | None = None,
    ) -> tuple[dict[str, Any], str | None, httpx.Response]:
        path = f"/mcp/{w.path_segment(server, 'server')}"
        jwt = w.bearer(token, self.token)
        auth = self._auth(jwt, path)
        resp = await self._post(
            path,
            lambda nonce: {**w.mcp_headers(jwt, session_id), **auth(nonce)},
            json=w.rpc_request(method, params, next(self._ids)),
        )
        result, decision_id = w.rpc_result(resp)
        return result, decision_id, resp

    async def initialize(
        self,
        token: Token | str | None,
        server: str,
        client_name: str = "attenuo-python",
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
        *,
        approval_token: str | None = None,
    ) -> w.ToolResult:
        result, decision_id, _ = await self._rpc(
            token, server, "tools/call", w.call_params(tool, arguments, approval_token), session_id
        )
        return w.tool_result(result, decision_id)

    def call_tool_stream(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        approval_token: str | None = None,
        max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES,
        deadline: float | None = None,
    ) -> AsyncIterator[StreamEvent]:
        """:meth:`Client.call_tool_stream` as an async iterator (``async for``, no ``await``)."""
        path = f"/mcp/{w.path_segment(server, 'server')}"
        jwt = w.bearer(token, self.token)
        if max_event_bytes <= 0:
            raise ValueError("max_event_bytes must be positive")
        check_deadline(deadline)
        request_id = next(self._ids)
        params = w.call_params(tool, arguments, approval_token)
        body = w.rpc_request("tools/call", params, request_id)
        auth = self._auth(jwt, path)
        return self._stream(
            path,
            lambda nonce: {**w.mcp_headers(jwt, session_id), **auth(nonce)},
            body,
            request_id,
            max_event_bytes,
            deadline,
        )

    async def _stream(
        self,
        path: str,
        headers: Callable[[str | None], dict[str, str]],
        body: dict[str, Any],
        request_id: int,
        max_event_bytes: int,
        deadline: float | None = None,
    ) -> AsyncIterator[StreamEvent]:
        async def send() -> httpx.Response:
            h = headers(self._nonce.value)
            req = self._http.build_request("POST", path, headers=h, json=body)
            resp = await self._http.send(req, stream=True)
            if resp.status_code in (400, 401, 429, 503):
                await resp.aread()  # small; NonceCache and RetryPolicy look in it
            return resp

        async def first() -> httpx.Response:
            resp = await send()
            if self.dpop_key is not None and self._nonce.update(resp):
                await resp.aclose()
                resp = await send()
                self._nonce.update(resp)
            return resp

        expires = Deadline(deadline)
        retries = 0
        resp = await first()
        # A load refusal is retried here, before anything of the stream has been yielded.
        while (wait := self._retry.delay(resp, retries, expires.left())) is not None:
            await resp.aclose()
            await _retry.asleep(wait)
            retries += 1
            resp = await first()
        try:
            stream = CallStream(resp, request_id, max_event_bytes)
            if not (stream.sse and resp.is_success):
                data = bytearray()
                async for chunk in resp.aiter_bytes():
                    expires.check()
                    data += chunk
                    if len(data) > max_event_bytes:
                        break
                for ev in stream.plain(bytes(data)):
                    yield ev
                return
            async for chunk in resp.aiter_bytes():
                expires.check()
                for ev in stream.feed(chunk):
                    yield ev
                if stream.done:
                    return
            for ev in stream.finish():
                yield ev
        finally:
            await resp.aclose()

    async def list_tools(
        self, token: Token | str | None, server: str, session_id: str | None = None
    ) -> list[w.Tool]:
        result, _, _ = await self._rpc(token, server, "tools/list", {}, session_id)
        return w.tools_from_result(result)

    async def close_session(self, token: Token | str | None, server: str, session_id: str) -> bool:
        path, headers = _session_request(self._auth, token, self.token, server, session_id)
        return w.session_closed(await self._request("DELETE", path, headers))

    async def get_approval(self, approval_id: str, token: Token | str | None = None) -> w.Approval:
        path = f"/approvals/{w.path_segment(approval_id, 'approval_id')}"
        resp = await self._request(
            "GET", path, self._auth(w.bearer(token, self.token), path, "GET")
        )
        return w.approval_from_json(w.json_body(resp))

    async def wait_for_approval(
        self,
        approval_id: str,
        token: Token | str | None = None,
        *,
        timeout: float | None = None,
        interval: float = 2.0,
    ) -> w.Approval:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            approval = await self.get_approval(approval_id, token)
            if w.approval_ready(approval):
                return approval
            pause = interval
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise ApprovalNotGranted(approval_id, "timeout")
                pause = min(interval, left)
            await asyncio.sleep(pause)

    async def call_tool_with_approval(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        on_approval: Callable[[ApprovalRequired], None] | None = None,
        timeout: float | None = None,
        interval: float = 2.0,
    ) -> w.ToolResult:
        try:
            return await self.call_tool(token, server, tool, arguments, session_id)
        except ApprovalRequired as e:
            if e.approval_id is None:
                raise
            if on_approval is not None:
                on_approval(e)
            granted = await self.wait_for_approval(
                e.approval_id, token, timeout=timeout, interval=interval
            )
        return await self.call_tool(
            token, server, tool, arguments, session_id, approval_token=granted.approval_token
        )

    async def grant_approval(self, approval_id: str, id_token: str) -> w.Approval:
        return await self._decide(approval_id, id_token, "grant")

    async def decline_approval(self, approval_id: str, id_token: str) -> w.Approval:
        return await self._decide(approval_id, id_token, "decline")

    async def _decide(self, approval_id: str, id_token: str, decision: str) -> w.Approval:
        path = f"/approvals/{w.path_segment(approval_id, 'approval_id')}"
        h, body = w.id_token_headers(id_token), w.approval_decision_body(decision)
        resp = await self._retrying(lambda: self._http.post(path, headers=h, json=body))
        return w.approval_from_json(w.json_body(resp))

    async def authzen_evaluate(
        self,
        token: Token | str | None,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
    ) -> w.AuthzenDecision:
        resp = await self._post(
            "/access/v1/evaluation",
            self._auth(w.bearer(token, self.token), "/access/v1/evaluation"),
            json=w.authzen_body(server, tool, arguments),
        )
        return w.authzen_from_response(w.json_body(resp))

    async def authzen_evaluate_batch(
        self,
        token: Token | str | None,
        evaluations: Iterable[w.AuthzenEvaluationLike],
        *,
        semantic: str | None = None,
    ) -> list[w.AuthzenDecision]:
        body = w.authzen_batch_body(evaluations, semantic)
        path = "/access/v1/evaluations"
        resp = await self._post(path, self._auth(w.bearer(token, self.token), path), json=body)
        return w.authzen_batch_from_response(w.json_body(resp))

    async def authzen_search_action(
        self,
        token: Token | str | None,
        server: str,
        arguments: dict[str, Any] | None = None,
        *,
        page_token: str | None = None,
        limit: int | None = None,
    ) -> w.AuthzenActionPage:
        path = "/access/v1/search/action"
        body = w.authzen_search_action_body(server, arguments, page_token, limit)
        resp = await self._post(path, self._auth(w.bearer(token, self.token), path), json=body)
        return w.authzen_search_action_from_response(w.json_body(resp))

    async def authzen_search_action_iter(
        self,
        token: Token | str | None,
        server: str,
        arguments: dict[str, Any] | None = None,
        *,
        limit: int | None = None,
    ) -> AsyncIterator[w.AuthzenAction]:
        page_token: str | None = None
        while True:
            page = await self.authzen_search_action(
                token, server, arguments, page_token=page_token, limit=limit
            )
            for action in page.actions:
                yield action
            page_token = w.advance_cursor(page.next_token, page_token)
            if page_token is None:
                return

    async def authzen_configuration(self) -> w.AuthzenConfiguration:
        resp = await self._retrying(lambda: self._http.get("/.well-known/authzen-configuration"))
        return w.authzen_configuration_from_json(w.json_body(resp))

    async def jwks(self) -> dict[str, Any]:
        resp = await self._retrying(lambda: self._http.get("/.well-known/jwks.json"))
        body = w.json_body(resp)
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


def _session_request(
    auth: Callable[[str, str, str], Callable[[str | None], dict[str, str]]],
    token: Token | str | None,
    default: Token | str | None,
    server: str,
    session_id: str,
) -> tuple[str, Callable[[str | None], dict[str, str]]]:
    """The path and headers of ``DELETE /mcp/{server}`` for ``session_id``."""
    if not session_id:
        raise ValueError("session_id must be the Mcp-Session-Id to close")
    path = f"/mcp/{w.path_segment(server, 'server')}"
    presented_auth = auth(w.bearer(token, default), path, "DELETE")
    return path, lambda nonce: {
        "accept": w.MCP_ACCEPT,
        w.SESSION_HEADER: session_id,
        **presented_auth(nonce),
    }


def _exchange_dpop(
    server_url: str,
    key: DpopKey | None,
    body: dict[str, Any],
    subject_dpop_key: DpopKey | dict[str, Any] | None,
    subject_token_dpop: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Add DPoP to an exchange: the ``DPoP`` header binding the new token to ``key`` (with the
    server's ``nonce``, if any), and the parent's sign-off in ``body``, made here when
    ``subject_dpop_key`` is given or passed in ready-made as ``subject_token_dpop``."""
    if subject_dpop_key is not None and subject_token_dpop is not None:
        raise AttenuoError("pass subject_dpop_key or subject_token_dpop, not both")
    header, sign_off = exchange_proofs(
        f"{server_url}/token",
        body["subject_token"],
        key,
        DpopKey.of(subject_dpop_key),
        body["actor"],
        nonce,
    )
    sign_off = sign_off or subject_token_dpop
    if sign_off is not None:
        body["subject_token_dpop"] = sign_off
    return {"dpop": header} if header is not None else {}
