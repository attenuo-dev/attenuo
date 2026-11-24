"""``httpx`` clients whose transport failures are :class:`~attenuo.TransportError` (a timeout
:class:`~attenuo.TransportTimeout`).

Every request the SDK's clients send goes through ``send``, so wrapping there covers them all:
a failure to send or to read a whole answer, and, for a streamed answer, a failure while its
body is read. The nonce retry is not affected: it looks at answers, never at exceptions.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from ._tls import TlsSettings
from .errors import ApiError, TransportError, TransportTimeout

#: The ``error`` and ``code`` of the :class:`~attenuo.ApiError` a 3xx answer raises (SR-112).
REDIRECT_NOT_FOLLOWED = "redirect_not_followed"


def redirect_error(resp: httpx.Response) -> ApiError | None:
    """The error for a 3xx answer, else ``None``. No client of the SDK follows a redirect: a
    followed ``307`` or ``308`` would send the body again to wherever ``Location`` names, a
    client secret, client assertion or subject token included (SR-112). The error names the
    status and the ``Location``, so the caller can set the server URL to the final one."""
    if not 300 <= resp.status_code < 400:
        return None
    location = resp.headers.get("location")
    where = f"Location {location}" if location else "no Location"
    detail = (
        f"{resp.request.method} {resp.request.url} answered {resp.status_code} ({where}); "
        "the client does not follow redirects, so the server URL must be the final URL, the "
        "one that answers without a redirect"
    )
    return ApiError(resp.status_code, REDIRECT_NOT_FOLLOWED, detail)


def _wrap(e: httpx.TransportError, request: httpx.Request | None) -> TransportError:
    """``e`` as a :class:`TransportError`; a timeout as its :class:`TransportTimeout`."""
    target = f"{request.method} {request.url}" if request is not None else "request"
    cls = TransportTimeout if isinstance(e, httpx.TimeoutException) else TransportError
    return cls(f"{target} failed: {type(e).__name__}: {e}", request=request)


def _request_of(e: httpx.TransportError) -> httpx.Request | None:
    try:
        return e.request
    except RuntimeError:  # raised by an httpx error made without a request
        return None


class _SyncBody(httpx.SyncByteStream):
    def __init__(self, inner: httpx.SyncByteStream, request: httpx.Request) -> None:
        self._inner = inner
        self._request = request

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self._inner
        except TransportError:
            raise
        except httpx.TransportError as e:
            raise _wrap(e, self._request) from e

    def close(self) -> None:
        self._inner.close()


class _AsyncBody(httpx.AsyncByteStream):
    def __init__(self, inner: httpx.AsyncByteStream, request: httpx.Request) -> None:
        self._inner = inner
        self._request = request

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._inner:
                yield chunk
        except TransportError:
            raise
        except httpx.TransportError as e:
            raise _wrap(e, self._request) from e

    async def aclose(self) -> None:
        await self._inner.aclose()


def _tls_kwargs(tls: TlsSettings | None, kwargs: dict[str, Any]) -> dict[str, Any] | None:
    """Set ``verify`` in ``kwargs`` for ``tls``, and return the arguments of the second client,
    the one without the client certificate, when ``tls`` has one (else ``None``)."""
    if tls is None:
        return None
    kwargs["verify"] = tls.server_context
    if not tls.has_client_cert:
        return None
    if "_transport_for_url" not in vars(httpx.Client) or (
        "_transport_for_url" not in vars(httpx.AsyncClient)
    ):
        # The per-origin choice hooks this httpx method; without it, fail closed.
        raise RuntimeError("this httpx version cannot keep the client certificate to one origin")
    other: dict[str, Any] = {
        k: kwargs[k] for k in ("timeout", "trust_env", "limits") if k in kwargs
    }
    return {**other, "verify": tls.other_context, "follow_redirects": False}


class HttpClient(httpx.Client):
    """An ``httpx.Client`` that raises :class:`~attenuo.TransportError` for transport
    failures, with the ``httpx`` error as ``__cause__``, and :class:`~attenuo.ApiError`
    ``redirect_not_followed`` for a 3xx answer (:func:`redirect_error`).

    With ``tls`` (the ``tls_*`` options), the TLS context with the client certificate is used
    for the server's origin only: :meth:`_transport_for_url`, which httpx calls for every
    request it sends, is the one place that chooses, by the request's origin, never its path.
    Any other origin goes through a second client whose context has the CA and no certificate.
    """

    def __init__(self, *args: Any, tls: TlsSettings | None = None, **kwargs: Any) -> None:
        kwargs["follow_redirects"] = False
        other = _tls_kwargs(tls, kwargs)
        self._tls = tls
        self._plain = None if other is None else httpx.Client(**other)
        super().__init__(*args, **kwargs)

    def _transport_for_url(self, url: httpx.URL) -> httpx.BaseTransport:
        tls = self._tls
        if self._plain is not None and tls is not None and not tls.is_server_origin(url):
            return self._plain._transport_for_url(url)
        return super()._transport_for_url(url)

    def close(self) -> None:
        super().close()
        if self._plain is not None:
            self._plain.close()

    def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        try:
            resp = super().send(request, **kwargs)
        except TransportError:
            raise
        except httpx.TransportError as e:
            raise _wrap(e, _request_of(e) or request) from e
        redirect = redirect_error(resp)
        if redirect is not None:
            resp.close()
            raise redirect
        if kwargs.get("stream") and isinstance(resp.stream, httpx.SyncByteStream):
            resp.stream = _SyncBody(resp.stream, request)
        return resp


class AsyncHttpClient(httpx.AsyncClient):
    """The ``asyncio`` :class:`HttpClient`."""

    def __init__(self, *args: Any, tls: TlsSettings | None = None, **kwargs: Any) -> None:
        kwargs["follow_redirects"] = False
        other = _tls_kwargs(tls, kwargs)
        self._tls = tls
        self._plain = None if other is None else httpx.AsyncClient(**other)
        super().__init__(*args, **kwargs)

    def _transport_for_url(self, url: httpx.URL) -> httpx.AsyncBaseTransport:
        tls = self._tls
        if self._plain is not None and tls is not None and not tls.is_server_origin(url):
            return self._plain._transport_for_url(url)
        return super()._transport_for_url(url)

    async def aclose(self) -> None:
        await super().aclose()
        if self._plain is not None:
            await self._plain.aclose()

    async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        try:
            resp = await super().send(request, **kwargs)
        except TransportError:
            raise
        except httpx.TransportError as e:
            raise _wrap(e, _request_of(e) or request) from e
        redirect = redirect_error(resp)
        if redirect is not None:
            await resp.aclose()
            raise redirect
        if kwargs.get("stream") and isinstance(resp.stream, httpx.AsyncByteStream):
            resp.stream = _AsyncBody(resp.stream, request)
        return resp
