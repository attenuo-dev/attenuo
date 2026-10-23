from __future__ import annotations

import httpx
import pytest

from onbehalf import Client
from onbehalf.mcp import TokenAuth, mcp_headers, mcp_url

from .helpers import Signer


def test_url() -> None:
    assert mcp_url("http://127.0.0.1:8080/", "github") == "http://127.0.0.1:8080/mcp/github"
    with pytest.raises(ValueError):
        mcp_url("github", "github")


def test_headers() -> None:
    assert mcp_headers("T") == {"Authorization": "Bearer T"}
    assert mcp_headers("T", "sess") == {"Authorization": "Bearer T", "Mcp-Session-Id": "sess"}
    h = mcp_headers("T", content_headers=True)
    assert h["Accept"] == "application/json, text/event-stream"
    assert h["Content-Type"] == "application/json"
    tok = Client("http://x").inspect(Signer().mint())
    assert mcp_headers(tok)["Authorization"] == f"Bearer {tok.jwt}"


def test_token_auth_reads_provider_each_request() -> None:
    current = ["one"]
    seen: list[str] = []

    def handler(r: httpx.Request) -> httpx.Response:
        seen.append(r.headers["authorization"])
        return httpx.Response(200)

    with httpx.Client(
        transport=httpx.MockTransport(handler), auth=TokenAuth(lambda: current[0])
    ) as c:
        c.get("http://x/mcp/github")
        current[0] = "two"
        c.get("http://x/mcp/github")
    assert seen == ["Bearer one", "Bearer two"]
