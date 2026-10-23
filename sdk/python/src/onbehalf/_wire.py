"""Request building and response parsing shared by the sync and async clients (no I/O here)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from .capability import capabilities_to_json
from .errors import ApiError, Denied, OnbehalfError, RpcError, Unauthorized
from .token import Token, decode_token, parse_time

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
AUTHORIZATION_DETAILS_TYPE = "onbehalf_capabilities"

CODE_UNAUTHORIZED = -32001
CODE_DENIED = -32003
DECISION_ID_HEADER = "x-onbehalf-decision-id"
SESSION_HEADER = "mcp-session-id"
MCP_ACCEPT = "application/json, text/event-stream"


def normalize_base(url: str) -> str:
    base = url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise ValueError(
            f"server_url must be the onbehalf server's base URL (http://host:port), got {url!r}. "
            "To name an MCP upstream, pass it as the `server` argument of call_tool/list_tools."
        )
    return base


def bearer(token: Token | str | None, default: Token | str | None = None) -> str:
    chosen = token if token is not None else default
    if chosen is None:
        raise ValueError("no token: pass one, or give the client a default `token=`")
    return chosen.jwt if isinstance(chosen, Token) else str(chosen).strip()


# --- results ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Lease:
    """Result of ``renew``."""

    lease: str
    expires_at: datetime
    expires_in: int


@dataclass(frozen=True)
class ToolResult:
    """An allowed ``tools/call``. ``is_error`` means the *tool* reported an error."""

    content: list[dict[str, Any]]
    is_error: bool
    decision_id: str | None
    raw: dict[str, Any] = field(repr=False)

    @property
    def text(self) -> str:
        """All text content items joined with newlines."""
        return "\n".join(str(c.get("text", "")) for c in self.content if c.get("type") == "text")

    @property
    def structured_content(self) -> Any:
        return self.raw.get("structuredContent")


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any] = field(repr=False)
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class AuthzenDecision:
    """Answer to an AuthZEN evaluation. A ``False`` decision is returned, never raised."""

    decision: bool
    reason: str
    decision_id: str | None
    policy_ids: list[str]
    diagnostics: list[Any]

    def __bool__(self) -> bool:
        return self.decision


# --- plain HTTP ------------------------------------------------------------------------------


def error_from_response(resp: httpx.Response) -> ApiError:
    text = resp.text
    error, detail, description = "http_error", text.strip(), None
    try:
        body = json.loads(text)
    except ValueError:
        body = None
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        error = body["error"]
        detail = str(body.get("detail", ""))
        description = body.get("error_description")
    elif isinstance(body, dict) and isinstance(body.get("error"), dict):
        # A JSON-RPC error body (the proxy's 401).
        error = str(body["error"].get("code", "rpc_error"))
        detail = str(body["error"].get("message", ""))
    cls = Unauthorized if resp.status_code == 401 else ApiError
    return cls(resp.status_code, error, detail, description)


def json_body(resp: httpx.Response) -> Any:
    """The JSON body of a success response; raises ``ApiError`` otherwise."""
    if not resp.is_success:
        raise error_from_response(resp)
    try:
        return resp.json()
    except ValueError as e:
        raise OnbehalfError(f"server sent non-JSON ({resp.status_code}): {resp.text[:200]}") from e


def exchange_body(
    subject_token: Token | str,
    actor: str,
    capabilities: Any,
    ttl_seconds: int | None,
    client_id: str | None,
    client_secret: str | None,
    subject_token_type: str | None,
) -> dict[str, Any]:
    if client_id is not None and not client_secret:
        raise ValueError("client_id and client_secret go together")
    if client_secret and client_id is None:
        # A hop n+1 exchange authenticates as its actor.
        client_id = actor
    subject = bearer(subject_token)
    if subject_token_type is None:
        # Client credentials alone do not make this hop 0: the server also requires them, as
        # the actor's, on a hop n+1 exchange. Hop 0 is an IdP credential, which is not an
        # onbehalf delegation token.
        intake = client_secret is not None and not is_delegation_token(subject_token)
        subject_token_type = TYPE_ID_TOKEN if intake else TYPE_JWT
    body: dict[str, Any] = {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": subject,
        "subject_token_type": subject_token_type,
        "actor": actor,
        "authorization_details": [
            {
                "type": AUTHORIZATION_DETAILS_TYPE,
                "capabilities": capabilities_to_json(capabilities),
            }
        ],
    }
    if ttl_seconds is not None:
        body["requested_ttl_seconds"] = int(ttl_seconds)
    if client_secret:
        body["client_id"] = client_id
        body["client_secret"] = client_secret
    return body


def is_delegation_token(token: Token | str) -> bool:
    """Does ``token`` decode as an onbehalf delegation token? Nothing is verified."""
    if isinstance(token, Token):
        return True
    try:
        decode_token(str(token))
    except OnbehalfError:
        return False
    return True


def token_from_response(body: Any) -> Token:
    if not isinstance(body, dict) or "access_token" not in body:
        raise OnbehalfError(f"unexpected token response: {str(body)[:200]}")
    return decode_token(body["access_token"], lease=body.get("lease"))


def lease_from_response(body: Any) -> Lease:
    return Lease(
        lease=str(body["lease"]),
        expires_at=parse_time(body["expires_at"]),
        expires_in=int(body["expires_in"]),
    )


def authzen_body(server: str, tool: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    # The server fills an empty subject id from the verified chain.
    return {
        "subject": {"type": "agent", "id": ""},
        "action": {"name": tool, "properties": {"server": server}},
        "resource": {"type": "tool", "id": f"{server}/{tool}"},
        "context": {"input": arguments or {}},
    }


def authzen_from_response(body: Any) -> AuthzenDecision:
    ctx = body.get("context") or {}
    return AuthzenDecision(
        decision=body.get("decision") is True,
        reason=str(ctx.get("reason", "")),
        decision_id=ctx.get("decision_id"),
        policy_ids=list(ctx.get("policy_ids") or []),
        diagnostics=list(ctx.get("diagnostics") or []),
    )


# --- MCP / JSON-RPC --------------------------------------------------------------------------


def mcp_headers(token: str, session_id: str | None = None) -> dict[str, str]:
    h = {
        "authorization": f"Bearer {token}",
        "accept": MCP_ACCEPT,
        "content-type": "application/json",
    }
    if session_id:
        h["mcp-session-id"] = session_id
    return h


def rpc_request(method: str, params: dict[str, Any], request_id: int) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def parse_rpc_body(text: str, sse: bool) -> dict[str, Any] | None:
    """The JSON-RPC response in a plain JSON or ``text/event-stream`` body."""
    if not sse:
        try:
            v = json.loads(text)
        except ValueError:
            return None
        return v if isinstance(v, dict) else None
    # An SSE event's data may span several `data:` lines; events are separated by blank lines.
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(
            line[5:].removeprefix(" ") for line in block.split("\n") if line.startswith("data:")
        )
        if not data.strip():
            continue
        try:
            v = json.loads(data)
        except ValueError:
            continue
        if isinstance(v, dict) and ("result" in v or "error" in v):
            return v
    return None


def rpc_result(resp: httpx.Response) -> tuple[dict[str, Any], str | None]:
    """The ``result`` of a JSON-RPC response, or the right exception.

    Returns ``(result, decision_id)``. Denials (``-32003``) raise :class:`Denied`; ``-32001``
    or HTTP 401 raises :class:`Unauthorized`; any other JSON-RPC error raises :class:`RpcError`.
    """
    decision_id = resp.headers.get(DECISION_ID_HEADER)
    sse = "event-stream" in resp.headers.get("content-type", "")
    msg = parse_rpc_body(resp.text, sse)
    if msg is None:
        if resp.is_success:
            raise OnbehalfError(f"no JSON-RPC response in body: {resp.text[:200]}")
        raise error_from_response(resp)
    err = msg.get("error")
    if isinstance(err, dict):
        code = err.get("code")
        raw_data = err.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        message = str(err.get("message", ""))
        if code == CODE_DENIED:
            raise Denied(
                str(data.get("reason", "unknown")),
                data.get("decision_id") or decision_id,
                message,
            )
        if code == CODE_UNAUTHORIZED or resp.status_code == 401:
            raise Unauthorized(401, "unauthorized", message)
        raise RpcError(int(code) if isinstance(code, int) else 0, message, raw_data)
    if not resp.is_success:
        raise error_from_response(resp)
    result = msg.get("result")
    return (result if isinstance(result, dict) else {}), decision_id


def tool_result(result: dict[str, Any], decision_id: str | None) -> ToolResult:
    return ToolResult(
        content=[c for c in result.get("content", []) if isinstance(c, dict)],
        is_error=result.get("isError") is True,
        decision_id=decision_id,
        raw=result,
    )


def tools_from_result(result: dict[str, Any]) -> list[Tool]:
    return [
        Tool(
            name=str(t.get("name", "")),
            description=str(t.get("description", "")),
            input_schema=dict(t.get("inputSchema") or {}),
            raw=t,
        )
        for t in result.get("tools", [])
        if isinstance(t, dict)
    ]
