"""Request building and response parsing shared by the sync and async clients (no I/O here)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

from .capability import capabilities_to_json
from .errors import (
    ApiError,
    ApprovalNotGranted,
    ApprovalRequired,
    AttenuoError,
    Denied,
    RpcError,
    Unauthorized,
)
from .token import Token, decode_token, parse_time

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
AUTHORIZATION_DETAILS_TYPE = "attenuo_capabilities"

CODE_UNAUTHORIZED = -32001
CODE_DENIED = -32003
CODE_APPROVAL_REQUIRED = -32008
DECISION_ID_HEADER = "x-attenuo-decision-id"
SESSION_HEADER = "mcp-session-id"
MCP_ACCEPT = "application/json, text/event-stream"


def normalize_base(url: str) -> str:
    base = url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise ValueError(
            f"server_url must be the attenuo server's base URL (http://host:port), got {url!r}. "
            "To name an MCP upstream, pass it as the `server` argument of call_tool/list_tools."
        )
    return base


def path_segment(value: str, what: str) -> str:
    """``value`` as one percent-encoded URL path segment.

    Server names and lease ids can come from untrusted input (a lease id is read from a token
    an agent handed over). Left as they are, ``../`` or ``?`` in them would send the request,
    with this client's bearer, to another endpoint (SR-31). ``.`` and ``..`` are refused
    because URL normalization removes them even inside an encoded path.
    """
    if value in ("", ".", ".."):
        raise ValueError(f"{what} must be a non-empty name other than '.' and '..', got {value!r}")
    return quote(value, safe="")


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
    """Answer to an AuthZEN evaluation. A ``False`` decision is returned, never raised.

    On ``reason == "approval_required"`` the fields the proxy's ``-32008`` carries are set too:
    ``call_hash`` (what an approval is bound to), and ``approval_id`` and ``expires_at`` of the
    pending approval. ``approval_id`` is ``None`` when the server opened none: the run already
    has as many pending approvals as it keeps (32), and a PEP that gets diagnostics sees
    ``"too many pending approvals for this run"`` in ``diagnostics``. The call is then simply
    denied until an approval of the run is decided or lapses.
    """

    decision: bool
    reason: str
    decision_id: str | None
    policy_ids: list[str]
    diagnostics: list[Any]
    approval_id: str | None = None
    call_hash: str | None = None
    expires_at: datetime | None = None

    def __bool__(self) -> bool:
        return self.decision


@dataclass(frozen=True)
class Approval:
    """An approval as ``GET /approvals/{id}`` and the ``/admin/approvals`` routes show it.
    Fields the dataclass does not name (``labels``, ``decision_id``, ``created_at``, ...) are
    in ``raw``, among them ``untrusted_args`` (``[{arg, seq, kind}]``, present when an argument
    of the call matched an untrusted result of the run).

    ``state`` is ``pending``, ``granted``, ``declined`` or ``consumed``; ``expired`` is the
    server's view of whether ``expires_at`` has passed. ``usable`` is true for a grant that a
    retry of the identical call can still use. ``approval_token`` is the signed approval token
    (``attenuo-approval+jwt``) the server returns while the approval is granted and unexpired,
    else ``None``; see :mod:`attenuo.approval`.
    """

    approval_id: str
    state: str
    expired: bool
    chain_id: str
    call_hash: str
    server: str
    tool: str
    arguments: dict[str, Any]
    expires_at: datetime | None
    approver: dict[str, Any] | None
    consumed_by: str | None
    raw: dict[str, Any] = field(repr=False)
    approval_token: str | None = field(default=None, repr=False)

    @property
    def usable(self) -> bool:
        return self.state == "granted" and not self.expired


# --- plain HTTP ------------------------------------------------------------------------------


def error_from_response(resp: httpx.Response) -> ApiError:
    """The :class:`ApiError` (:class:`Unauthorized` for a 401) for a non-success answer.

    ``decision_id`` is the body's ``decision_id`` when ``X-Attenuo-Decision-Id`` vouches for
    it (see :func:`_proven_decision_id`). A JSON-RPC error body (the proxy's 401) gives its
    ``data.reason`` and ``data``.
    """
    text = resp.text
    error, detail, description = "http_error", text.strip(), None
    claimed: Any = None
    reason: str | None = None
    data: dict[str, Any] | None = None
    try:
        body = json.loads(text)
    except ValueError:
        body = None
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        error = body["error"]
        detail = str(body.get("detail", ""))
        description = body.get("error_description")
        claimed = body.get("decision_id")
    elif isinstance(body, dict) and isinstance(body.get("error"), dict):
        # A JSON-RPC error body (the proxy's 401).
        error = str(body["error"].get("code", "rpc_error"))
        detail = str(body["error"].get("message", ""))
        raw_data = body["error"].get("data")
        data = raw_data if isinstance(raw_data, dict) else {}
        claimed = data.get("decision_id")
        reason = _opt_str(data.get("reason")) or "unauthorized"
    decision_id = _proven_decision_id(resp, claimed)
    if resp.status_code == 401:
        return Unauthorized(
            resp.status_code, error, detail, description, decision_id, reason=reason, data=data
        )
    return ApiError(resp.status_code, error, detail, description, decision_id)


def json_body(resp: httpx.Response) -> Any:
    """The JSON body of a success response; raises ``ApiError`` otherwise."""
    if not resp.is_success:
        raise error_from_response(resp)
    try:
        return resp.json()
    except ValueError as e:
        raise AttenuoError(f"server sent non-JSON ({resp.status_code}): {resp.text[:200]}") from e


def exchange_body(
    subject_token: Token | str,
    actor: str,
    capabilities: Any,
    ttl_seconds: int | None,
    client_id: str | None,
    client_secret: str | None,
    subject_token_type: str | None,
    actor_token: str | None = None,
    may_act: Iterable[str] | None = None,
) -> dict[str, Any]:
    if actor_token is not None and not actor_token.strip():
        raise ValueError("actor_token is empty")
    if client_id is not None and not client_secret:
        raise ValueError("client_id and client_secret go together")
    if client_secret and client_id is None:
        # A hop n+1 exchange authenticates as its actor.
        client_id = actor
    subject = bearer(subject_token)
    if subject_token_type is None:
        # Agent credentials (a client secret or an actor token) alone do not make this hop 0:
        # the server also requires them, as the actor's, on a hop n+1 exchange. Hop 0 is an
        # IdP credential, which is not an attenuo delegation token.
        authenticated = client_secret is not None or actor_token is not None
        intake = authenticated and not is_delegation_token(subject_token)
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
    if actor_token is not None:
        # RFC 8693 §2.1: a workload-identity JWT (e.g. a SPIFFE JWT-SVID) for the actor.
        body["actor_token"] = actor_token.strip()
        body["actor_token_type"] = TYPE_JWT
    if may_act is not None:
        body["may_act"] = may_act_json(may_act)
    return body


def may_act_json(may_act: Iterable[str]) -> dict[str, list[str]]:
    """The RFC 8693 §4.4 ``may_act`` claim for a list of agent ids."""
    if isinstance(may_act, str):
        raise TypeError("may_act is a list of agent ids, not a string")
    agents = list(may_act)
    if not all(isinstance(a, str) and a for a in agents):
        raise ValueError("may_act agent ids must be non-empty strings")
    return {"sub": agents}


def is_delegation_token(token: Token | str) -> bool:
    """Does ``token`` decode as an attenuo delegation token? Nothing is verified."""
    if isinstance(token, Token):
        return True
    try:
        decode_token(str(token))
    except AttenuoError:
        return False
    return True


def token_from_response(body: Any) -> Token:
    if not isinstance(body, dict) or "access_token" not in body:
        raise AttenuoError(f"unexpected token response: {str(body)[:200]}")
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
        approval_id=_opt_str(ctx.get("approval_id")),
        call_hash=_opt_str(ctx.get("call_hash")),
        expires_at=_opt_time(ctx.get("expires_at")),
    )


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


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


def call_params(
    tool: str, arguments: dict[str, Any] | None, approval_token: str | None = None
) -> dict[str, Any]:
    """``tools/call`` params; an approval token goes in ``_meta["dev.attenuo/approval"]``."""
    params: dict[str, Any] = {"name": tool, "arguments": arguments or {}}
    if approval_token:
        params["_meta"] = {"dev.attenuo/approval": approval_token}
    return params


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


def _proven_decision_id(resp: httpx.Response, claimed: Any) -> str | None:
    """``claimed`` when it is one of the ids in ``resp``'s ``X-Attenuo-Decision-Id``, else
    ``None`` (SR-32).

    The server and the proxy set that header (a comma separated list, request order) on every
    response that carries their decisions, and the proxy forwards no such header from an
    upstream. An upstream is untrusted and can put any error, and any ``decision_id``, in its
    own body, so an id counts only when the header names it too.
    """
    header = resp.headers.get(DECISION_ID_HEADER)
    if not isinstance(claimed, str) or not claimed or not header:
        return None
    ids = [part.strip() for part in header.split(",")]
    return claimed if claimed in ids else None


def _proxy_decision_id(resp: httpx.Response, data: dict[str, Any]) -> str | None:
    """The decision id of a denial the proxy produced, else ``None``: a ``-32003`` or
    ``-32008`` counts as the proxy's only when ``data.decision_id`` is proven by the header
    (:func:`_proven_decision_id`)."""
    return _proven_decision_id(resp, data.get("decision_id"))


def _opt_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return parse_time(value)
    except ValueError:
        return None


def approval_from_json(body: Any) -> Approval:
    if not isinstance(body, dict) or not isinstance(body.get("approval_id"), str):
        raise AttenuoError("not an approval: missing approval_id")
    raw_call = body.get("call")
    call: dict[str, Any] = raw_call if isinstance(raw_call, dict) else {}
    args = call.get("arguments")
    approver = body.get("approver")
    consumed = body.get("consumed_by")
    approval_token = body.get("approval_token")
    return Approval(
        approval_id=body["approval_id"],
        state=str(body.get("state", "")),
        expired=body.get("expired") is True,
        chain_id=str(body.get("chain_id", "")),
        call_hash=str(body.get("call_hash", "")),
        server=str(call.get("server", "")),
        tool=str(call.get("tool", "")),
        arguments=args if isinstance(args, dict) else {},
        expires_at=_opt_time(body.get("expires_at")),
        approver=approver if isinstance(approver, dict) else None,
        consumed_by=consumed if isinstance(consumed, str) else None,
        raw=body,
        approval_token=approval_token
        if isinstance(approval_token, str) and approval_token
        else None,
    )


def approval_ready(approval: Approval) -> bool:
    """True when the grant is usable, False while it is still pending; raises
    :class:`~attenuo.ApprovalNotGranted` when waiting longer cannot help."""
    if approval.usable:
        return True
    if approval.expired:
        raise ApprovalNotGranted(approval.approval_id, "expired")
    if approval.state == "pending":
        return False
    raise ApprovalNotGranted(approval.approval_id, approval.state or "unknown")


_UNPARSED: Any = object()


def rpc_result(
    resp: httpx.Response, msg: dict[str, Any] | None = _UNPARSED
) -> tuple[dict[str, Any], str | None]:
    """The ``result`` of a JSON-RPC response, or the right exception.

    Returns ``(result, decision_id)``. ``msg`` is the response message when the caller already
    parsed it (an event of a stream); otherwise it is read from ``resp``'s body. Denials
    (``-32003`` that the proxy vouches for with ``X-Attenuo-Decision-Id``, see
    :func:`_proxy_decision_id`) raise
    :class:`Denied`; a ``-32003`` without that proof is an upstream's own error and raises
    :class:`RpcError`. A ``-32008`` with the same proof raises :class:`ApprovalRequired`.
    ``-32001`` or HTTP 401 raises :class:`Unauthorized` with the error's ``data.reason`` as
    ``reason`` and, when the header vouches for it, its ``data.decision_id``; any other
    JSON-RPC error raises :class:`RpcError`.
    """
    decision_id = resp.headers.get(DECISION_ID_HEADER)
    if msg is _UNPARSED:
        sse = "event-stream" in resp.headers.get("content-type", "")
        msg = parse_rpc_body(resp.text, sse)
    if msg is None:
        if resp.is_success:
            raise AttenuoError(f"no JSON-RPC response in body: {resp.text[:200]}")
        raise error_from_response(resp)
    err = msg.get("error")
    if isinstance(err, dict):
        code = err.get("code")
        raw_data = err.get("data")
        data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        message = str(err.get("message", ""))
        if code == CODE_DENIED:
            proven = _proxy_decision_id(resp, data)
            if proven is not None:
                raise Denied(str(data.get("reason", "unknown")), proven, message, data)
        if code == CODE_APPROVAL_REQUIRED:
            proven = _proxy_decision_id(resp, data)
            if proven is not None:
                approval_id = data.get("approval_id")
                call_hash = data.get("call_hash")
                raise ApprovalRequired(
                    proven,
                    approval_id if isinstance(approval_id, str) and approval_id else None,
                    _opt_time(data.get("expires_at")),
                    call_hash if isinstance(call_hash, str) else None,
                    message,
                    data,
                )
        if code == CODE_UNAUTHORIZED or resp.status_code == 401:
            raise Unauthorized(
                401,
                "unauthorized",
                message,
                decision_id=_proxy_decision_id(resp, data),
                # Only the proxy answers with HTTP 401. A `-32001` inside a 200 answer can be an
                # upstream's own error, so its `data.reason` is not taken as the server's word.
                reason=(_opt_str(data.get("reason")) if resp.status_code == 401 else None)
                or "unauthorized",
                data=data,
            )
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
