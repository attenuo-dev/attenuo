"""Operator API: revoke leases, read and verify the audit log, reload policy, mint dev roots.

Every route needs the static admin bearer (``[admin] token`` in the server config). Keep that
token out of agents: it can revoke anything and read every decision.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable, Iterator
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

import httpx

from . import _wire as w
from .capability import CapabilityLike, capabilities_to_json
from .dpop import DpopKey
from .errors import OnbehalfError
from .token import Token

_MAX_PAGE = 1000


@dataclass(frozen=True)
class RevokeResult:
    lease_id: str
    revoked: int
    reason: str


@dataclass(frozen=True)
class LeaseStatus:
    lease_id: str
    active: bool
    parent: str | None
    expires_at: str
    revoked_at: str | None
    revoke_reason: str | None


@dataclass(frozen=True)
class AuditEntry:
    """One row of the hash-chained audit log; ``record`` is the decision record."""

    seq: int
    record: dict[str, Any]
    raw: dict[str, Any] = field(repr=False)

    @property
    def id(self) -> str | None:
        return self.record.get("id")

    @property
    def decision(self) -> str | None:
        return self.record.get("decision")

    @property
    def reason(self) -> str | None:
        return self.record.get("reason")

    @property
    def tool(self) -> str | None:
        return self.record.get("tool")

    @property
    def server(self) -> str | None:
        return self.record.get("server")

    @property
    def kind(self) -> str | None:
        """``decision``, ``exchange``, ``root_token``, ``lease_renew``, ``lease_revoke`` or
        ``admin``."""
        return self.record.get("kind")

    @property
    def chain_id(self) -> str | None:
        """The lease id of the delegation chain's first hop (``None`` for admin records)."""
        return self.record.get("chain_id")

    @property
    def dpop_bound(self) -> bool:
        """The request proved possession of the key its token is bound to (DPoP); for an
        issuance, the new token is bound."""
        return bool(self.record.get("dpop_bound", False))


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    entries: int
    first_bad_seq: int | None


@dataclass(frozen=True)
class PolicyReload:
    policy_ids: list[str]
    warnings: list[str]


def _entries(page: Any) -> list[AuditEntry]:
    return [
        AuditEntry(seq=int(e["seq"]), record=dict(e.get("record") or {}), raw=e)
        for e in page.get("entries", [])
    ]


def _head(page: Any) -> int:
    head = page.get("head") if isinstance(page, dict) else None
    return head if isinstance(head, int) and not isinstance(head, bool) and head >= 0 else 0


def _export_params(
    from_seq: int, to_seq: int | None, kind: str | None, chain_id: str | None
) -> dict[str, Any]:
    params: dict[str, Any] = {"from": from_seq}
    if to_seq is not None:
        params["to"] = to_seq
    if kind is not None:
        params["kind"] = kind
    if chain_id is not None:
        params["chain_id"] = chain_id
    return params


def _export_line(line: str) -> dict[str, Any]:
    try:
        obj = json.loads(line)
    except ValueError as e:
        raise OnbehalfError(f"audit export: line is not JSON: {line[:200]}") from e
    if not isinstance(obj, dict):
        raise OnbehalfError(f"audit export: line is not an object: {line[:200]}")
    return obj


def _root_dpop(server_url: str, dpop_key: DpopKey | dict[str, Any] | None) -> dict[str, str]:
    """The ``DPoP`` header that binds a dev root token to ``dpop_key``."""
    key = DpopKey.of(dpop_key)
    if key is None:
        return {}
    return {"dpop": key.proof("POST", f"{server_url}/admin/root-token")}


def _root_body(
    subject: str,
    issuer: str,
    agent: str,
    capabilities: Any,
    ttl_seconds: int | None,
    attributes: dict[str, Any] | None,
    may_act: Iterable[str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"subject": subject, "issuer": issuer, "agent": agent}
    if capabilities is not None:
        body["capabilities"] = capabilities_to_json(capabilities)
    if ttl_seconds is not None:
        body["ttl_seconds"] = int(ttl_seconds)
    if attributes:
        body["attributes"] = attributes
    if may_act is not None:
        body["may_act"] = w.may_act_json(may_act)
    return body


def _verify_report(body: dict[str, Any]) -> VerifyReport:
    return VerifyReport(
        ok=body.get("ok") is True,
        entries=int(body.get("entries", 0)),
        first_bad_seq=body.get("first_bad_seq"),
    )


class AdminClient:
    """Operator client. ``mint_root_dev`` needs ``[dev] allow_root_mint = true`` on the server."""

    def __init__(
        self,
        server_url: str,
        admin_token: str,
        timeout: float | httpx.Timeout | None = 30.0,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.server_url = w.normalize_base(server_url)
        self._http = httpx.Client(
            base_url=self.server_url,
            timeout=timeout,
            transport=transport,
            headers={"authorization": f"Bearer {admin_token}"},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> AdminClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def revoke_lease(self, lease_id: str, reason: str | None = None) -> RevokeResult:
        """Revoke a lease and, by cascade, every lease delegated from it."""
        body = w.json_body(
            self._http.post(
                f"/admin/leases/{w.path_segment(lease_id, 'lease_id')}/revoke",
                json={"reason": reason} if reason else {},
            )
        )
        return RevokeResult(body["lease_id"], int(body["revoked"]), str(body["reason"]))

    def lease_status(self, lease_id: str) -> LeaseStatus:
        b = w.json_body(self._http.get(f"/admin/leases/{w.path_segment(lease_id, 'lease_id')}"))
        return LeaseStatus(
            b["lease_id"],
            b["active"] is True,
            b.get("parent"),
            b["expires_at"],
            b.get("revoked_at"),
            b.get("revoke_reason"),
        )

    def audit(self, from_seq: int = 1, limit: int = 100) -> tuple[list[AuditEntry], int | None]:
        """One page of entries from ``from_seq``, and the ``from`` for the next page (or None)."""
        page = w.json_body(
            self._http.get("/admin/audit", params={"from": from_seq, "limit": limit})
        )
        return _entries(page), page.get("next")

    def audit_head(self) -> int:
        """The newest audit ``seq`` (0 for an empty log). Reads ``head`` from
        ``GET /admin/audit``; unlike :meth:`audit_checkpoint` it signs nothing."""
        return _head(w.json_body(self._http.get("/admin/audit", params={"from": 1, "limit": 1})))

    def audit_tail(self, n: int = 20) -> list[AuditEntry]:
        """The last ``n`` audit entries, oldest first."""
        head = self.audit_head()
        start = max(1, head + 1 - n)
        out: list[AuditEntry] = []
        while True:
            page, nxt = self.audit(start, _MAX_PAGE)
            out.extend(page)
            if nxt is None:
                return out
            start = nxt

    def audit_checkpoint(self) -> dict[str, Any]:
        """The signed checkpoint of the log head (``seq``, ``head_hash``, ``hash``, ``at``,
        ``kid``, ``signature``). Every call may create and store a signed checkpoint; use
        :meth:`audit_head` to just read the head."""
        body = w.json_body(self._http.get("/admin/audit/checkpoint"))
        return body if isinstance(body, dict) else {}

    def audit_export(
        self,
        from_seq: int = 1,
        to_seq: int | None = None,
        *,
        kind: str | None = None,
        chain_id: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Stream ``GET /admin/audit/export`` as parsed JSON Lines objects: a ``header``, then
        ``entry`` and ``checkpoint`` objects, each tagged with ``type``. Write the raw lines to
        a file and check it offline with :func:`onbehalf.audit.verify_export`.

        ``kind`` (``decision``, ``exchange``, ``root_token``, ``lease_renew``, ``lease_revoke``,
        ``admin``) and ``chain_id`` keep only matching entries. The header then carries a
        ``filter`` and the file cannot be verified (its chain has gaps): verify an unfiltered
        export, then filter."""
        params = _export_params(from_seq, to_seq, kind, chain_id)
        with self._http.stream("GET", "/admin/audit/export", params=params) as resp:
            if not resp.is_success:
                resp.read()
                raise w.error_from_response(resp)
            for line in resp.iter_lines():
                if line.strip():
                    yield _export_line(line)

    def audit_verify(self) -> VerifyReport:
        """Walk the whole hash chain. ``ok`` is false (not an exception) if it is broken."""
        return _verify_report(w.json_body(self._http.get("/admin/audit/verify")))

    def policy_reload(self) -> PolicyReload:
        """Re-read the policy file. A policy that does not validate raises ``ApiError`` (422)
        and the old set stays in force."""
        b = w.json_body(self._http.post("/admin/policies/reload", json={}))
        return PolicyReload(list(b.get("policy_ids") or []), list(b.get("warnings") or []))

    def mint_root_dev(
        self,
        subject: str,
        issuer: str,
        agent: str,
        capabilities: list[CapabilityLike] | CapabilityLike | None = None,
        ttl_seconds: int | None = None,
        attributes: dict[str, Any] | None = None,
        *,
        may_act: Iterable[str] | None = None,
        dpop_key: DpopKey | dict[str, Any] | None = None,
    ) -> Token:
        """**Development only.** Mint a root token for an asserted, unverified user.

        ``may_act`` lists the agents allowed to exchange the root token next (RFC 8693 §4.4); it
        must be within the ``[[root_grants]]`` entry's ``may_act`` when that has one.
        ``dpop_key`` binds the root token to that key (DPoP, RFC 9449).
        """
        body = _root_body(subject, issuer, agent, capabilities, ttl_seconds, attributes, may_act)
        headers = _root_dpop(self.server_url, dpop_key)
        resp = self._http.post("/admin/root-token", json=body, headers=headers)
        return w.token_from_response(w.json_body(resp))


class AsyncAdminClient:
    """The :class:`AdminClient` API for ``asyncio``."""

    def __init__(
        self,
        server_url: str,
        admin_token: str,
        timeout: float | httpx.Timeout | None = 30.0,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.server_url = w.normalize_base(server_url)
        self._http = httpx.AsyncClient(
            base_url=self.server_url,
            timeout=timeout,
            transport=transport,
            headers={"authorization": f"Bearer {admin_token}"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncAdminClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def revoke_lease(self, lease_id: str, reason: str | None = None) -> RevokeResult:
        body = w.json_body(
            await self._http.post(
                f"/admin/leases/{w.path_segment(lease_id, 'lease_id')}/revoke",
                json={"reason": reason} if reason else {},
            )
        )
        return RevokeResult(body["lease_id"], int(body["revoked"]), str(body["reason"]))

    async def lease_status(self, lease_id: str) -> LeaseStatus:
        b = w.json_body(
            await self._http.get(f"/admin/leases/{w.path_segment(lease_id, 'lease_id')}")
        )
        return LeaseStatus(
            b["lease_id"],
            b["active"] is True,
            b.get("parent"),
            b["expires_at"],
            b.get("revoked_at"),
            b.get("revoke_reason"),
        )

    async def audit(
        self, from_seq: int = 1, limit: int = 100
    ) -> tuple[list[AuditEntry], int | None]:
        page = w.json_body(
            await self._http.get("/admin/audit", params={"from": from_seq, "limit": limit})
        )
        return _entries(page), page.get("next")

    async def audit_head(self) -> int:
        return _head(
            w.json_body(await self._http.get("/admin/audit", params={"from": 1, "limit": 1}))
        )

    async def audit_tail(self, n: int = 20) -> list[AuditEntry]:
        head = await self.audit_head()
        start = max(1, head + 1 - n)
        out: list[AuditEntry] = []
        while True:
            page, nxt = await self.audit(start, _MAX_PAGE)
            out.extend(page)
            if nxt is None:
                return out
            start = nxt

    async def audit_checkpoint(self) -> dict[str, Any]:
        body = w.json_body(await self._http.get("/admin/audit/checkpoint"))
        return body if isinstance(body, dict) else {}

    async def audit_export(
        self,
        from_seq: int = 1,
        to_seq: int | None = None,
        *,
        kind: str | None = None,
        chain_id: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        params = _export_params(from_seq, to_seq, kind, chain_id)
        async with self._http.stream("GET", "/admin/audit/export", params=params) as resp:
            if not resp.is_success:
                await resp.aread()
                raise w.error_from_response(resp)
            async for line in resp.aiter_lines():
                if line.strip():
                    yield _export_line(line)

    async def audit_verify(self) -> VerifyReport:
        return _verify_report(w.json_body(await self._http.get("/admin/audit/verify")))

    async def policy_reload(self) -> PolicyReload:
        b = w.json_body(await self._http.post("/admin/policies/reload", json={}))
        return PolicyReload(list(b.get("policy_ids") or []), list(b.get("warnings") or []))

    async def mint_root_dev(
        self,
        subject: str,
        issuer: str,
        agent: str,
        capabilities: list[CapabilityLike] | CapabilityLike | None = None,
        ttl_seconds: int | None = None,
        attributes: dict[str, Any] | None = None,
        *,
        may_act: Iterable[str] | None = None,
        dpop_key: DpopKey | dict[str, Any] | None = None,
    ) -> Token:
        body = _root_body(subject, issuer, agent, capabilities, ttl_seconds, attributes, may_act)
        headers = _root_dpop(self.server_url, dpop_key)
        resp = await self._http.post("/admin/root-token", json=body, headers=headers)
        return w.token_from_response(w.json_body(resp))
