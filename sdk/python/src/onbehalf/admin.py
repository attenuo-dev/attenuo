"""Operator API: revoke leases, read and verify the audit log, reload policy, mint dev roots.

Every route needs the static admin bearer (``[admin] token`` in the server config). Keep that
token out of agents: it can revoke anything and read every decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

import httpx

from . import _wire as w
from .capability import CapabilityLike, capabilities_to_json
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


def _root_body(
    subject: str,
    issuer: str,
    agent: str,
    capabilities: Any,
    ttl_seconds: int | None,
    attributes: dict[str, Any] | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"subject": subject, "issuer": issuer, "agent": agent}
    if capabilities is not None:
        body["capabilities"] = capabilities_to_json(capabilities)
    if ttl_seconds is not None:
        body["ttl_seconds"] = int(ttl_seconds)
    if attributes:
        body["attributes"] = attributes
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

    def audit_tail(self, n: int = 20) -> list[AuditEntry]:
        """The last ``n`` audit entries, oldest first."""
        head = w.json_body(self._http.get("/admin/audit/checkpoint")).get("seq") or 0
        start = max(1, head + 1 - n)
        out: list[AuditEntry] = []
        while True:
            page, nxt = self.audit(start, _MAX_PAGE)
            out.extend(page)
            if nxt is None:
                return out
            start = nxt

    def audit_checkpoint(self) -> dict[str, Any]:
        """``{seq, hash}`` of the log head."""
        body = w.json_body(self._http.get("/admin/audit/checkpoint"))
        return body if isinstance(body, dict) else {}

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
    ) -> Token:
        """**Development only.** Mint a root token for an asserted, unverified user."""
        body = _root_body(subject, issuer, agent, capabilities, ttl_seconds, attributes)
        return w.token_from_response(w.json_body(self._http.post("/admin/root-token", json=body)))


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

    async def audit_tail(self, n: int = 20) -> list[AuditEntry]:
        head = w.json_body(await self._http.get("/admin/audit/checkpoint")).get("seq") or 0
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
    ) -> Token:
        body = _root_body(subject, issuer, agent, capabilities, ttl_seconds, attributes)
        resp = await self._http.post("/admin/root-token", json=body)
        return w.token_from_response(w.json_body(resp))
