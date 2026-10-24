"""Operator API: revoke leases, read and verify the audit log, reload policy, decide
approvals, mint dev roots.

Every route needs the static admin bearer (``[admin] token`` in the server config). Keep that
token out of agents: it can revoke anything and read every decision.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import Any

import httpx

from . import _wire as w
from .capability import CapabilityLike, capabilities_to_json
from .dpop import DpopKey, NonceCache
from .errors import AttenuoError
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


@dataclass(frozen=True)
class AuditFilter:
    """Filters for :meth:`AdminClient.audit_query`. Each is an exact match, never a pattern;
    the ones you set combine with AND.

    ``kind`` is one kind or several (``decision``, ``exchange``, ``root_token``,
    ``lease_renew``, ``lease_revoke``, ``admin``). ``agent`` and ``lease`` match one of the
    record's ``agents`` / ``leases``. ``since`` and ``until`` bound ``at`` to
    ``[since, until)``: RFC 3339 strings or timezone-aware datetimes."""

    kind: str | Sequence[str] | None = None
    decision: str | None = None
    reason: str | None = None
    subject: str | None = None
    agent: str | None = None
    lease: str | None = None
    server: str | None = None
    tool: str | None = None
    chain_id: str | None = None
    since: str | datetime | None = None
    until: str | datetime | None = None


@dataclass(frozen=True)
class AuditPage:
    """One page of :meth:`AdminClient.audit_query`.

    ``next`` is the ``from`` of the following page read oldest first, ``prev`` the ``before``
    of the following page read newest first; each is ``None`` at its end. A filtered page can
    be short, even empty, with a link still set: use :meth:`AdminClient.audit_iter`."""

    entries: list[AuditEntry]
    next: int | None
    prev: int | None
    head: int


@dataclass(frozen=True)
class LeaseState:
    """A lease named in an audit record, as the registry sees it now (``known`` is false when
    the registry does not hold it)."""

    lease_id: str
    known: bool
    active: bool
    parent: str | None
    expires_at: str | None
    revoked_at: str | None
    revoke_reason: str | None


@dataclass(frozen=True)
class AuditEntryDetail:
    """One audit entry with its context (``GET /admin/audit/entries/{seq}`` or
    ``/records/{id}``).

    ``covered_by_checkpoint`` is the oldest stored checkpoint whose signature covers the entry
    (``None`` when the entry is newer than all of them), as stored, unverified.
    ``policy_reloaded_after`` is the seq of the first policy reload after the entry: when set,
    the policy in force now may not be the one that decided."""

    entry: AuditEntry
    lease_states: list[LeaseState]
    covered_by_checkpoint: dict[str, Any] | None
    policy_reloaded_after: int | None


@dataclass(frozen=True)
class CheckpointPage:
    """Stored checkpoints, newest first; ``prev`` is the ``before`` of the next (older) page."""

    checkpoints: list[dict[str, Any]]
    prev: int | None


@dataclass(frozen=True)
class LeaseNode:
    """One lease of a :class:`LeaseTree`. ``agent``, ``issued_at`` and ``issued_seq`` come from
    the audit record that issued it, ``None`` when there is none."""

    lease_id: str
    parent: str | None
    agent: str | None
    active: bool
    expires_at: str
    revoked_at: str | None
    revoke_reason: str | None
    issued_at: str | None
    issued_seq: int | None


@dataclass(frozen=True)
class LeaseTree:
    """What a revoke of the lease would reach, changing nothing.

    ``nodes`` is the lease then its descendants, breadth-first, cut short when ``truncated``.
    ``ancestors`` runs nearest first to ``root``, the chain's first hop. ``would_revoke`` is the
    count a revoke sent now would return (whole subtree, ignoring ``max_nodes``)."""

    root: str
    ancestors: list[LeaseNode]
    nodes: list[LeaseNode]
    would_revoke: int
    truncated: bool


@dataclass(frozen=True)
class PolicySet:
    """The policy set in force. ``sha256`` and ``loaded_at`` describe the text the engine
    loaded; ``path`` and ``sha256`` are ``None`` without a policy file. ``policies`` maps each
    policy id to its text, in the server's order."""

    path: str | None
    sha256: str | None
    loaded_at: str
    policy_ids: list[str]
    warnings: list[str]
    policies: dict[str, str]


@dataclass(frozen=True)
class PolicyCheck:
    """The policy file on disk, linted against the running schema. ``ok`` means a reload would
    succeed; each issue has ``severity``, ``stage``, ``message`` and, when known,
    ``policy_id``, ``line`` and ``column``."""

    path: str
    sha256: str
    loaded_sha256: str | None
    differs_from_loaded: bool
    ok: bool
    error_count: int
    warning_count: int
    issues: list[dict[str, Any]]
    policy_ids: list[str]


@dataclass(frozen=True)
class PolicyEvaluation:
    """A dry-run decision. ``lease_check`` is always ``skipped``; ``chain_source`` is ``token``
    or ``admin_supplied``."""

    decision: str
    reason: str
    policy_ids: list[str]
    diagnostics: list[Any]
    lease_check: str
    chain_source: str
    token_expired: bool

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


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
        raise AttenuoError(f"audit export: line is not JSON: {line[:200]}") from e
    if not isinstance(obj, dict):
        raise AttenuoError(f"audit export: line is not an object: {line[:200]}")
    return obj


def _root_dpop(server_url: str, key: DpopKey | None, nonce: str | None) -> dict[str, str]:
    """The ``DPoP`` header that binds a dev root token to ``key``, with the server's nonce."""
    if key is None:
        return {}
    return {"dpop": key.proof("POST", f"{server_url}/admin/root-token", nonce=nonce)}


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


def _rfc3339(v: str | datetime) -> str:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            raise ValueError("audit filter times must be timezone-aware datetimes")
        return v.isoformat()
    return v


def _audit_params(
    flt: AuditFilter | None,
    order: str,
    from_seq: int | None,
    before: int | None,
    limit: int,
) -> dict[str, Any]:
    params: dict[str, Any] = {"order": order, "limit": limit}
    if from_seq is not None:
        params["from"] = from_seq
    if before is not None:
        params["before"] = before
    if flt is None:
        return params
    for name in ("decision", "reason", "subject", "agent", "lease", "server", "tool", "chain_id"):
        value = getattr(flt, name)
        if value is not None:
            params[name] = value
    if flt.kind is not None:
        params["kind"] = flt.kind if isinstance(flt.kind, str) else ",".join(flt.kind)
    if flt.since is not None:
        params["since"] = _rfc3339(flt.since)
    if flt.until is not None:
        params["until"] = _rfc3339(flt.until)
    return params


def _audit_page(page: Any) -> AuditPage:
    return AuditPage(_entries(page), page.get("next"), page.get("prev"), _head(page))


def _cursor(page: AuditPage, order: str, last: int | None) -> int | None:
    """The link to follow after ``page``: ``prev`` newest first, ``next`` oldest first."""
    cur = page.prev if order == "desc" else page.next
    if cur is not None and cur == last:
        raise AttenuoError(f"audit paging did not advance (cursor {cur})")
    return cur


def _entry_detail(b: Any) -> AuditEntryDetail:
    e = b["entry"]
    return AuditEntryDetail(
        entry=AuditEntry(seq=int(e["seq"]), record=dict(e.get("record") or {}), raw=e),
        lease_states=[
            LeaseState(
                str(s["lease_id"]),
                s.get("known") is True,
                s.get("active") is True,
                s.get("parent"),
                s.get("expires_at"),
                s.get("revoked_at"),
                s.get("revoke_reason"),
            )
            for s in b.get("lease_states") or []
        ],
        covered_by_checkpoint=b.get("covered_by_checkpoint"),
        policy_reloaded_after=b.get("policy_reloaded_after"),
    )


def _checkpoint_params(before: int | None, limit: int | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if before is not None:
        params["before"] = before
    if limit is not None:
        params["limit"] = limit
    return params


def _checkpoint_page(b: Any) -> CheckpointPage:
    return CheckpointPage(list(b.get("checkpoints") or []), b.get("prev"))


def _lease_node(n: Any) -> LeaseNode:
    return LeaseNode(
        str(n["lease_id"]),
        n.get("parent"),
        n.get("agent"),
        n.get("active") is True,
        str(n["expires_at"]),
        n.get("revoked_at"),
        n.get("revoke_reason"),
        n.get("issued_at"),
        n.get("issued_seq"),
    )


def _lease_tree(b: Any) -> LeaseTree:
    return LeaseTree(
        root=str(b["root"]),
        ancestors=[_lease_node(n) for n in b.get("ancestors") or []],
        nodes=[_lease_node(n) for n in b.get("nodes") or []],
        would_revoke=int(b.get("would_revoke", 0)),
        truncated=b.get("truncated") is True,
    )


def _policy_set(b: Any) -> PolicySet:
    return PolicySet(
        path=b.get("path"),
        sha256=b.get("sha256"),
        loaded_at=str(b.get("loaded_at", "")),
        policy_ids=list(b.get("policy_ids") or []),
        warnings=list(b.get("warnings") or []),
        policies={str(p["id"]): str(p["text"]) for p in b.get("policies") or []},
    )


def _policy_check(b: Any) -> PolicyCheck:
    return PolicyCheck(
        path=str(b["path"]),
        sha256=str(b["sha256"]),
        loaded_sha256=b.get("loaded_sha256"),
        differs_from_loaded=b.get("differs_from_loaded") is True,
        ok=b.get("ok") is True,
        error_count=int(b.get("error_count", 0)),
        warning_count=int(b.get("warning_count", 0)),
        issues=list(b.get("issues") or []),
        policy_ids=list(b.get("policy_ids") or []),
    )


def _evaluate_body(
    server: str,
    tool: str,
    arguments: dict[str, Any] | None,
    token: Token | str | None,
    chain: dict[str, Any] | None,
) -> dict[str, Any]:
    if token is None and chain is None:
        raise ValueError("policy_evaluate needs a token or a chain")
    body = w.authzen_body(server, tool, arguments)
    if token is not None:
        body["token"] = w.bearer(token)
    if chain is not None:
        body["subject"]["properties"] = {"chain": chain}
    return body


def _policy_evaluation(b: Any) -> PolicyEvaluation:
    return PolicyEvaluation(
        decision=str(b.get("decision", "")),
        reason=str(b.get("reason", "")),
        policy_ids=list(b.get("policy_ids") or []),
        diagnostics=list(b.get("diagnostics") or []),
        lease_check=str(b.get("lease_check", "")),
        chain_source=str(b.get("chain_source", "")),
        token_expired=b.get("token_expired") is True,
    )


def _approval_params(chain_id: str | None, state: str | None, limit: int | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if chain_id:
        params["chain_id"] = chain_id
    if state:
        params["state"] = state
    if limit is not None:
        params["limit"] = limit
    return params


def _approvals(b: Any) -> list[w.Approval]:
    items = b.get("approvals") if isinstance(b, dict) else None
    return [w.approval_from_json(a) for a in items or []]


def _approval_path(approval_id: str) -> str:
    return f"/admin/approvals/{w.path_segment(approval_id, 'approval_id')}"


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
        self._nonce = NonceCache()

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
        a file and check it offline with :func:`attenuo.audit.verify_export`.

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

    def lease_tree(self, lease_id: str, max_nodes: int | None = None) -> LeaseTree:
        """The lease, its descendants and ancestors, and how many leases a revoke would change
        now. A dry run of :meth:`revoke_lease`: nothing changes, nothing is audited."""
        params = {} if max_nodes is None else {"max_nodes": max_nodes}
        path = f"/admin/leases/{w.path_segment(lease_id, 'lease_id')}/tree"
        return _lease_tree(w.json_body(self._http.get(path, params=params)))

    def audit_query(
        self,
        filter: AuditFilter | None = None,
        *,
        order: str = "asc",
        from_seq: int | None = None,
        before: int | None = None,
        limit: int = 100,
    ) -> AuditPage:
        """One filtered page of ``GET /admin/audit``.

        ``order="asc"`` reads oldest first from ``from_seq``; ``order="desc"`` reads newest
        first, entries with ``seq < before`` (default: from the head). A filtered page can come
        back short or empty with a link still set; :meth:`audit_iter` follows the links."""
        params = _audit_params(filter, order, from_seq, before, limit)
        return _audit_page(w.json_body(self._http.get("/admin/audit", params=params)))

    def audit_iter(
        self,
        filter: AuditFilter | None = None,
        *,
        order: str = "asc",
        from_seq: int | None = None,
        before: int | None = None,
        limit: int = _MAX_PAGE,
    ) -> Iterator[AuditEntry]:
        """Every matching entry, in ``order``, following ``next`` (asc) or ``prev`` (desc)
        until it is null. Pages lazily: stop iterating to stop reading."""
        while True:
            page = self.audit_query(
                filter, order=order, from_seq=from_seq, before=before, limit=limit
            )
            yield from page.entries
            last = before if order == "desc" else from_seq
            cur = _cursor(page, order, last)
            if cur is None:
                return
            if order == "desc":
                before = cur
            else:
                from_seq = cur

    def audit_entry(self, seq: int) -> AuditEntryDetail:
        """The entry at ``seq`` with its context. ``ApiError`` (404) when there is none."""
        return _entry_detail(w.json_body(self._http.get(f"/admin/audit/entries/{int(seq)}")))

    def audit_record(self, record_id: str) -> AuditEntryDetail:
        """The entry whose record id is ``record_id``: the ``decision_id`` a denial or an
        AuthZEN answer carries. ``ApiError`` 400 if it is not a UUID, 404 if unknown."""
        path = f"/admin/audit/records/{w.path_segment(record_id, 'record_id')}"
        return _entry_detail(w.json_body(self._http.get(path)))

    def audit_checkpoints(
        self, before: int | None = None, limit: int | None = None
    ) -> CheckpointPage:
        """Stored checkpoints with ``seq < before``, newest first. Read-only: unlike
        :meth:`audit_checkpoint` it never signs."""
        params = _checkpoint_params(before, limit)
        return _checkpoint_page(
            w.json_body(self._http.get("/admin/audit/checkpoints", params=params))
        )

    def policies(self) -> PolicySet:
        """The policy set in force: file, digest, load time, ids, warnings and texts."""
        return _policy_set(w.json_body(self._http.get("/admin/policies")))

    def policy_check(self) -> PolicyCheck:
        """Lint the policy file as it is on disk now, without loading it. ``ApiError`` (409
        ``check_unavailable``) when the server has no policy file."""
        return _policy_check(w.json_body(self._http.get("/admin/policies/check")))

    def policy_evaluate(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        *,
        token: Token | str | None = None,
        chain: dict[str, Any] | None = None,
    ) -> PolicyEvaluation:
        """Dry run: what the loaded policies decide for this call. No lease check, no audit
        record. Pass a delegation ``token`` (verified by the server; an expired one is accepted
        and flagged ``token_expired``) or a ``chain`` object, checked only structurally."""
        body = _evaluate_body(server, tool, arguments, token, chain)
        return _policy_evaluation(
            w.json_body(self._http.post("/admin/policies/evaluate", json=body))
        )

    def approvals(
        self,
        chain_id: str | None = None,
        *,
        state: str | None = None,
        limit: int | None = None,
    ) -> list[w.Approval]:
        """The newest approvals, newest first: of one delegation run with ``chain_id``, in one
        ``state`` (``pending``, ``granted``, ``declined``, ``consumed``), at most ``limit``
        (server default and maximum 500). An unknown state is an ``ApiError`` (400)."""
        params = _approval_params(chain_id, state, limit)
        return _approvals(w.json_body(self._http.get("/admin/approvals", params=params)))

    def approval(self, approval_id: str) -> w.Approval:
        """One approval: the exact call, the run's labels, state, approver and expiry.
        ``ApiError`` (404) when it is unknown."""
        return w.approval_from_json(w.json_body(self._http.get(_approval_path(approval_id))))

    def grant_approval(self, approval_id: str) -> w.Approval:
        """Grant a pending approval as the operator (``by = "operator"``); returns it. The
        grant is good for one retry of the identical call by the same hop. ``ApiError`` 409
        (``approval_not_pending``, ``approval_expired``, ``lease_revoked``) when it cannot be
        decided any more, 404 when it is unknown."""
        return self._decide(approval_id, "grant")

    def decline_approval(self, approval_id: str) -> w.Approval:
        """Decline a pending approval as the operator; returns it. Errors as
        :meth:`grant_approval`."""
        return self._decide(approval_id, "decline")

    def _decide(self, approval_id: str, decision: str) -> w.Approval:
        path = _approval_path(approval_id)
        return w.approval_from_json(w.json_body(self._http.post(path, json={"decision": decision})))

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
        key = DpopKey.of(dpop_key)
        headers = _root_dpop(self.server_url, key, self._nonce.value)
        resp = self._http.post("/admin/root-token", json=body, headers=headers)
        if key is not None and self._nonce.update(resp):  # use_dpop_nonce: retry once
            headers = _root_dpop(self.server_url, key, self._nonce.value)
            resp = self._http.post("/admin/root-token", json=body, headers=headers)
            self._nonce.update(resp)
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
        self._nonce = NonceCache()

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

    async def lease_tree(self, lease_id: str, max_nodes: int | None = None) -> LeaseTree:
        params = {} if max_nodes is None else {"max_nodes": max_nodes}
        path = f"/admin/leases/{w.path_segment(lease_id, 'lease_id')}/tree"
        return _lease_tree(w.json_body(await self._http.get(path, params=params)))

    async def audit_query(
        self,
        filter: AuditFilter | None = None,
        *,
        order: str = "asc",
        from_seq: int | None = None,
        before: int | None = None,
        limit: int = 100,
    ) -> AuditPage:
        params = _audit_params(filter, order, from_seq, before, limit)
        return _audit_page(w.json_body(await self._http.get("/admin/audit", params=params)))

    async def audit_iter(
        self,
        filter: AuditFilter | None = None,
        *,
        order: str = "asc",
        from_seq: int | None = None,
        before: int | None = None,
        limit: int = _MAX_PAGE,
    ) -> AsyncIterator[AuditEntry]:
        while True:
            page = await self.audit_query(
                filter, order=order, from_seq=from_seq, before=before, limit=limit
            )
            for entry in page.entries:
                yield entry
            last = before if order == "desc" else from_seq
            cur = _cursor(page, order, last)
            if cur is None:
                return
            if order == "desc":
                before = cur
            else:
                from_seq = cur

    async def audit_entry(self, seq: int) -> AuditEntryDetail:
        return _entry_detail(w.json_body(await self._http.get(f"/admin/audit/entries/{int(seq)}")))

    async def audit_record(self, record_id: str) -> AuditEntryDetail:
        path = f"/admin/audit/records/{w.path_segment(record_id, 'record_id')}"
        return _entry_detail(w.json_body(await self._http.get(path)))

    async def audit_checkpoints(
        self, before: int | None = None, limit: int | None = None
    ) -> CheckpointPage:
        params = _checkpoint_params(before, limit)
        return _checkpoint_page(
            w.json_body(await self._http.get("/admin/audit/checkpoints", params=params))
        )

    async def policies(self) -> PolicySet:
        return _policy_set(w.json_body(await self._http.get("/admin/policies")))

    async def policy_check(self) -> PolicyCheck:
        return _policy_check(w.json_body(await self._http.get("/admin/policies/check")))

    async def policy_evaluate(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None = None,
        *,
        token: Token | str | None = None,
        chain: dict[str, Any] | None = None,
    ) -> PolicyEvaluation:
        body = _evaluate_body(server, tool, arguments, token, chain)
        return _policy_evaluation(
            w.json_body(await self._http.post("/admin/policies/evaluate", json=body))
        )

    async def approvals(
        self,
        chain_id: str | None = None,
        *,
        state: str | None = None,
        limit: int | None = None,
    ) -> list[w.Approval]:
        params = _approval_params(chain_id, state, limit)
        return _approvals(w.json_body(await self._http.get("/admin/approvals", params=params)))

    async def approval(self, approval_id: str) -> w.Approval:
        return w.approval_from_json(w.json_body(await self._http.get(_approval_path(approval_id))))

    async def grant_approval(self, approval_id: str) -> w.Approval:
        return await self._decide(approval_id, "grant")

    async def decline_approval(self, approval_id: str) -> w.Approval:
        return await self._decide(approval_id, "decline")

    async def _decide(self, approval_id: str, decision: str) -> w.Approval:
        path = _approval_path(approval_id)
        return w.approval_from_json(
            w.json_body(await self._http.post(path, json={"decision": decision}))
        )

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
        key = DpopKey.of(dpop_key)
        headers = _root_dpop(self.server_url, key, self._nonce.value)
        resp = await self._http.post("/admin/root-token", json=body, headers=headers)
        if key is not None and self._nonce.update(resp):  # use_dpop_nonce: retry once
            headers = _root_dpop(self.server_url, key, self._nonce.value)
            resp = await self._http.post("/admin/root-token", json=body, headers=headers)
            self._nonce.update(resp)
        return w.token_from_response(w.json_body(resp))
