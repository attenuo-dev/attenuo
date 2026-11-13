"""Operator API: revoke leases, refund a decision's budget charge, read and verify the audit
log, reload policy, decide approvals, mint dev roots.

Every route needs the static admin bearer (``[admin] token`` in the server config). Keep that
token out of agents: it can revoke anything and read every decision.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import Any, Literal

import httpx

from . import _wire as w
from ._http import AsyncHttpClient, HttpClient
from .capability import CapabilityLike, capabilities_to_json
from .dpop import DpopKey, NonceCache
from .errors import AttenuoError, budget_limit_from_json
from .errors import BudgetLimit as BudgetLimit
from .errors import LimitKind as LimitKind
from .token import Token

_MAX_PAGE = 1000


@dataclass(frozen=True)
class RevokeResult:
    """The answer of :meth:`AdminClient.revoke_lease`. ``audit_id`` is the id of the
    ``admin.lease.revoke`` record, ``None`` when the server could not write it (the revocation
    stands)."""

    lease_id: str
    revoked: int
    reason: str
    audit_id: str | None = None


@dataclass(frozen=True)
class BudgetRefund:
    """The answer of :meth:`AdminClient.refund_budget` (``POST /admin/budgets/refund``).

    ``refunded`` counts the token-limit counters credited. The run usage and per-user windows
    the decision charged are given back too but not counted, so a decision that charged only
    usage answers 0. ``audit_id`` is the id of the ``admin.budget.refund`` record, ``None``
    when the server could not write it (the refund stands)."""

    decision_id: str
    refunded: int
    reason: str
    audit_id: str | None = None


@dataclass(frozen=True)
class SelectorRevocation:
    """The answer of :meth:`AdminClient.revoke_by_selector` (``POST /admin/leases/revoke``).

    ``selector`` is how the server shows the selector: ``{"user": ...}``, ``{"chain_id": ...}``
    or, for a session, ``{"session_tag": "<12 hex>", "chain_ids": [...]}``, never the raw
    session id. ``matched`` holds the unrevoked leases the selector named and ``revoked`` every
    lease that changed (the matches, then the cascade), each in id order and cut at 10,000 ids
    (``truncated``); the counts are always complete. On a preview ``revoked`` is what a
    revocation sent now would change, and ``reason`` and ``audit_id`` are ``None``.
    ``audit_id`` is also ``None`` when the server could not write the record (the revocation
    stands)."""

    selector: dict[str, Any]
    preview: bool
    matched: list[str]
    revoked: list[str]
    matched_count: int
    revoked_count: int
    truncated: bool
    reason: str | None
    audit_id: str | None


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

    ``next_cursor`` fetches the following page in the same ``order`` (pass it back as
    ``cursor`` with the same filter and range); ``None`` once the range has been read. It is
    opaque. A filtered page can be short, even empty, with ``next_cursor`` still set: use
    :meth:`AdminClient.audit_iter`, which follows it."""

    entries: list[AuditEntry]
    next_cursor: str | None
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
    """Stored checkpoints, newest first; ``next_cursor`` fetches the next (older) page, ``None``
    after the oldest."""

    checkpoints: list[dict[str, Any]]
    next_cursor: str | None


@dataclass(frozen=True)
class ApprovalPage:
    """One page of :meth:`AdminClient.approvals`, newest first; ``next_cursor`` fetches the
    next (older) page with the same filters, ``None`` after the last."""

    approvals: list[w.Approval]
    next_cursor: str | None


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
    #: The hop's run limits and what is left (``{"recorded", "limits", "usage"}``, see the
    #: admin API reference), ``None`` when it has no limits and nothing was charged under it.
    budget: dict[str, Any] | None = None


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
class StatedBudget:
    """The run-limit state a dry run decides the call in, instead of the store's counters (the
    ``budget`` block of ``POST /admin/policies/evaluate``, in the vocabulary of a
    ``policy test`` case's ``budget``). Members left ``None`` are not sent.

    ``calls_remaining`` / ``amount_remaining``: what every matching ``calls`` / ``sum`` limit
    has left. ``destination_new=False``: the call's value was already counted by each matching
    ``calls_per`` and ``distinct`` limit. ``limited``: ``context.budget.limited`` when no limit
    of the chain matches the call (server default ``True``). ``limits``: at most 64 single
    counters over those figures. The server checks everything and answers 400
    ``invalid_request`` for a malformed block or an entry that names no matching limit."""

    calls_remaining: int | None = None
    amount_remaining: int | None = None
    destination_new: bool | None = None
    limited: bool | None = None
    limits: Sequence[BudgetLimit] = ()

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in ("calls_remaining", "amount_remaining", "destination_new", "limited"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        if self.limits:
            out["limits"] = [lim.to_json() for lim in self.limits]
        return out


@dataclass(frozen=True)
class StatedSession:
    """The run's output labels a dry run decides the call with, instead of the store's (the
    ``session`` block of ``POST /admin/policies/evaluate``, ADR-0009). Members left ``None``
    or empty are not sent.

    ``tainted_by``: the ``<server>/<tool>`` sources the run has read untrusted output from.
    ``tainted``: ``context.session.tainted`` (server default: whether ``tainted_by`` is
    non-empty; ``True`` alone taints the run with no named source). ``untrusted_args``: the
    call's arguments that carry a span of untrusted output. ``args_contain_untrusted``:
    ``context.args_contain_untrusted`` (server default: whether ``untrusted_args`` is
    non-empty). The answer's ``labels.source`` is then ``request``. The server answers 400
    ``invalid_request`` for a malformed block."""

    tainted_by: Sequence[str] = ()
    tainted: bool | None = None
    untrusted_args: Sequence[str] = ()
    args_contain_untrusted: bool | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.tainted_by:
            out["tainted_by"] = list(self.tainted_by)
        if self.tainted is not None:
            out["tainted"] = self.tainted
        if self.untrusted_args:
            out["untrusted_args"] = list(self.untrusted_args)
        if self.args_contain_untrusted is not None:
            out["args_contain_untrusted"] = self.args_contain_untrusted
        return out


ApprovalBy = Literal["user", "operator", "policy"]


@dataclass(frozen=True)
class StatedApproval:
    """Evaluate the call as a retry that carries a granted approval (the ``approval`` block of
    ``POST /admin/policies/evaluate``): ``context.approval.present`` is true and
    ``context.approval.by`` is ``by``. The dry run never looks up or consumes a stored
    approval, so no approval id or token is taken. The answer's ``approval_by`` is then
    ``by``."""

    by: ApprovalBy

    def to_json(self) -> dict[str, Any]:
        return {"by": self.by}


@dataclass(frozen=True)
class StatedUsage:
    """The run usage a dry run decides the call with (``context.usage``, the ``usage`` block
    of ``POST /admin/policies/evaluate``), instead of the store's. Members left ``None`` are
    not sent; the server takes them as 0 or ``False``. The answer's ``usage.source`` is then
    ``request``. The server answers 400 ``invalid_request`` for a negative or non-integer
    figure."""

    calls: int | None = None
    amount: int | None = None
    destination_seen: bool | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in ("calls", "amount", "destination_seen"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out


@dataclass(frozen=True)
class EvaluationBudget:
    """``context.budget`` of a dry run: what the run limits matching the call have left.

    ``calls_remaining`` and ``amount_remaining`` are ``2**63 - 1`` when no limit of that kind
    matches. ``source`` is ``store`` (the run's counters as they stand, read and never
    charged) or ``request`` (as the request's ``budget`` stated them)."""

    limited: bool
    calls_remaining: int
    amount_remaining: int
    destination_new: bool
    source: str


@dataclass(frozen=True)
class EvaluationLabels:
    """The run's output labels the dry run decided with (ADR-0009); ``source`` is ``store``
    or ``request``."""

    tainted: bool
    tainted_by: list[str]
    args_contain_untrusted: bool
    untrusted_args: list[str]
    source: str


@dataclass(frozen=True)
class EvaluationUsage:
    """``context.usage`` of a dry run; ``source`` is ``request``, ``store`` or ``untracked``
    (the server keeps no run usage, so the zeros are not a reading of the run)."""

    calls: int
    amount: int
    destination_seen: bool
    source: str


@dataclass(frozen=True)
class PolicyEvaluation:
    """A dry-run decision. ``lease_check`` is always ``skipped``; ``chain_source`` is ``token``
    or ``admin_supplied``. ``limit`` is set when the call would take a run limit past its
    ``max`` (reason ``budget_exhausted``). ``budget``, ``labels`` and ``usage`` are ``None``
    only for a server that does not send them. ``approval_by`` is the ``by`` of the granted
    approval the call was evaluated with, ``None`` without one."""

    decision: str
    reason: str
    policy_ids: list[str]
    diagnostics: list[Any]
    lease_check: str
    chain_source: str
    token_expired: bool
    budget: EvaluationBudget | None = None
    limit: BudgetLimit | None = None
    labels: EvaluationLabels | None = None
    usage: EvaluationUsage | None = None
    approval_by: str | None = None

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
    from_seq: int,
    to_seq: int | None,
    kind: str | None,
    chain_id: str | None,
    tool: str | None = None,
    decision: str | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {"from": from_seq}
    if to_seq is not None:
        params["to"] = to_seq
    for name, value in (("kind", kind), ("chain_id", chain_id), ("tool", tool)):
        if value is not None:
            params[name] = value
    if decision is not None:
        params["decision"] = decision
    return params


def _selector_request(
    user: str | None,
    chain_id: str | None,
    session: str | None,
    reason: str | None,
    preview: bool,
) -> tuple[dict[str, Any], dict[str, str]]:
    """The body and query of ``POST /admin/leases/revoke``. ``ValueError`` unless exactly one
    selector is given and it is not empty. No message names a value: ``session`` is a secret
    that grants use of the MCP session."""
    given = {"user": user, "chain_id": chain_id, "session": session}
    named = [k for k, v in given.items() if v is not None]
    if len(named) != 1:
        raise ValueError("give exactly one of `user`, `chain_id`, `session`")
    if not given[named[0]]:
        raise ValueError(f"`{named[0]}` must not be empty")
    body: dict[str, Any] = {named[0]: given[named[0]]}
    if reason is not None:
        body["reason"] = reason
    return body, ({"preview": "true"} if preview else {})


def _selector_revocation(b: Any) -> SelectorRevocation:
    audit_id = b.get("audit_id")
    reason = b.get("reason")
    return SelectorRevocation(
        selector=dict(b.get("selector") or {}),
        preview=b.get("preview") is True,
        matched=[str(x) for x in b.get("matched") or []],
        revoked=[str(x) for x in b.get("revoked") or []],
        matched_count=int(b.get("matched_count", 0)),
        revoked_count=int(b.get("revoked_count", 0)),
        truncated=b.get("truncated") is True,
        reason=None if reason is None else str(reason),
        audit_id=None if audit_id is None else str(audit_id),
    )


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
    to_seq: int | None,
    cursor: str | None,
    limit: int,
) -> dict[str, Any]:
    params: dict[str, Any] = {"order": order, "limit": limit}
    if from_seq is not None:
        params["from"] = from_seq
    if to_seq is not None:
        params["to"] = to_seq
    if cursor is not None:
        params["cursor"] = cursor
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
    return AuditPage(_entries(page), _next_cursor(page), _head(page))


def _next_cursor(page: Any) -> str | None:
    cur = page.get("next_cursor") if isinstance(page, dict) else None
    return cur if isinstance(cur, str) else None


def _advance(cur: str | None, last: str | None) -> str | None:
    """``cur`` to follow next, refusing a cursor that repeats the one just sent (which would
    page forever)."""
    if cur is not None and cur == last:
        raise AttenuoError("paging did not advance (the server sent the same cursor again)")
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


def _checkpoint_params(cursor: str | None, limit: int | None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if cursor is not None:
        params["cursor"] = cursor
    if limit is not None:
        params["limit"] = limit
    return params


def _checkpoint_page(b: Any) -> CheckpointPage:
    return CheckpointPage(list(b.get("checkpoints") or []), _next_cursor(b))


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
        n.get("budget") if isinstance(n.get("budget"), dict) else None,
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
    budget: StatedBudget | dict[str, Any] | None = None,
    session: StatedSession | dict[str, Any] | None = None,
    approval: StatedApproval | dict[str, Any] | None = None,
    usage: StatedUsage | dict[str, Any] | None = None,
) -> dict[str, Any]:
    if token is None and chain is None:
        raise ValueError("policy_evaluate needs a token or a chain")
    body = w.authzen_body(server, tool, arguments)
    if token is not None:
        body["token"] = w.bearer(token)
    if chain is not None:
        body["subject"]["properties"] = {"chain": chain}
    if budget is not None:
        body["budget"] = budget.to_json() if isinstance(budget, StatedBudget) else dict(budget)
    if session is not None:
        body["session"] = session.to_json() if isinstance(session, StatedSession) else dict(session)
    if approval is not None:
        body["approval"] = (
            approval.to_json() if isinstance(approval, StatedApproval) else dict(approval)
        )
    if usage is not None:
        body["usage"] = usage.to_json() if isinstance(usage, StatedUsage) else dict(usage)
    return body


def _int(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _evaluation_budget(v: Any) -> EvaluationBudget | None:
    if not isinstance(v, dict):
        return None
    return EvaluationBudget(
        limited=v.get("limited") is True,
        calls_remaining=_int(v.get("calls_remaining")),
        amount_remaining=_int(v.get("amount_remaining")),
        destination_new=v.get("destination_new") is True,
        source=str(v.get("source", "")),
    )


def _evaluation_labels(v: Any) -> EvaluationLabels | None:
    if not isinstance(v, dict):
        return None
    return EvaluationLabels(
        tainted=v.get("tainted") is True,
        tainted_by=[str(x) for x in v.get("tainted_by") or []],
        args_contain_untrusted=v.get("args_contain_untrusted") is True,
        untrusted_args=[str(x) for x in v.get("untrusted_args") or []],
        source=str(v.get("source", "")),
    )


def _evaluation_usage(v: Any) -> EvaluationUsage | None:
    if not isinstance(v, dict):
        return None
    return EvaluationUsage(
        calls=_int(v.get("calls")),
        amount=_int(v.get("amount")),
        destination_seen=v.get("destination_seen") is True,
        source=str(v.get("source", "")),
    )


def _policy_evaluation(b: Any) -> PolicyEvaluation:
    approval = b.get("approval")
    present = isinstance(approval, dict) and approval.get("present") is True
    return PolicyEvaluation(
        decision=str(b.get("decision", "")),
        reason=str(b.get("reason", "")),
        policy_ids=list(b.get("policy_ids") or []),
        diagnostics=list(b.get("diagnostics") or []),
        lease_check=str(b.get("lease_check", "")),
        chain_source=str(b.get("chain_source", "")),
        token_expired=b.get("token_expired") is True,
        budget=_evaluation_budget(b.get("budget")),
        limit=budget_limit_from_json(b.get("limit")),
        labels=_evaluation_labels(b.get("session")),
        usage=_evaluation_usage(b.get("usage")),
        approval_by=str(approval.get("by", "")) if present else None,
    )


def _revoke_result(b: Any) -> RevokeResult:
    audit_id = b.get("audit_id")
    return RevokeResult(
        b["lease_id"],
        int(b["revoked"]),
        str(b["reason"]),
        None if audit_id is None else str(audit_id),
    )


def _approval_params(
    chain_id: str | None, state: str | None, limit: int | None, cursor: str | None
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if cursor is not None:
        params["cursor"] = cursor
    if chain_id:
        params["chain_id"] = chain_id
    if state:
        params["state"] = state
    if limit is not None:
        params["limit"] = limit
    return params


def _approvals(b: Any) -> ApprovalPage:
    items = b.get("approvals") if isinstance(b, dict) else None
    return ApprovalPage([w.approval_from_json(a) for a in items or []], _next_cursor(b))


def _refund_body(decision_id: str, reason: str | None) -> dict[str, Any]:
    if not isinstance(decision_id, str) or not decision_id.strip():
        raise ValueError("decision_id must be the id of an allowed decision")
    body: dict[str, Any] = {"decision_id": decision_id.strip()}
    if reason is not None:
        body["reason"] = reason
    return body


def _budget_refund(b: Any) -> BudgetRefund:
    if not isinstance(b, dict):
        raise AttenuoError(f"unexpected refund response: {str(b)[:200]}")
    audit_id = b.get("audit_id")
    refunded = b.get("refunded")
    return BudgetRefund(
        decision_id=str(b.get("decision_id", "")),
        refunded=refunded if isinstance(refunded, int) and not isinstance(refunded, bool) else 0,
        reason=str(b.get("reason", "")),
        audit_id=None if audit_id is None else str(audit_id),
    )


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
        self._http = HttpClient(
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
        return _revoke_result(body)

    def revoke_by_selector(
        self,
        *,
        user: str | None = None,
        chain_id: str | None = None,
        session: str | None = None,
        reason: str | None = None,
        preview: bool = False,
    ) -> SelectorRevocation:
        """``POST /admin/leases/revoke``: revoke every unrevoked lease of one originating
        ``user`` (the ``sub``, any issuer), one delegation chain (``chain_id``, the first hop's
        lease id) or the chain that opened one MCP ``session`` (the raw ``Mcp-Session-Id``),
        each with its descendants, in one transaction. Give exactly one (``ValueError``
        otherwise). Matching nothing is not an error: the lists come back empty.

        ``preview=True`` changes nothing and writes no audit record: the answer says what a
        revocation sent now would revoke. The SDK never logs or echoes ``session``; the answer
        shows only its tag and the chains it resolved to."""
        body, params = _selector_request(user, chain_id, session, reason, preview)
        resp = self._http.post("/admin/leases/revoke", json=body, params=params)
        return _selector_revocation(w.json_body(resp))

    def refund_budget(self, decision_id: str, reason: str | None = None) -> BudgetRefund:
        """``POST /admin/budgets/refund``: give back what the allowed decision ``decision_id``
        charged to its run's limits, once, for a call whose effect did not happen. The server
        writes an ``admin.budget.refund`` record (``reason`` defaults to ``refunded by
        admin``).

        A refund that cannot be made is an :class:`~attenuo.ApiError`: 409
        ``already_refunded``, 410 ``charge_pruned`` (the charge is older than the server
        keeps), 404 ``not_found`` (an unknown id, or a decision that charged nothing). Its
        ``detail`` says which, from the decision's audit record."""
        body = _refund_body(decision_id, reason)
        return _budget_refund(w.json_body(self._http.post("/admin/budgets/refund", json=body)))

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

    def audit(
        self, from_seq: int = 1, limit: int = 100, *, cursor: str | None = None
    ) -> tuple[list[AuditEntry], str | None]:
        """One page of entries from ``from_seq`` oldest first, and the ``next_cursor`` for the
        next page (``None`` at the head). Pass it back as ``cursor`` with the same
        ``from_seq``."""
        params: dict[str, Any] = {"from": from_seq, "limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        page = w.json_body(self._http.get("/admin/audit", params=params))
        return _entries(page), _next_cursor(page)

    def audit_head(self) -> int:
        """The newest audit ``seq`` (0 for an empty log). Reads ``head`` from
        ``GET /admin/audit``; unlike :meth:`audit_checkpoint` it signs nothing."""
        return _head(w.json_body(self._http.get("/admin/audit", params={"from": 1, "limit": 1})))

    def audit_tail(self, n: int = 20) -> list[AuditEntry]:
        """The last ``n`` audit entries, oldest first."""
        head = self.audit_head()
        start = max(1, head + 1 - n)
        out: list[AuditEntry] = []
        cursor: str | None = None
        while True:
            page, nxt = self.audit(start, _MAX_PAGE, cursor=cursor)
            out.extend(page)
            cursor = _advance(nxt, cursor)
            if cursor is None:
                return out

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
        tool: str | None = None,
        decision: Literal["allow", "deny"] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Stream ``GET /admin/audit/export`` as parsed JSON Lines objects: a ``header``, then
        ``entry`` and ``checkpoint`` objects, each tagged with ``type``. Write the raw lines to
        a file and check it offline with :func:`attenuo.audit.verify_export`.

        ``kind`` (``decision``, ``tool_result``, ``exchange``, ``root_token``, ``lease_renew``,
        ``lease_revoke``, ``admin``), ``chain_id``, ``tool`` (for example ``token.exchange``)
        and ``decision`` (``allow`` or ``deny``) keep only matching entries, combined with AND.
        The header then carries a ``filter`` naming them and the file cannot be verified (its
        chain has gaps): verify an unfiltered export, then filter. An unknown kind or decision,
        or an empty value, is an ``ApiError`` (400)."""
        params = _export_params(from_seq, to_seq, kind, chain_id, tool, decision)
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
        to_seq: int | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> AuditPage:
        """One filtered page of ``GET /admin/audit``.

        ``from_seq`` and ``to_seq`` (inclusive) select a range, by default the whole log;
        ``order="asc"`` reads it oldest first, ``order="desc"`` newest first. ``cursor`` is the
        ``next_cursor`` of the previous page, sent with the same filter, range and order. A
        filtered page can come back short or empty with ``next_cursor`` still set;
        :meth:`audit_iter` follows it."""
        params = _audit_params(filter, order, from_seq, to_seq, cursor, limit)
        return _audit_page(w.json_body(self._http.get("/admin/audit", params=params)))

    def audit_iter(
        self,
        filter: AuditFilter | None = None,
        *,
        order: str = "asc",
        from_seq: int | None = None,
        to_seq: int | None = None,
        limit: int = _MAX_PAGE,
    ) -> Iterator[AuditEntry]:
        """Every matching entry of the range, in ``order``, following ``next_cursor`` until it
        is null. Pages lazily: stop iterating to stop reading. Entries appended meanwhile do
        not shift the ones not read yet."""
        cursor: str | None = None
        while True:
            page = self.audit_query(
                filter, order=order, from_seq=from_seq, to_seq=to_seq, cursor=cursor, limit=limit
            )
            yield from page.entries
            cursor = _advance(page.next_cursor, cursor)
            if cursor is None:
                return

    def audit_entry(self, seq: int) -> AuditEntryDetail:
        """The entry at ``seq`` with its context. ``ApiError`` (404) when there is none."""
        return _entry_detail(w.json_body(self._http.get(f"/admin/audit/entries/{int(seq)}")))

    def audit_record(self, record_id: str) -> AuditEntryDetail:
        """The entry whose record id is ``record_id``: the ``decision_id`` a denial or an
        AuthZEN answer carries. ``ApiError`` 400 if it is not a UUID, 404 if unknown."""
        path = f"/admin/audit/records/{w.path_segment(record_id, 'record_id')}"
        return _entry_detail(w.json_body(self._http.get(path)))

    def audit_checkpoints(
        self, cursor: str | None = None, limit: int | None = None
    ) -> CheckpointPage:
        """Stored checkpoints, newest first; ``cursor`` is the ``next_cursor`` of the previous
        page (server default page 100, at most 1000). Read-only: unlike
        :meth:`audit_checkpoint` it never signs."""
        params = _checkpoint_params(cursor, limit)
        return _checkpoint_page(
            w.json_body(self._http.get("/admin/audit/checkpoints", params=params))
        )

    def audit_checkpoints_iter(self, limit: int | None = None) -> Iterator[dict[str, Any]]:
        """Every stored checkpoint, newest first, following ``next_cursor``."""
        cursor: str | None = None
        while True:
            page = self.audit_checkpoints(cursor, limit)
            yield from page.checkpoints
            cursor = _advance(page.next_cursor, cursor)
            if cursor is None:
                return

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
        budget: StatedBudget | dict[str, Any] | None = None,
        session: StatedSession | dict[str, Any] | None = None,
        approval: StatedApproval | dict[str, Any] | None = None,
        usage: StatedUsage | dict[str, Any] | None = None,
    ) -> PolicyEvaluation:
        """Dry run: what the loaded policies decide for this call. No lease check, no charge,
        no audit record. Pass a delegation ``token`` (verified by the server; an expired one is
        accepted and flagged ``token_expired``) or a ``chain`` object, checked only
        structurally.

        ``budget`` states the run-limit counters to decide in (a :class:`StatedBudget`, or the
        raw block as a dict) instead of the store's; the answer's ``budget.source`` is then
        ``request``. A spent hard limit answers ``budget_exhausted`` with ``limit`` set, as the
        live call would.

        ``session`` states the run's output labels (a :class:`StatedSession`; answer
        ``labels.source == "request"``), ``approval`` evaluates the call as if it carried a
        granted approval (a :class:`StatedApproval`; answer ``approval_by``), and ``usage``
        states ``context.usage`` (a :class:`StatedUsage`; answer ``usage.source ==
        "request"``). Each also takes the raw block as a dict. Nothing is checked here: a
        malformed block is the server's 400, raised as :class:`ApiError`."""
        body = _evaluate_body(
            server, tool, arguments, token, chain, budget, session, approval, usage
        )
        return _policy_evaluation(
            w.json_body(self._http.post("/admin/policies/evaluate", json=body))
        )

    def approvals(
        self,
        chain_id: str | None = None,
        *,
        state: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> ApprovalPage:
        """One page of approvals, newest first: of one delegation run with ``chain_id``, in
        one ``state`` (``pending``, ``granted``, ``declined``, ``consumed``), at most ``limit``
        (server default 100, maximum 500). ``cursor`` is the ``next_cursor`` of the previous
        page, sent with the same filters; :meth:`approvals_iter` follows it. An unknown state
        is an ``ApiError`` (400)."""
        params = _approval_params(chain_id, state, limit, cursor)
        return _approvals(w.json_body(self._http.get("/admin/approvals", params=params)))

    def approvals_iter(
        self,
        chain_id: str | None = None,
        *,
        state: str | None = None,
        limit: int | None = None,
    ) -> Iterator[w.Approval]:
        """Every matching approval, newest first, following ``next_cursor``. Approvals created
        meanwhile sort above the first page and do not shift the rest."""
        cursor: str | None = None
        while True:
            page = self.approvals(chain_id, state=state, limit=limit, cursor=cursor)
            yield from page.approvals
            cursor = _advance(page.next_cursor, cursor)
            if cursor is None:
                return

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
        self._http = AsyncHttpClient(
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
        return _revoke_result(body)

    async def revoke_by_selector(
        self,
        *,
        user: str | None = None,
        chain_id: str | None = None,
        session: str | None = None,
        reason: str | None = None,
        preview: bool = False,
    ) -> SelectorRevocation:
        body, params = _selector_request(user, chain_id, session, reason, preview)
        resp = await self._http.post("/admin/leases/revoke", json=body, params=params)
        return _selector_revocation(w.json_body(resp))

    async def refund_budget(self, decision_id: str, reason: str | None = None) -> BudgetRefund:
        body = _refund_body(decision_id, reason)
        resp = await self._http.post("/admin/budgets/refund", json=body)
        return _budget_refund(w.json_body(resp))

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
        self, from_seq: int = 1, limit: int = 100, *, cursor: str | None = None
    ) -> tuple[list[AuditEntry], str | None]:
        params: dict[str, Any] = {"from": from_seq, "limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        page = w.json_body(await self._http.get("/admin/audit", params=params))
        return _entries(page), _next_cursor(page)

    async def audit_head(self) -> int:
        return _head(
            w.json_body(await self._http.get("/admin/audit", params={"from": 1, "limit": 1}))
        )

    async def audit_tail(self, n: int = 20) -> list[AuditEntry]:
        head = await self.audit_head()
        start = max(1, head + 1 - n)
        out: list[AuditEntry] = []
        cursor: str | None = None
        while True:
            page, nxt = await self.audit(start, _MAX_PAGE, cursor=cursor)
            out.extend(page)
            cursor = _advance(nxt, cursor)
            if cursor is None:
                return out

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
        tool: str | None = None,
        decision: Literal["allow", "deny"] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        params = _export_params(from_seq, to_seq, kind, chain_id, tool, decision)
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
        to_seq: int | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> AuditPage:
        params = _audit_params(filter, order, from_seq, to_seq, cursor, limit)
        return _audit_page(w.json_body(await self._http.get("/admin/audit", params=params)))

    async def audit_iter(
        self,
        filter: AuditFilter | None = None,
        *,
        order: str = "asc",
        from_seq: int | None = None,
        to_seq: int | None = None,
        limit: int = _MAX_PAGE,
    ) -> AsyncIterator[AuditEntry]:
        cursor: str | None = None
        while True:
            page = await self.audit_query(
                filter, order=order, from_seq=from_seq, to_seq=to_seq, cursor=cursor, limit=limit
            )
            for entry in page.entries:
                yield entry
            cursor = _advance(page.next_cursor, cursor)
            if cursor is None:
                return

    async def audit_entry(self, seq: int) -> AuditEntryDetail:
        return _entry_detail(w.json_body(await self._http.get(f"/admin/audit/entries/{int(seq)}")))

    async def audit_record(self, record_id: str) -> AuditEntryDetail:
        path = f"/admin/audit/records/{w.path_segment(record_id, 'record_id')}"
        return _entry_detail(w.json_body(await self._http.get(path)))

    async def audit_checkpoints(
        self, cursor: str | None = None, limit: int | None = None
    ) -> CheckpointPage:
        params = _checkpoint_params(cursor, limit)
        return _checkpoint_page(
            w.json_body(await self._http.get("/admin/audit/checkpoints", params=params))
        )

    async def audit_checkpoints_iter(
        self, limit: int | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        cursor: str | None = None
        while True:
            page = await self.audit_checkpoints(cursor, limit)
            for cp in page.checkpoints:
                yield cp
            cursor = _advance(page.next_cursor, cursor)
            if cursor is None:
                return

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
        budget: StatedBudget | dict[str, Any] | None = None,
        session: StatedSession | dict[str, Any] | None = None,
        approval: StatedApproval | dict[str, Any] | None = None,
        usage: StatedUsage | dict[str, Any] | None = None,
    ) -> PolicyEvaluation:
        body = _evaluate_body(
            server, tool, arguments, token, chain, budget, session, approval, usage
        )
        return _policy_evaluation(
            w.json_body(await self._http.post("/admin/policies/evaluate", json=body))
        )

    async def approvals(
        self,
        chain_id: str | None = None,
        *,
        state: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> ApprovalPage:
        params = _approval_params(chain_id, state, limit, cursor)
        return _approvals(w.json_body(await self._http.get("/admin/approvals", params=params)))

    async def approvals_iter(
        self,
        chain_id: str | None = None,
        *,
        state: str | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[w.Approval]:
        cursor: str | None = None
        while True:
            page = await self.approvals(chain_id, state=state, limit=limit, cursor=cursor)
            for a in page.approvals:
                yield a
            cursor = _advance(page.next_cursor, cursor)
            if cursor is None:
                return

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
