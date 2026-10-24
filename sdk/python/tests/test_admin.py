from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from attenuo import (
    AdminClient,
    ApiError,
    AsyncAdminClient,
    AttenuoError,
    AuditEntry,
    AuditFilter,
    BudgetLimit,
    Capability,
    EvaluationBudget,
    EvaluationLabels,
    EvaluationUsage,
    Prefix,
    RevokeResult,
    StatedBudget,
    Unauthorized,
)

from .helpers import Signer, token_response

BASE = "http://ob.test"


@pytest.fixture(params=["sync", "async"])
def make(
    request: pytest.FixtureRequest,
) -> Callable[[Callable[[httpx.Request], httpx.Response]], tuple[Any, list[httpx.Request]]]:
    def build(
        handler: Callable[[httpx.Request], httpx.Response],
    ) -> tuple[Any, list[httpx.Request]]:
        seen: list[httpx.Request] = []

        def record(r: httpx.Request) -> httpx.Response:
            seen.append(r)
            return handler(r)

        cls = AdminClient if request.param == "sync" else AsyncAdminClient
        return cls(BASE, "adm", transport=httpx.MockTransport(record)), seen

    return build


async def call(client: Any, name: str, *args: Any, **kwargs: Any) -> Any:
    result = getattr(client, name)(*args, **kwargs)
    return await result if inspect.isawaitable(result) else result


async def test_revoke_lease(make: Any) -> None:
    client, seen = make(
        lambda r: httpx.Response(200, json={"lease_id": "L1", "revoked": 2, "reason": "demo"})
    )
    res = await call(client, "revoke_lease", "L1", "demo")
    assert (seen[-1].method, seen[-1].url.path) == ("POST", "/admin/leases/L1/revoke")
    assert seen[-1].headers["authorization"] == "Bearer adm"
    assert json.loads(seen[-1].content) == {"reason": "demo"}
    assert (res.lease_id, res.revoked, res.reason) == ("L1", 2, "demo")
    assert res.audit_id is None  # an answer without the member
    await call(client, "revoke_lease", "L1")
    assert json.loads(seen[-1].content) == {}


async def test_revoke_lease_returns_the_audit_id(make: Any) -> None:
    answers = iter(
        [
            {"lease_id": "L1", "revoked": 1, "reason": "r", "audit_id": "a-1"},
            {"lease_id": "L1", "revoked": 0, "reason": "r", "audit_id": None},
        ]
    )
    client, _ = make(lambda r: httpx.Response(200, json=next(answers)))
    res = await call(client, "revoke_lease", "L1", "r")
    assert res == RevokeResult("L1", 1, "r", "a-1")
    # The record could not be written: the revocation stands, the id is None.
    assert (await call(client, "revoke_lease", "L1", "r")).audit_id is None


async def test_lease_status(make: Any) -> None:
    body = {
        "lease_id": "L1", "active": False, "parent": None, "expires_at": "2026-10-23T10:00:00Z",
        "revoked_at": "2026-10-23T09:00:00Z", "revoke_reason": "demo",
    }  # fmt: skip
    client, seen = make(lambda r: httpx.Response(200, json=body))
    st = await call(client, "lease_status", "L1")
    assert seen[-1].url.path == "/admin/leases/L1"
    assert not st.active and st.revoke_reason == "demo"

    client, _ = make(
        lambda r: httpx.Response(404, json={"error": "not_found", "detail": "unknown lease"})
    )
    with pytest.raises(ApiError) as e:
        await call(client, "lease_status", "nope")
    assert e.value.status == 404


def _entry(seq: int, decision: str = "allow") -> dict[str, Any]:
    return {
        "seq": seq,
        "hash": "h",
        "record": {
            "id": f"id{seq}",
            "decision": decision,
            "reason": "r",
            "tool": "t",
            "server": "s",
        },
    }


async def test_audit_page_and_tail(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/admin/audit/checkpoint":
            return httpx.Response(200, json={"seq": 7, "hash": "abc"})
        q = dict(r.url.params)
        start = int(q["from"])
        entries = [_entry(s) for s in range(start, 8)][: int(q["limit"])]
        return httpx.Response(200, json={"entries": entries, "next": None, "head": 7})

    client, seen = make(handler)
    entries = await call(client, "audit_tail", 3)
    # the head comes from GET /admin/audit; the checkpoint endpoint (which signs) is not used
    assert all(r.url.path == "/admin/audit" for r in seen)
    assert [e.seq for e in entries] == [5, 6, 7]
    assert entries[0].id == "id5" and entries[0].decision == "allow" and entries[0].tool == "t"
    assert dict(seen[-1].url.params) == {"from": "5", "limit": "1000"}
    assert await call(client, "audit_head") == 7
    entries = await call(client, "audit_tail", 100)
    assert entries[0].seq == 1 and len(entries) == 7
    page, nxt = await call(client, "audit", 2, 2)
    assert nxt is None and page[0].seq == 2
    assert (await call(client, "audit_checkpoint")) == {"seq": 7, "hash": "abc"}
    assert seen[-1].url.path == "/admin/audit/checkpoint"


async def test_audit_tail_follows_next(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        assert not r.url.path.endswith("checkpoint")
        q = r.url.params
        start = int(q["from"])
        if q["limit"] == "1":
            return httpx.Response(200, json={"entries": [_entry(1)], "next": 2, "head": 3})
        if start == 1:
            return httpx.Response(
                200, json={"entries": [_entry(1), _entry(2)], "next": 3, "head": 3}
            )
        return httpx.Response(200, json={"entries": [_entry(3)], "next": None, "head": 3})

    client, _ = make(handler)
    assert [e.seq for e in await call(client, "audit_tail", 10)] == [1, 2, 3]


async def test_audit_head_empty_log_and_missing_field(make: Any) -> None:
    client, _ = make(lambda r: httpx.Response(200, json={"entries": [], "next": None, "head": 0}))
    assert await call(client, "audit_head") == 0
    assert await call(client, "audit_tail", 5) == []
    client, _ = make(lambda r: httpx.Response(200, json={"entries": [], "next": None}))
    assert await call(client, "audit_head") == 0


async def _collect(client: Any, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    it = client.audit_export(*args, **kwargs)
    if hasattr(it, "__aiter__"):
        return [x async for x in it]
    return list(it)


async def test_audit_export_streams_jsonl(make: Any) -> None:
    body = (
        '{"type":"header","format":"attenuo-audit-export/1","from":1,"to":2}\n'
        '{"type":"entry","seq":1}\n\n'
        '{"type":"checkpoint","seq":2}\n'
    )
    client, seen = make(lambda r: httpx.Response(200, text=body))
    lines = await _collect(client, 1, 2)
    assert [x["type"] for x in lines] == ["header", "entry", "checkpoint"]
    assert seen[-1].url.path == "/admin/audit/export"
    assert dict(seen[-1].url.params) == {"from": "1", "to": "2"}
    await _collect(client)
    assert dict(seen[-1].url.params) == {"from": "1"}
    await _collect(client, 3, kind="lease_renew", chain_id="l 1")
    assert dict(seen[-1].url.params) == {
        "from": "3",
        "kind": "lease_renew",
        "chain_id": "l 1",
    }


async def test_audit_export_tool_and_decision_filters(make: Any) -> None:
    client, seen = make(lambda r: httpx.Response(200, text='{"type":"header"}\n'))
    await _collect(client, tool="token.exchange", decision="deny")
    assert dict(seen[-1].url.params) == {"from": "1", "tool": "token.exchange", "decision": "deny"}
    assert seen[-1].url.query == b"from=1&tool=token.exchange&decision=deny"
    await _collect(client, 2, 9, kind="decision", chain_id="c1", tool="read_file", decision="allow")
    assert dict(seen[-1].url.params) == {
        "from": "2",
        "to": "9",
        "kind": "decision",
        "chain_id": "c1",
        "tool": "read_file",
        "decision": "allow",
    }
    # The server rejects a bad decision with a 400; the SDK passes it on as ApiError.
    client, _ = make(lambda r: httpx.Response(400, json={"error": "invalid_request"}))
    with pytest.raises(ApiError) as e:
        await _collect(client, decision="maybe")
    assert e.value.status == 400


_SELECTED = {
    "selector": {"chain_id": "c1"}, "preview": False, "matched": ["c1"],
    "revoked": ["c1", "c2"], "matched_count": 1, "revoked_count": 2, "truncated": False,
    "reason": "run went wrong", "audit_id": "3f2a",
}  # fmt: skip


async def test_revoke_by_selector_request(make: Any) -> None:
    client, seen = make(lambda r: httpx.Response(200, json=_SELECTED))
    res = await call(client, "revoke_by_selector", chain_id="c1", reason="run went wrong")
    assert (seen[-1].method, seen[-1].url.path) == ("POST", "/admin/leases/revoke")
    assert seen[-1].url.query == b""
    assert json.loads(seen[-1].content) == {"chain_id": "c1", "reason": "run went wrong"}
    assert res.selector == {"chain_id": "c1"} and not res.preview
    assert (res.matched, res.revoked) == (["c1"], ["c1", "c2"])
    assert (res.matched_count, res.revoked_count, res.truncated) == (1, 2, False)
    assert (res.reason, res.audit_id) == ("run went wrong", "3f2a")

    await call(client, "revoke_by_selector", user="alice@example.com", preview=True)
    assert dict(seen[-1].url.params) == {"preview": "true"}
    assert json.loads(seen[-1].content) == {"user": "alice@example.com"}


async def test_revoke_by_selector_preview_answer(make: Any) -> None:
    body = {
        "selector": {"session_tag": "a1b2c3d4e5f6", "chain_ids": []}, "preview": True,
        "matched": [], "revoked": [], "matched_count": 0, "revoked_count": 0,
        "truncated": False, "reason": None, "audit_id": None,
    }  # fmt: skip
    client, seen = make(lambda r: httpx.Response(200, json=body))
    res = await call(client, "revoke_by_selector", session="sid-secret", preview=True)
    assert json.loads(seen[-1].content) == {"session": "sid-secret"}
    assert res.preview and res.matched == [] and res.revoked == []
    assert res.reason is None and res.audit_id is None
    assert res.selector == {"session_tag": "a1b2c3d4e5f6", "chain_ids": []}


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"user": "a", "chain_id": "c"},
        {"chain_id": "c", "session": "s"},
        {"user": "a", "chain_id": "c", "session": "s"},
        {"user": ""},
        {"session": ""},
        {"reason": "no selector"},
    ],
)
async def test_revoke_by_selector_needs_exactly_one(make: Any, kwargs: dict[str, Any]) -> None:
    client, seen = make(lambda r: httpx.Response(200, json=_SELECTED))
    with pytest.raises(ValueError, match=r"exactly one|must not be empty"):
        await call(client, "revoke_by_selector", **kwargs)
    assert seen == []


async def test_revoke_by_selector_never_logs_the_session(
    make: Any, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "mcp-session-9f8e7d6c5b4a"
    client, _ = make(lambda r: httpx.Response(400, json={"error": "invalid_request"}))
    with caplog.at_level("DEBUG"), pytest.raises(ApiError) as e:
        await call(client, "revoke_by_selector", session=secret, preview=True)
    assert secret not in caplog.text and secret not in str(e.value)
    client, _ = make(lambda r: httpx.Response(200, json=_SELECTED))
    with caplog.at_level("DEBUG"):
        res = await call(client, "revoke_by_selector", session=secret)
    assert secret not in caplog.text and secret not in repr(res)
    with pytest.raises(ValueError) as bad:
        await call(client, "revoke_by_selector", session=secret, user="alice")
    assert secret not in str(bad.value)


def test_audit_entry_exposes_kind_and_chain_id() -> None:
    e = AuditEntry(seq=1, record={"kind": "exchange", "chain_id": "l1"}, raw={})
    assert (e.kind, e.chain_id) == ("exchange", "l1")
    assert AuditEntry(seq=2, record={}, raw={}).chain_id is None


async def test_audit_export_errors(make: Any) -> None:
    client, _ = make(lambda r: httpx.Response(401, json={"error": "unauthorized"}))
    with pytest.raises(ApiError):
        await _collect(client)
    client, _ = make(lambda r: httpx.Response(200, text="not json\n"))
    with pytest.raises(AttenuoError):
        await _collect(client)


async def test_audit_verify(make: Any) -> None:
    client, seen = make(
        lambda r: httpx.Response(200, json={"entries": 5, "ok": True, "first_bad_seq": None})
    )
    rep = await call(client, "audit_verify")
    assert seen[-1].url.path == "/admin/audit/verify"
    assert rep.ok and rep.entries == 5 and rep.first_bad_seq is None
    client, _ = make(
        lambda r: httpx.Response(200, json={"entries": 5, "ok": False, "first_bad_seq": 3})
    )
    rep = await call(client, "audit_verify")
    assert not rep.ok and rep.first_bad_seq == 3


async def test_policy_reload(make: Any) -> None:
    client, seen = make(
        lambda r: httpx.Response(200, json={"policy_ids": ["a", "b"], "warnings": ["w"]})
    )
    rep = await call(client, "policy_reload")
    assert (seen[-1].method, seen[-1].url.path) == ("POST", "/admin/policies/reload")
    assert rep.policy_ids == ["a", "b"] and rep.warnings == ["w"]
    client, _ = make(
        lambda r: httpx.Response(422, json={"error": "policy_invalid", "detail": "parse error"})
    )
    with pytest.raises(ApiError) as e:
        await call(client, "policy_reload")
    assert e.value.error == "policy_invalid"


async def test_mint_root_dev(make: Any) -> None:
    jwt = Signer().mint()
    client, seen = make(lambda r: httpx.Response(200, json=token_response(jwt, "root-lease")))
    tok = await call(
        client,
        "mint_root_dev",
        "alice",
        "https://idp.example",
        "planner",
        [Capability("github", "*", repo=Prefix("alice/"))],
        ttl_seconds=60,
        attributes={"mfa": True},
    )
    assert seen[-1].url.path == "/admin/root-token"
    assert json.loads(seen[-1].content) == {
        "subject": "alice",
        "issuer": "https://idp.example",
        "agent": "planner",
        "capabilities": [
            {
                "server": "github",
                "tool": "*",
                "constraints": {"repo": {"op": "prefix", "value": "alice/"}},
            }
        ],
        "ttl_seconds": 60,
        "attributes": {"mfa": True},
    }
    assert tok.lease == "root-lease" and tok.jwt == jwt

    await call(client, "mint_root_dev", "alice", "https://idp.example", "planner")
    assert set(json.loads(seen[-1].content)) == {"subject", "issuer", "agent"}

    await call(
        client, "mint_root_dev", "alice", "https://idp.example", "planner", may_act=["coder"]
    )
    assert json.loads(seen[-1].content)["may_act"] == {"sub": ["coder"]}
    await call(client, "mint_root_dev", "a", "i", "p", may_act=iter(["x", "y"]))
    assert json.loads(seen[-1].content)["may_act"] == {"sub": ["x", "y"]}
    # An empty list is sent: nobody may exchange the token.
    await call(client, "mint_root_dev", "a", "i", "p", may_act=[])
    assert json.loads(seen[-1].content)["may_act"] == {"sub": []}
    with pytest.raises(TypeError):
        await call(client, "mint_root_dev", "a", "i", "p", may_act="coder")
    with pytest.raises(ValueError):
        await call(client, "mint_root_dev", "a", "i", "p", may_act=[""])


async def test_admin_errors(make: Any) -> None:
    client, _ = make(
        lambda r: httpx.Response(
            401, json={"error": "unauthorized", "detail": "admin bearer token required"}
        )
    )
    with pytest.raises(Unauthorized):
        await call(client, "audit_verify")
    client, _ = make(lambda r: httpx.Response(404, text=""))
    with pytest.raises(ApiError) as e:
        await call(client, "mint_root_dev", "a", "i", "p")
    assert e.value.status == 404


def test_context_managers() -> None:
    with AdminClient(BASE, "t", transport=httpx.MockTransport(lambda r: httpx.Response(200))) as a:
        assert a.server_url == BASE
    with pytest.raises(ValueError):
        AdminClient("nope", "t")


async def test_async_context_manager() -> None:
    async with AsyncAdminClient(
        BASE, "t", transport=httpx.MockTransport(lambda r: httpx.Response(200))
    ) as a:
        assert a.server_url == BASE


async def _iter(client: Any, *args: Any, **kwargs: Any) -> list[AuditEntry]:
    it = client.audit_iter(*args, **kwargs)
    if hasattr(it, "__aiter__"):
        return [x async for x in it]
    return list(it)


async def test_audit_query_filter_and_desc_paging(make: Any) -> None:
    # Newest first, filtered: the first page comes back short but `prev` says read on.
    def handler(r: httpx.Request) -> httpx.Response:
        q = dict(r.url.params)
        if "before" not in q:
            return httpx.Response(
                200, json={"entries": [_entry(9, "deny")], "next": None, "prev": 9, "head": 12}
            )
        assert q["before"] == "9"
        return httpx.Response(
            200,
            json={"entries": [_entry(4, "deny"), _entry(2, "deny")], "next": 10, "prev": None,
                  "head": 12},
        )  # fmt: skip

    client, seen = make(handler)
    flt = AuditFilter(decision="deny", kind=["decision", "exchange"], lease="l 1")
    page = await call(client, "audit_query", flt, order="desc", limit=3)
    assert (page.next, page.prev, page.head) == (None, 9, 12)
    assert dict(seen[-1].url.params) == {
        "order": "desc",
        "limit": "3",
        "decision": "deny",
        "kind": "decision,exchange",
        "lease": "l 1",
    }
    entries = await _iter(client, flt, order="desc", limit=3)
    assert [e.seq for e in entries] == [9, 4, 2]
    assert all(e.decision == "deny" for e in entries)
    assert dict(seen[-1].url.params)["before"] == "9"


async def test_audit_iter_asc_follows_next_and_formats_times(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        start = int(r.url.params.get("from", "1"))
        nxt = None if start >= 5 else start + 4
        return httpx.Response(200, json={"entries": [_entry(start)], "next": nxt, "head": 5})

    client, seen = make(handler)
    since = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    entries = await _iter(client, AuditFilter(since=since, until="2026-10-24T00:00:00Z"))
    assert [e.seq for e in entries] == [1, 5]
    assert dict(seen[0].url.params) == {
        "order": "asc",
        "limit": "1000",
        "since": "2026-10-23T09:00:00+00:00",
        "until": "2026-10-24T00:00:00Z",
    }
    with pytest.raises(ValueError):
        await _iter(client, AuditFilter(since=datetime(2026, 10, 23)))


async def test_audit_iter_refuses_a_cursor_that_does_not_move(make: Any) -> None:
    client, _ = make(lambda r: httpx.Response(200, json={"entries": [], "prev": 5, "head": 9}))
    with pytest.raises(AttenuoError):
        await _iter(client, order="desc", before=5)


def _detail(seq: int) -> dict[str, Any]:
    return {
        "entry": {"seq": seq, "hash": "h", "record": {"id": "0b7c", "kind": "decision",
                  "chain_id": "root"}},
        "lease_states": [
            {"lease_id": "root", "known": True, "active": True, "parent": None,
             "expires_at": "2026-10-23T10:00:00Z", "revoked_at": None, "revoke_reason": None},
            {"lease_id": "gone", "known": False},
        ],
        "covered_by_checkpoint": {"seq": 10, "head_hash": "hh"},
        "policy_reloaded_after": None,
    }  # fmt: skip


async def test_audit_entry_by_seq_and_by_record_id(make: Any) -> None:
    client, seen = make(lambda r: httpx.Response(200, json=_detail(7)))
    d = await call(client, "audit_entry", 7)
    assert seen[-1].url.path == "/admin/audit/entries/7"
    assert d.entry.seq == 7 and d.entry.chain_id == "root"
    assert [(s.lease_id, s.known, s.active) for s in d.lease_states] == [
        ("root", True, True),
        ("gone", False, False),
    ]
    assert d.covered_by_checkpoint == {"seq": 10, "head_hash": "hh"}
    assert d.policy_reloaded_after is None
    d = await call(client, "audit_record", "0b7c-uuid")
    assert seen[-1].url.path == "/admin/audit/records/0b7c-uuid"
    assert d.entry.id == "0b7c"
    with pytest.raises(ValueError):
        await call(client, "audit_record", "..")


async def test_audit_entry_not_found(make: Any) -> None:
    client, _ = make(
        lambda r: httpx.Response(404, json={"error": "not_found", "detail": "no entry at seq 99"})
    )
    with pytest.raises(ApiError) as e:
        await call(client, "audit_entry", 99)
    assert e.value.status == 404 and e.value.error == "not_found"


async def test_audit_checkpoints(make: Any) -> None:
    cps = [{"seq": 20, "head_hash": "a"}, {"seq": 10, "head_hash": "b"}]
    client, seen = make(lambda r: httpx.Response(200, json={"checkpoints": cps, "prev": 10}))
    page = await call(client, "audit_checkpoints", 30, 2)
    assert seen[-1].url.path == "/admin/audit/checkpoints"
    assert dict(seen[-1].url.params) == {"before": "30", "limit": "2"}
    assert page.checkpoints == cps and page.prev == 10
    await call(client, "audit_checkpoints")
    assert dict(seen[-1].url.params) == {}


def _node(lease: str, parent: str | None, active: bool = True) -> dict[str, Any]:
    return {
        "lease_id": lease, "parent": parent, "agent": "coder", "active": active,
        "expires_at": "2026-10-23T19:20:00Z", "revoked_at": None, "revoke_reason": None,
        "issued_at": None if parent is None else "2026-10-23T19:05:00Z",
        "issued_seq": None if parent is None else 42,
        "budget": None if parent is None else {"recorded": True, "limits": [], "usage": []},
    }  # fmt: skip


async def test_lease_tree(make: Any) -> None:
    body = {
        "root": "r", "ancestors": [_node("r", None)],
        "nodes": [_node("l1", "r"), _node("l2", "l1", active=False)],
        "would_revoke": 1, "truncated": False,
    }  # fmt: skip
    client, seen = make(lambda r: httpx.Response(200, json=body))
    tree = await call(client, "lease_tree", "l1", max_nodes=50)
    assert seen[-1].url.path == "/admin/leases/l1/tree"
    assert dict(seen[-1].url.params) == {"max_nodes": "50"}
    assert tree.root == "r" and tree.would_revoke == 1 and not tree.truncated
    assert [n.lease_id for n in tree.nodes] == ["l1", "l2"]
    assert tree.nodes[0].issued_seq == 42 and not tree.nodes[1].active
    assert tree.ancestors[0].issued_at is None and tree.ancestors[0].budget is None
    assert tree.nodes[0].budget == {"recorded": True, "limits": [], "usage": []}
    await call(client, "lease_tree", "l1")
    assert dict(seen[-1].url.params) == {}


async def test_policies_and_check(make: Any) -> None:
    listing = {
        "path": "/etc/p.cedar", "sha256": "9f", "loaded_at": "2026-10-23T19:02:11Z",
        "policy_ids": ["a"], "warnings": [], "policies": [{"id": "a", "text": "permit(...);"}],
    }  # fmt: skip
    check = {
        "path": "/etc/p.cedar", "sha256": "41", "loaded_sha256": "9f",
        "differs_from_loaded": True, "ok": False, "error_count": 1, "warning_count": 0,
        "issues": [{"severity": "error", "stage": "validate", "message": "m", "line": 3}],
        "policy_ids": ["a"],
    }  # fmt: skip

    def handler(r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=check if r.url.path.endswith("/check") else listing)

    client, seen = make(handler)
    ps = await call(client, "policies")
    assert seen[-1].url.path == "/admin/policies"
    assert ps.policies == {"a": "permit(...);"} and ps.sha256 == "9f"
    pc = await call(client, "policy_check")
    assert seen[-1].url.path == "/admin/policies/check"
    assert pc.differs_from_loaded and not pc.ok and pc.issues[0]["line"] == 3


async def test_policy_evaluate(make: Any) -> None:
    answer = {
        "decision": "allow", "reason": "policy_allow", "policy_ids": ["a"], "diagnostics": [],
        "lease_check": "skipped", "chain_source": "token", "token_expired": True,
    }  # fmt: skip
    client, seen = make(lambda r: httpx.Response(200, json=answer))
    ev = await call(
        client, "policy_evaluate", "github", "read_file", {"repo": "alice/x"}, token=" tok "
    )
    assert (seen[-1].method, seen[-1].url.path) == ("POST", "/admin/policies/evaluate")
    sent = json.loads(seen[-1].content)
    assert sent["token"] == "tok"
    assert sent["resource"] == {"type": "tool", "id": "github/read_file"}
    assert sent["context"] == {"input": {"repo": "alice/x"}}
    assert ev.allowed and ev.token_expired and ev.policy_ids == ["a"]
    assert ev.chain_source == "token" and ev.lease_check == "skipped"

    await call(client, "policy_evaluate", "github", "read_file", chain={"hops": []})
    sent = json.loads(seen[-1].content)
    assert "token" not in sent and sent["subject"]["properties"] == {"chain": {"hops": []}}
    with pytest.raises(ValueError):
        await call(client, "policy_evaluate", "github", "read_file")
    # An answer without the newer members leaves them None, and no `budget` is sent.
    assert "budget" not in json.loads(seen[0].content)
    assert (ev.budget, ev.limit, ev.labels, ev.usage, ev.approval_by) == (None,) * 5


_EXHAUSTED: dict[str, Any] = {
    "decision": "deny", "reason": "budget_exhausted", "policy_ids": [],
    "diagnostics": ["limit `distinct` on `repo` of hop 1 would be exceeded: max 1, used 1"],
    "lease_check": "skipped", "chain_source": "token", "token_expired": False,
    "session": {"tainted": True, "tainted_by": ["github/read_file"],
                "args_contain_untrusted": False, "untrusted_args": [], "source": "store"},
    "approval": {"present": False, "by": ""},
    "budget": {"limited": True, "calls_remaining": 9223372036854775807,
               "amount_remaining": 9223372036854775807, "destination_new": True,
               "source": "request"},
    "usage": {"calls": 0, "amount": 0, "destination_seen": False, "source": "request"},
    "limit": {"hop": 1, "kind": "distinct", "arg": "repo", "max": 1, "used": 1},
}  # fmt: skip


async def test_policy_evaluate_with_a_stated_budget(make: Any) -> None:
    client, seen = make(lambda r: httpx.Response(200, json=_EXHAUSTED))
    stated = StatedBudget(
        calls_remaining=0,
        destination_new=False,
        limits=[BudgetLimit(hop=1, kind="distinct", arg="repo", used=1, max=1)],
    )
    ev = await call(
        client, "policy_evaluate", "github", "read_file", {"repo": "b"}, token="t", budget=stated
    )
    sent = json.loads(seen[-1].content)
    # Members left None are not sent; the entry has the server's spelling.
    assert sent["budget"] == {
        "calls_remaining": 0,
        "destination_new": False,
        "limits": [{"hop": 1, "kind": "distinct", "arg": "repo", "used": 1, "max": 1}],
    }
    assert not ev.allowed and ev.reason == "budget_exhausted"
    assert ev.budget == EvaluationBudget(True, 2**63 - 1, 2**63 - 1, True, "request")
    assert ev.limit == BudgetLimit(hop=1, kind="distinct", arg="repo", used=1, max=1)
    assert ev.labels == EvaluationLabels(True, ["github/read_file"], False, [], "store")
    assert ev.usage == EvaluationUsage(0, 0, False, "request")
    assert ev.approval_by is None

    # A refusal's `limit` can be stated back as it came, as a raw dict.
    raw = {"limits": [_EXHAUSTED["limit"]]}
    await call(client, "policy_evaluate", "github", "read_file", token="t", budget=raw)
    assert json.loads(seen[-1].content)["budget"] == raw
    # An empty block is sent as `{}`; a `calls` entry carries no `arg`.
    await call(client, "policy_evaluate", "github", "read_file", token="t", budget=StatedBudget())
    assert json.loads(seen[-1].content)["budget"] == {}
    assert BudgetLimit(hop=0, kind="calls", used=3).to_json() == {
        "hop": 0,
        "kind": "calls",
        "used": 3,
    }


async def test_policy_evaluate_reads_an_approval_and_a_hit_without_arg(make: Any) -> None:
    answer = dict(
        _EXHAUSTED,
        approval={"present": True, "by": "operator"},
        limit={"hop": 0, "kind": "calls", "max": 2, "used": 2},
    )
    client, _ = make(lambda r: httpx.Response(200, json=answer))
    ev = await call(client, "policy_evaluate", "github", "read_file", token="t")
    assert ev.approval_by == "operator"
    assert ev.limit == BudgetLimit(hop=0, kind="calls", used=2, arg=None, max=2)


async def test_policy_evaluate_passes_a_budget_refusal_on(make: Any) -> None:
    # The server checks the block; a malformed one is its 400, raised as ApiError.
    client, _ = make(lambda r: httpx.Response(400, json={"error": "invalid_request"}))
    with pytest.raises(ApiError) as e:
        await call(
            client,
            "policy_evaluate",
            "github",
            "read_file",
            token="t",
            budget=StatedBudget(calls_remaining=-1),
        )
    assert (e.value.status, e.value.error) == (400, "invalid_request")


def _approval_body(state: str = "pending", **extra: Any) -> dict[str, Any]:
    body = {
        "approval_id": "a1", "state": state, "expired": False, "chain_id": "c1",
        "lease": "l1", "call_hash": "h", "decision_id": "d1",
        "call": {"server": "github", "tool": "delete_repo", "arguments": {"repo": "x"}},
        "labels": [{"seq": 4}], "subject": "alice", "issuer": "https://idp",
        "agents": ["planner"], "created_at": "2026-10-24T10:00:00Z",
        "expires_at": "2026-10-24T10:02:00Z",
    }  # fmt: skip
    body.update(extra)
    return body


async def test_approvals_list_and_get(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/admin/approvals":
            return httpx.Response(200, json={"approvals": [_approval_body()]})
        return httpx.Response(200, json=_approval_body())

    client, seen = make(handler)
    items = await call(client, "approvals", "c1", state="pending", limit=10)
    assert (seen[-1].method, seen[-1].url.path) == ("GET", "/admin/approvals")
    assert dict(seen[-1].url.params) == {"chain_id": "c1", "state": "pending", "limit": "10"}
    assert seen[-1].headers["authorization"] == "Bearer adm"
    assert [a.approval_id for a in items] == ["a1"]
    assert items[0].tool == "delete_repo" and items[0].arguments == {"repo": "x"}
    assert items[0].raw["decision_id"] == "d1" and not items[0].usable
    await call(client, "approvals")
    assert dict(seen[-1].url.params) == {}

    a = await call(client, "approval", "a1")
    assert (seen[-1].method, seen[-1].url.path) == ("GET", "/admin/approvals/a1")
    assert a.state == "pending" and a.chain_id == "c1"
    await call(client, "approval", "../a1")
    assert seen[-1].url.raw_path == b"/admin/approvals/..%2Fa1"


async def test_approval_grant_and_decline(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        decision = json.loads(r.content)["decision"]
        state = "granted" if decision == "grant" else "declined"
        approver = {"subject": "urn:attenuo:admin", "method": "admin_token", "by": "operator"}
        return httpx.Response(200, json=_approval_body(state, approver=approver))

    client, seen = make(handler)
    a = await call(client, "grant_approval", "a1")
    assert (seen[-1].method, seen[-1].url.path) == ("POST", "/admin/approvals/a1")
    assert json.loads(seen[-1].content) == {"decision": "grant"}
    assert a.usable and a.approver is not None and a.approver["by"] == "operator"
    a = await call(client, "decline_approval", "a1")
    assert json.loads(seen[-1].content) == {"decision": "decline"}
    assert a.state == "declined" and not a.usable


async def test_approval_errors(make: Any) -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.method == "POST":
            return httpx.Response(
                409, json={"error": "approval_not_pending", "detail": "already granted"}
            )
        return httpx.Response(404, json={"error": "not_found", "detail": "unknown approval"})

    client, _ = make(handler)
    with pytest.raises(ApiError) as e:
        await call(client, "grant_approval", "a1")
    assert e.value.status == 409 and e.value.error == "approval_not_pending"
    with pytest.raises(ApiError) as e:
        await call(client, "approval", "nope")
    assert e.value.status == 404
