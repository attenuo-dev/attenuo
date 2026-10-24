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
    Capability,
    Prefix,
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
    await call(client, "revoke_lease", "L1")
    assert json.loads(seen[-1].content) == {}


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
    assert tree.ancestors[0].issued_at is None
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
