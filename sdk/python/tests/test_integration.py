"""The GitHub-leak scenario through the SDK, against the real server and a fake MCP upstream.

Skipped unless ``ATTENUO_INTEGRATION=1``. Needs ``cargo``. Builds ``attenuo-server`` and the
``fake_mcp`` example (honours ``CARGO_TARGET_DIR``), starts both on free ports with the demo
config from ``examples/github-leak-demo``, and plays the scenario from ``run.sh``.

Set ``ATTENUO_BIN_DIR`` to a directory holding prebuilt ``attenuo-server`` and
``examples/fake_mcp`` (or ``fake_mcp``) to skip the build.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.hazmat.primitives.serialization import PublicFormat as _PublicFormat

from attenuo import (
    AdminClient,
    ApiError,
    ApprovalRequired,
    AsyncClient,
    AuthzenEvaluation,
    BudgetLimit,
    Capability,
    Client,
    Denied,
    DpopKey,
    EvaluationLabels,
    EvaluationUsage,
    Prefix,
    RefreshError,
    RpcError,
    StatedApproval,
    StatedBudget,
    StatedSession,
    StatedUsage,
    Token,
    TokenRefresher,
    Unauthorized,
    call_hash,
)
from attenuo.audit import entry_hash
from attenuo.mcp import TokenAuth

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("ATTENUO_INTEGRATION") != "1", reason="set ATTENUO_INTEGRATION=1 to run"
    ),
]

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "examples" / "github-leak-demo"
ADMIN_TOKEN = "demo-admin-token"
# [[agents]] secrets in the demo config: an exchange authenticates as its actor.
CODER_SECRET = "demo-coder-secret"
TESTER_SECRET = "demo-tester-secret"


def reserve_ports(n: int) -> list[int]:
    """Distinct free ports. All the probe sockets stay open until every port is chosen, so the
    kernel cannot hand the same port out twice; the caller starts the servers right after."""
    socks = [socket.socket() for _ in range(n)]
    try:
        for s in socks:
            s.bind(("127.0.0.1", 0))
        return [int(s.getsockname()[1]) for s in socks]
    finally:
        for s in socks:
            s.close()


def cargo_executable(args: list[str], name: str) -> Path:
    """Build with cargo and return the path of the executable it reports for target ``name``.

    Caveat: when several checkouts share one ``CARGO_TARGET_DIR``, another checkout's build can
    replace ``debug/<name>`` after ours. If the scenario fails oddly there (for example a token
    header the repo does not produce), pin the binaries with ``ATTENUO_BIN_DIR``.
    """
    proc = subprocess.run(
        ["cargo", "build", "-q", "--message-format=json-render-diagnostics", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if (
            msg.get("reason") == "compiler-artifact"
            and msg.get("executable")
            and msg["target"]["name"] == name
        ):
            return Path(msg["executable"])
    raise AssertionError(f"cargo did not report an executable for {name}")


def binaries() -> tuple[Path, Path]:
    given = os.environ.get("ATTENUO_BIN_DIR")
    if given:
        d = Path(given)
        fake = d / "examples" / "fake_mcp"
        return d / "attenuo-server", fake if fake.exists() else d / "fake_mcp"
    return (
        cargo_executable(["-p", "attenuo-server"], "attenuo-server"),
        cargo_executable(
            ["-p", "attenuo-proxy", "--features", "testing", "--example", "fake_mcp"], "fake_mcp"
        ),
    )


class Stack:
    def __init__(self, url: str, work: Path) -> None:
        self.url = url
        self.work = work
        #: The issuer's private key, when the test generated it (``sink_stack``).
        self.issuer_key: Ed25519PrivateKey | None = None

    def upstream_calls(self) -> list[str]:
        log = (self.work / "fake-mcp.log").read_text()
        return [line for line in log.splitlines() if "tools/call" in line]


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    yield from run_stack(tmp_path_factory.mktemp("attenuo-it"))


@pytest.fixture(scope="module")
def nonce_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    """The same stack with ``[token] dpop_nonce = "required"`` (RFC 9449 §8)."""
    yield from run_stack(
        tmp_path_factory.mktemp("attenuo-it-nonce"), '[token]\ndpop_nonce = "required"\n\n'
    )


@pytest.fixture(scope="module")
def sink_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    """The same stack with an issuer key the test holds (the stolen key of SR-21) and the file
    checkpoint sink on (``[audit.sink]``)."""
    work = tmp_path_factory.mktemp("attenuo-it-sink")
    key = Ed25519PrivateKey.generate()
    pem = work / "issuer.pem"
    pem.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    pem.chmod(0o600)
    stack = run_stack(
        work,
        '[audit.sink]\nkind = "file"\npath = "{work}/shipped.jsonl"\n\n',
        issuer_key=pem,
    )
    for s in stack:
        s.issuer_key = key
        yield s


@pytest.fixture(scope="module")
def sse_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    """The same stack with a fake upstream that streams its answers (``fake_mcp --sse``) and the
    proxy's stream re-check every second (``[proxy] stream_recheck_seconds = 1``)."""
    yield from run_stack(
        tmp_path_factory.mktemp("attenuo-it-sse"),
        "[proxy]\nstream_recheck_seconds = 1\n\n",
        fake_args=["--sse"],
    )


@pytest.fixture(scope="module")
def decimal_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    """The same stack with ``amount`` declared ``decimal`` for ``github/read_file`` and a policy
    that refuses an amount of 100 or more."""
    work = tmp_path_factory.mktemp("attenuo-it-decimal")
    policy = work / "policy.cedar"
    policy.write_text(
        (DEMO / "policy.cedar").read_text()
        + '\n@id("read_file_amount_below_100")\n'
        + 'forbid(principal, action == Action::"github/read_file", resource)\n'
        + 'when { context.input has amount && !context.input.amount.lessThan(decimal("100.0")) };\n'
    )
    yield from run_stack(
        work,
        policy=policy,
        edits={
            'inputs = { repo = "string", path = "string" }': (
                'inputs = { repo = "string", path = "string", amount = "decimal" }'
            )
        },
    )


def run_stack(
    work: Path,
    token_section: str = "",
    issuer_key: Path | None = None,
    fake_args: list[str] | None = None,
    policy: Path | None = None,
    edits: Mapping[str, str] | None = None,
) -> Iterator[Stack]:
    built_server, built_fake = binaries()
    # Copy them: a shared CARGO_TARGET_DIR can be rebuilt under us mid-test.
    server_bin = work / "attenuo-server"
    fake_bin = work / "fake_mcp"
    shutil.copy2(built_server, server_bin)
    shutil.copy2(built_fake, fake_bin)
    ob_port, mcp_port = reserve_ports(2)

    config = (
        (DEMO / "config.toml")
        .read_text()
        .replace("18080", str(ob_port))
        .replace("13001", str(mcp_port))
        .replace("examples/github-leak-demo/policy.cedar", str(policy or DEMO / "policy.cedar"))
        .replace("[audit]\n", f"{token_section.replace('{work}', str(work))}[audit]\n", 1)
    )
    for old, new in (edits or {}).items():
        assert old in config, f"not in the demo config: {old}"
        config = config.replace(old, new, 1)
    if issuer_key is not None:
        config = config.replace(
            "[issuer]\n", f'[issuer]\nprivate_key_pem_path = "{issuer_key}"\n', 1
        )
    (work / "config.toml").write_text(config)

    procs: list[subprocess.Popen[bytes]] = []
    fake_out = (work / "fake-mcp.out").open("wb")
    fake_log = (work / "fake-mcp.log").open("wb")
    server_log = (work / "server.log").open("wb")
    try:
        procs.append(
            subprocess.Popen(
                [str(fake_bin), "--port", str(mcp_port), *(fake_args or [])],
                stdout=fake_out,
                stderr=fake_log,
            )
        )
        procs.append(
            subprocess.Popen(
                [str(server_bin), "--config", str(work / "config.toml")],
                stdout=server_log,
                stderr=subprocess.STDOUT,
                env={**os.environ, "RUST_LOG": "warn"},
            )
        )
        url = f"http://127.0.0.1:{ob_port}"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                ready = httpx.get(f"{url}/healthz", timeout=1).is_success
            except httpx.HTTPError:
                ready = False
            if ready and b"listening" in (work / "fake-mcp.out").read_bytes():
                break
            for p in procs:
                assert p.poll() is None, (
                    f"a server exited early:\n{(work / 'server.log').read_text()}"
                )
            time.sleep(0.1)
        else:
            pytest.fail(f"server did not start:\n{(work / 'server.log').read_text()}")
        yield Stack(url, work)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        for f in (fake_out, fake_log, server_log):
            f.close()


def test_call_tool_stream_relays_events_and_raises_on_revocation(sse_stack: Stack) -> None:
    """A streamed tools/call through the real proxy: the upstream's notification arrives before
    the result; then a call held open by the upstream is cut by the proxy within its re-check
    interval once the lease is revoked, and the SDK raises Denied with the stream.end record."""
    admin = AdminClient(sse_stack.url, ADMIN_TOKEN)
    ob = Client(sse_stack.url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(
        root, "coder", [Capability("github", "read_file")], client_secret=CODER_SECRET
    )
    args = {"repo": "alice/public-docs", "path": "README.md"}

    events = list(ob.call_tool_stream(coder, "github", "read_file", args))
    assert [e.method for e in events] == ["notifications/message", None]
    assert events[0].message["params"]["data"] == "working"
    final = events[-1]
    assert final.is_final and final.last_event_id == "0"
    assert final.result is not None and not final.result.is_error
    assert final.result.decision_id
    assert admin.audit_record(final.result.decision_id).entry.decision == "allow"

    # A denial is raised before anything streams.
    with pytest.raises(Denied) as denied:
        next(ob.call_tool_stream(coder, "github", "read_file", {"repo": "alice/private-x"}))
    assert denied.value.reason == "policy_deny"

    # The upstream holds the response back for 20 s; revoke the lease after the first event.
    held = ob.call_tool_stream(coder, "github", "read_file", {**args, "hold_ms": 20000})
    first = next(held)
    assert first.method == "notifications/message" and not first.is_final
    started = time.monotonic()
    assert admin.revoke_lease(coder.lease, "stream test").revoked == 1
    with pytest.raises(Denied) as cut:
        next(held)
    assert time.monotonic() - started < 10  # one re-check interval (1 s), with slack
    assert cut.value.reason == "lease_revoked"
    assert cut.value.decision_id
    end = admin.audit_record(cut.value.decision_id).entry
    assert (end.tool, end.decision, end.reason) == ("stream.end", "deny", "lease_revoked")


def test_github_leak_scenario(stack: Stack) -> None:
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)

    # 1. A broad root token for Alice's assistant (dev mint: no IdP in this setup).
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    assert root.subject == "alice"
    assert root.agent == "assistant"
    assert root.chain.depth == 1

    # 2. The assistant hands its coder read_file and nothing else.
    coder = ob.exchange(
        root,
        "coder",
        [Capability("github", "read_file")],
        ttl_seconds=600,
        client_secret=CODER_SECRET,
    )
    assert coder.chain.agents == ("assistant", "coder")
    assert [str(c) for c in coder.capabilities] == ["github:read_file"]
    assert coder.lease != root.lease

    # 3. The token verifies against the server's JWKS; a tampered copy does not.
    verified = ob.inspect(coder, verify=True, issuer=stack.url, audience="attenuo")
    assert verified.verified and verified.chain == coder.chain
    head, payload, sig = coder.jwt.split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    from attenuo import VerificationError

    with pytest.raises(VerificationError):
        ob.inspect(f"{head}.{payload}.{flipped}", verify=True)

    # 4. Tools visible to the coder: only what it may call.
    names = [t.name for t in ob.list_tools(coder, "github")]
    assert "read_file" in names and "create_issue" not in names

    # 5. The intended read: allowed, forwarded upstream.
    ok = ob.call_tool(
        coder, "github", "read_file", {"repo": "alice/public-docs", "path": "README.md"}
    )
    assert not ok.is_error
    assert ok.decision_id
    allowed_decision = ok.decision_id

    # 6. The AuthZEN endpoint agrees with the proxy, and nothing reaches upstream.
    assert ob.authzen_evaluate(coder, "github", "read_file", {"repo": "alice/public-docs"})
    verdict = ob.authzen_evaluate(coder, "github", "read_file", {"repo": "alice/private-salaries"})
    assert not verdict and verdict.reason == "policy_deny"

    # 7. The injected read of a private repo: the token allows read_file, the policy does not.
    with pytest.raises(Denied) as policy_denied:
        ob.call_tool(
            coder, "github", "read_file", {"repo": "alice/private-salaries", "path": "2025.csv"}
        )
    assert policy_denied.value.reason == "policy_deny"
    assert policy_denied.value.decision_id

    # 8. Exfiltration through create_issue: never delegated.
    with pytest.raises(Denied) as cap_denied:
        ob.call_tool(
            coder, "github", "create_issue", {"repo": "alice/public-docs", "title": "leak"}
        )
    assert cap_denied.value.reason == "capability_denied"

    # 9. Attenuation is monotonic: the coder cannot widen, and a Prefix constraint binds.
    with pytest.raises(ApiError) as widen:
        ob.exchange(
            coder, "tester", [Capability("github", "create_issue")], client_secret=TESTER_SECRET
        )
    assert widen.value.status == 400 and widen.value.error == "invalid_scope"
    tester = ob.exchange(
        coder,
        "tester",
        [Capability("github", "read_file", repo=Prefix("alice/public-d"))],
        client_secret=TESTER_SECRET,
    )
    assert tester.chain.depth == 3
    assert ob.call_tool(tester, "github", "read_file", {"repo": "alice/public-docs"}).decision_id
    with pytest.raises(Denied) as narrowed:
        ob.call_tool(tester, "github", "read_file", {"repo": "alice/public-other"})
    assert narrowed.value.reason == "capability_denied"

    # 10. Renewal extends the coder's lease.
    lease = ob.renew(coder)
    assert lease.lease == coder.lease and lease.expires_in > 0

    # 10b. The actor must authenticate as itself.
    with pytest.raises(ApiError) as unauthenticated:
        ob.exchange(root, "reviewer", ["github:read_file"])
    assert unauthenticated.value.status == 401

    # 11. A bad bearer is a 401, not a denial, and says why.
    with pytest.raises(Unauthorized) as bad_bearer:
        ob.call_tool("not.a.token", "github", "read_file", {"repo": "alice/public-docs"})
    assert bad_bearer.value.reason == "invalid_token"
    assert bad_bearer.value.decision_id is None  # a token that does not verify writes no record

    # 12. Revoke the root lease: the cascade takes the coder and the tester with it.
    revoked = admin.revoke_lease(root.lease, "agent session compromised")
    assert revoked.revoked == 3
    assert not admin.lease_status(coder.lease).active
    with pytest.raises(Denied) as after:
        ob.call_tool(
            coder, "github", "read_file", {"repo": "alice/public-docs", "path": "README.md"}
        )
    assert after.value.reason == "lease_revoked"
    with pytest.raises(Denied):
        ob.call_tool(tester, "github", "read_file", {"repo": "alice/public-docs"})
    # A request without a per-call decision is a 401 that names the reason and its record.
    with pytest.raises(Unauthorized) as listing:
        ob.list_tools(tester, "github")
    assert listing.value.reason == "lease_revoked"
    assert listing.value.decision_id
    with pytest.raises(ApiError) as renewal:
        ob.renew(coder)  # a revoked lease is final
    assert (renewal.value.status, renewal.value.error) == (400, "invalid_grant")
    assert renewal.value.decision_id

    # 13. The audit log has every decision, and its hash chain verifies.
    report = admin.audit_verify()
    assert report.ok and report.entries >= 8
    entries = admin.audit_tail(200)
    by_id = {e.id: e for e in entries}
    assert by_id[allowed_decision].decision == "allow"
    assert by_id[policy_denied.value.decision_id].reason == "policy_deny"
    assert by_id[cap_denied.value.decision_id].reason == "capability_denied"
    assert by_id[after.value.decision_id].reason == "lease_revoked"
    listed = by_id[listing.value.decision_id]
    assert (listed.tool, listed.reason) == ("tools/list", "lease_revoked")
    renew_record = by_id[renewal.value.decision_id]
    assert (renew_record.tool, renew_record.reason) == ("lease.renew", "lease_revoked")

    # 14. Only the intended reads (one for the coder, one for the tester) reached upstream.
    assert len(stack.upstream_calls()) == 2

    # 15. Policy reload works and keeps the policies.
    assert "read_file_public_repos_only" in admin.policy_reload().policy_ids

    ob.close()
    admin.close()


async def test_async_client_end_to_end(stack: Stack) -> None:
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    async with AsyncClient(stack.url) as ob:
        coder = await ob.exchange(root, "coder", ["github:read_file"], client_secret=CODER_SECRET)
        res = await ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
        assert res.decision_id
        with pytest.raises(Denied) as d:
            await ob.call_tool(coder, "github", "read_file", {"repo": "alice/private-x"})
        assert d.value.reason == "policy_deny"
        assert (await ob.renew(coder)).expires_in > 0
    admin.revoke_lease(root.lease)
    admin.close()


def test_dpop_bound_chain(stack: Stack) -> None:
    """SR-24: tokens bound to keys work end to end, and are useless without the key."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    assistant_key, coder_key = DpopKey.generate(), DpopKey.generate()
    root = admin.mint_root_dev(
        "alice", "https://idp.example", "assistant", ["github:*"], dpop_key=assistant_key
    )
    assert root.dpop_jkt == assistant_key.thumbprint

    # The coder binds its token to its own key. The assistant signs off on this delegation
    # (to the coder's key and agent id) without handing over its own key (SR-40).
    sign_off = assistant_key.sign_off(f"{stack.url}/token", root.jwt, coder_key.thumbprint, "coder")
    with Client(stack.url, dpop_key=coder_key.private_jwk()) as coder_ob:
        # A sign-off for another agent is no good.
        with pytest.raises(ApiError) as other_agent:
            coder_ob.exchange(
                root,
                "coder",
                ["github:read_file"],
                client_secret=CODER_SECRET,
                subject_token_dpop=assistant_key.sign_off(
                    f"{stack.url}/token", root.jwt, coder_key.thumbprint, "tester"
                ),
            )
        assert other_agent.value.status == 401
        coder = coder_ob.exchange(
            root,
            "coder",
            ["github:read_file"],
            client_secret=CODER_SECRET,
            subject_token_dpop=sign_off,
        )
        assert coder.dpop_jkt == coder_key.thumbprint
        res = coder_ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
        assert res.decision_id
        assert [t.name for t in coder_ob.list_tools(coder, "github")] == ["read_file"]
        assert coder_ob.authzen_evaluate(coder, "github", "read_file", {"repo": "alice/public-x"})
        assert coder_ob.renew(coder).expires_in > 0

    # The same token without the key: refused everywhere.
    with Client(stack.url) as thief:
        # Every route says why the same way: `reason`, for the proxy as for REST routes.
        with pytest.raises(Unauthorized) as no_proof:
            thief.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
        assert no_proof.value.status == 401
        assert no_proof.value.reason == "dpop_required"
        with pytest.raises(Unauthorized) as no_proof_list:
            thief.list_tools(coder, "github")
        assert no_proof_list.value.reason == "dpop_required"
        with pytest.raises(Unauthorized) as renew:
            thief.renew(coder)
        assert renew.value.error == "dpop_required"
        assert renew.value.reason == "dpop_required"
        with pytest.raises(Unauthorized) as exchange:
            thief.exchange(coder, "tester", ["github:read_file"], client_secret=TESTER_SECRET)
        assert exchange.value.error == "dpop_required"
        assert exchange.value.reason == "dpop_required"
    # Another key does not help either.
    with Client(stack.url, dpop_key=DpopKey.generate()) as other:
        with pytest.raises(Unauthorized) as wrong_key:
            other.renew(coder)
        assert wrong_key.value.error == "invalid_dpop_proof"
        assert wrong_key.value.reason == "invalid_dpop_proof"
        with pytest.raises(Unauthorized) as wrong_key_call:
            other.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
        assert wrong_key_call.value.reason == "invalid_dpop_proof"

    # The audit log records the bound use.
    entries = admin.audit_tail(50)
    by_id = {e.id: e for e in entries}
    assert by_id[res.decision_id].dpop_bound
    assert not any(e.dpop_bound for e in entries if e.tool == "admin.root_token")
    admin.revoke_lease(root.lease)
    admin.close()


def test_dpop_server_nonce(nonce_stack: Stack) -> None:
    """RFC 9449 §8: against a server that requires its nonce, the clients pick it up from the
    first ``use_dpop_nonce`` refusal, retry once, and use it from then on."""
    url = nonce_stack.url
    admin = AdminClient(url, ADMIN_TOKEN)
    key = DpopKey.generate()
    root = admin.mint_root_dev(
        "alice", "https://idp.example", "assistant", ["github:*"], dpop_key=key
    )
    assert root.dpop_jkt == key.thumbprint

    # Raw: a proof without the nonce is refused with the nonce to use.
    resp = httpx.post(
        f"{url}/token/renew",
        headers={
            "authorization": f"DPoP {root.jwt}",
            "dpop": key.proof("POST", f"{url}/token/renew", root.jwt),
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "use_dpop_nonce"
    assert 'error="use_dpop_nonce"' in resp.headers["www-authenticate"]
    assert resp.headers["dpop-nonce"]

    with Client(url, dpop_key=key) as ob:
        res = ob.call_tool(root, "github", "read_file", {"repo": "alice/public-docs"})
        assert res.decision_id
        assert ob.renew(root).expires_in > 0
        assert ob.authzen_evaluate(root, "github", "read_file", {"repo": "alice/public-x"})
        coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=CODER_SECRET)
        assert coder.dpop_jkt == key.thumbprint

    # Through the `httpx` auth an MCP client library would use.
    auth = TokenAuth(lambda: coder, dpop_key=key)
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"repo": "alice/public-docs"}},
    }
    with httpx.Client(auth=auth) as http:
        r = http.post(
            f"{url}/mcp/github",
            json=body,
            headers={"accept": "application/json, text/event-stream"},
        )
        assert r.status_code == 200, r.text
        assert "result" in r.json()
    admin.revoke_lease(root.lease)
    admin.close()


async def test_dpop_server_nonce_async(nonce_stack: Stack) -> None:
    """The async client against the same server: its own nonce cache starts empty, so its first
    call is refused, and the retry goes out on a new connection (see ``drop_connection``)."""
    url = nonce_stack.url
    key = DpopKey.generate()
    with AdminClient(url, ADMIN_TOKEN) as admin:
        root = admin.mint_root_dev(
            "alice", "https://idp.example", "assistant", ["github:*"], dpop_key=key
        )
        async with AsyncClient(url, dpop_key=key) as ob:
            res = await ob.call_tool(root, "github", "read_file", {"repo": "alice/public-docs"})
            assert res.decision_id
            assert (await ob.renew(root)).expires_in > 0
        admin.revoke_lease(root.lease)


def test_too_many_pending_approvals(stack: Stack) -> None:
    """A run holds at most 32 pending approvals (SR-92). The next gated call is still
    ``approval_required``, with no approval to wait for: ``approval_id`` is ``None`` in the
    ``-32008`` and in the AuthZEN answer, and ``call_tool_with_approval`` raises at once."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])

    def issue(title: str) -> dict[str, Any]:
        return {"repo": "alice/public-docs", "title": title}

    ids = []
    for n in range(32):
        with pytest.raises(ApprovalRequired) as held:
            ob.call_tool(root, "github", "create_issue", issue(f"t{n}"))
        assert held.value.approval_id
        ids.append(held.value.approval_id)

    with pytest.raises(ApprovalRequired) as full:
        ob.call_tool(root, "github", "create_issue", issue("one too many"))
    assert full.value.reason == "approval_required" and full.value.decision_id
    assert full.value.approval_id is None and full.value.expires_at is None
    assert full.value.call_hash == call_hash("github", "create_issue", issue("one too many"))

    told: list[ApprovalRequired] = []
    with pytest.raises(ApprovalRequired) as again:
        ob.call_tool_with_approval(
            root, "github", "create_issue", issue("one too many"), on_approval=told.append
        )
    assert again.value.approval_id is None and told == []

    verdict = ob.authzen_evaluate(root, "github", "create_issue", issue("also too many"))
    assert not verdict and verdict.reason == "approval_required"
    assert verdict.approval_id is None and verdict.expires_at is None
    assert verdict.call_hash == call_hash("github", "create_issue", issue("also too many"))

    # A repeat of a waiting call keeps its approval, in the -32008 and in AuthZEN.
    with pytest.raises(ApprovalRequired) as repeat:
        ob.call_tool(root, "github", "create_issue", issue("t7"))
    assert repeat.value.approval_id == ids[7]
    assert ob.authzen_evaluate(root, "github", "create_issue", issue("t7")).approval_id == ids[7]

    # Deciding one makes room for the next.
    admin.decline_approval(ids[0])
    with pytest.raises(ApprovalRequired) as room:
        ob.call_tool(root, "github", "create_issue", issue("one too many"))
    assert room.value.approval_id and room.value.approval_id not in ids
    admin.revoke_lease(root.lease)
    ob.close()
    admin.close()


def test_decimal_catalog_input(decimal_stack: Stack) -> None:
    """A ``decimal`` catalog input: the SDK sends the JSON number as given, the policy compares
    it as a Cedar decimal, and a number with more than 4 fractional digits is refused with
    ``input_type_mismatch`` by the proxy, AuthZEN and the dry run alike."""
    url = decimal_stack.url
    admin = AdminClient(url, ADMIN_TOKEN)
    ob = Client(url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])

    def read(amount: Any) -> dict[str, Any]:
        return {"repo": "alice/public-docs", "path": "README.md", "amount": amount}

    for fine in (12.5, 99.9999, 0, 99):
        assert ob.call_tool(root, "github", "read_file", read(fine)).decision_id
        assert ob.authzen_evaluate(root, "github", "read_file", read(fine))
    for over in (100, 100.0, 150.25):
        with pytest.raises(Denied) as d:
            ob.call_tool(root, "github", "read_file", read(over))
        assert d.value.reason == "policy_deny"
        assert ob.authzen_evaluate(root, "github", "read_file", read(over)).reason == "policy_deny"
    for bad in (1.23456, "12.5"):
        with pytest.raises(Denied) as d:
            ob.call_tool(root, "github", "read_file", read(bad))
        assert d.value.reason == "input_type_mismatch"
        verdict = ob.authzen_evaluate(root, "github", "read_file", read(bad))
        assert not verdict and verdict.reason == "input_type_mismatch"

    assert admin.policy_evaluate("github", "read_file", read(12.5), token=root).decision == "allow"
    dry = admin.policy_evaluate("github", "read_file", read(1.23456), token=root)
    assert (dry.decision, dry.reason) == ("deny", "input_type_mismatch")
    admin.revoke_lease(root.lease)
    ob.close()
    admin.close()


def wait_for(cond: Callable[[], bool], seconds: float, what: str) -> None:
    deadline = time.monotonic() + seconds  # not time.time(): a clock step must not cut the wait
    while time.monotonic() < deadline:
        if cond():
            return
        time.sleep(0.1)
    pytest.fail(f"timed out waiting for {what}")


def test_token_refresher(stack: Stack) -> None:
    """A short-lived coder token is replaced before exp, stays usable, and revocation stops it."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    changes: list[Token] = []
    errors: list[RefreshError] = []
    with Client(stack.url) as ob:

        def exchange() -> Token:
            # Each exchange needs a fresh parent: a parent delegates to an actor once.
            root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
            return ob.exchange(
                root, "coder", ["github:read_file"], ttl_seconds=6, client_secret=CODER_SECRET
            )

        first = exchange()
        with TokenRefresher(
            ob, first, exchange, on_change=changes.append, on_error=errors.append
        ) as r:
            wait_for(lambda: bool(changes), 10, "a replacement token")
            assert r.token.jwt != first.jwt and r.token.lease != first.lease
            assert ob.call_tool(r.token, "github", "read_file", {"repo": "alice/public-docs"})
            # The lease is being renewed: the audit log has lease.renew entries.
            assert any(e.tool == "lease.renew" for e in admin.audit_tail(100))
            admin.revoke_lease(r.token.lease, "test")
            wait_for(lambda: bool(errors), 10, "the terminal error")
        assert errors[0].reason == "lease_revoked" and r.error is errors[0]
        with pytest.raises(Denied) as denied:
            ob.call_tool(r.token, "github", "read_file", {"repo": "alice/public-docs"})
        assert denied.value.reason == "lease_revoked"
    admin.close()


def test_token_refresher_keeps_the_dpop_key(stack: Stack) -> None:
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    assistant_key, coder_key = DpopKey.generate(), DpopKey.generate()
    changes: list[Token] = []
    with Client(stack.url, dpop_key=coder_key) as ob:

        def exchange() -> Token:
            root = admin.mint_root_dev(
                "alice", "https://idp.example", "assistant", ["github:*"], dpop_key=assistant_key
            )
            return ob.exchange(
                root,
                "coder",
                ["github:read_file"],
                ttl_seconds=6,
                client_secret=CODER_SECRET,
                subject_dpop_key=assistant_key,
            )

        first = exchange()
        assert first.dpop_jkt == coder_key.thumbprint
        with TokenRefresher(ob, first, exchange, on_change=changes.append) as r:
            wait_for(lambda: bool(changes), 10, "a replacement token")
            assert r.error is None
            assert r.token.dpop_jkt == coder_key.thumbprint
            assert ob.call_tool(r.token, "github", "read_file", {"repo": "alice/public-docs"})
            assert ob.renew(r.token).expires_in > 0
    admin.close()


def run_example(stack: Stack, script: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "ATTENUO_SERVER": stack.url, "ATTENUO_ADMIN_TOKEN": ADMIN_TOKEN}
    return subprocess.run(
        [sys.executable, str(ROOT / "examples" / "python-agent" / script)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_example_agent(stack: Stack) -> None:
    proc = run_example(stack, "agent.py")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # The delegated Prefix constraint stops the private repo before policy is even asked.
    assert proc.stdout.count("not allowed (capability_denied") == 2
    # The run limit (one distinct repo) stops the second public repo.
    assert "not allowed (budget_exhausted" in proc.stdout
    # create_issue asks for an approval; after the operator's grant the retry is allowed.
    assert "approval_required (-32008)" in proc.stdout
    assert "retried once with the grant: allowed" in proc.stdout
    assert "stopping: lease_revoked" in proc.stdout
    assert "chain ok=True" in proc.stdout


def test_example_mcp_client(stack: Stack) -> None:
    pytest.importorskip("mcp")
    proc = run_example(stack, "mcp_client_example.py")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "tools the token may call: ['read_file']" in proc.stdout
    assert "allowed:" in proc.stdout
    assert "denied:" in proc.stdout


# ---- filtered export and revocation by selector ---------------------------------------------


@pytest.fixture
def fresh_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    """A stack of its own, for a test that must be the first to open an MCP session (the fake
    upstream hands every caller the same session id, and the proxy binds it to the first)."""
    yield from run_stack(tmp_path_factory.mktemp("attenuo-it-fresh"))


def test_export_filtered_on_tool_and_decision(stack: Stack, tmp_path: Path) -> None:
    from attenuo.audit import ExportError, verify_export

    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=CODER_SECRET)
    # A widening exchange: refused, and recorded as a `deny` of tool `token.exchange`.
    with pytest.raises(ApiError) as widen:
        ob.exchange(coder, "tester", ["github:create_issue"], client_secret=TESTER_SECRET)
    assert widen.value.error == "invalid_scope"

    lines = list(admin.audit_export(tool="token.exchange", decision="deny"))
    header, rest = lines[0], lines[1:]
    assert header["type"] == "header"
    assert header["filter"] == {"tool": "token.exchange", "decision": "deny"}
    entries = [o for o in rest if o["type"] == "entry"]
    assert entries, "the refused exchange should be exported"
    assert {(e["record"]["tool"], e["record"]["decision"]) for e in entries} == {
        ("token.exchange", "deny")
    }
    assert any(
        e["record"].get("chain_id") == root.lease
        and e["record"].get("reason") == "exchange_widening"
        for e in entries
    )
    # The allowed exchange of the same run is not in it.
    allowed = list(admin.audit_export(tool="token.exchange", decision="allow"))
    assert any(o["type"] == "entry" and o["record"].get("chain_id") == root.lease for o in allowed)

    # Offline verification refuses the filtered file: its chain has gaps.
    jwks = httpx.get(f"{stack.url}/.well-known/jwks.json").json()
    path = tmp_path / "filtered.jsonl"
    path.write_text("".join(json.dumps(o) + "\n" for o in lines))
    with pytest.raises(ExportError, match="filtered"):
        verify_export(path, checkpoint_public_keys=jwks)

    # An unknown decision is the server's 400.
    with pytest.raises(ApiError) as bad:
        list(admin.audit_export(decision="maybe"))  # type: ignore[arg-type]
    assert bad.value.status == 400
    admin.revoke_lease(root.lease)
    admin.close()
    ob.close()


def test_revoke_by_chain_id_preview_then_for_real(stack: Stack) -> None:
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    user = "alice"  # the demo config grants roots to alice only
    root = admin.mint_root_dev(user, "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=CODER_SECRET)
    both = sorted([root.lease, coder.lease])

    # A preview changes nothing and writes nothing.
    head = admin.audit_head()
    preview = admin.revoke_by_selector(chain_id=root.lease, preview=True)
    assert preview.preview and preview.selector == {"chain_id": root.lease}
    assert sorted(preview.matched) == both and sorted(preview.revoked) == both
    assert (preview.matched_count, preview.revoked_count, preview.truncated) == (2, 2, False)
    assert preview.reason is None and preview.audit_id is None
    assert admin.audit_head() == head
    assert admin.lease_status(root.lease).active
    by_user = admin.revoke_by_selector(user=user, preview=True)
    assert by_user.selector == {"user": user} and root.lease in by_user.matched
    assert ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"}).decision_id

    # For real: the chain is revoked and the revocation is audited.
    done = admin.revoke_by_selector(chain_id=root.lease, reason="run went wrong")
    assert not done.preview and sorted(done.matched) == both and sorted(done.revoked) == both
    assert done.revoked_count == 2 and done.reason == "run went wrong"
    assert done.audit_id is not None
    record = admin.audit_record(done.audit_id).entry
    assert (record.tool, record.kind) == ("admin.lease.revoke", "lease_revoke")
    assert not admin.lease_status(coder.lease).active
    with pytest.raises(Denied) as after:
        ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
    assert after.value.reason == "lease_revoked"

    # Nothing is left to match, and an unknown chain is an empty answer, not an error.
    again = admin.revoke_by_selector(chain_id=root.lease, preview=True)
    assert again.matched == [] and again.revoked == [] and again.revoked_count == 0
    unknown = admin.revoke_by_selector(chain_id="no-such-chain", preview=True)
    assert unknown.matched == [] and unknown.revoked == []
    admin.close()
    ob.close()


def test_revoke_by_session(fresh_stack: Stack, caplog: pytest.LogCaptureFixture) -> None:
    admin = AdminClient(fresh_stack.url, ADMIN_TOKEN)
    ob = Client(fresh_stack.url)

    # A session the server never recorded resolves to no chain: an empty answer.
    unknown = admin.revoke_by_selector(session="no-such-session", preview=True)
    assert unknown.preview and unknown.matched == [] and unknown.revoked == []
    assert unknown.selector["chain_ids"] == []
    assert len(unknown.selector["session_tag"]) == 12
    assert "no-such-session" not in json.dumps(unknown.selector)

    # Open a session through the proxy; the server binds it to the caller's chain.
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=CODER_SECRET)
    sid = ob.initialize(coder, "github")
    assert sid, "the fake upstream assigns a session id"
    both = sorted([root.lease, coder.lease])

    with caplog.at_level("DEBUG"):
        preview = admin.revoke_by_selector(session=sid, preview=True)
        assert preview.selector["chain_ids"] == [root.lease]
        assert sorted(preview.matched) == both and sorted(preview.revoked) == both
        assert admin.lease_status(coder.lease).active

        done = admin.revoke_by_selector(session=sid, reason="session hijacked")
    assert not done.preview and sorted(done.revoked) == both and done.audit_id is not None
    assert sid not in json.dumps(done.selector) and sid not in repr(done)
    assert sid not in caplog.text
    with pytest.raises(Denied) as after:
        ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"}, session_id=sid)
    assert after.value.reason == "lease_revoked"
    admin.close()
    ob.close()


# ---- cross-language export verification ------------------------------------------------------

TS_DIST = ROOT / "sdk" / "typescript" / "dist" / "index.js"


def test_dry_run_with_a_stated_budget_session_approval_and_usage(stack: Stack) -> None:
    """The dry run's request overrides reach a real server: each answer says it decided on
    the stated figures (``source == "request"``), a stated budget that runs out refuses with
    the limit it hit, and nothing is charged or audited."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(
        root,
        "coder",
        [Capability("github", "read_file").with_limits(calls=2)],
        client_secret=CODER_SECRET,
    )
    read = {"repo": "alice/public-docs", "path": "README.md"}
    head = admin.audit_head()

    # From the store: a fresh run, nothing used, no labels.
    live = admin.policy_evaluate("github", "read_file", read, token=coder)
    assert (live.decision, live.reason) == ("allow", "policy_allow")
    assert live.budget is not None and live.budget.source == "store" and live.budget.limited
    assert live.labels is not None and live.labels.source == "store"
    assert not live.labels.tainted

    # Stated: one call left on the `calls: 2` limit, and a tainted run.
    session = StatedSession(tainted_by=["web/fetch"], untrusted_args=["path"])
    ok = admin.policy_evaluate(
        "github",
        "read_file",
        read,
        token=coder,
        budget=StatedBudget(calls_remaining=1),
        session=session,
        usage=StatedUsage(calls=3, amount=7, destination_seen=True),
    )
    assert (ok.decision, ok.reason) == ("allow", "policy_allow") and ok.limit is None
    assert ok.budget is not None and ok.budget.source == "request" and ok.budget.limited
    assert ok.budget.calls_remaining == 1
    assert ok.labels == EvaluationLabels(True, ["web/fetch"], True, ["path"], "request")
    assert ok.usage == EvaluationUsage(3, 7, True, "request")

    # The stated figures run out: refused as the live call would be, with the limit it hit.
    spent = admin.policy_evaluate(
        "github",
        "read_file",
        read,
        token=coder,
        budget=StatedBudget(calls_remaining=0),
        session=session,
    )
    assert (spent.decision, spent.reason) == ("deny", "budget_exhausted")
    assert spent.budget is not None and spent.budget.source == "request"
    assert spent.labels is not None and spent.labels.source == "request"
    assert spent.limit == BudgetLimit(hop=1, kind="calls", used=2, arg=None, max=2)
    # A stated budget without usage decides on zero usage, said to come from the request.
    assert spent.usage == EvaluationUsage(0, 0, False, "request")

    # A stated approval: create_issue asks without one and passes with one.
    issue = {"repo": "alice/public-docs", "title": "typo"}
    asked = admin.policy_evaluate("github", "create_issue", issue, token=root)
    assert asked.reason == "approval_required" and asked.approval_by is None
    granted = admin.policy_evaluate(
        "github", "create_issue", issue, token=root, approval=StatedApproval(by="operator")
    )
    assert (granted.decision, granted.approval_by) == ("allow", "operator")

    # The server checks the blocks: its 400 comes back as ApiError.
    with pytest.raises(ApiError) as bad:
        admin.policy_evaluate("github", "read_file", read, token=coder, session={"x": True})
    assert (bad.value.status, bad.value.error) == (400, "invalid_request")
    with pytest.raises(ApiError) as bad_usage:
        admin.policy_evaluate("github", "read_file", read, token=coder, usage=StatedUsage(calls=-1))
    assert bad_usage.value.status == 400

    # Nothing was audited or charged: the live run still has both calls.
    assert admin.audit_head() == head
    for _ in range(2):
        assert ob.call_tool(coder, "github", "read_file", read).decision_id
    with pytest.raises(Denied) as over:
        ob.call_tool(coder, "github", "read_file", read)
    assert over.value.reason == "budget_exhausted"
    # The refusal names the limit, as the dry run did.
    assert over.value.limit == BudgetLimit(hop=1, kind="calls", used=2, arg=None, max=2)
    assert over.value.data["limit"] == over.value.limit.to_json()
    admin.revoke_lease(root.lease)
    admin.close()
    ob.close()


def cli_binary() -> Path:
    given = os.environ.get("ATTENUO_BIN_DIR")
    if given:
        return Path(given) / "attenuo"
    return cargo_executable(["-p", "attenuo-cli"], "attenuo")


def run_cli(stack: Stack, cli: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "ATTENUO_SERVER": stack.url, "ATTENUO_ADMIN_TOKEN": ADMIN_TOKEN}
    return subprocess.run([str(cli), *args], env=env, capture_output=True, text=True, timeout=60)


def verify_with_typescript(export: Path, jwks: Path) -> dict[str, object]:
    script = (
        f"import {{ verifyExport }} from {json.dumps(TS_DIST.as_uri())};"
        "import { readFileSync } from 'node:fs';"
        "const [e, j] = process.argv.slice(1);"
        "try { console.log(JSON.stringify(await verifyExport({ path: e },"
        " { checkpointPublicKeys: JSON.parse(readFileSync(j, 'utf8')) }))); }"
        " catch (err) { console.log(JSON.stringify({ error: String(err.message) })); }"
    )
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(export), str(jwks)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert isinstance(out, dict)
    return out


def test_one_mutated_byte_is_rejected_at_the_same_seq_by_rust_python_and_typescript(
    stack: Stack, tmp_path: Path
) -> None:
    from attenuo.audit import ExportError, verify_export

    cli = cli_binary()
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)

    # Every kind of record: root token (and its admin record), exchange, decision, renewal,
    # revocation.
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(
        root, "coder", [Capability("github", "read_file")], client_secret=CODER_SECRET
    )
    ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs", "path": "README.md"})
    ob.renew(coder)
    admin.revoke_lease(coder.lease, "cross-language test")
    admin.audit_checkpoint()  # countersign the head: the strict check needs no unsigned tail

    jwks = tmp_path / "jwks.json"
    jwks.write_text(httpx.get(f"{stack.url}/.well-known/jwks.json").text)
    export = tmp_path / "export.jsonl"
    proc = run_cli(stack, cli, "audit", "export", "--out", str(export))
    assert proc.returncode == 0, proc.stderr
    objs = [json.loads(line) for line in export.read_text().splitlines()]
    entries = [o for o in objs if o["type"] == "entry"]
    kinds = {e["record"]["kind"] for e in entries}
    assert {"root_token", "admin", "exchange", "decision", "lease_renew", "lease_revoke"} <= kinds
    ours = [e for e in entries if e["record"].get("chain_id") == root.lease]
    assert {e["record"]["kind"] for e in ours} >= {"root_token", "exchange", "decision"}

    def rust(path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return run_cli(
            stack,
            cli,
            "--json",
            "audit",
            "verify",
            "--file",
            str(path),
            "--jwks",
            str(jwks),
            *extra,
        )

    def python(path: Path) -> object:
        return verify_export(path, checkpoint_public_keys=json.loads(jwks.read_text()))

    have_ts = TS_DIST.exists() and shutil.which("node") is not None
    if os.environ.get("ATTENUO_REQUIRE_TS") == "1":
        assert have_ts, "build sdk/typescript (npm run build) first"

    # Clean: all three accept.
    p0 = rust(export)
    assert p0.returncode == 0, p0.stdout
    clean = python(export)
    assert clean.ok  # type: ignore[attr-defined]
    if have_ts:
        assert verify_with_typescript(export, jwks)["ok"] is True

    # One byte of one entry's record changes: all three name the same seq.
    target = entries[len(entries) // 2]
    out_lines = export.read_text().splitlines(keepends=True)
    (idx,) = [i for i, ln in enumerate(out_lines) if f'"seq":{target["seq"]},"type":"entry"' in ln]
    needle = '"chain_digest":"'
    pos = out_lines[idx].index(needle) + len(needle)
    old = out_lines[idx][pos]
    out_lines[idx] = out_lines[idx][:pos] + ("0" if old != "0" else "1") + out_lines[idx][pos + 1 :]
    bad = tmp_path / "bad.jsonl"
    bad.write_text("".join(out_lines))

    proc = rust(bad)
    assert proc.returncode != 0, proc.stdout
    assert json.loads(proc.stdout)["first_bad_seq"] == target["seq"]
    report = python(bad)
    assert not report.ok and report.first_bad_seq == target["seq"]  # type: ignore[attr-defined]
    if have_ts:
        ts = verify_with_typescript(bad, jwks)
        assert ts["ok"] is False and ts["firstBadSeq"] == target["seq"]

    # A filtered export is refused by all three (its chain has gaps by construction).
    filtered = tmp_path / "filtered.jsonl"
    proc = run_cli(stack, cli, "audit", "export", "--kind", "decision", "--out", str(filtered))
    assert proc.returncode == 0, proc.stderr
    only = [json.loads(line) for line in filtered.read_text().splitlines()]
    assert only[0]["filter"] == {"kind": "decision"}
    assert {o["record"]["kind"] for o in only if o["type"] == "entry"} == {"decision"}
    assert rust(filtered).returncode != 0
    with pytest.raises(ExportError, match="filtered"):
        python(filtered)
    if have_ts:
        assert "filtered" in str(verify_with_typescript(filtered, jwks)["error"])

    # --chain-id keeps one run, whatever its kinds.
    proc = run_cli(stack, cli, "audit", "export", "--chain-id", root.lease, "--out", str(filtered))
    assert proc.returncode == 0, proc.stderr
    mine = [json.loads(line) for line in filtered.read_text().splitlines()]
    assert {o["record"]["chain_id"] for o in mine if o["type"] == "entry"} == {root.lease}
    assert len([o for o in mine if o["type"] == "entry"]) == len(ours)
    admin.close()
    ob.close()


# ---- cross-language check of shipped checkpoints (SR-21) -------------------------------------


def cross_check_with_typescript(export: Path, shipped: Path, jwks: Path) -> dict[str, object]:
    script = (
        f"import {{ crossCheck }} from {json.dumps(TS_DIST.as_uri())};"
        "import { readFileSync } from 'node:fs';"
        "const [e, s, j] = process.argv.slice(1);"
        "try { console.log(JSON.stringify(await crossCheck({ path: e }, { path: s },"
        " { checkpointPublicKeys: JSON.parse(readFileSync(j, 'utf8')) }))); }"
        " catch (err) { console.log(JSON.stringify({ error: String(err.message) })); }"
    )
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(export), str(shipped), str(jwks)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert isinstance(out, dict)
    return out


def sign_checkpoint(
    key: Ed25519PrivateKey, kid: str, seq: int, head: str, at: str
) -> dict[str, Any]:
    ctx = b"attenuo-checkpoint-v1"
    payload = rfc8785.dumps([seq, head, at, kid])
    sig = key.sign(struct.pack(">I", len(ctx)) + ctx + payload)
    return {
        "seq": seq,
        "head_hash": head,
        "at": at,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode(),
    }


def envelope(cp: Mapping[str, Any]) -> str:
    env = {
        "checkpoint": cp,
        "checkpoint_sha256": hashlib.sha256(rfc8785.dumps(cp)).hexdigest(),
        "format": "attenuo-shipped-checkpoint-v1",
        "kid": cp["kid"],
        "public_url": None,
        "signature": cp["signature"],
    }
    return rfc8785.dumps(env).decode() + "\n"


def test_shipped_checkpoint_tampering_is_reported_at_the_same_seq_by_rust_python_and_typescript(
    sink_stack: Stack, tmp_path: Path
) -> None:
    from attenuo.audit import cross_check, verify_export

    stack = sink_stack
    key = stack.issuer_key
    assert key is not None
    cli = cli_binary()
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)

    # Three stretches of activity, each countersigned (and so shipped to the file sink).
    shipped_cps: list[dict[str, Any]] = []
    for _ in range(3):
        root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
        coder = ob.exchange(
            root, "coder", [Capability("github", "read_file")], client_secret=CODER_SECRET
        )
        ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs", "path": "R.md"})
        shipped_cps.append(admin.audit_checkpoint())
    sink = stack.work / "shipped.jsonl"
    wait_for(
        lambda: sink.exists() and len(sink.read_text().splitlines()) >= 3,
        10,
        "the file sink to receive three checkpoints",
    )

    jwks = tmp_path / "jwks.json"
    jwks.write_text(httpx.get(f"{stack.url}/.well-known/jwks.json").text)
    kid = json.loads(jwks.read_text())["keys"][0]["kid"]
    export = tmp_path / "export.jsonl"
    proc = run_cli(stack, cli, "audit", "export", "--out", str(export))
    assert proc.returncode == 0, proc.stderr
    objs = [json.loads(line) for line in export.read_text().splitlines()]
    cp_seqs = sorted(o["seq"] for o in objs if o["type"] == "checkpoint")
    assert len(cp_seqs) >= 3, cp_seqs
    shipped = tmp_path / "shipped.jsonl"
    shutil.copy2(sink, shipped)
    shipped_lines = shipped.read_text().splitlines(keepends=True)
    shipped_seqs = [json.loads(ln)["checkpoint"]["seq"] for ln in shipped_lines]
    assert set(cp_seqs[-3:]) <= set(shipped_seqs)
    first, second, third = cp_seqs[-3:]

    keys = json.loads(jwks.read_text())
    have_ts = TS_DIST.exists() and shutil.which("node") is not None
    if os.environ.get("ATTENUO_REQUIRE_TS") == "1":
        assert have_ts, "build sdk/typescript (npm run build) first"

    def findings(exp: Path, ship: Path) -> list[tuple[int, int, str]]:
        """The mismatches all three implementations report: (seq, shipped line, reason)."""
        proc = run_cli(
            stack, cli, "--json", "audit", "verify", "--file", str(exp), "--jwks", str(jwks),
            "--checkpoints", str(ship),
        )  # fmt: skip
        rust_report = json.loads(proc.stdout)["shipped"]
        assert proc.returncode == (0 if rust_report["ok"] else 2), proc.stdout
        rust = [(m["seq"], m["line"], m["reason"]) for m in rust_report["mismatches"]]
        py_report = cross_check(exp, ship, checkpoint_public_keys=keys)
        py = [(m.seq, m.line, m.reason) for m in py_report.mismatches]
        assert py == rust
        counts = ("shipped", "in_range", "matched", "beyond_range")
        assert [getattr(py_report, c) for c in counts] == [rust_report[c] for c in counts]
        assert py_report.ok is rust_report["ok"]
        if have_ts:
            ts_report = cross_check_with_typescript(exp, ship, jwks)
            assert [(m["seq"], m["line"], m["reason"]) for m in ts_report["mismatches"]] == rust  # type: ignore[attr-defined]
            assert ts_report["ok"] is rust_report["ok"]
            assert ts_report["inRange"] == rust_report["in_range"]
            assert ts_report["matched"] == rust_report["matched"]
        return rust

    # Clean: nothing to report.
    assert findings(export, shipped) == []

    # 1. Re-signed after shipping. The attacker holds the host and the issuer key: they change a
    #    record after the first checkpoint, recompute the chain and sign fresh checkpoints.
    entries = [o for o in objs if o["type"] == "entry"]
    victim = next(e["seq"] for e in entries if e["seq"] > first)
    prev = entries[0]["prev_hash"]
    new_hash: dict[int, str] = {}
    for e in entries:
        if e["seq"] >= victim:
            e["record"] = {**e["record"], "reason": "rewritten"}
        e["prev_hash"] = prev
        e["entry_hash"] = prev = entry_hash(e["seq"], prev, e["record"])
        new_hash[e["seq"]] = e["entry_hash"]
    forged = []
    for o in objs:
        if o["type"] == "checkpoint" and o["seq"] >= victim:
            o.update(
                sign_checkpoint(key, kid, o["seq"], new_hash[o["seq"]], "2026-10-24T00:00:00Z")
            )
        forged.append(o)
    resigned = tmp_path / "resigned.jsonl"
    resigned.write_text("".join(json.dumps(o) + "\n" for o in forged))
    assert verify_export(resigned, checkpoint_public_keys=keys).ok  # alone it verifies
    got = findings(resigned, shipped)
    assert [g[0] for g in got] == [second, third]
    assert "RE-SIGNED after shipping" in got[0][2]

    # 2. A checkpoint deleted from the export.
    deleted = tmp_path / "deleted.jsonl"
    deleted.write_text(
        "".join(
            line
            for line in export.read_text().splitlines(keepends=True)
            if not (json.loads(line)["type"] == "checkpoint" and json.loads(line)["seq"] == second)
        )
    )
    got = findings(deleted, shipped)
    assert [g[0] for g in got] == [second]
    assert "deleted after shipping" in got[0][2]

    # 3. Two different shipped copies for one seq (the second is signed with the same key).
    twin = sign_checkpoint(key, kid, second, "ab" * 32, "2026-10-24T00:00:00Z")
    twice = tmp_path / "twice.jsonl"
    twice.write_text("".join(shipped_lines) + envelope(twin))
    got = findings(export, twice)
    assert got[0][0] == second and "two different checkpoints for this seq" in got[0][2]

    # 4. A shipped copy that does not verify: a signature that is not the issuer's.
    third_line = next(ln for ln in shipped_lines if json.loads(ln)["checkpoint"]["seq"] == third)
    bad_cp = json.loads(third_line)["checkpoint"]
    other_key = Ed25519PrivateKey.generate()
    bad_cp["signature"] = sign_checkpoint(other_key, kid, third, bad_cp["head_hash"], bad_cp["at"])[
        "signature"
    ]
    lines_with_bad = [envelope(bad_cp) if ln == third_line else ln for ln in shipped_lines]
    unverifiable = tmp_path / "unverifiable.jsonl"
    unverifiable.write_text("".join(lines_with_bad))
    got = findings(export, unverifiable)
    assert [g[0] for g in got] == [third]
    assert "shipped checkpoint does not verify" in got[0][2]
    admin.close()
    ob.close()


# ---- K-5: budget refund, AuthZEN batch and discovery, user decision, session close ---------


def test_refund_budget(stack: Stack) -> None:
    """An allowed call charged to a ``calls`` limit is refunded once by its decision id: the
    run gets the call back, a second refund is 409, an unknown id 404."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(
        root,
        "coder",
        [Capability("github", "read_file").with_limits(calls=1)],
        client_secret=CODER_SECRET,
    )
    read = {"repo": "alice/public-docs", "path": "README.md"}
    first = ob.call_tool(coder, "github", "read_file", read)
    assert first.decision_id
    with pytest.raises(Denied) as spent:
        ob.call_tool(coder, "github", "read_file", read)
    assert spent.value.reason == "budget_exhausted"

    refund = admin.refund_budget(first.decision_id, "upstream failed")
    assert refund.decision_id == first.decision_id
    assert refund.refunded >= 1 and refund.reason == "upstream failed"
    assert refund.audit_id is not None
    assert ob.call_tool(coder, "github", "read_file", read).decision_id  # the call is back

    with pytest.raises(ApiError) as again:
        admin.refund_budget(first.decision_id)
    assert (again.value.status, again.value.error) == (409, "already_refunded")
    assert again.value.decision_id is None
    with pytest.raises(ApiError) as unknown:
        admin.refund_budget("00000000-0000-4000-8000-000000000000")
    assert (unknown.value.status, unknown.value.error) == (404, "not_found")
    admin.revoke_lease(root.lease)
    ob.close()
    admin.close()


async def test_authzen_batch_and_discovery(stack: Stack) -> None:
    """A batch is one decision per call, in order; ``deny_on_first_deny`` stops at the first
    deny; discovery names this server's endpoints. The async client agrees."""
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=CODER_SECRET)
    read = {"repo": "alice/public-docs", "path": "README.md"}
    issue = {"repo": "alice/public-docs", "title": "t"}

    allow, deny = ob.authzen_evaluate_batch(
        coder,
        [AuthzenEvaluation("github", "read_file", read), ("github", "create_issue", issue)],
    )
    assert allow and allow.decision_id and allow.error is None
    assert not deny and deny.reason == "capability_denied" and deny.decision_id

    stopped = ob.authzen_evaluate_batch(
        coder,
        [("github", "create_issue", issue), ("github", "read_file", read)],
        semantic="deny_on_first_deny",
    )
    assert [d.decision for d in stopped] == [False]

    with pytest.raises(Unauthorized):
        ob.authzen_evaluate_batch("not-a-token", [("github", "read_file", read)])

    cfg = ob.authzen_configuration()
    assert cfg.policy_decision_point == stack.url
    assert cfg.access_evaluation_endpoint == f"{stack.url}/access/v1/evaluation"
    assert cfg.access_evaluations_endpoint == f"{stack.url}/access/v1/evaluations"

    async with AsyncClient(stack.url) as aob:
        assert (await aob.authzen_configuration()) == cfg
        (one,) = await aob.authzen_evaluate_batch(coder, [("github", "read_file", read)])
        assert one.decision
    admin.revoke_lease(root.lease)
    ob.close()
    admin.close()


def test_close_session(fresh_stack: Stack) -> None:
    """``DELETE /mcp/{server}`` reaches the upstream; another run's attempt on the session is
    the proxy's audited ``session_mismatch``; an unknown session is its ``-32600``."""
    stack = fresh_stack
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    coder = ob.exchange(root, "coder", ["github:read_file"], client_secret=CODER_SECRET)
    sid = ob.initialize(coder, "github")
    assert sid, "the fake upstream assigns a session id"
    other = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
    with pytest.raises(Denied) as mismatch:
        ob.close_session(other, "github", sid)
    assert mismatch.value.reason == "session_mismatch" and mismatch.value.decision_id
    assert ob.close_session(coder, "github", sid) is True
    with pytest.raises(RpcError) as unknown:
        ob.close_session(coder, "github", "no-such-session")
    assert unknown.value.code == -32600
    admin.revoke_lease(other.lease)
    admin.revoke_lease(root.lease)
    ob.close()
    admin.close()


class Idp:
    """A stand-in OIDC issuer: an Ed25519 key, its JWKS served on a local port."""

    ISSUER = "https://idp.example"

    def __init__(self) -> None:
        import http.server
        import threading

        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(Encoding.Raw, _PublicFormat.Raw)
        jwks = json.dumps(
            {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "idp-1", "x": _b64(raw)}]}
        ).encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(jwks)))
                self.end_headers()
                self.wfile.write(jwks)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/jwks"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def id_token(self, subject: str, audience: str, jti: str) -> str:
        now = int(time.time())
        head = {"alg": "EdDSA", "typ": "JWT", "kid": "idp-1"}
        claims = {
            "iss": self.ISSUER,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + 300,
            "jti": jti,
        }
        signing = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(claims).encode())}"
        return f"{signing}.{_b64(self.key.sign(signing.encode()))}"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def idp_stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Stack, Idp]]:
    """The demo stack with ``[[idps]]`` trusting a local issuer, so a test can sign the
    originating user's ID token."""
    idp = Idp()
    section = f'[[idps]]\nissuer = "{Idp.ISSUER}"\njwks_url = "{idp.url}"\n\n'
    try:
        for s in run_stack(tmp_path_factory.mktemp("attenuo-it-idp"), section):
            yield s, idp
    finally:
        idp.server.shutdown()


def test_user_decides_an_approval_with_their_id_token(idp_stack: tuple[Stack, Idp]) -> None:
    """``POST /approvals/{id}`` with the originating user's ID token: a delegation token is
    refused, the user's token grants, the granted call goes through, and the same ID token
    cannot decide a second time."""
    stack, idp = idp_stack
    admin = AdminClient(stack.url, ADMIN_TOKEN)
    ob = Client(stack.url)
    root = admin.mint_root_dev("alice", Idp.ISSUER, "assistant", ["github:*"])
    issue = {"repo": "alice/public-docs", "title": "from the user"}
    with pytest.raises(ApprovalRequired) as held:
        ob.call_tool(root, "github", "create_issue", issue)
    approval_id = held.value.approval_id
    assert approval_id

    with pytest.raises(ApiError) as agent:
        ob.grant_approval(approval_id, root.jwt)
    assert (agent.value.status, agent.value.error) == (403, "agent_token_refused")
    with pytest.raises(ApiError) as other:
        ob.grant_approval(approval_id, idp.id_token("mallory", "demo-approval-page", "j-0"))
    assert (other.value.status, other.value.error) == (403, "wrong_user")

    id_token = idp.id_token("alice", "demo-approval-page", "j-1")
    granted = ob.grant_approval(approval_id, id_token)
    assert granted.state == "granted" and granted.usable
    assert granted.approver is not None and granted.approver["by"] == "user"
    result = ob.call_tool(
        root, "github", "create_issue", issue, approval_token=granted.approval_token
    )
    assert result.decision_id

    with pytest.raises(ApprovalRequired) as second:
        ob.call_tool(root, "github", "create_issue", {**issue, "title": "again"})
    assert second.value.approval_id
    with pytest.raises(ApiError) as replay:
        ob.decline_approval(second.value.approval_id, id_token)
    assert (replay.value.status, replay.value.error) == (400, "invalid_grant")
    declined = ob.decline_approval(
        second.value.approval_id, idp.id_token("alice", "demo-approval-page", "j-2")
    )
    assert declined.state == "declined"
    admin.revoke_lease(root.lease)
    ob.close()
    admin.close()
