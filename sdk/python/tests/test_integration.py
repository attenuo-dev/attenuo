"""The GitHub-leak scenario through the SDK, against the real server and a fake MCP upstream.

Skipped unless ``ATTENUO_INTEGRATION=1``. Needs ``cargo``. Builds ``attenuo-server`` and the
``fake_mcp`` example (honours ``CARGO_TARGET_DIR``), starts both on free ports with the demo
config from ``examples/github-leak-demo``, and plays the scenario from ``run.sh``.

Set ``ATTENUO_BIN_DIR`` to a directory holding prebuilt ``attenuo-server`` and
``examples/fake_mcp`` (or ``fake_mcp``) to skip the build.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from attenuo import (
    AdminClient,
    ApiError,
    AsyncClient,
    Capability,
    Client,
    Denied,
    DpopKey,
    Prefix,
    RefreshError,
    Token,
    TokenRefresher,
    Unauthorized,
)
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


def run_stack(work: Path, token_section: str = "") -> Iterator[Stack]:
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
        .replace("examples/github-leak-demo/policy.cedar", str(DEMO / "policy.cedar"))
        .replace("[audit]\n", f"{token_section}[audit]\n", 1)
    )
    (work / "config.toml").write_text(config)

    procs: list[subprocess.Popen[bytes]] = []
    fake_out = (work / "fake-mcp.out").open("wb")
    fake_log = (work / "fake-mcp.log").open("wb")
    server_log = (work / "server.log").open("wb")
    try:
        procs.append(
            subprocess.Popen(
                [str(fake_bin), "--port", str(mcp_port)], stdout=fake_out, stderr=fake_log
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

    # 11. A bad bearer is a 401, not a denial.
    with pytest.raises(Unauthorized):
        ob.call_tool("not.a.token", "github", "read_file", {"repo": "alice/public-docs"})

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
    with pytest.raises(ApiError):
        ob.renew(coder)  # a revoked lease is final

    # 13. The audit log has every decision, and its hash chain verifies.
    report = admin.audit_verify()
    assert report.ok and report.entries >= 8
    entries = admin.audit_tail(200)
    by_id = {e.id: e for e in entries}
    assert by_id[allowed_decision].decision == "allow"
    assert by_id[policy_denied.value.decision_id].reason == "policy_deny"
    assert by_id[cap_denied.value.decision_id].reason == "capability_denied"
    assert by_id[after.value.decision_id].reason == "lease_revoked"

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
        with pytest.raises(Unauthorized) as no_proof:
            thief.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
        assert no_proof.value.status == 401
        with pytest.raises(Unauthorized) as renew:
            thief.renew(coder)
        assert renew.value.error == "dpop_required"
        with pytest.raises(Unauthorized) as exchange:
            thief.exchange(coder, "tester", ["github:read_file"], client_secret=TESTER_SECRET)
        assert exchange.value.error == "dpop_required"
    # Another key does not help either.
    with Client(stack.url, dpop_key=DpopKey.generate()) as other:
        with pytest.raises(Unauthorized) as wrong_key:
            other.renew(coder)
        assert wrong_key.value.error == "invalid_dpop_proof"

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
    assert "stopping: lease_revoked" in proc.stdout
    assert "chain ok=True" in proc.stdout


def test_example_mcp_client(stack: Stack) -> None:
    pytest.importorskip("mcp")
    proc = run_example(stack, "mcp_client_example.py")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "tools the token may call: ['read_file']" in proc.stdout
    assert "allowed:" in proc.stdout
    assert "denied:" in proc.stdout


# ---- cross-language export verification ------------------------------------------------------

TS_DIST = ROOT / "sdk" / "typescript" / "dist" / "index.js"


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
