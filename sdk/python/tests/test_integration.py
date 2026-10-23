"""The GitHub-leak scenario through the SDK, against the real server and a fake MCP upstream.

Skipped unless ``ONBEHALF_INTEGRATION=1``. Needs ``cargo``. Builds ``onbehalf-server`` and the
``fake_mcp`` example (honours ``CARGO_TARGET_DIR``), starts both on free ports with the demo
config from ``examples/github-leak-demo``, and plays the scenario from ``run.sh``.

Set ``ONBEHALF_BIN_DIR`` to a directory holding prebuilt ``onbehalf-server`` and
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
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from onbehalf import (
    AdminClient,
    ApiError,
    AsyncClient,
    Capability,
    Client,
    Denied,
    Prefix,
    Unauthorized,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("ONBEHALF_INTEGRATION") != "1", reason="set ONBEHALF_INTEGRATION=1 to run"
    ),
]

ROOT = Path(__file__).resolve().parents[3]
DEMO = ROOT / "examples" / "github-leak-demo"
ADMIN_TOKEN = "demo-admin-token"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def cargo_executable(args: list[str], name: str) -> Path:
    """Build with cargo and return the path of the executable it reports for target ``name``.

    Caveat: when several checkouts share one ``CARGO_TARGET_DIR``, another checkout's build can
    replace ``debug/<name>`` after ours. If the scenario fails oddly there (for example a token
    header the repo does not produce), pin the binaries with ``ONBEHALF_BIN_DIR``.
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
    given = os.environ.get("ONBEHALF_BIN_DIR")
    if given:
        d = Path(given)
        fake = d / "examples" / "fake_mcp"
        return d / "onbehalf-server", fake if fake.exists() else d / "fake_mcp"
    return (
        cargo_executable(["-p", "onbehalf-server"], "onbehalf-server"),
        cargo_executable(
            ["-p", "onbehalf-proxy", "--features", "testing", "--example", "fake_mcp"], "fake_mcp"
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
    work = tmp_path_factory.mktemp("onbehalf-it")
    built_server, built_fake = binaries()
    # Copy them: a shared CARGO_TARGET_DIR can be rebuilt under us mid-test.
    server_bin = work / "onbehalf-server"
    fake_bin = work / "fake_mcp"
    shutil.copy2(built_server, server_bin)
    shutil.copy2(built_fake, fake_bin)
    ob_port, mcp_port = free_port(), free_port()
    while mcp_port == ob_port:
        mcp_port = free_port()

    config = (
        (DEMO / "config.toml")
        .read_text()
        .replace("18080", str(ob_port))
        .replace("13001", str(mcp_port))
        .replace("examples/github-leak-demo/policy.cedar", str(DEMO / "policy.cedar"))
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
        deadline = time.time() + 20
        while time.time() < deadline:
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
    coder = ob.exchange(root, "coder", [Capability("github", "read_file")], ttl_seconds=600)
    assert coder.chain.agents == ("assistant", "coder")
    assert [str(c) for c in coder.capabilities] == ["github:read_file"]
    assert coder.lease != root.lease

    # 3. The token verifies against the server's JWKS; a tampered copy does not.
    verified = ob.inspect(coder, verify=True, issuer=stack.url, audience="onbehalf")
    assert verified.verified and verified.chain == coder.chain
    head, payload, sig = coder.jwt.split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    from onbehalf import VerificationError

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
        ob.exchange(coder, "tester", [Capability("github", "create_issue")])
    assert widen.value.status == 400 and widen.value.error == "invalid_scope"
    tester = ob.exchange(
        coder, "tester", [Capability("github", "read_file", repo=Prefix("alice/public-d"))]
    )
    assert tester.chain.depth == 3
    assert ob.call_tool(tester, "github", "read_file", {"repo": "alice/public-docs"}).decision_id
    with pytest.raises(Denied) as narrowed:
        ob.call_tool(tester, "github", "read_file", {"repo": "alice/public-other"})
    assert narrowed.value.reason == "capability_denied"

    # 10. Renewal extends the coder's lease.
    lease = ob.renew(coder)
    assert lease.lease == coder.lease and lease.expires_in > 0

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
        coder = await ob.exchange(root, "coder", ["github:read_file"])
        res = await ob.call_tool(coder, "github", "read_file", {"repo": "alice/public-docs"})
        assert res.decision_id
        with pytest.raises(Denied) as d:
            await ob.call_tool(coder, "github", "read_file", {"repo": "alice/private-x"})
        assert d.value.reason == "policy_deny"
        assert (await ob.renew(coder)).expires_in > 0
    admin.revoke_lease(root.lease)
    admin.close()


def run_example(stack: Stack, script: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "ONBEHALF_SERVER": stack.url, "ONBEHALF_ADMIN_TOKEN": ADMIN_TOKEN}
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
