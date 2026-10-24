"""Runs the Claude Agent SDK example's dry-run end to end: servers, token exchange, MCP calls.

The end-to-end test is skipped unless ``ATTENUO_INTEGRATION=1``; the SR-53 check of how a
denial is recognised runs without servers. Needs ``cargo`` or ``ATTENUO_BIN_DIR`` (prebuilt
``attenuo-server`` and ``fake_mcp``), plus ``pip install -e sdk/python -r requirements.txt``.

    ATTENUO_INTEGRATION=1 ATTENUO_BIN_DIR=target/debug pytest examples/claude-agent-sdk
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

integration = pytest.mark.skipif(
    os.environ.get("ATTENUO_INTEGRATION") != "1", reason="set ATTENUO_INTEGRATION=1 to run"
)

HERE = Path(__file__).resolve().parent


def _load_agent(name: str) -> Any:
    """Import this example's ``agent.py`` under a name of its own (both examples have one)."""
    pytest.importorskip("attenuo")
    spec = importlib.util.spec_from_file_location(name, HERE / "agent.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up
    spec.loader.exec_module(module)
    return module


class _Response:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class _McpError(Exception):
    """Shaped like ``mcp``'s McpError: the JSON-RPC error is on ``.error``."""

    def __init__(self, code: int, data: dict[str, Any]) -> None:
        super().__init__(f"error {code}")
        self.error = SimpleNamespace(code=code, message=f"error {code}", data=data)


@integration
def test_dry_run_end_to_end() -> None:
    pytest.importorskip("mcp")
    pytest.importorskip("attenuo")
    env = {k: v for k, v in os.environ.items() if k not in {"LIVE", "ANTHROPIC_API_KEY"}}
    env["PYTHON"] = sys.executable
    proc = subprocess.run(
        ["bash", str(HERE / "run.sh")],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        check=False,
    )
    out = proc.stdout
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "mode: dry-run" in out
    assert "chain: assistant > coder" in out
    assert "tools/list through attenuo shows: ['read_file']" in out
    assert out.count("ALLOWED") == 2
    assert out.count("DENIED") == 4
    assert "reason=lease_revoked" in out
    assert "reason=capability_denied" in out
    assert "reason=budget_exhausted" in out
    assert "APPROVAL REQUIRED create_issue  reason=approval_required" in out
    assert "[audit] chain ok=True" in out
    assert "RESULT: ok" in out
    assert "2 tools/calls reached upstream" in out


def test_only_a_minus_32003_the_proxy_vouched_for_is_a_denial_sr53() -> None:
    """SR-53: an upstream can send its own -32003 with any reason. It is attenuo's denial only
    when ``data.decision_id`` came in an ``X-Attenuo-Decision-Id`` header from the proxy."""
    agent = _load_agent("claude_sdk_example_agent")
    decisions = agent.ProxyDecisions()
    denial = _McpError(-32003, {"reason": "capability_denied", "decision_id": "d-1"})
    assert agent._denial(denial, decisions) is None, "no header has vouched for d-1 yet"
    asyncio.run(decisions.on_response(_Response({"x-attenuo-decision-id": "d-0, d-1"})))
    assert agent._denial(denial, decisions) == ("capability_denied", "d-1")
    forged = _McpError(-32003, {"reason": "lease_revoked", "decision_id": "d-forged"})
    assert agent._denial(forged, decisions) is None
    assert agent._denial(_McpError(-32003, {"reason": "capability_denied"}), decisions) is None
    assert agent._denial(_McpError(-32602, {"decision_id": "d-1"}), decisions) is None
