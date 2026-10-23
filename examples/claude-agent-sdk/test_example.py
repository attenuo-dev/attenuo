"""Runs the Claude Agent SDK example's dry-run end to end: servers, token exchange, MCP calls.

Skipped unless ``ONBEHALF_INTEGRATION=1``. Needs ``cargo`` or ``ONBEHALF_BIN_DIR`` (prebuilt
``onbehalf-server`` and ``fake_mcp``), plus ``pip install -e sdk/python -r requirements.txt``.

    ONBEHALF_INTEGRATION=1 ONBEHALF_BIN_DIR=target/debug pytest examples/claude-agent-sdk
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("ONBEHALF_INTEGRATION") != "1", reason="set ONBEHALF_INTEGRATION=1 to run"
    ),
]

HERE = Path(__file__).resolve().parent


def test_dry_run_end_to_end() -> None:
    pytest.importorskip("mcp")
    pytest.importorskip("onbehalf")
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
    assert "tools/list through onbehalf shows: ['read_file']" in out
    assert out.count("ALLOWED") == 1
    assert out.count("DENIED") == 3
    assert "reason=lease_revoked" in out
    assert "reason=capability_denied" in out
    assert "[audit] chain ok=True" in out
    assert "RESULT: ok" in out
    assert "1 tools/call reached upstream" in out
