"""The Python snippets of the READMEs, checked as code.

Every fenced ``python`` block of ``sdk/python/README.md`` and of the repository README's "Python
SDK" section is

- compiled (``compile()``), so a syntax error fails;
- checked for its ``from attenuo... import`` names, so a renamed export fails;
- type-checked with mypy when it is installed (the ``dev`` extra), each snippet in a module of
  its own whose free names are declared first: ``ob`` a ``Client``, ``admin`` an
  ``AdminClient``, ``root``, ``coder`` and ``token`` a ``Token``, ``URL`` and ``url`` a ``str``,
  anything else ``Any``, and ``...`` as an argument value ``Any``. A misspelt method, a removed
  keyword argument or a renamed attribute of a result fails;
- run, when ``ATTENUO_INTEGRATION=1``, if it is self-contained: no free names and no local file
  it would need. It runs against a real ``attenuo-server`` started from ``config/example.toml``
  with ``[dev] allow_root_mint = true``, as the walkthrough's "Run the server" starts it,
  and the fake MCP upstream (binaries as in ``test_integration.py``). Its
  ``http://127.0.0.1:8080`` is replaced by the server's address.
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import importlib
import io
import os
import re
import shutil
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[3]
PAGES = [REPO / "sdk" / "python" / "README.md", REPO / "README.md"]
FENCE = re.compile(r"^```python\s*\n(.*?)^```\s*$", re.S | re.M)
# The types the type check gives to free names; the rest are Any.
KNOWN = {
    "URL": "str",
    "url": "str",
    "ob": "Client",
    "admin": "AdminClient",
    "root": "Token",
    "coder": "Token",
    "token": "Token",
}
# A snippet that names one of these reads or writes a file of the reader's: not run.
LOCAL_FILE = re.compile(r"""["'][^"']*\.(jsonl|jwk|jwt|pem)["']""")
ADMIN_TOKEN = "readme-admin-token-0123456789abcdef0123456789abcdef"
CODER_SECRET = "coder-secret-change-me"  # the example config's [[agents]] coder


@dataclass
class Snippet:
    page: Path
    line: int
    code: str

    @property
    def id(self) -> str:
        return f"{self.page.relative_to(REPO)}:{self.line}"

    def tree(self) -> ast.Module:
        return ast.parse(self.code, self.id)

    def free_names(self) -> list[str]:
        """Names read before the snippet binds them (or never bound)."""
        tree = self.tree()
        first_store: dict[str, int] = {}
        for n in ast.walk(tree):
            names: list[tuple[str, int]] = []
            if isinstance(n, ast.Import | ast.ImportFrom):
                names = [((a.asname or a.name).split(".")[0], n.lineno) for a in n.names]
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                names = [(n.id, n.lineno)]
            elif isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                names = [(n.name, n.lineno)]
            elif isinstance(n, ast.arg):
                names = [(n.arg, 0)]
            elif isinstance(n, ast.ExceptHandler) and n.name:
                names = [(n.name, n.lineno)]
            for name, line in names:
                first_store[name] = min(line, first_store.get(name, line))
        free = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if hasattr(builtins, n.id):
                    continue
                stored = first_store.get(n.id)
                if stored is None or stored > n.lineno:
                    free.add(n.id)
        return sorted(free)

    def runnable(self) -> bool:
        return not self.free_names() and not LOCAL_FILE.search(self.code)


def snippets() -> list[Snippet]:
    found = []
    for page in PAGES:
        text = page.read_text(encoding="utf-8")
        if page.name == "README.md" and page.parent == REPO:
            # Only the repository README's Python SDK section.
            start = text.index("\n## Python SDK\n")
            text_part = text[start : text.index("\n## ", start + 1)]
            offset = text[:start].count("\n")
        else:
            text_part, offset = text, 0
        for m in FENCE.finditer(text_part):
            line = offset + text_part[: m.start()].count("\n") + 1
            found.append(Snippet(page, line, m.group(1)))
    return found


ALL = snippets()


def test_every_page_has_snippets() -> None:
    for page in PAGES:
        assert any(s.page == page for s in ALL), f"no ```python block found in {page}"


@pytest.mark.parametrize("snippet", ALL, ids=lambda s: s.id)
def test_snippet_compiles_and_imports_resolve(snippet: Snippet) -> None:
    compile(snippet.code, snippet.id, "exec")
    for n in ast.walk(snippet.tree()):
        if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] == "attenuo":
            module = importlib.import_module(n.module)
            for alias in n.names:
                assert hasattr(module, alias.name), f"{snippet.id}: {n.module} has no {alias.name}"


def test_snippets_type_check(tmp_path: Path) -> None:
    mypy_api = pytest.importorskip("mypy.api")
    files = []
    for k, s in enumerate(ALL):
        prelude = ["from typing import Any", "from attenuo import AdminClient, Client, Token"]
        prelude += [f"{name}: {KNOWN.get(name, 'Any')}" for name in s.free_names()]
        prelude.append("_ANY: Any = None")
        # `client_secret=...` is a placeholder for the reader's value.
        code = re.sub(r"=\.\.\.(?=\s*[,)])", "=_ANY", s.code)
        path = tmp_path / f"snippet_{k}.py"
        path.write_text("\n".join(prelude) + "\n" + code)
        files.append((path, s, len(prelude)))
    # A config of its own: not pyproject.toml's `strict`, which would ask a README for return
    # annotations, and this checkout's source rather than an installed attenuo.
    config = tmp_path / "mypy.ini"
    config.write_text(f"[mypy]\nmypy_path = {REPO / 'sdk' / 'python' / 'src'}\n")
    out, err, status = mypy_api.run(
        [
            "--config-file",
            str(config),
            "--check-untyped-defs",
            "--no-error-summary",
            "--python-version",
            "3.10",
            # A README prints optional fields of a result it knows are set.
            "--disable-error-code",
            "union-attr",
            "--cache-dir",
            str(tmp_path / ".mypy_cache"),
            *(str(p) for p, _, _ in files),
        ]
    )
    # Report each error at its line in the README.
    where = {str(p): (s, n) for p, s, n in files}
    lines = []
    for line in out.splitlines():
        m = re.match(r"^(.*?):(\d+): (.*)$", line)
        if m and m.group(1) in where:
            s, n = where[m.group(1)]
            lines.append(f"{s.page.relative_to(REPO)}:{s.line + int(m.group(2)) - n}: {m.group(3)}")
        else:
            lines.append(line)
    assert status == 0, "\n".join(lines) + err


RUNNABLE = [s for s in ALL if s.runnable()]


def test_some_snippets_are_runnable() -> None:
    """The quick starts must stay self-contained, or nothing below runs them."""
    assert any(s.page == REPO / "README.md" for s in RUNNABLE)
    assert any(s.page.parent.name == "python" for s in RUNNABLE)


@pytest.fixture(scope="module")
def example_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """attenuo-server on config/example.toml with the dev root mint on, and the fake upstream."""
    if os.environ.get("ATTENUO_INTEGRATION") != "1":
        pytest.skip("set ATTENUO_INTEGRATION=1 to run")
    from tests.test_integration import binaries, reserve_ports

    work = tmp_path_factory.mktemp("attenuo-readme")
    built_server, built_fake = binaries()
    server_bin, fake_bin = work / "attenuo-server", work / "fake_mcp"
    shutil.copy2(built_server, server_bin)
    shutil.copy2(built_fake, fake_bin)
    port, mcp_port = reserve_ports(2)
    config = (REPO / "config" / "example.toml").read_text()
    for old, new in {
        'listen = "127.0.0.1:8080"': f'listen = "127.0.0.1:{port}"',
        "127.0.0.1:3001": f"127.0.0.1:{mcp_port}",
        '"config/policies/default.cedar"': f'"{REPO / "config" / "policies" / "default.cedar"}"',
        "\nallow_root_mint = false\n": "\nallow_root_mint = true\n",
    }.items():
        assert old in config, f"not in config/example.toml: {old}"
        config = config.replace(old, new, 1)
    (work / "data").mkdir()
    (work / "config.toml").write_text(config)
    env = {**os.environ, "ATTENUO_ADMIN_TOKEN": ADMIN_TOKEN, "RUST_LOG": "warn"}
    with contextlib.ExitStack() as stack:
        log = stack.enter_context((work / "server.log").open("wb"))
        fake_out = stack.enter_context((work / "fake.out").open("wb"))
        procs = [
            subprocess.Popen(
                [str(fake_bin), "--port", str(mcp_port)], stdout=fake_out, stderr=log, cwd=work
            ),
            subprocess.Popen(
                [str(server_bin), "--config", "config.toml"],
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=work,
                env=env,
            ),
        ]
        try:
            url = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 20
            while True:
                try:
                    if httpx.get(f"{url}/healthz", timeout=1).is_success and (
                        b"listening" in (work / "fake.out").read_bytes()
                    ):
                        break
                except httpx.HTTPError:
                    pass
                assert all(p.poll() is None for p in procs), (work / "server.log").read_text()
                assert time.monotonic() < deadline, (work / "server.log").read_text()
                time.sleep(0.1)
            yield url
        finally:
            for p in procs:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()


@pytest.mark.integration
@pytest.mark.parametrize("snippet", RUNNABLE, ids=lambda s: s.id)
def test_snippet_runs(
    snippet: Snippet, example_server: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ATTENUO_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("CODER_SECRET", CODER_SECRET)
    monkeypatch.chdir(tmp_path)
    code = snippet.code.replace("http://127.0.0.1:8080", example_server)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(compile(code, snippet.id, "exec"), {"__name__": "__readme__"})
    printed = out.getvalue()
    # The quick starts' denial, as their comments show it.
    if "create_issue" in snippet.code and "Denied" in snippet.code:
        assert "capability_denied" in printed, printed
