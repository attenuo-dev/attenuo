"""Tests for scripts/rename.py on a small temporary tree. Run: python3 -m pytest scripts/test_rename.py"""
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "rename.py"


def make_tree(root: Path):
    files = {
        "crates/onbehalf-core/src/lib.rs": 'pub const CTX: &str = "onbehalf-ou-v2"; // on behalf of\nuse onbehalf_core::X;\n',
        "sdk/python/src/onbehalf/__init__.py": "class OnbehalfClient: ...\nimport os; os.environ['ONBEHALF_TOKEN']\n",
        "docs/spec/rfc-0001-onbehalf.md": "# RFC onbehalf\n",
        "docs/log/2026-10-22.md": "# Log\n\nSee [rfc](../spec/rfc-0001-onbehalf.md); the onbehalf CLI.\n",
        "Cargo.lock": 'name = "onbehalf-core"\n',
        "CHANGELOG.md": "# Changelog\n\n## [Unreleased]\n\n### Changed\n\n- x onbehalf\n",
        "scripts/rename.py": "onbehalf\n",
        "node_modules/x/index.js": "onbehalf\n",
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def run(root, *args):
    return subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), *args],
                          capture_output=True, text=True)


def test_dry_run_changes_nothing(tmp_path):
    make_tree(tmp_path)
    r = run(tmp_path, "--to", "creance", "--dry-run")
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "crates/onbehalf-core").is_dir()
    assert "Cargo.lock" in r.stdout and "cargo update" in r.stdout


def test_apply_four_spellings_and_paths(tmp_path):
    make_tree(tmp_path)
    r = run(tmp_path, "--to", "creance", "--apply", "--force")
    assert r.returncode == 0, r.stderr
    lib = (tmp_path / "crates/creance-core/src/lib.rs").read_text()
    assert '"creance-ou-v2"' in lib and "use creance_core::X;" in lib
    assert "on behalf of" in lib  # prose is untouched
    py = (tmp_path / "sdk/python/src/creance/__init__.py").read_text()
    assert "CreanceClient" in py and "CREANCE_TOKEN" in py
    assert (tmp_path / "docs/spec/rfc-0001-creance.md").read_text() == "# RFC creance\n"
    assert not (tmp_path / "crates/onbehalf-core").exists()
    # history: text kept, link target fixed, note added
    log = (tmp_path / "docs/log/2026-10-22.md").read_text()
    assert "(../spec/rfc-0001-creance.md)" in log and "the onbehalf CLI" in log and "renamed from `onbehalf`" in log
    # lockfile, vendored dir and the tool itself untouched; changelog gets its entry
    assert "onbehalf" in (tmp_path / "Cargo.lock").read_text()
    assert "onbehalf" in (tmp_path / "node_modules/x/index.js").read_text()
    assert (tmp_path / "scripts/rename.py").read_text() == "onbehalf\n"
    assert "renamed from `onbehalf`" in (tmp_path / "CHANGELOG.md").read_text()


def test_keep_legacy_contexts_and_rerun(tmp_path):
    make_tree(tmp_path)
    run(tmp_path, "--to", "creance", "--apply", "--force", "--keep-legacy-contexts")
    assert '"onbehalf-ou-v2"' in (tmp_path / "crates/creance-core/src/lib.rs").read_text()


def test_rejects_bad_names(tmp_path):
    assert run(tmp_path, "--to", "Bad-Name").returncode != 0
    assert run(tmp_path, "--to", "onbehalf").returncode != 0
