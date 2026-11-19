"""Tests for scripts/check-links.py on a small temporary tree. Run: python3 -m pytest scripts/test_check_links.py"""
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-links.py"


def make_tree(root: Path, files: dict):
    base = {
        "book.toml": '[book]\ntitle = "t"\nsrc = "docs"\n',
        "docs/SUMMARY.md": "# Summary\n\n- [Page](page.md)\n- [Guide](guides/guide.md)\n",
        "crates/core/src/lib.rs": "\n",
        "README.md": "# Readme\n",
    }
    for rel, text in {**base, **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def run(root):
    return subprocess.run([sys.executable, str(SCRIPT), "--root", str(root)],
                          capture_output=True, text=True)


def test_relative_links_inside_the_book_pass(tmp_path):
    make_tree(tmp_path, {
        "docs/page.md": "# Page\n\n## Part two\n\nSee [guide](guides/guide.md) and [here](#part-two).\n",
        "docs/guides/guide.md": "# Guide\n\nBack to [page](../page.md#part-two) and the [folder](../guides/).\n",
    })
    r = run(tmp_path)
    assert r.returncode == 0, r.stdout
    assert "all relative links ok" in r.stdout


def test_a_book_page_linking_out_of_the_book_fails_and_names_the_github_url(tmp_path):
    make_tree(tmp_path, {
        "docs/page.md": "# Page\n\nSee [lib](../crates/core/src/lib.rs) and [crates](../crates/).\n",
        "docs/guides/guide.md": "# Guide\n\n[readme](../../README.md#readme)\n",
    })
    r = run(tmp_path)
    assert r.returncode == 1
    assert "docs/page.md:3: leaves the book: ../crates/core/src/lib.rs" in r.stdout
    assert "https://github.com/attenuo-dev/attenuo/blob/main/crates/core/src/lib.rs" in r.stdout
    assert "https://github.com/attenuo-dev/attenuo/tree/main/crates" in r.stdout
    assert "https://github.com/attenuo-dev/attenuo/blob/main/README.md#readme" in r.stdout
    assert "3 broken link(s)" in r.stdout


def test_pages_outside_the_book_keep_relative_links(tmp_path):
    make_tree(tmp_path, {
        "docs/page.md": "# Page\n",
        "docs/guides/guide.md": "# Guide\n",
        "docs/not-listed.md": "[lib](../crates/core/src/lib.rs)\n",
        "CONTRIBUTING.md": "[lib](crates/core/src/lib.rs) and [docs](docs/page.md)\n",
    })
    r = run(tmp_path)
    assert r.returncode == 0, r.stdout


def test_links_in_code_are_ignored_and_missing_files_still_fail(tmp_path):
    make_tree(tmp_path, {
        "docs/page.md": "# Page\n\n`[lib](../crates/core/src/lib.rs)`\n\n```\n[x](../README.md)\n```\n",
        "docs/guides/guide.md": "# Guide\n\n[gone](../../crates/gone.rs)\n",
    })
    r = run(tmp_path)
    assert r.returncode == 1
    assert "docs/guides/guide.md:3: missing file: ../../crates/gone.rs" in r.stdout
    assert "leaves the book" not in r.stdout
