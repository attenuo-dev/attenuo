"""The bundle exporter: its field allowlist, and its leak check on a real export."""

import json
from types import SimpleNamespace

import pytest

planner_bundle = pytest.importorskip("planner_bundle", reason="needs agentdojo installed")


class Params:
    @staticmethod
    def model_json_schema():
        return {"properties": {"x": {"type": "string"}}, "type": "object"}


def test_entries_hold_only_the_allowlisted_fields():
    # A task object carries much more than the prompt: none of it may be exported.
    task = SimpleNamespace(
        ID="user_task_0",
        PROMPT="Do the thing.",
        GROUND_TRUTH_OUTPUT="secret",
        COMMENT="secret",
        ground_truth=lambda env: ["secret"],
        utility=lambda *a: True,
    )
    assert planner_bundle.task_entry(task) == {"id": "user_task_0", "prompt": "Do the thing."}
    assert tuple(planner_bundle.task_entry(task)) == planner_bundle.TASK_FIELDS
    tool = SimpleNamespace(
        name="get_x", description="Gets x.", parameters=Params, dependencies={"env": "secret"}
    )
    out = planner_bundle.tool_entry(tool)
    assert tuple(out) == planner_bundle.TOOL_FIELDS
    assert out["read"] is True
    assert (
        planner_bundle.tool_entry(SimpleNamespace(**{**vars(tool), "name": "send_x"}))["read"]
        is False
    )


def test_principal_holds_only_identifiers():
    env = SimpleNamespace(inbox=SimpleNamespace(account_email="me@example.org"))
    assert planner_bundle.principal("workspace", env) == {"email": "me@example.org"}
    assert planner_bundle.principal("slack", env) is None
    bank = SimpleNamespace(bank_account=SimpleNamespace(iban="XX00", balance=10))
    assert planner_bundle.principal("banking", bank) == {"iban": "XX00"}


@pytest.fixture(scope="module")
def banking_bundle(tmp_path_factory):
    out = tmp_path_factory.mktemp("bundle") / "b"
    planner_bundle.export(out, ["banking"])
    return out


def test_a_real_export_passes_the_allowlist_and_the_leak_check(banking_bundle):
    files = sorted(p.relative_to(banking_bundle).as_posix() for p in banking_bundle.rglob("*.*"))
    assert files == [
        "INSTRUCTIONS.md",
        "MANIFEST.json",
        "banking/principal.json",
        "banking/tasks.json",
        "banking/tools.json",
        "planner_grants.py",
    ]
    assert planner_bundle.allowlist_problems(banking_bundle, ["banking"]) == []
    report = planner_bundle.leak_check(banking_bundle, ["banking"])
    assert report["ok"], report["failures"] + report["forbidden_words"]
    assert report["checked"] > 50


def test_the_allowlist_check_flags_extra_fields_and_files(banking_bundle, tmp_path):
    import shutil

    copy = tmp_path / "copy"
    shutil.copytree(banking_bundle, copy)
    tasks = json.loads((copy / "banking" / "tasks.json").read_text())
    tasks[0]["difficulty"] = "easy"
    (copy / "banking" / "tasks.json").write_text(json.dumps(tasks))
    (copy / "banking" / "notes.txt").write_text("x")
    problems = planner_bundle.allowlist_problems(copy, ["banking"])
    assert "unexpected file banking/notes.txt" in problems
    assert any("tasks.json: fields" in p for p in problems)


def test_the_leak_check_finds_a_planted_value(banking_bundle, tmp_path):
    import shutil

    copy = tmp_path / "copy"
    shutil.copytree(banking_bundle, copy)
    values, _ = planner_bundle.forbidden_values("banking", None)
    tasks = {t["id"]: t["prompt"] for t in json.loads((copy / "banking/tasks.json").read_text())}
    # A ground-truth value its own prompt does not contain, planted in a tool description.
    planted = next(
        (owner, v)
        for kind, owner, v in values
        if kind == "user_ground_truth" and v.lower() not in tasks[owner].lower()
    )
    tools = json.loads((copy / "banking/tools.json").read_text())
    tools[0]["description"] += f" e.g. {planted[1]}"
    (copy / "banking/tools.json").write_text(json.dumps(tools))
    report = planner_bundle.leak_check(copy, ["banking"])
    assert not report["ok"]
    assert any(f[3] == planted[1] for f in report["failures"])
    # And a word naming the benchmark's attacks.
    (copy / "INSTRUCTIONS.md").write_text("Watch for prompt injection.")
    assert planner_bundle.leak_check(copy, ["banking"])["forbidden_words"]
