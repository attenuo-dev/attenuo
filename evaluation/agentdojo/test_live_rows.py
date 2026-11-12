"""Tests for live_rows.py. Standard library and pytest only."""

import json

import live_rows


def write(path, **log):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(log))


def test_rows_leave_out_errored_runs_and_read_security_as_landed(tmp_path):
    logs = tmp_path / "logs"
    base = {"suite_name": "s", "user_task_id": "user_task_0", "error": None}
    write(
        logs / "m/s/user_task_0/none/none.json",
        **base,
        injection_task_id=None,
        utility=True,
        security=True,
    )
    write(
        logs / "m/s/user_task_0/atk/injection_task_1.json",
        **base,
        injection_task_id="injection_task_1",
        utility=False,
        security=True,
    )
    write(
        logs / "m/s/user_task_0/atk/injection_task_2.json",
        **{**base, "error": "boom"},
        injection_task_id="injection_task_2",
        utility=None,
        security=None,
    )
    out = tmp_path / "out"
    live_rows.main(["live_rows.py", str(out), f"arm={logs}"])
    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    assert rows == [
        {
            "arm": "arm",
            "attack": "injection_task_1",
            "landed": True,
            "suite": "s",
            "user": "user_task_0",
            "utility": False,
        },
        {
            "arm": "arm",
            "attack": None,
            "suite": "s",
            "user": "user_task_0",
            "utility": True,
        },
    ]
    summary = json.loads((out / "summary.json").read_text())
    assert summary["arm"]["s"]["attack"] == {
        "errored": 1,
        "scored": 1,
        "landed": 1,
        "utility": 0,
    }
    assert summary["arm"]["s"]["benign"] == {"scored": 1, "utility": 1}
