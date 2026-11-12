"""replay.py's planner arms: the FROZEN check and how the arms mirror the oracle arms."""

import json

import pytest

replay = pytest.importorskip("replay", reason="needs agentdojo installed")
import planner_grants as pg  # noqa: E402


def test_planner_arms_mirror_the_oracle_arms():
    assert set(replay.PLANNER_ARMS) <= set(replay.ARMS)
    assert not set(replay.PLANNER_ARMS) & set(replay.GRANT_ARMS)
    assert replay.PLANNER_ARMS["planner"] == "contacts"
    assert replay.PLANNER_ARMS["planner_only"] is None
    assert "grants_only" in replay.PERMIT_ALL_ARMS
    assert replay.PLANNER_ARMS["planner_nocontact"] == replay.RECIPIENT_ARMS["grants_nocontact"]


@pytest.fixture(scope="module")
def frozen_fixture(tmp_path_factory):
    root = tmp_path_factory.mktemp("planner")
    grants = root / "fixture-reads-only"
    grants.mkdir()
    grants.joinpath("banking.json").write_text(
        json.dumps(pg.fixture(pg.catalog_from_definitions("banking")))
    )
    frozen = root / "FROZEN.json"
    frozen.write_text(json.dumps(pg.freeze(grants, ["banking"], "fixture-reads-only")))
    return grants, frozen


def test_a_matching_frozen_record_outside_the_repository_loads(frozen_fixture, capsys):
    grants, frozen = frozen_fixture
    planner = replay.load_planner(grants, frozen, ["banking"])
    assert planner["source"] == "fixture-reads-only"
    assert planner["frozen_committed"] is False
    assert planner["sha256"]["banking"] == pg.sha256_file(grants / "banking.json")
    assert "not a measured run" in capsys.readouterr().out
    caps = pg.to_capabilities(planner["grants"]["banking"]["user_task_0"], "banking")
    assert all(c.server == "banking" and not c.constraints for c in caps)


def test_a_missing_frozen_record_is_refused(frozen_fixture, tmp_path):
    grants, _ = frozen_fixture
    with pytest.raises(SystemExit, match="needs a FROZEN record"):
        replay.load_planner(grants, tmp_path / "FROZEN.json", ["banking"])


def test_a_changed_grant_file_is_refused(frozen_fixture, tmp_path):
    grants, frozen = frozen_fixture
    changed = tmp_path / "g"
    changed.mkdir()
    changed.joinpath("banking.json").write_text(grants.joinpath("banking.json").read_text() + "\n")
    with pytest.raises(SystemExit, match="does not match its frozen SHA-256"):
        replay.load_planner(changed, frozen, ["banking"])


def test_a_suite_the_record_does_not_cover_is_refused(frozen_fixture):
    grants, frozen = frozen_fixture
    with pytest.raises(SystemExit, match=r"no hash for slack\.json"):
        replay.load_planner(grants, frozen, ["banking", "slack"])


def test_a_g1_source_needs_the_committed_record(frozen_fixture, tmp_path):
    grants, frozen = frozen_fixture
    record = json.loads(frozen.read_text())
    record["source"] = "G1"
    g1 = tmp_path / "FROZEN.json"
    g1.write_text(json.dumps(record))
    with pytest.raises(SystemExit, match="G1 grant source needs the committed FROZEN"):
        replay.load_planner(grants, g1, ["banking"])


def test_an_uncommitted_record_inside_the_repository_is_refused(frozen_fixture):
    grants, frozen = frozen_fixture
    inside = replay.ROOT / "evaluation/agentdojo/planner/FROZEN-test-uncommitted.json"
    inside.write_text(frozen.read_text())
    try:
        with pytest.raises(SystemExit, match="is not committed"):
            replay.load_planner(grants, inside, ["banking"])
    finally:
        inside.unlink()
