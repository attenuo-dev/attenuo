"""stats.py against hand-computed values."""

import json
import math

import pytest
import stats


def test_wilson_matches_hand_computed_intervals():
    # 5/10: centre (0.5 + z^2/20) / (1 + z^2/10) = 0.5, half-width 0.26340.
    lo, hi = stats.wilson(5, 10)
    assert lo == pytest.approx(0.23659, abs=1e-5)
    assert hi == pytest.approx(0.76341, abs=1e-5)
    # 0/10: lower bound 0, upper z^2 / (n + z^2) = 3.8415 / 13.8415.
    lo, hi = stats.wilson(0, 10)
    assert lo == 0.0
    assert hi == pytest.approx(3.841459 / 13.841459, abs=1e-6)
    assert stats.wilson(0, 0) is None


def test_mcnemar_exact_matches_binomial_tails():
    assert stats.mcnemar_exact(0, 5) == pytest.approx(2 / 32)  # 0.0625
    assert stats.mcnemar_exact(1, 4) == pytest.approx(2 * 6 / 32)  # 0.375
    assert stats.mcnemar_exact(4, 1) == pytest.approx(0.375)
    assert stats.mcnemar_exact(3, 3) == 1.0  # capped
    assert stats.mcnemar_exact(0, 0) == 1.0
    assert stats.mcnemar_exact(0, 10) == pytest.approx(2 / 1024)


def test_quantile_interpolates_like_numpy_type_7():
    assert stats.quantile([0.0, 1.0, 2.0, 3.0, 4.0], 0.5) == 2.0
    assert stats.quantile([0.0, 10.0], 0.25) == 2.5
    assert stats.quantile([1.0, 2.0, 3.0, 4.0], 0.975) == pytest.approx(3.925)


def test_bootstrap_of_identical_clusters_is_degenerate():
    # Every cluster has one pair landed in A only and one in neither: diff is 1/2 always.
    clusters = {("s", u): [(1, 0), (0, 0)] for u in range(5)}
    assert stats.cluster_bootstrap(clusters, resamples=200) == (0.5, 0.5)


def test_bootstrap_is_seeded_and_contains_the_estimate():
    clusters = {("s", u): [(u % 2, 0), (u % 3 == 0, 0)] for u in range(12)}
    clusters = {k: [(int(a), b) for a, b in v] for k, v in clusters.items()}
    first = stats.cluster_bootstrap(clusters, resamples=500, seed=7)
    assert first == stats.cluster_bootstrap(clusters, resamples=500, seed=7)
    point = sum(a - b for v in clusters.values() for a, b in v) / 24
    assert first[0] <= point <= first[1]


def test_compare_counts_pairs_and_discordance():
    a = {("s", "u1", "i1"): 1, ("s", "u1", "i2"): 0, ("s", "u2", "i1"): 1, ("s", "u2", "i2"): 1}
    b = {("s", "u1", "i1"): 0, ("s", "u1", "i2"): 0, ("s", "u2", "i1"): 1, ("s", "u2", "i2"): 0}
    b[("s", "u3", "i1")] = 1  # not in A: left out of the paired analysis
    r = stats.compare(a, b, resamples=100)
    assert (r["n"], r["a"], r["b"], r["unpaired_b"]) == (4, 3, 1, 1)
    assert (r["both"], r["only_a"], r["only_b"], r["neither"]) == (1, 2, 0, 1)
    assert r["mcnemar_p"] == pytest.approx(0.5)  # b=2, c=0: 2 * 1/4
    assert r["diff"] == pytest.approx(0.5)
    assert r["clusters"] == 2


def test_run_reads_rows_and_skips_missing_arms(tmp_path):
    rows = []
    for arm, landed, util in (("planner", [1, 0], True), ("suite", [1, 1], False)):
        rows.append({"arm": arm, "suite": "s", "user": "u0", "attack": None, "utility": util})
        for i, x in enumerate(landed):
            rows.append({"arm": arm, "suite": "s", "user": "u0", "attack": f"i{i}", "landed": x})
    (tmp_path / "rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    out, skipped = stats.run(tmp_path, [("planner", "suite"), ("planner", "grants")], 50)
    assert skipped == ["planner vs grants: arm not in results"]
    landed, utility = out
    assert (landed["stats"]["a"], landed["stats"]["b"], landed["stats"]["n"]) == (1, 2, 2)
    assert (utility["stats"]["a"], utility["stats"]["b"]) == (1, 0)
    table = stats.markdown(out)
    assert "| attacks landed | planner | suite | 2 |" in table
    assert not math.isnan(landed["stats"]["mcnemar_p"])
