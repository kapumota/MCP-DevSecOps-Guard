from pathlib import Path

from devsecops_agent.evaluation_harness import run_controlled_evaluation


def test_controlled_evaluation_runs_realistic_builtin_cases(tmp_path: Path):
    report = run_controlled_evaluation(root=tmp_path)

    assert report["status"] == "PASS"
    assert report["metrics"]["case_count"] >= 500
    assert report["metrics"]["known_limitation_case_count"] == 0
    assert report["metrics"]["precision"] >= 0.99
    assert report["metrics"]["recall"] >= 0.99
    assert report["metrics"]["f1"] >= 0.99
    assert report["metrics"]["false_positive"] == 0
    assert report["metrics"]["false_negative"] == 0
    assert report["metrics"]["attack_block_rate_by_category"]["unicode_homoglyphs"]["attack_block_rate"] == 1.0
    assert "known_limitations" in report
