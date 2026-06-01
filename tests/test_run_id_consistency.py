import json
from pathlib import Path

from devsecops_agent.report_writer import write_json_report
from devsecops_agent.policy_engine import evaluate_policy
from devsecops_agent.config import SKILL_REPORT_PATH, MCP_AUDIT_REPORT_PATH


def test_reports_share_global_run_id(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SKILLCHAIN_RUN_ID", "run-final-001")
    skill = write_json_report({"status": "PASS", "finding_counts": {"high_or_critical": 0}}, Path(SKILL_REPORT_PATH), root=tmp_path)
    mcp = write_json_report({"status": "PASS", "finding_counts": {"high_or_critical": 0}}, Path(MCP_AUDIT_REPORT_PATH), root=tmp_path)

    assert json.loads(skill.read_text(encoding="utf-8"))["run_id"] == "run-final-001"
    assert json.loads(mcp.read_text(encoding="utf-8"))["run_id"] == "run-final-001"


def test_policy_blocks_mixed_run_id_when_global_run_is_set(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SKILLCHAIN_RUN_ID", "run-final-001")
    (tmp_path / "artifacts").mkdir(parents=True)
    (tmp_path / SKILL_REPORT_PATH).write_text(json.dumps({"status": "PASS", "run_id": "run-final-001", "finding_counts": {"high_or_critical": 0}}), encoding="utf-8")
    (tmp_path / MCP_AUDIT_REPORT_PATH).write_text(json.dumps({"status": "PASS", "run_id": "otro-run", "finding_counts": {"high_or_critical": 0}}), encoding="utf-8")

    report = evaluate_policy(root=tmp_path, mode="demo")

    assert report["status"] == "FAIL"
    assert any(finding["rule_id"] == "POLICY020" for finding in report["findings"])
