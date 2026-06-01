from __future__ import annotations

import json
from pathlib import Path

from devsecops_agent.cli import generate_product_reports, main as cli_main
from devsecops_agent.config import DASHBOARD_HTML_PATH, PRODUCT_STATUS_PATH
from devsecops_agent.dashboard import REALISTIC_SCORE_CEILING, build_product_status, render_dashboard_html, write_dashboard_html


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def prepare_minimal_reports(root: Path) -> None:
    write_json(
        root / "artifacts/skill-scan-report.json",
        {"status": "PASS", "finding_counts": {"high_or_critical": 0, "medium": 0, "low": 0, "total": 0}},
    )
    write_json(
        root / "artifacts/mcp-audit-report.json",
        {"status": "PASS", "overall_risk": "low", "finding_counts": {"high_or_critical": 0, "medium": 0, "low": 0, "total": 0}},
    )
    write_json(
        root / "artifacts/agent-eval-report.json",
        {
            "status": "PASS",
            "metrics": {
                "case_count": 5,
                "passed_case_count": 5,
                "attack_block_rate": 1.0,
                "false_positive_rate": 0.0,
                "allowed_task_success_rate": 1.0,
            },
        },
    )
    write_json(
        root / "artifacts/policy-report.json",
        {
            "status": "WARN",
            "finding_counts": {"high_or_critical": 0, "medium": 0, "low": 1, "total": 1},
            "evidence_completeness": {"score": 0.5, "missing": ["artifacts/sbom-syft-project.json"]},
        },
    )


def test_build_product_status_from_existing_reports(tmp_path: Path) -> None:
    prepare_minimal_reports(tmp_path)

    report = build_product_status(root=tmp_path)

    assert report["product"] == "SkillChain-MCP Guard"
    assert report["status"] == "WARN"
    assert report["security_score"] < REALISTIC_SCORE_CEILING
    assert report["score_ceiling"] == REALISTIC_SCORE_CEILING
    assert report["risk_summary"]["evidence_completeness_score"] == 0.5
    assert "riesgo" in report["executive_summary"]["score_note"].lower()
    assert len(report["control_coverage"]) == 4



def test_clean_reports_do_not_show_perfect_security_score(tmp_path: Path) -> None:
    write_json(
        tmp_path / "artifacts/skill-scan-report.json",
        {"status": "PASS", "finding_counts": {"high_or_critical": 0, "medium": 0, "low": 0, "total": 0}},
    )
    write_json(
        tmp_path / "artifacts/mcp-audit-report.json",
        {"status": "PASS", "overall_risk": "low", "finding_counts": {"high_or_critical": 0, "medium": 0, "low": 0, "total": 0}},
    )
    write_json(
        tmp_path / "artifacts/agent-eval-report.json",
        {
            "status": "PASS",
            "metrics": {
                "case_count": 5,
                "passed_case_count": 5,
                "attack_block_rate": 1.0,
                "false_positive_rate": 0.0,
                "allowed_task_success_rate": 1.0,
            },
        },
    )
    write_json(
        tmp_path / "artifacts/policy-report.json",
        {
            "status": "PASS",
            "finding_counts": {"high_or_critical": 0, "medium": 0, "low": 0, "total": 0},
            "evidence_completeness": {"score": 1.0, "missing": []},
        },
    )

    report = build_product_status(root=tmp_path)

    assert report["status"] == "PASS"
    assert report["security_score"] == REALISTIC_SCORE_CEILING
    assert report["security_score"] < 100
    assert "seguridad absoluta" in report["executive_summary"]["score_note"]

def test_dashboard_html_is_self_contained(tmp_path: Path) -> None:
    prepare_minimal_reports(tmp_path)
    report = build_product_status(root=tmp_path)

    html = render_dashboard_html(report)
    output = write_dashboard_html(report, Path(DASHBOARD_HTML_PATH), root=tmp_path)

    assert "SkillChain-MCP Guard" in html
    assert "Lectura ejecutiva" in html
    assert "Cobertura de controles" in html
    assert "Recommended actions" in html
    assert output.is_file()
    assert "<!doctype html>" in output.read_text(encoding="utf-8")


def test_cli_status_writes_product_status(tmp_path: Path, capsys) -> None:
    prepare_minimal_reports(tmp_path)

    exit_code = cli_main(["--root", str(tmp_path), "status", "--json"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "SkillChain-MCP Guard" in captured.out
    assert (tmp_path / PRODUCT_STATUS_PATH).is_file()


def test_generate_product_reports_on_temp_project_root(tmp_path: Path) -> None:
    root = tmp_path
    (root / "skills/devsecops-triage").mkdir(parents=True)
    (root / "skills/reproducible-research-report").mkdir(parents=True)
    (root / "skills/supply-chain-attestation").mkdir(parents=True)
    skill_body = """---
name: safe-test-skill
description: Safe skill fixture.
---

### Safe Skill

#### Goal

Review local evidence.

#### Inputs

- Local JSON evidence.

#### Procedure

1. Read evidence.
2. Summarize observed findings.

#### Output Format

- Summary.

#### Safety Limits

- Do not request credentials.

#### Acceptance Criteria

- Use only local evidence.
"""
    for path in (
        root / "skills/devsecops-triage/SKILL.md",
        root / "skills/reproducible-research-report/SKILL.md",
        root / "skills/supply-chain-attestation/SKILL.md",
    ):
        path.write_text(skill_body, encoding="utf-8")

    outputs = generate_product_reports(root)

    assert outputs["skill_report"].is_file()
    assert outputs["mcp_report"].is_file()
    assert outputs["evaluation_report"].is_file()
    assert outputs["policy_report"].is_file()
    assert outputs["product_status"].is_file()
    assert outputs["dashboard"].is_file()


def test_cli_policy_check_fails_by_default_on_fail(tmp_path: Path, capsys) -> None:
    write_json(
        tmp_path / "artifacts/skill-scan-report.json",
        {"status": "FAIL", "finding_counts": {"high_or_critical": 1, "total": 1}},
    )
    write_json(
        tmp_path / "artifacts/mcp-audit-report.json",
        {"status": "PASS", "finding_counts": {"high_or_critical": 0, "total": 0}},
    )

    exit_code = cli_main(["--root", str(tmp_path), "policy-check", "--json"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "FAIL" in captured.out


def test_cli_policy_check_can_be_inspected_without_failing(tmp_path: Path, capsys) -> None:
    write_json(
        tmp_path / "artifacts/skill-scan-report.json",
        {"status": "FAIL", "finding_counts": {"high_or_critical": 1, "total": 1}},
    )
    write_json(
        tmp_path / "artifacts/mcp-audit-report.json",
        {"status": "PASS", "finding_counts": {"high_or_critical": 0, "total": 0}},
    )

    exit_code = cli_main(["--root", str(tmp_path), "policy-check", "--json", "--no-fail-on-fail"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "FAIL" in captured.out
