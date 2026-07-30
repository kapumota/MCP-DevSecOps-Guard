import json
import os
from pathlib import Path

from devsecops_agent.config import MCP_AUDIT_REPORT_PATH, SKILL_REPORT_PATH
from devsecops_agent.policy_engine import (
    SCANNER_EXIT_EVIDENCE,
    evaluate_policy,
    write_policy_report,
)
from devsecops_agent.tool_evidence import build_tool_exit_record


def write_json(root: Path, relative_path: str, payload: dict) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def passing_report() -> dict:
    report: dict = {
        "status": "PASS",
        "finding_counts": {
            "high_or_critical": 0,
            "total": 0,
        },
    }

    run_id = os.environ.get("SKILLCHAIN_RUN_ID")

    if run_id:
        report["run_id"] = run_id

    return report


def test_policy_engine_fails_when_sbom_evidence_is_missing(tmp_path: Path):
    write_json(tmp_path, SKILL_REPORT_PATH, passing_report())
    write_json(tmp_path, MCP_AUDIT_REPORT_PATH, passing_report())

    report = evaluate_policy(root=tmp_path)

    assert report["status"] == "FAIL"
    assert report["decision"]["allow_merge"] is False
    assert report["finding_counts"]["high_or_critical"] >= 1


def test_policy_engine_warns_with_local_fallback_evidence(tmp_path: Path):
    from devsecops_agent.local_evidence import generate_local_evidence

    write_json(tmp_path, SKILL_REPORT_PATH, passing_report())
    write_json(tmp_path, MCP_AUDIT_REPORT_PATH, passing_report())
    write_json(tmp_path, "artifacts/agent-eval-report.json", {"status": "PASS", "metrics": {}})
    generate_local_evidence(root=tmp_path)

    report = evaluate_policy(root=tmp_path, mode="demo")

    assert report["mode"] == "demo"
    assert report["status"] == "WARN"
    assert report["blocking_issues"] == 0
    assert report["evidence_completeness_score"] == 1.0
    assert any(finding["rule_id"] == "POLICY011" for finding in report["findings"])


def test_policy_engine_fails_missing_required_report(tmp_path: Path):
    write_json(tmp_path, SKILL_REPORT_PATH, passing_report())

    report = evaluate_policy(root=tmp_path)

    assert report["status"] == "FAIL"
    assert report["decision"]["allow_merge"] is False
    assert report["finding_counts"]["high_or_critical"] >= 1


def test_policy_report_writer(tmp_path: Path):
    write_json(tmp_path, SKILL_REPORT_PATH, passing_report())
    write_json(tmp_path, MCP_AUDIT_REPORT_PATH, passing_report())
    report = evaluate_policy(root=tmp_path)
    output = write_policy_report(report, Path("artifacts/policy-report.json"), root=tmp_path)

    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded["engine"] == "skillchain-mcp-guard-policy-engine"


def write_scanner_exit_inputs(root: Path) -> None:
    for scanner, (artifact, evidence) in SCANNER_EXIT_EVIDENCE.items():
        record = build_tool_exit_record(
            root=root,
            tool=scanner,
            exit_code=0,
            artifact=artifact,
            command=f"synthetic {scanner}",
            started_at="2026-01-01T00:00:00Z",
        )
        write_json(root, evidence, record)


def write_required_policy_inputs(root: Path) -> None:
    write_json(root, SKILL_REPORT_PATH, passing_report())
    write_json(root, MCP_AUDIT_REPORT_PATH, passing_report())
    write_json(root, "artifacts/bandit.json", {"results": []})
    write_json(root, "artifacts/semgrep.json", {"results": []})
    write_json(root, "artifacts/pip-audit-runtime.json", {"dependencies": []})
    write_json(root, "artifacts/pip-audit-dev.json", {"dependencies": []})
    write_json(root, "artifacts/pip-audit-mcp.json", {"dependencies": []})
    write_json(root, "artifacts/sbom-project.json", {"bomFormat": "CycloneDX"})
    write_json(root, "artifacts/sbom-image.json", {"bomFormat": "CycloneDX"})
    write_json(root, "artifacts/grype-image.sarif", {"runs": [{"results": []}]})
    write_json(root, "artifacts/trivy-image.sarif", {"runs": [{"results": []}]})
    write_json(
        root,
        "artifacts/image-vulnerabilities-normalized.json",
        {
            "summary": {
                "unique_high_or_critical": 0,
                "critical": 0,
                "high": 0,
            },
            "vulnerabilities": [],
        },
    )
    write_json(root, "artifacts/gitleaks.sarif", {"runs": [{"results": []}]})
    write_json(root, "artifacts/scorecard.json", {"score": 10.0, "checks": []})
    write_json(root, "artifacts/zap-baseline.json", {"site": []})
    write_json(root, "artifacts/agent-eval-report.json", {"status": "PASS", "metrics": {}})
    write_scanner_exit_inputs(root)


def test_external_scanner_high_findings_block_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("STRICT_POLICY", raising=False)
    write_required_policy_inputs(tmp_path)
    (
        tmp_path / "artifacts/image-vulnerabilities-normalized.json"
    ).unlink()
    write_json(
        tmp_path,
        "artifacts/grype-image.sarif",
        {"runs": [{"results": [{"level": "error", "ruleId": "CVE-DEMO"}]}]},
    )

    report = evaluate_policy(root=tmp_path)

    assert report["status"] == "FAIL"
    assert report["decision"]["allow_merge"] is False
    assert report["finding_counts"]["high_or_critical"] >= 1


def test_external_scanner_findings_block_in_strict_policy(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STRICT_POLICY", "1")
    write_required_policy_inputs(tmp_path)
    (
        tmp_path / "artifacts/image-vulnerabilities-normalized.json"
    ).unlink()
    write_json(
        tmp_path,
        "artifacts/grype-image.sarif",
        {"runs": [{"results": [{"level": "error", "ruleId": "CVE-DEMO"}]}]},
    )

    report = evaluate_policy(root=tmp_path)

    assert report["status"] == "FAIL"
    assert report["decision"]["allow_merge"] is False
    assert report["finding_counts"]["high_or_critical"] >= 1


def test_zap_high_alert_blocks_policy(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("STRICT_POLICY", raising=False)
    write_required_policy_inputs(tmp_path)
    write_json(
        tmp_path,
        "artifacts/zap-baseline.json",
        {"site": [{"alerts": [{"riskdesc": "High (Medium)", "pluginid": "10038"}]}]},
    )

    report = evaluate_policy(root=tmp_path)

    assert report["status"] == "FAIL"
    assert report["decision"]["allow_merge"] is False
    assert any(finding["rule_id"] == "POLICY012" for finding in report["findings"])


def test_pip_audit_dev_vulnerability_blocks_policy(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("STRICT_POLICY", raising=False)
    write_required_policy_inputs(tmp_path)
    write_json(
        tmp_path,
        "artifacts/pip-audit-dev.json",
        {"dependencies": [{"name": "demo", "version": "0", "vulns": [{"id": "PYSEC-DEMO"}]}]},
    )

    report = evaluate_policy(root=tmp_path)

    assert report["status"] == "FAIL"
    assert any(
        "pip-audit-dev.json" in finding.get("evidence", "") for finding in report["findings"]
    )


def test_strict_policy_blocks_fallback_evidence(tmp_path: Path, monkeypatch):
    from devsecops_agent.local_evidence import generate_local_evidence

    monkeypatch.setenv("STRICT_POLICY", "1")
    write_json(tmp_path, SKILL_REPORT_PATH, passing_report())
    write_json(tmp_path, MCP_AUDIT_REPORT_PATH, passing_report())
    write_json(tmp_path, "artifacts/agent-eval-report.json", {"status": "PASS", "metrics": {}})
    generate_local_evidence(root=tmp_path)

    report = evaluate_policy(root=tmp_path)

    assert report["status"] == "FAIL"
    assert report["finding_counts"]["high_or_critical"] >= 1


def test_policy_mode_ci_blocks_fallback_evidence(tmp_path: Path):
    from devsecops_agent.local_evidence import generate_local_evidence

    write_json(tmp_path, SKILL_REPORT_PATH, passing_report())
    write_json(tmp_path, MCP_AUDIT_REPORT_PATH, passing_report())
    write_json(tmp_path, "artifacts/agent-eval-report.json", {"status": "PASS", "metrics": {}})
    generate_local_evidence(root=tmp_path)

    report = evaluate_policy(root=tmp_path, mode="ci")

    assert report["status"] == "FAIL"
    assert report["fallback_allowed"] is False
    assert any(finding["rule_id"] == "POLICY011" for finding in report["findings"])


def test_policy_mode_demo_marks_missing_scanners_as_low_risk(tmp_path: Path):
    write_json(tmp_path, SKILL_REPORT_PATH, passing_report())
    write_json(tmp_path, MCP_AUDIT_REPORT_PATH, passing_report())

    report = evaluate_policy(root=tmp_path, mode="demo")

    assert report["mode"] == "demo"
    assert report["status"] == "WARN"
    assert report["blocking_issues"] == 0


def test_ci_policy_blocks_missing_scanner_exit_evidence(tmp_path: Path):
    write_required_policy_inputs(tmp_path)
    (tmp_path / ".evidence/bandit-exit.json").unlink()

    report = evaluate_policy(root=tmp_path, mode="ci")

    assert report["status"] == "FAIL"
    assert any(finding["rule_id"] == "POLICY017" for finding in report["findings"])


def test_ci_policy_blocks_stale_scanner_artifact_hash(tmp_path: Path):
    write_required_policy_inputs(tmp_path)
    (tmp_path / "artifacts/bandit.json").write_text(
        json.dumps({"results": [{"issue_severity": "LOW"}]}), encoding="utf-8"
    )

    report = evaluate_policy(root=tmp_path, mode="ci")

    assert report["status"] == "FAIL"
    assert any(finding["rule_id"] == "POLICY018" for finding in report["findings"])


def test_ci_warns_for_upstream_unfixed_image_vulnerability(
    tmp_path: Path,
):
    write_required_policy_inputs(tmp_path)
    write_json(
        tmp_path,
        "artifacts/image-vulnerabilities-normalized.json",
        {
            "summary": {
                "unique_high_or_critical": 1,
                "critical": 1,
                "high": 0,
            },
            "vulnerabilities": [
                {
                    "vulnerability_id": "CVE-DEMO-UPSTREAM",
                    "package_name": "perl-base",
                    "installed_version": "1.0",
                    "severity": "CRITICAL",
                    "fixed_versions": [],
                    "statuses": ["not_fixed"],
                    "sources": ["grype", "trivy"],
                }
            ],
        },
    )

    report = evaluate_policy(root=tmp_path, mode="ci")

    assert report["status"] == "WARN"
    assert report["blocking_issues"] == 0
    assert report["decision"]["allow_merge"] is True
    assert report["decision"]["requires_human_review"] is True
    assert (
        report["image_vulnerability_policy"]["summary"]["actionable"]
        == 0
    )
    assert (
        report["image_vulnerability_policy"]["summary"][
            "review_required"
        ]
        == 1
    )


def test_ci_blocks_python_vulnerability_with_same_line_fix(
    tmp_path: Path,
):
    write_required_policy_inputs(tmp_path)
    write_json(
        tmp_path,
        "artifacts/image-vulnerabilities-normalized.json",
        {
            "summary": {
                "unique_high_or_critical": 1,
                "critical": 0,
                "high": 1,
            },
            "vulnerabilities": [
                {
                    "vulnerability_id": "CVE-DEMO-FIXED",
                    "package_name": "python",
                    "installed_version": "3.13.13",
                    "severity": "HIGH",
                    "fixed_versions": ["3.13.14"],
                    "statuses": ["fixed"],
                    "sources": ["grype"],
                }
            ],
        },
    )

    report = evaluate_policy(root=tmp_path, mode="ci")

    assert report["status"] == "FAIL"
    assert report["blocking_issues"] >= 1
    assert report["decision"]["allow_merge"] is False
    assert (
        report["image_vulnerability_policy"]["summary"]["actionable"]
        == 1
    )


def test_ci_reviews_python_fix_from_another_minor_line(
    tmp_path: Path,
):
    write_required_policy_inputs(tmp_path)
    write_json(
        tmp_path,
        "artifacts/image-vulnerabilities-normalized.json",
        {
            "summary": {
                "unique_high_or_critical": 1,
                "critical": 0,
                "high": 1,
            },
            "vulnerabilities": [
                {
                    "vulnerability_id": "CVE-DEMO-MIGRATION",
                    "package_name": "python",
                    "installed_version": "3.13.14",
                    "severity": "HIGH",
                    "fixed_versions": ["3.14.6", "3.15.0b2"],
                    "statuses": ["fixed"],
                    "sources": ["grype"],
                }
            ],
        },
    )

    report = evaluate_policy(root=tmp_path, mode="ci")

    assert report["status"] == "WARN"
    assert report["blocking_issues"] == 0
    assert (
        report["image_vulnerability_policy"]["summary"]["actionable"]
        == 0
    )


def test_strict_blocks_upstream_risk_without_acceptance(
    tmp_path: Path,
):
    write_required_policy_inputs(tmp_path)
    write_json(
        tmp_path,
        "artifacts/image-vulnerabilities-normalized.json",
        {
            "summary": {
                "unique_high_or_critical": 1,
                "critical": 1,
                "high": 0,
            },
            "vulnerabilities": [
                {
                    "vulnerability_id": "CVE-DEMO-STRICT",
                    "package_name": "libc6",
                    "installed_version": "1.0",
                    "severity": "CRITICAL",
                    "fixed_versions": [],
                    "statuses": ["wont_fix"],
                    "sources": ["grype"],
                }
            ],
        },
    )

    report = evaluate_policy(root=tmp_path, mode="strict")

    assert report["status"] == "FAIL"
    assert report["blocking_issues"] >= 1
