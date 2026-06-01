"""Configuración central del agente DevSecOps."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Final


REPO_ROOT: Final[Path] = Path(os.environ.get("DEVSECOPS_REPO_ROOT", Path.cwd())).resolve()
ARTIFACT_DIRS: Final[tuple[str, ...]] = ("artifacts", ".evidence")
SKILLS_DIR: Final[str] = "skills"
MAX_TEXT_BYTES: Final[int] = 200_000
MIN_TIMEOUT_SECONDS: Final[int] = 5
MAX_TIMEOUT_SECONDS: Final[int] = 900

ALLOWED_MAKE_TARGETS: Final[frozenset[str]] = frozenset(
    {
        "unit",
        "lint",
        "type-check",
        "coverage",
        "integration-tests",
        "sast",
        "sca",
        "secret-scan",
        "sbom",
        "scan-image",
        "compose-up",
        "compose-down",
        "dast",
        "smoke",
        "skills-validate",
        "skill-scan",
        "mcp-audit",
        "policy-check",
        "agent-eval",
        "evidence-pack",
        "product-status",
        "product-scan",
        "dashboard",
        "product-demo",
        "local-evidence",
        "demo-local",
        "security-local",
        "security-ci",
        "release-verify",
    }
)

REQUIRED_SKILL_SECTIONS: Final[tuple[str, ...]] = (
    "goal",
    "inputs",
    "procedure",
    "output format",
    "acceptance criteria",
    "safety limits",
)

SKILL_REPORT_PATH: Final[str] = "artifacts/skill-scan-report.json"
MCP_AUDIT_REPORT_PATH: Final[str] = "artifacts/mcp-audit-report.json"
POLICY_REPORT_PATH: Final[str] = "artifacts/policy-report.json"
EVIDENCE_MANIFEST_PATH: Final[str] = "artifacts/evidence-manifest.json"
EVALUATION_REPORT_PATH: Final[str] = "artifacts/agent-eval-report.json"
PIP_AUDIT_REPORT_PATHS: Final[tuple[str, ...]] = (
    "artifacts/pip-audit-runtime.json",
    "artifacts/pip-audit-dev.json",
    "artifacts/pip-audit-mcp.json",
)
LEGACY_PIP_AUDIT_REPORT_PATH: Final[str] = "artifacts/pip-audit.json"
PRODUCT_STATUS_PATH: Final[str] = "artifacts/product-status.json"
DASHBOARD_HTML_PATH: Final[str] = "artifacts/dashboard.html"

REQUIRED_POLICY_REPORTS: Final[tuple[str, ...]] = (
    SKILL_REPORT_PATH,
    MCP_AUDIT_REPORT_PATH,
)

RECOMMENDED_EVIDENCE_FILES: Final[tuple[str, ...]] = (
    "artifacts/bandit.json",
    "artifacts/semgrep.json",
    *PIP_AUDIT_REPORT_PATHS,
    "artifacts/sbom-project.json",
    "artifacts/sbom-image.json",
    "artifacts/grype-image.sarif",
    "artifacts/trivy-image.sarif",
    "artifacts/gitleaks.sarif",
    "artifacts/scorecard.json",
    "artifacts/zap-baseline.json",
    EVALUATION_REPORT_PATH,
)
