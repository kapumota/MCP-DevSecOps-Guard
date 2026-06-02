"""Motor de políticas para convertir evidencias DevSecOps en una decisión de gate."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from .artifacts import read_json_if_exists
from .config import (
    LEGACY_PIP_AUDIT_REPORT_PATH,
    MCP_AUDIT_REPORT_PATH,
    PIP_AUDIT_REPORT_PATHS,
    POLICY_REPORT_PATH,
    RECOMMENDED_EVIDENCE_FILES,
    REPO_ROOT,
    REQUIRED_POLICY_REPORTS,
    SKILL_REPORT_PATH,
)
from .report_writer import write_json_report
from .security_models import RiskLevel, ScanStatus, SecurityFinding
from .tool_evidence import verify_tool_exit_record

PASSING_STATUSES: frozenset[str] = frozenset({ScanStatus.PASS.value})
WARNING_STATUSES: frozenset[str] = frozenset({ScanStatus.WARN.value})
FAILING_STATUSES: frozenset[str] = frozenset({ScanStatus.FAIL.value})
BLOCKING_EVIDENCE_FILES: frozenset[str] = frozenset(
    {"artifacts/sbom-project.json", "artifacts/sbom-image.json"}
)
STRICT_POLICY_ENV = "STRICT_POLICY"
STRICT_POLICY_TRUE_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on"})
LOCAL_EVIDENCE_GENERATOR = "skillchain-local-evidence"
STRICT_REQUIRED_EVIDENCE_FILES: frozenset[str] = frozenset(RECOMMENDED_EVIDENCE_FILES)

SCANNER_EXIT_EVIDENCE: dict[str, tuple[str, str]] = {
    "bandit": ("artifacts/bandit.json", ".evidence/bandit-exit.json"),
    "semgrep": ("artifacts/semgrep.json", ".evidence/semgrep-exit.json"),
    "pip-audit-runtime": (
        "artifacts/pip-audit-runtime.json",
        ".evidence/pip-audit-runtime-exit.json",
    ),
    "pip-audit-dev": ("artifacts/pip-audit-dev.json", ".evidence/pip-audit-dev-exit.json"),
    "pip-audit-mcp": ("artifacts/pip-audit-mcp.json", ".evidence/pip-audit-mcp-exit.json"),
    "gitleaks": ("artifacts/gitleaks.sarif", ".evidence/gitleaks-exit.json"),
    "syft-project": ("artifacts/sbom-project.json", ".evidence/syft-project-exit.json"),
    "syft-image": ("artifacts/sbom-image.json", ".evidence/syft-image-exit.json"),
    "grype": ("artifacts/grype-image.sarif", ".evidence/grype-exit.json"),
    "trivy": ("artifacts/trivy-image.sarif", ".evidence/trivy-exit.json"),
    "openssf-scorecard": ("artifacts/scorecard.json", ".evidence/scorecard-exit.json"),
    "zap": ("artifacts/zap-baseline.json", ".evidence/zap-exit.json"),
}

FALLBACK_EVIDENCE_FILES: frozenset[str] = frozenset(
    {
        "artifacts/bandit.json",
        "artifacts/semgrep.json",
        *PIP_AUDIT_REPORT_PATHS,
        LEGACY_PIP_AUDIT_REPORT_PATH,
        "artifacts/grype-image.sarif",
        "artifacts/trivy-image.sarif",
        "artifacts/gitleaks.sarif",
        "artifacts/zap-baseline.json",
    }
)

PolicyMode = Literal["demo", "ci", "strict"]
VALID_POLICY_MODES: frozenset[str] = frozenset({"demo", "ci", "strict"})


def normalize_policy_mode(mode: str | None = None) -> PolicyMode:
    """Normaliza el perfil de policy gate.

    demo: permite evidencia fallback y reporta WARN.
    ci: exige evidencia real para scanners principales.
    strict: exige evidencia real completa para release.
    """
    if mode is None:
        if os.environ.get(STRICT_POLICY_ENV, "").strip().lower() in STRICT_POLICY_TRUE_VALUES:
            return "strict"
        env_mode = os.environ.get("SKILLCHAIN_POLICY_MODE", "strict").strip().lower()
        mode = env_mode or "strict"
    normalized = mode.strip().lower()
    if normalized not in VALID_POLICY_MODES:
        raise ValueError(f"Modo de policy inválido: {mode}. Usa demo, ci o strict.")
    return normalized  # type: ignore[return-value]


def mode_allows_fallback(mode: PolicyMode) -> bool:
    """Indica si el modo tolera evidencia fallback."""
    return mode == "demo"


def external_tool_severity() -> RiskLevel:
    """Clasifica hallazgos high/critical externos como bloqueantes."""
    return RiskLevel.HIGH


def missing_evidence_severity(relative_path: str, mode: PolicyMode) -> RiskLevel:
    """Define si la ausencia de evidencia recomendada bloquea el gate según perfil."""
    if relative_path in REQUIRED_POLICY_REPORTS:
        return RiskLevel.HIGH
    if mode in {"ci", "strict"} and relative_path in STRICT_REQUIRED_EVIDENCE_FILES:
        return RiskLevel.HIGH
    if relative_path in BLOCKING_EVIDENCE_FILES and mode != "demo":
        return RiskLevel.HIGH
    return RiskLevel.LOW


def fallback_evidence_severity(mode: PolicyMode) -> RiskLevel:
    """En ci/strict la evidencia fallback bloquea; localmente queda como warning."""
    return RiskLevel.MEDIUM if mode_allows_fallback(mode) else RiskLevel.HIGH


def is_local_fallback_report(report: Any) -> bool:
    """Reconoce reportes generados por el flujo local liviano, no por scanners reales."""
    if not isinstance(report, dict):
        return False
    generated_by = str(report.get("generated_by", ""))
    tool_mode = str(report.get("tool_mode", ""))
    if generated_by == LOCAL_EVIDENCE_GENERATOR or tool_mode == "stdlib-fallback":
        return True
    for run in report.get("runs", []) if isinstance(report.get("runs", []), list) else []:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool", {}) if isinstance(run.get("tool", {}), dict) else {}
        driver = tool.get("driver", {}) if isinstance(tool.get("driver", {}), dict) else {}
        if str(driver.get("name", "")) == LOCAL_EVIDENCE_GENERATOR:
            return True
    return False


def normalize_severity(value: Any) -> str:
    """Normaliza severidades heterogéneas de reportes JSON/SARIF/ZAP."""
    return str(value or "").strip().upper()


def sarif_result_severity(result: dict[str, Any]) -> str:
    """Extrae severidad aproximada desde un resultado SARIF de Grype/Trivy."""
    level = str(result.get("level", "")).strip().lower()
    if level == "error":
        return "HIGH"
    if level == "warning":
        return "MEDIUM"

    properties = (
        result.get("properties", {}) if isinstance(result.get("properties", {}), dict) else {}
    )
    for key in ("severity", "Security-Severity", "security-severity"):
        severity = normalize_severity(properties.get(key))
        if severity:
            return severity

    security_score = properties.get("security-severity") or properties.get("cvssScore")
    try:
        score = float(security_score)
    except (TypeError, ValueError):
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return ""


def zap_alert_severity(alert: dict[str, Any]) -> str:
    """Extrae severidad desde formatos comunes de OWASP ZAP baseline JSON."""
    for key in ("riskdesc", "risk", "riskDesc"):
        raw_value = str(alert.get(key, ""))
        if raw_value:
            return normalize_severity(raw_value.split()[0])

    risk_code = str(alert.get("riskcode", alert.get("riskCode", ""))).strip()
    return {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}.get(risk_code, "")


def add_fallback_finding(
    findings: list[SecurityFinding],
    report: Any,
    relative_path: str,
    component: str,
    mode: PolicyMode,
) -> None:
    """Registra cuando una evidencia es fallback para que no se confunda con scan real."""
    if not is_local_fallback_report(report):
        return
    add_finding(
        findings,
        "POLICY011",
        fallback_evidence_severity(mode),
        "La evidencia fue generada por el modo local fallback, no por el scanner real.",
        component,
        "Ejecuta el scanner real correspondiente para obtener una decisión de seguridad completa.",
        evidence=relative_path,
    )


def load_report(root: Path, relative_path: str) -> dict[str, Any] | None:
    """Carga un reporte JSON relativo al repositorio."""
    report = read_json_if_exists(root / relative_path)
    return report if isinstance(report, dict) else None


def add_finding(
    findings: list[SecurityFinding],
    rule_id: str,
    severity: RiskLevel,
    message: str,
    component: str,
    recommendation: str,
    evidence: str | None = None,
) -> None:
    """Agrega un hallazgo de política normalizado."""
    findings.append(
        SecurityFinding(
            rule_id=rule_id,
            severity=severity.value,
            message=message,
            component=component,
            recommendation=recommendation,
            evidence=evidence,
        )
    )


def evaluate_report_status(
    findings: list[SecurityFinding],
    report: dict[str, Any] | None,
    relative_path: str,
    component: str,
) -> None:
    """Evalúa el status de un reporte requerido por el gate."""
    if report is None:
        add_finding(
            findings,
            "POLICY001",
            RiskLevel.HIGH,
            "Falta un reporte requerido para tomar la decisión del gate.",
            component,
            "Ejecuta los targets previos del pipeline antes de policy-check.",
            evidence=relative_path,
        )
        return

    status = str(report.get("status", "UNKNOWN")).upper()
    if status in FAILING_STATUSES:
        add_finding(
            findings,
            "POLICY002",
            RiskLevel.HIGH,
            f"El reporte requerido terminó en estado {status}.",
            component,
            "Corrige hallazgos high/critical antes de permitir el avance del pipeline.",
            evidence=relative_path,
        )
    elif status in WARNING_STATUSES:
        add_finding(
            findings,
            "POLICY003",
            RiskLevel.MEDIUM,
            f"El reporte requerido terminó en estado {status}.",
            component,
            "Documenta mitigaciones o reduce los hallazgos medium/low.",
            evidence=relative_path,
        )
    elif status not in PASSING_STATUSES:
        add_finding(
            findings,
            "POLICY004",
            RiskLevel.MEDIUM,
            "El reporte requerido no usa un status reconocido.",
            component,
            "Normaliza la salida a PASS, WARN o FAIL.",
            evidence=f"{relative_path}:{status}",
        )


def evaluate_finding_counts(
    findings: list[SecurityFinding],
    report: dict[str, Any] | None,
    component: str,
    relative_path: str,
) -> None:
    """Bloquea hallazgos high/critical aunque el status de la herramienta esté mal formado."""
    if report is None:
        return
    counts = report.get("finding_counts", {})
    if not isinstance(counts, dict):
        return

    high_or_critical = int(counts.get("high_or_critical", 0) or 0)
    if high_or_critical > 0:
        add_finding(
            findings,
            "POLICY005",
            RiskLevel.HIGH,
            "El reporte contiene hallazgos high o critical.",
            component,
            "Atiende esos hallazgos antes de aprobar el gate.",
            evidence=f"{relative_path}:high_or_critical={high_or_critical}",
        )


def evaluate_recommended_evidence(
    root: Path, findings: list[SecurityFinding], mode: PolicyMode
) -> dict[str, Any]:
    """Calcula completitud de evidencias y bloquea faltantes críticos/estrictos."""
    expected = list(REQUIRED_POLICY_REPORTS) + list(RECOMMENDED_EVIDENCE_FILES)
    existing = [relative_path for relative_path in expected if (root / relative_path).is_file()]
    missing = [relative_path for relative_path in expected if relative_path not in existing]

    for relative_path in missing:
        severity = missing_evidence_severity(relative_path, mode)
        add_finding(
            findings,
            "POLICY006",
            severity,
            "Falta evidencia esperada del pipeline.",
            "evidence_completeness",
            "Genera la evidencia con el target Makefile correspondiente o documenta por qué no aplica.",
            evidence=relative_path,
        )

    total = len(expected)
    return {
        "expected": expected,
        "existing": existing,
        "missing": missing,
        "score": round(len(existing) / total, 3) if total else 1.0,
    }


def evaluate_scanner_exit_evidence(
    root: Path, findings: list[SecurityFinding], mode: PolicyMode
) -> dict[str, Any]:
    """Valida exit codes, frescura y hash de artefactos producidos por scanners reales."""
    rows: dict[str, Any] = {}
    for scanner, (artifact_path, evidence_path) in SCANNER_EXIT_EVIDENCE.items():
        evidence = read_json_if_exists(root / evidence_path)
        if not isinstance(evidence, dict):
            rows[scanner] = {
                "status": "missing",
                "evidence": evidence_path,
                "artifact": artifact_path,
            }
            if mode in {"ci", "strict"}:
                add_finding(
                    findings,
                    "POLICY017",
                    RiskLevel.HIGH,
                    "Falta evidencia operacional del scanner externo.",
                    scanner,
                    "Ejecuta el target real del scanner para registrar exit code, run_id y hash del artefacto.",
                    evidence=evidence_path,
                )
            continue

        ok, reason = verify_tool_exit_record(root, evidence, artifact_path)
        rows[scanner] = {
            "status": "valid" if ok else "invalid",
            "reason": reason,
            "evidence": evidence_path,
            "artifact": artifact_path,
            "scanner_exit_code": evidence.get("scanner_exit_code"),
            "run_id": evidence.get("run_id"),
            "git_commit": evidence.get("git_commit"),
            "config_hash": evidence.get("config_hash"),
            "scanner_started_at": evidence.get("scanner_started_at"),
            "scanner_finished_at": evidence.get("scanner_finished_at"),
        }
        if not ok and mode in {"ci", "strict"}:
            add_finding(
                findings,
                "POLICY018",
                RiskLevel.HIGH,
                "La evidencia operacional del scanner no coincide con el artefacto actual.",
                scanner,
                "Regenera el scanner y el artifact en el mismo run antes de aprobar el release.",
                evidence=f"{evidence_path}:{reason}",
            )
        exit_code = evidence.get("scanner_exit_code")
        if isinstance(exit_code, int) and exit_code in {126, 127} and mode in {"ci", "strict"}:
            add_finding(
                findings,
                "POLICY019",
                RiskLevel.HIGH,
                "El scanner no pudo ejecutarse en el entorno actual.",
                scanner,
                "Instala la herramienta o usa el GitHub Action oficial antes de considerar el gate como release-ready.",
                evidence=f"{evidence_path}:exit_code={exit_code}",
            )
    return rows


def evaluate_security_tool_outputs(
    root: Path, findings: list[SecurityFinding], mode: PolicyMode
) -> None:
    """Bloquea hallazgos críticos conocidos en reportes SAST, SCA, imagen y DAST."""
    artifacts = root / "artifacts"

    bandit = read_json_if_exists(artifacts / "bandit.json")
    add_fallback_finding(findings, bandit, "artifacts/bandit.json", "bandit", mode)
    if isinstance(bandit, dict):
        for result in (
            bandit.get("results", []) if isinstance(bandit.get("results", []), list) else []
        ):
            if not isinstance(result, dict):
                continue
            severity = normalize_severity(result.get("issue_severity", ""))
            if severity in {"HIGH", "CRITICAL"}:
                add_finding(
                    findings,
                    "POLICY007",
                    external_tool_severity(),
                    "Bandit reporta un hallazgo high/critical.",
                    "bandit",
                    "Corrige el hallazgo SAST o documenta una excepción aprobada antes de permitir merge.",
                    evidence=str(result.get("test_id", "bandit")),
                )

    semgrep = read_json_if_exists(artifacts / "semgrep.json")
    add_fallback_finding(findings, semgrep, "artifacts/semgrep.json", "semgrep", mode)
    if isinstance(semgrep, dict):
        for result in (
            semgrep.get("results", []) if isinstance(semgrep.get("results", []), list) else []
        ):
            if not isinstance(result, dict):
                continue
            extra = result.get("extra", {}) if isinstance(result.get("extra", {}), dict) else {}
            severity = normalize_severity(extra.get("severity", ""))
            if severity in {"ERROR", "HIGH", "CRITICAL"}:
                add_finding(
                    findings,
                    "POLICY008",
                    external_tool_severity(),
                    "Semgrep reporta un hallazgo high/critical.",
                    "semgrep",
                    "Corrige el hallazgo o documenta una excepción aprobada antes de permitir merge.",
                    evidence=str(result.get("check_id", "semgrep")),
                )

    pip_audit_reports: list[tuple[str, Any]] = [
        (relative_path, read_json_if_exists(root / relative_path))
        for relative_path in PIP_AUDIT_REPORT_PATHS
    ]
    # Compatibilidad con reportes antiguos: se evalúa solo si no existen los reportes
    # separados por runtime/dev/mcp.
    if not any(isinstance(report, dict) for _, report in pip_audit_reports):
        pip_audit_reports.append(
            (LEGACY_PIP_AUDIT_REPORT_PATH, read_json_if_exists(root / LEGACY_PIP_AUDIT_REPORT_PATH))
        )

    for relative_path, pip_audit in pip_audit_reports:
        add_fallback_finding(findings, pip_audit, relative_path, "pip-audit", mode)
        if not isinstance(pip_audit, dict):
            continue
        for dependency in (
            pip_audit.get("dependencies", [])
            if isinstance(pip_audit.get("dependencies", []), list)
            else []
        ):
            if not isinstance(dependency, dict):
                continue
            vulns = dependency.get("vulns", [])
            if isinstance(vulns, list) and vulns:
                add_finding(
                    findings,
                    "POLICY009",
                    external_tool_severity(),
                    "pip-audit reporta vulnerabilidades de dependencias.",
                    "pip-audit",
                    "Actualiza, reemplaza o documenta una excepción aprobada antes de permitir merge.",
                    evidence=f"{relative_path}:{dependency.get('name', 'unknown')}",
                )

    for scanner_name, relative_path, rule_id, message in (
        (
            "grype",
            "artifacts/grype-image.sarif",
            "POLICY010",
            "El escaneo de imagen reporta un resultado high/critical.",
        ),
        (
            "trivy",
            "artifacts/trivy-image.sarif",
            "POLICY014",
            "Trivy reporta un resultado high/critical en la imagen.",
        ),
        (
            "gitleaks",
            "artifacts/gitleaks.sarif",
            "POLICY015",
            "Gitleaks reporta una exposición de secreto.",
        ),
    ):
        sarif_report = read_json_if_exists(root / relative_path)
        add_fallback_finding(findings, sarif_report, relative_path, scanner_name, mode)
        if isinstance(sarif_report, dict):
            for run in (
                sarif_report.get("runs", [])
                if isinstance(sarif_report.get("runs", []), list)
                else []
            ):
                if not isinstance(run, dict):
                    continue
                for result in (
                    run.get("results", []) if isinstance(run.get("results", []), list) else []
                ):
                    if not isinstance(result, dict):
                        continue
                    severity = sarif_result_severity(result)
                    if scanner_name == "gitleaks" or severity in {"HIGH", "CRITICAL"}:
                        add_finding(
                            findings,
                            rule_id,
                            RiskLevel.HIGH
                            if scanner_name == "gitleaks"
                            else external_tool_severity(),
                            message,
                            scanner_name,
                            "Corrige el hallazgo o documenta una excepción aprobada antes de permitir release.",
                            evidence=str(result.get("ruleId", scanner_name)),
                        )

    scorecard = read_json_if_exists(artifacts / "scorecard.json")
    add_fallback_finding(findings, scorecard, "artifacts/scorecard.json", "openssf-scorecard", mode)
    if isinstance(scorecard, dict):
        score = scorecard.get("score")
        try:
            score_value = float(score)
        except (TypeError, ValueError):
            score_value = None
        if score_value is not None and score_value < 7.0:
            add_finding(
                findings,
                "POLICY016",
                RiskLevel.MEDIUM,
                "OpenSSF Scorecard reporta una postura de seguridad baja.",
                "openssf-scorecard",
                "Revisa checks con bajo puntaje y documenta remediaciones antes de release.",
                evidence=f"score={score_value}",
            )

    zap = read_json_if_exists(artifacts / "zap-baseline.json")
    add_fallback_finding(findings, zap, "artifacts/zap-baseline.json", "zap", mode)
    if isinstance(zap, dict):
        for site in zap.get("site", []) if isinstance(zap.get("site", []), list) else []:
            if not isinstance(site, dict):
                continue
            for alert in site.get("alerts", []) if isinstance(site.get("alerts", []), list) else []:
                if not isinstance(alert, dict):
                    continue
                severity = zap_alert_severity(alert)
                if severity in {"HIGH", "CRITICAL"}:
                    add_finding(
                        findings,
                        "POLICY012",
                        RiskLevel.HIGH,
                        "OWASP ZAP reporta una alerta high/critical.",
                        "zap",
                        "Corrige el hallazgo DAST o documenta una excepción aprobada antes de permitir merge.",
                        evidence=str(
                            alert.get("pluginid", alert.get("pluginId", alert.get("alert", "zap")))
                        ),
                    )
                elif severity == "MEDIUM":
                    add_finding(
                        findings,
                        "POLICY013",
                        RiskLevel.MEDIUM,
                        "OWASP ZAP reporta una alerta medium.",
                        "zap",
                        "Revisa el hallazgo DAST y documenta la decisión de mitigación.",
                        evidence=str(
                            alert.get("pluginid", alert.get("pluginId", alert.get("alert", "zap")))
                        ),
                    )


def flatten_evidence_score(evidence: dict[str, Any]) -> float:
    """Extrae el score numérico de completitud para la salida resumida."""
    return float(evidence.get("score", 0.0) or 0.0)


def count_findings(findings: Sequence[SecurityFinding]) -> dict[str, int]:
    """Cuenta hallazgos del gate por severidad."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for finding in findings:
        severity = finding.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1
        counts["total"] += 1
    counts["high_or_critical"] = counts.get("critical", 0) + counts.get("high", 0)
    return counts


def determine_policy_status(findings: Sequence[SecurityFinding]) -> ScanStatus:
    """Determina la decisión final del policy gate."""
    severities = {finding.severity for finding in findings}
    if RiskLevel.CRITICAL.value in severities or RiskLevel.HIGH.value in severities:
        return ScanStatus.FAIL
    if RiskLevel.MEDIUM.value in severities or RiskLevel.LOW.value in severities:
        return ScanStatus.WARN
    return ScanStatus.PASS


def evaluate_run_id_consistency(
    findings: list[SecurityFinding],
    reports: dict[str, dict[str, Any] | None],
    mode: PolicyMode,
) -> None:
    """Valida que los reportes internos pertenezcan al mismo run_id global."""
    expected_run_id = os.environ.get("SKILLCHAIN_RUN_ID")
    if not expected_run_id:
        return
    for relative_path, report in reports.items():
        if not isinstance(report, dict):
            continue
        report_run_id = report.get("run_id")
        if not report_run_id:
            if mode in {"ci", "strict"}:
                add_finding(
                    findings,
                    "POLICY021",
                    RiskLevel.HIGH,
                    "El reporte no declara run_id y no puede trazarse a la ejecución actual.",
                    "run_id",
                    "Regenera el reporte con write_json_report o exporta SKILLCHAIN_RUN_ID antes de ejecutar el pipeline.",
                    evidence=relative_path,
                )
            continue
        if report_run_id != expected_run_id:
            add_finding(
                findings,
                "POLICY020",
                RiskLevel.HIGH,
                "El reporte pertenece a un run_id distinto al de la ejecución actual.",
                "run_id",
                "Regenera todos los reportes dentro de la misma corrida exportando SKILLCHAIN_RUN_ID global.",
                evidence=relative_path,
            )


def evaluate_policy(root: Path | None = None, mode: str | None = None) -> dict[str, Any]:
    """Evalúa reportes y evidencias para producir PASS, WARN o FAIL."""
    base = (root or REPO_ROOT).resolve()
    policy_mode = normalize_policy_mode(mode)
    findings: list[SecurityFinding] = []
    skill_report = load_report(base, SKILL_REPORT_PATH)
    mcp_report = load_report(base, MCP_AUDIT_REPORT_PATH)

    report_inputs = {
        "skill_scanner": (SKILL_REPORT_PATH, skill_report),
        "mcp_auditor": (MCP_AUDIT_REPORT_PATH, mcp_report),
    }

    for component, (relative_path, report) in report_inputs.items():
        evaluate_report_status(findings, report, relative_path, component)
        evaluate_finding_counts(findings, report, component, relative_path)

    evaluate_run_id_consistency(
        findings,
        {relative_path: report for relative_path, report in report_inputs.values()},
        policy_mode,
    )

    evaluate_security_tool_outputs(base, findings, policy_mode)
    scanner_exit_evidence = evaluate_scanner_exit_evidence(base, findings, policy_mode)
    evidence = evaluate_recommended_evidence(base, findings, policy_mode)
    counts = count_findings(findings)
    status = determine_policy_status(findings)

    return {
        "engine": "skillchain-mcp-guard-policy-engine",
        "mode": policy_mode,
        "fallback_allowed": mode_allows_fallback(policy_mode),
        "status": status.value,
        "repo_root": str(base),
        "inputs": {name: path for name, (path, _) in report_inputs.items()},
        "evidence_completeness": evidence,
        "evidence_completeness_score": flatten_evidence_score(evidence),
        "scanner_exit_evidence": scanner_exit_evidence,
        "blocking_issues": counts["high_or_critical"],
        "warnings": counts.get("medium", 0) + counts.get("low", 0),
        "finding_counts": counts,
        "findings": [finding.to_dict() for finding in findings],
        "decision": {
            "allow_merge": status != ScanStatus.FAIL,
            "requires_human_review": status == ScanStatus.WARN,
            "blocking_issues": counts["high_or_critical"],
        },
    }


def write_policy_report(
    report: dict[str, Any], output_path: Path, root: Path | None = None
) -> Path:
    """Escribe la decisión de policy gate en JSON."""
    return write_json_report(report, output_path, root=root)


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI del policy engine."""
    parser = argparse.ArgumentParser(
        description="Evalúa evidencia DevSecOps y aplica el policy gate."
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="Raíz del repositorio a evaluar.")
    parser.add_argument(
        "--output", default=POLICY_REPORT_PATH, help="Ruta de salida del reporte JSON."
    )
    parser.add_argument(
        "--mode",
        choices=sorted(VALID_POLICY_MODES),
        default="strict",
        help="Perfil de política: demo, ci o strict.",
    )
    parser.add_argument(
        "--fail-on-fail",
        action="store_true",
        help="Compatibilidad: strict/ci ya fallan por defecto cuando status es FAIL.",
    )
    parser.add_argument(
        "--no-fail-on-fail",
        action="store_true",
        help="Modo reporte: escribe JSON y devuelve 0 aunque status sea FAIL.",
    )
    parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Devuelve estado 3 cuando la política queda en WARN.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada CLI del policy gate."""
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    report = evaluate_policy(root=root, mode=args.mode)
    output = write_policy_report(report, Path(args.output), root=root)
    print(json.dumps({"status": report["status"], "output": str(output)}, ensure_ascii=False))

    if report["status"] == ScanStatus.FAIL.value and not args.no_fail_on_fail:
        return 2
    if args.fail_on_warn and report["status"] == ScanStatus.WARN.value:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
