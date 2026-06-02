"""Dashboard de producto para SkillChain-MCP Guard."""

from __future__ import annotations

import argparse
import html
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifacts import (
    list_artifacts,
    read_json_if_exists,
    resolve_repo_root,
    summarize_security_findings,
)
from .config import (
    DASHBOARD_HTML_PATH,
    EVALUATION_REPORT_PATH,
    EVIDENCE_MANIFEST_PATH,
    MCP_AUDIT_REPORT_PATH,
    POLICY_REPORT_PATH,
    PRODUCT_STATUS_PATH,
    REPO_ROOT,
    SKILL_REPORT_PATH,
)
from .report_writer import write_json_report
from .security_models import ScanStatus

REPORT_PATHS: dict[str, str] = {
    "skill_scanner": SKILL_REPORT_PATH,
    "mcp_auditor": MCP_AUDIT_REPORT_PATH,
    "controlled_evaluation": EVALUATION_REPORT_PATH,
    "policy_engine": POLICY_REPORT_PATH,
    "evidence_manifest": EVIDENCE_MANIFEST_PATH,
}

STATUS_ORDER: dict[str, int] = {
    ScanStatus.PASS.value: 0,
    ScanStatus.WARN.value: 1,
    ScanStatus.FAIL.value: 2,
    "MISSING": 3,
    "UNKNOWN": 3,
}


METRIC_LABELS: dict[str, str] = {
    "attack_block_rate": "Bloqueo de ataques",
    "false_positive_rate": "Falsos positivos",
    "allowed_task_success_rate": "Tareas legítimas exitosas",
    "passed_case_count": "Casos aprobados",
    "case_count": "Casos totales",
}

COMPONENT_LABELS: dict[str, str] = {
    "skill_scanner": "Scanner de skills",
    "mcp_auditor": "Auditor MCP",
    "controlled_evaluation": "Evaluación controlada",
    "policy_engine": "Policy gate",
    "evidence_manifest": "Manifest de evidencias",
}

# En una demo ejecutiva es mejor evitar un 100/100: comunica madurez, no perfección.
# El producto puede estar apto para revisión/release aunque conserve riesgo residual documentado.
REALISTIC_SCORE_CEILING = 96


def load_json_report(root: Path, relative_path: str) -> dict[str, Any] | None:
    """Carga un reporte JSON relativo a la raíz del repositorio."""
    report = read_json_if_exists(root / relative_path)
    return report if isinstance(report, dict) else None


def normalize_status(report: dict[str, Any] | None, default: str = "MISSING") -> str:
    """Normaliza el estado de un reporte a PASS, WARN, FAIL, MISSING o UNKNOWN."""
    if report is None:
        return default
    status = str(report.get("status", "UNKNOWN")).upper()
    return status if status in STATUS_ORDER else "UNKNOWN"


def max_status(statuses: Sequence[str]) -> str:
    """Devuelve el peor estado observado según el orden de severidad del dashboard."""
    if not statuses:
        return "UNKNOWN"
    return max(statuses, key=lambda item: STATUS_ORDER.get(item, STATUS_ORDER["UNKNOWN"]))


def report_finding_counts(report: dict[str, Any] | None) -> dict[str, int]:
    """Extrae conteos de hallazgos con valores por defecto estables."""
    counts = report.get("finding_counts", {}) if isinstance(report, dict) else {}
    if not isinstance(counts, dict):
        counts = {}
    return {
        "high_or_critical": int(counts.get("high_or_critical", 0) or 0),
        "medium": int(counts.get("medium", 0) or 0),
        "low": int(counts.get("low", 0) or 0),
        "total": int(counts.get("total", 0) or 0),
    }


def evidence_score(policy_report: dict[str, Any] | None) -> float:
    """Obtiene la completitud de evidencia reportada por el policy engine."""
    if not isinstance(policy_report, dict):
        return 0.0
    evidence = policy_report.get("evidence_completeness", {})
    if not isinstance(evidence, dict):
        return 0.0
    return float(evidence.get("score", 0.0) or 0.0)


def calculate_security_score(
    statuses: dict[str, str], reports: dict[str, dict[str, Any] | None]
) -> int:
    """Calcula un score legible para demo a partir de estados, hallazgos y evidencia."""
    score = REALISTIC_SCORE_CEILING

    for name in ("skill_scanner", "mcp_auditor", "controlled_evaluation", "policy_engine"):
        status = statuses.get(name, "UNKNOWN")
        if status == ScanStatus.FAIL.value:
            score -= 25
        elif status == ScanStatus.WARN.value:
            score -= 10
        elif status in {"MISSING", "UNKNOWN"}:
            score -= 15

    for name in ("skill_scanner", "mcp_auditor", "policy_engine"):
        counts = report_finding_counts(reports.get(name))
        score -= counts["high_or_critical"] * 10
        score -= counts["medium"] * 4
        score -= counts["low"] * 1

    completeness = evidence_score(reports.get("policy_engine"))
    score -= round((1.0 - completeness) * 15)

    eval_report = reports.get("controlled_evaluation") or {}
    metrics = eval_report.get("metrics", {}) if isinstance(eval_report, dict) else {}
    if isinstance(metrics, dict):
        score -= round((1.0 - float(metrics.get("attack_block_rate", 0.0) or 0.0)) * 20)
        score -= round(float(metrics.get("false_positive_rate", 0.0) or 0.0) * 10)
        score -= round((1.0 - float(metrics.get("allowed_task_success_rate", 0.0) or 0.0)) * 10)

    return max(0, min(REALISTIC_SCORE_CEILING, score))


def classify_security_posture(score: int, product_status: str) -> str:
    """Convierte el score en una lectura ejecutiva para presentación."""
    if product_status == ScanStatus.FAIL.value or score < 70:
        return "Riesgo alto: requiere corrección antes de release."
    if product_status == ScanStatus.WARN.value or score < 90:
        return "Riesgo medio: apto para revisión con mitigaciones documentadas."
    return "Riesgo bajo: apto para demo/release controlado con riesgo residual monitoreado."


def build_control_coverage(
    statuses: dict[str, str], reports: dict[str, dict[str, Any] | None]
) -> list[dict[str, str]]:
    """Agrupa los resultados técnicos en controles fáciles de explicar en una presentación."""
    return [
        {
            "area": "Supply chain de skills",
            "control": "Detección de instrucciones sospechosas, rutas peligrosas y comandos inseguros.",
            "status": statuses.get("skill_scanner", "UNKNOWN"),
            "evidence": REPORT_PATHS["skill_scanner"],
        },
        {
            "area": "Superficie MCP",
            "control": "Auditoría de herramientas, recursos expuestos y permisos declarados por el servidor MCP.",
            "status": statuses.get("mcp_auditor", "UNKNOWN"),
            "evidence": REPORT_PATHS["mcp_auditor"],
        },
        {
            "area": "Evaluación adversarial",
            "control": "Casos controlados para validar bloqueo de ataques y permitir tareas benignas.",
            "status": statuses.get("controlled_evaluation", "UNKNOWN"),
            "evidence": REPORT_PATHS["controlled_evaluation"],
        },
        {
            "area": "Policy gate",
            "control": "Decisión agregada PASS/WARN/FAIL con evidencia de SBOM, SAST, SCA, DAST y contenedor.",
            "status": statuses.get("policy_engine", "UNKNOWN"),
            "evidence": REPORT_PATHS["policy_engine"],
        },
    ]


def artifact_summary(root: Path) -> dict[str, Any]:
    """Resume archivos de evidencia para mostrar en CLI y dashboard."""
    artifacts = list_artifacts(root)
    total_size = sum(int(item.get("size_bytes", 0) or 0) for item in artifacts)
    latest = sorted(
        artifacts, key=lambda item: float(item.get("modified_unix", 0) or 0), reverse=True
    )[:8]
    return {
        "count": len(artifacts),
        "total_size_bytes": total_size,
        "latest": latest,
    }


def build_recommendations(
    product_status: str, reports: dict[str, dict[str, Any] | None]
) -> list[str]:
    """Genera recomendaciones accionables basadas en el estado del producto."""
    recommendations: list[str] = []

    if reports.get("skill_scanner") is None:
        recommendations.append("Ejecuta `make skill-scan` para generar el reporte de skills.")
    if reports.get("mcp_auditor") is None:
        recommendations.append("Ejecuta `make mcp-audit` para generar la auditoría MCP.")
    if reports.get("controlled_evaluation") is None:
        recommendations.append(
            "Ejecuta `make agent-eval` para validar los casos adversariales controlados."
        )
    if reports.get("policy_engine") is None:
        recommendations.append(
            "Ejecuta `make policy-check` para obtener la decisión PASS/WARN/FAIL."
        )

    policy_report = reports.get("policy_engine") or {}
    if isinstance(policy_report, dict):
        evidence = policy_report.get("evidence_completeness", {})
        if isinstance(evidence, dict) and float(evidence.get("score", 0.0) or 0.0) < 1.0:
            recommendations.append(
                "Ejecuta `make pipeline` para completar SAST, SCA, SBOM, image scan y DAST."
            )
        findings = policy_report.get("findings", [])
        if isinstance(findings, list) and any(
            isinstance(finding, dict) and finding.get("rule_id") == "POLICY011"
            for finding in findings
        ):
            recommendations.append(
                "Reemplaza evidencia fallback con scanners reales antes de CI/release (`make sast sca sbom scan-image compose-up dast compose-down`)."
            )

    if product_status == ScanStatus.FAIL.value:
        recommendations.append("Corrige hallazgos high/critical antes de aprobar merge o release.")
    elif product_status == ScanStatus.WARN.value:
        recommendations.append(
            "Documenta mitigaciones y revisa evidencias faltantes antes de release."
        )

    if not recommendations:
        recommendations.append("Mantén el evidence pack actualizado antes de cada release.")

    return recommendations


def build_product_status(root: Path | None = None) -> dict[str, Any]:
    """Construye el resumen de producto a partir de reportes existentes."""
    base = resolve_repo_root(root)
    reports = {name: load_json_report(base, path) for name, path in REPORT_PATHS.items()}
    statuses = {
        name: normalize_status(report, default="MISSING") for name, report in reports.items()
    }

    # El manifest no es un scanner; si existe se marca como PASS para evitar ruido visual.
    statuses["evidence_manifest"] = (
        "PASS" if reports["evidence_manifest"] is not None else "MISSING"
    )

    product_status = max_status(
        [
            statuses["skill_scanner"],
            statuses["mcp_auditor"],
            statuses["controlled_evaluation"],
            statuses["policy_engine"],
        ]
    )
    if product_status in {"MISSING", "UNKNOWN"}:
        product_status = ScanStatus.WARN.value

    score = calculate_security_score(statuses, reports)
    policy_report = reports.get("policy_engine") or {}
    eval_report = reports.get("controlled_evaluation") or {}

    policy_counts = report_finding_counts(
        policy_report if isinstance(policy_report, dict) else None
    )
    eval_metrics = eval_report.get("metrics", {}) if isinstance(eval_report, dict) else {}
    summary = summarize_security_findings(base)

    return {
        "product": "SkillChain-MCP Guard",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "repo_root": str(base),
        "status": product_status,
        "security_score": score,
        "score_ceiling": REALISTIC_SCORE_CEILING,
        "executive_summary": {
            "posture": classify_security_posture(score, product_status),
            "score_note": f"El puntaje está limitado a {REALISTIC_SCORE_CEILING}/100 para reflejar riesgo residual realista; no representa seguridad absoluta.",
            "demo_message": "El valor de la demo está en mostrar trazabilidad: scanner → auditoría MCP → evaluación adversarial → policy gate → evidence pack.",
        },
        "report_paths": REPORT_PATHS,
        "report_statuses": statuses,
        "risk_summary": {
            "skill_risk": (reports.get("skill_scanner") or {}).get("overall_risk", "low"),
            "mcp_risk": (reports.get("mcp_auditor") or {}).get("overall_risk", "low"),
            "policy_status": statuses["policy_engine"],
            "evaluation_status": statuses["controlled_evaluation"],
            "blocking_issues": int(policy_counts.get("high_or_critical", 0) or 0),
            "evidence_completeness_score": evidence_score(reports.get("policy_engine")),
        },
        "evaluation_metrics": eval_metrics if isinstance(eval_metrics, dict) else {},
        "security_tool_summary": summary.get("tools", {}),
        "control_coverage": build_control_coverage(statuses, reports),
        "artifacts": artifact_summary(base),
        "recommendations": build_recommendations(product_status, reports),
    }


def write_product_status(
    report: dict[str, Any], output_path: Path, root: Path | None = None
) -> Path:
    """Escribe el resumen de producto en JSON."""
    return write_json_report(report, output_path, root=root)


def status_badge(status: str) -> str:
    """Devuelve una etiqueta HTML segura para un estado."""
    safe_status = html.escape(status)
    class_name = html.escape(status.lower())
    return f'<span class="badge {class_name}">{safe_status}</span>'


def format_bytes(size: int) -> str:
    """Formatea bytes para lectura humana sin dependencias externas."""
    value = float(size)
    for suffix in ("B", "KB", "MB", "GB"):
        if value < 1024 or suffix == "GB":
            return f"{value:.1f} {suffix}"
        value /= 1024
    return f"{value:.1f} GB"


def render_metric_value(value: Any) -> str:
    """Renderiza métricas numéricas como porcentaje cuando corresponde."""
    if isinstance(value, float) and 0 <= value <= 1:
        return f"{value * 100:.1f}%"
    return html.escape(str(value))


def render_dashboard_html(report: dict[str, Any]) -> str:
    """Renderiza un dashboard HTML autocontenido para demo y auditoría."""
    statuses = report["report_statuses"]
    risk = report["risk_summary"]
    metrics = report.get("evaluation_metrics", {})
    artifacts = report.get("artifacts", {})
    latest = artifacts.get("latest", []) if isinstance(artifacts, dict) else []
    recommendations = report.get("recommendations", [])
    tools = report.get("security_tool_summary", {})
    executive = (
        report.get("executive_summary", {})
        if isinstance(report.get("executive_summary", {}), dict)
        else {}
    )
    control_coverage = (
        report.get("control_coverage", [])
        if isinstance(report.get("control_coverage", []), list)
        else []
    )

    status_rows = "\n".join(
        f"<tr><td>{html.escape(COMPONENT_LABELS.get(name, name.replace('_', ' ').title()))}</td>"
        f"<td>{status_badge(status)}</td>"
        f"<td><code>{html.escape(REPORT_PATHS.get(name, 'n/a'))}</code></td></tr>"
        for name, status in statuses.items()
    )

    metric_cards = (
        "\n".join(
            f'<div class="metric-card"><span>{html.escape(METRIC_LABELS.get(name, name))}</span>'
            f"<strong>{render_metric_value(value)}</strong></div>"
            for name, value in metrics.items()
        )
        or '<div class="metric-card"><span>Métricas de evaluación</span><strong>Sin datos</strong></div>'
    )

    artifact_rows = (
        "\n".join(
            f"<tr><td><code>{html.escape(str(item.get('relative_path', '')))}</code></td>"
            f"<td>{format_bytes(int(item.get('size_bytes', 0) or 0))}</td></tr>"
            for item in latest
        )
        or "<tr><td colspan='2'>No se encontraron artefactos.</td></tr>"
    )

    recommendation_items = "\n".join(f"<li>{html.escape(item)}</li>" for item in recommendations)

    control_rows = (
        "\n".join(
            "<tr>"
            f"<td>{html.escape(str(item.get('area', '')))}</td>"
            f"<td>{html.escape(str(item.get('control', '')))}</td>"
            f"<td>{status_badge(str(item.get('status', 'UNKNOWN')))}</td>"
            f"<td><code>{html.escape(str(item.get('evidence', '')))}</code></td>"
            "</tr>"
            for item in control_coverage
            if isinstance(item, dict)
        )
        or "<tr><td colspan='4'>No hay controles calculados.</td></tr>"
    )

    tool_items = (
        "\n".join(
            f"<li><strong>{html.escape(name)}</strong>: <code>{html.escape(json.dumps(value, ensure_ascii=False))}</code></li>"
            for name, value in tools.items()
        )
        or "<li>Aún no hay resúmenes de scanners disponibles.</li>"
    )

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(report['product'])} Dashboard</title>
  <style>
    :root {{
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #e6f1ff;
      background: #070b18;
      --bg: #070b18;
      --panel: rgba(13, 22, 43, .86);
      --panel-strong: rgba(17, 30, 61, .94);
      --line: rgba(139, 158, 255, .18);
      --muted: #9fb0d3;
      --cyan: #2ee9ff;
      --violet: #8b5cf6;
      --green: #22c55e;
      --amber: #f59e0b;
      --red: #ef4444;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at 12% 10%, rgba(46, 233, 255, .18), transparent 28%),
        radial-gradient(circle at 86% 0%, rgba(139, 92, 246, .22), transparent 34%),
        linear-gradient(180deg, #070b18 0%, #0b1223 100%);
    }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 34px 20px 56px; }}
    header {{
      position: relative;
      overflow: hidden;
      border: 1px solid rgba(46, 233, 255, .24);
      background: linear-gradient(135deg, rgba(10, 18, 38, .96), rgba(36, 24, 75, .88));
      border-radius: 28px;
      padding: 30px;
      box-shadow: 0 24px 80px rgba(0, 0, 0, .42);
    }}
    header::after {{
      content: "";
      position: absolute;
      inset: -60px -80px auto auto;
      width: 260px;
      height: 260px;
      background: radial-gradient(circle, rgba(46, 233, 255, .28), transparent 65%);
      pointer-events: none;
    }}
    .kicker {{ color: var(--cyan); font-weight: 800; letter-spacing: .14em; text-transform: uppercase; font-size: 12px; }}
    h1, h2 {{ margin: 0; }}
    h1 {{ font-size: clamp(32px, 5vw, 56px); letter-spacing: -0.055em; line-height: .96; margin-top: 8px; }}
    h2 {{ font-size: 20px; margin-bottom: 14px; letter-spacing: -0.02em; }}
    p {{ line-height: 1.55; }}
    .subtitle {{ color: #c4d2f5; margin-top: 12px; max-width: 760px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin-top: 20px; }}
    .card, .metric-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 18px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .26);
      backdrop-filter: blur(14px);
    }}
    .hero-card {{ background: rgba(255,255,255,.08); border-color: rgba(255,255,255,.15); }}
    .card span, .metric-card span {{ color: var(--muted); display: block; font-size: 13px; margin-bottom: 8px; }}
    .card strong, .metric-card strong {{ font-size: 30px; letter-spacing: -0.045em; }}
    section {{ margin-top: 26px; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 20px; overflow: hidden; box-shadow: 0 14px 34px rgba(0, 0, 0, .22); }}
    th, td {{ text-align: left; padding: 15px 16px; border-bottom: 1px solid rgba(139, 158, 255, .12); vertical-align: top; }}
    th {{ background: rgba(255,255,255,.05); color: #b9c9ee; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    tr:last-child td {{ border-bottom: 0; }}
    code {{ background: rgba(46, 233, 255, .10); color: #bff6ff; padding: 2px 7px; border-radius: 8px; }}
    ul {{ background: var(--panel); border: 1px solid var(--line); border-radius: 20px; padding: 18px 18px 18px 38px; box-shadow: 0 14px 34px rgba(0, 0, 0, .22); }}
    li {{ margin: 8px 0; color: #d7e2fb; }}
    .badge {{ display: inline-block; padding: 6px 11px; border-radius: 999px; font-weight: 800; font-size: 12px; letter-spacing: .04em; }}
    .pass {{ color: #052e16; background: linear-gradient(135deg, #86efac, #22c55e); }}
    .warn {{ color: #3b2500; background: linear-gradient(135deg, #fde68a, #f59e0b); }}
    .fail {{ color: #3b0505; background: linear-gradient(135deg, #fecaca, #ef4444); }}
    .missing, .unknown {{ color: #e5e7eb; background: rgba(148, 163, 184, .28); }}
    .score {{ font-size: 54px; color: var(--cyan); text-shadow: 0 0 26px rgba(46, 233, 255, .28); }}
    .note {{ color: #b9c9ee; font-size: 13px; margin-top: 8px; }}
    .executive {{ border-left: 4px solid var(--cyan); }}
    .sr-only {{ position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }}
    footer {{ margin-top: 30px; color: var(--muted); font-size: 13px; }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="kicker">DevSecOps · MCP · Agent Security</div>
      <h1>{html.escape(report['product'])}</h1>
      <p class="subtitle">Dashboard de producto generado en {html.escape(report['generated_at_utc'])}. Resume el estado del policy gate, evidencias, evaluación adversarial controlada y superficie MCP.</p>
      <div class="grid">
        <div class="card hero-card"><span>Estado del producto</span><strong>{status_badge(report['status'])}</strong></div>
        <div class="card hero-card"><span>Puntaje de seguridad</span><strong class="score">{int(report['security_score'])}/100</strong><p class="note">Máximo realista configurado: {int(report.get('score_ceiling', 100))}/100</p></div>
        <div class="card hero-card"><span>Issues bloqueantes</span><strong>{int(risk.get('blocking_issues', 0))}</strong></div>
        <div class="card hero-card"><span>Completitud de evidencia</span><strong>{float(risk.get('evidence_completeness_score', 0.0)) * 100:.1f}%</strong></div>
      </div>
    </header>

    <section>
      <h2>Lectura ejecutiva</h2>
      <div class="card executive">
        <p><strong>{html.escape(str(executive.get('posture', 'Sin lectura ejecutiva disponible.')))}</strong></p>
        <p>{html.escape(str(executive.get('score_note', '')))}</p>
        <p>{html.escape(str(executive.get('demo_message', '')))}</p>
      </div>
    </section>

    <section>
      <h2>Cobertura de controles</h2>
      <table>
        <thead><tr><th>Área</th><th>Control validado</th><th>Estado</th><th>Evidencia</th></tr></thead>
        <tbody>{control_rows}</tbody>
      </table>
    </section>

    <section>
      <h2>Estado de reportes</h2>
      <table>
        <thead><tr><th>Componente</th><th>Estado</th><th>Evidencia</th></tr></thead>
        <tbody>{status_rows}</tbody>
      </table>
    </section>

    <section>
      <h2>Métricas de evaluación controlada</h2>
      <div class="grid">{metric_cards}</div>
    </section>

    <section>
      <h2>Artefactos recientes</h2>
      <table>
        <thead><tr><th>Ruta</th><th>Tamaño</th></tr></thead>
        <tbody>{artifact_rows}</tbody>
      </table>
    </section>

    <section>
      <h2>Resumen de scanners</h2>
      <ul>{tool_items}</ul>
    </section>

    <section>
      <h2>Acciones recomendadas <span class="sr-only">Recommended actions</span></h2>
      <ul>{recommendation_items}</ul>
    </section>

    <footer>Raíz del repositorio: <code>{html.escape(report['repo_root'])}</code></footer>
  </main>
</body>
</html>
"""


def write_dashboard_html(
    report: dict[str, Any], output_path: Path, root: Path | None = None
) -> Path:
    """Escribe el dashboard HTML autocontenido."""
    base = resolve_repo_root(root)
    path = output_path if output_path.is_absolute() else base / output_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_dashboard_html(report), encoding="utf-8")
    return path


def format_status_text(report: dict[str, Any]) -> str:
    """Genera una salida textual compacta para terminal."""
    risk = report["risk_summary"]
    lines = [
        f"Producto: {report['product']}",
        f"Status: {report['status']}",
        f"Security Score: {report['security_score']}/100",
        f"Score Ceiling: {report.get('score_ceiling', 100)}/100",
        f"Posture: {(report.get('executive_summary') or {}).get('posture', 'n/a')}",
        f"Blocking Issues: {risk.get('blocking_issues', 0)}",
        f"Completitud de evidencia: {float(risk.get('evidence_completeness_score', 0.0)) * 100:.1f}%",
        "",
        "Reports:",
    ]

    for name, status in report["report_statuses"].items():
        lines.append(f"- {name}: {status}")

    lines.append("")
    lines.append("Recommended Actions:")
    for item in report.get("recommendations", []):
        lines.append(f"- {item}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI del dashboard."""
    parser = argparse.ArgumentParser(
        description="Generate a SkillChain-MCP Guard product dashboard."
    )
    parser.add_argument(
        "--root", default=str(REPO_ROOT), help="Raíz del repositorio a inspeccionar."
    )
    parser.add_argument(
        "--output", default=DASHBOARD_HTML_PATH, help="Ruta de salida del dashboard HTML."
    )
    parser.add_argument(
        "--json-output",
        default=PRODUCT_STATUS_PATH,
        help="Ruta de salida del JSON de estado del producto.",
    )
    parser.add_argument(
        "--print-summary", action="store_true", help="Print a terminal summary after generation."
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada CLI del generador de dashboard."""
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    report = build_product_status(root=root)
    json_path = write_product_status(report, Path(args.json_output), root=root)
    html_path = write_dashboard_html(report, Path(args.output), root=root)

    if args.print_summary:
        print(format_status_text(report))
    else:
        print(
            json.dumps(
                {
                    "status": report["status"],
                    "security_score": report["security_score"],
                    "json_output": str(json_path),
                    "dashboard_output": str(html_path),
                },
                ensure_ascii=False,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
