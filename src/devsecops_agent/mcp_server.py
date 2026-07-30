"""Servidor MCP para exponer capacidades DevSecOps controladas a agentes."""

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from .artifacts import (
    list_artifacts,
    read_named_artifact_text,
    repo_root,
    summarize_security_findings,
)
from .commands import ALLOWED_MAKE_TARGETS, run_make_target
from .dashboard import build_product_status, write_dashboard_html, write_product_status
from .evaluation_harness import run_controlled_evaluation
from .evidence_pack import create_evidence_pack
from .mcp_auditor import audit_mcp_server as run_mcp_audit
from .policy_engine import evaluate_policy as run_policy_evaluation
from .rbac import authorize_tool_invocation
from .skill_scanner import scan_skills

mcp = FastMCP("skillchain-mcp-guard")


def require_mcp_tool(tool_name: str, target: str | None = None) -> dict[str, Any]:
    """Autoriza una tool MCP usando solo el rol efectivo del entorno controlado."""
    return authorize_tool_invocation(
        role=None, tool_name=tool_name, target=target, root=repo_root()
    )


def read_repo_text(relative_path: str, fallback: str) -> str:
    """Lee un archivo Markdown del repositorio como contexto MCP."""
    path = repo_root() / relative_path
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else fallback


@mcp.resource("repo://readme")
def repo_readme() -> str:
    """Devuelve README.md como contexto principal del repositorio."""
    return read_repo_text("README.md", "README.md no encontrado")


@mcp.resource("repo://project")
def project_summary() -> str:
    """Devuelve el resumen principal del proyecto."""
    return read_repo_text("README.md", "README.md no encontrado")


@mcp.resource("repo://security")
def security_policy() -> str:
    """Devuelve la política de seguridad ubicada en docs/."""
    return read_repo_text(
        "docs/SEGURIDAD.md",
        "docs/SEGURIDAD.md no encontrado",
    )


@mcp.resource("artifact://{filename}")
def artifact_file(filename: str) -> str:
    """Lee una evidencia generada bajo artifacts/ usando solo nombre de archivo."""
    return read_named_artifact_text("artifacts", filename)


@mcp.resource("evidence://{filename}")
def evidence_file(filename: str) -> str:
    """Lee una evidencia operativa generada bajo .evidence/ usando solo nombre de archivo."""
    return read_named_artifact_text(".evidence", filename)


@mcp.tool()
def list_devsecops_artifacts() -> list:
    """Lista evidencias generadas por el pipeline."""
    require_mcp_tool("list_devsecops_artifacts")
    return list_artifacts()


@mcp.tool()
def run_devsecops_check(target: str, timeout_seconds: int = 180) -> dict:
    """Ejecuta un target Makefile permitido, autorizado por RBAC y sandbox."""
    require_mcp_tool("run_devsecops_check", target=target)
    return run_make_target(target=target, timeout_seconds=timeout_seconds)


@mcp.tool()
def allowed_devsecops_targets() -> list:
    """Muestra los targets Makefile que el servidor MCP puede ejecutar."""
    require_mcp_tool("allowed_devsecops_targets")
    return sorted(ALLOWED_MAKE_TARGETS)


@mcp.tool()
def summarize_findings() -> dict:
    """Resume evidencia de Bandit, Semgrep, pip-audit, Syft, Grype y ZAP."""
    require_mcp_tool("summarize_findings")
    return summarize_security_findings()


@mcp.tool()
def scan_agent_skills() -> dict:
    """Audita los SKILL.md del repositorio y devuelve hallazgos estructurales/de seguridad."""
    require_mcp_tool("scan_agent_skills")
    return scan_skills(root=repo_root())


@mcp.tool()
def audit_mcp_server() -> dict:
    """Audita tools, resources, prompts y controles del servidor MCP."""
    require_mcp_tool("audit_mcp_server")
    return run_mcp_audit(root=repo_root())


@mcp.tool()
def evaluate_policy_gate() -> dict:
    """Evalúa Skill Scanner, MCP Auditor y evidencias mínimas para PASS/WARN/FAIL."""
    require_mcp_tool("evaluate_policy_gate")
    return run_policy_evaluation(root=repo_root())


@mcp.tool()
def run_adversarial_evaluation() -> dict:
    """Ejecuta casos adversariales controlados contra skills, tools y resources."""
    require_mcp_tool("run_adversarial_evaluation")
    return run_controlled_evaluation(root=repo_root())


@mcp.tool()
def create_evidence_archive() -> dict:
    """Crea un paquete tar.gz con manifiesto e integridad SHA-256 de evidencias."""
    require_mcp_tool("create_evidence_archive")
    return create_evidence_pack(root=repo_root())


@mcp.tool()
def generate_product_dashboard() -> dict:
    """Genera el dashboard HTML y el resumen JSON de estado de producto."""
    require_mcp_tool("generate_product_dashboard")
    root = repo_root()
    report = build_product_status(root=root)
    json_path = write_product_status(report, root / "artifacts/product-status.json", root=root)
    dashboard_path = write_dashboard_html(report, root / "artifacts/dashboard.html", root=root)

    return {
        "status": report["status"],
        "security_score": report["security_score"],
        "product_status": str(json_path),
        "dashboard": str(dashboard_path),
    }


@mcp.prompt()
def triage_security_findings(release_goal: str = "demo local de investigación") -> str:
    """Genera un flujo estructurado de triage sobre la evidencia actual."""
    evidence = json.dumps(summarize_security_findings(), indent=2, ensure_ascii=False)

    # El prompt está en español porque la salida esperada del proyecto es documentación local.
    return f"""
Actúa como revisor DevSecOps. Objetivo de release: {release_goal}.

Usa esta evidencia generada por el pipeline:
{evidence}

Entrega:
1. Resumen ejecutivo de riesgo.
2. Tabla de hallazgos priorizados por severidad, explotabilidad y blast radius.
3. Acciones de remediación reproducibles con comandos Makefile.
4. Limitaciones de la evidencia y experimentos faltantes.
5. Criterio claro de aceptación para pasar a Done.
""".strip()


if __name__ == "__main__":
    mcp.run()
