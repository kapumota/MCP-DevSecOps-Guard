"""Auditor estático para servidores MCP usados por el agente DevSecOps."""

from __future__ import annotations

import argparse
import ast
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .config import MCP_AUDIT_REPORT_PATH, REPO_ROOT
from .report_writer import write_json_report
from .security_models import RiskLevel, ScanStatus, SecurityFinding


MCP_DECORATORS: frozenset[str] = frozenset({"tool", "resource", "prompt"})
DIRECT_EXECUTION_CALLS: frozenset[str] = frozenset(
    {
        "os.system",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
)


def read_text_if_exists(path: Path) -> str:
    """Lee texto de forma tolerante para auditoría estática."""
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def dotted_name(node: ast.AST) -> str:
    """Convierte una expresión AST simple en nombre punteado."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def mcp_decorator_kind(decorator: ast.AST) -> str | None:
    """Detecta decoradores del patrón @mcp.tool, @mcp.resource o @mcp.prompt."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Attribute) and dotted_name(target.value) == "mcp":
        if target.attr in MCP_DECORATORS:
            return target.attr
    return None


def decorator_argument(decorator: ast.AST) -> str | None:
    """Extrae el primer argumento textual de un decorador MCP cuando existe."""
    if not isinstance(decorator, ast.Call) or not decorator.args:
        return None
    first_arg = decorator.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return first_arg.value
    return None


def component_risk(kind: str, name: str, locator: str | None) -> str:
    """Clasifica el riesgo inherente de una superficie MCP."""
    if kind == "resource" and locator and locator.startswith("artifact://"):
        return RiskLevel.MEDIUM.value
    if kind == "tool" and name.startswith(("run_", "execute_", "create_", "write_")):
        return RiskLevel.MEDIUM.value
    return RiskLevel.LOW.value


def component_mitigation(kind: str, name: str, locator: str | None) -> str:
    """Describe el control principal esperado para una superficie MCP."""
    if kind == "resource" and locator and locator.startswith("artifact://"):
        return "path_validation"
    if kind == "tool" and name.startswith(("run_", "execute_")):
        return "make_target_allowlist"
    if kind == "tool" and name.startswith(("create_", "write_")):
        return "controlled_output_path"
    if kind == "prompt":
        return "prompt_scope_review"
    return "least_privilege"


def discover_mcp_components(source_path: Path) -> list[dict[str, Any]]:
    """Descubre tools, resources y prompts expuestos por un archivo MCP."""
    source = source_path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(source_path))
    components: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            kind = mcp_decorator_kind(decorator)
            if not kind:
                continue
            locator = decorator_argument(decorator)
            components.append(
                {
                    "kind": kind,
                    "name": node.name,
                    "line": node.lineno,
                    "locator": locator,
                    "risk_level": component_risk(kind, node.name, locator),
                    "mitigation": component_mitigation(kind, node.name, locator),
                    "has_docstring": ast.get_docstring(node) is not None,
                    "arguments": [arg.arg for arg in node.args.args],
                    "call_names": sorted(find_call_names(node)),
                    "direct_execution_calls": sorted(find_direct_execution_calls(node)),
                }
            )
    return sorted(components, key=lambda item: (item["kind"], item["name"]))


def find_call_names(node: ast.AST) -> set[str]:
    """Lista nombres de llamadas usadas dentro de una función MCP."""
    calls: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = dotted_name(child.func)
            if name:
                calls.add(name)
    return calls


def find_direct_execution_calls(node: ast.AST) -> set[str]:
    """Busca ejecución directa de comandos dentro de una función MCP."""
    calls: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = dotted_name(child.func)
        if name in DIRECT_EXECUTION_CALLS or name in {"eval", "exec"}:
            calls.add(name)
    return calls


def analyze_mcp_controls(root: Path) -> dict[str, bool]:
    """Verifica controles defensivos implementados fuera del servidor MCP."""
    commands_text = read_text_if_exists(root / "src/devsecops_agent/commands.py")
    artifacts_text = read_text_if_exists(root / "src/devsecops_agent/artifacts.py")
    config_text = read_text_if_exists(root / "src/devsecops_agent/config.py")
    rbac_text = read_text_if_exists(root / "src/devsecops_agent/rbac.py")
    sandbox_text = read_text_if_exists(root / "src/devsecops_agent/sandbox.py")
    mcp_server_text = read_text_if_exists(root / "src/devsecops_agent/mcp_server.py")

    return {
        "make_target_allowlist": "ALLOWED_MAKE_TARGETS" in config_text and "validate_make_target" in commands_text,
        "timeout_validation": "validate_timeout" in commands_text and "MAX_TIMEOUT_SECONDS" in commands_text,
        "shell_false_execution": "shell=False" in commands_text or "shell=False" in sandbox_text,
        "artifact_path_validation": "safe_artifact_path" in artifacts_text and "allowed_base_dirs" in artifacts_text,
        "artifact_read_limit": "MAX_TEXT_BYTES" in artifacts_text,
        "rbac_authorization": "authorize_tool_invocation" in commands_text and "roles" in read_text_if_exists(root / "config/rbac.json"),
        "sandbox_execution": "run_sandboxed_make_target" in commands_text and "SandboxRunner" in sandbox_text,
        "mcp_tool_authorization": "require_mcp_tool" in mcp_server_text and "authorize_tool_invocation" in mcp_server_text,
    }


def add_finding(
    findings: list[SecurityFinding],
    rule_id: str,
    severity: RiskLevel,
    message: str,
    component: str,
    recommendation: str,
    evidence: str | None = None,
) -> None:
    """Agrega un hallazgo normalizado de auditoría MCP."""
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


def evaluate_mcp_findings(components: Sequence[dict[str, Any]], controls: dict[str, bool]) -> list[SecurityFinding]:
    """Evalúa hallazgos sobre la superficie MCP descubierta."""
    findings: list[SecurityFinding] = []

    if not components:
        add_finding(
            findings,
            "MCP001",
            RiskLevel.HIGH,
            "No se encontraron tools, resources ni prompts MCP.",
            "mcp_server",
            "Verifica que el servidor use decoradores @mcp.tool, @mcp.resource o @mcp.prompt.",
        )
        return findings

    for component in components:
        component_name = f"{component['kind']}:{component['name']}"
        if not component["has_docstring"]:
            add_finding(
                findings,
                "MCP002",
                RiskLevel.LOW,
                "La superficie MCP no tiene docstring descriptivo.",
                component_name,
                "Documenta intención, entradas y límites para reducir ambigüedad en clientes MCP.",
                evidence=f"line:{component['line']}",
            )

        for call in component["direct_execution_calls"]:
            add_finding(
                findings,
                "MCP003",
                RiskLevel.CRITICAL,
                "Una tool/resource/prompt MCP ejecuta comandos directamente.",
                component_name,
                "Encapsula ejecución en commands.py, usa shell=False, timeout y allowlist de targets.",
                evidence=call,
            )

        if component["kind"] == "tool" and component["name"].startswith(("run_", "execute_")):
            if not controls["make_target_allowlist"]:
                add_finding(
                    findings,
                    "MCP004",
                    RiskLevel.HIGH,
                    "La tool ejecutora no tiene allowlist central de targets.",
                    component_name,
                    "Valida toda ejecución contra ALLOWED_MAKE_TARGETS antes de invocar subprocess.",
                )
            if not controls["timeout_validation"]:
                add_finding(
                    findings,
                    "MCP005",
                    RiskLevel.MEDIUM,
                    "La tool ejecutora no valida timeouts.",
                    component_name,
                    "Limita duración mínima y máxima para evitar ejecuciones colgadas o abusivas.",
                )
            if not controls["shell_false_execution"]:
                add_finding(
                    findings,
                    "MCP006",
                    RiskLevel.HIGH,
                    "La ejecución controlada no evidencia shell=False.",
                    component_name,
                    "Evita shell=True y pasa argumentos como lista.",
                )

        locator = str(component.get("locator") or "")
        if component["kind"] == "resource" and locator.startswith("artifact://"):
            if not controls["artifact_path_validation"]:
                add_finding(
                    findings,
                    "MCP007",
                    RiskLevel.HIGH,
                    "El resource de artifacts no evidencia validación contra path traversal.",
                    component_name,
                    "Resuelve rutas con Path.resolve y limita lectura a artifacts/ y .evidence/.",
                )
            if not controls["artifact_read_limit"]:
                add_finding(
                    findings,
                    "MCP008",
                    RiskLevel.MEDIUM,
                    "El resource de artifacts no evidencia límite de lectura.",
                    component_name,
                    "Aplica un máximo de bytes por lectura para evitar respuestas excesivas.",
                )

        if component["kind"] == "tool":
            if "role" in component.get("arguments", []):
                add_finding(
                    findings,
                    "MCP009",
                    RiskLevel.HIGH,
                    "Una tool MCP permite que el cliente indique el rol RBAC.",
                    component_name,
                    "Obtén el rol desde identidad autenticada, variable de entorno controlada o política externa, no desde argumentos de la tool.",
                )
            if component["name"] != "run_devsecops_check" and "require_mcp_tool" not in component.get("call_names", []):
                add_finding(
                    findings,
                    "MCP010",
                    RiskLevel.MEDIUM,
                    "La tool MCP no pasa por autorización RBAC común.",
                    component_name,
                    "Invoca require_mcp_tool(nombre_de_tool) al inicio de cada tool expuesta por MCP.",
                )
            if component["name"] == "run_devsecops_check" and "require_mcp_tool" not in component.get("call_names", []):
                add_finding(
                    findings,
                    "MCP010",
                    RiskLevel.HIGH,
                    "La tool ejecutora no pasa por autorización RBAC común.",
                    component_name,
                    "Autoriza el target con require_mcp_tool antes de ejecutar cualquier comando.",
                )

    return findings


def count_findings(findings: Sequence[SecurityFinding]) -> dict[str, int]:
    """Cuenta hallazgos por severidad normalizada."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for finding in findings:
        severity = finding.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1
        counts["total"] += 1
    counts["high_or_critical"] = counts.get("critical", 0) + counts.get("high", 0)
    return counts


def determine_status(findings: Sequence[SecurityFinding]) -> ScanStatus:
    """Determina PASS/WARN/FAIL para la auditoría MCP."""
    severities = {finding.severity for finding in findings}
    if RiskLevel.CRITICAL.value in severities or RiskLevel.HIGH.value in severities:
        return ScanStatus.FAIL
    if RiskLevel.MEDIUM.value in severities or RiskLevel.LOW.value in severities:
        return ScanStatus.WARN
    return ScanStatus.PASS


def determine_overall_risk(components: Sequence[dict[str, Any]], findings: Sequence[SecurityFinding]) -> str:
    """Calcula riesgo agregado combinando riesgo inherente y hallazgos."""
    ordered = {RiskLevel.LOW.value: 0, RiskLevel.MEDIUM.value: 1, RiskLevel.HIGH.value: 2, RiskLevel.CRITICAL.value: 3}
    values = [ordered.get(str(component.get("risk_level", RiskLevel.LOW.value)), 0) for component in components]
    values.extend(ordered.get(finding.severity, 0) for finding in findings)
    if not values:
        return RiskLevel.HIGH.value
    max_value = max(values)
    for level, value in ordered.items():
        if value == max_value:
            return level
    return RiskLevel.LOW.value


def audit_mcp_server(root: Path | None = None, source: str = "src/devsecops_agent/mcp_server.py") -> dict[str, Any]:
    """Ejecuta auditoría estática sobre el servidor MCP del repositorio."""
    base = (root or REPO_ROOT).resolve()
    source_path = (base / source).resolve()
    controls = analyze_mcp_controls(base)

    if not source_path.exists():
        finding = SecurityFinding(
            rule_id="MCP000",
            severity=RiskLevel.HIGH.value,
            message="No existe el archivo de servidor MCP esperado.",
            component=source,
            recommendation="Crea src/devsecops_agent/mcp_server.py o ajusta la ruta del auditor.",
            evidence=str(source_path),
        )
        findings = [finding]
        components: list[dict[str, Any]] = []
    else:
        components = discover_mcp_components(source_path)
        findings = evaluate_mcp_findings(components, controls)

    tools = [item for item in components if item["kind"] == "tool"]
    resources = [item for item in components if item["kind"] == "resource"]
    prompts = [item for item in components if item["kind"] == "prompt"]
    counts = count_findings(findings)
    overall_risk = determine_overall_risk(components, findings)

    return {
        "auditor": "skillchain-mcp-guard-mcp-auditor",
        "status": determine_status(findings).value,
        "repo_root": str(base),
        "source": source,
        "overall_risk": overall_risk,
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
        "surface": {
            "tool_count": len(tools),
            "resource_count": len(resources),
            "prompt_count": len(prompts),
            "tools": tools,
            "resources": resources,
            "prompts": prompts,
        },
        "controls": controls,
        "finding_counts": counts,
        "findings": [finding.to_dict() for finding in findings],
    }


def write_audit_report(report: dict[str, Any], output_path: Path, root: Path | None = None) -> Path:
    """Escribe el reporte de auditoría MCP en formato JSON."""
    return write_json_report(report, output_path, root=root)


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI del auditor MCP."""
    parser = argparse.ArgumentParser(description="Audita tools, resources y prompts MCP para detectar exposición insegura.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Raíz del repositorio a auditar.")
    parser.add_argument("--source", default="src/devsecops_agent/mcp_server.py", help="Ruta del archivo fuente del servidor MCP.")
    parser.add_argument("--output", default=MCP_AUDIT_REPORT_PATH, help="Ruta de salida del reporte JSON.")
    parser.add_argument("--fail-on-high", action="store_true", help="Devuelve estado 2 si existen hallazgos altos o críticos.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada CLI para generar la auditoría MCP."""
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    report = audit_mcp_server(root=root, source=args.source)
    output = write_audit_report(report, Path(args.output), root=root)
    print(json.dumps({"status": report["status"], "output": str(output)}, ensure_ascii=False))

    if args.fail_on_high and report["finding_counts"]["high_or_critical"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
