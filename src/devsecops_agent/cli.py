"""CLI final de producto para SkillChain-MCP Guard."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .config import (
    DASHBOARD_HTML_PATH,
    EVALUATION_REPORT_PATH,
    MCP_AUDIT_REPORT_PATH,
    POLICY_REPORT_PATH,
    PRODUCT_STATUS_PATH,
    REPO_ROOT,
    SKILL_REPORT_PATH,
)
from .dashboard import (
    build_product_status,
    format_status_text,
    write_dashboard_html,
    write_product_status,
)
from .evaluation_harness import run_controlled_evaluation, write_evaluation_report
from .mcp_auditor import audit_mcp_server, write_audit_report
from .evidence_pack import create_evidence_pack, verify_evidence_pack
from .policy_engine import VALID_POLICY_MODES, evaluate_policy, write_policy_report
from .local_evidence import generate_local_evidence
from .security_models import ScanStatus
from .skill_scanner import scan_skills, write_scan_report


def generate_product_reports(root: Path) -> dict[str, Path]:
    """Ejecuta checks livianos de producto y escribe reportes JSON principales."""
    skill_report = scan_skills(root=root)
    skill_path = write_scan_report(skill_report, Path(SKILL_REPORT_PATH), root=root)

    mcp_report = audit_mcp_server(root=root)
    mcp_path = write_audit_report(mcp_report, Path(MCP_AUDIT_REPORT_PATH), root=root)

    eval_report = run_controlled_evaluation(root=root)
    eval_path = write_evaluation_report(eval_report, Path(EVALUATION_REPORT_PATH), root=root)

    generate_local_evidence(root=root)
    policy_report = evaluate_policy(root=root, mode="demo")
    policy_path = write_policy_report(policy_report, Path(POLICY_REPORT_PATH), root=root)

    product_status = build_product_status(root=root)
    product_path = write_product_status(product_status, Path(PRODUCT_STATUS_PATH), root=root)

    dashboard_path = write_dashboard_html(product_status, Path(DASHBOARD_HTML_PATH), root=root)

    return {
        "skill_report": skill_path,
        "mcp_report": mcp_path,
        "evaluation_report": eval_path,
        "policy_report": policy_path,
        "product_status": product_path,
        "dashboard": dashboard_path,
    }


def command_scan(args: argparse.Namespace) -> int:
    """Ejecuta el flujo liviano de producto para demo local."""
    root = Path(args.root).resolve()
    outputs = generate_product_reports(root)
    report = build_product_status(root=root)

    payload = {
        "status": report["status"],
        "security_score": report["security_score"],
        "outputs": {name: str(path) for name, path in outputs.items()},
    }
    print(json.dumps(payload, indent=2 if args.json else None, ensure_ascii=False))

    if args.fail_on_fail and report["status"] == ScanStatus.FAIL.value:
        return 2
    return 0


def command_status(args: argparse.Namespace) -> int:
    """Muestra el estado actual de producto sin regenerar scanners."""
    root = Path(args.root).resolve()
    report = build_product_status(root=root)
    write_product_status(report, Path(args.output), root=root)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_status_text(report))

    if args.fail_on_fail and report["status"] == ScanStatus.FAIL.value:
        return 2
    return 0


def command_dashboard(args: argparse.Namespace) -> int:
    """Genera el dashboard HTML y el JSON de estado de producto."""
    root = Path(args.root).resolve()
    report = build_product_status(root=root)
    product_path = write_product_status(report, Path(args.json_output), root=root)
    dashboard_path = write_dashboard_html(report, Path(args.output), root=root)

    payload = {
        "status": report["status"],
        "security_score": report["security_score"],
        "product_status": str(product_path),
        "dashboard": str(dashboard_path),
    }
    print(json.dumps(payload, indent=2 if args.json else None, ensure_ascii=False))
    return 0


def command_audit_mcp(args: argparse.Namespace) -> int:
    """Ejecuta solo la auditoría MCP y escribe su reporte."""
    root = Path(args.root).resolve()
    report = audit_mcp_server(root=root)
    output = write_audit_report(report, Path(args.output), root=root)
    payload = {"status": report["status"], "overall_risk": report.get("overall_risk", "unknown"), "output": str(output)}
    print(json.dumps(payload, indent=2 if args.json else None, ensure_ascii=False))
    if args.fail_on_fail and report["status"] == ScanStatus.FAIL.value:
        return 2
    return 0


def command_benchmark_run(args: argparse.Namespace) -> int:
    """Ejecuta el benchmark adversarial controlado."""
    root = Path(args.root).resolve()
    report = run_controlled_evaluation(root=root)
    output = write_evaluation_report(report, Path(args.output), root=root)
    payload = {
        "status": report["status"],
        "case_count": report["metrics"]["case_count"],
        "precision": report["metrics"].get("precision"),
        "recall": report["metrics"].get("recall"),
        "f1": report["metrics"].get("f1"),
        "known_limitation_case_count": report["metrics"].get("known_limitation_case_count"),
        "output": str(output),
    }
    print(json.dumps(payload, indent=2 if args.json else None, ensure_ascii=False))
    if args.fail_on_fail and report["status"] == ScanStatus.FAIL.value:
        return 2
    return 0


def command_policy_check(args: argparse.Namespace) -> int:
    """Ejecuta el policy gate y escribe su reporte."""
    root = Path(args.root).resolve()
    report = evaluate_policy(root=root, mode=args.mode)
    output = write_policy_report(report, Path(args.output), root=root)
    payload = {
        "status": report["status"],
        "mode": report.get("mode", args.mode),
        "fallback_allowed": report.get("fallback_allowed", False),
        "blocking_issues": report.get("blocking_issues", 0),
        "warnings": report.get("warnings", 0),
        "evidence_completeness": report.get("evidence_completeness_score", 0.0),
        "output": str(output),
    }
    print(json.dumps(payload, indent=2 if args.json else None, ensure_ascii=False))
    if report["status"] == ScanStatus.FAIL.value and not args.no_fail_on_fail:
        return 2
    return 0


def command_report(args: argparse.Namespace) -> int:
    """Genera estado agregado, dashboard y opcionalmente evidence pack."""
    root = Path(args.root).resolve()
    if args.generate_local_evidence:
        generate_local_evidence(root=root)
    report = build_product_status(root=root)
    product_path = write_product_status(report, Path(args.output), root=root)
    dashboard_path = write_dashboard_html(report, Path(args.dashboard_output), root=root)
    payload = {
        "status": report["status"],
        "security_score": report["security_score"],
        "product_status": str(product_path),
        "dashboard": str(dashboard_path),
    }
    if args.evidence_pack:
        manifest = create_evidence_pack(root=root)
        payload["evidence_pack"] = manifest["pack_path"]
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(format_status_text(report))
        print(f"Estado del producto: {product_path}")
        print(f"Dashboard: {dashboard_path}")
        if "evidence_pack" in payload:
            print(f"Evidence pack: {payload['evidence_pack']}")
    return 0


def command_local_evidence(args: argparse.Namespace) -> int:
    """Genera evidencias locales mínimas para policy-check reproducible."""
    report = generate_local_evidence(root=Path(args.root).resolve())
    print(json.dumps(report, indent=2 if args.json else None, ensure_ascii=False))
    return 0


def command_evidence_verify(args: argparse.Namespace) -> int:
    """Verifica un evidence pack contra su manifiesto sidecar."""
    root = Path(args.root).resolve()
    result = verify_evidence_pack(root=root, pack_path=Path(args.pack), manifest_path=Path(args.manifest))
    print(json.dumps(result, indent=2 if args.json else None, ensure_ascii=False))
    return 0 if result["status"] == "PASS" else 2


def command_evidence_create(args: argparse.Namespace) -> int:
    """Crea un evidence pack y manifiesto sidecar."""
    root = Path(args.root).resolve()
    manifest = create_evidence_pack(root=root, output_path=Path(args.output) if args.output else None)
    print(json.dumps({"status": "PASS", "pack_path": manifest["pack_path"], "manifest_path": manifest["manifest_path"]}, indent=2 if args.json else None, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser principal del CLI de producto."""
    parser = argparse.ArgumentParser(
        prog="skillchain",
        description="CLI de producto para SkillChain-MCP Guard.",
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="Raíz del repositorio a inspeccionar o escanear.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Ejecuta checks livianos y genera dashboard.")
    scan_parser.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    scan_parser.add_argument("--fail-on-fail", action="store_true", help="Devuelve 2 cuando el estado del producto es FAIL.")
    scan_parser.set_defaults(func=command_scan)

    status_parser = subparsers.add_parser("status", help="Muestra el estado actual desde reportes existentes.")
    status_parser.add_argument("--json", action="store_true", help="Imprime el estado JSON completo.")
    status_parser.add_argument("--output", default=PRODUCT_STATUS_PATH, help="Ruta del JSON de estado del producto.")
    status_parser.add_argument("--fail-on-fail", action="store_true", help="Devuelve 2 cuando el estado del producto es FAIL.")
    status_parser.set_defaults(func=command_status)

    dashboard_parser = subparsers.add_parser("dashboard", help="Genera el dashboard HTML del producto.")
    dashboard_parser.add_argument("--output", default=DASHBOARD_HTML_PATH, help="Ruta de salida del dashboard HTML.")
    dashboard_parser.add_argument("--json-output", default=PRODUCT_STATUS_PATH, help="Ruta de salida del JSON de estado del producto.")
    dashboard_parser.add_argument("--json", action="store_true", help="Imprime salida legible del comando.")
    dashboard_parser.set_defaults(func=command_dashboard)


    audit_parser = subparsers.add_parser("audit-mcp", help="Ejecuta auditoría MCP y escribe reporte JSON.")
    audit_parser.add_argument("--output", default=MCP_AUDIT_REPORT_PATH, help="Ruta del JSON de auditoría MCP.")
    audit_parser.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    audit_parser.add_argument("--fail-on-fail", action="store_true", help="Devuelve 2 cuando la auditoría MCP queda en FAIL.")
    audit_parser.set_defaults(func=command_audit_mcp)

    policy_parser = subparsers.add_parser("policy-check", help="Ejecuta el policy gate y escribe reporte JSON.")
    policy_parser.add_argument("--output", default=POLICY_REPORT_PATH, help="Ruta del JSON de política.")
    policy_parser.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    policy_parser.add_argument("--mode", choices=sorted(VALID_POLICY_MODES), default="strict", help="Perfil de política: demo, ci o strict.")
    policy_parser.add_argument(
        "--fail-on-fail",
        action="store_true",
        help="Compatibilidad: policy-check ya devuelve exit 2 por defecto cuando el estado es FAIL.",
    )
    policy_parser.add_argument(
        "--no-fail-on-fail",
        action="store_true",
        help="Solo inspección: devuelve exit 0 aunque el policy status sea FAIL.",
    )
    policy_parser.set_defaults(func=command_policy_check)

    report_parser = subparsers.add_parser("report", help="Genera reporte de producto, dashboard y evidence pack opcional.")
    report_parser.add_argument("--output", default=PRODUCT_STATUS_PATH, help="Ruta del JSON de estado del producto.")
    report_parser.add_argument("--dashboard-output", default=DASHBOARD_HTML_PATH, help="Ruta del dashboard HTML.")
    report_parser.add_argument("--json", action="store_true", help="Imprime salida legible del comando.")
    report_parser.add_argument("--evidence-pack", action="store_true", help="También crea evidence-pack tar.gz.")
    report_parser.add_argument("--generate-local-evidence", action="store_true", help="Crea evidencia fallback local antes de reportar.")
    report_parser.set_defaults(func=command_report)

    local_evidence_parser = subparsers.add_parser("local-evidence", help="Genera evidencia fallback local.")
    local_evidence_parser.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    local_evidence_parser.set_defaults(func=command_local_evidence)

    evidence_parser = subparsers.add_parser("evidence", help="Crea o verifica evidence packs.")
    evidence_subparsers = evidence_parser.add_subparsers(dest="evidence_command", required=True)

    evidence_create = evidence_subparsers.add_parser("create", help="Crea evidence-pack tar.gz y manifiesto sidecar.")
    evidence_create.add_argument("--output", default=None, help="Ruta opcional del evidence-pack tar.gz.")
    evidence_create.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    evidence_create.set_defaults(func=command_evidence_create)

    evidence_verify = evidence_subparsers.add_parser("verify", help="Verifica evidence-pack tar.gz contra evidence-manifest.json.")
    evidence_verify.add_argument("pack", help="Ruta al evidence-pack tar.gz.")
    evidence_verify.add_argument("--manifest", default="artifacts/evidence-manifest.json", help="Ruta al manifiesto sidecar JSON.")
    evidence_verify.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    evidence_verify.set_defaults(func=command_evidence_verify)


    benchmark_parser = subparsers.add_parser("benchmark", help="Ejecuta benchmark adversarial.")
    benchmark_subparsers = benchmark_parser.add_subparsers(dest="benchmark_command", required=True)
    benchmark_run_parser = benchmark_subparsers.add_parser("run", help="Ejecuta el benchmark adversarial controlado.")
    benchmark_run_parser.add_argument("--suite", default="eval_cases", help="Suite declarativa; reservado para compatibilidad.")
    benchmark_run_parser.add_argument("--output", default="artifacts/benchmark-report.json", help="Ruta de salida JSON.")
    benchmark_run_parser.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    benchmark_run_parser.add_argument("--fail-on-fail", action="store_true", help="Devuelve 2 si el benchmark falla.")
    benchmark_run_parser.set_defaults(func=command_benchmark_run)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI final de producto."""
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
