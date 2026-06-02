"""Generación local de evidencias mínimas sin depender de herramientas externas."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifacts import ensure_artifact_dirs, resolve_repo_root
from .config import LEGACY_PIP_AUDIT_REPORT_PATH, PIP_AUDIT_REPORT_PATHS, REPO_ROOT
from .report_writer import read_json_report, write_json_report

LOCAL_EVIDENCE_GENERATOR = "skillchain-local-evidence"


def utc_now() -> str:
    """Devuelve una marca temporal UTC serializable."""
    return datetime.now(UTC).isoformat()


REQUIREMENT_FILES: tuple[str, ...] = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-mcp.txt",
)


def parse_requirements(
    root: Path, filenames: tuple[str, ...] = REQUIREMENT_FILES
) -> list[dict[str, str]]:
    """Extrae dependencias directas desde archivos requirements con parsing conservador."""
    components: list[dict[str, str]] = []
    seen: set[str] = set()
    for filename in filenames:
        path = root / filename
        if not path.exists():
            continue
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(
                r"(?P<name>[A-Za-z0-9_.-]+)\s*(?P<op>==|>=|<=|~=|>|<)?\s*(?P<version>[^;#\s]+)?",
                line,
            )
            if not match:
                continue
            name = match.group("name")
            version = match.group("version") or "unspecified"
            key = f"{filename}:{name.lower()}"
            if key in seen:
                continue
            seen.add(key)
            components.append({"name": name, "version": version, "source": filename})
    return sorted(components, key=lambda item: (item["source"], item["name"].lower()))


def docker_base_image(root: Path) -> str:
    """Obtiene la imagen base declarada en docker/Dockerfile si existe."""
    dockerfile = root / "docker" / "Dockerfile"
    if not dockerfile.exists():
        return "unknown"
    for line in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            return stripped.split()[1]
    return "unknown"


def should_preserve_json(path: Path) -> bool:
    """Evita sobrescribir evidencia real ya existente y válida."""
    return read_json_report(path) is not None


def should_preserve_text(path: Path) -> bool:
    """Evita sobrescribir evidencia textual ya existente y no vacía."""
    return path.exists() and path.is_file() and path.stat().st_size > 0


def write_if_missing(root: Path, relative_path: str, payload: dict[str, Any]) -> Path:
    """Escribe JSON solo cuando el archivo falta, está vacío o no es JSON objeto."""
    path = root / relative_path
    if should_preserve_json(path):
        return path
    return write_json_report(payload, Path(relative_path), root=root)


def build_project_sbom(root: Path) -> dict[str, Any]:
    """Construye un SBOM mínimo del proyecto usando archivos de dependencias locales."""
    components = parse_requirements(root)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:skillchain-local-project-sbom",
        "version": 1,
        "metadata": {
            "timestamp": utc_now(),
            "tools": [{"vendor": "local", "name": LOCAL_EVIDENCE_GENERATOR, "version": "1"}],
            "component": {"type": "application", "name": "skillchain-mcp-guard"},
        },
        "components": [
            {
                "type": "library",
                "name": item["name"],
                "version": item["version"],
                "scope": "required",
            }
            for item in components
        ],
        "packages": components,
    }


def build_image_sbom(root: Path) -> dict[str, Any]:
    """Construye un SBOM mínimo de imagen a partir del Dockerfile local."""
    base_image = docker_base_image(root)
    packages = [
        {"name": "base-image", "version": base_image, "source": "docker/Dockerfile"},
        {"name": "application", "version": "local-source", "source": "src/"},
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:skillchain-local-image-sbom",
        "version": 1,
        "metadata": {
            "timestamp": utc_now(),
            "tools": [{"vendor": "local", "name": LOCAL_EVIDENCE_GENERATOR, "version": "1"}],
            "component": {"type": "container", "name": "python-microservice:dev"},
        },
        "components": [
            {
                "type": "container" if item["name"] == "base-image" else "application",
                "name": item["name"],
                "version": item["version"],
            }
            for item in packages
        ],
        "packages": packages,
    }


def build_bandit_report() -> dict[str, Any]:
    """Genera una salida Bandit compatible sin hallazgos para el flujo local liviano."""
    return {
        "generated_by": LOCAL_EVIDENCE_GENERATOR,
        "tool_mode": "stdlib-fallback",
        "not_a_real_scan": True,
        "replacement_command": "make sast",
        "created_at_utc": utc_now(),
        "metrics": {"_totals": {"CONFIDENCE.HIGH": 0, "SEVERITY.HIGH": 0}},
        "results": [],
    }


def build_semgrep_report() -> dict[str, Any]:
    """Genera una salida Semgrep compatible sin hallazgos para el flujo local liviano."""
    return {
        "generated_by": LOCAL_EVIDENCE_GENERATOR,
        "tool_mode": "stdlib-fallback",
        "not_a_real_scan": True,
        "replacement_command": "make sast",
        "created_at_utc": utc_now(),
        "errors": [],
        "paths": {"scanned": ["src", "tests"]},
        "results": [],
    }


def build_pip_audit_report(root: Path, requirement_file: str) -> dict[str, Any]:
    """Genera salida pip-audit compatible para un archivo requirements específico."""
    return {
        "generated_by": LOCAL_EVIDENCE_GENERATOR,
        "tool_mode": "stdlib-fallback",
        "not_a_real_scan": True,
        "requirement_file": requirement_file,
        "replacement_command": f"pip-audit -r {requirement_file}",
        "created_at_utc": utc_now(),
        "dependencies": [
            {"name": item["name"], "version": item["version"], "vulns": []}
            for item in parse_requirements(root, (requirement_file,))
        ],
    }


def build_grype_sarif() -> dict[str, Any]:
    """Genera SARIF mínimo compatible con consumidores de Grype."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "generated_by": LOCAL_EVIDENCE_GENERATOR,
        "tool_mode": "stdlib-fallback",
        "not_a_real_scan": True,
        "replacement_command": "make scan-image",
        "runs": [
            {
                "tool": {"driver": {"name": LOCAL_EVIDENCE_GENERATOR, "informationUri": "local"}},
                "results": [],
            }
        ],
    }


def build_trivy_sarif() -> dict[str, Any]:
    """Genera SARIF mínimo compatible con Trivy para demo local."""
    report = build_grype_sarif()
    report["replacement_command"] = "make scan-image"
    report["runs"][0]["tool"]["driver"]["name"] = LOCAL_EVIDENCE_GENERATOR
    return report


def build_gitleaks_sarif() -> dict[str, Any]:
    """Genera SARIF mínimo compatible con Gitleaks para demo local."""
    report = build_grype_sarif()
    report["replacement_command"] = "make secret-scan"
    report["runs"][0]["tool"]["driver"]["name"] = LOCAL_EVIDENCE_GENERATOR
    return report


def build_scorecard_report() -> dict[str, Any]:
    """Genera salida OpenSSF Scorecard mínima para demo local."""
    return {
        "generated_by": LOCAL_EVIDENCE_GENERATOR,
        "tool_mode": "stdlib-fallback",
        "not_a_real_scan": True,
        "replacement_command": "make openssf-scorecard",
        "created_at_utc": utc_now(),
        "score": None,
        "checks": [],
    }


def build_zap_report() -> dict[str, Any]:
    """Genera salida mínima compatible con OWASP ZAP baseline."""
    return {
        "generated_by": LOCAL_EVIDENCE_GENERATOR,
        "tool_mode": "stdlib-fallback",
        "not_a_real_scan": True,
        "replacement_command": "make compose-up dast compose-down",
        "created_at_utc": utc_now(),
        "site": [{"@name": "http://127.0.0.1:8000", "alerts": []}],
    }


def generate_local_evidence(root: Path | None = None) -> dict[str, Any]:
    """Genera evidencias mínimas necesarias para ejecutar policy-check localmente."""
    base = resolve_repo_root(root)
    ensure_artifact_dirs(base)

    pip_reports = {
        PIP_AUDIT_REPORT_PATHS[0]: build_pip_audit_report(base, "requirements.txt"),
        PIP_AUDIT_REPORT_PATHS[1]: build_pip_audit_report(base, "requirements-dev.txt"),
        PIP_AUDIT_REPORT_PATHS[2]: build_pip_audit_report(base, "requirements-mcp.txt"),
        LEGACY_PIP_AUDIT_REPORT_PATH: {
            "generated_by": LOCAL_EVIDENCE_GENERATOR,
            "tool_mode": "stdlib-fallback",
            "not_a_real_scan": True,
            "replacement_command": "make sca",
            "created_at_utc": utc_now(),
            "dependencies": [
                {"name": item["name"], "version": item["version"], "vulns": []}
                for item in parse_requirements(base)
            ],
        },
    }

    outputs = {
        "artifacts/bandit.json": build_bandit_report(),
        "artifacts/semgrep.json": build_semgrep_report(),
        **pip_reports,
        "artifacts/sbom-project.json": build_project_sbom(base),
        "artifacts/sbom-image.json": build_image_sbom(base),
        "artifacts/grype-image.sarif": build_grype_sarif(),
        "artifacts/trivy-image.sarif": build_trivy_sarif(),
        "artifacts/gitleaks.sarif": build_gitleaks_sarif(),
        "artifacts/scorecard.json": build_scorecard_report(),
        "artifacts/zap-baseline.json": build_zap_report(),
    }

    written: list[str] = []
    preserved: list[str] = []
    for relative_path, payload in outputs.items():
        path = base / relative_path
        if should_preserve_json(path):
            preserved.append(relative_path)
            continue
        write_json_report(payload, Path(relative_path), root=base)
        written.append(relative_path)

    # Alias de compatibilidad con versiones previas que usaban nombres Syft explícitos.
    aliases = {
        "artifacts/sbom-syft-project.json": "artifacts/sbom-project.json",
        "artifacts/sbom-syft-image.json": "artifacts/sbom-image.json",
    }
    for alias, source in aliases.items():
        alias_path = base / alias
        if should_preserve_json(alias_path):
            preserved.append(alias)
            continue
        payload = read_json_report(base / source)
        if payload is not None:
            write_json_report(payload, Path(alias), root=base)
            written.append(alias)

    fallback_present = bool(written)
    for relative_path in outputs:
        payload = read_json_report(base / relative_path)
        if isinstance(payload, dict) and (
            payload.get("generated_by") == LOCAL_EVIDENCE_GENERATOR
            or payload.get("tool_mode") == "stdlib-fallback"
        ):
            fallback_present = True
            break

    operational = {
        "status": "WARN" if fallback_present else "PASS",
        "generated_by": LOCAL_EVIDENCE_GENERATOR,
        "not_a_real_scan": True,
        "created_at_utc": utc_now(),
        "written": written,
        "preserved": preserved,
        "warning": "Los archivos escritos son evidencia fallback para el flujo local; no sustituyen scanners reales.",
    }
    write_json_report(operational, Path(".evidence/local-security.json"), root=base)

    return operational


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI para evidencias locales."""
    parser = argparse.ArgumentParser(
        description="Generate local DevSecOps evidence without external tools."
    )
    parser.add_argument(
        "--root", default=str(REPO_ROOT), help="Raíz del repositorio a inspeccionar."
    )
    parser.add_argument("--json", action="store_true", help="Imprime JSON legible.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada para generar evidencias locales."""
    args = build_parser().parse_args(argv)
    report = generate_local_evidence(root=Path(args.root).resolve())
    print(json.dumps(report, indent=2 if args.json else None, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
