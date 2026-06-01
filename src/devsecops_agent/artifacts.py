"""Lectura y resumen seguro de evidencias DevSecOps."""

from __future__ import annotations

from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import json
from typing import Any

from .config import ARTIFACT_DIRS, LEGACY_PIP_AUDIT_REPORT_PATH, MAX_TEXT_BYTES, PIP_AUDIT_REPORT_PATHS, REPO_ROOT
from .security_models import ArtifactInfo


def repo_root() -> Path:
    """Devuelve la raíz configurada del repositorio."""
    return REPO_ROOT


def resolve_repo_root(root: Path | None = None) -> Path:
    """Normaliza la raíz efectiva del repositorio."""
    return (root or REPO_ROOT).resolve()


def allowed_base_dirs(root: Path | None = None) -> list[Path]:
    """Calcula los directorios desde los que está permitido leer evidencias."""
    base = resolve_repo_root(root)
    return [(base / directory_name).resolve() for directory_name in ARTIFACT_DIRS]


def is_inside(candidate: Path, allowed_dir: Path) -> bool:
    """Verifica si una ruta está dentro de un directorio permitido."""
    return candidate == allowed_dir or allowed_dir in candidate.parents


def ensure_artifact_dirs(root: Path | None = None) -> None:
    """Crea los directorios de evidencia si aún no existen."""
    base = resolve_repo_root(root)
    for directory_name in ARTIFACT_DIRS:
        (base / directory_name).mkdir(parents=True, exist_ok=True)


def safe_artifact_path(relative_path: str, root: Path | None = None) -> Path:
    """Resuelve una ruta de evidencia sin permitir traversal ni directorios arbitrarios."""
    base = resolve_repo_root(root)
    candidate = (base / relative_path).resolve()
    allowed_dirs = allowed_base_dirs(base)

    # Solo se permite leer evidencia generada por el pipeline, no archivos del sistema.
    if not any(is_inside(candidate, allowed_dir) for allowed_dir in allowed_dirs):
        raise ValueError("Solo se pueden leer archivos dentro de artifacts/ o .evidence/")

    if not candidate.is_file():
        raise FileNotFoundError(f"Evidencia no encontrada: {relative_path}")

    return candidate




def validate_resource_filename(filename: str) -> str:
    """Valida nombres usados por resources MCP sin permitir rutas ni traversal."""
    if not isinstance(filename, str):
        raise TypeError("filename debe ser texto")
    candidate = filename.strip()
    if candidate != filename or candidate in {"", ".", ".."}:
        raise ValueError("Solo se permite un nombre de archivo simple")
    if PurePosixPath(candidate).name != candidate or PureWindowsPath(candidate).name != candidate:
        raise ValueError("Solo se permite nombre de archivo, no rutas ni separadores")
    if any(sep in candidate for sep in ("/", "\\")) or ".." in PurePath(candidate).parts:
        raise ValueError("Solo se permite nombre de archivo, no rutas ni traversal")
    return candidate


def read_named_artifact_text(directory_name: str, filename: str, root: Path | None = None) -> str:
    """Lee artifacts/<filename> o .evidence/<filename> usando nombre simple validado."""
    if directory_name not in ARTIFACT_DIRS:
        raise ValueError("Directorio de evidencia no permitido")
    safe_name = validate_resource_filename(filename)
    return read_artifact_text(f"{directory_name}/{safe_name}", root=root)

def list_artifacts(root: Path | None = None) -> list[dict[str, Any]]:
    """Lista todos los archivos presentes en artifacts/ y .evidence/."""
    base = resolve_repo_root(root)
    ensure_artifact_dirs(base)
    rows: list[ArtifactInfo] = []

    for directory_name in ARTIFACT_DIRS:
        directory = base / directory_name
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            stat = path.stat()
            rows.append(
                ArtifactInfo(
                    name=path.name,
                    relative_path=path.relative_to(base).as_posix(),
                    size_bytes=stat.st_size,
                    modified_unix=stat.st_mtime,
                )
            )

    return [row.to_dict() for row in rows]


def read_artifact_text(relative_path: str, root: Path | None = None) -> str:
    """Lee una evidencia textual aplicando un límite conservador de bytes."""
    path = safe_artifact_path(relative_path, root=root)
    data = path.read_bytes()[:MAX_TEXT_BYTES]
    return data.decode("utf-8", errors="replace")


def read_json_if_exists(path: Path) -> Any | None:
    """Carga JSON solo cuando el archivo existe y tiene formato válido."""
    if not path.exists() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None


def count_by(items: list[dict[str, Any]], keys: tuple[str, ...]) -> dict[str, int]:
    """Cuenta valores anidados usando una ruta de claves."""
    counts: dict[str, int] = {}

    for item in items:
        value = "unknown"
        cursor: Any = item
        for key in keys:
            if isinstance(cursor, dict) and key in cursor:
                cursor = cursor[key]
                value = str(cursor)
                continue
            value = "unknown"
            break
        normalized_value = value.lower()
        counts[normalized_value] = counts.get(normalized_value, 0) + 1

    return counts


def summarize_bandit(artifacts: Path) -> dict[str, Any] | None:
    """Resume hallazgos de Bandit cuando existe salida JSON."""
    bandit = read_json_if_exists(artifacts / "bandit.json")
    if not isinstance(bandit, dict):
        return None

    results = bandit.get("results", [])
    if not isinstance(results, list):
        return None

    return {
        "finding_count": len(results),
        "by_severity": count_by(results, ("issue_severity",)),
        "by_confidence": count_by(results, ("issue_confidence",)),
    }


def summarize_semgrep(artifacts: Path) -> dict[str, Any] | None:
    """Resume hallazgos de Semgrep cuando existe salida JSON."""
    semgrep = read_json_if_exists(artifacts / "semgrep.json")
    if not isinstance(semgrep, dict):
        return None

    results = semgrep.get("results", [])
    if not isinstance(results, list):
        return None

    return {
        "finding_count": len(results),
        "by_severity": count_by(results, ("extra", "severity")),
    }


def summarize_pip_audit_file(path: Path) -> dict[str, Any] | None:
    """Resume vulnerabilidades reportadas por un archivo pip-audit JSON."""
    pip_audit = read_json_if_exists(path)
    if not isinstance(pip_audit, dict):
        return None

    deps = pip_audit.get("dependencies", [])
    vulnerability_count = 0
    affected_packages: list[str] = []

    if isinstance(deps, list):
        for dependency in deps:
            vulns = dependency.get("vulns", []) if isinstance(dependency, dict) else []
            if vulns:
                affected_packages.append(str(dependency.get("name", "unknown")))
                vulnerability_count += len(vulns)

    return {
        "vulnerability_count": vulnerability_count,
        "affected_packages": sorted(set(affected_packages)),
    }


def summarize_pip_audit(artifacts: Path) -> dict[str, Any] | None:
    """Resume vulnerabilidades reportadas por pip-audit en runtime/dev/mcp."""
    summaries: dict[str, Any] = {}
    total_vulnerabilities = 0
    affected_packages: set[str] = set()

    for relative_path in PIP_AUDIT_REPORT_PATHS:
        name = Path(relative_path).stem.replace("pip-audit-", "")
        summary = summarize_pip_audit_file(artifacts.parent / relative_path)
        if summary is None:
            continue
        summaries[name] = summary
        total_vulnerabilities += int(summary.get("vulnerability_count", 0) or 0)
        affected_packages.update(summary.get("affected_packages", []))

    if not summaries:
        legacy_summary = summarize_pip_audit_file(artifacts.parent / LEGACY_PIP_AUDIT_REPORT_PATH)
        if legacy_summary is None:
            return None
        summaries["legacy"] = legacy_summary
        total_vulnerabilities = int(legacy_summary.get("vulnerability_count", 0) or 0)
        affected_packages.update(legacy_summary.get("affected_packages", []))

    return {
        "vulnerability_count": total_vulnerabilities,
        "affected_packages": sorted(affected_packages),
        "by_requirements_file": summaries,
    }


def summarize_sbom(artifacts: Path, sbom_name: str) -> dict[str, Any] | None:
    """Cuenta paquetes presentes en un SBOM de Syft."""
    sbom = read_json_if_exists(artifacts / sbom_name)
    if not isinstance(sbom, dict):
        return None

    packages = sbom.get("artifacts", sbom.get("packages", sbom.get("components", [])))
    return {"package_count": len(packages) if isinstance(packages, list) else 0}


def summarize_grype(artifacts: Path) -> dict[str, Any] | None:
    """Cuenta hallazgos presentes en salida SARIF de Grype."""
    grype = read_json_if_exists(artifacts / "grype-image.sarif")
    if not isinstance(grype, dict):
        return None

    runs = grype.get("runs", [])
    results: list[Any] = []
    if isinstance(runs, list):
        for run in runs:
            if isinstance(run, dict):
                results.extend(run.get("results", []) or [])

    return {"finding_count": len(results)}


def summarize_zap(artifacts: Path) -> dict[str, Any] | None:
    """Resume alertas de OWASP ZAP baseline."""
    zap = read_json_if_exists(artifacts / "zap-baseline.json")
    if not isinstance(zap, dict):
        return None

    sites = zap.get("site", [])
    alert_count = 0
    risk_counts: dict[str, int] = {}

    if isinstance(sites, list):
        for site in sites:
            alerts = site.get("alerts", []) if isinstance(site, dict) else []
            alert_count += len(alerts)
            for alert in alerts:
                risk = str(alert.get("riskdesc", "unknown")).split()[0].lower()
                risk_counts[risk] = risk_counts.get(risk, 0) + 1

    return {"alert_count": alert_count, "by_risk": risk_counts}


def summarize_security_findings(root: Path | None = None) -> dict[str, Any]:
    """Resume formatos comunes producidos por el pipeline DevSecOps."""
    base = resolve_repo_root(root)
    artifacts = base / "artifacts"
    ensure_artifact_dirs(base)

    summary: dict[str, Any] = {
        "repo_root": str(base),
        "artifact_count": len(list_artifacts(base)),
        "tools": {},
        "recommended_next_step": "Ejecuta `make pipeline` para generar evidencia fresca y vuelve a resumir.",
    }

    tool_summaries = {
        "bandit": summarize_bandit(artifacts),
        "semgrep": summarize_semgrep(artifacts),
        "pip-audit": summarize_pip_audit(artifacts),
        "grype": summarize_grype(artifacts),
        "zap": summarize_zap(artifacts),
    }

    for sbom_name in ("sbom-project.json", "sbom-image.json", "sbom-syft-project.json", "sbom-syft-image.json"):
        summary_name = sbom_name.removesuffix(".json").replace("sbom-syft", "sbom")
        tool_summaries[summary_name] = summarize_sbom(artifacts, sbom_name)

    # Se omiten herramientas sin evidencia disponible para mantener el resumen limpio.
    summary["tools"] = {name: data for name, data in tool_summaries.items() if data is not None}

    if summary["tools"]:
        summary["recommended_next_step"] = (
            "Prioriza hallazgos high/critical, documenta remediación y regenera `make evidence-pack`."
        )

    return summary
