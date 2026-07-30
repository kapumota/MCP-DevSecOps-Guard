#!/usr/bin/env python3
"""Normaliza vulnerabilidades HIGH/CRITICAL producidas por Grype y Trivy."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SEVERITY_RANK = {
    "UNKNOWN": 0,
    "NEGLIGIBLE": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


def read_json(path: Path) -> dict[str, Any]:
    """Lee un objeto JSON desde disco."""
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"{path} no contiene un objeto JSON")

    return data


def normalize_severity(value: Any) -> str:
    """Normaliza una severidad a mayúsculas."""
    severity = str(value or "UNKNOWN").strip().upper()
    return severity if severity in SEVERITY_RANK else "UNKNOWN"


def normalize_status(value: Any) -> str:
    """Normaliza estados heterogéneos de corrección."""
    status = str(value or "unknown").strip().lower()
    return status.replace(" ", "_").replace("-", "_")


def split_fixed_versions(value: Any) -> set[str]:
    """Convierte versiones corregidas heterogéneas en un conjunto."""
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}

    raw = str(value or "").strip()

    if not raw:
        return set()

    return {part.strip() for part in raw.split(",") if part.strip()}


def add_record(
    records: dict[tuple[str, str, str], dict[str, Any]],
    *,
    vulnerability_id: str,
    package_name: str,
    installed_version: str,
    severity: str,
    source: str,
    status: str,
    fixed_versions: set[str],
    package_type: str,
) -> None:
    """Agrega o fusiona una vulnerabilidad normalizada."""
    vulnerability_id = vulnerability_id.strip().upper()
    package_name = package_name.strip().lower()
    installed_version = installed_version.strip()

    if not vulnerability_id:
        raise ValueError(f"{source}: vulnerabilidad sin identificador")

    if not package_name:
        raise ValueError(f"{source}: {vulnerability_id} no contiene nombre de paquete")

    if not installed_version:
        raise ValueError(f"{source}: {vulnerability_id}/{package_name} no contiene versión")

    key = (
        vulnerability_id,
        package_name,
        installed_version,
    )

    current = records.setdefault(
        key,
        {
            "vulnerability_id": vulnerability_id,
            "package_name": package_name,
            "installed_version": installed_version,
            "severity": severity,
            "sources": set(),
            "statuses": set(),
            "fixed_versions": set(),
            "package_types": set(),
        },
    )

    if SEVERITY_RANK[severity] > SEVERITY_RANK[current["severity"]]:
        current["severity"] = severity

    current["sources"].add(source)
    current["statuses"].add(status)
    current["fixed_versions"].update(fixed_versions)

    if package_type:
        current["package_types"].add(package_type)


def parse_grype(
    path: Path,
    records: dict[tuple[str, str, str], dict[str, Any]],
) -> int:
    """Extrae vulnerabilidades bloqueantes desde el JSON nativo de Grype."""
    report = read_json(path)
    accepted = 0

    for match in report.get("matches", []):
        if not isinstance(match, dict):
            continue

        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        if not isinstance(vulnerability, dict):
            continue

        if not isinstance(artifact, dict):
            continue

        severity = normalize_severity(vulnerability.get("severity"))

        if severity not in BLOCKING_SEVERITIES:
            continue

        fix = vulnerability.get("fix", {})

        if not isinstance(fix, dict):
            fix = {}

        add_record(
            records,
            vulnerability_id=str(vulnerability.get("id", "")),
            package_name=str(artifact.get("name", "")),
            installed_version=str(artifact.get("version", "")),
            severity=severity,
            source="grype",
            status=normalize_status(fix.get("state")),
            fixed_versions=split_fixed_versions(fix.get("versions")),
            package_type=str(artifact.get("type", "")),
        )

        accepted += 1

    return accepted


def parse_trivy(
    path: Path,
    records: dict[tuple[str, str, str], dict[str, Any]],
) -> int:
    """Extrae vulnerabilidades bloqueantes desde el JSON nativo de Trivy."""
    report = read_json(path)
    accepted = 0

    for result in report.get("Results", []):
        if not isinstance(result, dict):
            continue

        package_type = str(result.get("Type") or result.get("Class") or "")

        vulnerabilities = result.get("Vulnerabilities") or []

        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            severity = normalize_severity(vulnerability.get("Severity"))

            if severity not in BLOCKING_SEVERITIES:
                continue

            add_record(
                records,
                vulnerability_id=str(vulnerability.get("VulnerabilityID", "")),
                package_name=str(vulnerability.get("PkgName", "")),
                installed_version=str(vulnerability.get("InstalledVersion", "")),
                severity=severity,
                source="trivy",
                status=normalize_status(vulnerability.get("Status")),
                fixed_versions=split_fixed_versions(vulnerability.get("FixedVersion")),
                package_type=package_type,
            )

            accepted += 1

    return accepted


def serialize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Convierte conjuntos internos en listas JSON deterministas."""
    fixed_versions = sorted(record["fixed_versions"])
    sources = sorted(record["sources"])
    statuses = sorted(record["statuses"])
    package_types = sorted(record["package_types"])

    return {
        "vulnerability_id": record["vulnerability_id"],
        "package_name": record["package_name"],
        "installed_version": record["installed_version"],
        "severity": record["severity"],
        "sources": sources,
        "statuses": statuses,
        "fixed_versions": fixed_versions,
        "fix_available": bool(fixed_versions),
        "package_types": package_types,
    }


def main() -> int:
    """Ejecuta la normalización y escribe el inventario consolidado."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--grype",
        type=Path,
        default=Path("artifacts/grype-image.json"),
    )
    parser.add_argument(
        "--trivy",
        type=Path,
        default=Path("artifacts/trivy-image.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/image-vulnerabilities-normalized.json"),
    )

    args = parser.parse_args()

    records: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}

    grype_count = parse_grype(args.grype, records)
    trivy_count = parse_trivy(args.trivy, records)

    vulnerabilities = [serialize_record(record) for _, record in sorted(records.items())]

    severity_counts = Counter(vulnerability["severity"] for vulnerability in vulnerabilities)

    source_counts = Counter()

    for vulnerability in vulnerabilities:
        sources = vulnerability["sources"]

        if sources == ["grype", "trivy"]:
            source_counts["both"] += 1
        elif sources == ["grype"]:
            source_counts["grype_only"] += 1
        elif sources == ["trivy"]:
            source_counts["trivy_only"] += 1
        else:
            source_counts["other"] += 1

    fixable = sum(1 for vulnerability in vulnerabilities if vulnerability["fix_available"])

    payload = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "identity_fields": [
            "vulnerability_id",
            "package_name",
            "installed_version",
        ],
        "input_counts": {
            "grype_high_or_critical": grype_count,
            "trivy_high_or_critical": trivy_count,
        },
        "summary": {
            "unique_high_or_critical": len(vulnerabilities),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "fixable": fixable,
            "without_fixed_version": len(vulnerabilities) - fixable,
            "grype_only": source_counts["grype_only"],
            "trivy_only": source_counts["trivy_only"],
            "reported_by_both": source_counts["both"],
        },
        "vulnerabilities": vulnerabilities,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            payload["summary"],
            indent=2,
            sort_keys=True,
        )
    )
    print(f"Reporte: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
