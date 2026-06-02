"""Empaquetado reproducible de evidencias DevSecOps para auditoría."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifacts import ensure_artifact_dirs, list_artifacts, read_json_if_exists, resolve_repo_root
from .config import ARTIFACT_DIRS, EVIDENCE_MANIFEST_PATH, POLICY_REPORT_PATH, REPO_ROOT
from .report_schema import build_report_metadata, ensure_report_metadata

AUXILIARY_EVIDENCE_FILES: tuple[str, ...] = (
    "artifacts/evidence-summary.md",
    "artifacts/checksums.txt",
    "artifacts/provenance.json",
)


def sha256_file(path: Path) -> str:
    """Calcula SHA-256 de un archivo sin cargarlo completo a memoria."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Calcula SHA-256 de bytes ya cargados."""
    return hashlib.sha256(data).hexdigest()


def should_include(path: Path, root: Path | None = None) -> bool:
    """Decide si un archivo debe formar parte del paquete de evidencias.

    El manifiesto y paquetes previos se excluyen para evitar hashes circulares.
    El manifiesto final queda como sidecar verificable del tar.gz.
    """
    if not path.is_file():
        return False
    if path.name == ".gitkeep":
        return False
    if path.suffixes[-2:] == [".tar", ".gz"] or path.suffix == ".tgz":
        return False
    if root is not None and path.resolve() == (root / EVIDENCE_MANIFEST_PATH).resolve():
        return False
    if path.name == Path(EVIDENCE_MANIFEST_PATH).name:
        return False
    return True


def collect_evidence_files(root: Path) -> list[Path]:
    """Recolecta archivos de artifacts/ y .evidence/ excluyendo paquetes previos."""
    files: list[Path] = []
    for directory_name in ARTIFACT_DIRS:
        directory = root / directory_name
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if should_include(path, root=root):
                files.append(path)
    return files


def build_file_entries(root: Path, files: Sequence[Path]) -> list[dict[str, Any]]:
    """Construye entradas de manifiesto con rutas, tamaños y hashes."""
    entries: list[dict[str, Any]] = []
    for path in files:
        stat = path.stat()
        entries.append(
            {
                "relative_path": path.relative_to(root).as_posix(),
                "size_bytes": stat.st_size,
                "sha256": sha256_file(path),
            }
        )
    return entries


def build_evidence_summary(root: Path, files: Sequence[Path]) -> str:
    """Genera un resumen Markdown breve del evidence pack."""
    policy = read_json_if_exists(root / POLICY_REPORT_PATH)
    status = policy.get("status", "UNKNOWN") if isinstance(policy, dict) else "UNKNOWN"
    mode = policy.get("mode", "unknown") if isinstance(policy, dict) else "unknown"
    blocking = policy.get("blocking_issues", "unknown") if isinstance(policy, dict) else "unknown"
    warnings = policy.get("warnings", "unknown") if isinstance(policy, dict) else "unknown"
    lines = [
        "# Resumen de evidencia SkillChain-MCP Guard",
        "",
        f"Generado UTC: {datetime.now(UTC).isoformat()}",
        f"Estado de política: {status}",
        f"Modo de política: {mode}",
        f"Problemas bloqueantes: {blocking}",
        f"Advertencias: {warnings}",
        f"Archivos de evidencia incluidos: {len(files)}",
        "",
        "## Verificación",
        "",
        "Ejecuta:",
        "",
        "```bash",
        "skillchain evidence verify artifacts/evidence-pack.tar.gz --manifest artifacts/evidence-manifest.json",
        "```",
        "",
        "Este resumen se genera desde reportes locales. No reemplaza la evidencia JSON completa.",
    ]
    return "\n".join(lines) + "\n"


def build_checksums(root: Path, files: Sequence[Path]) -> str:
    """Genera checksums SHA-256 para las evidencias incluidas, excluyendo checksums.txt."""
    lines: list[str] = []
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "artifacts/checksums.txt":
            continue
        lines.append(f"{sha256_file(path)}  {relative}")
    return "\n".join(lines) + ("\n" if lines else "")


def build_provenance(root: Path, files: Sequence[Path]) -> dict[str, Any]:
    """Construye provenance local estilo SLSA-lite para el paquete de evidencias."""
    metadata = build_report_metadata(root=root)
    policy = read_json_if_exists(root / POLICY_REPORT_PATH)
    return {
        **metadata,
        "provenance_type": "skillchain.local.slsa-lite.v1",
        "subject": "devsecops-evidence-pack",
        "builder": {"id": "skillchain-mcp-guard.local", "version": metadata["tool_version"]},
        "materials": [
            {"uri": path.relative_to(root).as_posix(), "digest": {"sha256": sha256_file(path)}}
            for path in files
            if path.relative_to(root).as_posix() != "artifacts/provenance.json"
        ],
        "policy_status": policy.get("status", "UNKNOWN") if isinstance(policy, dict) else "UNKNOWN",
    }


def write_text(root: Path, relative_path: str, content: str) -> Path:
    """Escribe un archivo textual relativo a la raíz."""
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def write_json(root: Path, relative_path: str, payload: dict[str, Any]) -> Path:
    """Escribe JSON con schema metadata."""
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    enriched = ensure_report_metadata(payload, root=root)
    path.write_text(json.dumps(enriched, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def refresh_auxiliary_evidence(root: Path) -> None:
    """Genera summary, checksums y provenance antes de empaquetar."""
    initial_files = [
        path
        for path in collect_evidence_files(root)
        if path.relative_to(root).as_posix() not in AUXILIARY_EVIDENCE_FILES
    ]
    write_text(root, "artifacts/evidence-summary.md", build_evidence_summary(root, initial_files))
    provenance_files = initial_files + [root / "artifacts/evidence-summary.md"]
    write_json(root, "artifacts/provenance.json", build_provenance(root, provenance_files))
    checksum_files = provenance_files + [root / "artifacts/provenance.json"]
    write_text(root, "artifacts/checksums.txt", build_checksums(root, checksum_files))


def build_evidence_manifest(root: Path, files: Sequence[Path]) -> dict[str, Any]:
    """Construye un manifiesto con rutas, tamaños y hashes de evidencias."""
    metadata = build_report_metadata(root=root)
    entries = build_file_entries(root, files)
    return {
        **metadata,
        "packager": "skillchain-mcp-guard-evidence-pack",
        "repo_root": str(root),
        "artifact_count": len(list_artifacts(root)),
        "included_file_count": len(entries),
        "files": entries,
    }


def write_manifest(root: Path, manifest: dict[str, Any], output_path: Path | None = None) -> Path:
    """Escribe el manifiesto JSON dentro de artifacts/."""
    path = output_path or (root / EVIDENCE_MANIFEST_PATH)
    if not path.is_absolute():
        path = root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def add_file_to_tar(archive: tarfile.TarFile, path: Path, arcname: str) -> None:
    """Agrega un archivo al tar normalizando metadatos no esenciales."""
    info = archive.gettarinfo(str(path), arcname=arcname)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    with path.open("rb") as handle:
        archive.addfile(info, handle)


def create_evidence_pack(
    root: Path | None = None, output_path: Path | None = None
) -> dict[str, Any]:
    """Crea un tar.gz con evidencias y un manifiesto sidecar consistente."""
    base = resolve_repo_root(root)
    ensure_artifact_dirs(base)
    refresh_auxiliary_evidence(base)

    files = collect_evidence_files(base)
    if output_path is None:
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        output_path = base / "artifacts" / f"evidence-pack-{timestamp}.tar.gz"
    elif not output_path.is_absolute():
        output_path = base / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(output_path, mode="w:gz") as archive:
        for path in files:
            add_file_to_tar(archive, path, path.relative_to(base).as_posix())

    manifest_path = base / EVIDENCE_MANIFEST_PATH
    final_manifest = build_evidence_manifest(base, files)
    final_manifest["manifest_path"] = manifest_path.relative_to(base).as_posix()
    final_manifest["pack_path"] = output_path.relative_to(base).as_posix()
    final_manifest["pack_sha256"] = sha256_file(output_path)
    final_manifest["manifest_design"] = (
        "sidecar_manifest_excludes_itself_and_previous_packs_to_avoid_self_hash_cycles"
    )
    final_manifest["verification_command"] = (
        f"skillchain evidence verify {final_manifest['pack_path']} --manifest {final_manifest['manifest_path']}"
    )
    write_manifest(base, final_manifest, manifest_path)

    return final_manifest


def safe_member_name(name: str) -> bool:
    """Evita path traversal dentro de tarballs verificadas."""
    normalized = Path(name)
    return not normalized.is_absolute() and ".." not in normalized.parts


def verify_evidence_pack(root: Path | None, pack_path: Path, manifest_path: Path) -> dict[str, Any]:
    """Verifica hash del pack y hashes/tamaños de archivos declarados en manifest."""
    base = resolve_repo_root(root)
    pack = pack_path if pack_path.is_absolute() else base / pack_path
    manifest_file = manifest_path if manifest_path.is_absolute() else base / manifest_path
    findings: list[dict[str, str]] = []

    if not pack.is_file():
        findings.append(
            {"severity": "high", "message": "El evidence pack no existe.", "evidence": str(pack)}
        )
    if not manifest_file.is_file():
        findings.append(
            {
                "severity": "high",
                "message": "Manifest sidecar no existe.",
                "evidence": str(manifest_file),
            }
        )
    if findings:
        return {"status": "FAIL", "findings": findings}

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "status": "FAIL",
            "findings": [
                {"severity": "high", "message": "Manifest JSON inválido.", "evidence": str(exc)}
            ],
        }

    expected_pack_sha = manifest.get("pack_sha256")
    actual_pack_sha = sha256_file(pack)
    if expected_pack_sha != actual_pack_sha:
        findings.append(
            {
                "severity": "high",
                "message": "SHA-256 del pack no coincide.",
                "evidence": "pack_sha256",
            }
        )

    expected_entries: dict[str, dict[str, Any]] = {}
    manifest_files = manifest.get("files", [])
    if isinstance(manifest_files, list):
        for entry in manifest_files:
            if not isinstance(entry, dict):
                continue

            relative_path = entry.get("relative_path")
            if not isinstance(relative_path, str) or not relative_path:
                continue
            expected_entries[relative_path] = entry

    try:
        with tarfile.open(pack, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers() if member.isfile()}
            for name, entry in expected_entries.items():
                if not safe_member_name(name):
                    findings.append(
                        {
                            "severity": "high",
                            "message": "Ruta insegura en manifest.",
                            "evidence": name,
                        }
                    )
                    continue
                member = members.get(name)
                if member is None:
                    findings.append(
                        {
                            "severity": "high",
                            "message": "Archivo declarado no está en el pack.",
                            "evidence": name,
                        }
                    )
                    continue
                extracted = archive.extractfile(member)
                data = extracted.read() if extracted is not None else b""
                if len(data) != int(entry.get("size_bytes", -1)):
                    findings.append(
                        {"severity": "high", "message": "Tamaño no coincide.", "evidence": name}
                    )
                if sha256_bytes(data) != entry.get("sha256"):
                    findings.append(
                        {
                            "severity": "high",
                            "message": "SHA-256 de archivo no coincide.",
                            "evidence": name,
                        }
                    )
    except (tarfile.TarError, OSError) as exc:
        findings.append(
            {
                "severity": "high",
                "message": "No se pudo leer el evidence pack.",
                "evidence": str(exc),
            }
        )

    return {
        "status": "FAIL" if findings else "PASS",
        "pack_path": str(pack),
        "manifest_path": str(manifest_file),
        "checked_file_count": len(expected_entries),
        "findings": findings,
    }


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI del empaquetador de evidencias."""
    parser = argparse.ArgumentParser(
        description="Crea o verifica un paquete reproducible de evidencia DevSecOps."
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="Raíz del repositorio a empaquetar.")
    subparsers = parser.add_subparsers(dest="command")

    create_parser = subparsers.add_parser("create", help="Crea el evidence pack.")
    create_parser.add_argument("--output", default=None, help="Ruta tar.gz de salida opcional.")

    verify_parser = subparsers.add_parser("verify", help="Verifica el evidence pack.")
    verify_parser.add_argument("pack", help="Ruta al evidence-pack tar.gz.")
    verify_parser.add_argument(
        "--manifest", default=EVIDENCE_MANIFEST_PATH, help="Ruta al evidence-manifest.json."
    )

    # Backward-compatible single-command mode: python -m ...evidence_pack --output file.tar.gz
    parser.add_argument("--output", default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada CLI para crear o verificar el evidence pack."""
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    command = args.command or "create"
    if command == "verify":
        result = verify_evidence_pack(
            root=root, pack_path=Path(args.pack), manifest_path=Path(args.manifest)
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] == "PASS" else 2

    output_arg = getattr(args, "output", None)
    output = Path(output_arg) if output_arg else None
    manifest = create_evidence_pack(root=root, output_path=output)
    print(
        json.dumps(
            {
                "status": "PASS",
                "pack_path": manifest["pack_path"],
                "manifest_path": manifest["manifest_path"],
                "included_file_count": manifest["included_file_count"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
