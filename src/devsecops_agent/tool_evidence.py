"""Registro verificable de ejecuciones de scanners externos."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import REPO_ROOT
from .report_schema import config_hash, git_commit
from .report_writer import write_json_report


def utc_now() -> str:
    """Devuelve timestamp UTC ISO-8601."""
    return datetime.now(UTC).isoformat()


def sha256_file(path: Path) -> str | None:
    """Calcula SHA-256 si el artefacto existe."""
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_tool_exit_record(
    *,
    root: Path,
    tool: str,
    exit_code: int,
    artifact: str | None = None,
    command: str | None = None,
    started_at: str | None = None,
) -> dict[str, Any]:
    """Construye una evidencia operacional que liga scanner, exit code y artefacto."""
    base = root.resolve()
    artifact_path = (base / artifact).resolve() if artifact else None
    artifact_exists = bool(artifact_path and artifact_path.exists() and artifact_path.is_file())
    return {
        "status": "PASS" if exit_code == 0 else "WARN",
        "record_type": "scanner-exit-code",
        "tool_name": tool,
        "scanner_exit_code": int(exit_code),
        "scanner_started_at": started_at
        or os.environ.get("SKILLCHAIN_TOOL_STARTED_AT")
        or utc_now(),
        "scanner_finished_at": utc_now(),
        "run_id": os.environ.get("SKILLCHAIN_RUN_ID", "local-run"),
        "git_commit": git_commit(base),
        "config_hash": config_hash(base),
        "command": command or "",
        "artifact": artifact or "",
        "artifact_exists": artifact_exists,
        "artifact_sha256": sha256_file(artifact_path) if artifact_path else None,
        "environment": {
            "python": platform.python_version(),
            "os": platform.platform(),
            "ci": os.environ.get("CI", "").lower() in {"1", "true", "yes"},
        },
    }


def write_tool_exit_record(record: dict[str, Any], output: Path, root: Path | None = None) -> Path:
    """Escribe el registro de ejecución del scanner."""
    return write_json_report(record, output, root=root)


def verify_tool_exit_record(
    root: Path, record: dict[str, Any], relative_artifact: str
) -> tuple[bool, str]:
    """Verifica que el registro siga apuntando al artefacto presente en disco."""
    if not isinstance(record, dict):
        return False, "La evidencia de salida del scanner no es un objeto JSON"
    if not record.get("artifact_exists"):
        return False, "La evidencia de salida del scanner indica que el artefacto no fue creado"
    artifact = str(record.get("artifact") or relative_artifact)
    if artifact != relative_artifact:
        return False, f"scanner exit evidence references {artifact}, expected {relative_artifact}"
    path = root / relative_artifact
    current_hash = sha256_file(path)
    expected_hash = record.get("artifact_sha256")
    if not current_hash or not expected_hash:
        return False, "Falta hash del artefacto en la evidencia de salida del scanner"
    if current_hash != expected_hash:
        return False, "El hash del artefacto no coincide con la evidencia de salida del scanner"
    expected_run_id = os.environ.get("SKILLCHAIN_RUN_ID")
    if expected_run_id and str(record.get("run_id")) != expected_run_id:
        return False, "El run_id de la evidencia del scanner no coincide con SKILLCHAIN_RUN_ID"
    expected_commit = git_commit(root)
    if expected_commit != "unknown" and str(record.get("git_commit")) not in {
        expected_commit,
        "unknown",
    }:
        return False, "El git_commit de la evidencia del scanner está obsoleto"
    return True, "ok"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Registra código de salida y hash de artefacto de un scanner externo."
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="Raíz del repositorio.")
    parser.add_argument("--tool", required=True, help="Nombre del scanner.")
    parser.add_argument(
        "--exit-code", required=True, type=int, help="Código de salida del proceso scanner."
    )
    parser.add_argument(
        "--artifact", default="", help="Ruta del artefacto relativa al repositorio."
    )
    parser.add_argument(
        "--output", required=True, help="Ruta JSON de salida relativa al repositorio."
    )
    parser.add_argument("--command", default="", help="Comando ejecutado.")
    parser.add_argument("--started-at", default="", help="Timestamp de inicio del scanner.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    record = build_tool_exit_record(
        root=root,
        tool=args.tool,
        exit_code=args.exit_code,
        artifact=args.artifact or None,
        command=args.command or None,
        started_at=args.started_at or None,
    )
    output = write_tool_exit_record(record, Path(args.output), root=root)
    print(json.dumps({"status": record["status"], "output": str(output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
