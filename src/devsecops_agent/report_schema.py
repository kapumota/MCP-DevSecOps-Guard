"""Ayudantes de metadatos para reportes JSON de SkillChain-MCP Guard."""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import REPO_ROOT

SCHEMA_VERSION = "1.0.0"
TOOL_NAME = "skillchain-mcp-guard"


def tool_version() -> str:
    """Devuelve la versión del paquete sin importar dependencias opcionales."""
    pyproject = REPO_ROOT / "pyproject.toml"
    if pyproject.exists():
        for line in pyproject.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("version") and "=" in line:
                return line.split("=", 1)[1].strip().strip("\"'")
    return "0.0.0"


def utc_now() -> str:
    """Devuelve un timestamp UTC ISO-8601."""
    return datetime.now(UTC).isoformat()


def git_commit(root: Path | None = None) -> str:
    """Devuelve el commit actual de Git o un marcador estable cuando no está disponible."""
    env_sha = os.environ.get("SKILLCHAIN_GIT_COMMIT") or os.environ.get("GITHUB_SHA")
    if env_sha:
        return env_sha
    base = (root or REPO_ROOT).resolve()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=base,
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and commit else "unknown"


def config_hash(root: Path | None = None) -> str:
    """Calcula hash de la configuración local relevante para decisiones de seguridad."""
    base = (root or REPO_ROOT).resolve()
    candidates = [
        "pyproject.toml",
        "Makefile",
        ".semgrep.yml",
        ".bandit.yaml",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-mcp.txt",
        "config/rbac.json",
        "k8s/deployment.yaml",
        "eval_cases/cases.yaml",
        "src/devsecops_agent/config.py",
        "src/devsecops_agent/policy_engine.py",
        "src/devsecops_agent/rbac.py",
        "src/devsecops_agent/sandbox.py",
    ]
    digest = hashlib.sha256()
    for relative in candidates:
        path = base / relative
        if not path.exists() or not path.is_file():
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def environment_snapshot() -> dict[str, Any]:
    """Devuelve metadatos mínimos del entorno para reproducibilidad de auditoría."""
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "os": platform.platform(),
        "ci": os.environ.get("CI", "").lower() in {"1", "true", "yes"},
        "github_actions": os.environ.get("GITHUB_ACTIONS", "").lower() == "true",
    }


def current_run_id() -> str:
    """Devuelve el identificador global de corrida o crea uno local estable para el proceso."""
    run_id = os.environ.get("SKILLCHAIN_RUN_ID")
    if run_id:
        return run_id
    generated = os.environ.get("SKILLCHAIN_LOCAL_RUN_ID")
    if not generated:
        generated = f"local-{uuid.uuid4()}"
        os.environ["SKILLCHAIN_LOCAL_RUN_ID"] = generated
    return generated


def build_report_metadata(
    root: Path | None = None, started_at: str | None = None
) -> dict[str, Any]:
    """Construye el bloque estándar de metadatos requerido por cada reporte interno."""
    finished = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "tool_version": tool_version(),
        "run_id": current_run_id(),
        "started_at": started_at or os.environ.get("SKILLCHAIN_STARTED_AT") or finished,
        "finished_at": finished,
        "git_commit": git_commit(root),
        "config_hash": config_hash(root),
        "environment": environment_snapshot(),
    }


def ensure_report_metadata(report: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    """Devuelve una copia enriquecida con metadatos de schema y trazabilidad."""
    payload = deepcopy(report)
    started_at = (
        str(
            payload.get("started_at")
            or payload.get("created_at_utc")
            or payload.get("generated_at_utc")
            or ""
        )
        or None
    )
    metadata = build_report_metadata(root=root, started_at=started_at)
    for key, value in metadata.items():
        payload.setdefault(key, value)
    return payload
