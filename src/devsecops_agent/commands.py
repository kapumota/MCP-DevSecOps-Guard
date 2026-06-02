"""Ejecución controlada de comandos para tools MCP DevSecOps."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import ALLOWED_MAKE_TARGETS, MAX_TIMEOUT_SECONDS, MIN_TIMEOUT_SECONDS, REPO_ROOT
from .rbac import authorize_tool_invocation
from .sandbox import run_sandboxed_make_target


def validate_timeout(timeout_seconds: int) -> int:
    """Normaliza el timeout para evitar ejecuciones demasiado largas o inválidas."""
    if not isinstance(timeout_seconds, int):
        raise TypeError("timeout_seconds debe ser un entero")
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout_seconds debe estar entre {MIN_TIMEOUT_SECONDS} y {MAX_TIMEOUT_SECONDS}, "
            f"recibido: {timeout_seconds}"
        )
    return timeout_seconds


def validate_make_target(target: str) -> str:
    """Valida un target Makefile contra la allowlist del agente."""
    if target not in ALLOWED_MAKE_TARGETS:
        allowed = ", ".join(sorted(ALLOWED_MAKE_TARGETS))
        raise ValueError(f"Target no permitido: {target}. Targets permitidos: {allowed}")
    return target


def run_make_target(
    target: str, timeout_seconds: int = 180, root: Path | None = None
) -> dict[str, Any]:
    """Ejecuta un target Makefile permitido con rol efectivo externo al cliente MCP."""
    safe_target = validate_make_target(target)
    timeout = validate_timeout(timeout_seconds)
    base = (root or REPO_ROOT).resolve()
    authorization = authorize_tool_invocation(
        role=None,
        tool_name="run_devsecops_check",
        target=safe_target,
        root=base,
    )

    result = run_sandboxed_make_target(safe_target, timeout_seconds=timeout, root=base)

    # Solo se devuelven colas de logs para no saturar clientes MCP ni exponer ruido excesivo.
    return {
        "target": safe_target,
        "role": authorization["role"],
        "sandbox_mode": result.sandbox_mode,
        "returncode": result.returncode,
        "duration_seconds": result.duration_seconds,
        "stdout_tail": result.stdout[-6000:],
        "stderr_tail": result.stderr[-6000:],
    }
