"""Ejecución sandboxeada para targets Makefile invocados desde MCP."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import REPO_ROOT


@dataclass(frozen=True)
class SandboxResult:
    """Resultado normalizado de una ejecución sandboxeada."""

    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    sandbox_mode: str


class SandboxRunner(Protocol):
    """Contrato de ejecución para sandboxes compatibles."""

    mode: str

    def run(self, command: list[str], timeout_seconds: int, cwd: Path) -> SandboxResult:
        """Ejecuta un comando bajo controles de aislamiento."""


class LocalSandboxRunner:
    """Sandbox local mínimo para desarrollo controlado."""

    mode = "local"

    def run(self, command: list[str], timeout_seconds: int, cwd: Path) -> SandboxResult:
        """Ejecuta sin shell, con timeout y directorio controlado."""
        started = time.time()
        process = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        return SandboxResult(
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            duration_seconds=round(time.time() - started, 3),
            sandbox_mode=self.mode,
        )


class DisabledSandboxRunner:
    """Runner usado solo para pruebas negativas de política."""

    mode = "disabled"

    def run(self, command: list[str], timeout_seconds: int, cwd: Path) -> SandboxResult:  # noqa: ARG002
        """Bloquea toda ejecución cuando el sandbox está deshabilitado."""
        raise RuntimeError("La ejecución fue bloqueada porque el sandbox está deshabilitado.")


class DockerSandboxRunner:
    """Sandbox Docker endurecido para preproducción controlada."""

    mode = "docker"

    def run(self, command: list[str], timeout_seconds: int, cwd: Path) -> SandboxResult:
        """Ejecuta el comando dentro de un contenedor con privilegios mínimos.

        El repositorio se monta de solo lectura. Las salidas esperadas del
        pipeline se montan por separado con permisos de escritura para evitar
        que el sandbox necesite acceso global de escritura al workspace.
        """
        image = os.environ.get("SKILLCHAIN_SANDBOX_IMAGE", "skillchain-sandbox:dev")
        artifacts_dir = cwd / "artifacts"
        evidence_dir = cwd / ".evidence"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        docker_command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "128",
            "--memory",
            "512m",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-e",
            "PYTHONPATH=/workspace/src",
            "-e",
            "PYTEST_ADDOPTS=-p no:cacheprovider",
            "-v",
            f"{cwd}:/workspace:ro",
            "-v",
            f"{artifacts_dir}:/workspace/artifacts:rw",
            "-v",
            f"{evidence_dir}:/workspace/.evidence:rw",
            "-w",
            "/workspace",
            image,
            *command,
        ]
        started = time.time()
        process = subprocess.run(
            docker_command,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        return SandboxResult(
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            duration_seconds=round(time.time() - started, 3),
            sandbox_mode=self.mode,
        )


def sandbox_mode() -> str:
    """Devuelve el modo de sandbox configurado para MCP."""
    return os.environ.get("SKILLCHAIN_SANDBOX_MODE", "local").strip().lower() or "local"


def policy_mode() -> str:
    """Devuelve el modo de política activo."""
    return os.environ.get("SKILLCHAIN_POLICY_MODE") or os.environ.get("POLICY_MODE") or "demo"


def require_sandbox_for_mode(mode: str | None = None, sandbox: str | None = None) -> None:
    """Impide modo strict/ci cuando el sandbox está deshabilitado."""
    effective_mode = (mode or policy_mode()).strip().lower()
    effective_sandbox = (sandbox or sandbox_mode()).strip().lower()
    if effective_mode in {"ci", "strict"} and effective_sandbox == "disabled":
        raise RuntimeError("El modo ci/strict exige sandbox habilitado para ejecutar tools MCP.")


def get_sandbox_runner(mode: str | None = None) -> SandboxRunner:
    """Crea el runner de sandbox solicitado por configuración."""
    effective = (mode or sandbox_mode()).strip().lower()
    if effective == "disabled":
        return DisabledSandboxRunner()
    if effective == "docker":
        return DockerSandboxRunner()
    if effective == "local":
        return LocalSandboxRunner()
    raise ValueError(f"Modo de sandbox inválido: {effective}")


def run_sandboxed_make_target(
    target: str, timeout_seconds: int, root: Path | None = None
) -> SandboxResult:
    """Ejecuta make target mediante el sandbox configurado."""
    base = (root or REPO_ROOT).resolve()
    require_sandbox_for_mode()
    runner = get_sandbox_runner()
    return runner.run(["make", target], timeout_seconds=timeout_seconds, cwd=base)
