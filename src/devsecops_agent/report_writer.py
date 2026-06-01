"""Utilidades comunes para escribir reportes JSON reproducibles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import REPO_ROOT
from .report_schema import ensure_report_metadata


def resolve_output_path(output_path: Path, root: Path | None = None) -> Path:
    """Resuelve una ruta de salida dentro de la raíz del repositorio cuando es relativa."""
    base = (root or REPO_ROOT).resolve()
    return output_path if output_path.is_absolute() else base / output_path


def write_json_report(report: dict[str, Any], output_path: Path, root: Path | None = None) -> Path:
    """Escribe un reporte JSON con indentación estable y UTF-8."""
    path = resolve_output_path(output_path, root=root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = ensure_report_metadata(report, root=root)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def read_json_report(path: Path) -> dict[str, Any] | None:
    """Carga un reporte JSON objeto; devuelve None si falta o no es válido."""
    if not path.exists() or not path.is_file() or path.stat().st_size == 0:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None
