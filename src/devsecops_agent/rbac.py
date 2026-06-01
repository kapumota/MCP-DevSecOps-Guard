"""Autorización RBAC declarativa para tools MCP."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .config import REPO_ROOT

RBAC_CONFIG_PATH = "config/rbac.json"


class RbacError(PermissionError):
    """Error de autorización para invocaciones MCP."""


def load_rbac_policy(root: Path | None = None, path: str = RBAC_CONFIG_PATH) -> dict[str, Any]:
    """Carga la política RBAC escrita como JSON."""
    base = (root or REPO_ROOT).resolve()
    config_path = base / path
    if not config_path.exists():
        return {"deny_by_default": True, "default_role": "auditor", "roles": {}}
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Política RBAC inválida: {config_path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("La política RBAC debe ser un objeto JSON.")
    return payload


def default_role(policy: dict[str, Any]) -> str:
    """Devuelve el rol por defecto declarado por la política."""
    return str(policy.get("default_role") or "auditor")


def tool_rule(policy: dict[str, Any], role: str, tool_name: str) -> dict[str, Any] | None:
    """Busca la regla aplicable para una tool y un rol."""
    roles = policy.get("roles", {}) if isinstance(policy.get("roles", {}), dict) else {}
    role_config = roles.get(role, {}) if isinstance(roles.get(role, {}), dict) else {}
    tools = role_config.get("tools", {}) if isinstance(role_config.get("tools", {}), dict) else {}
    rule = tools.get(tool_name) or tools.get("*")
    return rule if isinstance(rule, dict) else None


def authorize_tool_invocation(
    *,
    role: str | None,
    tool_name: str,
    target: str | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    """Autoriza una invocación MCP según rol, tool y target solicitado."""
    policy = load_rbac_policy(root=root)
    effective_role = role or os.environ.get("SKILLCHAIN_MCP_ROLE") or default_role(policy)
    rule = tool_rule(policy, effective_role, tool_name)
    if rule is None:
        if policy.get("deny_by_default", True):
            raise RbacError(f"Invocación denegada por RBAC: rol={effective_role}, tool={tool_name}")
        return {"allowed": True, "role": effective_role, "tool": tool_name, "reason": "allow_by_default"}

    if rule.get("allowed") is True and target is None:
        return {"allowed": True, "role": effective_role, "tool": tool_name, "reason": "tool_allowed"}

    allowed_targets = rule.get("allowed_targets")
    if target is not None and isinstance(allowed_targets, list) and target in {str(item) for item in allowed_targets}:
        return {"allowed": True, "role": effective_role, "tool": tool_name, "target": target, "reason": "target_allowed"}

    if rule.get("allowed") is True and isinstance(allowed_targets, list) and target is None:
        return {"allowed": True, "role": effective_role, "tool": tool_name, "reason": "tool_allowed"}

    raise RbacError(f"Invocación denegada por RBAC: rol={effective_role}, tool={tool_name}, target={target}")


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI de verificación RBAC."""
    parser = argparse.ArgumentParser(description="Valida autorización RBAC para una tool MCP.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Raíz del repositorio.")
    parser.add_argument("--role", default="", help="Rol MCP a evaluar.")
    parser.add_argument("--tool", required=True, help="Nombre de la tool MCP.")
    parser.add_argument("--target", default="", help="Target Makefile opcional.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada CLI para diagnóstico RBAC."""
    args = build_parser().parse_args(argv)
    try:
        result = authorize_tool_invocation(
            role=args.role or None,
            tool_name=args.tool,
            target=args.target or None,
            root=Path(args.root).resolve(),
        )
    except RbacError as exc:
        print(json.dumps({"status": "DENEGADO", "message": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "PERMITIDO", **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
