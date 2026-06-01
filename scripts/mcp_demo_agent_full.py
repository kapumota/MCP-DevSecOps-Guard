"""Agente MCP potente para SkillChain-MCP Guard.

Ejecutar desde la raíz del repositorio:

    source .mcp/bin/activate
    python scripts/mcp_demo_agent_full.py --mode quick --max-chars 1200

Opciones útiles:

    python scripts/mcp_demo_agent_full.py --mode quick
    python scripts/mcp_demo_agent_full.py --mode full
    python scripts/mcp_demo_agent_full.py --mode full --include-make-targets
    python scripts/mcp_demo_agent_full.py --mode full --max-chars 1800

Este script NO inicia un LLM real. Simula el rol operativo de un agente MCP:
1. Arranca el servidor MCP como subprocess por stdio.
2. Descubre tools, resources y prompts.
3. Ejecuta tools seguras.
4. Ejecuta checks DevSecOps permitidos por allowlist.
5. Lee resources de solo lectura.
6. Lee artifacts generados.
7. Solicita prompts.
8. Produce un resumen final para demostración.

Notas:
- No ejecutes `make mcp-server` aparte. Este script levanta el servidor automáticamente.
- Los artifacts se leen con URI tipo `artifact://policy-report.json`.
- Los documentos del proyecto se leen con `repo://readme`, `repo://project` y `repo://security`.
"""

import argparse
import asyncio
import ast
import json
import os
import re
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


DEFAULT_QUICK_TARGETS = [
    "skills-validate",
    "skill-scan",
    "mcp-audit",
    "agent-eval",
    "local-evidence",
    "policy-check",
    "evidence-pack",
    "product-status",
    "dashboard",
]

DEFAULT_FULL_TARGETS = [
    "unit",
    "skills-validate",
    "skill-scan",
    "mcp-audit",
    "agent-eval",
    "local-evidence",
    "policy-check",
    "evidence-pack",
    "product-scan",
    "product-status",
    "dashboard",
]

EXTRA_SAFE_TARGETS = [
    "prepare-dirs",
    "local-evidence",
    "skills-validate",
    "skill-scan",
    "mcp-audit",
    "agent-eval",
    "policy-check",
    "evidence-pack",
    "product-scan",
    "product-status",
    "dashboard",
]

KNOWN_SAFE_TARGETS = sorted(set(DEFAULT_QUICK_TARGETS + DEFAULT_FULL_TARGETS + EXTRA_SAFE_TARGETS))

ARTIFACT_RESOURCES_TO_READ = [
    "artifact://skill-scan-report.json",
    "artifact://mcp-audit-report.json",
    "artifact://agent-eval-report.json",
    "artifact://policy-report.json",
    "artifact://product-status.json",
    "artifact://evidence-manifest.json",
]


def print_title(title: str) -> None:
    """Imprime una sección legible para demostración."""
    print("\n" + "=" * 88)
    print(title)
    print("=" * 88)


def print_step(title: str) -> None:
    """Imprime un paso interno."""
    print("\n" + "-" * 88)
    print(title)
    print("-" * 88)


def truncate(text: str, max_chars: int) -> str:
    """Recorta texto largo para mantener la demostración legible."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[salida truncada]..."


def to_serializable(value: Any) -> Any:
    """Convierte objetos del SDK MCP en estructuras imprimibles."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [to_serializable(item) for item in value]
    if isinstance(value, tuple):
        return [to_serializable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_serializable(item) for key, item in value.items()}

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return to_serializable(model_dump())

    if hasattr(value, "__dict__"):
        return to_serializable(vars(value))

    return str(value)


def extract_text(value: Any) -> str:
    """Extrae texto de respuestas MCP cuando sea posible."""
    serializable = to_serializable(value)

    if isinstance(serializable, dict):
        for key in ("content", "contents"):
            content = serializable.get(key)
            if isinstance(content, list):
                parts: list[str] = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        parts.append(str(text) if text is not None else json.dumps(item, ensure_ascii=False, indent=2))
                    else:
                        parts.append(str(item))
                return "\n".join(parts)

        return json.dumps(serializable, ensure_ascii=False, indent=2)

    return json.dumps(serializable, ensure_ascii=False, indent=2)


def parse_json_from_mcp(value: Any) -> Any:
    """Intenta interpretar una respuesta MCP como JSON o literal Python simple."""
    text = extract_text(value).strip()
    if not text:
        return None

    for parser in (json.loads, ast.literal_eval):
        try:
            return parser(text)
        except Exception:
            pass

    return text


def extract_allowed_targets(value: Any) -> list[str]:
    """Extrae targets desde la respuesta MCP de allowed_devsecops_targets."""
    parsed = parse_json_from_mcp(value)
    candidates: list[str] = []

    if isinstance(parsed, list):
        candidates.extend(str(item) for item in parsed)
    elif isinstance(parsed, dict):
        for key in ("targets", "allowed_targets", "result"):
            inner = parsed.get(key)
            if isinstance(inner, list):
                candidates.extend(str(item) for item in inner)
    elif isinstance(parsed, str):
        candidates.extend(re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]*", parsed))

    normalized = []
    for item in candidates:
        target = item.strip().strip("'\"")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", target):
            normalized.append(target)

    return sorted(set(normalized))


def print_mcp_result(value: Any, max_chars: int = 2500) -> None:
    """Imprime una respuesta MCP en formato legible."""
    print(truncate(extract_text(value), max_chars))


async def safe_call_tool(
    session: ClientSession,
    name: str,
    arguments: dict[str, Any] | None = None,
    max_chars: int = 2500,
) -> Any:
    """Ejecuta una tool MCP y captura errores para que la demostración continúe."""
    arguments = arguments or {}
    print_step(f"Tool: {name} | args={arguments}")
    try:
        result = await session.call_tool(name, arguments)
        print_mcp_result(result, max_chars=max_chars)
        return result
    except Exception as exc:
        print(f"[ERROR] La tool `{name}` falló: {exc}")
        return {"error": str(exc), "tool": name}


async def safe_read_resource(
    session: ClientSession,
    uri: str,
    max_chars: int = 2500,
) -> Any:
    """Lee un resource MCP y captura errores."""
    print_step(f"Resource: {uri}")
    try:
        result = await session.read_resource(uri)
        print_mcp_result(result, max_chars=max_chars)
        return result
    except Exception as exc:
        print(f"[ERROR] No se pudo leer `{uri}`: {exc}")
        return {"error": str(exc), "resource": uri}


async def safe_get_prompt(
    session: ClientSession,
    name: str,
    arguments: dict[str, Any] | None = None,
    max_chars: int = 2500,
) -> Any:
    """Obtiene un prompt MCP y captura errores."""
    arguments = arguments or {}
    print_step(f"Prompt: {name} | args={arguments}")
    try:
        result = await session.get_prompt(name, arguments)
        print_mcp_result(result, max_chars=max_chars)
        return result
    except Exception as exc:
        print(f"[ERROR] No se pudo obtener el prompt `{name}`: {exc}")
        return {"error": str(exc), "prompt": name}


def select_targets(mode: str, allowed_targets: list[str], include_make_targets: bool) -> list[str]:
    """Selecciona targets seguros para la demostración."""
    desired = DEFAULT_QUICK_TARGETS if mode == "quick" else DEFAULT_FULL_TARGETS

    if allowed_targets:
        selected = [target for target in desired if target in allowed_targets]
    else:
        selected = [target for target in desired if target in KNOWN_SAFE_TARGETS]

    if include_make_targets:
        for target in EXTRA_SAFE_TARGETS:
            allowed_by_server = not allowed_targets or target in allowed_targets
            if allowed_by_server and target not in selected:
                selected.append(target)

    return selected


def get_value(obj: Any, *keys: str, default: str = "n/a") -> Any:
    """Obtiene un valor anidado desde dicts."""
    current = obj
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def summarize_status(raw_results: dict[str, Any]) -> None:
    """Imprime un resumen final de resultados relevantes."""
    print_title("RESUMEN FINAL DEL AGENTE")

    product_json = parse_json_from_mcp(raw_results.get("generate_product_dashboard"))
    policy_json = parse_json_from_mcp(raw_results.get("evaluate_policy_gate"))
    mcp_json = parse_json_from_mcp(raw_results.get("audit_mcp_server"))
    skill_json = parse_json_from_mcp(raw_results.get("scan_agent_skills"))

    print(f"Estado policy gate: {get_value(policy_json, 'status')}")
    print(f"Dashboard status: {get_value(product_json, 'status')}")
    print(f"Puntaje de seguridad: {get_value(product_json, 'security_score')}")
    print(f"Riesgo MCP: {get_value(mcp_json, 'overall_risk')}")
    print(f"Riesgo skills: {get_value(skill_json, 'overall_risk')}")
    print(f"Dashboard HTML: {get_value(product_json, 'dashboard')}")
    print(f"Product status JSON: {get_value(product_json, 'product_status')}")

    print(
        "\nConclusión: el agente usó MCP por stdio para descubrir capacidades, "
        "ejecutar operaciones DevSecOps permitidas, leer contexto controlado y generar evidencia, "
        "sin recibir ejecución arbitraria ni acceso libre al filesystem."
    )


async def main() -> int:
    """Ejecuta una demostración MCP potente usando stdio."""
    parser = argparse.ArgumentParser(description="SkillChain-MCP Guard MCP agent.")
    parser.add_argument(
        "--mode",
        choices=["quick", "full"],
        default="full",
        help="quick ejecuta menos pasos; full muestra más capacidades del proyecto.",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=2200,
        help="Máximo de caracteres impresos por respuesta MCP.",
    )
    parser.add_argument(
        "--include-make-targets",
        action="store_true",
        help="Ejecuta una selección adicional de targets Makefile allowlisted.",
    )
    parser.add_argument(
        "--repo-root",
        default=os.getcwd(),
        help="Raíz del repositorio. Por defecto usa el directorio actual.",
    )
    args = parser.parse_args()

    repo_root = str(Path(args.repo_root).resolve())

    server_params = StdioServerParameters(
        command="python",
        args=["-m", "devsecops_agent.mcp_server"],
        env={
            **os.environ,
            "DEVSECOPS_REPO_ROOT": repo_root,
        },
    )

    raw_results: dict[str, Any] = {}

    print_title("0. DEMOSTRACIÓN MCP + AGENTE LOCAL")
    print("Este script simula un agente usando SkillChain-MCP Guard vía MCP stdio.")
    print("No necesitas ejecutar `make mcp-server` aparte.")
    print("Servidor:", "python -m devsecops_agent.mcp_server")
    print("Repo root:", repo_root)
    print("Modo:", args.mode)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            print_title("1. Inicializando sesión MCP")
            await session.initialize()
            print("Sesión MCP inicializada correctamente.")

            print_title("2. Descubrimiento de tools")
            tools = await session.list_tools()
            tool_names = [tool.name for tool in tools.tools]
            for tool in tools.tools:
                description = getattr(tool, "description", "") or ""
                print(f"- {tool.name}: {description}")

            print_title("3. Descubrimiento de resources")
            try:
                resources = await session.list_resources()
                if resources.resources:
                    for resource in resources.resources:
                        print(f"- {resource.uri}: {getattr(resource, 'name', '')}")
                else:
                    print("No se listaron resources estáticos. Se probarán URIs conocidas igualmente.")
            except Exception as exc:
                print(f"[WARN] El listado de resources no estuvo disponible: {exc}")

            print_title("4. Descubrimiento de prompts")
            try:
                prompts = await session.list_prompts()
                if prompts.prompts:
                    for prompt in prompts.prompts:
                        print(f"- {prompt.name}: {getattr(prompt, 'description', '')}")
                else:
                    print("No se listaron prompts.")
            except Exception as exc:
                print(f"[WARN] El listado de prompts no estuvo disponible: {exc}")

            print_title("5. Allowlist de targets Makefile")
            targets_result = await safe_call_tool(
                session,
                "allowed_devsecops_targets",
                {},
                max_chars=args.max_chars,
            )
            raw_results["allowed_devsecops_targets"] = targets_result

            allowed_targets = extract_allowed_targets(targets_result)
            if allowed_targets:
                print("\nTargets interpretados desde allowlist:")
                print(", ".join(allowed_targets))
            else:
                print("\n[WARN] No se pudo interpretar la allowlist. Se usará una lista segura local para la demostración.")

            print_title("6. Ejecución de tools principales del proyecto")
            for tool_name in [
                "scan_agent_skills",
                "audit_mcp_server",
                "run_adversarial_evaluation",
                "evaluate_policy_gate",
                "create_evidence_archive",
                "generate_product_dashboard",
                "list_devsecops_artifacts",
                "summarize_findings",
            ]:
                if tool_name in tool_names:
                    raw_results[tool_name] = await safe_call_tool(
                        session,
                        tool_name,
                        {},
                        max_chars=args.max_chars,
                    )
                else:
                    print(f"[SKIP] Tool no expuesta por el servidor: {tool_name}")

            print_title("7. Ejecución controlada mediante run_devsecops_check")
            if "run_devsecops_check" in tool_names:
                selected_targets = select_targets(args.mode, allowed_targets, args.include_make_targets)
                print("Targets seleccionados:", ", ".join(selected_targets))

                for target in selected_targets:
                    raw_results[f"target:{target}"] = await safe_call_tool(
                        session,
                        "run_devsecops_check",
                        {
                            "target": target,
                            "timeout_seconds": 240,
                        },
                        max_chars=args.max_chars,
                    )
            else:
                print("[SKIP] run_devsecops_check no está expuesta.")

            print_title("8. Lectura de resources de solo lectura")
            await safe_read_resource(session, "repo://readme", max_chars=args.max_chars)
            await safe_read_resource(session, "repo://project", max_chars=args.max_chars)
            await safe_read_resource(session, "repo://security", max_chars=args.max_chars)

            print_title("9. Lectura de artifacts generados como resources")
            for uri in ARTIFACT_RESOURCES_TO_READ:
                await safe_read_resource(session, uri, max_chars=args.max_chars)

            print_title("10. Prueba defensiva: artifact path traversal")
            print("El agente intenta leer una ruta no permitida. Debe fallar o ser bloqueada.")
            await safe_read_resource(
                session,
                "artifact://../pyproject.toml",
                max_chars=args.max_chars,
            )

            print_title("11. Uso del prompt de triage")
            await safe_get_prompt(
                session,
                "triage_security_findings",
                {
                    "release_goal": "GitHub public release",
                },
                max_chars=args.max_chars,
            )

            summarize_status(raw_results)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nDemostración interrumpida por el usuario.")
        raise SystemExit(130)
