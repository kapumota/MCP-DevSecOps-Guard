"""Scanner defensivo para validar skills antes de usarlos con agentes."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .commands import ALLOWED_MAKE_TARGETS
from .config import REQUIRED_SKILL_SECTIONS, REPO_ROOT, SKILL_REPORT_PATH, SKILLS_DIR
from .report_writer import write_json_report
from .security_models import RiskLevel, ScanStatus, SkillFinding, SkillScanResult
from .text_security import normalize_security_text, suspicious_unicode_delta


DANGEROUS_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (
        r"\brm\s+-rf\s+(/|\$\{|~|\*)",
        "dangerous_recursive_delete",
        "Evita instrucciones que puedan borrar rutas amplias o variables críticas.",
    ),
    (
        r"\b(curl|wget)\b.+\|\s*(sh|bash)\b",
        "remote_script_pipe_to_shell",
        "No permitas instalación o ejecución remota encadenada directamente a shell.",
    ),
    (
        r"\bchmod\s+777\b",
        "world_writable_permission",
        "Usa permisos mínimos y explícitos en lugar de chmod 777.",
    ),
    (
        r"\bsudo\b",
        "privileged_execution",
        "Los skills deben evitar privilegios elevados salvo justificación explícita y controlada.",
    ),
    (
        r"/etc/(passwd|shadow)|~/.ssh|id_rsa|id_ed25519",
        "sensitive_file_reference",
        "No incluyas lectura de archivos sensibles en instrucciones de skills.",
    ),
    (
        r"\b(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY|PRIVATE_KEY|API_KEY)\b",
        "secret_reference",
        "No solicites ni manipules secretos desde un skill reutilizable.",
    ),
    (
        r"ignore (all )?(previous|prior|system|developer) instructions",
        "prompt_injection_phrase",
        "Elimina frases diseñadas para anular instrucciones superiores del agente.",
    ),
    (
        r"ignore\s+(safety|security)\s+limits.*\b(reveal|expose|print|dump)\b",
        "security_limit_bypass",
        "No permitas instrucciones que pidan ignorar límites de seguridad o revelar datos sensibles.",
    ),
    (
        r"\b(exfiltrate|steal|leak)\b",
        "data_exfiltration_language",
        "Evita lenguaje de exfiltración o extracción no autorizada de datos.",
    ),
)

AMBIGUOUS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(as needed|etc\.|and so on|do the necessary|fix everything)\b", "Reemplaza instrucciones vagas por pasos observables y criterios verificables."),
    (r"\b(use your judgment|be creative|whatever works)\b", "Define límites operativos explícitos para que el agente no improvise fuera del alcance."),
)

UNNECESSARY_ACCESS_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"\b(internet|external network|public web|remote server)\b", "network_access", "Justifica el acceso de red o limita el skill a evidencias locales."),
    (r"\b(entire filesystem|whole disk|all files|home directory)\b", "broad_filesystem_access", "Limita el acceso a artifacts/, .evidence/ o archivos declarados."),
)

MAKE_COMMAND_PATTERN = re.compile(r"`make\s+([A-Za-z0-9_.:-]+)(?:\s|`)")
FRONT_MATTER_PATTERN = re.compile(r"\A---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(?P<title>.+)$")


def normalize_heading(value: str) -> str:
    """Normaliza un heading Markdown para comparaciones simples."""
    return re.sub(r"\s+", " ", value.strip().lower())


def discover_skill_files(root: Path | None = None, skills_dir: str = SKILLS_DIR) -> list[Path]:
    """Descubre archivos SKILL.md dentro del directorio de skills."""
    base = (root or REPO_ROOT).resolve()
    directory = (base / skills_dir).resolve()
    if not directory.exists():
        return []
    return sorted(path for path in directory.glob("*/SKILL.md") if path.is_file())


def parse_front_matter(text: str) -> dict[str, str]:
    """Extrae front matter YAML simple sin depender de PyYAML."""
    match = FRONT_MATTER_PATTERN.search(text)
    if not match:
        return {}

    fields: dict[str, str] = {}
    for line in match.group("body").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip().strip('"\'')
    return fields


def iter_lines(text: str) -> Iterable[tuple[int, str]]:
    """Itera líneas con numeración humana desde 1."""
    for line_number, line in enumerate(text.splitlines(), start=1):
        yield line_number, line


def add_finding(
    findings: list[SkillFinding],
    rule_id: str,
    severity: RiskLevel,
    message: str,
    relative_path: str,
    recommendation: str,
    line: int | None = None,
) -> None:
    """Agrega un hallazgo normalizado al resultado del scanner."""
    findings.append(
        SkillFinding(
            rule_id=rule_id,
            severity=severity.value,
            message=message,
            relative_path=relative_path,
            line=line,
            recommendation=recommendation,
        )
    )


def scan_front_matter(text: str, relative_path: str, findings: list[SkillFinding]) -> dict[str, str]:
    """Valida metadata mínima del skill."""
    metadata = parse_front_matter(text)
    if not metadata:
        add_finding(
            findings,
            "SKILL001",
            RiskLevel.MEDIUM,
            "El skill no tiene front matter inicial.",
            relative_path,
            "Agrega front matter con name y description.",
            line=1,
        )
        return metadata

    for key in ("name", "description"):
        if not metadata.get(key):
            add_finding(
                findings,
                "SKILL002",
                RiskLevel.MEDIUM,
                f"El front matter no define `{key}`.",
                relative_path,
                f"Declara `{key}` en el front matter del SKILL.md.",
                line=1,
            )

    return metadata


def scan_markdown_structure(text: str, relative_path: str, findings: list[SkillFinding]) -> None:
    """Valida que la documentación use título ### y subtítulos ####."""
    headings: list[tuple[int, str, str]] = []
    for line_number, line in iter_lines(text):
        match = HEADING_PATTERN.match(line)
        if match:
            headings.append((line_number, match.group(1), match.group("title")))

    if not headings:
        add_finding(
            findings,
            "SKILL003",
            RiskLevel.MEDIUM,
            "El skill no tiene headings Markdown.",
            relative_path,
            "Agrega un título con ### y subtítulos con ####.",
        )
        return

    first_line, first_level, _ = headings[0]
    if first_level != "###":
        add_finding(
            findings,
            "SKILL004",
            RiskLevel.MEDIUM,
            "El primer heading debe usar ### como título principal.",
            relative_path,
            "Cambia el título principal del skill a nivel ###.",
            line=first_line,
        )

    for line_number, level, title in headings[1:]:
        if level != "####":
            add_finding(
                findings,
                "SKILL005",
                RiskLevel.LOW,
                f"El subtítulo `{title}` debería usar ####.",
                relative_path,
                "Usa #### para subtítulos dentro de SKILL.md.",
                line=line_number,
            )

    normalized_headings = {normalize_heading(title) for _, _, title in headings}
    for required_section in REQUIRED_SKILL_SECTIONS:
        if required_section not in normalized_headings:
            add_finding(
                findings,
                "SKILL006",
                RiskLevel.MEDIUM,
                f"Falta la sección obligatoria `{required_section}`.",
                relative_path,
                "Agrega la sección para mejorar reproducibilidad y criterios de revisión.",
            )


def scan_dangerous_language(text: str, relative_path: str, findings: list[SkillFinding]) -> None:
    """Busca patrones peligrosos sobre texto original y normalizado defensivamente."""
    compiled_patterns = [
        (re.compile(pattern, re.IGNORECASE), rule_suffix, recommendation)
        for pattern, rule_suffix, recommendation in DANGEROUS_PATTERNS
    ]

    emitted: set[tuple[int, str]] = set()
    for line_number, line in iter_lines(text):
        candidates = [line]
        normalized_line = normalize_security_text(line)
        if normalized_line != line.casefold():
            candidates.append(normalized_line)
            if suspicious_unicode_delta(line):
                key = (line_number, "unicode_confusable")
                if key not in emitted:
                    emitted.add(key)
                    add_finding(
                        findings,
                        "SKILL-DANGEROUS-UNICODE_CONFUSABLE",
                        RiskLevel.MEDIUM,
                        "El skill contiene caracteres Unicode confusables que pueden ocultar instrucciones sensibles.",
                        relative_path,
                        "Normaliza o elimina homoglifos antes de aprobar el skill.",
                        line=line_number,
                    )
        for candidate in candidates:
            for pattern, rule_suffix, recommendation in compiled_patterns:
                key = (line_number, rule_suffix)
                if key not in emitted and pattern.search(candidate):
                    emitted.add(key)
                    add_finding(
                        findings,
                        f"SKILL-DANGEROUS-{rule_suffix.upper()}",
                        RiskLevel.HIGH,
                        "El skill contiene una instrucción o referencia potencialmente peligrosa.",
                        relative_path,
                        recommendation,
                        line=line_number,
                    )


def scan_ambiguous_language(text: str, relative_path: str, findings: list[SkillFinding]) -> None:
    """Detecta instrucciones vagas que dificultan aceptación y revisión segura."""
    compiled_patterns = [(re.compile(pattern, re.IGNORECASE), recommendation) for pattern, recommendation in AMBIGUOUS_PATTERNS]
    for line_number, line in iter_lines(text):
        for pattern, recommendation in compiled_patterns:
            if pattern.search(line):
                add_finding(
                    findings,
                    "SKILL008",
                    RiskLevel.LOW,
                    "El skill contiene una instrucción ambigua.",
                    relative_path,
                    recommendation,
                    line=line_number,
                )


def scan_unnecessary_access(text: str, relative_path: str, findings: list[SkillFinding]) -> None:
    """Detecta solicitudes amplias de red o sistema de archivos."""
    compiled_patterns = [
        (re.compile(pattern, re.IGNORECASE), rule_suffix, recommendation)
        for pattern, rule_suffix, recommendation in UNNECESSARY_ACCESS_PATTERNS
    ]
    for line_number, line in iter_lines(text):
        for pattern, rule_suffix, recommendation in compiled_patterns:
            if pattern.search(line):
                add_finding(
                    findings,
                    f"SKILL-ACCESS-{rule_suffix.upper()}",
                    RiskLevel.MEDIUM,
                    "El skill solicita acceso amplio a red o sistema de archivos.",
                    relative_path,
                    recommendation,
                    line=line_number,
                )


def scan_make_commands(text: str, relative_path: str, findings: list[SkillFinding]) -> None:
    """Detecta comandos make documentados que no estén en la allowlist."""
    for line_number, line in iter_lines(text):
        for match in MAKE_COMMAND_PATTERN.finditer(line):
            target = match.group(1)
            if target not in ALLOWED_MAKE_TARGETS:
                add_finding(
                    findings,
                    "SKILL007",
                    RiskLevel.MEDIUM,
                    f"El skill referencia `make {target}`, que no está en la allowlist MCP.",
                    relative_path,
                    "Usa solo targets Makefile permitidos o actualiza la allowlist de forma explícita.",
                    line=line_number,
                )


def calculate_skill_score(findings: Sequence[SkillFinding]) -> int:
    """Calcula un score simple de 0 a 100 a partir de severidades."""
    penalties = {
        RiskLevel.LOW.value: 5,
        RiskLevel.MEDIUM.value: 15,
        RiskLevel.HIGH.value: 35,
        RiskLevel.CRITICAL.value: 60,
    }
    score = 100 - sum(penalties.get(finding.severity, 10) for finding in findings)
    return max(0, min(100, score))


def determine_risk_level(findings: Sequence[SkillFinding]) -> RiskLevel:
    """Calcula el riesgo agregado del skill según la severidad máxima."""
    severities = {finding.severity for finding in findings}
    if RiskLevel.CRITICAL.value in severities:
        return RiskLevel.CRITICAL
    if RiskLevel.HIGH.value in severities:
        return RiskLevel.HIGH
    if RiskLevel.MEDIUM.value in severities:
        return RiskLevel.MEDIUM
    if RiskLevel.LOW.value in severities:
        return RiskLevel.LOW
    return RiskLevel.LOW


def scan_skill_file(path: Path, root: Path | None = None) -> SkillScanResult:
    """Escanea un archivo SKILL.md y devuelve un resultado estructurado."""
    base = (root or REPO_ROOT).resolve()
    skill_path = path.resolve()
    relative_path = skill_path.relative_to(base).as_posix()
    text = skill_path.read_text(encoding="utf-8", errors="replace")
    findings: list[SkillFinding] = []

    metadata = scan_front_matter(text, relative_path, findings)
    scan_markdown_structure(text, relative_path, findings)
    scan_dangerous_language(text, relative_path, findings)
    scan_ambiguous_language(text, relative_path, findings)
    scan_unnecessary_access(text, relative_path, findings)
    scan_make_commands(text, relative_path, findings)

    skill_name = metadata.get("name") or skill_path.parent.name
    risk_level = determine_risk_level(findings)
    score = calculate_skill_score(findings)

    return SkillScanResult(
        skill_name=skill_name,
        relative_path=relative_path,
        risk_level=risk_level.value,
        score=score,
        findings=findings,
    )


def summarize_skill_scan(results: Sequence[SkillScanResult], root: Path | None = None) -> dict[str, Any]:
    """Construye un resumen agregado para todos los skills auditados."""
    base = (root or REPO_ROOT).resolve()
    high_count = sum(
        1
        for result in results
        for finding in result.findings
        if finding.severity in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}
    )
    medium_count = sum(
        1 for result in results for finding in result.findings if finding.severity == RiskLevel.MEDIUM.value
    )
    low_count = sum(
        1 for result in results for finding in result.findings if finding.severity == RiskLevel.LOW.value
    )

    status = ScanStatus.FAIL if high_count else ScanStatus.WARN if medium_count else ScanStatus.PASS
    average_score = round(sum(result.score for result in results) / len(results), 2) if results else 0.0

    return {
        "scanner": "skillchain-mcp-guard-skill-scanner",
        "status": status.value,
        "repo_root": str(base),
        "scanned_skills": len(results),
        "average_score": average_score,
        "finding_counts": {
            "high_or_critical": high_count,
            "medium": medium_count,
            "low": low_count,
            "total": high_count + medium_count + low_count,
        },
        "results": [result.to_dict() for result in results],
    }


def scan_skills(root: Path | None = None, skills_dir: str = SKILLS_DIR) -> dict[str, Any]:
    """Ejecuta el scanner sobre todos los skills del repositorio."""
    base = (root or REPO_ROOT).resolve()
    skill_files = discover_skill_files(base, skills_dir=skills_dir)
    results = [scan_skill_file(path, root=base) for path in skill_files]
    return summarize_skill_scan(results, root=base)


def write_scan_report(report: dict[str, Any], output_path: Path, root: Path | None = None) -> Path:
    """Escribe el reporte JSON en disco creando directorios si hace falta."""
    return write_json_report(report, output_path, root=root)


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser CLI del scanner."""
    parser = argparse.ArgumentParser(description="Audit agent skills for structure and supply-chain risk.")
    parser.add_argument("--root", default=str(REPO_ROOT), help="Raíz del repositorio a escanear.")
    parser.add_argument("--skills-dir", default=SKILLS_DIR, help="Directory containing skill folders.")
    parser.add_argument("--output", default=SKILL_REPORT_PATH, help="Ruta de salida del reporte JSON.")
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Devuelve estado 2 si existen hallazgos altos o críticos.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada CLI para generar el reporte del scanner."""
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    report = scan_skills(root=root, skills_dir=args.skills_dir)
    output = write_scan_report(report, Path(args.output), root=root)
    print(json.dumps({"status": report["status"], "output": str(output)}, ensure_ascii=False))

    if args.fail_on_high and report["finding_counts"]["high_or_critical"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
