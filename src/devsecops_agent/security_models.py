"""Modelos compartidos para reportes de seguridad."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class RiskLevel(StrEnum):
    """Niveles normalizados para decisiones de seguridad."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(StrEnum):
    """Estados normalizados para salidas de scanners."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True)
class ArtifactInfo:
    """Metadatos mínimos de una evidencia generada por el pipeline."""

    name: str
    relative_path: str
    size_bytes: int
    modified_unix: float

    def to_dict(self) -> dict[str, Any]:
        """Convierte el modelo a un diccionario serializable."""
        return asdict(self)


@dataclass(frozen=True)
class SkillFinding:
    """Hallazgo emitido por el scanner de skills."""

    rule_id: str
    severity: str
    message: str
    relative_path: str
    line: int | None
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Convierte el hallazgo a JSON simple."""
        return asdict(self)


@dataclass(frozen=True)
class SkillScanResult:
    """Resultado individual de auditoría para un archivo SKILL.md."""

    skill_name: str
    relative_path: str
    risk_level: str
    score: int
    findings: list[SkillFinding]

    def to_dict(self) -> dict[str, Any]:
        """Convierte el resultado a un diccionario serializable."""
        return {
            "skill": self.skill_name,
            "skill_name": self.skill_name,
            "relative_path": self.relative_path,
            "risk_level": self.risk_level,
            "score": self.score,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class SecurityFinding:
    """Hallazgo genérico para auditorías MCP, policy gates y evaluación."""

    rule_id: str
    severity: str
    message: str
    component: str
    recommendation: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convierte el hallazgo genérico a un diccionario serializable."""
        return asdict(self)
