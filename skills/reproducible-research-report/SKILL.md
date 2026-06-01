---
name: reproducible-research-report
description: Usar este skill para convertir el laboratorio en reporte de investigación, esquema de paper o plan de evaluación.
---

### Skill de reporte reproducible

#### Goal

Convertir el laboratorio DevSecOps MCP en un proyecto académico serio de sistemas, seguridad o ingeniería de software.

#### Inputs

- `README.md` actual.
- Resumen de evidencia DevSecOps desde `summarize_findings`.
- Auditoría de skills desde `scan_agent_skills` o `make skill-scan`.
- Métricas almacenadas en `artifacts/` o `.evidence/`.

#### Procedure

1. Identificar la contribución del proyecto en una oración.
2. Formular preguntas de investigación sobre seguridad MCP, supply chain de skills y reproducibilidad.
3. Resumir arquitectura, threat model, método de evaluación, resultados y limitaciones.
4. Separar evidencia medida de afirmaciones que todavía requieren experimentos.
5. Producir una estructura breve usable en un curso de sistemas/seguridad o portafolio.

#### Output Format

- Esquema tipo paper.
- Checklist de reproducibilidad.
- Plantilla de tabla de evaluación.
- Limitaciones y próximos experimentos.

#### Safety Limits

- No inventar resultados experimentales ni citar evidencia inexistente.
- No solicitar secretos, datos productivos ni acceso de red externo.
- Etiquetar supuestos, limitaciones y mediciones incompletas.

#### Acceptance Criteria

- El reporte separa funcionalidades implementadas de trabajo futuro.
- Cada afirmación de evaluación apunta a un artifact, comando o test.
- La estructura puede usarse sin reescribir encabezados.
- El tono es académico y evita lenguaje de marketing.
