---
name: devsecops-triage
description: Usar este skill para revisar artifacts DevSecOps, priorizar vulnerabilidades o decidir si un build/release puede avanzar.
---

### Skill de triage DevSecOps

#### Goal

Convertir evidencia cruda del pipeline en una decisión de seguridad clara y reproducible.

#### Inputs

- Salida de la tool MCP `summarize_findings`.
- Archivos opcionales desde resources `artifact://...`.
- Objetivo de release, entorno y tolerancia al riesgo.

#### Procedure

1. Verificar frescura de evidencia: fecha de corrida, cantidad de artifacts y scanners faltantes.
2. Agrupar hallazgos por fuente: SAST, SCA, SBOM, image scan, DAST y pruebas de humo Kubernetes.
3. Priorizar críticos/altos explotables, vulnerabilidades alcanzables, issues de imagen base, exposición web e higiene.
4. Para cada hallazgo importante, escribir impacto, ruta probable de explotación, responsable, comando de remediación y comando de validación.
5. Producir una decisión: `PASS`, `PASS_WITH_RISK` o `BLOCKED`.

#### Output Format

- Resumen ejecutivo de riesgo.
- Tabla priorizada de hallazgos.
- Checklist de remediación.
- Brechas de evidencia y siguiente experimento.
- Decisión final del gate.

#### Safety Limits

- No solicitar secretos, credenciales, claves privadas ni acceso arbitrario al sistema de archivos.
- Usar solo comandos permitidos del proyecto y leer únicamente artifacts declarados.
- Tratar evidencia faltante u obsoleta como incertidumbre, no como prueba de seguridad.

#### Acceptance Criteria

- La decisión cita la fuente de evidencia usada en cada afirmación principal.
- La respuesta distingue bloqueantes de advertencias no bloqueantes.
- Los pasos de remediación usan comandos existentes o explican por qué se requiere trabajo manual.
- La decisión final es `PASS`, `PASS_WITH_RISK` o `BLOCKED`.
