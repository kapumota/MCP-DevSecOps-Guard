### Benchmark adversarial

El benchmark usa `eval_cases/cases.yaml` como dataset declarativo controlado. Incluye casos benignos, prompt injection, tool poisoning, path traversal, evidence tampering, ambigüedad operativa, traversal codificado, unicode homoglyphs y casos curados de borde.

El objetivo no es afirmar seguridad perfecta ni reemplazar un pentest. El reporte mide regresiones internas del producto y deja explícito el alcance metodológico. En esta entrega los casos de `unicode_homoglyphs` se consideran mitigados dentro del dataset controlado mediante normalización defensiva.

Comando principal:

```bash
skillchain benchmark run --suite eval_cases --output artifacts/benchmark-report.json --json
```

Métricas esperadas en esta versión controlada:

```text
case_count >= 555
precision = 1.0
recall = 1.0
f1 = 1.0
false_negative = 0
false_positive = 0
known_limitation_case_count = 0
```

Estas métricas solo aplican al dataset versionado del repositorio. Para investigación top todavía se requiere dataset externo, ataques manuales no vistos, comparación contra herramientas baseline, ablation study, métricas por familia de ataque y revisión de terceros.
