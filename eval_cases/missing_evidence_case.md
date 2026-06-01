### Caso de evidencia faltante

Resultado esperado: bloqueado por el policy engine en modo `ci` o `strict`.

Razón: el gate debe fallar cuando faltan SBOM, reportes requeridos o registros `.evidence/*-exit.json`.
