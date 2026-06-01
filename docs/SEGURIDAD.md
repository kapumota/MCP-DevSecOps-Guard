### Modelo de seguridad

SkillChain-MCP Guard protege un flujo agentico local-first mediante cinco controles:

1. auditoría de skills `SKILL.md`;
2. auditoría de tools, resources y prompts MCP;
3. policy gate con modos `demo`, `ci` y `strict`;
4. evidence pack verificable con hashes SHA-256;
5. RBAC y sandbox para ejecución MCP.

#### Principio operativo

El modo `demo` permite evidencia fallback y puede terminar en `WARN`. Los modos `ci` y `strict` no deben aceptar fallback, artifacts obsoletos ni hashes inconsistentes.

#### Release candidate

Una entrega de preproducción exige que todos los reportes compartan el mismo `run_id`, que Kubernetes use `securityContext` endurecido, que las tools MCP estén autorizadas por RBAC y que el benchmark adversarial reporte métricas realistas con limitaciones conocidas.


#### Strict después de demo-local

Después de `make demo-local`, un `policy-check --mode strict` debe fallar. No es un bug: la evidencia local fallback existe, por eso la completitud puede ser 100%, pero no proviene de scanners reales. El modo `strict` solo debe aceptar registros operacionales de herramientas reales y hashes consistentes generados en la misma ejecución.
