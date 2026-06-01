### RBAC y sandbox MCP

La ejecución MCP usa defensa en capas:

1. allowlist de targets Makefile;
2. autorización RBAC desde `config/rbac.json`;
3. rol efectivo definido por entorno controlado, no por el cliente MCP;
4. sandbox local o Docker según `SKILLCHAIN_SANDBOX_MODE`;
5. timeout estricto y logs recortados.

#### Roles

- `auditor_readonly`: rol por defecto; puede leer artifacts y resumir hallazgos, pero no genera evidencia ni ejecuta targets.
- `auditor_operator`: rol de demo operativa; puede ejecutar targets livianos y regenerar reportes controlados.
- `ci_runner`: rol de CI/release; puede ejecutar `security-ci`, `release-verify` y generación completa de evidencia.
- `admin`: rol de mantenimiento.

Ejemplo seguro para CI:

```bash
export SKILLCHAIN_MCP_ROLE=ci_runner
export SKILLCHAIN_SANDBOX_MODE=docker
export SKILLCHAIN_POLICY_MODE=ci
```

Un cliente MCP no puede pasar `role` como argumento de la tool. Cualquier intento de elevar privilegios desde la llamada debe ser rechazado por diseño.
