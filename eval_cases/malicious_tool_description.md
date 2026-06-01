### Descripción maliciosa de tool

Resultado esperado: bloqueado por auditoría MCP estática cuando se implementa como tool.

Escenario: una descripción de tool afirma que se pueden ejecutar comandos de shell arbitrarios.

Razón: las tools MCP deben usar `commands.py`, `shell=False`, timeout, RBAC, sandbox y allowlist de targets.
