### SkillChain-MCP Guard

SkillChain-MCP Guard es un framework local-first para auditar skills, tools MCP y evidencia DevSecOps antes de confiar en un agente. El proyecto implementa scanner de skills, auditor MCP, policy gate, benchmark adversarial, evidence pack verificable, dashboard, CI de seguridad y controles de runtime.


#### Qué hace

- Audita archivos `skills/*/SKILL.md`.
- Audita tools, resources y prompts MCP.
- Ejecuta benchmark adversarial controlado.
- Valida evidencia real frente a fallback local.
- Genera `policy-report.json`, `dashboard.html` y evidence pack verificable.
- Protege ejecución MCP con allowlist, RBAC y sandbox.
- Endurece Docker Compose y Kubernetes para demostración/preproducción.

#### Perfiles principales

| Perfil | Comando | Uso |
|---|---|---|
| Demo local | `make demo-local` | Demostración reproducible; puede quedar en `WARN`. |
| CI seguridad | `make security-ci` | Scanners reales, evidence pack y policy gate `ci`. |
| Release estricto | `make release-verify` | No acepta fallback ni evidencia faltante. |

#### Comandos esenciales

```bash
python -m pytest -q
make demo-local
skillchain policy-check --mode demo --json
skillchain benchmark run --suite eval_cases --output artifacts/benchmark-report.json --json
skillchain evidence verify artifacts/evidence-pack-*.tar.gz --manifest artifacts/evidence-manifest.json
```

#### Trazabilidad por ejecución

Cada corrida usa `SKILLCHAIN_RUN_ID` global exportado por el Makefile. Los reportes internos, registros `.evidence/*-exit.json`, policy gate y evidence pack deben compartir ese identificador para evitar mezclar artifacts de ejecuciones distintas.

#### Seguridad MCP

La tool `run_devsecops_check` no ejecuta comandos libres. Debe pasar por:

1. allowlist de targets Makefile;
2. política RBAC en `config/rbac.json`;
3. sandbox configurado por `SKILLCHAIN_SANDBOX_MODE`;
4. timeout validado;
5. logs recortados para clientes MCP.

#### Benchmark adversarial

El dataset en `eval_cases/cases.yaml` contiene más de 500 casos declarativos. Incluye benignos, prompt injection, tool poisoning, path traversal, evidence tampering, traversal codificado, unicode homoglyphs y casos curados de borde. La versión corregida normaliza texto de seguridad para bloquear homoglifos Unicode dentro del dataset controlado. Las métricas no deben venderse como certificación de seguridad ni como pentest exhaustivo.


#### Nota sobre release estricto

`make demo-local` puede producir `WARN` y un score bajo porque usa evidencia fallback local. Esto es intencional. Si después de `make demo-local` ejecutas:

```bash
python -m devsecops_agent.cli --root . policy-check --mode strict --json
```

la salida esperada es `FAIL`, aunque `evidence_completeness` sea `1.0`. La razón es que la completitud solo indica que existen archivos de evidencia; no indica que provengan de scanners reales. En modo `strict`, la evidencia fallback local no es aceptable.

Para que `strict` pase, antes debe ejecutarse `make security-ci` o `make release-verify` en GitHub Actions o en una máquina preparada con Bandit, Semgrep, pip-audit, Gitleaks, Syft, Grype, Trivy, OpenSSF Scorecard, Docker Compose y ZAP.

#### Empaquetado Python

El workflow construye el paquete distribuible con:

```bash
python -m build
```

Esto valida que el proyecto no dependa únicamente de `pip install -e .`. Los artefactos `dist/*.whl` y `dist/*.tar.gz` se suben como artifact del job de seguridad.

#### Roles MCP

La política RBAC separa cuatro roles:

- `auditor_readonly`: lee evidencias y resume hallazgos, sin ejecutar targets ni regenerar archivos.
- `auditor_operator`: ejecuta operaciones controladas de demo y regeneración liviana.
- `ci_runner`: ejecuta targets de CI/release y generación completa de evidencia.
- `admin`: reservado para mantenimiento controlado.

El rol efectivo no lo decide el cliente MCP. Se obtiene desde `SKILLCHAIN_MCP_ROLE` o desde el rol por defecto definido en `config/rbac.json`.

#### Estado de CI real

El repositorio incluye workflow para instalar herramientas externas y ejecutar `make security-ci`, pero el estado de release estricto solo puede afirmarse después de ver una corrida real exitosa en GitHub Actions o en una máquina equivalente. Si una herramienta externa falta, el policy gate debe fallar.

#### Documentación mantenida

- `docs/SEGURIDAD.md`
- `docs/BENCHMARK.md`
- `docs/RBAC_SANDBOX.md`
- `docs/KUBERNETES.md`
- `SECURITY.md`


