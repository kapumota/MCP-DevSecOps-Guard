# Pipe DevSecOps local-first (sin secretos, sin registries remotos, sin act)
# Uso típico:
#   make ensure-tools   # Verifica herramientas locales
#   make venv           # Crea entorno virtual de Python
#   make pipeline       # Ejecuta el pipeline completo DevSecOps local

SERVICE ?= python-microservice
IMAGE ?= $(SERVICE):dev
ZAP_IMAGE ?= ghcr.io/zaproxy/zaproxy:stable
SCORECARD_REPO ?= $(if $(GITHUB_REPOSITORY),https://github.com/$(GITHUB_REPOSITORY),https://github.com/kapumota/SkillChain-MCP-Guard)
POLICY_MODE ?= strict
ifndef SKILLCHAIN_RUN_ID
SKILLCHAIN_RUN_ID := local-$(shell date -u +%Y%m%dT%H%M%SZ)-$(shell printf "%s" $$$$)
endif
ifndef SKILLCHAIN_STARTED_AT
SKILLCHAIN_STARTED_AT := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
endif
ifndef SKILLCHAIN_GIT_COMMIT
SKILLCHAIN_GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
endif
SKILLCHAIN_SANDBOX_MODE ?= local
SKILLCHAIN_SANDBOX_IMAGE ?= skillchain-sandbox:dev
SKILLCHAIN_MCP_ROLE ?= auditor_readonly

export SKILLCHAIN_RUN_ID
export SKILLCHAIN_STARTED_AT
export SKILLCHAIN_GIT_COMMIT
export SKILLCHAIN_SANDBOX_MODE
export SKILLCHAIN_SANDBOX_IMAGE
export SKILLCHAIN_MCP_ROLE

VENV ?= .skillchain
PYTHON_BOOTSTRAP ?= python3.12
PY ?= $(VENV)/bin/python
PIP ?= $(PY) -m pip
PYTHONPATH ?= src
export PYTHONPATH

# Directorios de salida usados por scanners y evidencias operativas

prepare-dirs:
	@echo ">> Preparando directorios de evidencias"
	@mkdir -p artifacts .evidence

# Herramientas necesarias (local-first, todo corre en tu máquina)

ensure-tools:
	@echo ">> Verificando herramientas locales requeridas (syft, grype, trivy, docker, kind, kubectl, semgrep, bandit, pip-audit, gitleaks, scorecard, in-toto)..."
	@which docker >/dev/null || (echo "Falta 'docker' en el PATH" && exit 1)
	@which kind >/dev/null || (echo "Falta 'kind' en el PATH" && exit 1)
	@which kubectl >/dev/null || (echo "Falta 'kubectl' en el PATH" && exit 1)
	@which syft >/dev/null || echo "Instalar syft: https://github.com/anchore/syft"
	@which grype >/dev/null || echo "Instalar grype: https://github.com/anchore/grype"
	@which trivy >/dev/null || echo "Opcional: instalar trivy: https://github.com/aquasecurity/trivy"
	@which semgrep >/dev/null || echo "Instalar semgrep: pip install semgrep"
	@which bandit >/dev/null || echo "Instalar bandit: pip install bandit"
	@which pip-audit >/dev/null || echo "Instalar pip-audit: pip install pip-audit"
	@which gitleaks >/dev/null || echo "Instalar gitleaks para secret-scan"
	@which scorecard >/dev/null || echo "Instalar scorecard CLI o usar GitHub Action oficial"
	@which in-toto-run >/dev/null || echo "Instalar in-toto: pip install in-toto"


# Entorno virtual de Python para desarrollo y herramientas

venv:
	@echo ">> Creando entorno virtual $(VENV) e instalando dependencias de desarrollo"
	$(PYTHON_BOOTSTRAP) -m venv $(VENV)
	$(PIP) install -U pip
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .


# Construcción de la imagen Docker de la aplicación

build:
	@echo ">> Construyendo imagen Docker $(IMAGE)"
	docker build -t $(IMAGE) -f docker/Dockerfile .

sandbox-image:
	@echo ">> Construyendo imagen de sandbox MCP skillchain-sandbox:dev"
	docker build -t skillchain-sandbox:dev -f docker/sandbox.Dockerfile .

sandbox-smoke: sandbox-image prepare-dirs
	@echo ">> Verificando ejecución MCP dentro del sandbox Docker"
	@SKILLCHAIN_SANDBOX_MODE=docker SKILLCHAIN_POLICY_MODE=demo POLICY_MODE=demo SKILLCHAIN_MCP_ROLE=ci_runner python -c "from devsecops_agent.commands import run_make_target; result = run_make_target('unit-sandbox', 180); print(result['sandbox_mode']); print(result.get('stdout_tail', '')); print(result.get('stderr_tail', '')); raise SystemExit(result['returncode'])"

# Pruebas unitarias (nivel código)

unit: venv
	@echo ">> Ejecutando pruebas unitarias con pytest"
	$(PY) -m pytest -q

unit-sandbox:
	@echo ">> Ejecutando pruebas unitarias dentro del sandbox Docker sin crear venv"
	python -m pytest -q

lint: venv
	@echo ">> Ejecutando lint con ruff"
	$(PY) -m ruff check src tests

type-check: venv
	@echo ">> Ejecutando type-check con mypy"
	$(PY) -m mypy --ignore-missing-imports src

coverage: venv prepare-dirs
	@echo ">> Ejecutando cobertura con coverage.py"
	$(PY) -m coverage run -m pytest -q
	$(PY) -m coverage xml -o artifacts/coverage.xml
	$(PY) -m coverage report

integration-tests: venv
	@echo ">> Ejecutando pruebas de integración livianas"
	$(PY) -m pytest -q tests/test_health.py tests/test_mcp_auditor.py

package-build: venv
	@echo ">> Construyendo paquete Python distribuible"
	$(PY) -m build

# SAST: Análisis estático de seguridad (código fuente)

sast: prepare-dirs
	@echo ">> SAST: ejecutando bandit y semgrep sobre el código fuente"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); bandit -r src -f json -o artifacts/bandit.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool bandit --exit-code $$rc --artifact artifacts/bandit.json --output .evidence/bandit-exit.json --command "bandit -r src -f json -o artifacts/bandit.json" --started-at $$START; exit 0
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); semgrep --config .semgrep.yml --error --json --output artifacts/semgrep.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool semgrep --exit-code $$rc --artifact artifacts/semgrep.json --output .evidence/semgrep-exit.json --command "semgrep --config .semgrep.yml --error --json --output artifacts/semgrep.json" --started-at $$START; exit 0

# SCA: Análisis de dependencias (Software Composition Analysis)

sca: prepare-dirs
	@echo ">> SCA: auditando dependencias runtime/dev/mcp con pip-audit"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); pip-audit -r requirements.txt -f json -o artifacts/pip-audit-runtime.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool pip-audit-runtime --exit-code $$rc --artifact artifacts/pip-audit-runtime.json --output .evidence/pip-audit-runtime-exit.json --command "pip-audit -r requirements.txt" --started-at $$START; exit 0
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); pip-audit -r requirements-dev.txt -f json -o artifacts/pip-audit-dev.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool pip-audit-dev --exit-code $$rc --artifact artifacts/pip-audit-dev.json --output .evidence/pip-audit-dev-exit.json --command "pip-audit -r requirements-dev.txt" --started-at $$START; exit 0
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); pip-audit -r requirements-mcp.txt -f json -o artifacts/pip-audit-mcp.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool pip-audit-mcp --exit-code $$rc --artifact artifacts/pip-audit-mcp.json --output .evidence/pip-audit-mcp-exit.json --command "pip-audit -r requirements-mcp.txt" --started-at $$START; exit 0

secret-scan: prepare-dirs
	@echo ">> Secret scanning con gitleaks"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); gitleaks detect --source . --no-git --report-format sarif --report-path artifacts/gitleaks.sarif; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool gitleaks --exit-code $$rc --artifact artifacts/gitleaks.sarif --output .evidence/gitleaks-exit.json --command "gitleaks detect --source . --no-git" --started-at $$START; exit 0

# SBOM: Bill of Materials del proyecto y de la imagen

sbom: prepare-dirs
	@echo ">> Generando SBOM del proyecto (directorio) con syft"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); syft packages dir:. -o json > artifacts/sbom-project.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool syft-project --exit-code $$rc --artifact artifacts/sbom-project.json --output .evidence/syft-project-exit.json --command "syft packages dir:. -o json" --started-at $$START; exit 0
	@echo ">> Generando SBOM de la imagen Docker con syft"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); syft $(IMAGE) -o json > artifacts/sbom-image.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool syft-image --exit-code $$rc --artifact artifacts/sbom-image.json --output .evidence/syft-image-exit.json --command "syft $(IMAGE) -o json" --started-at $$START; exit 0


# Escaneo de vulnerabilidades de la imagen (container scanning)

scan-image: prepare-dirs
	@echo ">> Analizando vulnerabilidades de la imagen con grype (salida SARIF)"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); grype $(IMAGE) -o sarif > artifacts/grype-image.sarif; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool grype --exit-code $$rc --artifact artifacts/grype-image.sarif --output .evidence/grype-exit.json --command "grype $(IMAGE) -o sarif" --started-at $$START; exit 0
	@echo ">> Escaneo de imagen con trivy (salida SARIF)"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); trivy image --format sarif --output artifacts/trivy-image.sarif $(IMAGE); rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool trivy --exit-code $$rc --artifact artifacts/trivy-image.sarif --output .evidence/trivy-exit.json --command "trivy image --format sarif --output artifacts/trivy-image.sarif $(IMAGE)" --started-at $$START; exit 0

openssf-scorecard: prepare-dirs
	@echo ">> OpenSSF Scorecard local si el CLI está disponible"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); scorecard --repo="$(SCORECARD_REPO)" --format=json --show-details > artifacts/scorecard.json; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool openssf-scorecard --exit-code $$rc --artifact artifacts/scorecard.json --output .evidence/scorecard-exit.json --command "scorecard --repo=$(SCORECARD_REPO) --format=json --show-details" --started-at $$START; exit 0
# Docker Compose: levantar y bajar el servicio para pruebas locales

compose-up: prepare-dirs
	@echo ">> Levantando servicios con docker compose y construyendo imagen si es necesario"
	docker compose up -d --build
	@sleep 2
	@echo ">> Verificando endpoint /health de la aplicación en modo compose"
	curl -sf http://127.0.0.1:8000/health | tee .evidence/compose-health.json

compose-down:
	@echo ">> Deteniendo servicios de docker compose y eliminando volúmenes"
	docker compose down -v

# DAST: Pruebas dinámicas con OWASP ZAP (desde contenedor)

dast: prepare-dirs
	@echo ">> DAST: ejecutando OWASP ZAP baseline contra http://127.0.0.1:8000"
	@set +e; START=$$(date -u +%Y-%m-%dT%H:%M:%SZ); docker run --rm -t --network host -v "$(CURDIR)/artifacts:/zap/wrk:rw" $(ZAP_IMAGE) zap-baseline.py -t http://127.0.0.1:8000 -J zap-baseline.json -r zap-report.html; rc=$$?; $(PY) -m devsecops_agent.tool_evidence --root . --tool zap --exit-code $$rc --artifact artifacts/zap-baseline.json --output .evidence/zap-exit.json --command "zap-baseline.py -t http://127.0.0.1:8000" --started-at $$START; exit 0

# Kubernetes local con kind

kind-up:
	@echo ">> Creando clúster kind 'devsecops' con configuración k8s/kind-config.yaml (si no existe)"
	kind create cluster --name devsecops --config k8s/kind-config.yaml || true

kind-load:
	@echo ">> Cargando la imagen local $(IMAGE) dentro del clúster kind 'devsecops'"
	kind load docker-image $(IMAGE) --name devsecops

# Despliegue en Kubernetes (manifiesto k8s/deployment.yaml)

k8s-deploy: prepare-dirs
	@echo ">> Aplicando manifiestos Kubernetes desde k8s/deployment.yaml"
	kubectl apply -f k8s/deployment.yaml
	@echo ">> Esperando a que termine el rollout del deployment $(SERVICE)"
	kubectl rollout status deploy/$(SERVICE) --timeout=90s
	@echo ">> Listando pods (se guarda en .evidence/pods.txt)"
	kubectl get pods -o wide | tee .evidence/pods.txt

# Port-forward del servicio de Kubernetes hacia localhost

k8s-portforward:
	@echo ">> Redirigiendo el servicio $(SERVICE) al puerto localhost:30080 -> 8000 del contenedor"
	- pkill -f "kubectl port-forward service/$(SERVICE) 30080:8000" || true
	kubectl port-forward service/$(SERVICE) 30080:8000 >/dev/null 2>&1 &
	@sleep 2


# Prueba de humo contra el servicio expuesto por Kubernetes

smoke: prepare-dirs
	@echo ">> Ejecutando prueba de humo contra /health en Kubernetes (localhost:30080)"
	curl -sf http://127.0.0.1:30080/health | tee .evidence/k8s-health.json


# Limpieza de recursos en Kubernetes y kind

k8s-destroy:
	@echo ">> Eliminando recursos Kubernetes definidos en k8s/deployment.yaml"
	kubectl delete -f k8s/deployment.yaml || true

kind-down:
	@echo ">> Eliminando clúster kind 'devsecops'"
	kind delete cluster --name devsecops || true

# in-toto: generar una atestación/procedencia simple (solo local)

attest: prepare-dirs
	@echo ">> Creando una atestación de tipo in-toto (provenance local, sin claves reales)"
	in-toto-run --step-name "build" --products artifacts --key /dev/null --record-streams --local-run --signing-key-fob-data foo || true


# Evidencia local mínima sin herramientas externas pesadas.
# Nota: los reportes fallback permiten demo local, pero el policy gate los marca como WARN.

local-evidence: prepare-dirs
	@echo ">> Generando evidencia local mínima reproducible"
	$(PY) -m devsecops_agent.local_evidence --root .

# Empaquetar evidencias del pipeline (logs, reportes, SBOM, policy y evaluación)
# No depende de policy-check: el evidence pack debe generarse también cuando el gate falla.

evidence-pack: prepare-dirs
	@echo ">> Empaquetando evidencias con manifest de integridad"
	$(PY) -m devsecops_agent.evidence_pack --root . create

evidence-verify:
	@echo ">> Verificando evidence pack contra manifest sidecar"
	@PACK=$$(ls -t artifacts/evidence-pack-*.tar.gz 2>/dev/null | head -n 1); \
	if [ -z "$$PACK" ]; then echo "No existe artifacts/evidence-pack-*.tar.gz"; exit 2; fi; \
	$(PY) -m devsecops_agent.evidence_pack --root . verify "$$PACK" --manifest artifacts/evidence-manifest.json


# Pipeline completo: desde build hasta evidencias (devsecops local-first)

pipeline: release-verify

# Benchmark adversarial realista: incluye casos ambiguos y de evasión controlada.
benchmark: prepare-dirs
	@echo ">> Ejecutando benchmark adversarial realista"
	$(PY) -m devsecops_agent.evaluation_harness --root . --output artifacts/benchmark-report.json

# Perfil 1: demo local reproducible sin herramientas externas pesadas. Puede quedar en WARN.
demo-local: unit skills-validate skill-scan mcp-audit agent-eval local-evidence
	@$(MAKE) POLICY_MODE=demo policy-check
	@$(MAKE) POLICY_MODE=demo evidence-pack dashboard product-status
	@echo ">> demo-local completado: WARN es aceptable si hay evidencia fallback"

# Alias retrocompatible del perfil demo.
security-local: demo-local

# Perfil 2: CI de seguridad con scanners reales. No acepta fallback en scanners principales.
security-ci: lint type-check coverage integration-tests package-build build skills-validate skill-scan mcp-audit agent-eval benchmark sast sca secret-scan sbom scan-image openssf-scorecard compose-up dast compose-down
	@$(MAKE) POLICY_MODE=ci policy-check
	@$(MAKE) POLICY_MODE=ci evidence-pack dashboard product-status

# Perfil 3: verificación estricta de release. No acepta evidencia fallback ni evidencia faltante.
release-verify: lint type-check coverage integration-tests package-build build skills-validate skill-scan mcp-audit agent-eval benchmark sast sca secret-scan sbom scan-image openssf-scorecard compose-up dast compose-down
	@$(MAKE) POLICY_MODE=strict policy-check
	@$(MAKE) POLICY_MODE=strict evidence-pack evidence-verify dashboard product-status


# MCP + skills: instalar dependencias opcionales del agente
mcp-install:
	@echo ">> Instalando dependencias opcionales MCP"
	$(PIP) install -r requirements-mcp.txt

# MCP + skills: verificar que los skills existan
skills-validate:
	@echo ">> Validando skills"
	@test -f skills/devsecops-triage/SKILL.md
	@test -f skills/reproducible-research-report/SKILL.md
	@test -f skills/supply-chain-attestation/SKILL.md
	@echo ">> Skills OK"

# MCP + skills: auditar estructura, comandos y riesgos de supply chain en SKILL.md
skill-scan: prepare-dirs
	@echo ">> Auditando skills con Skill Scanner"
	$(PY) -m devsecops_agent.skill_scanner --root . --output artifacts/skill-scan-report.json --fail-on-high

# MCP + skills: auditar superficie de tools/resources/prompts
mcp-audit: prepare-dirs
	@echo ">> Auditando servidor MCP"
	$(PY) -m devsecops_agent.mcp_auditor --root . --output artifacts/mcp-audit-report.json --fail-on-high

# MCP + skills: ejecutar casos adversariales controlados
agent-eval: prepare-dirs
	@echo ">> Ejecutando evaluación adversarial controlada"
	$(PY) -m devsecops_agent.evaluation_harness --root . --output artifacts/agent-eval-report.json --fail-on-fail

# MCP + skills: generar reporte de policy sin cortar el flujo.
# Este target SIEMPRE intenta escribir artifacts/policy-report.json.
policy-report: prepare-dirs
	@echo ">> Generando reporte de policy gate en modo $(POLICY_MODE)"
	$(PY) -m devsecops_agent.policy_engine --root . --mode $(POLICY_MODE) --output artifacts/policy-report.json --no-fail-on-fail

# MCP + skills: aplicar gate de políticas sobre reportes y evidencias.
# Este target falla si el reporte final queda en FAIL.
policy-check: policy-report
	@echo ">> Evaluando resultado del policy gate en modo $(POLICY_MODE)"
	$(PY) -m devsecops_agent.cli --root . policy-check --mode $(POLICY_MODE) --json


# Producto final: estado agregado legible para demo
product-status: prepare-dirs
	@echo ">> Mostrando estado de producto SkillChain-MCP Guard"
	$(PY) -m devsecops_agent.cli --root . status

# Producto final: escaneo liviano + dashboard sin depender de Docker/Kubernetes
product-scan: prepare-dirs
	@echo ">> Ejecutando flujo liviano de producto"
	$(PY) -m devsecops_agent.cli --root . scan --json

# Producto final: dashboard HTML autocontenido
dashboard: prepare-dirs
	@echo ">> Generando dashboard HTML de producto"
	$(PY) -m devsecops_agent.cli --root . dashboard --json

# Producto final: demo local completa y rápida
product-demo: unit skills-validate product-scan
	@echo ">> Demo de producto lista: abre artifacts/dashboard.html"

# MCP + skills: ejecutar servidor MCP local por stdio
mcp-server:
	@echo ">> Iniciando servidor MCP SkillChain-MCP Guard"
	DEVSECOPS_REPO_ROOT=$(CURDIR) $(PY) -m devsecops_agent.mcp_server

# MCP + agente: ejecutar demostración local por stdio
mcp-demo: mcp-install security-local
	@echo ">> Ejecutando demo MCP con agente local"
	$(PY) scripts/mcp_demo_agent_full.py --mode quick --max-chars 1200

.PHONY: prepare-dirs ensure-tools venv build package-build sandbox-image unit lint type-check coverage integration-tests sast sca secret-scan sbom scan-image openssf-scorecard compose-up compose-down dast kind-up kind-load k8s-deploy k8s-portforward smoke k8s-destroy kind-down attest evidence-pack evidence-verify pipeline demo-local security-ci release-verify mcp-install skills-validate skill-scan mcp-audit agent-eval benchmark policy-report policy-check product-status product-scan dashboard local-evidence security-local product-demo mcp-server mcp-demo
