#!/usr/bin/env bash
set -Eeuo pipefail

MODE="check"
REMOTE="origin"
EXPECTED_BRANCH="fix/github-actions-first-run"
SCORECARD_REPO="https://github.com/kapumota/MCP-DevSecOps-Guard"
COMMIT_MESSAGE="fix(ci): normalizar riesgo upstream y completar evidencias"

usage() {
    cat <<'EOF'
Uso:
  bash scripts/advance_ci_green.sh --check
  bash scripts/advance_ci_green.sh --full
  bash scripts/advance_ci_green.sh --commit
  bash scripts/advance_ci_green.sh --push

Modos:
  --check   Ejecuta lint, mypy y pytest.
  --full    Ejecuta check y security-ci completo, sin commit ni push.
  --commit  Ejecuta check y crea un commit con archivos permitidos.
  --push    Ejecuta check, commit, security-ci, verificación y git push.

No usa gh, no usa force push y no modifica main.
EOF
}

log() {
    printf '\n### %s\n' "$*"
}

die() {
    printf '\nERROR: %s\n' "$*" >&2
    exit 1
}

cleanup_python_cache() {
    log "Limpiando cachés Python locales"

    find . \
        -type d \
        -name __pycache__ \
        -prune \
        -exec rm -rf {} + 2>/dev/null || true

    rm -rf \
        .pytest_cache \
        .mypy_cache \
        .ruff_cache \
        .coverage \
        htmlcov
}

on_error() {
    local rc=$?
    local line=${BASH_LINENO[0]:-desconocida}

    printf '\nFALLO: línea %s, código %s\n' "$line" "$rc" >&2
    printf 'Estado actual:\n' >&2
    git status --short >&2 || true
    exit "$rc"
}

trap on_error ERR

while (($#)); do
    case "$1" in
        --check)
            MODE="check"
            ;;
        --full)
            MODE="full"
            ;;
        --commit)
            MODE="commit"
            ;;
        --push)
            MODE="push"
            ;;
        --remote)
            shift
            REMOTE="${1:?Falta el nombre del remoto}"
            ;;
        --branch)
            shift
            EXPECTED_BRANCH="${1:?Falta el nombre de la rama}"
            ;;
        --scorecard-repo)
            shift
            SCORECARD_REPO="${1:?Falta el repositorio de Scorecard}"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Argumento desconocido: $1"
            ;;
    esac

    shift
done

export PYTHONDONTWRITEBYTECODE=1

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || die "Ejecuta el script dentro del repositorio Git"

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

BRANCH="$(git branch --show-current)"

[[ "$BRANCH" == "$EXPECTED_BRANCH" ]] \
    || die "Rama actual: $BRANCH; esperada: $EXPECTED_BRANCH"

required_files=(
    Makefile
    docker/Dockerfile
    scripts/normalize_image_vulnerabilities.py
    src/devsecops_agent/image_vulnerability_policy.py
    src/devsecops_agent/policy_engine.py
    tests/test_policy_engine.py
)

for file in "${required_files[@]}"; do
    [[ -f "$file" ]] || die "Falta el archivo requerido: $file"
done

cleanup_python_cache

log "Validando que el parche no dejó errores de whitespace"
git diff --check

log "Ejecutando Ruff"
make lint

log "Ejecutando mypy"
make type-check

log "Ejecutando pruebas del motor de políticas"
.skillchain/bin/python -m pytest -q tests/test_policy_engine.py

log "Ejecutando todas las pruebas"
.skillchain/bin/python -m pytest -q

log "Ejecutando Ruff sobre código y normalizador"
.skillchain/bin/python -m ruff check \
    src \
    tests \
    scripts/normalize_image_vulnerabilities.py

log "Validando sintaxis del runner"
bash -n scripts/advance_ci_green.sh

log "Ejecutando mypy directo"
.skillchain/bin/python -m mypy --ignore-missing-imports src

if [[ "$MODE" == "check" ]]; then
    cleanup_python_cache
    log "Validación rápida completada"
    exit 0
fi

stage_allowed_files() {
    local allowed=(
        .github/workflows/ci-devsecops.yml
        Makefile
        docker/Dockerfile
        requirements-dev.txt
        scripts/normalize_image_vulnerabilities.py
        scripts/advance_ci_green.sh
        src/devsecops_agent/image_vulnerability_policy.py
        src/devsecops_agent/policy_engine.py
        tests/test_policy_engine.py
    )

    local file

    for file in "${allowed[@]}"; do
        if [[ -e "$file" ]] && {
            ! git diff --quiet -- "$file" \
            || ! git diff --cached --quiet -- "$file" \
            || ! git ls-files --error-unmatch "$file" >/dev/null 2>&1
        }; then
            git add -- "$file"
        fi
    done
}

create_commit() {
    log "Preparando archivos fuente permitidos"
    stage_allowed_files

    git diff --cached --check
    git diff --cached --stat

    if git diff --cached --quiet; then
        log "No hay cambios nuevos para confirmar"
        return
    fi

    git commit -m "$COMMIT_MESSAGE"
}

if [[ "$MODE" == "commit" || "$MODE" == "push" ]]; then
    create_commit
fi

if [[ "$MODE" == "commit" ]]; then
    cleanup_python_cache
    log "Commit local completado"
    exit 0
fi

log "Preparando corrida limpia"
docker compose down --remove-orphans --volumes >/dev/null 2>&1 || true

rm -rf artifacts .evidence
mkdir -p artifacts .evidence
touch artifacts/.gitkeep .evidence/.gitkeep

export SKILLCHAIN_RUN_ID="local-$(date -u +%Y%m%dT%H%M%SZ)-final"
export SKILLCHAIN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export SKILLCHAIN_GIT_COMMIT="$(git rev-parse HEAD)"

if [[ -z "${GITHUB_AUTH_TOKEN:-}" ]]; then
    read -rsp "GITHUB_AUTH_TOKEN para Scorecard: " GITHUB_AUTH_TOKEN
    printf '\n'
    export GITHUB_AUTH_TOKEN
fi

log "Ejecutando security-ci con scanners reales"
set +e
set -o pipefail

make security-ci \
    SCORECARD_REPO="$SCORECARD_REPO" \
    2>&1 | tee artifacts/security-ci-local.log

security_rc=${PIPESTATUS[0]}
set +o pipefail
set -e

printf 'Código final de security-ci: %s\n' "$security_rc"

[[ "$security_rc" -eq 0 ]] \
    || die "security-ci terminó con código $security_rc"

log "Validando policy-report.json"
.skillchain/bin/python - <<'PY'
import json
from pathlib import Path

path = Path("artifacts/policy-report.json")

if not path.is_file():
    raise SystemExit("Falta artifacts/policy-report.json")

report = json.loads(path.read_text(encoding="utf-8"))
decision = report.get("decision", {})
image_policy = report.get("image_vulnerability_policy", {})
image_summary = image_policy.get("summary", {})

status = str(report.get("status", ""))
blocking = int(report.get("blocking_issues", -1))
completeness = float(
    report.get("evidence_completeness_score", 0.0)
)
allow_merge = bool(decision.get("allow_merge", False))
actionable = int(image_summary.get("actionable", -1))
review_required = int(
    image_summary.get("review_required", -1)
)

print("status:", status)
print("blocking_issues:", blocking)
print("evidence_completeness_score:", completeness)
print("allow_merge:", allow_merge)
print("image actionable:", actionable)
print("image review_required:", review_required)

if status not in {"PASS", "WARN"}:
    raise SystemExit(f"Estado de política no permitido: {status}")

if blocking != 0:
    raise SystemExit(f"Persisten bloqueos: {blocking}")

if completeness != 1.0:
    missing = report.get("evidence_completeness", {}).get(
        "missing",
        [],
    )
    raise SystemExit(
        f"Completitud {completeness}; faltantes: {missing}"
    )

if not allow_merge:
    raise SystemExit("decision.allow_merge es false")

if actionable != 0:
    raise SystemExit(
        f"Persisten vulnerabilidades accionables: {actionable}"
    )
PY

log "Verificando evidence pack"
make evidence-verify

log "Comprobando un único run_id"
.skillchain/bin/python - <<'PY'
import json
from collections import Counter
from pathlib import Path

counts: Counter[str] = Counter()

for path in sorted(Path(".evidence").glob("*-exit.json")):
    payload = json.loads(path.read_text(encoding="utf-8"))
    counts[str(payload.get("run_id", "sin-run-id"))] += 1

print(dict(counts))

if not counts:
    raise SystemExit("No se encontraron evidencias operacionales")

if len(counts) != 1:
    raise SystemExit(f"Se encontraron múltiples run_id: {dict(counts)}")
PY

cleanup_python_cache

if [[ "$MODE" == "full" ]]; then
    unset GITHUB_AUTH_TOKEN
    log "Corrida completa local terminada correctamente"
    exit 0
fi

log "Verificando que el remoto no tenga commits nuevos"
git fetch "$REMOTE" --prune

read -r remote_only local_only < <(
    git rev-list \
        --left-right \
        --count \
        "$REMOTE/$EXPECTED_BRANCH...HEAD"
)

printf 'Solo remoto: %s\n' "$remote_only"
printf 'Solo local:  %s\n' "$local_only"

[[ "$remote_only" -eq 0 ]] \
    || die "El remoto avanzó; revisa y rebasa antes del push"

log "Publicando la rama sin force"
git push -u "$REMOTE" "$EXPECTED_BRANCH"

local_sha="$(git rev-parse HEAD)"
remote_sha="$(
    git ls-remote "$REMOTE" \
        "refs/heads/$EXPECTED_BRANCH" \
        | awk '{print $1}'
)"

printf 'Local:  %s\n' "$local_sha"
printf 'Remoto: %s\n' "$remote_sha"

[[ "$local_sha" == "$remote_sha" ]] \
    || die "El SHA remoto no coincide con HEAD"

unset GITHUB_AUTH_TOKEN

log "Push verificado; GitHub Actions debe iniciar automáticamente"
