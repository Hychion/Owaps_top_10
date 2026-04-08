#!/usr/bin/env bash
# ============================================================
# setup-lab.sh — Bootstrap the OWASP Tester lab environment
# Usage: ./scripts/setup-lab.sh [--test-only] [--clean]
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

TEST_ONLY=false
CLEAN=false

for arg in "$@"; do
    case $arg in
        --test-only) TEST_ONLY=true ;;
        --clean)     CLEAN=true ;;
        --help|-h)
            echo "Usage: $0 [--test-only] [--clean]"
            echo "  --test-only  Build test images only (no dev compose up)"
            echo "  --clean      Remove existing containers and images first"
            exit 0 ;;
    esac
done

# ── Prerequisites ─────────────────────────────────────────────────────────────

info "Checking prerequisites..."

command -v docker  >/dev/null 2>&1 || error "docker not found. Install Docker first."
command -v cargo   >/dev/null 2>&1 || error "cargo not found. Install Rust first."

docker info >/dev/null 2>&1 || error "Docker daemon is not running."

DOCKER_COMPOSE_CMD=""
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
else
    error "docker compose (v2) or docker-compose not found."
fi

info "All prerequisites satisfied."

# ── Optional clean ────────────────────────────────────────────────────────────

if $CLEAN; then
    warn "Cleaning existing lab containers and images..."
    $DOCKER_COMPOSE_CMD down --rmi local -v 2>/dev/null || true
    docker rmi owasp-lab-info:test owasp-lab-inpval:test \
               owasp-lab-sess:test owasp-lab-sqli:test \
               owasp-lab-authn:test 2>/dev/null || true
    info "Clean done."
fi

# ── Build lab images ──────────────────────────────────────────────────────────

info "Building lab Docker images..."

LABS=(
    "owasp-lab-info:test:docker/lab-info"
    "owasp-lab-inpval:test:docker/lab-inpval"
    "owasp-lab-sess:test:docker/lab-sess"
    "owasp-lab-sqli:test:docker/lab-sqli"
    "owasp-lab-authn:test:docker/lab-authn"
)

for entry in "${LABS[@]}"; do
    IFS=':' read -r name tag context <<< "${entry//:test:/:test }"
    tag_full="${name}:${tag}"
    # Fix: split properly
    parts=(${entry//:/ })
    tag_full="${parts[0]}:${parts[1]}"
    context="${parts[2]}"

    info "  Building ${tag_full} from ${context}..."
    docker build -t "${tag_full}" "${context}" --quiet
done

info "All lab images built successfully."

# ── Start environment ─────────────────────────────────────────────────────────

if ! $TEST_ONLY; then
    info "Starting dev lab environment..."
    $DOCKER_COMPOSE_CMD up -d

    info "Waiting for health checks..."
    MAX_WAIT=60
    ELAPSED=0
    while true; do
        ALL_HEALTHY=true
        for cname in owasp-lab-info owasp-lab-inpval owasp-lab-sess owasp-lab-sqli owasp-lab-authn; do
            STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$cname" 2>/dev/null || echo "missing")
            if [[ "$STATUS" != "healthy" ]]; then
                ALL_HEALTHY=false
                break
            fi
        done

        if $ALL_HEALTHY; then
            break
        fi

        if [[ $ELAPSED -ge $MAX_WAIT ]]; then
            error "Containers did not become healthy within ${MAX_WAIT}s. Check: docker ps"
        fi

        sleep 3
        ELAPSED=$((ELAPSED + 3))
        echo -n "."
    done
    echo ""

    info "Lab environment is ready!"
    echo ""
    echo "  OTG-INFO-001   → http://localhost:8081"
    echo "  OTG-INPVAL-001 → http://localhost:8082"
    echo "  OTG-SESS-001   → http://localhost:8083"
    echo "  OTG-INPVAL-005 → http://localhost:8084  (SQLi)"
    echo "  OTG-AUTHN-001  → http://localhost:8085"
    echo ""
    echo "  Run scans:  make scan-all"
    echo "  Run tests:  make test"
    echo "  Int. tests: make test-integration"
    echo "  Stop labs:  make lab-down"
fi
