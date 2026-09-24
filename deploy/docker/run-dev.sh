#!/usr/bin/env bash
# run-dev.sh — Start feednow-auth dev environment in Docker
#
# Usage:
#   ./run-dev.sh --cognito    # Start full local SQLite + Cognito runtime
#   ./run-dev.sh --stop       # Stop and remove containers
#   ./run-dev.sh --logs       # Follow logs
#   ./run-dev.sh --reset      # Stop, remove volumes, and restart fresh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
ENV_FILE="${SCRIPT_DIR}/.env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Start feednow-auth development environment in Docker.

Options:
  --cognito     Enable Cognito authentication (requires .env with Cognito vars)
  --stop        Stop and remove containers
  --logs        Follow container logs
  --reset       Stop, remove volumes, and restart fresh
  --status      Show container status
  --help        Show this help

Environment:
  The script uses ${ENV_FILE} for configuration.
  Copy ${ENV_FILE}.example to ${ENV_FILE} and adjust values.

  Key variables:
    FEEDNOW_STORAGE_TYPE=sqlite|dynamodb
    FEEDNOW_SQLITE_PATH=/data/feednow-auth.db
    FEEDNOW_COGNITO_ISSUER=https://cognito-idp.<region>.amazonaws.com/<user-pool-id>
    FEEDNOW_COGNITO_CLIENT_ID=<client-id>
    FEEDNOW_COGNITO_DOMAIN=https://<prefix>.auth.<region>.amazoncognito.com
    FEEDNOW_PEPPER_SECRET=<base64-encoded-32-bytes>

Examples:
  $(basename "$0") --cognito          # Start with Cognito auth enabled
  $(basename "$0") --logs             # Follow logs
  $(basename "$0") --reset            # Fresh start and restart Cognito
EOF
}

check_env_file() {
    if [[ ! -f "${ENV_FILE}" ]]; then
        log_warn "No .env file found at ${ENV_FILE}"
        log_info "Creating from .env.example..."
        cp "${ENV_FILE}.example" "${ENV_FILE}"
        log_success "Created ${ENV_FILE} — edit it to configure Cognito if needed"
    fi
}

enable_cognito() {
    log_info "Enabling Cognito authentication..."
    # Check required Cognito vars
    local missing=()
    source "${ENV_FILE}" 2>/dev/null || true
    [[ -z "${FEEDNOW_COGNITO_ISSUER:-}" ]] && missing+=("FEEDNOW_COGNITO_ISSUER")
    [[ -z "${FEEDNOW_COGNITO_CLIENT_ID:-}" ]] && missing+=("FEEDNOW_COGNITO_CLIENT_ID")
    [[ -z "${FEEDNOW_PEPPER_SECRET:-}" ]] && missing+=("FEEDNOW_PEPPER_SECRET")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required Cognito variables in ${ENV_FILE}:"
        for var in "${missing[@]}"; do
            echo "  - ${var}"
        done
        log_info "Get these from your Cognito User Pool > App integration > App client"
        exit 1
    fi
    log_success "Cognito configuration found"
}

start_dev() {
    local with_cognito="${1:-false}"

    check_env_file

    if [[ "${with_cognito}" != "true" ]]; then
        log_error "The restored local composition is Cognito-only; run ./run-dev.sh --cognito"
        exit 2
    fi
    enable_cognito

    log_info "Building and starting containers..."
    local compose_args=(-f "${COMPOSE_FILE}" --profile cognito)
    docker compose "${compose_args[@]}" up --build -d

    log_info "Waiting for health check..."
    local retries=30
    while [[ ${retries} -gt 0 ]]; do
        if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
            log_success "Service is healthy at http://localhost:8000"
            break
        fi
        sleep 1
        ((retries--))
    done

    if [[ ${retries} -eq 0 ]]; then
        log_error "Service failed to become healthy"
        docker compose "${compose_args[@]}" logs app
        exit 1
    fi

    echo
    log_success "Development environment ready!"
    echo
    echo "  API:        http://localhost:8000"
    echo "  Health:     http://localhost:8000/health"
    echo "  OpenAPI:    http://localhost:8000/openapi.json"
    echo "  Docs:       http://localhost:8000/docs"
    echo
    echo "  Cognito:    ENABLED — use ./cognito-login.sh to authenticate"
    echo
    echo "  Logs:       ./run-dev.sh --logs"
    echo "  Stop:       ./run-dev.sh --stop"
    echo "  Reset:      ./run-dev.sh --reset"
}

stop_dev() {
    log_info "Stopping containers..."
    docker compose -f "${COMPOSE_FILE}" down
    log_success "Containers stopped"
}

reset_dev() {
    log_warn "This will delete the SQLite database volume!"
    read -rp "Continue? [y/N] " -n 1
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted"
        exit 0
    fi
    log_info "Stopping and removing volumes..."
    docker compose -f "${COMPOSE_FILE}" down -v
    log_success "Reset complete"
    start_dev "${1:-false}"
}

show_logs() {
    docker compose -f "${COMPOSE_FILE}" logs -f app
}

show_status() {
    docker compose -f "${COMPOSE_FILE}" ps
}

main() {
    case "${1:-}" in
        --cognito)
            start_dev true
            ;;
        --stop)
            stop_dev
            ;;
        --reset)
            reset_dev true
            ;;
        --logs)
            show_logs
            ;;
        --status)
            show_status
            ;;
        --help|-h)
            usage
            ;;
        "")
            usage
            exit 2
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
