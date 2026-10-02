#!/usr/bin/env bash
# run-dev.sh — Start feednow-auth dev environment in Docker
#
# Usage:
#   ./run-dev.sh --cognito          # Start backend; run UI from a terminal
#   ./run-dev.sh --cognito --ui     # Start backend and UI in Docker
#   ./run-dev.sh --ui               # Alias for --cognito --ui
#   ./run-dev.sh --dynamodb-local   # Start app against persistent DynamoDB Local
#   ./run-dev.sh --dynamodb-local --ui # Also start the account UI
#   ./run-dev.sh --stop       # Stop and remove containers
#   ./run-dev.sh --logs       # Follow logs
#   ./run-dev.sh --reset      # Stop, remove volumes, and restart fresh
#   ./run-dev.sh --ensure-google-trigger # Check/attach Google trigger on dev pool

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
  --ui           Also build and start the account UI in Docker on port 3000
  --dynamodb-local
                Use DynamoDB Local for app storage instead of SQLite
  --stop        Stop and remove containers
  --logs        Follow container logs
  --reset       Stop, remove volumes, and restart fresh
  --status      Show container status
  --ensure-google-trigger
                Check the configured Cognito dev pool and deploy its Google trigger if missing
  --help        Show this help

Environment:
  The script uses ${ENV_FILE} for configuration.
  Copy ${ENV_FILE}.example to ${ENV_FILE} and adjust values.

  Key variables:
    FEEDNOW_STORAGE_BACKEND=sqlite|dynamodb
    FEEDNOW_SQLITE_PATH=/data/feednow-auth.db
    FEEDNOW_COGNITO_ISSUER=https://cognito-idp.<region>.amazonaws.com/<user-pool-id>
    FEEDNOW_COGNITO_CLIENT_ID=<client-id>
    FEEDNOW_COGNITO_DOMAIN=https://<prefix>.auth.<region>.amazoncognito.com
    FEEDNOW_PEPPER_SECRET=<base64-encoded-32-bytes>

Examples:
  $(basename "$0") --cognito          # Start with Cognito auth enabled
  $(basename "$0") --cognito --ui     # Start backend and UI together in Docker
  $(basename "$0") --dynamodb-local   # Start backend with local DynamoDB storage
  $(basename "$0") --dynamodb-local --ui # Also start account UI
  $(basename "$0") --cognito          # Then run npm run dev in feednow-auth-ui
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
    [[ -z "${FEEDNOW_COGNITO_DOMAIN:-}" ]] && missing+=("FEEDNOW_COGNITO_DOMAIN")
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
    local with_ui="${2:-false}"
    local with_dynamodb_local="${3:-false}"

    check_env_file

    if [[ "${with_cognito}" != "true" ]]; then
        log_error "The restored local composition is Cognito-only; run ./run-dev.sh --cognito"
        exit 2
    fi
    enable_cognito

    log_info "Building and starting containers..."
    local compose_args=(-f "${COMPOSE_FILE}")
    if [[ "${with_dynamodb_local}" == "true" ]]; then
        compose_args+=(-f "${SCRIPT_DIR}/docker-compose.dynamodb-local.yml")
    fi
    compose_args+=(--profile cognito)
    if [[ "${with_ui}" == "true" ]]; then
        compose_args+=(--profile ui)
    fi
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
    echo "  Cognito:    ENABLED — open the account UI and use Managed Login"
    if [[ "${with_dynamodb_local}" == "true" ]]; then
        echo "  Storage:    DynamoDB Local (persistent Docker volume)"
    else
        echo "  Storage:    SQLite (persistent Docker volume)"
    fi
    if [[ "${with_ui}" == "true" ]]; then
        echo "  UI:         http://localhost:3000 (Vite proxy uses Docker service app:8000)"
    else
        echo "  UI:         run from terminal: cd ../../../feednow-auth-ui && npm run dev"
        echo "              Vite proxies /api to http://127.0.0.1:8000 by default"
    fi
    echo
    echo "  Logs:       ./run-dev.sh --logs"
    echo "  Stop:       ./run-dev.sh --stop"
    echo "  Reset:      ./run-dev.sh --reset"
}

stop_dev() {
    log_info "Stopping containers..."
    docker compose -f "${COMPOSE_FILE}" -f "${SCRIPT_DIR}/docker-compose.dynamodb-local.yml" down
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
    docker compose -f "${COMPOSE_FILE}" -f "${SCRIPT_DIR}/docker-compose.dynamodb-local.yml" ps
}

ensure_google_trigger() {
    check_env_file
    command -v aws >/dev/null || { log_error "AWS CLI is required"; exit 1; }
    command -v cdk >/dev/null || { log_error "AWS CDK CLI is required"; exit 1; }
    command -v python3 >/dev/null || { log_error "python3 is required"; exit 1; }

    local issuer client_id pool_id region pool_name account trigger_name trigger_arn current
    issuer="$(sed -n 's/^FEEDNOW_COGNITO_ISSUER=//p' "${ENV_FILE}" | tail -n 1)"
    client_id="$(sed -n 's/^FEEDNOW_COGNITO_CLIENT_ID=//p' "${ENV_FILE}" | tail -n 1)"
    issuer="${issuer%$'\r'}"; issuer="${issuer#\"}"; issuer="${issuer%\"}"; issuer="${issuer#\'}"; issuer="${issuer%\'}"
    client_id="${client_id%$'\r'}"; client_id="${client_id#\"}"; client_id="${client_id%\"}"; client_id="${client_id#\'}"; client_id="${client_id%\'}"
    if [[ ! "${issuer}" =~ ^https://cognito-idp\.([a-z0-9-]+)\.amazonaws\.com/(.+)$ || -z "${client_id}" || "${client_id}" == replace-* ]]; then
        log_error "Set a real FEEDNOW_COGNITO_ISSUER and FEEDNOW_COGNITO_CLIENT_ID in ${ENV_FILE}"
        exit 1
    fi
    region="${BASH_REMATCH[1]}"
    pool_id="${BASH_REMATCH[2]}"
    if [[ "${pool_id}" != "${region}_"* || ! "${pool_id}" =~ ^[A-Za-z0-9_-]+$ ]]; then
        log_error "FEEDNOW_COGNITO_ISSUER must contain a valid pool ID for its region"
        exit 1
    fi
    pool_name="$(aws cognito-idp describe-user-pool --user-pool-id "${pool_id}" --region "${region}" --query 'UserPool.Name' --output text)"
    if [[ "${pool_name,,}" != *dev* ]]; then
        log_error "Refusing to deploy: configured pool is not clearly named as a dev pool"
        exit 1
    fi

    account="$(aws sts get-caller-identity --query Account --output text)"
    trigger_name="feednow-auth-${pool_id##*_}-google-trigger-v3"
    trigger_arn="arn:aws:lambda:${region}:${account}:function:${trigger_name}"
    current="$(aws cognito-idp describe-user-pool --user-pool-id "${pool_id}" --region "${region}" --query 'UserPool.LambdaConfig' --output json)"
    if ! python3 -c 'import json,sys; d=json.load(sys.stdin); expected=sys.argv[1]; print("safe" if all(not d.get(k) or d.get(k)==expected for k in ("PreSignUp","PreAuthentication")) else "conflict")' "${trigger_arn}" <<<"${current}" | grep -qx safe; then
        log_error "The dev pool already has a different PreSignUp or PreAuthentication trigger; resolve it before applying this overlay"
        exit 1
    fi
    if [[ "$(python3 -c 'import json,sys; d=json.load(sys.stdin); print("yes" if d.get("PreSignUp")==sys.argv[1] and d.get("PreAuthentication")==sys.argv[1] else "no")' "${trigger_arn}" <<<"${current}")" == yes ]] && aws lambda get-function --function-name "${trigger_name}" --region "${region}" >/dev/null 2>&1; then
        log_success "Google verification trigger is deployed and attached to ${pool_id}"
        return
    fi

    log_info "Google verification trigger is missing from the configured dev pool; deploying the CDK overlay..."
    (
        cd "${PROJECT_ROOT}/deploy/aws/cdk"
        export CDK_DEFAULT_ACCOUNT="${account}"
        export AWS_REGION="${region}"
        export GOOGLE_FIX_USER_POOL_ID="${pool_id}"
        export GOOGLE_FIX_CLIENT_ID="${client_id}"
        # Force the custom resource to reapply configuration when AWS drifted
        # after a previously successful stack deployment.
        export GOOGLE_FIX_IMPLEMENTATION_VERSION="google-email-proof-repair-$(date +%s)"
        cdk --app "python3 google_federation_fix.py" deploy FeedNowAuthGoogleFederationFix-dev --require-approval never
    )
    log_success "Google verification trigger deployment completed"
}

main() {
    case "${1:-}" in
        --cognito)
            if [[ "${2:-}" == "--ui" ]]; then
                start_dev true true
            else
                start_dev true false
            fi
            ;;
        --ui)
            start_dev true true
            ;;
        --dynamodb-local)
            if [[ "${2:-}" == "--ui" ]]; then
                start_dev true true true
            else
                start_dev true false true
            fi
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
        --ensure-google-trigger)
            ensure_google_trigger
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
