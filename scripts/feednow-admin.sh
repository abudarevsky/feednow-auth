#!/usr/bin/env bash
# Operator convenience wrapper: local Docker by default; AWS only when an
# explicit named profile is supplied.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_PROFILE_NAME=""

usage() {
  cat <<'EOF'
Usage:
  scripts/feednow-admin.sh [--profile AWS_PROFILE] grant --email ADDRESS
  scripts/feednow-admin.sh [--profile AWS_PROFILE] revoke --email ADDRESS
  scripts/feednow-admin.sh [--profile AWS_PROFILE] list

Without --profile, commands run in the local Cognito Docker composition.
With --profile, commands use AWS DynamoDB with that named AWS CLI profile.
AWS mode also requires FEEDNOW_DYNAMODB_REGION and FEEDNOW_TABLE_PREFIX.
EOF
}

while (($#)); do
  case "$1" in
    --profile)
      if (($# < 2)) || [[ -z "$2" ]]; then
        echo "error: --profile requires an AWS profile name" >&2
        exit 2
      fi
      AWS_PROFILE_NAME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

if (($# == 0)); then
  usage >&2
  exit 2
fi

if [[ -n "$AWS_PROFILE_NAME" ]]; then
  if [[ -z "${FEEDNOW_DYNAMODB_REGION:-}" || ! ${FEEDNOW_TABLE_PREFIX+x} ]]; then
    echo "error: AWS mode requires FEEDNOW_DYNAMODB_REGION and FEEDNOW_TABLE_PREFIX" >&2
    exit 2
  fi
  if [[ -n "${FEEDNOW_DYNAMODB_ENDPOINT:-}" ]]; then
    echo "error: refusing AWS mode while FEEDNOW_DYNAMODB_ENDPOINT is set" >&2
    exit 2
  fi
  export AWS_PROFILE="$AWS_PROFILE_NAME"
  export FEEDNOW_STORAGE_BACKEND=dynamodb
  cd "$ROOT"
  exec uv run -- python -m feednow_auth.admin "$@"
fi

# Rebuild/recreate so the running container has the current CLI implementation
# (notably newer subcommands such as `list`) before delegating to it. Named
# SQLite volume is preserved across container replacement.
cd "$ROOT/deploy/docker"
# docker compose --profile cognito up -d --build app
exec docker compose --profile cognito exec \
  -e FEEDNOW_STORAGE_BACKEND=sqlite \
  -e FEEDNOW_SQLITE_PATH=/data/feednow-auth.db \
  app python -m feednow_auth.admin "$@"
