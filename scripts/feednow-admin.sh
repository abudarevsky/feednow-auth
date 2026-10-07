#!/usr/bin/env bash
# Operator convenience wrapper: the running local Docker app by default; AWS
# only when both a standard AWS profile and FeedNow environment are explicit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_PROFILE_NAME=""
AWS_TARGET_ENV=""

usage() {
  cat <<'EOF'
Usage:
  scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] grant --email ADDRESS
  scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] revoke --email ADDRESS
  scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] list
  scripts/feednow-admin.sh --profile AWS_PROFILE --env dev|staging|prod demo create --name NAME [--slug SLUG]
  scripts/feednow-admin.sh --profile AWS_PROFILE --env dev|staging|prod demo delete --org SLUG
  scripts/feednow-admin.sh --profile AWS_PROFILE --env dev|staging|prod demo reset-password --org SLUG
  scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] demo list

Without --profile, commands run in the local Cognito Docker composition.
AWS mode requires both --profile and --env. --env selects
deploy/aws/cdk/.env.<environment>; --profile is passed to standard AWS
credential resolution. The target account is verified before the operation.
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
    --env)
      if (($# < 2)) || [[ -z "$2" ]]; then
        echo "error: --env requires dev, staging, or prod" >&2
        exit 2
      fi
      AWS_TARGET_ENV="$2"
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

if [[ -z "$AWS_PROFILE_NAME" && -n "$AWS_TARGET_ENV" ]]; then
  echo "error: --env is only valid with --profile" >&2
  exit 2
fi

if [[ -n "$AWS_PROFILE_NAME" ]]; then
  if [[ -z "$AWS_TARGET_ENV" || ! "$AWS_TARGET_ENV" =~ ^(dev|staging|prod)$ ]]; then
    echo "error: --env must be dev, staging, or prod" >&2
    exit 2
  fi
  if [[ -n "${FEEDNOW_DYNAMODB_ENDPOINT:-}" ]]; then
    echo "error: refusing AWS mode while FEEDNOW_DYNAMODB_ENDPOINT is set" >&2
    exit 2
  fi

  # shellcheck source=../deploy/aws/env.sh
  source "$ROOT/deploy/aws/env.sh"
  feednow_load_env "$ROOT" "$AWS_TARGET_ENV"
  actual_account="$(feednow_verify_identity "$AWS_PROFILE_NAME" "$AWS_ACCOUNT_ID" "$AWS_REGION")"
  feednow_show_target "$AWS_TARGET_ENV" "$AWS_PROFILE_NAME" "$actual_account" "$AWS_REGION"
  expected_prefix="feednow-auth-${AWS_TARGET_ENV}-"
  export AWS_PROFILE="$AWS_PROFILE_NAME"
  export AWS_REGION
  export FEEDNOW_DYNAMODB_REGION="$AWS_REGION"
  export FEEDNOW_TABLE_PREFIX="$expected_prefix"
  export FEEDNOW_STORAGE_BACKEND=dynamodb
  cd "$ROOT"
  exec uv run -- python -m feednow_auth.admin "$@"
fi

if [[ "${1:-}" == "demo" && "${2:-}" != "list" ]]; then
  echo "error: demo create/delete/reset-password require --profile and --env to manage the configured Cognito User Pool" >&2
  exit 2
fi

# Use the app container's configured storage backend and credentials. This
# keeps local administrator changes in the same store the API reads, whether
# the app is configured for SQLite or DynamoDB Local.
cd "$ROOT/deploy/docker"
exec docker compose --profile cognito exec app python -m feednow_auth.admin "$@"
