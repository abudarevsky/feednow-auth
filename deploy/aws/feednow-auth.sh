#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=env.sh
source "$root/deploy/aws/env.sh"
profile=""
environment=""
usage() {
  cat <<'EOF'
Usage: deploy/aws/feednow-auth.sh --profile AWS_PROFILE --env dev|staging|prod \
  recover-pepper-ciphertext|ensure-pepper-ciphertext|ensure-cognito-client-secret-ciphertext|ensure-google [--reset]|ensure-oauth-redirects|configure-google|rotate-google-credentials

The profile uses standard AWS credentials. The environment selects the
matching deploy/aws/cdk/.env.<environment> file. Only KMS ciphertext for the
API-key pepper may be written there; plaintext secrets are never written.
Google secrets are entered through a non-echoing prompt. `ensure-google --reset`
restarts Google configuration and prompts for the client ID and secret again.
EOF
}
while (($#)); do
  case "$1" in
    --profile) (($# >= 2)) || { usage >&2; exit 2; }; profile="$2"; shift 2 ;;
    --env) (($# >= 2)) || { usage >&2; exit 2; }; environment="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done
[[ -n "$profile" && -n "$environment" && "$environment" =~ ^(dev|staging|prod)$ && $# -ge 1 && $# -le 2 ]] || { usage >&2; exit 2; }
command="$1"
shift
if (($#)); then
  [[ "$command" == "ensure-google" && "$1" == "--reset" ]] || { usage >&2; exit 2; }
fi
feednow_load_env "$root" "$environment"
export AWS_PROFILE="$profile"
actual_account="$(feednow_verify_identity "$profile" "$AWS_ACCOUNT_ID" "$AWS_REGION")"
feednow_show_target "$environment" "$profile" "$actual_account" "$AWS_REGION"
if (($#)); then
  uv run --project "$root" -- python "$root/deploy/aws/feednow_aws_operator.py" \
    --profile "$profile" --env "$environment" "$command" --reset
else
  uv run --project "$root" -- python "$root/deploy/aws/feednow_aws_operator.py" \
    --profile "$profile" --env "$environment" "$command"
fi
