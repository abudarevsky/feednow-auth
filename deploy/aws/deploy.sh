#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cdk_dir="$root/deploy/aws/cdk"
# shellcheck source=env.sh
source "$root/deploy/aws/env.sh"

profile=""
environment=""
action=""
usage() {
  cat <<'EOF'
Usage: deploy/aws/deploy.sh --profile AWS_PROFILE --env dev|staging|prod synth|diff|deploy

--profile selects standard AWS CLI/CDK credentials.
--env selects deploy/aws/cdk/.env.<environment>.
EOF
}
while (($#)); do
  case "$1" in
    --profile) (($# >= 2)) || { usage >&2; exit 2; }; profile="$2"; shift 2 ;;
    --env) (($# >= 2)) || { usage >&2; exit 2; }; environment="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) action="$1"; shift; break ;;
  esac
done
[[ -n "$profile" && -n "$environment" && -n "$action" && $# -eq 0 ]] || { usage >&2; exit 2; }
[[ "$environment" =~ ^(dev|staging|prod)$ ]] || { echo "--env must be dev, staging, or prod" >&2; exit 2; }
[[ "$action" =~ ^(synth|diff|deploy)$ ]] || { usage >&2; exit 2; }

feednow_load_env "$root" "$environment"
export CDK_DEFAULT_ACCOUNT="$AWS_ACCOUNT_ID" FEEDNOW_ENV="$environment" AWS_PROFILE="$profile"
actual_account="$(feednow_verify_identity "$profile" "$AWS_ACCOUNT_ID" "$AWS_REGION")"
feednow_show_target "$environment" "$profile" "$actual_account" "$AWS_REGION"

cd "$cdk_dir"
case "$action" in
  synth)
    cdk synth "FeedNowAuth-$environment" --profile "$profile"
    ;;
  diff)
    if [[ -z "${FEEDNOW_PEPPER_CIPHERTEXT_B64:-}" ]]; then
      if uv run --project "$root" --group dev python "$root/deploy/aws/feednow_aws_operator.py" \
        --profile "$profile" --env "$environment" recover-pepper-ciphertext; then
        feednow_load_env "$root" "$environment"
      else
        recover_status=$?
        [[ $recover_status -eq 3 ]] || exit "$recover_status"
      fi
    fi
    cdk diff "FeedNowAuth-$environment" --profile "$profile"
    ;;
  deploy)
    if [[ -z "${FEEDNOW_PEPPER_CIPHERTEXT_B64:-}" ]]; then
      if uv run --project "$root" --group dev python "$root/deploy/aws/feednow_aws_operator.py" \
        --profile "$profile" --env "$environment" recover-pepper-ciphertext; then
        feednow_load_env "$root" "$environment"
      else
        recover_status=$?
        [[ $recover_status -eq 3 ]] || exit "$recover_status"
      fi
    fi
    cdk deploy "FeedNowAuth-$environment" --profile "$profile"
    if [[ -z "${FEEDNOW_PEPPER_CIPHERTEXT_B64:-}" ]]; then
      uv run --project "$root" --group dev python "$root/deploy/aws/feednow_aws_operator.py" \
        --profile "$profile" --env "$environment" ensure-pepper-ciphertext
      feednow_load_env "$root" "$environment"
      cdk deploy "FeedNowAuth-$environment" --profile "$profile"
    fi
    if [[ -z "${FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64:-}" ]]; then
      uv run --project "$root" --group dev python "$root/deploy/aws/feednow_aws_operator.py" \
        --profile "$profile" --env "$environment" ensure-cognito-client-secret-ciphertext
      feednow_load_env "$root" "$environment"
      if [[ -n "${FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64:-}" ]]; then
        cdk deploy "FeedNowAuth-$environment" --profile "$profile"
      fi
    fi
    api_endpoint="$(aws cloudformation describe-stacks --profile "$profile" \
      --region "$AWS_REGION" --stack-name "FeedNowAuth-$environment" \
      --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue | [0]" --output text)"
    [[ -n "$api_endpoint" && "$api_endpoint" != "None" ]] || {
      echo "Backend stack has no ApiEndpoint output" >&2; exit 1;
    }
    api_endpoint="${api_endpoint%/}"
    curl --fail --silent --show-error --retry 12 --retry-delay 5 --retry-all-errors \
      "$api_endpoint/health" -o /dev/null
    echo "Backend health check passed at $api_endpoint/health"
    ;;
esac
