#!/usr/bin/env bash
# Safe loader for non-secret FeedNow deployment settings. It parses KEY=value
# lines and never evaluates the file as shell code.

feednow_load_env() {
  local root="$1" expected_env="$2" config="$1/deploy/aws/cdk/.env.$2"
  local line key value
  [[ -r "$config" ]] || { echo "Missing environment config: $config" >&2; return 2; }

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)=(.*)$ ]] || {
      echo "Invalid environment config line in $config" >&2
      return 2
    }
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    case "$key" in
      FEEDNOW_ENV|AWS_ACCOUNT_ID|AWS_REGION|ACCOUNT_BASE_URL|VISPECTOR_BASE_URL|\
      ACCOUNT_DOMAIN_NAME|ACM_CERTIFICATE_ARN|ROUTE53_HOSTED_ZONE_ID|\
      ACCOUNT_ORIGIN|FEEDNOW_VISPECTOR_URL|FEEDNOW_API_DOMAIN|FEEDNOW_COGNITO_CALLBACK_URLS|\
      FEEDNOW_COGNITO_DOMAIN|\
      FEEDNOW_COGNITO_USER_POOL_ID|FEEDNOW_COGNITO_CLIENT_ID|\
      FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64|FEEDNOW_PEPPER_CIPHERTEXT_B64)
        ;;
      AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_PROFILE)
        echo "$key is AWS credential/profile configuration and is not allowed in $config" >&2
        return 2
        ;;
      *) echo "Unsupported setting $key in $config" >&2; return 2 ;;
    esac
    if [[ ${#value} -ge 2 && ( ( ${value:0:1} == '"' && ${value: -1} == '"' ) || ( ${value:0:1} == "'" && ${value: -1} == "'" ) ) ]]; then
      value="${value:1:${#value}-2}"
    fi
    printf -v "$key" '%s' "$value"
    export "$key"
  done < "$config"

  [[ "${FEEDNOW_ENV:-}" == "$expected_env" ]] || {
    echo "FEEDNOW_ENV in $config must equal $expected_env" >&2
    return 2
  }
  [[ -n "${AWS_ACCOUNT_ID:-}" && "$AWS_ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || {
    echo "AWS_ACCOUNT_ID in $config must be a 12-digit account ID" >&2
    return 2
  }
  [[ -n "${AWS_REGION:-}" ]] || { echo "AWS_REGION is required in $config" >&2; return 2; }
  ACCOUNT_ORIGIN="${ACCOUNT_ORIGIN:-${ACCOUNT_BASE_URL:-}}"
  FEEDNOW_VISPECTOR_URL="${FEEDNOW_VISPECTOR_URL:-${VISPECTOR_BASE_URL:-}}"
  export ACCOUNT_ORIGIN FEEDNOW_VISPECTOR_URL
}

feednow_verify_identity() {
  local profile="$1" expected_account="$2" region="$3" actual_account
  actual_account="$(aws sts get-caller-identity --profile "$profile" --region "$region" --query Account --output text)" || {
    echo "Unable to verify AWS identity for profile $profile" >&2
    return 1
  }
  [[ "$actual_account" == "$expected_account" ]] || {
    echo "AWS account mismatch: profile $profile resolves to $actual_account; expected $expected_account" >&2
    return 1
  }
  printf '%s\n' "$actual_account"
}

feednow_show_target() {
  printf 'FeedNow environment: %s\nAWS profile:         %s\nAWS account:         %s\nAWS region:          %s\nStack:               %s\nCognito pool:        %s\n' \
    "$1" "$2" "$3" "$4" "FeedNowAuth-$1" "feednow-auth-$1"
}
