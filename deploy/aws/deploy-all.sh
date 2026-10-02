#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=env.sh
source "$root/deploy/aws/env.sh"
profile=""
environment=""
ui_only=false
ui_root="${FEEDNOW_AUTH_UI_DIR:-$(cd "$root/../feednow-auth-ui" 2>/dev/null && pwd || true)}"
usage() {
  cat <<'EOF'
Usage: deploy/aws/deploy-all.sh --profile AWS_PROFILE --env dev|staging|prod [--ui]

Deploys the backend first, then the static account UI through CloudFront with
the same profile and environment. Use --ui to deploy only the UI against the
already-deployed backend. Override FEEDNOW_AUTH_UI_DIR if the UI checkout is
not the adjacent ../feednow-auth-ui directory.
EOF
}
while (($#)); do
  case "$1" in
    --profile) (($# >= 2)) || { usage >&2; exit 2; }; profile="$2"; shift 2 ;;
    --env) (($# >= 2)) || { usage >&2; exit 2; }; environment="$2"; shift 2 ;;
    --ui) ui_only=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$profile" && -n "$environment" && "$environment" =~ ^(dev|staging|prod)$ ]] || { usage >&2; exit 2; }
[[ -x "$ui_root/deploy/aws/deploy.sh" ]] || { echo "UI deployment script not found under FEEDNOW_AUTH_UI_DIR=$ui_root" >&2; exit 2; }
feednow_load_env "$root" "$environment"
export AWS_PROFILE="$profile"

if [[ "$ui_only" == true ]]; then
  "$root/deploy/aws/feednow-auth.sh" \
    --profile "$profile" --env "$environment" ensure-oauth-redirects
  FEEDNOW_AUTH_DIR="$root" \
  FEEDNOW_PEPPER_CIPHERTEXT_B64="" \
  "$ui_root/deploy/aws/deploy.sh" --profile "$profile" --env "$environment"
  exit 0
fi

"$root/deploy/aws/deploy.sh" --profile "$profile" --env "$environment" deploy
"$root/deploy/aws/feednow-auth.sh" \
  --profile "$profile" --env "$environment" ensure-oauth-redirects
"$root/deploy/aws/feednow-auth.sh" --profile "$profile" --env "$environment" ensure-google
FEEDNOW_AUTH_DIR="$root" \
FEEDNOW_PEPPER_CIPHERTEXT_B64="" \
"$ui_root/deploy/aws/deploy.sh" --profile "$profile" --env "$environment"
