#!/usr/bin/env bash
# Run a local Cognito authorization-code + PKCE journey and print /v1/me.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${FEEDNOW_LOGIN_ENV_FILE:-${SCRIPT_DIR}/.env}"

if [[ -f "${ENV_FILE}" ]]; then
    # The file is local-only configuration; none of its values are printed.
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
fi

REGION="${AWS_REGION:-${FEEDNOW_COGNITO_REGION:-eu-north-1}}"
CLIENT_ID="${FEEDNOW_COGNITO_CLIENT_ID:-}"
CLIENT_SECRET="${FEEDNOW_COGNITO_CLIENT_SECRET:-}"
COGNITO_DOMAIN="${FEEDNOW_COGNITO_DOMAIN:-}"
REDIRECT_URI="${FEEDNOW_COGNITO_CLI_REDIRECT_URI:-http://localhost:8000/oauth/cli-callback}"
API_URL="${FEEDNOW_API_URL:-http://localhost:8000}"
IDENTITY_PROVIDER="${FEEDNOW_COGNITO_IDP:-}"
OPEN_BROWSER=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-open) OPEN_BROWSER=false ;;
        --provider)
            [[ $# -ge 2 && -n "$2" ]] || { echo "--provider requires a value" >&2; exit 2; }
            IDENTITY_PROVIDER="$2"
            shift
            ;;
        *) echo "usage: $(basename "$0") [--no-open] [--provider Google]" >&2; exit 2 ;;
    esac
    shift
done

if [[ -z "${CLIENT_ID}" ]]; then
    echo "Missing FEEDNOW_COGNITO_CLIENT_ID in local login configuration" >&2
    exit 1
fi
if [[ -z "${COGNITO_DOMAIN}" ]]; then
    COGNITO_DOMAIN="https://feednow-auth-dev.auth.${REGION}.amazoncognito.com"
fi
for command in curl openssl python3; do
    command -v "${command}" >/dev/null 2>&1 || { echo "Required command not found: ${command}" >&2; exit 1; }
done

base64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
CODE_VERIFIER="$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9-._~' | cut -c1-96)"
CODE_CHALLENGE="$(printf '%s' "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | base64url)"
STATE="$(openssl rand -hex 32)"

AUTH_URL="$(python3 - "${COGNITO_DOMAIN}/oauth2/authorize" "${CLIENT_ID}" "${REDIRECT_URI}" "${CODE_CHALLENGE}" "${STATE}" "${IDENTITY_PROVIDER}" <<'PY'
import sys
from urllib.parse import urlencode

endpoint, client_id, redirect_uri, challenge, state, provider = sys.argv[1:]
params = {
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "scope": "openid email profile",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "state": state,
}
if provider:
    params["identity_provider"] = provider
print(endpoint + "?" + urlencode(params))
PY
)"

echo "Open this Cognito login URL:" >&2
echo "${AUTH_URL}" >&2
if [[ "${OPEN_BROWSER}" == true ]]; then
    case "$(uname -s)" in
        Darwin) open "${AUTH_URL}" >/dev/null 2>&1 || true ;;
        Linux) xdg-open "${AUTH_URL}" >/dev/null 2>&1 || true ;;
    esac
fi

read -r -p "Paste the complete callback URL: " CALLBACK_INPUT
CALLBACK_VALUES="$(printf '%s' "${CALLBACK_INPUT}" | python3 -c '
import sys
from urllib.parse import parse_qs, urlparse

value = sys.stdin.read().strip()
query = parse_qs(urlparse(value).query)
if query.get("error"):
    raise SystemExit("Cognito returned an authorization error")
code = query.get("code", [""])[0]
state = query.get("state", [""])[0]
if not code or not state:
    raise SystemExit("Callback URL is missing code or state")
print(code)
print(state)
')"
AUTH_CODE="$(printf '%s\n' "${CALLBACK_VALUES}" | sed -n '1p')"
CALLBACK_STATE="$(printf '%s\n' "${CALLBACK_VALUES}" | sed -n '2p')"
if [[ "${CALLBACK_STATE}" != "${STATE}" ]]; then
    echo "Callback state did not match the login request" >&2
    exit 1
fi

TOKEN_CURL_ARGS=(
    -fsS -X POST "${COGNITO_DOMAIN}/oauth2/token"
    -H 'Content-Type: application/x-www-form-urlencoded'
    --data-urlencode 'grant_type=authorization_code'
    --data-urlencode "client_id=${CLIENT_ID}"
    --data-urlencode "code=${AUTH_CODE}"
    --data-urlencode "redirect_uri=${REDIRECT_URI}"
    --data-urlencode "code_verifier=${CODE_VERIFIER}"
)
if [[ -n "${CLIENT_SECRET}" ]]; then
    # Cognito confidential clients require HTTP Basic authentication at the
    # token endpoint. The value stays in curl's process invocation only and
    # is never printed or persisted by this script.
    TOKEN_CURL_ARGS+=(--user "${CLIENT_ID}:${CLIENT_SECRET}")
fi
if ! TOKEN_RESPONSE="$(curl "${TOKEN_CURL_ARGS[@]}")"; then
    echo "Cognito token exchange failed" >&2
    exit 1
fi
ACCESS_TOKEN="$(printf '%s' "${TOKEN_RESPONSE}" | python3 -c '
import json
import sys

payload = json.load(sys.stdin)
token = payload.get("access_token")
if not isinstance(token, str) or not token:
    raise SystemExit("Cognito token exchange failed")
print(token)
')"

if ! ME_RESPONSE="$(curl -sS -w $'\n%{http_code}' "${API_URL}/v1/me" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")"; then
    echo "FeedNow /v1/me request failed before receiving an HTTP response" >&2
    exit 1
fi
ME_STATUS="${ME_RESPONSE##*$'\n'}"
ME_BODY="${ME_RESPONSE%$'\n'*}"
if [[ "${ME_STATUS}" != "200" ]]; then
    ME_ERROR="$(printf '%s' "${ME_BODY}" | python3 -c '
import json
import sys

try:
    payload = json.load(sys.stdin)
    code = payload.get("code") if isinstance(payload, dict) else None
    message = payload.get("message") if isinstance(payload, dict) else None
except (ValueError, TypeError):
    code = message = None

if isinstance(code, str) and isinstance(message, str):
    print(f"{code}: {message[:240]}")
else:
    print("API returned an unreadable error response")
')"
    echo "FeedNow /v1/me returned HTTP ${ME_STATUS}: ${ME_ERROR}" >&2
    exit 1
fi
printf '%s\n' "${ME_BODY}"
