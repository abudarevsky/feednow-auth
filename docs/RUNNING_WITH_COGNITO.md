# Running feednow-auth with Cognito

This guide covers the Cognito resources, the bearer-token contract that
feednow-auth implements, and the local authorization-code + PKCE login flow
(`run-dev.sh --cognito` plus `cognito-login.sh`). The browser-facing
`/oauth/callback` capture page is local-only: the deployed runtime accepts
Cognito access tokens on its `/v1/*` routes and never serves the callback
itself.

## Prerequisites

- Docker Desktop running
- AWS CLI configured (`aws configure`)
- `jq` for JSON parsing (optional but helpful)

---

## 1. Create Cognito Resources

### Option A: Quick Setup (AWS Console)

1. **Create User Pool**
   - Go to AWS Console → Cognito → Create User Pool
   - Provider: Email
   - Password policy: Your choice
   - MFA: Optional
   - Self-service account recovery: Email only
   - **Note the User Pool ID** (e.g., `us-east-1_ABC123xyz`)

2. **Create App Client**
   - In your User Pool → App integration → App client → Create app client
   - Auth flows: `ALLOW_USER_SRP_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`
   - Secret: **Do not generate a secret** (this is a public PKCE client)
   - **Note the Client ID**. This is a public client and has no client secret.

3. **Configure Callback URLs**
   - App client → Hosted UI → Edit
   - Callback URL: `http://localhost:8000/oauth/callback` (for local testing)
   - Logout URL: `http://localhost:8000/logout`
   - Allowed OAuth flows: `Authorization code grant`
   - Allowed OAuth scopes: `openid`, `email`, `profile`
   - Branding: **Hosted UI (classic)**. The CDK stack explicitly selects this
     mode so the domain does not require a separately assigned managed-login
     branding style.

4. **Note the Issuer URL**
   ```
   https://cognito-idp.{region}.amazonaws.com/{user-pool-id}
   ```

### Option B: Automated (AWS CLI)

```bash
# Set variables
REGION=us-east-1
POOL_NAME=feednow-auth-dev
CLIENT_NAME=feednow-auth-client
CALLBACK_URL=http://localhost:8000/oauth/callback
LOGOUT_URL=http://localhost:8000/logout

# Create User Pool
USER_POOL_ID=$(aws cognito-idp create-user-pool \
  --pool-name "$POOL_NAME" \
  --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":false}}' \
  --auto-verified-attributes email \
  --username-attributes email \
  --region "$REGION" \
  --query 'UserPool.Id' --output text)

echo "User Pool ID: $USER_POOL_ID"

# Create App Client
CLIENT_RESPONSE=$(aws cognito-idp create-user-pool-client \
  --user-pool-id "$USER_POOL_ID" \
  --client-name "$CLIENT_NAME" \
  --explicit-auth-flows ALLOW_USER_SRP_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --supported-identity-providers COGNITO \
  --callback-urls "$CALLBACK_URL" \
  --logout-urls "$LOGOUT_URL" \
  --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid email profile \
  --allowed-o-auth-flows-user-pool-client \
  --region "$REGION")

CLIENT_ID=$(echo "$CLIENT_RESPONSE" | jq -r '.UserPoolClient.ClientId')

echo "Client ID: $CLIENT_ID"

# Create the Cognito prefix domain using the classic hosted UI. Version 1
# avoids the managed-login branding-style requirement.
aws cognito-idp create-user-pool-domain \
  --user-pool-id "$USER_POOL_ID" \
  --domain "$POOL_NAME" \
  --managed-login-version 1 \
  --region "$REGION"

# Issuer URL
ISSUER="https://cognito-idp.$REGION.amazonaws.com/$USER_POOL_ID"
echo "Issuer: $ISSUER"
```

---

## 2. Local Docker scope

The default Docker command runs the import-safe application skeleton. Use the
local Cognito composition for authenticated development:

```bash
cd deploy/docker
cp .env.example .env
# Set FEEDNOW_COGNITO_ISSUER, FEEDNOW_COGNITO_CLIENT_ID, and a base64
# FEEDNOW_PEPPER_SECRET in .env.
./run-dev.sh --cognito
./cognito-login.sh
```

This local composition uses SQLite and the real Cognito JWKS endpoint, and it
serves the local-only `GET /oauth/callback` capture page
(`deploy/docker/oauth_callback.py`, mounted only by `local_runtime.py` — the
production `app.main:create_app` surface never sees it). `cognito-login.sh`
implements the WIP 09 flow contract:

1. Generates a PKCE verifier/challenge **and a random CSRF `state`**, then
   opens `{domain}/oauth2/authorize` (`--provider Google` adds
   `identity_provider=Google`; the flag value is passed to the URL builder).
2. The Cognito redirect lands on `http://localhost:8000/oauth/callback`,
   which renders a page instructing you to copy the **complete callback URL**
   from the browser address bar and paste it back into the terminal. The page
   echoes only `code`/`state` (or `error`/`error_description`), HTML-escaped,
   as text — it logs nothing and persists nothing, and the Cognito compose
   override runs uvicorn with `--no-access-log` so the query string (and the
   one-time code) never reaches container logs.
3. The script validates the pasted `state` against the generated one and
   aborts **before any token exchange** on a mismatch or an `error`
   parameter.
4. The token exchange posts `grant_type`, `code`, `redirect_uri`,
   `code_verifier`, and `client_id` (plus `client_secret` only when the env
   provides one) as a form body built by `python3 urlencode` and piped to
   `curl --data-binary @-` over HTTPS — code, verifier, and secret never
   appear in argv, logs, or files.
5. stdout carries **only** the `GET /v1/me` JSON body on HTTP 200; all
   guidance and fixed credential-free error messages go to stderr, and
   missing config (before any network call), a failed exchange, or a
   non-200 `/v1/me` exit non-zero.

Configuration is read from `FEEDNOW_LOGIN_ENV_FILE` when set, defaulting to
`deploy/docker/.env`. Because Cognito access tokens carry no `email` claim,
`/v1/me` derives the provisioned `User.email` from the validated claims
(`email` claim → email-shaped `username` → `{sub}@cognito.invalid`; see
`docs/contracts.md`).

---

## 3. Run with Docker Compose

### Production-like (no live reload)

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

### Development (with live reload)

```bash
docker compose -f deploy/docker/docker-compose.yml \
  -f deploy/docker/docker-compose.dev.yml up --build
```

### With DynamoDB Local (for Phase 06 tests)

```bash
docker compose -f deploy/docker/docker-compose.yml --profile testing up -d dynamodb-local
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  docker compose -f deploy/docker/docker-compose.yml run --rm app uv run pytest -m dynamodb_local
```

---

## 4. Test the Integration

### Health Check (no auth required)

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

### Cognito authorization page

```bash
REGION="eu-north-1"
COGNITO_DOMAIN="https://feednow-auth-dev.auth.${REGION}.amazoncognito.com"
CLIENT_ID="your-client-id"
REDIRECT_URI="http://localhost:8000/oauth/callback"

AUTH_URL="${COGNITO_DOMAIN}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=openid+email+profile"
echo "Open in browser: $AUTH_URL"
```

The local app serves the `/oauth/callback` capture page, and
`./cognito-login.sh` builds the full authorize URL (PKCE challenge and CSRF
`state` included) itself — construct the URL by hand only to debug app-client
configuration. A successful sign-in lands on the capture page, where you copy
the complete callback URL back into the terminal.

### Test with a Valid Token

`./cognito-login.sh` exchanges the authorization code and prints the
`GET /v1/me` JSON body directly. To call `/v1/*` manually instead, obtain an
access token through a supported Cognito client flow and send it as a bearer
token:

```bash
ACCESS_TOKEN="eyJraWQ..."
API_URL="http://localhost:8000"
curl -H "Authorization: Bearer ${ACCESS_TOKEN}" "${API_URL}/v1/me"
```

### Create an API Key (requires authenticated user)

```bash
curl -X POST "${API_URL}/v1/api-keys" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-key", "environment": "test", "scopes": ["feednow:orders:read"]}'
```

### WIP 09 live acceptance checklist (non-production dev pool)

Run against the dev User Pool created above and the local Docker runtime
(`./run-dev.sh --cognito`). Hermetic behavior for every step below is proven
offline by `src/tests/unit/test_cognito_login_script.py` and
`src/tests/unit/test_oauth_callback.py`; this checklist is the operator-run
live pass recorded in `docs/phases/09-local-cognito-login.md`.

- [ ] **New email/password user**: sign up in the Hosted UI, sign in, paste
      the callback URL → exit 0 and stdout is exactly the `GET /v1/me` JSON
      with a fresh `usr_` id (email-derived or `{sub}@cognito.invalid`
      placeholder).
- [ ] **Existing Google user**: `./cognito-login.sh --provider Google` →
      the authorize URL on stderr carries `identity_provider=Google` and the
      flow completes with the user's `/v1/me` JSON.
- [ ] **Second login stability**: re-run either flow for the same Cognito
      user → the same `usr_` id is returned and no second user/org/membership
      row is created.
- [ ] **Invalid state**: paste a callback URL with a wrong/missing `state` →
      non-zero exit, fixed credential-free message on stderr, and no token
      exchange attempted.
- [ ] **Failed exchange**: paste a valid-state URL with a bogus/consumed
      `code` → non-zero exit with "Cognito token exchange failed", no token
      or secret material printed.
- [ ] **Missing config**: run with no `FEEDNOW_COGNITO_CLIENT_ID` (e.g.
      `FEEDNOW_LOGIN_ENV_FILE=/dev/null`) → non-zero exit before any network
      call, printing no secret material.
- [ ] **Log hygiene**: `docker logs` of the app container contains no
      `/oauth/callback` access line and no code/token substring.

---

## 5. Environment Variable Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `FEEDNOW_COGNITO_ISSUERS` | AWS runtime | Comma-separated Cognito issuer allowlist |
| `FEEDNOW_COGNITO_CLIENT_IDS` | AWS runtime | Comma-separated public app-client ID allowlist |
| `FEEDNOW_DYNAMODB_REGION` | AWS runtime | DynamoDB region |
| `FEEDNOW_TABLE_PREFIX` | AWS runtime | Environment-specific table prefix |
| `FEEDNOW_PEPPER_SECRET_ID` | AWS runtime | Secrets Manager secret name, never secret material |

---

## 6. Troubleshooting

### "Token validation failed: invalid signature"
- Verify `FEEDNOW_COGNITO_ISSUER` matches exactly (including trailing slash)
- Check the token's `iss` claim matches your issuer

### "Token validation failed: audience mismatch"
- Verify `FEEDNOW_COGNITO_CLIENT_ID` matches the token's `client_id` claim

### "Pepper secret too short"
- Must be 32+ bytes (base64 decoded). Regenerate with `openssl rand -base64 32`

### Database locked / migration issues
- Stop containers: `docker compose -f deploy/docker/docker-compose.yml down`
- Remove volume: `docker volume rm feednow-auth_feednow-data`
- Restart: `docker compose -f deploy/docker/docker-compose.yml up --build`

### Login pages unavailable
- Ensure the deployed Cognito domain uses Hosted UI (classic), or create and
  assign a managed-login branding style to the app client.
- The CDK stack now selects Hosted UI (classic); redeploy the stack before
  retrying an existing domain.

### Cognito JWKS fetch fails
- Ensure container can reach `https://cognito-idp.{region}.amazonaws.com`
- Check VPC/security groups if running in AWS

---

## 7. Production Deployment (Phase 07)

For AWS Lambda deployment, see:
- `docs/phases/07-aws-infrastructure.md` — CDK stack, composition root
- `deploy/aws/cdk/.env.example` — Deployment inputs
- `deploy/aws/smoke/smoke.py` — Post-deploy verification

The CDK stack creates:
- Cognito User Pool + App Client (PKCE)
- 7 DynamoDB tables + 3 GSIs
- Secrets Manager secret for pepper
- HTTP API Gateway + Lambda function
- Least-privilege IAM roles

The stack does not create an OAuth callback route: `/oauth/callback` is a
local-only capture page mounted by `deploy/docker/local_runtime.py`, never by
the production `app.main:create_app` surface. Browser login completes through
the local `cognito-login.sh` flow; the deployed runtime keeps accepting
bearer access tokens, and feednow-auth owning a hosted browser login session
remains an explicit follow-up.
