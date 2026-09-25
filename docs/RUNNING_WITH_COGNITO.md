# Running feednow-auth with Cognito

This guide covers the Cognito resources, the bearer-token contract that
feednow-auth implements, the local authorization-code + PKCE login flow
(`run-dev.sh --cognito` plus `cognito-login.sh`), and the deployed client
settings verification runbook in section 7. The `/oauth/callback` capture page
is a local-only development harness; the deployed runtime mounts
`/oauth/login` and `/oauth/callback` only when the complete Phase 11 session
configuration is present, and `/v1/*` routes keep using the bearer-token
contract.

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
   - For a public client, do not generate a secret. For a confidential client,
     keep its client secret in the backend-only `FEEDNOW_COGNITO_CLIENT_SECRET`
     setting; never put it in the UI environment.
   - **Note the Client ID** and use it with the matching secret, if configured.

3. **Configure Callback URLs**
   - App client → Hosted UI → Edit
   - Callback URLs: `http://localhost:8000/oauth/callback` for the account UI
     and `http://localhost:8000/oauth/cli-callback` for `cognito-login.sh`
   - Allowed sign-out URL: `http://localhost:8000/logout`
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
./run-dev.sh --cognito --ui
```

This local composition uses SQLite and the real Cognito endpoints. The
browser-facing flow starts at `http://localhost:3000`; the backend owns the
authorization-code + PKCE exchange, establishes an HTTP-only `feednow_session`
cookie, and returns the browser to the account dashboard. With `--ui`, the
Compose `ui` service runs Vite on port 3000 and proxies `/api/*` to the backend
container at `http://app:8000`; browser requests never use the Docker service
name. Without `--ui`, only the backend runs in Docker; start Vite from a
terminal with `cd ../../../feednow-auth-ui && npm run dev`, which proxies to
`http://127.0.0.1:8000`. Set
`FEEDNOW_FRONTEND_URL=http://localhost:3000` and register
`http://localhost:8000/oauth/callback` on the existing public Cognito app
client. The old `cognito-login.sh` remains available for command-line
diagnostics but is not the account UI login path.

The browser flow uses the backend's PKCE state. Sign-out clears the local
session and navigates through Cognito's `/logout` endpoint, which returns the
browser through the registered local URL `http://localhost:8000/logout` and
then to the UI sign-in page. Add `http://localhost:8000/logout` to the app
client's allowed sign-out URLs. The
sign-in request includes `prompt=select_account` so Cognito can ask Google to
show its account chooser where supported.

1. The UI navigates to `/api/oauth/login`; the backend uses its configured
   absolute account landing URL (`FEEDNOW_FRONTEND_URL/account`) and stores a
   single-use state and PKCE verifier before redirecting to Cognito Managed
   Login. Do not send `/account` as a relative `next` path: the callback runs
   on the backend origin, so that path would return to the backend rather than
   the UI.
2. Cognito returns to the backend callback. The backend exchanges the code,
   validates the access token, fetches the verified profile, provisions the
   internal user and personal organization idempotently, and issues the
   session cookie.
3. The UI loads the account via `/api/v1/me`; protected browser API calls use
   that cookie. No Cognito token is stored in browser storage.

Configuration is read from `FEEDNOW_LOGIN_ENV_FILE` when set, defaulting to
`deploy/docker/.env`. On first login, `/v1/me` requires a verified Cognito
profile from the configured `FEEDNOW_COGNITO_USERINFO_URL`; it does not invent
an email from the token subject or username. Without that profile source, a
new identity is rejected before storage is changed. Existing identities are
resolved without another user-info request.

### Google email verification and existing federated profiles

The dev pool maps Google's `email_verified` claim to `custom:g_verified` (the
short name is required by Cognito's 20-character custom-attribute-name limit).
The dedicated `FeedNowAuthGoogleFederationFix-dev` CDK overlay attaches the
trigger to `PreSignUp` and `PreAuthentication`; it does not create or replace
the existing pool, app client, Google IdP, or hosted domain. `PreAuthentication`
is a read-only pass-through because Cognito requires synchronous trigger
responses within five seconds; it must not call the Cognito admin API.

On first Google registration, the trigger auto-confirms the Cognito user and
marks its email verified only when the Google claim was mapped to the exact
value `true`. Legacy profiles require a one-time operator repair, and only
when `custom:g_verified` is exactly `true`; never infer verification from an
email match. Cognito's `/oauth2/userInfo` endpoint returns `email_verified` as
the lowercase strings `true`/`false`; the backend normalizes only those exact
values to booleans before applying the verified-profile gate. Native Cognito
email/password sign-up keeps its normal email-code verification flow. No
email-based identity merge occurs.

To exercise this path, rebuild the local service, then run
`./cognito-login.sh --provider Google` from `deploy/docker`. Finish Google
sign-in, paste the callback URL into the script, and expect the `/v1/me` JSON
profile on stdout. Repeat the login for an existing Google account; Cognito
updates that federated profile in place rather than deleting or recreating it.

---

## 3. Run with Docker Compose

### Local account UI and API

```bash
cd deploy/docker
cp .env.example .env
# Fill in the existing development pool issuer, app client id, domain,
# and a locally generated base64 pepper. Set FEEDNOW_COGNITO_CLIENT_SECRET
# only when the selected app client has a secret. The user-info URL defaults to
# <domain>/oauth2/userInfo when FEEDNOW_COGNITO_USERINFO_URL is unset.
./run-dev.sh --cognito --ui
```

Open `http://localhost:3000`. Use `./run-dev.sh --cognito` to run only the
backend in Docker and start Vite in a terminal, or `./run-dev.sh --ui` as a
shortcut for `--cognito --ui`. The named SQLite volume is retained by normal
stop/start. Use `--reset` only when intentionally discarding local data.

### Backend development (with live reload)

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

The local app serves `/oauth/callback` for the browser UI flow and a separate
`/oauth/cli-callback` capture page for the host-side login helper.
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

### Historical Phase 09 local-harness checklist (superseded)

This checklist describes the earlier local bearer-token harness contract. It
is retained as historical context; Phase 11's verified-profile provisioning
and deployed session-flow checks below supersede its first-login expectations.

- [ ] **New email/password user**: sign up in the Hosted UI, sign in, paste
      the callback URL → earlier behavior returned a fresh `usr_` id; the
      current profile gate requires a verified user-info profile instead.
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
| `FEEDNOW_COGNITO_AUTHORIZE_URL` | Optional Phase 11 session gate | HTTPS Cognito authorization endpoint |
| `FEEDNOW_COGNITO_TOKEN_ENDPOINT` | Optional Phase 11 session gate | HTTPS Cognito token endpoint |
| `FEEDNOW_COGNITO_USERINFO_URL` | Optional Phase 11 session gate | HTTPS Cognito user-info endpoint; also needed for local first-login provisioning |
| `FEEDNOW_OAUTH_REDIRECT_URL` | Optional Phase 11 session gate | Exact callback URL |
| `FEEDNOW_ALLOWED_RETURN_ORIGINS` | Optional Phase 11 session gate | Comma-separated approved origins |
| `FEEDNOW_SESSION_TTL_SECONDS` | Optional Phase 11 session gate | Positive session lifetime in seconds |
| `FEEDNOW_COOKIE_SECURE` | Optional Phase 11 session gate | `true` for HTTPS deployments |

---

## 6. Troubleshooting

### "Token validation failed: invalid signature"
- Verify `FEEDNOW_COGNITO_ISSUER` matches exactly (including trailing slash)
- Check the token's `iss` claim matches your issuer

### "Token validation failed: audience mismatch"
- Verify `FEEDNOW_COGNITO_CLIENT_ID` matches the token's `client_id` claim

---

## 7. Deployed client settings verification (Phase 11)

Run these checks against the **dev** user pool and app client after deployment.
Use the deployed values from the `FeedNowAuth-dev` stack and the same
`COGNITO_CALLBACK_URLS` input used for its synth/deploy. Do not infer deployed
settings from CDK source or a successful local mock. The callback must be the
deployed service URL ending in `/oauth/callback`; the logout URL must also be
registered. Never request or print the app client's secret.

### Read the deployed app-client settings

Set the identifiers from the dev stack outputs or Cognito console (these are
resource identifiers, not credentials):

```bash
export AWS_REGION=<dev-region>
export USER_POOL_ID=<dev-user-pool-id>
export CLIENT_ID=<dev-public-app-client-id>
```

Read only the relevant deployed fields. This command deliberately omits
`ClientSecret` and emits no unrelated account configuration:

```bash
aws cognito-idp describe-user-pool-client \
  --region "$AWS_REGION" \
  --user-pool-id "$USER_POOL_ID" \
  --client-id "$CLIENT_ID" \
  --query 'UserPoolClient.{ClientId:ClientId,AllowedOAuthFlows:AllowedOAuthFlows,AllowedOAuthScopes:AllowedOAuthScopes,CallbackURLs:CallbackURLs,LogoutURLs:LogoutURLs,SupportedIdentityProviders:SupportedIdentityProviders,EnabledFlows:ExplicitAuthFlows,ClientSecretConfigured:contains(keys(@), `ClientSecret`)}' \
  --output json
```

Confirm the output contains all of the following:

- `AllowedOAuthFlows` contains `code` (authorization-code grant).
- `ClientSecretConfigured` is `false`, confirming this is a public client. The
  Hosted UI authorization request uses `code_challenge_method=S256` and the
  callback completes the `code_verifier` exchange.
- `AllowedOAuthScopes` contains `openid`, `email`, and `profile`.
- `CallbackURLs` contains every intended deployment callback, including the
  exact deployed `.../oauth/callback` URL. These URLs are sourced from the
  `COGNITO_CALLBACK_URLS` deploy input; compare against the value used for the
  deployed stack, not a source-code default.
- `LogoutURLs` contains the intended deployed post-logout URL.
- `SupportedIdentityProviders` contains `COGNITO` and `Google`.

In the Cognito console, verify the same client under **App integration → App
clients → Hosted UI**. Verify native self-service registration separately
under the user pool's sign-up settings: email is a sign-in attribute, email
verification is enabled, and self-registration is enabled for the dev pool.
For federation, verify the Google identity provider is configured and enabled
on this app client. The CLI client response cannot prove the Google provider's
upstream OAuth credentials or consent screen; those require the console's
identity-provider settings.

### Verify deployed runtime configuration

Confirm the Lambda's non-secret environment configuration includes the full
Phase 11 session set. The query returns only the seven named values:

```bash
aws lambda get-function-configuration \
  --region "$AWS_REGION" \
  --function-name <dev-function-name> \
  --query 'Environment.Variables.{Authorize:FEEDNOW_COGNITO_AUTHORIZE_URL,Token:FEEDNOW_COGNITO_TOKEN_ENDPOINT,UserInfo:FEEDNOW_COGNITO_USERINFO_URL,Redirect:FEEDNOW_OAUTH_REDIRECT_URL,Origins:FEEDNOW_ALLOWED_RETURN_ORIGINS,SessionTTL:FEEDNOW_SESSION_TTL_SECONDS,CookieSecure:FEEDNOW_COOKIE_SECURE}' \
  --output json
```

Do not add the secret-name or unrelated variables to this output.

| Key | Expected value shape |
| --- | --- |
| `FEEDNOW_COGNITO_AUTHORIZE_URL` | HTTPS Cognito `/oauth2/authorize` endpoint |
| `FEEDNOW_COGNITO_TOKEN_ENDPOINT` | HTTPS Cognito `/oauth2/token` endpoint |
| `FEEDNOW_COGNITO_USERINFO_URL` | HTTPS Cognito `/oauth2/userInfo` endpoint |
| `FEEDNOW_OAUTH_REDIRECT_URL` | Exact deployed callback URL ending in `/oauth/callback` |
| `FEEDNOW_ALLOWED_RETURN_ORIGINS` | Comma-separated approved HTTPS origins |
| `FEEDNOW_SESSION_TTL_SECONDS` | Positive integer |
| `FEEDNOW_COOKIE_SECURE` | `true` for deployed HTTPS |

The seven keys are an all-or-nothing gate. Removing all seven restores the
pre-Phase-11 deployed route surface; a partial set is a configuration error.
Keep environment values out of command transcripts when the deployment tool
prints unrelated Lambda settings. `FEEDNOW_COGNITO_USERINFO_URL` is also
required in the local Cognito composition for first-login provisioning: with
the Phase 11 profile gate, bearer-only first login without it fails with 401.

### Manual dev journeys

Use a dev account only. Complete both journeys through the deployed application
and record the date, deployment/stack revision, masked subject (for example,
first eight characters only), final route, and result. Do not record
authorization codes, state, PKCE verifier, access tokens, email addresses, or
client secrets.

1. **Native email:** start `/oauth/login` with an approved `next`, sign up or
   sign in through Cognito Managed Login, complete email verification when
   prompted, and confirm the browser returns to the approved destination with
   a `feednow_session` cookie marked `HttpOnly`, `SameSite=Lax`, `Path=/`, and
   `Secure`. Confirm a first login provisions the verified profile and a
   repeat login resolves the same account.
2. **Google federation:** start the same flow with the configured Google IdP,
   complete Google sign-in/consent, and confirm the same callback, cookie, and
   approved-return behavior. Confirm the profile returned by Cognito is
   verified and mapped to the same Cognito `sub` as the access token.

Do not treat a local test, mock, successful synth, or source configuration as
this deployed proof. Record the actual deployed output and both journey results
in `docs/phases/11-cognito-authentication-profile-and-session-boundary.md`.
Until those checks have been executed, this task's operational acceptance and
the Phase 11 handoff remain incomplete.

## 8. Troubleshooting reference

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

## 9. Production Deployment (Phase 07)

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

The deployed Lambda mounts `/oauth/login` and `/oauth/callback` only when the
complete Phase 11 session configuration is present. The local capture page
remains a separate development harness. This phase does not enable cookie-based
authentication on `/v1/*`; those routes continue to use the bearer-token
contract.

---

## 10. Administrator CLI via Docker Execution

Phase 13 authorizes exactly one administrator-bootstrap interface: the
operator CLI shipped inside the container as `python -m feednow_auth.admin`,
also available through `scripts/feednow-admin.sh`.
The prod image installs the project with `uv sync --frozen --no-dev`, so the
`feednow_auth` package is present in the running container with **no**
Dockerfile CMD/ENTRYPOINT change — the CLI is present but **never invoked at
startup**; deployment and container start only serve uvicorn, and no
environment-driven or startup-time promotion exists (spec 13 required
behavior 4). Role changes happen solely when an operator runs a command.

Against the local Cognito composition (run from the repository root):

```bash
./scripts/feednow-admin.sh grant --email admin@example.com
./scripts/feednow-admin.sh revoke --email admin@example.com
./scripts/feednow-admin.sh list
```

With no `--profile`, this wrapper targets the local Cognito Docker app and its
configured storage. To target AWS explicitly, supply a named AWS CLI profile;
also export `FEEDNOW_DYNAMODB_REGION` and `FEEDNOW_TABLE_PREFIX` first:

```bash
FEEDNOW_DYNAMODB_REGION=eu-north-1 FEEDNOW_TABLE_PREFIX=dev \
  ./scripts/feednow-admin.sh --profile feednow-dev list
```

The script forces the DynamoDB backend in AWS mode and refuses a configured
DynamoDB Local endpoint. `list` prints each user's internal ID, email, status,
application role, and registration time. Last-login time is currently not
persisted by FeedNow Auth and is reported as `not recorded`; it is not inferred
from `updated_at` or Cognito. The DynamoDB listing performs a paginated table
scan and is intended for infrequent operator use only.

The exec'd process inherits the app container's environment. The CLI derives
its storage from `FEEDNOW_STORAGE_BACKEND` (required, exactly `sqlite` or
`dynamodb`) plus the backend-specific variables (`FEEDNOW_SQLITE_PATH` for
SQLite, already `/data/feednow-auth.db` on the shared volume;
`FEEDNOW_DYNAMODB_REGION`/`FEEDNOW_TABLE_PREFIX` for DynamoDB). Ensure
`FEEDNOW_STORAGE_BACKEND` is present in `deploy/docker/.env` before using the
exec form; a missing or unknown value is a usage error (exit 2) and mutates
nothing. The user must already exist (registered through the Cognito journey);
the CLI never provisions users.

### Exit codes (stable operator-facing contract)

| Code | Meaning |
|------|---------|
| `0` | Success. stdout distinguishes `granted` / `already granted` / `revoked` / `already revoked`; idempotent no-ops exit 0 and write no duplicate audit. |
| `1` | Unexpected failure (`StorageError` or anything else) — one fixed safe stderr line, never a traceback. |
| `2` | Usage error (missing/unknown subcommand, missing `--email`) or unusable storage configuration. |
| `3` | No user exists for that email. |
| `4` | Ambiguous email — stderr lists the candidate `usr_` ids; nothing is written. |
| `5` | Refused: the revoke would remove the last active administrator; fully rolled back. |

### Container proof

`deploy/docker/admin-cli-smoke.sh` builds the cognito-profile image and runs
the whole sequence in one-shot `docker compose run --rm` containers against a
per-run SQLite file on the `/data` volume: seed through the storage API,
`grant` (exit 0 + persisted `admin` role read back through the storage API),
repeat `grant` (`already granted`, exit 0), and last-admin `revoke` (exit 5).
It prints only fixed messages and internal ids.
