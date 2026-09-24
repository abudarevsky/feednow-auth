# Operations

## Setup and development

```bash
uv sync
uv run pytest
uv run pytest src/tests/storage_contract   # storage conformance only
uv run ruff check .
uv run ruff format --check .
uv run feednow-auth
```

The project targets Python 3.13+ and pins the development toolchain to
3.14.5. Production serving is declared as `uvicorn[standard]`, so Uvicorn
uses `uvloop` when the platform supports it.

## DynamoDB Local (Phase 06 harness)

Adapter tests marked `dynamodb_local` skip with an explicit reason unless
`FEEDNOW_DYNAMODB_LOCAL_ENDPOINT` is set and reachable, so the default
`uv run pytest` stays green on machines without Docker. To run them:

```bash
docker run --rm -d --name feednow-dynamodb-local -p 8000:8000 \
  amazon/dynamodb-local:2.6.0 \
  -jar DynamoDBLocal.jar -inMemory -sharedDb

FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest -m dynamodb_local

docker stop feednow-dynamodb-local
```

The harness (`src/tests/support/dynamodb_local.py`) authenticates with fixed
dummy credentials against any region and creates/deletes the seven adapter
tables under a fresh random prefix per test, so runs are isolated without
truncation races. moto is not used: DynamoDB Local is the real transactional
oracle for conformance evidence.

## Verified behavior

Phases 01–05 expose `/health` and the ten mounted §14 routes over the
storage boundary: the `Storage` contract, the SQLite adapter behind
`open_sqlite_storage`, and the adapter-neutral conformance suite. Phase 06
adds the production DynamoDB adapter behind `open_dynamodb_storage` (schema,
IAM matrix, and limitations in
[docs/phases/06-dynamodb.md](phases/06-dynamodb.md)); the same suite runs
against DynamoDB Local through the marker-gated entry. Phase 07 adds the
deployable AWS runtime — the Python CDK stack, the import-safe Lambda
composition root, and the HTTP API (commands and evidence in
[docs/phases/07-aws-infrastructure.md](phases/07-aws-infrastructure.md),
operator summary below). Phase 11 adds the verified-profile provisioning
gate (first login requires a verified user-info profile; the placeholder
email is gone, so the local Cognito composition needs
`FEEDNOW_COGNITO_USERINFO_URL` for first-login provisioning) and the
`/oauth/login` + `/oauth/callback` session boundary, mounted in the
deployed runtime only under the complete session configuration below
(contract and evidence in
[docs/phases/11-cognito-authentication-profile-and-session-boundary.md](phases/11-cognito-authentication-profile-and-session-boundary.md)).
`/v1/*` routes still do not authenticate the `feednow_session` cookie —
session verification is component-level only. The service still does not
expose an audit read surface (Phase 08). Do not infer those capabilities
from a passing health check or a green conformance run.

## Deployed runtime (Phase 07)

Full command inventory and evidence live in
[docs/phases/07-aws-infrastructure.md](phases/07-aws-infrastructure.md).
Operator summary:

- Deployment inputs are four non-secret names — `FEEDNOW_ENV`
  (`dev|staging|prod`), `CDK_DEFAULT_ACCOUNT`, `AWS_REGION`,
  `COGNITO_CALLBACK_URLS` — set in the shell or in a never-committed
  `deploy/aws/cdk/.env` (copy `.env.example`; shell wins).
- Synth/deploy/destroy run from `deploy/aws/cdk` against the
  `FeedNowAuth-<env>` stack; the placeholder synth command in the phase doc
  runs as written. The runtime reads only the five stack-injected
  `FEEDNOW_*` keys (region, table prefix, Cognito issuer/client allowlists,
  pepper secret *name*); the pepper value is fetched once per container
  from Secrets Manager at cold start.
- After deploying dev/staging, prove the live path with the smoke script
  (from the repository root; refuses `prod` without `--force`, prints only
  ids):

  ```bash
  PYTHONPATH=. uv run python deploy/aws/smoke/smoke.py \
    --env dev --region <region> \
    --user-pool-id <CognitoUserPoolId> --client-id <CognitoClientId> \
    --api-url <ApiEndpoint> --table-prefix feednow-auth-dev-
  ```

- Rollback safety: dev/staging tables are destroyed with the stack; prod
  tables, the user pool, and the pepper secret are `RETAIN` — deleting the
  prod stack keeps the data, and losing the prod pepper invalidates every
  stored API-key digest (rotation is Phase 08).

## Deployed session configuration (Phase 11)

The session boundary is an **all-or-nothing runtime gate** of seven
optional Lambda keys — the CDK stack deliberately does not set them; the
operator supplies them (console or `aws lambda update-function-configuration`):
`FEEDNOW_COGNITO_AUTHORIZE_URL`,
`FEEDNOW_COGNITO_TOKEN_ENDPOINT`, `FEEDNOW_COGNITO_USERINFO_URL` (all
HTTPS Cognito endpoints), `FEEDNOW_OAUTH_REDIRECT_URL` (the exact
deployed `/oauth/callback` URL, matching the app-client registration in
`COGNITO_CALLBACK_URLS`), `FEEDNOW_ALLOWED_RETURN_ORIGINS`
(comma-separated bare HTTPS origins), `FEEDNOW_SESSION_TTL_SECONDS`
(positive integer), and `FEEDNOW_COOKIE_SECURE` (`true`/`false`).

- All seven present: `build_app` mounts `/oauth/login` +
  `/oauth/callback` and wires the user-info profile source into the four
  §14 routers.
- None present: the deployed **route** surface is exactly the
  pre-phase-11 app — **removing all seven keys is the rollback
  procedure** (the next invocation cold-starts without the session
  routes, and stored login states and sessions go unread while the gate
  stays off, expiring on their own). The rollback restores routes, not
  first-login behavior: with the gate off no profile source is wired, so
  deployed bearer first-login provisioning fails 401.
- A partial set fails cold start with a fixed message naming only the
  missing keys — never a silent downgrade.

The deployed-client settings proof (Hosted UI PKCE flow, `openid email
profile` scopes, callback/logout registrations, native self-service
email, Google IdP) and the two manual dev journeys are runbook §7 of
[RUNNING_WITH_COGNITO.md](RUNNING_WITH_COGNITO.md): deployed settings,
not source, are the operational proof.

## Verification

```bash
uv run pytest -q --tb=short                       # default env: DynamoDB Local cases skip by name
uv run pytest src/tests/storage_contract -q       # SQLite conformance entry (74)
uv run ruff check .
uv run ruff format --check .
git diff --check

# With DynamoDB Local running (see above):
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest -q                                # full suite, gated cases included
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest src/tests/storage_contract -q     # both adapter entries (74 + 73)
```

Report test results, third-party warnings, environment blocks, and any
unperformed remote or deployment checks separately.
