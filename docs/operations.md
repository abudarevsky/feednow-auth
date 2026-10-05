# Operations

## Development

The service targets Python 3.13 or newer and uses `uv` for dependency
management. From the repository root:

```bash
uv sync
uv run feednow-auth
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

The default `app.main:app` exposes `/health`. Deployment and local Docker
compositions explicitly supply their routers and settings.

Swagger UI (`/docs`), ReDoc (`/redoc`), and the OpenAPI schema
(`/openapi.json`) are available in local, development, and staging
environments. All three are disabled when `FEEDNOW_ENV=prod`.

## Local Docker and Cognito

Copy `deploy/docker/.env.example` to the local environment file and provide
the development Cognito issuer/client settings and a locally generated pepper
where required. The account UI and backend can be started with:

```bash
./deploy/docker/run-dev.sh --ui
```

Use `./deploy/docker/run-dev.sh --cognito` when running the backend in Docker
and Vite separately. The local composition uses SQLite and mounts the
browser-facing session, account, and local-admin routes. `--reset` discards
local data; use it only when that is intended. The Cognito callback and logout
URLs must match the local app-client configuration. See [cognito.md](cognito.md)
and [sessions.md](sessions.md).

To run the same local Cognito app with DynamoDB Local instead of SQLite, use:

```bash
./deploy/docker/run-dev.sh --dynamodb-local
./deploy/docker/run-dev.sh --dynamodb-local --ui
```

The Docker wrapper reuses existing images by default. Add `--build` to rebuild
images and force-recreate selected containers after source or Compose changes:

```bash
./deploy/docker/run-dev.sh --dynamodb-local --build
```

This starts a separate DynamoDB Local container, creates the FeedNow tables,
and points the app at it over the Compose network. DynamoDB Local data persists
in the `feednow-auth_dynamodb-data` named volume; `--stop` preserves it. Remove
that volume only when you intend to erase the local DynamoDB data. The same
local platform-administration routes are mounted for SQLite and DynamoDB
storage; each adapter provides the organization queries and lifecycle
operations. The DynamoDB Local service is internal to the Compose network and
does not take the API's host port 8000.
After stopping the stack, erase its local DynamoDB data with
`docker volume rm feednow-auth_dynamodb-data`.

To enable the local Vispector registration and handoff, set
`FEEDNOW_VISPECTOR_URL` to `http://localhost:5173`,
`FEEDNOW_VISPECTOR_CALLBACK_PATH` to its fixed callback path, and a random
`FEEDNOW_VISPECTOR_SERVICE_SECRET` in `deploy/docker/.env` before starting it.
The local service secret is for Docker development only. Production receives
only the KMS ciphertext input described below. Role grants are intersected
with `FEEDNOW_VISPECTOR_PERMISSIONS`; the local default is
`projects:read,projects:write,inspect`.

To exercise service API-key validation in this composition, create a Vispector
key for an active organization through the authenticated API-key endpoint with
exactly the `vispector:inspection:run` scope, then call the local service
endpoint with both the service credential and key. The current account UI
creates empty-scope keys, which this endpoint correctly rejects:
Create a Vispector key for an active organization through the authenticated
API-key endpoint with exactly the `vispector:inspection:run` scope, then call
the local service endpoint with both the service credential and key. The
current account UI creates empty-scope keys, which this endpoint correctly
rejects:

```bash
set -a
source deploy/docker/.env
set +a

curl -sS http://localhost:8000/v1/service-auth/api-keys/validate \
  -H "Authorization: Bearer $FEEDNOW_VISPECTOR_SERVICE_SECRET" \
  -H 'Content-Type: application/json' \
  --data '{"key":"<full-key-shown-once-at-creation>"}'
```

The response should contain the user and organization IDs, `service`, mapped
`permissions`, and `expires_at`, without returning the API-key literal. Run the
focused route and storage checks with:

```bash
uv run pytest src/tests/unit/test_service_auth.py -q
uv run pytest src/tests/unit/test_service_authorization_handoff.py -q
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  PYTHONPATH=.:deploy/aws/runtime:src uv run pytest \
  src/tests/integration/test_service_auth_dynamodb_local.py -q
```

For AWS, configure the registered origin with `FEEDNOW_VISPECTOR_URL`, and
optionally set the callback path, enabled flag, and permission allowlist using
the matching `FEEDNOW_VISPECTOR_*` settings. Supply only
`FEEDNOW_VISPECTOR_SERVICE_CREDENTIAL_CIPHERTEXT_B64` in the CDK environment
file. Encrypt the credential with the stack's environment-scoped KMS key and
encryption context `environment=<dev|staging|prod>`; Lambda decrypts it in
memory. Rotate it by replacing the encrypted value and deploying the updated
stack. Never put the plaintext credential in Lambda environment configuration,
the CDK file, or source control.

## DynamoDB Local

The shared adapter-conformance suite can run against DynamoDB Local:

```bash
docker run --rm -d --name feednow-dynamodb-local -p 8000:8000 \
  amazon/dynamodb-local:2.6.0 \
  -jar DynamoDBLocal.jar -inMemory -sharedDb

FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  PYTHONPATH=.:deploy/aws/runtime:src uv run pytest -m dynamodb_local

docker stop feednow-dynamodb-local
```

The test harness creates isolated tables with a random prefix and uses dummy
credentials. Without a reachable endpoint, marked cases skip with a reason.

## AWS deployment

AWS deployments target `dev`, `staging`, or `prod` through standard AWS CLI
profiles. FeedNow settings are non-secret files at
`deploy/aws/cdk/.env.<environment>`; copy `deploy/aws/cdk/.env.example` for
each target and set `FEEDNOW_ENV`, `AWS_ACCOUNT_ID`, `AWS_REGION`, and
`ACCOUNT_BASE_URL`. Set `FEEDNOW_COGNITO_DOMAIN` when the imported pool's
existing hosted domain does not use the default `feednow-auth-<environment>`
prefix. The file must not contain AWS credentials, profile names, Google OAuth
secrets, or plaintext API-key pepper/client-secret values. `.env.*` is ignored
by Git; the operator stores only KMS ciphertext for Lambda secrets.

Preview the backend change and then deploy it with an explicit standard AWS
profile and FeedNow environment:

```bash
deploy/aws/deploy.sh --profile work --env dev diff
deploy/aws/deploy.sh --profile work --env dev deploy
```

Both commands verify `aws sts get-caller-identity` using the selected profile
and compare its account ID to `AWS_ACCOUNT_ID` before proceeding. The backend
stack imports the user-provisioned Cognito pool and app client, and creates
environment-scoped DynamoDB, KMS, Lambda, and HTTP API resources. Cognito pools,
clients, and domains are never created or replaced by this deployment. Supply
`FEEDNOW_COGNITO_USER_POOL_ID` and `FEEDNOW_COGNITO_CLIENT_ID` in every environment file; verify
the existing pool's domain and callback/client configuration before deploying.
The API-key pepper is encrypted with the environment's CDK-managed KMS key;
only base64 ciphertext is written to the ignored `.env.<environment>` file and
passed to the Lambda environment. Lambda decrypts it at cold start with an
environment-specific encryption context and caches plaintext only in process
memory. Its execution role has `kms:Decrypt` on that one key with the matching
context condition. Neither SSM Parameter Store nor Secrets Manager stores the
pepper. On first deploy, the stack creates the key, then the operator generates
or migrates the pepper, encrypts it, and completes the Lambda deployment.
Existing dev pepper material is read in memory from the legacy Secrets Manager
value and re-encrypted without changing API-key validity; the migration does
not write a new Secrets Manager value.

Deploy the backend and static account UI together with one profile and target:

```bash
deploy/aws/deploy-all.sh --profile work --env prod
```

To redeploy only the UI against an already-deployed backend, add `--ui`:

```bash
deploy/aws/deploy-all.sh --profile work --env prod --ui
```

The coordinator deploys the backend first, reads `ApiEndpoint` from stack
outputs, verifies or securely configures the environment's Cognito Google IdP,
and adds the environment's callback and logout URLs to its existing Cognito
app client before running the UI checks and deploying private S3/CloudFront.
The `--ui` mode skips backend deployment but still synchronizes the existing
Cognito app-client redirects, authorization-code flow, and required OIDC
scopes before publishing the UI. Custom-domain values
(`ACCOUNT_DOMAIN_NAME`, `ACM_CERTIFICATE_ARN` in `us-east-1`, and
`ROUTE53_HOSTED_ZONE_ID`) belong in the selected non-secret environment file.
The Google OAuth client is created separately in Google Console; enter its
client ID and secret only when the secure operator prompt requests them.

To rotate the Google secret without printing it or writing it to configuration:

```bash
deploy/aws/feednow-auth.sh --profile work --env prod rotate-google-credentials
```

To restart Google provider configuration even when Cognito reports it is
already configured, add `--reset` to `ensure-google`. This updates the existing
provider and prompts for the client ID and secret again; it does not recreate
the user pool:

```bash
deploy/aws/feednow-auth.sh --profile work --env prod ensure-google --reset
```

Production data resources use retention policies. Review the selected
`cdk diff` and CloudFormation changes before deployment; never infer the target
from a profile name or fall back to `prod`.

The deployed browser-session routes use an all-or-nothing set of seven Lambda
environment values: `FEEDNOW_COGNITO_AUTHORIZE_URL`,
`FEEDNOW_COGNITO_TOKEN_ENDPOINT`, `FEEDNOW_COGNITO_USERINFO_URL`,
`FEEDNOW_OAUTH_REDIRECT_URL`, `FEEDNOW_ALLOWED_RETURN_ORIGINS`,
`FEEDNOW_SESSION_TTL_SECONDS`, and `FEEDNOW_COOKIE_SECURE`. The CDK stack does
not set this optional set. A partial set fails startup; with no set, those
routes are not mounted. Removing the set does not provide first-login profile
data for bearer-only provisioning.

After a non-production deployment, the smoke script can exercise the deployed
API using explicit resource identifiers:

```bash
PYTHONPATH=. uv run python deploy/aws/smoke/smoke.py \
  --env dev --region <region> \
  --user-pool-id <CognitoUserPoolId> --client-id <CognitoClientId> \
  --api-url <ApiEndpoint> --table-prefix feednow-auth-dev-
```

A local test, CDK synthesis, or configuration review is not evidence of a
successful deployed login or production request.

## Administrator CLI

The operator CLI grants and revokes global application-admin status for an
existing user:

```bash
python -m feednow_auth.admin grant --email <address>
python -m feednow_auth.admin revoke --email <address>
```

`scripts/feednow-admin.sh` targets the running local Docker app and inherits its
configured storage backend by default, so local role changes are visible to the
API. AWS access requires an explicit standard AWS profile and FeedNow environment.
`--env` selects the matching `.env.<environment>` file; the script verifies the
profile identity against `AWS_ACCOUNT_ID` before any operation. The table prefix
is derived from the selected environment using the same naming rule as the CDK
stack:

```bash
scripts/feednow-admin.sh grant --email <address>
scripts/feednow-admin.sh --profile <aws-profile> --env dev list
scripts/feednow-admin.sh --profile <aws-profile> --env dev grant --email <address>
```

See `scripts/feednow-admin.sh --help` for the complete command syntax. Do not
pass credential values on command lines or log secrets.

## SQLite migrations

SQLite migrations are forward-only. Before upgrading a persistent local or
operator database, take a file-level backup and stop writers. To roll back a
failed migration, restore that backup; there is no automatic downgrade path.
See [storage.md](storage.md) for the current schema and migration boundary.

Before a forward-only schema change, stop writers and take a file-level
database copy. A cold or WAL-checkpointed copy is the rollback artifact. New
code can migrate the database in place; rollback requires restoring the
pre-migration copy because older code can reject a newer schema stamp.

## DynamoDB index changes

Deploy additive table/index infrastructure before code that depends on a new
index. If existing items need an index attribute, backfill it before relying
on index-based authorization decisions. Runtime code does not fall back to a
base-table scan. Keep additive indexes during code rollback unless a
separately reviewed cleanup removes them.

## AWS account application

The Lambda runtime composes the same account and authentication routes used by
the local Docker runtime over DynamoDB storage. CDK supplies the Cognito
authorize, token, and user-info endpoints, the HTTPS callback routed through
the account CloudFront `/api/*` behavior, the account return origin, and secure
cookie settings. The seven session inputs are therefore mandatory in a
deployed stack; an incomplete runtime configuration fails during cold start.

Application-wide administration uses the same storage contract and is
available in the AWS runtime. Its global summary/search and organization
cleanup operations require table-scoped DynamoDB `Scan`, `UpdateItem`, and
`DeleteItem` permissions. These permissions are not granted to the administrator CLI role.
Organization cleanup spans multiple DynamoDB writes; a failed cleanup leaves
the organization suspended and may require operator follow-up. Confirm this
behavior and recovery procedure before exposing the delete action to production
operators.

The account UI infrastructure is in the sibling `feednow-auth-ui` repository.
It provisions a private S3 origin and CloudFront OAC, forwards `/api/*` to the
backend HTTP API without caching, and rewrites only extensionless UI routes to
`index.html`. See that repository's `docs/deployment.md` for stack inputs and
upload steps.

## Operator AWS access

Run the administrator CLI with a separate restricted role scoped to the
environment-prefixed DynamoDB tables and required indexes. It needs user
resolution and application-role reads, conditional updates and transaction
checks, membership and organization reads for the audit anchor, and append-only
audit-event writes. It does not need `Scan`, Cognito, SSM, or pepper access. The Lambda execution role is a separate principal.

## Verification commands

```bash
uv run pytest -q --tb=short
uv run pytest src/tests/storage_contract -q
uv run ruff check .
uv run ruff format --check .
git diff --check
```

Report local checks, emulator-dependent checks, live Cognito journeys, and
deployed AWS checks separately. A green local suite does not establish live
provider or deployment behavior.
