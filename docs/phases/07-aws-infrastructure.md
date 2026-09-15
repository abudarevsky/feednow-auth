# Current state: AWS infrastructure and deployable runtime

Phase 07 is implemented. An environment-parameterized Python CDK app under
`deploy/aws/cdk` provisions the full runtime: a Cognito user pool with a
public PKCE app client and hosted domain, the seven Phase 06 DynamoDB tables
(transcribed verbatim from the adapter `SCHEMA`), a Secrets Manager-generated
API-key pepper, a least-privilege Lambda execution role matching the Phase 06
IAM matrix exactly, the runtime Lambda (the task-5 composition root, bundled
without Docker), and an HTTP API with redaction-safe access logs. `src/app`
is unchanged: the deployment entrypoint is the only code that knows AWS SDKs
exist, so the repo-wide no-`boto3` proof stays green. A non-production smoke
script proves the deployed path end to end. No automatic production
deployment, no audit read surface (Phase 08), no Google/Microsoft/SAML
federation.

## Scope

- `deploy/aws/cdk/app.py`: entrypoint — loads the non-committed
  `deploy/aws/cdk/.env` without overriding the shell, requires the four
  inputs below, synthesizes `FeedNowAuthStack` bound to an explicit
  `cdk.Environment(account, region)`.
- `deploy/aws/cdk/cdk.json` (`{"app": "python3 app.py"}`),
  `deploy/aws/cdk/requirements.txt` (pins `aws-cdk-lib==2.260.0`,
  `constructs==10.6.0`; both also in the pyproject dev group so the
  assertion tests run under `uv run pytest`), `deploy/aws/cdk/.env.example`
  (placeholders only — no account ids, no secret material).
- `deploy/aws/cdk/feednow_auth_stack.py`: `FeedNowAuthEnv` (validates
  `FEEDNOW_ENV`, single source of every derived name) and the stack
  (tables, Cognito, pepper secret, IAM role, Lambda, HTTP API, access logs).
- `deploy/aws/lambda-requirements.txt`: Lambda payload pins (`fastapi`,
  `pydantic`, `pyjwt[crypto]`, `boto3`, `mangum`).
- `deploy/aws/runtime/handler.py`: composition root — import-safe (no env
  reads, no AWS I/O at import); everything happens in `build_app` on the
  first invocation via a lazy ASGI proxy; `handler = Mangum(app)`.
- `deploy/aws/runtime/secrets_pepper.py`: `SecretsManagerPepper` — the
  Phase 05 `PepperSource` seam's AWS implementation at the deployment
  entrypoint; one `GetSecretValue` per container, ≥32-byte floor, value
  never rendered in `repr`/`str`/errors.
- `deploy/aws/smoke/smoke.py`: non-production deployed smoke (below).
- `src/tests/unit/test_cdk_app.py`, `test_cdk_dynamodb.py`,
  `test_cdk_cognito.py`, `test_cdk_iam.py`, `test_cdk_lambda_api.py`,
  `test_runtime_handler.py`, `test_smoke_script.py`: 210 assertion tests.

## Deployment inputs (names only)

Four required, non-secret inputs, each supplied either in the shell or in
`deploy/aws/cdk/.env` (shell wins; `.env` and `cdk.out/` are gitignored):

| Input | Meaning |
| --- | --- |
| `FEEDNOW_ENV` | target environment: `dev`, `staging`, or `prod` (case-sensitive) |
| `CDK_DEFAULT_ACCOUNT` | 12-digit AWS account id to deploy into |
| `AWS_REGION` | deployment region |
| `COGNITO_CALLBACK_URLS` | comma-separated HTTPS OAuth callback/logout URIs for the Cognito client; required at synth time because CDK validates redirect URIs — the stack refuses to synthesize when empty |

`FEEDNOW_ENV` derives every physical name, so environments can never
collide: stack `FeedNowAuth-<env>`, table prefix `feednow-auth-<env>-`,
Cognito client and domain prefix `feednow-auth-<env>`, pepper secret
`feednow-auth/<env>/api-pepper`, Lambda function and HTTP API name
`feednow-auth-<env>`, execution role `feednow-auth-<env>-lambda`.

No deployment input reaches application runtime configuration directly; the
only bridge is the five stack-set Lambda environment variables below.

## CDK synth and deploy commands

Prerequisites for the synth path: Node available to `npx`, a `python3` on
PATH with `pip install -r deploy/aws/cdk/requirements.txt` applied (cdk.json
runs `python3 app.py`), and `uv` on PATH with network access for the
Docker-free local bundling (`uv pip install` of manylinux wheels).

Immediate placeholder synth — runs as written, from `deploy/aws/cdk`:

```bash
FEEDNOW_ENV=dev CDK_DEFAULT_ACCOUNT=123456789012 AWS_REGION=eu-north-1 \
  COGNITO_CALLBACK_URLS=https://example.invalid/callback \
  npx -y aws-cdk@2 synth --quiet
```

Deploy and destroy per environment — from `deploy/aws/cdk`, substituting the
`<...>` placeholders with real account/region/URI values (or after copying
`.env.example` to `.env` and filling it in, dropping the inline prefix
entirely):

```bash
# dev
FEEDNOW_ENV=dev CDK_DEFAULT_ACCOUNT=<account-id> AWS_REGION=<region> \
  COGNITO_CALLBACK_URLS=<https://.../callback> \
  npx -y aws-cdk@2 deploy FeedNowAuth-dev
FEEDNOW_ENV=dev CDK_DEFAULT_ACCOUNT=<account-id> AWS_REGION=<region> \
  COGNITO_CALLBACK_URLS=<https://.../callback> \
  npx -y aws-cdk@2 destroy FeedNowAuth-dev

# staging
FEEDNOW_ENV=staging CDK_DEFAULT_ACCOUNT=<account-id> AWS_REGION=<region> \
  COGNITO_CALLBACK_URLS=<https://.../callback> \
  npx -y aws-cdk@2 deploy FeedNowAuth-staging
FEEDNOW_ENV=staging CDK_DEFAULT_ACCOUNT=<account-id> AWS_REGION=<region> \
  COGNITO_CALLBACK_URLS=<https://.../callback> \
  npx -y aws-cdk@2 destroy FeedNowAuth-staging

# prod
FEEDNOW_ENV=prod CDK_DEFAULT_ACCOUNT=<account-id> AWS_REGION=<region> \
  COGNITO_CALLBACK_URLS=<https://.../callback> \
  npx -y aws-cdk@2 deploy FeedNowAuth-prod
```

`destroy` is deliberately not offered for prod (see rollback notes).
Stack outputs (`CognitoUserPoolId`, `CognitoIssuerUrl`, `CognitoClientId`)
and the HTTP API endpoint are read from the repo root with operator
credentials:

```bash
aws cloudformation describe-stacks --stack-name FeedNowAuth-dev \
  --query "Stacks[0].Outputs"
aws apigatewayv2 get-apis \
  --query "Items[?Name=='feednow-auth-dev'].{id:ApiId,url:ApiEndpoint}"
```

## Runtime configuration keys and injection path

The task-6 `Function` sets exactly five environment variables, every value
stack-derived (names and ids only — never secret material); the task-5
handler reads them **at cold start, never at import**
(`RuntimeConfig.from_environ`), and a missing/blank key fails the first
invocation with a message naming the missing keys and nothing else:

| Key | Stack-derived value | Consumed by |
| --- | --- | --- |
| `FEEDNOW_DYNAMODB_REGION` | deployment region | `open_dynamodb_storage(region=...)` |
| `FEEDNOW_TABLE_PREFIX` | `feednow-auth-<env>-` (the table names' prefix) | `open_dynamodb_storage(table_prefix=...)` |
| `FEEDNOW_COGNITO_ISSUERS` | pool issuer URL via `Fn::Sub` (`https://cognito-idp.<region>.amazonaws.com/<pool-id>`) | `CognitoJwksSource` / `CognitoAccessTokenVerifier` allowlist |
| `FEEDNOW_COGNITO_CLIENT_IDS` | user pool client id | verifier audience allowlist |
| `FEEDNOW_PEPPER_SECRET_ID` | pepper secret **name** (`feednow-auth/<env>/api-pepper`) | `SecretsManagerPepper`: one `GetSecretValue` at cold start, parses the JSON `pepper` field, enforces the ≥32-byte floor |

Cold start also forces the single pepper read before serving (`build_app`
calls `pepper_source.current()`), so a bad deployment fails on the
invocation, not on a customer request.

## Non-production deployed smoke

Prerequisite: a deployed dev (or staging) stack from the commands above.
The script takes operator AWS credentials from the standard chain and only
ids as inputs (stack outputs plus the table prefix):

```bash
PYTHONPATH=. uv run python deploy/aws/smoke/smoke.py \
  --env dev --region <region> \
  --user-pool-id <CognitoUserPoolId> --client-id <CognitoClientId> \
  --api-url <ApiEndpoint> \
  --table-prefix feednow-auth-dev-
```

Proof path, executed in exactly this order: `sign_up` a random throwaway
`smoke+<ts>@example.com` → `admin_confirm_sign_up` →
`initiate_auth(USER_PASSWORD_AUTH)` for an access token → `GET /v1/me`
bearer call asserting HTTP 200 and a `usr_`-prefixed id → `GetItem` the
`external_identity#cognito#<sub>#` row on `<prefix>unique_constraints` (must
map to the same user) → `GetItem` the `<prefix>users` row → `Query` the
`<prefix>memberships` `by-user` GSI (exactly one default-tenancy row yields
the `organization_id`) → `GetItem` the `(organization_id, user_id)` pair
(active, `owner`). It prints only ids and a `SMOKE PASS env=<env>` line —
never tokens, passwords, or key material — and refuses `--env prod` unless
`--force` is passed explicitly.

## Verification

Evidence (2026-09-15):

- `PYTHONPATH=. uv run pytest -q` → **1537 passed, 134 skipped** (Phase 06
  baseline 1327 + 210 Phase 07 unit assertions: cdk_app 21, cdk_dynamodb 10,
  cdk_cognito 46, cdk_iam 45, cdk_lambda_api 39, runtime_handler 37,
  smoke_script 12; the 134 skips remain the DynamoDB Local gated cases). Two
  pre-existing third-party deprecation warnings from the starlette/fastapi
  testclient stack (the `httpx` backend and the `anyio` `BlockingPortal`
  alias).
- Dev synth run as written above from `deploy/aws/cdk` → exit 0, no Docker;
  synthesized `FeedNowAuth-dev.template.json` contains exactly 7
  `AWS::DynamoDB::Table`, one each of UserPool/UserPoolClient/UserPoolDomain/
  Secret/IAM Role/IAM Policy/Lambda Function/HttpApi/Stage/Integration/
  LogGroup, 2 routes + 2 invoke permissions, and the three Cognito outputs.
- Smoke proofs: the 12 `test_smoke_script.py` cases pin the exact call
  sequence, keys, and prefixes against fake seams and prove (via capsys) no
  token/password literal appears in output; a live `--env prod` invocation
  exits 1 with the fixed refusal message and zero AWS calls (guard runs
  before any seam binds).
- `PYTHONPATH=. uv run ruff check .` and `uv run ruff format --check .`
  (158 files) clean; `uv run ruff check deploy/aws/smoke` clean;
  `git diff --check` clean excluding the user-owned `AGENTS.md` (which stays
  dirty in the working tree by the phase precondition).
- **Not performed:** a deployed dev/staging smoke run against a real AWS
  account — it needs operator credentials and a live stack, so the command
  above is recorded as the procedure, not as completed evidence.

## Rollback-safe operational notes

- **Stack delete semantics differ per environment.** dev/staging tables,
  user pool, and pepper secret are `RemovalPolicy.DESTROY`: `cdk destroy`
  removes the data with the stack (acceptable for throwaway environments).
  prod tables, user pool, and pepper secret are `RETAIN`: `cdk destroy
  FeedNowAuth-prod` (or a rollback of a failed prod deploy) leaves all seven
  tables, the pool, and the secret in place — data and credentials survive;
  a CloudFormation rollback never deletes retained prod tables.
- **Re-deploying prod after a destroy collides by design.** The retained
  tables keep their physical names (`feednow-auth-prod-<table>`), so a fresh
  `deploy FeedNowAuth-prod` fails on name conflict. Recovery is a
  CloudFormation resource import of the retained tables or a deliberate new
  prefix — never a deletion of the retained tables.
- **Never delete the prod pepper secret.** Every stored `secret_hash` is an
  HMAC over that value; losing it invalidates all API credentials at once.
  Rotation requires a dual-pepper window and is a **Phase 08** concern —
  see `docs/phases/06-dynamodb.md` for the credential digest contract.
- Re-deploy is idempotent for unchanged inputs (no-op); the access-log group
  is `DESTROY` in every environment (1-week retention) since it carries only
  request id/method/path/status/latency.

## Known limitations

- The deployed smoke run is pending an operator execution against a real
  dev/staging stack (see Verification); only the synth/deploy path and the
  hermetic proofs are recorded green today.
- The HTTP API endpoint URL is not a stack output; read it via
  `aws apigatewayv2 get-apis` (command above) or the console.
- Cognito email uses the pool's default email templates (no custom SES
  sender) — fine for dev/staging; a verified-sender configuration is a
  Phase 08+ operational hardening candidate, along with alarms, WAF, and
  capacity tuning.
- Bundling requires `uv` and network access at synth time; the Docker
  fallback declared in the bundling options never runs while local
  bundling succeeds.

## Published interfaces (what Phase 08 code against)

| Interface | Module | Consumers |
| --- | --- | --- |
| `FeedNowAuthEnv` (validated env + every derived name) and `FeedNowAuthStack` (exposes `table_prefix`, `user_pool*`, `pepper_secret`, `lambda_role`, `runtime_function`, `http_api`) | `deploy/aws/cdk/feednow_auth_stack.py` | Phase 08 stack additions (audit read surface, hardening) |
| The five `FEEDNOW_*` key constants (`LAMBDA_*_ENV`, pinned against the handler's `REQUIRED_ENV_KEYS`) and `API_ACCESS_LOG_FORMAT` | `deploy/aws/cdk/feednow_auth_stack.py` | any new runtime configuration must extend both sides in one change |
| `RuntimeConfig.from_environ` + `build_app(environ=..., *_factory=...)` seams; `API_STAGE` (`$default`) | `deploy/aws/runtime/handler.py` | Phase 08 router additions go through `build_app` |
| `SecretsManagerPepper` (secret name env key, JSON `pepper` field, ≥32-byte floor) | `deploy/aws/runtime/secrets_pepper.py` | Phase 08 pepper rotation |
| Smoke seams (`cognito_client`, `http_get`, `dynamodb_resource`) + prod guard | `deploy/aws/smoke/smoke.py` | Phase 08 smoke extensions (audit read, key lifecycle) |
| Stack outputs `CognitoUserPoolId` / `CognitoIssuerUrl` / `CognitoClientId` | synthesized template | operators and the smoke inputs |
