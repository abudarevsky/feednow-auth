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
session verification is component-level only. Phase 13 adds the
out-of-band administration path — the `python -m feednow_auth.admin` CLI,
the administration service, the atomic `transition_application_role`
storage operation on both adapters, and the (unmounted) global-admin
dependency — with **no** new HTTP route: the deployed route surface is
unchanged and the frozen `/v1` manifest still holds ten routes. The
administrator runbook (Docker exec, migration ordering, rollback, and the
operator IAM policy) is below. The service still does not
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

## Administrator CLI (Phase 13)

The only administrator-bootstrap interface is the operator CLI; the
contract (semantics, exit codes, env names) is pinned in
[docs/phases/13-application-administrator-bootstrap-and-operations.md](phases/13-application-administrator-bootstrap-and-operations.md).
The user must already exist (registered through the Cognito journey) —
the CLI never provisions users.

Against the local Cognito composition (app service running; full
procedure in [RUNNING_WITH_COGNITO.md](RUNNING_WITH_COGNITO.md) §10):

```bash
cd deploy/docker
docker compose --profile cognito exec app \
  python -m feednow_auth.admin grant --email admin@example.com
docker compose --profile cognito exec app \
  python -m feednow_auth.admin revoke --email admin@example.com
```

The exec'd process inherits the app container's environment; ensure
`FEEDNOW_STORAGE_BACKEND` (and the backend-specific variables, see the
phase doc) are present in `deploy/docker/.env` — the CLI derives storage
solely through `app.storage.factory`. Exit codes: `0` success (stdout
distinguishes `granted` / `already granted` / `revoked` / `already
revoked`), `1` unexpected failure, `2` usage or unusable storage
configuration, `3` no user for that email, `4` ambiguous email, `5`
last-active-admin refusal. `deploy/docker/admin-cli-smoke.sh` proves the
whole sequence inside the container (seed, grant, repeat grant, last-admin
revoke) against a per-run SQLite file on the `/data` volume. Deployment
and container startup never run the CLI and no environment-driven or
startup-time promotion exists.

### Migration release ordering

**SQLite (forward-only `2 → 3`).** The phase-13 schema adds the
non-unique `users_application_role_lookup` index and stamps
`PRAGMA user_version = 3`. Release order:

1. Take a **file copy of the SQLite database before deploying** (cold or
   WAL-checkpointed). This copy is the only rollback artifact.
2. Deploy the new code; the first open migrates `2 → 3` in place
   (data-retaining).
3. **Rollback = restore the pre-migration file copy.** Pre-phase-13 code
   rejects an unrecognized stamp loudly (a `user_version = 3` file is
   neither its current version nor a known migration key), so restoring
   the copy is mandatory — there is no downgrade migration and pre-13
   code must never be pointed at the migrated file.

**DynamoDB (additive; order matters).**

1. **CDK first:** deploy the stack delta that adds the
   `users/by-application-role` GSI (`g_role`/`pk`). GSI creation is
   online; tables are never replaced.
2. **Code second:** deploy the phase-13 runtime. New/updated user items
   carry `g_role` from this point (the CAS write always rewrites it from
   the same value as `application_role`, so the index can never lag).
3. **One-time `g_role` backfill** (operator obligation, not a runtime
   behavior): scan the users table once and set `g_role` =
   `application_role` on every item that lacks it — items predating
   Phase 12 have no `application_role` attribute and backfill to
   `'user'`. Until an item is backfilled it is **invisible** to the
   `by-application-role` index, so the active-admin guard can see too few
   admins; that fails **closed** to `LastActiveAdministratorError` (a
   demotion is refused, never wrongly allowed) and the adapter never
   falls back to a `Scan`. Run the backfill before relying on revokes.
4. **Rollback is code-only:** the `by-application-role` GSI and the
   `g_role` attribute are purely additive and ignored by pre-phase-13
   code, so **keep the index online on rollback and never drop it as
   part of a rollback** (index removal is a separate, deliberate cleanup
   decision) — the documented equivalent of Phase 12's pinned "GSI add
   is online and reversible" statement.

### Operator IAM policy (AWS)

The CLI runs **outside** Lambda under a separately restricted operator
role — it is deliberately **not** added to the Lambda execution role,
and carries no pepper/Secrets Manager/Cognito access. The policy is
scoped to exactly the CLI's DynamoDB path (email resolution + audit-anchor
read + transition), on the environment-prefixed table ARNs (e.g.
`feednow-auth-<env>-users`):

| Resource | Actions | Why |
| --- | --- | --- |
| `users` (base table) | `GetItem`, `Query`, `UpdateItem`, `ConditionCheckItem` | target read, CAS update, in-transaction checks (base `Query` is required because GSI reads authorize against the base ARN too, per the stack's own comment) |
| `users/by-email` (index) | `Query` | the service's `list_users_by_email` resolution |
| `users/by-application-role` (index) | `Query` | the active-admin guard |
| `memberships` (base) + `memberships/by-user` (index) | `Query` | the audit-anchor `list_user_organizations` read |
| `organizations` | `BatchGetItem`, `ConditionCheckItem` | anchor read reassembly + the transition's in-transaction parent check |
| `audit_events` | `PutItem` **only** | audit is append-only and no adapter operation ever reads it — no `GetItem`/`Get` grant |

No `Scan`, no writes to `organizations`/`memberships`, no other table
touched. Separately, the Lambda execution role gained exactly one
accepted read: mirroring the `by-application-role` index into the stack
`_SCHEMA` extends it with `Query` on that index even though no Lambda
code path queries it (the transition is CLI-only); this is accepted
because the grant exposes no data the role cannot already read (base-table
`GetItem`/`Query` on the same `users` items are already granted) and
excludes nothing writable, while an exclusion mechanism would fork the
`_SCHEMA` mirror invariant pinned field-for-field by
`src/tests/unit/test_cdk_dynamodb.py` (justification recorded in the
`INDEX_MATRIX` docstring of `src/tests/unit/test_cdk_iam.py`).

## Verification

```bash
uv run pytest -q --tb=short                       # default env: DynamoDB Local cases skip by name
uv run pytest src/tests/storage_contract -q       # SQLite conformance entry (86)
uv run ruff check .
uv run ruff format --check .
git diff --check

# Phase 13 focused (storage transition, factory, service, dependency, CLI, hygiene):
uv run pytest src/tests/unit/test_storage_contract.py \
  src/tests/unit/test_sqlite_identity_ops.py src/tests/unit/test_storage_factory.py \
  src/tests/unit/test_administration_service.py src/tests/integration/test_administration_sqlite.py \
  src/tests/unit/test_application_access.py src/tests/integration/test_application_admin_dependency.py \
  src/tests/unit/test_admin_cli.py src/tests/integration/test_admin_cli_sqlite.py \
  src/tests/integration/test_audit_hygiene.py -q

# With DynamoDB Local running (see above):
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest -q                                # full suite, gated cases included
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest src/tests/storage_contract -q     # both adapter entries (86 + 85)
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest src/tests/integration/test_dynamodb_identity_ops.py -q  # transition parity + race
```

Report test results, third-party warnings, environment blocks, and any
unperformed remote or deployment checks separately.
