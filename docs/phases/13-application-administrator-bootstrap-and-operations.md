# Current state: application administrator bootstrap and operations

Phase 13 is implemented and hermetically verified. Application-admin
promotion and revocation exist as a deliberate, out-of-band **CLI-only
bootstrap**: `python -m feednow_auth.admin grant|revoke --email <addr>`
runs an administration service over the `Storage` protocol, which hands one
caller-formed audit event to the new atomic
`transition_application_role` storage operation (both adapters). There is
**no** HTTP bootstrap route, no default administrator credential, no
environment-driven or startup-time promotion, and the deployed route
surface is unchanged (the frozen `/v1` manifest still holds ten routes).
The user must already be registered through the Cognito journey — the CLI
never provisions users. A server-side global-administrator dependency
exists for a future administration surface and is mounted on **no**
production route this phase.

## Scope

- `src/app/storage/contract.py`: `RoleTransitionOutcome`
  (`TRANSITIONED`/`NO_CHANGE`), frozen `RoleTransition(user, outcome)`, the
  additive `LastActiveAdministratorError(StorageError)`, and the 25th
  protocol method `transition_application_role` — the contract docstring
  **is** the storage-transition contract (no-op with zero writes and the
  audit event not persisted; last-ACTIVE-admin demotion refused fully
  rolled back; `TRANSITIONED` commits role CAS + audit append in one
  transaction; organizations-parent integrity when the audit names one;
  the closed two-value tripwire).
- `src/app/storage/sqlite.py`: the transition implementation (one
  transaction, `busy_timeout` serialization), `SCHEMA_VERSION` 3, and the
  forward-only `2 → 3` migration adding the non-unique
  `users_application_role_lookup` index.
- `src/app/storage/dynamodb.py`: the `users/by-application-role` GSI
  (`g_role`/`pk`), `g_role` written from the same value as
  `application_role` on every user item, and the transition as strong read
  → `by-application-role` witness `Query` → one `TransactWriteItems`
  (deterministic-witness `ConditionCheck`, CAS `Update`, audit `Put`,
  organizations-parent check) — concurrent last-pair revocations serialize
  with exactly one winner; a pre-backfill item is invisible to the guard
  and fails **closed**, never via `Scan`.
- `src/app/storage/factory.py` (new): CLI-facing `SqliteStorageSettings` /
  `DynamoDbStorageSettings`, `create_storage`, and the pure
  `storage_settings_from_env` (env names and fixed value-free messages in
  [Contracts](../contracts.md)); imports only `app.storage.*`, never
  `app.main`, Cognito, or pepper configuration.
- `src/app/services/administration.py` (new): `resolve_unique_user`,
  `grant_administrator`, `revoke_administrator`, the audit formation
  (`user.application_role.granted`/`.revoked`, metadata exactly
  `{"from_role", "to_role"}`, affected user as actor — the pinned
  out-of-band decision), the earliest-active-organization anchor, and the
  three service errors (`AdministratorNotFoundError`,
  `AmbiguousAdministratorEmailError`, `AdministratorAuditAnchorMissingError`
  — the last raised before any transition call).
- `src/app/auth/application_access.py` (new):
  `build_application_admin_dependency` — human + `ApplicationRole.ADMIN`
  only; every other outcome (ordinary humans and **every** API-key variant,
  including keys owned by admins) answers the same uniform 403 with one
  fixed message; denials are not audited at this seam; unmounted this
  phase.
- `src/feednow_auth/` (new wheel package): behavior-free `__init__.py` and
  `admin.py` (`main(argv) -> int` behind `python -m`; pinned exit-code
  table; import performs no I/O). `pyproject.toml` ships both `src/app`
  and `src/feednow_auth` in the wheel; no `[project.scripts]` entry.
- `deploy/aws/cdk/feednow_auth_stack.py`: the stack `_SCHEMA` mirrors the
  `by-application-role` index (field-for-field pin in
  `test_cdk_dynamodb.py`); `_DYNAMODB_GRANTS` is untouched — the `_SCHEMA`
  loop grants `Query` on every GSI ARN automatically, pinned by the
  `("users", "by-application-role") → {"Query"}` entry in `INDEX_MATRIX`
  (`test_cdk_iam.py`, accepted-Lambda-grant justification in its
  docstring).
- `deploy/docker/admin-cli-smoke.sh` (new) and
  [`../RUNNING_WITH_COGNITO.md`](../RUNNING_WITH_COGNITO.md) §10: the
  container proof and the operator `docker compose exec` form. The
  Dockerfile and Compose file are unchanged; the CLI ships via the image's
  `uv sync --frozen --no-dev` and is never invoked at startup.

## Contracts

The pinned current-state rules — transition semantics,
`LastActiveAdministratorError`, the two audit actions and their exact
metadata shape, the CLI exit-code contract, the factory env names, and the
dependency's uniform-403 rule — are recorded in the "Administration
boundary (Phase 13)" section of
[Contracts](../contracts.md); the administration pipeline and boundary
direction are in [Architecture](../architecture.md). This document does
not restate them.

## Operations

The operator runbook — the Docker exec command, SQLite forward-only
`2 → 3` migration ordering with restore-copy rollback, the DynamoDB
"CDK GSI first → code → one-time `g_role` backfill" order with
**code-only** rollback (keep the index online; never drop it as part of a
rollback), and the separately restricted operator IAM policy scoped to
exactly the CLI's DynamoDB path — is in
[Operations](../operations.md) ("Administrator CLI (Phase 13)").

## Verification

Evidence (2026-09-25):

- `uv run pytest -q` (default env, no Local endpoint) → **2055 passed,
  167 skipped** (the skips remain the DynamoDB Local gated cases). Two
  pre-existing third-party anyio/starlette deprecation warnings.
- With DynamoDB Local 2.6.0 running, `FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=
  http://localhost:8000 uv run pytest -q` → **2222 passed, 0 skipped** —
  the full suite including every gated case.
- Storage conformance: `uv run pytest src/tests/storage_contract -q` →
  86 passed (SQLite entry) without Local; with Local, **171 passed**
  (SQLite 86 + DynamoDB 85 entries). The suite gained the nine
  transition cases (no-op, refusal, rollback, parent-integrity, and
  disabled-admin paths) run identically against both adapters.
- DynamoDB transition parity and the race: with Local,
  `uv run pytest src/tests/integration/test_dynamodb_identity_ops.py -q`
  → **25 passed**, including
  `test_concurrent_double_revocation_of_the_last_pair_lets_exactly_one_win`
  (threaded; exactly one commit, the loser surfaces as
  `LastActiveAdministratorError` with zero mutation).
- Phase 13 focused set (factory, service, dependency, CLI, hygiene,
  isolation, contract surface) → 207 passed. Per-file:
  `test_storage_factory.py` 22, `test_administration_service.py` 12,
  `test_administration_sqlite.py` 6, `test_application_access.py` 11,
  `test_application_admin_dependency.py` 9 (human-admin/API-key denial
  matrix over a throwaway probe router), `test_admin_cli.py` 21 (parsing,
  idempotency wording, every exit code), `test_admin_cli_sqlite.py` 5
  (subprocess `python -m feednow_auth.admin` against a temp SQLite file),
  `test_audit_hygiene.py` 5 (the new Phase 13 sweep drives the real
  service pipeline and proves every `user.application_role.*` row carries
  only the pinned two-key metadata with no email/`sub`/token/auth-code
  material, and that no-ops and refusals write nothing).
- Container proof: `bash deploy/docker/admin-cli-smoke.sh` → **PASS**
  (seed via the storage API, `grant` exit 0 with `role=admin` read back
  in a separate container, repeat `grant` → `already granted` exit 0,
  last-admin `revoke` → exit 5); `docker compose --profile cognito config
  -q` validates; the Dockerfile and `docker-compose.yml` are untouched.
- Infrastructure: placeholder `cdk synth` (dev, `--quiet`) → exit 0; the
  assembly contains the `by-application-role` GSI on
  `feednow-auth-dev-users` and grants `dynamodb:Query` **only** on that
  index ARN; `test_cdk_dynamodb.py` (field-for-field `_SCHEMA` mirror) and
  `test_cdk_iam.py` (`INDEX_MATRIX` pin, transactional-action enclosing
  condition) are green on every default run.
- `uv run ruff format --check .` (175 files) and `git diff --check` clean.
  `uv run ruff check .` reports one **pre-existing** I001 in
  `deploy/docker/local_runtime.py` (the Phase 11 docs already record it as
  left for a separate chore change; it fires identically at the pre-Phase-13
  revision) plus unused-import F401s in `src/tests/unit/test_tokens.py`
  belonging to unrelated uncommitted work-in-progress; every file this
  phase touches is lint-clean (`ruff check` passes on each changed module).
- Two stale pins were corrected while getting the full suite green (both
  recorded here because they gate this phase's acceptance): the repo-wide
  DynamoDB AST-isolation scan now carries the documented narrow factory
  exception (the sanctioned `app.storage.factory` import of
  `open_dynamodb_storage`; the `boto3`/`botocore` ban is unchanged), and
  the gated DynamoDB runtime-checkable method-count pin moved 24 → 25
  with the new protocol method.
- **Not performed (pending operator execution):** the live-AWS checks —
  running the one-time `g_role` backfill and the CLI grant/revoke against
  a deployed stack under the operator IAM role, and the
  `docker compose --profile cognito exec` journey against live Cognito
  registrations. These need operator AWS credentials and a deployed
  environment, so the runbook sections above are recorded as the
  procedure, not as completed evidence. Until they are executed and their
  results recorded here, the phase's **operational acceptance on live AWS
  remains open**.

## Non-goals honored

No HTTP bootstrap endpoint or admin UI, no automatic or startup-time
promotion, no API-key privilege inheritance (keys stay roleless), no
change to organization-local membership administration, no new `/v1`
route (manifest frozen), no audit read surface (Phase 08), and no
Shopify features.

## Known limitations

- The global-admin dependency is unmounted (there is no administration
  HTTP surface yet); its denials are structurally unaudited until a
  mounting phase defines the `operation_id`.
- Out-of-band audit attribution: transition rows record the **affected
  user** as actor because the CLI carries no operator identity; forensic
  operator attribution needs an authenticated admin surface (future
  phase).
- On DynamoDB, pre-backfill items are invisible to the `by-application-role`
  guard until the operator backfill runs; the failure mode is fail-closed
  refusal (`LastActiveAdministratorError`), never a wrongly-allowed
  demotion.
- SQLite rollback is restore-based only (forward-only migrations);
  operators must take the pre-migration file copy.
- The Lambda execution role carries the accepted `Query` grant on
  `by-application-role` (mirror-invariant consequence, justified in the
  `INDEX_MATRIX` docstring); excluding it would fork the field-for-field
  `_SCHEMA` pin.

## Published interfaces (what later phases code against)

| Interface | Module | Consumers |
| --- | --- | --- |
| `transition_application_role` + `RoleTransition`/`RoleTransitionOutcome` + `LastActiveAdministratorError` | `src/app/storage/contract.py` | any future role-change path (must go through this one operation) |
| `resolve_unique_user`, `grant_administrator`, `revoke_administrator` + the three service errors | `src/app/services/administration.py` | any future authenticated administration surface |
| `build_application_admin_dependency` + `APPLICATION_ADMIN_FORBIDDEN_MESSAGE` | `src/app/auth/application_access.py` | future admin HTTP routes (uniform-403 rule frozen) |
| `storage_settings_from_env` / `create_storage` + settings dataclasses | `src/app/storage/factory.py` | CLI and tooling entrypoints |
| `python -m feednow_auth.admin` exit-code contract | `src/feednow_auth/admin.py` | operators and container runbooks |
| `user.application_role.granted` / `.revoked` audit actions (`{"from_role","to_role"}`) | `src/app/services/administration.py` | future audit read/reporting work (Phase 08) |
