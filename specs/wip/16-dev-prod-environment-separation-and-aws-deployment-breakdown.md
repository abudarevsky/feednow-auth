# Phase 16 — Dev/prod environment separation and AWS deployment

**Status:** active; authorized by the user on 2026-10-01 after Phase 15 moved to `specs/done/`.

## Entry decisions and prerequisites

- AWS baseline verified read-only on 2026-10-01: only profile `default` is
  configured; it resolves to account `495599767705` as the root principal in
  `eu-north-1`. Do not deploy with that principal; identify/configure a
  deployment-role profile and verify its account before any mutation.
- The account currently has no Route 53 hosted zones and no issued ACM
  certificate in `us-east-1`, so the requested `account.feednow.io` custom
  domain cannot yet be attached to CloudFront.
- Existing dev Cognito pool/client/domain and Google trigger were inspected.
  The CDK dev path imports the existing pool/client so their current ownership
  and settings are preserved.
- The user selected a KMS-encrypted API-key pepper supplied in Lambda
  configuration. Plaintext stays in the operator process; only KMS ciphertext
  is passed to Lambda and retained in the ignored environment file. Do not
  store application secrets in SSM Parameter Store or Secrets Manager.
- Supply or verify production Google OAuth credentials and callback
  registration. The operator accepts the secret through a hidden prompt and
  does not print or persist it.
- Phase 15 is in `specs/done/`. Coordinated production deployment remains
  blocked until a non-root profile, Route 53 zone, issued `us-east-1` ACM
  certificate, production env config, and Google OAuth credentials can be
  verified.

## Build steps

### Step 1 — Capture the existing development AWS baseline

- **Scope:** inspect the deployed dev stack and Cognito pool/client; compare the
  actual resources with the current CDK definition; record stable identifiers
  and replacement-sensitive properties without changing AWS resources.
- **Files/boundaries:** backend `deploy/aws/cdk/`, backend CDK tests, and the
  phase handoff. Keep `run-dev.sh` behavior intact.
- **Focused checks:** backend CDK tests for environment names, resource
  identity, and replacement-sensitive properties.
- **Handoff checks:** synth and a read-only `cdk diff` using the verified AWS
  profile; confirm no unexpected dev pool/client replacement. Record actual
  caller account and region, and distinguish unavailable live checks.
- **Migration/rollback:** no resource changes; no rollback required.
- **Non-goal:** deploying or mutating any environment.

### Step 2 — Add explicit environment and profile resolution

- **Scope:** parameterize CDK and admin/deployment entry points for `dev`,
  `staging`, and `prod`; load only `.env.<env>`; pass `--profile` through
  standard AWS CLI/CDK credential resolution; fail closed for missing config,
  invalid identity, or account mismatch. Keep `run-dev.sh` local-only.
- **Files/boundaries:** backend `scripts/feednow-admin.sh`, new or extended
  `deploy/aws/deploy.sh`, `deploy/aws/cdk/app.py`, CDK environment model,
  ignored env files/example, focused backend tests; preserve UI deployment
  boundary and API route semantics.
- **Focused checks:** tests with mocked AWS CLI/CDK that prove profile and
  environment are independent and all unsafe/missing-input paths fail closed.
- **Handoff checks:** backend full suite and CDK synth for each configured
  environment; shell syntax/help checks; UI `npm run check` and E2E where UI
  behavior changes.
- **Migration/rollback:** no deployed-resource change until a later approved
  step; restore previous scripts/config selection if reverted.
- **Non-goal:** creating production resources or silently using `prod` as a
  fallback.

### Step 3 — Isolate runtime data and supply KMS-encrypted pepper ciphertext

- **Scope:** give each environment distinct Cognito, DynamoDB tables, API-key
  pepper material, and runtime configuration; implement the approved
  KMS-encrypted Lambda environment value and a secure Cognito Google credential
  rotation command. Preserve dev users and data.
- **Files/boundaries:** backend CDK, runtime pepper provider, Lambda IAM,
  Cognito operations, documentation, and tests. Do not put credentials in
  `.env.<env>`, Git, Docker layers, logs, or ordinary outputs.
- **Focused checks:** storage/runtime unit tests, CDK assertions for distinct
  names and least privilege, secret-redaction tests, and CLI tests proving
  profile/environment resolution.
- **Handoff checks:** backend full suite, CDK synth for all environments,
  secret scan of the intended diff, and verified dev diff showing no pool or
  client replacement.
- **Migration/rollback:** plan an explicit pepper continuity/rotation strategy
  before deploying; rollback must preserve API-key validation for existing
  keys and must not delete retained production data.
- **Non-goal:** migrating dev users or sharing API keys/data across environments.

### Step 4 — Deploy the production backend and account UI

- **Scope:** deploy isolated prod Cognito and application resources, then the
  private S3/CloudFront account UI at `account.feednow.io`, with same-origin
  API forwarding and production data isolation.
- **Files/boundaries:** backend CDK and smoke tooling; UI CloudFormation,
  deployment script, and deployment docs. Use same-origin `/api/*` and retain
  API failure status/content type.
- **Focused checks:** backend and UI infrastructure assertions plus deployment
  script tests with mocked AWS calls.
- **Handoff checks:** verify profile identity against the env file before any
  change; review `cdk diff`/CloudFormation change set; run deployed non-prod
  smoke first; then production HTTPS/direct-route/API-edge checks and real
  Cognito login only after the required user credentials/domain inputs exist.
- **Migration/rollback:** retain production data resources; document stack
  rollback and UI artifact rollback/invalidation procedure before deployment.
- **Non-goal:** production administrator bootstrap or Vispector integration.

### Step 5 — Authentication, administrator bootstrap, and Vispector handoff

- **Scope:** verify production Google federation and callback/logout URLs,
  register the first account through normal sign-in, grant/revoke admin with
  the existing CLI, and connect Vispector to production API-key validation.
- **Files/boundaries:** backend operations/smoke docs and Vispector integration
  contract; no hard-coded production superuser or cross-environment key.
- **Focused checks:** CLI unit tests and non-production authentication/API-key
  smoke tests.
- **Handoff checks:** documented live production login/logout, admin list and
  grant verification, production key acceptance, dev-key rejection, and
  tested account/Vispector return-URL allowlist. Report each live check
  separately from local/synth evidence.
- **Migration/rollback:** revoke only the explicitly selected test/admin key;
  preserve unrelated production identities and data.
- **Non-goal:** staging deployment, user migration, or redesign of permissions.
