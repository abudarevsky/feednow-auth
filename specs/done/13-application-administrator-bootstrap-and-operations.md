# 13 — Application administrator bootstrap and operations

**Status:** draft — no implementation is authorized.  
**Depends on:** 12-cognito-shadow-registration-and-application-role.

## Scope

Implement deliberate application-admin promotion and revocation only after a
person has registered and authenticated through Cognito. The bootstrap
interface is the required CLI:

```bash
python -m feednow_auth.admin grant --email admin@example.com
python -m feednow_auth.admin revoke --email admin@example.com
```

There is no public HTTP bootstrap endpoint, default administrator credential,
environment-driven promotion, startup action, or deployment hook.

## Required behavior

1. An administration service over `Storage`, not HTTP, resolves exact email to
   exactly one internal user. Zero matches is missing; multiple matches is
   ambiguous; neither result mutates storage.
2. `grant` promotes an existing user to `admin`; granting an existing admin is
   idempotent. `revoke` demotes an admin to `user`; revoking an existing user
   is idempotent.
3. A revoke that removes the final active administrator is refused. The active
   admin check and transition must be one concurrency-safe adapter operation,
   not CLI check-then-write logic.
4. Add a minimal `feednow_auth` package/CLI shim and packaging update because
   the current package is `app`, while the required invocation is
   `python -m feednow_auth.admin`. Import has no I/O or credential lookup.
5. One explicit storage factory supports SQLite, DynamoDB Local, and AWS
   DynamoDB via selected path/endpoint/region/table-prefix configuration. It
   does not construct the web app, call Cognito, or read Cognito secrets.
6. A server-side global-admin dependency accepts only human principals with
   `ApplicationRole.ADMIN`; every API key fails, including keys owned by admins.
   Existing organization membership administration retains its separate
   org-local role policy.
7. Actual role transitions have reviewed audits with no email, Cognito subject,
   authorization code, or token. No-op commands do not create duplicate audits.

## Docker and AWS operations

- Support local use after first-login provisioning, for example:
  `docker compose --profile cognito exec app python -m feednow_auth.admin grant --email ...`.
- Include the CLI in the container without running it at startup.
- Document AWS use with a separately restricted operator IAM role. Do not add
  administrative permissions to the Lambda execution role unless runtime
  behavior needs them.
- Update DynamoDB index/IAM CDK assertions and operator runbook. Deployment and
  container startup must not alter administrator roles.

## Acceptance tests

- CLI parsing/output and idempotent grant/revoke.
- Missing/ambiguous email rejection; user must already exist.
- Last-active-admin refusal, including concurrent revocation attempts.
- SQLite/DynamoDB adapter parity and DynamoDB Local coverage.
- Human-admin success; ordinary humans and all API-key variants denied.
- Container CLI smoke with seeded data, Compose validation, CDK synth/IAM
  assertions, and separately recorded live Cognito/AWS checks.

## Handoff and non-goals

Before WIP, specify storage-transition semantics, CLI exit/error contract,
migration release ordering, Docker command, AWS IAM policy, rollback behavior,
and focused/full test commands. This phase does not create UI account
management, API-key privilege inheritance, Shopify features, or automatic
administrator bootstrap.
