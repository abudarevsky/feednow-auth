# 12 — Cognito shadow registration and application role

**Status:** draft — no implementation is authorized.  
**Depends on:** 11-cognito-authentication-profile-and-session-boundary.  
**Unblocks:** 13-administrator-bootstrap.

## Baseline and gap

`app.services.identity.resolve_or_provision` resolves immutable
`(cognito, sub, None)`, creates a user/external identity/personal organization/
owner membership atomically through `Storage.provision_user`, and converges
concurrent first logins by re-reading the identity tuple. API keys are already
owned by internal `usr_` IDs and authenticate independently of Cognito.

However, `User` has no global application role; email is unique in both
adapters; and a duplicate email for a different Cognito `sub` is a conflict.
`MembershipRole.ADMIN` is organization local and cannot be reused as global
FeedNow administration.

## Scope and invariants

1. Add `ApplicationRole.USER` and `ApplicationRole.ADMIN` to `User`; keep it
   completely separate from `MembershipRole`.
2. A first verified login creates exactly one active internal user with role
   `user`, its immutable Cognito identity, and the existing personal-org/owner
   membership batch. Cognito `sub` never becomes an application identifier.
3. Repeat or concurrent same-identity logins reuse the existing user. They do
   not overwrite global role, status, email, subscriptions, quotas, API keys,
   memberships, or audits.
4. Equal emails for different Cognito subjects are valid separate users. The
   identity tuple is the only automatic convergence key; explicit linking is
   out of scope.
5. Email becomes a non-unique exact-lookup field. Consumers must handle
   zero/one/many results explicitly rather than guessing.
6. Add ordered SQLite migrations to backfill `application_role='user'` and
   replace the unique email constraint with a non-unique index while retaining
   data. Add DynamoDB role persistence and non-unique email access path, with
   CDK schema and least-privilege IAM updates. Never replace tables.
7. API-key principal contexts remain roleless. An administrator-owned key does
   not inherit the owner's global role.

## Required implementation areas

- `User`, enum, codecs, storage contract, SQLite schema/migrations, DynamoDB
  item/index definitions, adapter parity tests, and CDK assertions.
- Exact-email list/resolve storage operation, not a generic adapter query API.
- `build_provisioning_batch` and `resolve_or_provision` consume Phase 11's
  verified profile while preserving the one-batch transaction and identity
  tuple race re-read.
- Disabled accounts stay disabled after Cognito authentication and receive no
  login mutation.
- `/v1/me` and API-key ownership remain based on internal user identity; never
  expose tokens, Cognito `sub`, or raw provider profile.

## Acceptance tests

- First mocked Google and native email/password Cognito login creates active
  role-`user` internal users.
- Repeat and concurrent same-`sub` first login creates exactly one user.
- Existing administrator and disabled-user states survive login unchanged.
- Two Cognito subjects sharing a verified email create two users without merge.
- SQLite migration/backfill and DynamoDB codec/adapter parity, including a
  DynamoDB Local contract run for changed access patterns.
- API-key owner stays `usr_`; ordinary and admin-owned keys have no global role.

## Handoff and non-goals

The WIP breakdown must define migration sequencing, old-data compatibility,
rollback policy, test commands, and exact API response changes. Do not add CLI
administration, public admin endpoints, automatic email synchronization,
subscription/quota policy, or account linking in this phase.
