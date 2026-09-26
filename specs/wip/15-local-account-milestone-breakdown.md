# Phase 15 follow-up — onboarding and organization administration

## Build step 6 — profile onboarding and organization lifecycle

- **Scope:** add authenticated profile-name updates, placeholder organization
  onboarding, and global admin suspend/delete operations.
- **Files/boundaries:** versioned request/response schemas and manifest entries;
  current-user/admin routes; service/storage contract and SQLite implementation;
  UI account/admin screens and typed APIs.
- **Focused checks:** profile endpoint tests and storage tests covering atomic
  organization suspension/deletion, API-key revocation, membership changes,
  complete associated-user cleanup, and authorization.
- **Handoff checks:** complete backend pytest suite and UI `npm run check` /
  `npm run test:e2e`; rebuild/start local Docker and check health endpoints.
- **Migration/rollback:** additive nullable suspended_at column; existing rows
  migrate with null. Suspension records the first time and revokes keys, while
  keeping member accounts and memberships active so users can sign in and see
  their suspended status. Backend organization authorization blocks business
  operations. Global admins remain active to administer the suspended tenant.
  Delete removes the org and every
  associated user account, membership, key, audit record, identity, and session.
  Current product behavior is one user per organization.
- **Non-goals:** subscriptions/usage, a resume action, and executing a destructive operation on
  existing development data.
