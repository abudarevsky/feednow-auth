# Phase 15 — Local account milestone completion

**Status:** active, authorized by the user on 2026-09-25 from the FeedNow
Auth UI Local Docker Implementation v1.3 spec.
**Goal:** implement the remaining local-only account requirements in the
existing service without replacing Cognito, the SQLite adapter, or Compose.

## Build steps

1. Add organization name status, authorized rename, and data-preserving SQLite
   migration; return explicit placeholder/confirmed status.
2. Add admin summary, paginated case-insensitive organization search, details
   and membership views using real membership/user records and existing
   global-admin authorization. Counts must be distinct. No admin mutations.
3. Bind new API keys to `vispector`, migrate existing local data, include the
   service ID only in masked summaries, and add a local route protected by the
   existing API-key verifier.
4. Document and verify the existing Compose build/start/restart path and
   persistence. Record Cognito dev-pool evidence only when exercised.

## Invariants

- Reuse the operator grant/revoke CLI. Ordinary users and API keys receive a
  uniform denial on admin endpoints.
- Plaintext API keys remain creation-only. Revoked/wrong-service credentials
  cannot access the protected proof route. Never claim Vispector integration.
- Preserve user/organization/membership/key timestamps except fields the
  operation is meant to update. All persisted timestamps remain UTC.
- Update service contract, operations, and API docs with verified behavior.

## Non-goals

Subscriptions and usage, billing, admin mutations, new admin bootstrap,
Vispector deployment, and production deployment.

## Acceptance

Focused tests first; then the backend full suite and UI `npm run check` plus
`npm run test:e2e` for changed authenticated UI flows. Verify Docker build,
startup, and API-key persistence across restart when Docker is available.
Report live Cognito, browser, and environment results separately.
