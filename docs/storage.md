# Storage

Persistence is behind the domain-oriented `Storage` protocol in
`src/app/storage/contract.py`. Application services use that protocol and
domain models only; SQLite and DynamoDB details stay in their adapters.

## Contract and adapters

The core protocol has 28 operations covering users and external identities,
organizations and memberships, API keys, audit append, atomic user and
organization provisioning, application-role transitions, and OAuth state and
application sessions. Its signatures use domain values and typed results;
adapters do not mint identifiers or timestamps.

`open_sqlite_storage` is used for local persistence. SQLite schema migrations
are forward-only; the current schema version is 5. `open_dynamodb_storage`
provides the AWS adapter. The DynamoDB schema and deployment table definitions
are maintained together. Both adapters implement the same core contract and
the shared storage-conformance suite.

The DynamoDB deployment uses nine environment-prefixed tables: `users`,
`external_identities`, `organizations`, `memberships`, `api_keys`,
`audit_events`, `unique_constraints`, `oauth_login_states`, and `app_sessions`.
Secondary indexes support user lookup by email and application role,
organization membership lookup in both directions, and API-key lookup by
organization. External identities use a composite partition key; uniqueness
guards use the `unique_constraints` table. The login-state and session tables
expire items through DynamoDB TTL. The deployment's least-privilege
table/index matrix is defined in the CDK stack and mirrored by its IAM
assertions. The runtime role can update user records for profile changes, with
`UpdateItem` scoped to the environment's users table.

An optional `LocalAdminStorage` extension adds organization search, summary,
suspension, reactivation, and deletion for the local administration API. Both
SQLite and DynamoDB adapters implement it, keeping route behavior storage
agnostic. It is not part of the portable core protocol and is not used by the
production Lambda composition. DynamoDB admin queries scan the local tables;
deletion is a sequence of table deletes and may be partially complete if a
storage failure interrupts it.

## Atomicity and errors

- `provision_user` writes the user, identity, personal organization, owner
  membership, and creation audits as one atomic operation.
- `provision_organization` writes the organization, owner membership, and
  creation audits atomically.
- `transition_application_role` applies the application-role change and audit
  append atomically, including the last-active-administrator guard.
- API-key revocation uses first-write-wins compare-and-swap semantics.
- OAuth login state is consumed atomically; only one concurrent caller can
  receive a state record.
- Organization suspension and key revocation are coordinated so an
  organization cannot continue using active keys after suspension.
- Adapter failures are translated into the storage error vocabulary. Database
  rows, driver exceptions, and interpretable cursor contents do not escape.

Lists use deterministic `(created_at, id)` ordering and opaque keyset cursors.
Cursors are adapter-specific and must be passed back unchanged to the adapter
that created them.

The adapters intentionally do not promise arbitrary cross-operation
transactions. Atomicity is provided only by the named provisioning, role
transition, state-consumption, and compare-and-swap operations. A DynamoDB
query against the application-role index must treat temporarily missing index
entries conservatively for the last-administrator guard; the service fails
closed rather than falling back to a table scan.

## Verification

Use `uv run pytest src/tests/storage_contract -q` for the SQLite conformance
entry. The DynamoDB Local entry requires its emulator and
`FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`; the setup is documented in
[operations.md](operations.md).
