# Contracts

This chapter summarizes the service's current domain, HTTP, error, and
security boundaries. The endpoint manifest in
`src/app/api/schemas/manifest.py` is the canonical inventory of versioned
routes.

## Identity and data

- Application identities use `usr_`, `org_`, and `key_` prefixes. Internal
  record IDs such as `extid_`, `mem_`, and `aud_` do not appear in HTTP paths
  or response payloads.
- External provider subjects remain provider-scoped values and are never
  substituted for FeedNow IDs.
- Persisted and serialized timestamps are timezone-aware UTC values.
- Request schemas reject unknown fields. API responses never expose password,
  token, pepper, or secret-hash material; only key creation returns the full
  API-key literal, once.
- `Page[T]` uses opaque keyset cursors. Clients pass cursors back unchanged.

## HTTP surface

The versioned manifest currently contains 21 endpoints: two current-user
operations; organization and member operations; API-key management; and local
application-administration operations, plus service-side API-key validation.
The generic `create_app()` factory
mounts health plus explicitly supplied routers. AWS and local Docker
compositions select their own router sets. OAuth, health, CSRF, and the local
Vispector proof route are outside the versioned manifest.

Successful reads and updates use 200; creates use 201; deletion and lifecycle
actions with no response body use 204. Error responses use the shared safe
error envelope. Backend, AWS, Cognito, token, and credential contents are not
echoed in error messages.

## Authentication and authorization

Cognito access tokens require exact `RS256`, issuer and client allowlist
membership, and `token_use="access"`. First-login provisioning requires a
verified user-info profile. Human organization roles and API-key scopes are
separate authorization vocabularies. API keys never acquire human roles.

Organization access denials use a uniform 403 response to avoid exposing
organization existence. Denials are audited when an organization row exists;
an unknown organization cannot be an audit target. Authentication failures
do not trigger storage writes.

## Storage and audit invariants

Storage operations accept fully formed domain records; adapters do not mint
IDs or timestamps. User and organization provisioning, application-role
transitions, and OAuth state consumption have their documented atomicity
guarantees. API-key revocation is idempotent with the original revocation time
preserved. Audit metadata excludes credentials and provider tokens.

See [storage.md](storage.md), [authentication.md](authentication.md),
[authorization.md](authorization.md), and [credentials.md](credentials.md) for
the detailed behavior and limits.
