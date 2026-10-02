# feednow-auth documentation

These chapters describe the implemented service by capability and are the
repository's current documentation entrypoint.

## Chapters

- [Architecture](architecture.md) — service boundaries, composition, and module map.
- [Authentication](authentication.md) — Cognito token validation and identity provisioning.
- [Cognito setup](cognito.md) — provider configuration and operator verification.
- [Sessions](sessions.md) — browser login, PKCE, cookies, and CSRF protection.
- [Authorization](authorization.md) — organization membership and application-admin policy.
- [Credentials](credentials.md) — API-key creation, verification, scope, and revocation.
- [Storage](storage.md) — the storage contract, adapters, migrations, and parity.
- [Contracts](contracts.md) — HTTP, domain, error, pagination, and audit invariants.
- [Administration](administration.md) — operator CLI and global organization administration.
- [Account application](local-account.md) — account UI API behavior and local service-bound proof route.
- [Operations](operations.md) — development, Docker, AWS, migration, and verification procedures.
- [Source map](reference/source-map.md) — source modules mapped to these topic chapters.

## Diagrams

- [User authentication](diagrams/user-authentication.html) — Cognito login,
  verified identity resolution, and the browser session.
- [API-key management](diagrams/api-key-management.html) — key creation,
  machine authentication, and revocation.

The chapters describe current behavior and its limits. They do not encode a
delivery sequence or claim unverified remote behavior.
