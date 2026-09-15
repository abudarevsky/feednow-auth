# feednow-auth documentation

This is the agent-oriented entrypoint for `feednow-auth`. Read documents in
this order before changing the service:

1. [Architecture](architecture.md) — ownership and dependency boundaries.
2. [Contracts](contracts.md) — stable domain, API, error, and pagination rules.
3. [Operations](operations.md) — local commands, production runtime, and checks.
4. [Phase 01](phases/01-foundation.md) — completed foundation handoff.
5. [Phase 02](phases/02-storage.md) — completed storage handoff: contract,
   SQLite adapter, and conformance suite.
6. [Phase 03](phases/03-identity.md) — completed identity handoff: Cognito
   token verification, resolution/provisioning, authorization context, and
   the `GET /v1/me` surface.
7. [Phase 04](phases/04-organizations.md) — completed tenancy handoff:
   organization/member endpoints, the shared role-check dependency, uniform
   audited denials, and the atomic `provision_organization` batch.
8. [Phase 05](phases/05-api-keys.md) — completed credential handoff: API-key
   minting/listing/revocation endpoints, the peppered-hash verification seam,
   human-or-key principal dispatch, the scoped-access dependency, and the
   extended denial vocabulary.
9. [Phase 06](phases/06-dynamodb.md) — completed adapter handoff: the
   production DynamoDB adapter behind the frozen storage contract, the
   table/index schema and least-privilege IAM matrix for Phase 07, and the
   conformance suite passing against DynamoDB Local.
10. [Phase 07](phases/07-aws-infrastructure.md) — completed infrastructure
   handoff: the environment-parameterized Python CDK stack (Cognito PKCE
   pool, the seven Phase 06 tables, the generated pepper secret, the
   least-privilege Lambda role, the HTTP API with redaction-safe access
   logs), the import-safe cold-start composition root, and the
   non-production deployed smoke procedure with its recorded evidence.

These documents are the source of truth for the application that exists in
this repository. They describe implemented paths, behavior, contracts,
runtime, and verified evidence. Transformation plans belong in `specs/` and
may link here for their current-state baseline; this documentation set does
not link to future-state specifications.

## Documentation rule

Every behavior or contract change must update the nearest document here and
the governing `specs/` file when the public contract changes. A phase is not
complete until its docs, verification evidence, and handoff boundary are
updated together. See [Documentation requirements](requirements.md).
