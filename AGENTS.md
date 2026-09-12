# feednow-auth contributor guide

## Purpose and scope

`feednow-auth` owns FeedNow application identity, organization tenancy, authorization context, API credentials, and audit records. Cognito and future identity providers establish an external identity; they do not replace the internal `User` model or authorization rules.

Work from `specs/draft/feednow-auth-service-specification.md`. The numbered plans in `specs/wip/` are the delivery contract and must be completed in order unless their stated dependency is already accepted.

## Architecture boundaries

- Keep HTTP handling in `app/api`, credential and JWT logic in `app/auth`, domain types in `app/models`, business rules in `app/services`, and persistence details in `app/storage`.
- Application services depend only on the storage contract. Do not expose SQLite rows, DynamoDB expressions, pagination tokens, sessions, or AWS exceptions above an adapter.
- Use internal FeedNow IDs (`usr_`, `org_`, `key_`) as application identities. Never use email, Cognito username/sub, or Shopify IDs as primary user identifiers.
- Keep product permissions as API-key scopes. Do not put commercial plan or rate-limit policy in scopes.
- No plaintext API secret, password, JWT, refresh token, or Cognito token may be persisted or written to logs/audit metadata.

## Delivery and testing rules

- Add focused unit tests with every rule change and integration tests for each endpoint/authorization decision.
- Add a storage-contract test before relying on new storage behavior; run it against SQLite and DynamoDB Local when the DynamoDB adapter exists.
- Treat provisioning and credential revocation as concurrency-sensitive: define and test atomicity and duplicate-request behavior.
- Use explicit, versioned Pydantic request/response schemas. API-key creation is the only response that may include a full key and it must do so once.
- AWS CDK changes under `deploy/aws/cdk` must be environment-parameterized (`dev`, `staging`, `prod`), least-privilege, and accompanied by synth/test evidence. Follow Vispector's entrypoint pattern: `app.py`, `cdk.json`, `requirements.txt`, stack module, and a non-committed `.env` based on `.env.example`.

## Project layout

```text
app/                 Runtime service code
  api/               FastAPI routers, dependencies, and schemas
  auth/              JWT/API-key authentication and authorization resolution
  models/            Provider-neutral domain entities and value types
  services/          Provisioning, tenancy, membership, keys, and audit rules
  storage/           Contract and adapter implementations
tests/               Unit, integration, and adapter conformance tests
deploy/aws/          Lambda runtime packaging requirements
deploy/aws/cdk/      AWS CDK application, stack, and deployment inputs
specs/draft/         Source specification; edit only through an agreed revision
specs/wip/           Ordered, reviewable implementation phases
```

## Definition of done for a phase

An implementation agent may mark a phase complete only when its acceptance criteria pass, the listed test evidence is recorded, migrations/infrastructure effects are documented, and the handoff boundary is preserved. Do not start a dependent phase by silently changing a completed phase's contract.
