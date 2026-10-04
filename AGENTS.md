# feednow-auth contributor guide

## Purpose and scope

`feednow-auth` owns FeedNow application identity, organization tenancy, authorization context, API credentials, and audit records. Cognito and future identity providers establish an external identity; they do not replace the internal `User` model or authorization rules.

For new planned work, record source requirements under `specs/draft/` and
sequence accepted implementation work under `specs/wip/`. Work from the
current-state documentation when changing existing behavior.

Start with `docs/README.md` for the current application architecture,
contracts, operations, and verified state. Treat `docs/` as the source of truth
for what exists. `specs/` defines future-state strategy and transformation
steps; specs may link to docs for their baseline, but docs must not link to WIP
or draft specs. Start with [the documentation index](docs/README.md).

`docs/` is the canonical, phase-free description of implemented behavior.
Keep it complete and internally consistent; do not copy phase handoffs or
planning history into it. The documentation and production Python docstrings
must describe enduring current behavior and must not mention phase numbers,
phase plans, or `specs/` documents. When a source docstring needs to point
readers to explanatory material, link the corresponding topic chapter in
`docs/`. Keep phase ordering, acceptance criteria, and transformation steps in
`specs/` only.

Use the workspace-shared specification tree at `../specs/` for cross-project
work. A project-local `specs/` entry supersedes the shared specification for
that project when one is available; otherwise the shared specification is the
source of truth. For current behavior, consult the project-root `docs/` first.

## Architecture boundaries

- Keep HTTP handling in `src/app/api`, credential and JWT logic in `src/app/auth`, domain types in `src/app/models`, business rules in `src/app/services`, and persistence details in `src/app/storage`.
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
src/app/             Runtime service code
  api/               FastAPI routers, dependencies, and schemas
  auth/              JWT/API-key authentication and authorization resolution
  models/            Provider-neutral domain entities and value types
  services/          Provisioning, tenancy, membership, keys, and audit rules
  storage/           Contract and adapter implementations
src/tests/           Unit, integration, and adapter conformance tests
deploy/aws/          Lambda runtime packaging requirements
deploy/aws/cdk/      AWS CDK application, stack, and deployment inputs
specs/draft/         Source specification; edit only through an agreed revision
specs/wip/           Ordered, reviewable implementation phases
```

## Definition of done for a phase

An implementation agent may mark a phase complete only when its acceptance criteria pass, the listed test evidence is recorded, migrations/infrastructure effects are documented, and the handoff boundary is preserved. Do not start a dependent phase by silently changing a completed phase's contract.


## Shared tool execution protocol

All agents may delegate tool operations to @run_tool.

Use @run_tool when the operation involves:
- Shell commands.
- Repository exploration.
- File or symbol discovery.
- Tests and diagnostics.
- Large or noisy tool output.
- Environment inspection.

The caller must specify the purpose and expected outcome.

@run_tool returns verified observations, not raw execution history.

The caller retains ownership of its original task.

Do not delegate source-code modifications to @run_tool.

Do not invoke @run_tool recursively.

Direct tool calls remain permitted when exact content is needed,
the output is predictably small, or delegation adds no value.

Treat @run_tool status as operation status, not task completion.
