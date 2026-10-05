# Source map

Use this map to find the topic chapter that explains a source area. Source
docstrings should point to these chapters for durable behavior and invariants.

| Source area | Documentation chapter |
| --- | --- |
| `src/app/main.py`, runtime composition | [Architecture](../architecture.md) |
| `deploy/aws/runtime/cognito_trigger_lambda.py`, `src/app/auth/cognito_triggers.py` | [Cognito integration](../cognito.md) |
| `src/app/api/schemas/manifest.py`, shared errors and pagination | [Contracts](../contracts.md) |
| `src/app/auth/cognito.py`, `jwks.py`, `services/identity.py` | [Authentication](../authentication.md) |
| `src/app/api/oauth.py`, `src/app/auth/session.py`, local CSRF middleware | [Sessions](../sessions.md) |
| `src/app/services/authorization.py`, organization/member routers | [Authorization](../authorization.md) |
| Service role-permission mapping and handoff routes | [Authorization](../authorization.md) |
| API-key primitives, verifier, key routes, and service authorization | [Credentials](../credentials.md) |
| `src/app/storage/` | [Storage](../storage.md) |
| `src/feednow_auth/`, application-admin service and dependency | [Administration](../administration.md) |
| Local Docker composition and SQLite admin extension | [Local account](../local-account.md) |
| Cognito resources and environment verification | [Cognito integration](../cognito.md) |
| Compose, migration, deployment, and operator commands | [Operations](../operations.md) |

This is a source-to-topic index for the current documentation set.
