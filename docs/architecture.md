# Architecture

`feednow-auth` owns FeedNow application identity, organization tenancy,
authorization context, API credentials, and audit records.

```text
src/app/api        HTTP routers, request/response schemas, error mapping
src/app/auth       JWT and API-key authentication resolution
src/app/services   business rules and use cases
src/app/models     provider-neutral domain entities and value types
src/app/storage    storage protocol and adapter implementations
```

Dependencies point inward: API/auth and services use domain models; services
use storage contracts; storage owns database/provider details. Adapter types,
database sessions, provider exceptions, and pagination token contents must not
escape `src/app/storage`.

Phase 01 exposes only the health endpoint and frozen contracts. Later phases
mount resource routers through `create_app(routers=[...])` and must match the
manifest in `src/app/api/schemas/manifest.py`.

Authentication providers establish external identity. They do not replace the
internal `User` model, organization membership, or authorization context.
