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

Phase 01 exposes only the health endpoint and frozen contracts. Phase 03
mounts the first §14 route (`GET /v1/me`) through `create_app(routers=[...])`
with `build_me_router`; every mounted route must match the manifest in
`src/app/api/schemas/manifest.py`. Later phases mount more routers the same
way.

Authentication providers establish external identity. They do not replace the
internal `User` model, organization membership, or authorization context.
The implemented Phase 03 flow (see
[Phase 03](phases/03-identity.md) for the pinned contract):

```text
Bearer token (src/app/auth)
  -> CognitoAccessTokenVerifier    claims verified against issuer-bound JWKS
  -> app.services.identity         claims -> ExternalIdentity tuple -> User
                                   (first sight: one atomic provision_user batch)
  -> AuthorizationContext (models) earliest-active org + role, scopes=[]
  -> src/app/api routers           user/org ids only; provider fields stop
                                   at the auth boundary
```

Dependency direction is preserved: `app/auth` and `app/services` use the
storage contract and domain models; the verifier knows nothing about storage,
and the service maps provider claims into domain types at one seam
(`resolve_or_provision`), keeping the provider layer swappable.
