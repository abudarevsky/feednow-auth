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
with `build_me_router`; Phase 04 mounts the six organization/member routes
the same way with `build_organizations_router` and `build_members_router`;
Phase 05 mounts the three api-keys routes with `build_api_keys_router`;
every mounted route must match the manifest in
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

Phase 04 adds the tenancy seam on top of that chain (see
[Phase 04](phases/04-organizations.md) for the pinned policy):

```text
organization-scoped request (src/app/auth/organization_access.py)
  -> build_current_user            the published Phase 03 chain (401/403/409/503)
  -> get_organization + get_membership
  -> app.services.authorization    classify_access (ROLE_RANK, fixed precedence)
  -> granted? OrganizationAccess   (handler receives org + membership, re-checks nothing)
     denied?  authorization.denied audit (when the org row exists) -> uniform 403
```

Phase 05 adds the machine-credential seam (see
[Phase 05](phases/05-api-keys.md) for the pinned contract):

```text
bearer request (src/app/auth/dependencies.py -> build_current_principal)
  -> prefix dispatch               fn_live_/fn_test_ -> API key; anything else -> JWT
  -> app.auth.api_key_auth         verify_api_key: parse -> point lookup (dummy
                                   compare on miss) -> secret -> env -> status -> expiry
  -> app.auth.principal            Principal(user XOR api_key, §10 context)
  -> organization_access scope dep org status -> organization_mismatch -> insufficient_scope
  -> granted? PrincipalAccess      denied? authorization.denied (usr_ or key_ actor) -> uniform 403
```

The credential primitives (`src/app/auth/credentials.py`) and the pepper
source (`src/app/auth/pepper.py`) stay inside `app/auth`: services and
routers only see domain rows, the `key_` application identity, and resolved
contexts — the plaintext secret never crosses into persistence, logs,
audits, or non-creation payloads, and the §8 key-id segment appears only as
the point-lookup column and inside the masked `key_prefix` (never as a
standalone path or payload field).

Phase 06 adds the second storage adapter behind the same frozen contract
(see [Phase 06](phases/06-dynamodb.md) for the schema and IAM matrix):
`src/app/storage/dynamodb.py` owns the seven-table `SCHEMA`, the codecs, the
positional conflict classification, and the transactional compounds; the
SQLite adapter is untouched. The dependency direction is unchanged —
`app/api`, `app/auth`, and `app/services` import only
`app.storage.contract` and obtain adapters through a documented factory —
and the boundary is now proven repo-wide: an AST scan pins
`storage/dynamodb.py` as the only module under `src/app` importing
`boto3`/`botocore`/`app.storage.dynamodb`, and the subprocess-isolated
`import app.main` proof shows the entrypoint loads no driver or adapter
module. DynamoDB rows, expressions, `LastEvaluatedKey` values, and driver
exceptions never escape the adapter; both adapters pass the same
adapter-neutral conformance suite (SQLite always; DynamoDB against
DynamoDB Local, marker-gated).

Dependency direction is preserved: `app/auth` and `app/services` use the
storage contract and domain models; the verifier knows nothing about storage,
and the service maps provider claims into domain types at one seam
(`resolve_or_provision`), keeping the provider layer swappable. The
authorization rules are pure functions with no FastAPI import; the HTTP
composition lives in `app/auth`, and status translation for service errors
lives in the `app/api` routers.
