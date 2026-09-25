# Architecture

`feednow-auth` owns FeedNow application identity, organization tenancy,
authorization context, API credentials, and audit records.

```text
src/app/api        HTTP routers, request/response schemas, error mapping
src/app/auth       JWT and API-key authentication resolution
src/app/services   business rules and use cases
src/app/models     provider-neutral domain entities and value types
src/app/storage    storage protocol and adapter implementations
src/feednow_auth   operator CLI shim (out-of-band administration entrypoint)
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
`src/app/api/schemas/manifest.py`. Phase 11 adds the session-boundary
router (`build_oauth_router` in `src/app/api/oauth.py`) mounted the same
way but deliberately outside the `/v1` manifest — the operational `/health`
route is the precedent for non-§14 mounts. Later phases mount more routers
the same way.

Authentication providers establish external identity. They do not replace the
internal `User` model, organization membership, or authorization context.
The implemented Phase 03 flow (see
[Phase 03](phases/03-identity.md) for the pinned contract):

```text
Bearer token (src/app/auth)
  -> CognitoAccessTokenVerifier    claims verified against issuer-bound JWKS
  -> app.services.identity         claims -> ExternalIdentity tuple -> User
                                   (first sight: one atomic provision_user
                                    batch, fed by the Phase 11 verified
                                    profile — see below)
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

Phase 11 extends the auth boundary with the verified-profile and session
components (see [Phase 11](phases/11-cognito-authentication-profile-and-session-boundary.md)
for the pinned contract). On the bearer chain the identity service now
takes an optional `ProfileSource` thunk used **only** on the
identity-tuple miss path — the hit path performs zero profile work and
never overwrites the stored email — and `User.email` comes exclusively
from a profile that passed `require_provisioning_profile` (subject match,
bounded non-empty email, `email_verified` exactly `True`); the old
`sub@cognito.invalid` placeholder is gone. The session boundary is a
server-side authorization-code + PKCE journey:

```text
GET /oauth/login (src/app/api/oauth.py)
  -> next validated against the exact-origin allowlist (400, never echoed)
  -> OAuthLoginState saved (single-use, 600s) -> 302 to Cognito authorize
     (S256 challenge; the verifier never leaves the server)
GET /oauth/callback
  -> consume_oauth_login_state     replay/expired/unknown -> 401
  -> CognitoTokenEndpoint          public PKCE exchange; access_token only
  -> CognitoAccessTokenVerifier    JWT validation stays mandatory first
  -> ProfileSource.fetch + gate    401/503 before any user storage touch
  -> resolve_or_provision          the same service seam as the bearer chain
  -> SessionManager.issue          opaque feednow_session cookie, 302 home
```

Cookie-based authentication of `/v1/*` is **not** enabled by this phase:
`SessionManager.verify` is component-level only and `/v1/*` keeps the
bearer contract. The user-info and token endpoints are fixed approved
HTTPS configuration (constructor-pinned, redirects refused); the session
modules import no logging and no code, state, verifier, token, or email
material appears in logs, error envelopes, or redirect targets.

Phase 13 adds the administration boundary (see
[Phase 13](phases/13-application-administrator-bootstrap-and-operations.md)
for the pinned contract). Application-admin promotion/revocation is
**CLI-only bootstrap**: the operator runs `python -m feednow_auth.admin`
(`src/feednow_auth/admin.py`, a behavior-free shim package shipped in the
wheel next to `app`), and there is deliberately **no** HTTP bootstrap
route, no default admin credential, and no startup- or deployment-time
promotion — the CLI is present in the container but never invoked at
startup. The dependency direction stays inward:

```text
python -m feednow_auth.admin (operator, out of band)
  -> app.storage.factory      env-derived settings -> adapter (no app, no Cognito, no pepper)
  -> app.services.administration  email -> one usr_, audit anchor, one formed AuditEvent
  -> Storage.transition_application_role  CAS + audit in one adapter transaction
```

The service knows only the `Storage` protocol; the last-active-admin guard,
the CAS, and the audit append are one atomic adapter operation (never
CLI check-then-write). The global `ApplicationRole` is separate from
organization membership: `src/app/auth/application_access.py` provides the
server-side global-admin dependency (human + `ADMIN` only, uniform 403 for
everything else including admin-owned API keys) for a future administration
surface and is mounted on **no** production route this phase, while
organization-membership administration keeps its independent org-local
`organization_access` role policy — the two vocabularies never inherit.

Dependency direction is preserved: `app/auth` and `app/services` use the
storage contract and domain models; the verifier knows nothing about storage,
and the service maps provider claims into domain types at one seam
(`resolve_or_provision`), keeping the provider layer swappable. The
authorization rules are pure functions with no FastAPI import; the HTTP
composition lives in `app/auth`, and status translation for service errors
lives in the `app/api` routers.
