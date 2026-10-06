# Architecture

`feednow-auth` owns FeedNow application identity, organization tenancy,
authorization context, API credentials, and audit records. Authentication
providers (Cognito, and future IdPs) establish **external identity only**: they
do **not** replace the internal `User` model, organization membership, or the
`AuthorizationContext`. Provider claims stop at the auth boundary, so routers
see user/org ids only. See `authentication.md` and `cognito.md`.

The generic `create_app` factory mounts `/health` and only the routers passed
to it. Deployment compositions select the routers they need; the default
module-level app is intentionally minimal. The current versioned route
inventory lives in `src/app/api/schemas/manifest.py`.

## Module map

| Module | Responsibility |
| --- | --- |
| `src/app/api` | HTTP routers, request/response schemas, error mapping, `create_app` composition |
| `src/app/auth` | JWT + API-key authentication resolution; authorization policy |
| `src/app/services` | Business rules / use cases (provisioning, tenancy, membership, keys, audit) |
| `src/app/models` | Provider-neutral domain entities and value types |
| `src/app/storage` | `Storage` protocol + adapter implementations (SQLite, DynamoDB) |
| `src/feednow_auth` | Operator CLI shim — out-of-band administration entrypoint |
| `src/tests` | Unit, integration, and adapter-conformance tests |

## Dependency direction

Dependencies point **inward**:

- `src/app/api` and `src/app/auth` use the domain models (`src/app/models`).
- `src/app/services` uses only the storage **contract** (`src/app/storage/contract`).
- `src/app/storage` owns database/provider details (SQLite rows, DynamoDB
  expressions, `LastEvaluatedKey` cursors, boto3, driver exceptions).

Adapter types, database sessions, provider exceptions, and pagination-token
contents **never** escape `src/app/storage` (see `storage.md`, `contracts.md`).
Adapters come from a documented factory and both pass the same adapter-neutral
conformance suite; the boundary is enforced repo-wide, since an AST scan pins
`storage/dynamodb.py` as the only `src/app` module importing `boto3`/`botocore`
and a subprocess-isolated `import app.main` loads no driver or adapter module.

## HTTP composition

Every versioned public API route matches the manifest in
`src/app/api/schemas/manifest.py`; browser session and OAuth routes are
composed separately. The app is built once via `create_app(routers=[...])`.

| Surface | Builder / mount | Notes |
| --- | --- | --- |
| `GET/PATCH /v1/me` | `build_me_router` | Identity and profile; earliest-active org + role, scopes `[]` |
| organization + member routes (7) | `build_organizations_router`, `build_members_router` | Tenancy seam on top of identity |
| api-keys routes (5) | `build_api_keys_router` | Generic key management plus a restricted Vispector collection; `fn_live_`/`fn_test_` dispatch |
| `POST /v1/service-auth/api-keys/validate` | `build_service_auth_router` | Server-credential protected; returns API-key actor and mapped permission context |
| `POST /v1/service-auth/contexts/validate` | `build_service_auth_router` | Server-credential protected; rechecks an active user, organization, and membership before refreshing service permissions |
| `POST /v1/oauth/service-handoff` | `build_service_auth_router` | Session protected; JSON uses CSRF and URL-encoded forms validate Origin; redirects only to the registered callback with a short-lived code |
| `POST /v1/service-auth/authorization-codes/exchange` | `build_service_auth_router` | Server-credential protected; atomically consumes a code and rechecks current user, organization, and membership access |
| local admin routes (7) | `build_admin_router` | Application-admin-gated operations through `LocalAdminStorage` |
| session router | `build_oauth_router` (`src/app/api/oauth.py`) | Mounted **outside** the `/v1` manifest |

`GET /v1/oauth/service-handoff/continue` is a browser-only route outside the
public endpoint manifest. It starts FeedNow OAuth when there is no session and
issues the registered-service handoff on the authenticated top-level GET after
login. The browser-facing account URL uses
`/api/v1/oauth/service-handoff/continue`; Vite and CloudFront remove the
`/api` prefix before forwarding it. `/health`, Cognito OAuth, CSRF, and the
local Vispector proof route are also outside the versioned manifest. The
service-auth routes are always mounted; API-key
validation and context revalidation require its configured service credential.
Handoff and exchange return an unavailable response until the service credential and registration
are configured. The local admin router uses manifest entries but is
mounted only by the local Docker composition. See
`authentication.md`, `authorization.md`, `credentials.md`, `sessions.md`, and
`local-account.md` for surface details.

## Authorization chain

`ROLE_RANK` (fixed precedence `viewer < member < org_admin < owner`, pure, no
FastAPI) classifies every request (full policy in `authorization.md`):

| Step | Module | Result |
| --- | --- | --- |
| 1. identity | `src/app/auth` → `app.services.identity` | Bearer/JWT `User` + `AuthorizationContext`; first sight = one atomic `provision_user` |
| 2. organization access | `src/app/auth/organization_access.py` | `get_organization` + `get_membership` (uniform denial behavior) |
| 3. classification | `app.services.authorization.classify_access` | `ROLE_RANK` grants or denies by role |
| 4. grant / deny | handler | granted → `OrganizationAccess` (org + membership; re-checks nothing); denied → `authorization.denied` audit (when the org row exists) → **uniform 403** |

The credential principal path (`build_current_principal`) dispatches on the
prefix — `fn_live_`/`fn_test_` → API key, anything else → JWT — yielding
`Principal(user XOR api_key)` + `PrincipalAccess` with the same uniform-403 +
audit behavior (actor `usr_` or `key_`).

## Credentials and the pepper seam

The credential primitives (`src/app/auth/credentials.py`) and the pepper source
(`src/app/auth/pepper.py`) stay inside `src/app/auth` (see `credentials.md`).
Services and routers see **only** domain rows, the `key_` application identity,
and resolved contexts. The plaintext secret never crosses into persistence,
logs, audits, or non-creation payloads; the key-id segment appears only as the
point-lookup column and inside the masked `key_prefix`, never as a standalone
path or payload field. API-key creation is the **only** response that returns a
full secret, and it does so **once**.

## Administration bootstrap

Application-admin promotion/revocation is **CLI-only**: the operator runs
`python -m feednow_auth.admin` (`src/feednow_auth/admin.py`, a behavior-free
wheel shim next to `app`); there is no HTTP route, no default credential, and
no startup/deployment-time promotion. The flow is `app.storage.factory`
(env-derived settings → adapter; no app/Cognito/pepper) →
`app.services.administration` (email → one `usr_`, audit anchor, one
`AuditEvent`) → `Storage.transition_application_role`. The last-active-admin
guard, CAS, and audit append are one atomic adapter transaction — never a CLI
check-then-write; the service knows only the `Storage` protocol. The global
application-admin dependency (`src/app/auth/application_access.py`) is unmounted
in production. See `administration.md`.

## Where things live

| Concern | Module path |
| --- | --- |
| Identity / token verify / `GET /v1/me` | `src/app/auth` (+ `app.services.identity`) |
| Organization + membership policy | `src/app/auth/organization_access.py` |
| Role classification (`ROLE_RANK`) | `app.services.authorization` |
| API-key credentials + pepper | `src/app/auth/credentials.py`, `src/app/auth/pepper.py` |
| API-key verify | `app.auth.api_key_auth` |
| Session boundary / `/oauth` | `src/app/api/oauth.py` (+ `SessionManager`) |
| Global application-admin dependency | `src/app/auth/application_access.py` (unmounted in production) |
| Operator CLI bootstrap | `src/feednow_auth/admin.py` |
| Storage contract + adapters | `src/app/storage/contract`, `src/app/storage/dynamodb.py` |
| Route manifest | `src/app/api/schemas/manifest.py` |

Cross-cutting contracts live in `contracts.md` and `storage.md`; Cognito,
sessions, operations, and local behavior are documented in their respective
chapters. The source-to-topic index is `reference/source-map.md`.
