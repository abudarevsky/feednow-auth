# Authentication

Authentication resolves an external identity (currently Cognito) into the
internal `User`, an organization role, and an `AuthorizationContext`. The
external identity provider does **not** replace the internal `User` model,
organization membership, or authorization context — it only feeds the one
resolution seam below. Pipeline direction lives in `architecture.md`.

## Provider chain

```text
Authorization: Bearer <jwt>        src/app/auth
   -> CognitoAccessTokenVerifier    claims verified against issuer-bound JWKS
   -> app.services.identity         claims -> ExternalIdentity tuple -> User
   -> AuthorizationContext          earliest-active org + role, scopes=[]
   -> src/app/api routers           user/org ids only
```

## Token verification

`CognitoAccessTokenVerifier.verify` (`src/app/auth/cognito.py`) enforces a
pinned stage order; each failure raises `TokenValidationError` with a fixed,
input-echo-free reason and **never mutates storage** — all verification and
JWKS work happens before any storage call:

1. Unverified structural parse (manual base64url + JSON, no early time check).
2. `alg` the exact case-sensitive `"RS256"`, `kid` non-empty — `none`/HS256
   forgeries reject before any issuer lookup or fetch.
3. Issuer by **exact set membership** in the allowlist (no prefix, no library
   `issuer=`); key fetch bound to that issuer only
(`JwksSource.signing_key(issuer, kid)`, `src/app/auth/jwks.py`).
4. `jwt.decode` `algorithms=["RS256"]`, `verify_aud` off, 60-second leeway;
    `token_use == "access"`, `client_id` set membership.
5. Claim shape: `sub` (≤255), `email`, optional `username`.

JWKS is **issuer-bound**: `CognitoJwksSource` resolves a `kid` only from that
issuer's set (`{iss}/.well-known/jwks.json`, one lazily-cached client, re-fetch
on unknown `kid`). Provider setup and runbook: `cognito.md`.

## Resolution and provisioning

`resolve_or_provision` (`src/app/services/identity.py`) maps provider claims
into domain types at **one seam**, keeping the provider layer swappable. On a
first sight it executes exactly one atomic `provision_user` batch — `User`,
`ExternalIdentity`, personal `Organization`, owner `Membership`, and three
creation audits — sharing one clock read and one ID set:

| Field | Value |
| --- | --- |
| `User` | `active`, `display_name = username or sub`, the verified `email` |
| `ExternalIdentity` | `(cognito, sub, None)` — Cognito carries no tenant dimension |
| `Organization` | name `"{display}'s Workspace"`, slug `personal-{user_id}`, `personal`/`active` |
| `Membership` | `owner`/`active` |
| Audits | `user.created`, `organization.created`, `membership.created`; no `sub`/token/email in metadata |

On a duplicate-identity race, convergence happens **only** via the
identity-tuple re-read after `DuplicateExternalIdentityError`;
`existing_user_id` is an advisory email-fallback cross-check, never the
convergence signal, and a re-read miss is a `ProvisioningConflictError` with
no partial rows.

The same first-provisioning transaction stores one idempotent Vispector
onboarding request with the committed organization ID and stable request ID.
It carries only bootstrap version `starter-v1`; the service credential is
resolved from runtime configuration for dispatch and never stored. OAuth
attempts dispatch pending or failed requests and record success or a sanitized
failure so a later login can retry. Race convergence and subsequent login hits
do not create additional requests.

### The provider-swap seam

`User` is a mutable container that later profile updates may extend; provider
material never persists. `User.email` is sourced from a **verified profile**
only — `require_provisioning_profile` demands bounded non-empty `email`,
`email_verified` exactly `True`, and a `sub` equal to the validated token's,
before any write; the hit path never overwrites it. The verified-profile gate
and PKCE session journey are `sessions.md`; provider config is `cognito.md`.

### Authorization context

`build_user_context(storage, user, organization_id=None)` yields
`actor_type="user"`, `actor_id=usr_`, `roles=[role]`, `scopes=[]`. The default
branch is the **earliest active** organization (`(created_at, id)` ascending over
active memberships); an explicit `organization_id` must name an `active`
membership in an `active` organization, else `NoActiveOrganizationError` (no
existence oracle). Role ranking is `authorization.md`; the machine principal
(API-key context, `roles=[]` always) is `credentials.md`.

## HTTP surface and status mapping

`GET /v1/me` (`src/app/api/me.py`) returns the caller's `User` projection only —
the internal `usr_` id is the sole identifier returned; no `sub`, `client_id`,
record ids (`extid_`/`mem_`/`aud_`), or token material. Status translation, in
the HTTP layer, reuses the frozen error envelope (`contracts.md`); a provider
outage is 503, deliberately not swallowed by the 401 handler:

| Condition | Status | Envelope code |
| --- | --- | --- |
| missing/malformed bearer; any `TokenValidationError` (incl. `UnknownKeyIdError`) | 401 | `unauthenticated` |
| `DisabledUserError`, `NoActiveOrganizationError` | 403 | `forbidden` |
| `ProvisioningConflictError` | 409 | `conflict` |
| `TokenProviderUnavailableError` | 503 | `internal_error` |

## Domain models and source modules

- `src/app/models/user.py` — `User`, the mutable principal container.
- `src/app/models/external_identity.py` — the `(provider, subject, tenant)`
  tuple; provider fields stop at the service seam.
- `src/app/models/authorization_context.py` — the resolved context.
- `src/app/models/ids.py` — ID conventions (`usr_`/`org_`/`key_` application
  identities; `extid_`/`mem_`/`aud_` internal, never in payloads).
- Verifier / JWKS / errors: `src/app/auth/{cognito,jwks,errors}.py`;
  resolution and minting: `src/app/services/{identity,idgen}.py`; bearer HTTP
  chain and error mapping: `src/app/auth/dependencies.py`.

Related: `authorization.md` (role), `credentials.md` (machine principal),
`sessions.md` (verified profile + PKCE), `cognito.md` (provider setup),
`contracts.md` (error envelope), `architecture.md` (boundaries).
