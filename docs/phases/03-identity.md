# Current state: identity resolution and provisioning

Phase 03 is implemented. A Cognito access token is now validated end to end
and resolved into an internal `User` plus a §10 `AuthorizationContext`, with
first-login provisioning executed through the Phase 02 `provision_user`
compound. The first HTTP surface exists: `GET /v1/me`, mounted through the
frozen `create_app(routers=[...])` extension point. No AWS calls, no live
Cognito pool, and no DynamoDB anywhere in this boundary.

## Scope

- `src/app/services/idgen.py`: prefix-valid ID minting (`usr_`, `org_`,
  `extid_`, `mem_`, `aud_` = prefix + `_` + `uuid4().hex`, `secrets`-backed).
  Discharges Phase 03's half of the Phase 01 generation deferral; `key_` and
  the §8 credential segment stay with Phase 05.
- `src/app/auth/errors.py`: the token-error hierarchy —
  `TokenValidationError(reason)` (base, fixed safe reasons),
  `UnknownKeyIdError` (subclass: no key under the verified issuer), and
  `TokenProviderUnavailableError` (sibling, deliberately not a
  `TokenValidationError`: an outage must not be swallowed by a 401 handler).
- `src/app/auth/jwks.py`: `JwksSource` protocol (issuer-bound
  `signing_key(issuer, kid)`) and `CognitoJwksSource` — URL derived as
  `{iss}/.well-known/jwks.json`, one lazily built `PyJWKClient(cache_keys=True)`
  per allowlisted issuer, rotation via refetch-on-unknown-kid.
- `src/app/auth/cognito.py`: `CognitoClaims` (frozen), the
  `AccessTokenVerifier` handoff protocol, and `CognitoAccessTokenVerifier`
  with the pinned stage order (below).
- `src/app/services/identity.py`: `build_provisioning_batch` (pure),
  `resolve_or_provision` (lookup → atomic batch → race convergence → status
  gate → context), `build_user_context` (both §10 branches), and the service
  errors `DisabledUserError`, `NoActiveOrganizationError`,
  `ProvisioningConflictError`.
- `src/app/auth/dependencies.py`: the bearer HTTP chain and the
  401/403/409/503 mapping onto `HTTPException` (rendered by the frozen
  Phase 01 envelope).
- `src/app/api/me.py`: `build_me_router(storage, verifier)` registering the
  manifest's `get_current_user` entry from the manifest data itself.
- Dependency: `pyjwt[crypto]>=2.13,<3` (security floor; the `crypto` extra
  also serves test RSA keygen). No `boto3`, no runtime `httpx`.

## Pinned token contract

`CognitoAccessTokenVerifier.verify` runs exactly this sequence, in order (the
module pins it as stages 1 → 0 → 2—7); each failure raises
`TokenValidationError` with a fixed reason that never contains token, key, or
claim material:

1. unverified structure parse (manual base64url + JSON — not
   `jwt.decode(verify_signature=False)`, which would run time checks early);
2. **step 0 (pre-claim, pre-network)**: header `alg` must be the exact
   case-sensitive string `"RS256"`, then `kid` must be a non-empty string —
   `none`/HS256 forgeries reject before any issuer membership or fetch;
3. issuer: the app's own exact set-membership against `allowed_issuers`
   (never PyJWT's `issuer=`; a strict-prefix `iss` is rejected);
4. key fetch bound to that issuer only: `jwks_source.signing_key(iss, kid)`;
5. `jwt.decode` with `algorithms=["RS256"]`, `options={"verify_aud": False}`
   (Cognito binds access tokens via `client_id`; `aud` is an ID-token claim),
   fixed 60-second leeway on `exp`/`iat`/`nbf`;
6. `token_use == "access"` (ID/refresh tokens rejected);
7. `client_id` exact set-membership;
8. claim shape: `sub` (≤255), required `email` (≤320), optional `username`
   (absent/null/empty normalize to `None`), then the frozen `CognitoClaims`.

Required claims: `sub`, `email`, `client_id`, `iss`, `exp`, `token_use`.
**`email` must appear in the access token** — the Cognito app client must be
configured to surface it (Phase 07 obligation); a token without it is a 401.

## Resolution and provisioning flow

```text
Authorization: Bearer <jwt>
  -> AccessTokenVerifier.verify           (no storage touched)
  -> resolve_or_provision(storage, claims)
       get_user_by_external_identity(cognito, sub, None)
         hit  -> exactly one read, zero writes
         miss -> build_provisioning_batch(claims, now, ids)
                 provision_user(...)      (one atomic Phase 02 batch)
         DuplicateExternalIdentityError
                 -> re-read identity tuple
                    found  -> converge on winner (existing_user_id is
                              cross-check only, never the convergence signal)
                    absent -> ProvisioningConflictError (email collision)
         user.status != active -> DisabledUserError (zero writes)
  -> build_user_context(storage, user)
  -> ResolvedIdentity(user, context)
```

Provisioning values (one `utc_now()` read and one ID set per request, shared
by all five entities and three audits):

- `User`: `active`, `display_name = username or sub`, token `email`.
- `ExternalIdentity`: `(cognito, sub, None)` — Cognito carries no tenant
  dimension; storage normalizes `None` internally.
- `Organization`: name `"{display_name}'s Workspace"`, slug
  `personal-{user_id}` (unique by construction, never derived from email),
  `personal`/`active`.
- `Membership`: `owner`/`active`.
- Audits (creation order): `user.created` `{"provider": "cognito"}`,
  `organization.created` `{"type": "personal"}`, `membership.created`
  `{"role": "owner"}`; targets `user`/`organization`/`membership` with the
  matching new ids; actor `user`/the new `usr_` (self-provisioning, FK
  satisfied inside the same transaction). No `sub`, token, or email in
  metadata.

## Context rule (`AuthorizationContext`, spec §10)

`build_user_context(storage, user, organization_id=None)`:

- default branch: the **earliest active** organization —
  `list_user_organizations(user_id, PageParams(limit=1))` (storage pins
  `(created_at, id)` ascending over active memberships only), role via
  `get_membership`; zero active organizations → `NoActiveOrganizationError`.
- explicit branch (Phase 04's org-selection seam, semantics pinned here):
  the given organization must exist, be `active`, and the user must hold an
  `active` membership — any failure raises `NoActiveOrganizationError`
  identically (403, no existence oracle).
- result: `actor_type="user"`, `actor_id=user.id`, `roles=[role]`, `scopes=[]`.

## HTTP surface and error mapping

`GET /v1/me` → 200 `MeResponse` (the `User` projection only; the frozen
manifest/schema are untouched). Mapping in `app/auth/dependencies.py`:

| Condition | Status | Envelope code |
| --- | --- | --- |
| missing/malformed bearer header; any `TokenValidationError` (incl. `UnknownKeyIdError`) | 401 | `unauthenticated` |
| `DisabledUserError`, `NoActiveOrganizationError` | 403 | `forbidden` |
| `ProvisioningConflictError` | 409 | `conflict` |
| `TokenProviderUnavailableError` | 503 | `internal_error` (frozen fallback; no new code invented) |

Verification and JWKS failures raise **before** any storage call — the
"rejected without storage mutation" acceptance holds structurally and is
proven per-401-variant with a recording storage wrapper.

## Convergence safety rule (supersedes Phase 02's docstring guidance)

`DuplicateExternalIdentityError.existing_user_id` is resolved by the SQLite
adapter through an **email fallback**, so in the not-a-race email-collision
case it names a stranger. Convergence therefore requires the identity-tuple
re-read (same `sub` found → winner); `existing_user_id` is advisory and used
only as a post-convergence cross-check — a disagreement is refused as
`ProvisioningConflictError`, never silently trusted.

## Published interfaces (what Phases 04/05/06/07 code against)

| Interface | Module | Consumers |
| --- | --- | --- |
| `AccessTokenVerifier.verify(token) -> CognitoClaims` | `src/app/auth/cognito.py` | Phase 05 (same seam, other credential kind), Phase 07 (wiring) |
| `JwksSource.signing_key(issuer, kid) -> PyJWK` (issuer-bound) | `src/app/auth/jwks.py` | Phase 07 (real Cognito domains) |
| `resolve_or_provision(storage, claims, *, now=None, ids=None) -> ResolvedIdentity` | `src/app/services/identity.py` | Phase 04+ auth dependencies |
| `build_user_context(storage, user, organization_id=None)` | `src/app/services/identity.py` | Phase 04 explicit org selection (no interface change needed) |
| `build_me_router(storage, verifier) -> APIRouter` | `src/app/api/me.py` | deployment entrypoint (`create_app`) |
| `build_current_user(storage, verifier)` | `src/app/auth/dependencies.py` | Phase 04/05 routers sharing the bearer chain |

Example (production wiring shape; environment reading happens at the
deployment edge, never at import time):

```python
from app.api.me import build_me_router
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.jwks import CognitoJwksSource
from app.main import create_app
from app.storage.sqlite import open_sqlite_storage

issuers = ["https://cognito.us-east-1.amazonaws.com/POOL_ID"]  # from config
verifier = CognitoAccessTokenVerifier(
    CognitoJwksSource(issuers), allowed_issuers=issuers, allowed_client_ids=[APP_CLIENT_ID]
)
app = create_app(routers=[build_me_router(open_sqlite_storage("var/feednow-auth.db"), verifier)])
```

## Verification

- `uv run pytest` — 739 passed (170 of them Phase 03): 55 idgen, 15 JWKS
  client, 38 verifier (every rejection individually, prefix-spoof issuer,
  `alg=none`/HS256 forgeries with `request_count == 0` pre-network proofs,
  no exception message contains token bytes), 20 stub-storage service rules
  (hit = one read/zero writes; stranger-id conflict proof), 4 SQLite service
  tests (full row read-back, repeat stability, disabled zero-mutation,
  collision no-partial-rows), 17 `/v1/me` integration tests (each 401 variant
  asserts zero storage calls; 403/409/503 named cases; envelope validated
  against the frozen `Error` model; response carries no provider material),
  21 concurrency cases (20 × 8-thread barrier races → one tenant, same
  `usr_`/`org_`; email-collision sequential case).
- Tests use signed fixtures and the loopback `JwksTestServer`
  (`src/tests/support/cognito.py`) — never a live Cognito pool.
- `uv run ruff check .` and `uv run ruff format --check .` clean; the
  subprocess-isolated no-`boto3` import proof for `app.main` stays green.

## Known limitations

- JWKS proactive TTL refresh, fetch rate-limiting, and rotation cooldown
  tuning are deferred to Phase 08 (`cooldown_duration` is 2.14-only and
  outside the pinned `>=2.13,<3` range).
- The explicit-`organization_id` context branch is defined and unit-tested,
  but no HTTP route exercises it until Phase 04 adds org selection; `/v1/me`
  uses the earliest-active default.
- The in-memory storage fake stays deferred (Phase 02 deferral honored:
  stubs + real SQLite cover every Phase 03 need).
- `WWW-Authenticate` headers and OpenAPI security-scheme polish are Phase 08.
- Default-workspace name/slug derivation and the required `email` claim are
  spec-revision proposals carried by the Phase 03 plan; the implemented
  behavior above is the current contract.
