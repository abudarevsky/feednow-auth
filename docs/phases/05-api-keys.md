# Current state: API-key credentials, verification, and scoped access

Phase 05 is implemented. Organizations mint product credentials
(``fn_live_``/``fn_test_`` literals) through three mounted §14 routes behind
the Phase 04 member/admin dependency, every bearer request dispatches to a
human (Cognito JWT) or machine (API-key) principal at one seam, API-key
authorization rides the same uniform audited 403 as human denials, and
revocation is an immediately effective first-write-wins CAS. The plaintext
secret crosses into an HTTP response exactly once (the create 201) and lives
nowhere else — storage holds only ``HMAC-SHA256(pepper, secret)``. No
DynamoDB (Phase 06), no deployment changes (Phase 07), no audit read surface
(Phase 08). Phase 05 adds **no storage methods** (the 19-method contract is
frozen) and **no runtime dependencies** (stdlib only).

## Scope

- `src/app/auth/credentials.py`: the credential format owner —
  `generate_key_id` (26-char Crockford-base32 ULID: 48-bit ms timestamp in
  chars 1–10 + 80 bits of `secrets` randomness in chars 11–26),
  `generate_secret` (`secrets.token_urlsafe(32)` — exactly 256 bits, 43
  base64url chars), `build_literal`/`parse_literal` (fixed 8-char environment
  prefix, split at the **first** `_`; the underscore-free key-id alphabet is
  what makes the split unambiguous even when the secret contains `_`),
  `hash_secret` (`HMAC-SHA256(pepper, secret)`, lowercase hex),
  `secret_matches` (`hmac.compare_digest`, constant-time), and
  `dummy_secret_matches` (the timing-equalized no-op comparison against a
  fixed same-shape digest for the unknown-key branch). Every shape violation
  raises `ApiKeyCredentialFormatError` with one fixed, input-echo-free
  message; `ParsedCredential` redacts the secret from `repr`/`str`.
- `src/app/auth/pepper.py`: `PepperSource` (runtime-checkable protocol,
  single `current() -> bytes` method — the rotation seam) and `StaticPepper`
  (in-memory implementation; ≥ 32-byte floor enforced at pure construction,
  input copied, `repr`/`str` redacted).
- `src/app/services/idgen.py`: `new_api_key_id()` mints the `key_`
  application identity with the established uuid4-based strategy; the §8
  credential segment deliberately stays in `credentials.py` so credential
  entropy never masquerades as application-ID entropy.
- `src/app/services/api_key_service.py`: `create_api_key` (normalize →
  mint → build → persist → `api_key.created` audit **after** the successful
  write → `(ApiKey, literal)`), `list_api_keys` pass-through,
  `revoke_api_key` (get → tenancy check → CAS → one truthful
  `api_key.revoked` per processed call), `build_key_prefix` (44-char masked
  display prefix), the audit builders, and the domain errors the router
  translates (`ApiKeyNotFoundError`, `ApiKeyConflictError`). No FastAPI
  imports.
- `src/app/auth/api_key_auth.py`: `verify_api_key` (the fixed-order
  verification pipeline), the uniform `ApiKeyAuthenticationError` (one
  message for every failure), `build_api_key_context` (§10 derivation), and
  `key_has_scope` (exact-string membership — no wildcards, no hierarchy).
  Pure and in-process; no FastAPI import, so product authorizers can reuse
  the seam without an HTTP hop.
- `src/app/auth/principal.py`: frozen `Principal(user, api_key, context)` —
  exactly one actor set, enforced structurally in `__post_init__`.
- `src/app/auth/dependencies.py`: `build_current_principal(storage, verifier,
  pepper_source)` — prefix dispatch (`fn_live_`/`fn_test_` → the key seam;
  anything else → the unchanged Phase 03 JWT chain). A JWS compact token
  always starts `eyJ`, never `fn_`, so the two verifiers can never receive
  each other's input.
- `src/app/auth/organization_access.py`: the API-key branch. The member/admin
  factories gained keyword-only `pepper_source: PepperSource | None = None`
  (`None` keeps the exact Phase 03/04 chain — byte-stable regression); with
  one wired, a key bearer on a management route gets the uniform 403 audited
  `human_only` after the organization fetch (so the denial row has its FK
  target). `build_organization_scope_dependency` is the new key-carrying
  seam yielding `PrincipalAccess(principal, organization)`.
- `src/app/models/authorization_context.py`: `actor_type_for(actor_id)` —
  the derivation sharing its single source with the §10 consistency
  validation.
- `src/app/services/authorization.py`: `build_denial_audit`/`audit_denial`
  generalized from `UserId` to any `ActorId` (actor type derived via
  `actor_type_for`); `AccessOutcome`/`DENIAL_REASONS` gained `human_only`,
  `organization_mismatch`, `insufficient_scope` (seven auditable reasons;
  human-actor behavior unchanged).
- `src/app/api/keys.py`: `build_api_keys_router(storage, verifier,
  pepper_source)` registering the three frozen manifest entries; no authz
  logic in handlers.

## Mounted HTTP surface

| Route | Access rule | Success | Failure additions |
| --- | --- | --- | --- |
| `GET /v1/organizations/{organization_id}/api-keys` | member dependency (any active role, human; `pepper_source` wired so key bearers get the audited `human_only` 403) | 200 `Page[ApiKeySummary]` (masked, all statuses) | 400 `validation_error` (bad cursor), 403 uniform denial |
| `POST /v1/organizations/{organization_id}/api-keys` | admin dependency (rank ≥ admin, human) | 201 `ApiKeyCreatedResponse` — the **only** full-literal response of the API | 422 (bad scope shape), 409 (minted-id collision), 403 |
| `DELETE /v1/organizations/{organization_id}/api-keys/{key_id}` | admin dependency (human) | 204 empty body (idempotent) | 404 (unknown **or** foreign-org key — one byte-identical body), 403 |

`{key_id}` in the revoke path is the `key_` application identity
(`ApiKeySummary.id`) — never the §8 credential segment, which appears in no
path and no payload as a standalone field (it surfaces only inside the
masked `key_prefix`, where §8 designed it to be visible).

## Credential format and parse contract (decision 2)

- Literal: `fn_<live|test>_<key-id>_<secret>` — 8-char fixed environment
  prefix, 26-char Crockford-base32 ULID key-id (non-secret point-lookup
  segment), 43-char base64url secret (256 bits of CSPRNG entropy). 78 chars
  total, inside the frozen `FullApiKey` ≤ 512 bound.
- Stored: `key_id` (UNIQUE-indexed lookup segment), `secret_hash` =
  `HMAC-SHA256(pepper, secret)` lowercase hex, `key_prefix` =
  `fn_<env>_<key-id>_<first 6 secret chars>...` (44 chars — masked
  identification only), never the secret itself.
- Parse: strip the fixed prefix, split at the **first** `_` (the key-id
  charset contains no `_`), exact Crockford-26 shape check on the key-id
  segment, non-empty secret (which may contain `_`). Every violation — wrong
  prefix, missing/empty segment, bad shape, oversized input — raises the one
  format error with one fixed message; no input fragment ever enters any
  exception text, cause, or context.
- The environment prefix is **authenticated data, not a routing hint**: the
  parsed environment must equal the stored `environment` (defense in depth
  against an inconsistent row), and it is what `verify_api_key` never has to
  trust from the caller's organization context.

## Pepper (decision 3; Phase 07 obligation)

`PepperSource.current() -> bytes` is the seam; `StaticPepper` is the
in-memory implementation used by tests and non-AWS deployments and enforces
the ≥ 32-byte floor at pure construction (no I/O, no config import). The
**Phase 07 obligation** is to wire the AWS Secrets Manager implementation at
the deployment entrypoint behind this same protocol — never read the pepper
from an environment dump, never log it, keep it out of `repr`/`str` and
error text (the protocol's construction-safety contract). `current()` being
a method (not an attribute) is the rotation seam: a future versioned source
needs no consumer signature change. Rotation itself is a Phase 05 non-goal.

## Verification pipeline (decision 4) — fixed order, uniform failure

`verify_api_key(storage, pepper_source, literal, *, now=None)` runs:

1. **Parse** (format failure → uniform error before any secret-source or
   storage touch);
2. **Point lookup** by key-id segment — on a miss the pipeline still performs
   the **dummy constant-time comparison** (identical HMAC + `compare_digest`
   work against a fixed digest no achievable input matches) before failing,
   so unknown-key and wrong-secret are indistinguishable on the **timing**
   axis, not just the message axis;
3. **Secret match** (constant-time);
4. **Environment match**;
5. **Status** must be `active`;
6. **Expiry** (derived, never a stored status): `expires_at` is `None` or
   strictly in the future — the boundary `expires_at == now` is **expired**
   (the `<=` comparison is pinned and test-asserted).

Every failure raises the one `ApiKeyAuthenticationError` with the single
fixed message `"invalid API key credentials"` — the router renders it as the
one uniform 401 `unauthenticated` body. Any other `StorageError` (a backend
outage, not a bad credential) propagates untranslated → 500, never a
misleading 401. Organization status and scopes are **authorization, not
authentication**: they are enforced by the access dependency below, where
denials ride the Phase 04 uniform audited 403.

## Principal dispatch and scoped access (decisions 6/7/8)

- `build_current_principal` dispatches on the bearer literal's **prefix**
  only; both branches wrap into the same `Principal` (human path: the
  unchanged Phase 03 `ResolvedIdentity` pair verbatim; key path: the verified
  row plus its context).
- Management routes are **human-only**: on a `pepper_source`-wired factory
  (the api-keys router today; the organizations/members routers join when
  the entrypoint wires pepper) a key bearer gets the uniform 403 audited
  `human_only` — keys never borrow a human role check (the AC-4 no-escalation
  proof). On routes built without a `pepper_source`, an `fn_` literal simply
  fails JWT verification → 401 (Phase 04 behavior, byte-stable).
- `build_organization_scope_dependency(storage, verifier, pepper_source,
  required_scope, operation_id)` is the key-carrying seam for product
  routes. Human branch: Phase 04 member-rank rules; `required_scope` is
  **never consulted for humans** (roles govern for people; product
  permissions are API-key scopes only). API-key branch, fixed precedence:
  organization status → `organization_mismatch` (the key's organization must
  equal the path organization) → `insufficient_scope` (exact-string
  membership of `required_scope` in the stored scopes — no wildcards, no
  hierarchy). Every denial is the same byte-identical 403 with its
  deterministic audit reason.

## §10 context shapes

| Actor | `actor_type` | `actor_id` | `organization_id` | `roles` | `scopes` |
| --- | --- | --- | --- | --- | --- |
| Human (JWT) | `"user"` | `usr_` | earliest active membership (or explicit) | `[role]` | `[]` |
| API key | `"api_key"` | `key_` (the application identity — never the creator `usr_`, never the credential segment) | the stored key's organization | `[]` **always** (creator memberships are never consulted) | the stored sorted-unique scopes |

## Denial vocabulary and audit metadata after Phase 05 (§16)

`authorization.denied` metadata stays exactly `{"reason", "operation"}`; the
`reason` set is now seven (`no_membership`, `inactive_membership`,
`inactive_organization`, `insufficient_role`, plus the Phase 05
`human_only`, `organization_mismatch`, `insufficient_scope`), the actor is
any §10 identity (`usr_` → `actor_type="user"`, `key_` → `"api_key"`,
derived via `actor_type_for`), and the unknown-org no-FK exception and
fail-closed append-failure→500 rules are unchanged for both actor kinds.

| Action | Metadata (exact) | Target | Actor | When |
| --- | --- | --- | --- | --- |
| `api_key.created` | `{"environment", "scopes"}` (sorted-unique list; no secret material) | `api_key`/`key_` id | human creator `usr_` | **after** a successful `create_api_key` write |
| `api_key.revoked` | `{}` (the `revoked_at` truth lives on the key row) | `api_key`/`key_` id | human revoker `usr_` | one truthful audit per processed revoke call (duplicate/concurrent revokes each audited) |
| `authorization.denied` | `{"reason", "operation"}` | none | `usr_` **or** `key_` | every denial whose organization row exists, before the 403 |

## Create/revoke rules (decisions 9/10/11)

- **Create** is non-idempotent: a minted-`key_`-id or key-id-segment
  collision (the storage UNIQUE index is the arbiter) → `ApiKeyConflictError`
  → 409 with a fixed retry message and **zero** audit rows and zero
  mutation; the correct client behavior is a plain retry with fresh entropy.
  Scopes are normalized sorted-unique once, so the persisted row and the
  creation audit carry the identical canonical list. The literal is
  assembled from the stored (caller-echo) segments plus the minted secret and
  returned only in the 201.
- **Revoke** is get → tenancy check → CAS: a foreign-org key raises the
  **same** `ApiKeyNotFoundError` with the **same** fixed message *before* any
  CAS call (the revoke path is not a cross-org existence oracle; unknown and
  foreign both render one byte-identical 404). The contract's first-write-wins
  CAS makes duplicate/concurrent revocation an idempotent success preserving
  the **original** `revoked_at`, each processed call appending its own
  truthful audit. "Immediately effective" is structural: verification reads
  stored truth per request — no cache, no per-request HTTP call.
- **List** is the contract's org-scoped, all-statuses page, projected
  field-by-field to `ApiKeySummary` (masked `key_prefix` only; no
  `secret_hash`, no plaintext, no standalone credential segment — the
  key-id appears only inside the masked prefix by design),
  `limit`/`next_cursor` passed through verbatim.

## Error mapping (decision 11; frozen envelope codes only)

| Condition | Status | `code` |
| --- | --- | --- |
| Any API-key authentication failure (format, unknown, wrong secret, env skew, revoked, expired) | 401 | `unauthenticated` (one fixed message) |
| `InvalidCursorError` | 400 | `validation_error` |
| Bad scope shape / unknown fields / missing body fields | 422 | `validation_error` (frozen schemas) |
| `ApiKeyConflictError` (minted-id collision) | 409 | `conflict` |
| `ApiKeyNotFoundError` (unknown **or** foreign-org key) | 404 | `not_found` |
| Access denials (all seven reasons) | 403 | `forbidden` (one fixed message) |
| any other `StorageError` | — | untranslated → frozen 500 `internal_error` (adapter text never echoed) |

## Concurrency behavior (proven by barrier races, 20 repeats each)

- 8 concurrent revokes of one key → all 204, exactly one stored `revoked_at`
  (the CAS winner, ∈ the audit timestamps), 8 truthful audits; an
  interleaved verification goes 200→401 monotonically and never back.
- 8 concurrent creates → 8 distinct ids/segments/secrets/literals, 8 rows,
  8 audits (creation is deliberately non-idempotent).
- Forced key-id and forced `key_`-id collisions (monkeypatched generators) →
  409 with zero audit rows and zero mutation, proven by direct reads.

## Published interfaces (what Phases 06/07/08 code against)

| Interface | Module | Consumers |
| --- | --- | --- |
| `verify_api_key(storage, pepper_source, literal, *, now=None) -> VerifiedApiKey(api_key, context)` + `build_api_key_context` + `key_has_scope` | `src/app/auth/api_key_auth.py` | Phase 06+ product authorizers (in-process, read-only — no per-request HTTP call back to this service), Phase 07 wiring |
| `build_current_principal(storage, verifier, pepper_source)` + `Principal` | `src/app/auth/dependencies.py`, `src/app/auth/principal.py` | any human-or-key route; Phase 07 entrypoint |
| `build_organization_scope_dependency(storage, verifier, pepper_source, required_scope, operation_id)` → `PrincipalAccess` | `src/app/auth/organization_access.py` | the reusable scoped-authorizer seam for product operations (Phase 06+ consumers of this service mount it on their own routes) |
| `PepperSource` / `StaticPepper` | `src/app/auth/pepper.py` | **Phase 07**: Secrets Manager implementation at the entrypoint (≥ 32-byte floor, never in env dumps); tests keep `StaticPepper` |
| Credential primitives (`generate_key_id`, `generate_secret`, `build_literal`, `parse_literal`, `hash_secret`, `secret_matches`, `dummy_secret_matches`) | `src/app/auth/credentials.py` | Phase 07 key-minting tooling; any future provider must reuse the parse/hash contract unchanged |
| `create_api_key` / `revoke_api_key` / `list_api_keys` + audit builders + `ApiKeyNotFoundError`/`ApiKeyConflictError` | `src/app/services/api_key_service.py` | `build_api_keys_router`; Phase 08 audit read surface (same metadata discipline) |
| `build_api_keys_router(storage, verifier, pepper_source)` | `src/app/api/keys.py` | deployment entrypoint (`create_app(routers=[...])`) |
| `actor_type_for` + generalized `audit_denial`/`build_denial_audit` (`ActorId`) + the seven-reason `DENIAL_REASONS` | `src/app/models/authorization_context.py`, `src/app/services/authorization.py` | every future actor kind's denials (no new plumbing needed) |
| The five existing api-key storage ops (`create_api_key`, `get_api_key`, `get_api_key_by_key_id`, `revoke_api_key` CAS, `list_api_keys`) — **unchanged 19-method contract** | `src/app/storage/contract.py` | **Phase 06**: the DynamoDB adapter must pass the same conformance-suite cases (key_id UNIQUE, first-write-wins CAS with original `revoked_at`, org-scoped order) — nothing new to add |

Example (production wiring shape; Phase 07 mounts all four routers on the
same storage/verifier instances and replaces `StaticPepper` with the
Secrets Manager source):

```python
from app.api.keys import build_api_keys_router
from app.api.members import build_members_router
from app.api.me import build_me_router
from app.api.organizations import build_organizations_router
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper  # Phase 07: Secrets Manager PepperSource
from app.main import create_app
from app.storage.sqlite import open_sqlite_storage

issuers = ["https://cognito.us-east-1.amazonaws.com/POOL_ID"]  # from config
verifier = CognitoAccessTokenVerifier(
    CognitoJwksSource(issuers), allowed_issuers=issuers, allowed_client_ids=[APP_CLIENT_ID]
)
storage = open_sqlite_storage("var/feednow-auth.db")
pepper_source = StaticPepper(pepper_bytes)  # ≥ 32 bytes, never from an env dump
app = create_app(
    routers=[
        build_me_router(storage, verifier),
        build_organizations_router(storage, verifier),
        build_members_router(storage, verifier),
        build_api_keys_router(storage, verifier, pepper_source),
    ]
)
```

## Verification

- `uv run pytest` — **1253 passed** (baseline 943 + 310 Phase 05: tasks 1–2
  146 — credentials 84, pepper 19, idgen +11, api_key_service 32; task 3 34
  verification-matrix units; task 4 +17 authorization-rule extensions; task
  5 +28 (principal dispatch 15, organization access +13); task 6 20 endpoint
  integration tests; task 7 +65 acceptance proofs — secrecy 4, auth matrix
  18, concurrency 42, audit hygiene +1).
- `uv run pytest src/tests/storage_contract` — 64 passed **unchanged**:
  Phase 05 added no storage methods; the five api-key ops (key_id UNIQUE,
  revoke CAS) were already in the adapter-neutral suite Phase 06 re-runs
  against DynamoDB Local.
- Acceptance proofs (task 7): full-battery secrecy sweep (`caplog` at every
  level + direct reads of every `api_keys`/`audit_events` row + every raw
  `secrecy.sqlite*` database file, WAL sidecars included — no literal,
  secret, credential segment outside the designed masked `key_prefix`, or
  pepper byte anywhere); the decision-4 failure matrix through a probe route
  (byte-identical 401s, zero storage mutation by recording counts);
  barrier-based concurrency (20 repeats, no sleeps, counts via direct SQLite
  reads).
- Tests use the loopback `JwksTestServer` and a fixed ≥ 32-byte test pepper —
  never a live Cognito pool, never a real secret store.
- `uv run ruff check .` and `uv run ruff format --check .` clean;
  `git diff --check` clean; the subprocess-isolated no-`boto3` import proof
  for `app.main` stays green (Phase 05 adds no runtime dependencies —
  `pyproject.toml`/`uv.lock` untouched).

## Known limitations

- **`last_used_at` is never set**: verification is deliberately read-only and
  the storage contract has no key-update method (adding a per-request write
  would make every verification a mutation — escalated as a §14 spec-revision
  proposal; usage recording is a Phase 08 candidate).
- **Expiry is enforced but not settable through the API**: the frozen §15
  create request has no `expires_at` field; verification honors seeded/derived
  expiries (the `expires_at == now` boundary is expired), and the escalation
  to add the field is on the planner record.
- **No rotation, no scope wildcards/hierarchy, no API-key self-management**:
  one current pepper version, exact-string scope match, and management
  restricted to organization admins (all phase non-goals, not omissions).
- **Audit-append-after-commit window** (unchanged from Phase 04): a crash
  between the committed key write/CAS and its audit append loses the audit
  row, not the mutation.
- **Duplicate revocations each append a truthful `api_key.revoked`**: with
  same-clock ties, winner-detection is impossible under the contract, so the
  idempotent success is audited once per processed call (documented semantics,
  not a bug to dedupe).
- **A key survives disabling its creator user**: no coupling was invented
  between `UserStatus` and `ApiKeyStatus` (the spec defines none); revoking
  a user's keys on disable is a Phase 08 revisit candidate.
- The list endpoint returns all key statuses (active and revoked) by
  contract; no filter is invented.
