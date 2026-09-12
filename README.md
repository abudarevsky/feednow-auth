# feednow-auth

FeedNow application identity, organization tenancy, authorization context,
API credentials, and audit records. Runtime code lives in `src/app`; HTTP
handling lives in `src/app/api`, credential/JWT logic in `src/app/auth`, domain
types in `src/app/models`, business rules in `src/app/services`, and
persistence in `src/app/storage`.

## Requirements

- [uv](https://docs.astral.sh/uv/) as the package/venv manager
- Python 3.14.5 for the dev toolchain (pinned in `.python-version`; uv will
  fetch it if missing). The package itself declares `requires-python = ">=3.13"`
  for Lambda runtime compatibility.

## Local development

```bash
uv sync                                      # create .venv and install dependencies
uv run pytest                                # unit/integration tests
uv run ruff check .                          # lint
uv run ruff format --check .                 # formatting gate
uv run uvicorn app.main:app --reload        # development server with uvloop
uv run feednow-auth                          # server without reload
```

`uv sync` resolves against the committed `uv.lock`, so environments are
reproducible; do not edit `uv.lock` by hand.

## Layout

```text
src/app/             Runtime service package
  api/               FastAPI routers, dependencies, and schemas
  auth/              JWT/API-key authentication and authorization resolution
  models/            Provider-neutral domain entities and value types
  services/          Provisioning, tenancy, membership, keys, and audit rules
  storage/           Storage contract and adapters
src/tests/            Unit, integration, and adapter conformance tests
  unit/
  integration/
  storage_contract/
deploy/aws/          Lambda packaging; deploy/aws/cdk/ holds the CDK app
specs/               Specification (draft/) and ordered phases (wip/)
```

## Phase 01 contracts (handoff)

Phase 01 ships provider-neutral domain and API contracts only: no storage
adapter, no Cognito validation, no §14 endpoint behavior, no CDK. The
modules below are the frozen surface later phases code against — editing
them is a contract change requiring a spec revision. Delivery commands are
in [Local development](#local-development); the toolchain is Python 3.14.5
via `.python-version` + committed `uv.lock`, with `requires-python = ">=3.13"`
for Lambda compatibility (do **not** narrow to `==3.14.*`).

### Contract modules

| Module | Surface | First consumer |
| --- | --- | --- |
| `src/app/models/ids.py` | Prefix-validated ID value objects: application identities `UserId`/`OrganizationId`/`ApiKeyId` (`usr_`/`org_`/`key_`), internal record IDs `ExternalIdentityId`/`MembershipId`/`AuditEventId` (`extid_`/`mem_`/`aud_`), `ActorId` union, `ProviderSubject` (plain string) | Phase 02 storage keys |
| `src/app/models/timestamps.py` | `UtcDatetime` (reject-naive input, UTC `Z` ISO-8601 JSON), `utc_now`, `ensure_utc`, `to_utc_rfc3339` | Phase 02 round-trips |
| `src/app/models/pagination.py` | `Page[T]`, `PageParams`, `Cursor`, `clamp_limit`, bound constants | Phase 02 adapters |
| `src/app/models/errors.py` | `Error`/`FieldError` envelope + `ErrorCode` (no HTTP status encoded) | wired to HTTP by `src/app/api/errors.py` |
| `src/app/models/enums.py` | All pinned `StrEnum` sets (see Conventions) | Phase 02 stores as strings; Phase 05 branches |
| `src/app/models/{user,external_identity,organization,membership}.py` | §4 identity entities, `extra="forbid"`, exact field lists | Phase 02 rows; Phase 03 provisioning |
| `src/app/models/{api_key,audit_event,authorization_context}.py` | §4 credential/audit entities + §10 context (actor-type/actor-id consistency rule) | Phase 02 rows; Phases 04/05 services |
| `src/app/api/schemas/*` | Versioned request/response models for §14/§15 payloads | Phase 04/05 routers |
| `src/app/api/schemas/manifest.py` | Frozen endpoint manifest: `API_V1_PREFIX`, `EndpointSpec`, `ENDPOINTS` (all 10 §14 routes), `endpoint_for` | Phase 04/05 mounting |
| `src/app/main.py` | `create_app(routers=...)` factory + module-level `app` (uvicorn target) | Phase 04/05 registration |

### Conventions

| Topic | Rule |
| --- | --- |
| ID prefixes | `usr_`/`org_`/`key_` are the only application identities (usable as `actor_id` and §14 path parameters). `extid_`/`mem_`/`aud_` record IDs are internal: never in paths, never in response payloads. Provider subjects (Cognito `sub`, Shopify IDs) are constrained strings, never coerced into ID types. |
| Enum values | `UserStatus {active, disabled}` · `OrganizationStatus {active, disabled}` · `MembershipStatus {active, disabled}` (member removal = physical delete; `disabled` is a suspension) · `ApiKeyStatus {active, revoked}` (expiry is **derived** from `expires_at` at verification, never a stored status) · `MembershipRole {owner, admin, member, viewer}` · `OrganizationType {personal, customer, internal}` · `ApiKeyEnvironment {live, test}` · `IdentityProvider {cognito, shopify, google, microsoft, oidc}` |
| Scope pattern | `^[a-z][a-z0-9]*(:[a-z][a-z0-9]*){2}$` — exactly three lowercase `product:resource:action` segments. Single source: `SCOPE_PATTERN`/`Scope` in `src/app/models/api_key.py`; API schemas reuse `Scope` and must never re-declare the regex. |
| Timestamps | Naive datetimes rejected on input; JSON serializes as UTC ISO-8601 with `Z` suffix so SQLite/DynamoDB round-trips stay comparable. |
| Page limits | `limit` default 20, min 1, max 100; out-of-range requests are **clamped**, never a 422. |
| Cursor opacity | `cursor`/`next_cursor` are opaque strings (≤ 2048 chars). Only `src/app/storage` adapters generate or decode cursor content; nothing above an adapter may parse, construct, or depend on it (AGENTS.md). |
| Error envelope | `{"code", "message", "field_errors", "request_id"}` with stable codes `validation_error`, `unauthenticated`, `forbidden`, `not_found`, `conflict`, `internal_error`. `field_errors` entries carry only `field` + `message` (never submitted values). HTTP status mapping lives solely in `src/app/api/errors.py` (422 validation, 400/401/403/404/409 table, unmapped <500 → `validation_error`, ≥500 → `internal_error`). |
| Versioning | Every §14 route lives under `API_V1_PREFIX = "/v1"`. `/health` is operational, outside the manifest and the versioned surface. |

### Mounting convention (Phase 04/05)

- Routers land in `src/app/api/<resource>.py` and are attached by passing them
  to `create_app(routers=[...])` in the deployment entrypoint. Phase 01
  mounts **no** §14 routers (endpoint behavior is a non-goal).
- Every mounted route must match a `manifest.ENDPOINTS` entry exactly:
  method, full `/v1` path, request/response models, `PageParams` query for
  lists, success status (GET 200, create 201, delete 204 no-body), and
  path-parameter identity types. A route absent from the manifest may not
  be mounted without a spec revision.
- `{key_id}` in the revoke path carries the `key_` application identity
  (`ApiKeyId`, i.e. `ApiKeySummary.id`) — never the §8 non-secret `key_id`
  credential segment, which stays out of all paths and payloads.
- `EndpointSpec` self-validates the structural invariants at import time
  (prefix, 204-no-body, `Page`↔`paginated`, `PageParams` query,
  request-model rules, placeholders↔`path_params` match); the 200/201
  convention and identity-typed path params are enforced by the manifest
  tests in `src/tests/unit/test_endpoint_manifest.py`.

### Planner decisions (binding on later phases)

- **Python:** `requires-python = ">=3.13"` (spec compatibility; Phase 07
  Lambda runtime may be 3.13) while `.python-version = 3.14.5` pins the dev
  toolchain; `uv.lock` is committed and never hand-edited.
- **ID generation deferred:** Phase 01 types validate prefix/shape only.
  Concrete entropy strategies (ULID-style `key_id`, user/org IDs) belong to
  owner phases 03/05; do not add a generator in Phase 01 code.
- **Scopes are review-only:** "no commercial plan or rate-limit policy in
  scopes" (AGENTS.md, spec §9) is a design/review rule, **not** a runtime
  denylist. Phase 05 must not add one.
- **boto3:** not a Phase 01 dependency at all, enforced by a
  subprocess-isolated import check (fresh interpreter, so test order cannot
  skew it) — deliberately *not* an in-process `sys.modules` assertion, which
  would false-fail in Phase 06 when boto3 becomes a lazily-imported adapter
  dependency.
- **Record-ID prefixes** `extid_`/`mem_`/`aud_` are Phase 01 definitions
  (spec §4 gives `id` without fixing prefixes) — see the derived register.
- **`ApiKey`/`ApiKeySummary` secret policy:** the only secret-derived field
  anywhere is `ApiKey.secret_hash` (persisted-entity model; no API payload
  carries it). The only credential material in any payload is
  `ApiKeyCreatedResponse.key`, returned exactly once at creation; it is
  never persisted, logged, or re-served.

### Derived-payload register (Phase 01 contract additions → spec-revision proposals)

§14/§15 define no body for the following; each was derived from endpoint
semantics (payloads and success statuses are additionally listed in
`src/app/api/schemas/manifest.py`'s docstring register). §15's
key-creation request/response are copied verbatim and are **not** derived.

| Payload | Derived fields |
| --- | --- |
| `MeResponse` | `id`, `display_name`, `email`, `status`, `created_at`, `updated_at` (mirrors §4 `User`) |
| `OrganizationCreateRequest` | `name`, `slug`, `type` (default `customer`; `personal` is provisioning-owned, `internal` operator-only) |
| `OrganizationResponse` | `id`, `name`, `slug`, `type`, `status`, `created_at`, `updated_at` (mirrors §4 `Organization`) |
| `MemberCreateRequest` | `user_id`, `role` (status server-assigned) |
| `MemberResponse` | `user_id`, `role`, `status`, `created_at` (membership `mem_` record ID deliberately omitted) |
| `ApiKeySummary` | `id`, `name`, `environment`, `key_prefix`, `status`, `scopes`, `created_at`, `last_used_at`, `expires_at`, `revoked_at` (masked only) |
| Success statuses | GET 200; create POST 201 (REST convention — the spec pins only "deletes = 204") |
| `{key_id}` path parameter | interpreted as the `key_` application identity (see Mounting convention) |
| Record-ID prefixes | `extid_`/`mem_`/`aud_` (see Planner decisions) |
| Pinned enum values | full value sets incl. `ApiKeyStatus {active, revoked}` + derived-expiry semantics and membership physical-delete semantics |

### Commands

```bash
uv sync                          # reproducible env from uv.lock
uv run pytest                    # full suite (335 tests at Phase 01 completion)
uv run ruff check .              # lint
uv run ruff format .             # format (commits must keep --check clean)
uv run uvicorn app.main:app --reload   # health-only skeleton with uvloop
uv run feednow-auth                  # installed entry point without reload
```

## Phase 02 storage contracts (handoff)

Phase 02 ships the storage boundary only: the `Storage` protocol, the SQLite
adapter, and the adapter-neutral conformance suite. No service, route, or
deployment code reads or writes through it yet — Phases 03/04/05 are the first
consumers, and Phase 06 runs the same suite against DynamoDB Local. Editing the
modules below is a contract change requiring a spec revision.

### Contract modules

| Module | Surface | First consumer |
| --- | --- | --- |
| `src/app/storage/contract.py` | `Storage` (`@runtime_checkable` Protocol, 18 sync methods: users, external identities, organizations, memberships, API keys, `append_audit_event`, `provision_user`, three paginated lists); domain errors `StorageError`/`EntityNotFoundError`/`DuplicateEntityError` (+`DuplicateEntityKind`)/`DuplicateExternalIdentityError`/`ReferenceNotFoundError`/`InvalidCursorError`; frozen `ProvisionedUser` caller-echo bundle | Phases 03/04/05 services; Phase 06 adapter |
| `src/app/storage/__init__.py` | Contract symbols only; never imports an adapter | any `app.storage` importer |
| `src/app/storage/sqlite.py` | `open_sqlite_storage(path: str | Path) -> Storage` factory, `SQLiteStorage` adapter, schema v1 (6 tables, 5 unique indexes), codecs, opaque keyset cursors, sqlite3→domain error translation | Phase 03 provisioning; Phase 06 (as the behavior reference) |
| `src/tests/storage_contract/suite.py` | 56 adapter-neutral behavior cases + deterministic `make_*` builders; module docstring is the fixture/import/builder reuse contract | Phase 06 DynamoDB entry (imported unchanged) |
| `src/tests/storage_contract/test_sqlite_contract.py` | SQLite entry point: `storage` fixture (fresh temp file per test) + suite-import isolation proofs | Phase 06 copies this pattern |

### Storage conventions

| Topic | Rule |
| --- | --- |
| Access | Application code is typed against `Storage` only and obtains instances through the documented factory; adapters are imported by explicit submodule path (`from app.storage.sqlite import open_sqlite_storage`), never constructed above `app/storage`. |
| Protocol | Synchronous `def` methods (stdlib `sqlite3` and `boto3` are sync; FastAPI uses its threadpool). Stdlib `sqlite3` only — no ORM. |
| Identity minting | Storage never mints IDs or timestamps: every write receives a fully formed domain entity and reads back unchanged; `revoke_api_key` takes `revoked_at` from the caller (`utc_now` is the service clock). Entropy strategies stay Phase 03/05 work. |
| Error vocabulary | Driver errors are translated inside the adapter; only `StorageError` subclasses escape. `kind` is the machine-readable discriminator; `entity_id` covers primary-key collisions on any table. HTTP 404/409 mapping is Phase 04+ work in `app/api`. |
| Uniqueness | `(provider, provider_subject, tenant_normalized)`, `(organization_id, user_id)`, `organization.slug`, `user.email`, and `api_keys.key_id` (credential segment) — five unique indexes. Email and slug are constraints, never identities. |
| Tenant normalization | `provider_tenant=None` stores as `''` and reads back as `None` (lossless: `ProviderTenant` pins `min_length=1`); SQLite `UNIQUE` treats NULLs as distinct, so normalization is what makes the constraint deterministic. Phase 06 keeps the same semantics. |
| Stored timestamps | Fixed-width TEXT `YYYY-MM-DDTHH:MM:SS.ffffffZ` (microseconds always present) so lexicographic order equals chronological order; `to_utc_rfc3339` (API JSON) must not be reused for stored columns. |
| Pagination | Keyset over `(created_at, id)` ascending; opaque base64url cursor carrying position plus a list-scope tag (a cursor from one list is invalid for another); `limit + 1` fetch decides `next_cursor`; `limit` re-clamped via `clamp_limit`; tampered/foreign cursors raise `InvalidCursorError`. Cursors are created/decoded only inside the adapter. |
| Transactions / CAS | `provision_user` writes user + identity + organization + membership + audit events (required keyword-only) in one `BEGIN IMMEDIATE` transaction; any email/identity-tuple conflict maps to `DuplicateExternalIdentityError` (with `existing_user_id` when resolvable) after full rollback. `revoke_api_key` is a first-write-wins CAS: duplicate/concurrent revocations return the stored key with the original `revoked_at` (idempotent success); an unknown id raises. |
| Tenancy | `get_api_key`/`revoke_api_key` are keyed by the `key_` identity and are deliberately **not** org-filtered (verification resolves the org *from* the key); `get_api_key_by_key_id` is the §8 credential-segment lookup. Org-scoped route enforcement is Phase 05 service work. |
| Referential integrity | `identity→user`, `membership→org+user`, `api_key→org+creator`, `audit→org` are enforced by every adapter (`PRAGMA foreign_keys=ON` in SQLite; conditional writes in Phase 06) and raise `ReferenceNotFoundError`. |
| Stored JSON / enums | `scopes` and `audit.metadata` round-trip exactly as JSON (scope order and duplicates preserved — normalization is Phase 05); enums store exact `StrEnum` strings; row→domain goes through `model_validate`, so corrupt stored values fail loudly. |
| Audit | `append_audit_event(event) -> None` is the standalone write path for Phase 03–05 events; only provisioning batches go through `provision_user`. No audit read/list surface this phase (Phase 08). |
| Connection model | Thread-local connections, `journal_mode=WAL`, `busy_timeout` 5000 ms, `foreign_keys` asserted on as the first statement per connection, idempotent schema init stamped with `PRAGMA user_version`; `close()` releases and the instance is not reusable. Concurrency tests use barriers + WAL, never sleeps. |
| Conformance invocation | `uv run pytest src/tests/storage_contract` (60 tests: 56 suite cases + 4 harness isolation proofs) against a clean temporary SQLite database per test. |
