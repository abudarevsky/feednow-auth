# feednow-auth

FeedNow application identity, organization tenancy, authorization context,
API credentials, and audit records. HTTP handling lives in `app/api`,
credential/JWT logic in `app/auth`, domain types in `app/models`, business
rules in `app/services`, and persistence in `app/storage`.

## Requirements

- [uv](https://docs.astral.sh/uv/) as the package/venv manager
- Python 3.14.5 for the dev toolchain (pinned in `.python-version`; uv will
  fetch it if missing). The package itself declares `requires-python = ">=3.13"`
  for Lambda runtime compatibility.

## Local development

```bash
uv sync                      # create .venv and install runtime + dev deps
uv run pytest                # unit/integration tests
uv run ruff check .          # lint
uv run ruff format .         # format
uv run uvicorn app.main:app --reload   # run the service (Phase 01: health-only skeleton)
```

`uv sync` resolves against the committed `uv.lock`, so environments are
reproducible; do not edit `uv.lock` by hand.

## Layout

```text
app/                 Runtime service code
  api/               FastAPI routers, dependencies, and schemas
  auth/              JWT/API-key authentication and authorization resolution
  models/            Provider-neutral domain entities and value types
  services/          Provisioning, tenancy, membership, keys, and audit rules
  storage/           Storage contract and adapters
tests/
  unit/              Focused rule tests
  integration/       Endpoint/authorization tests
  storage_contract/  Adapter conformance tests (placeholders until Phase 02)
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
| `app/models/ids.py` | Prefix-validated ID value objects: application identities `UserId`/`OrganizationId`/`ApiKeyId` (`usr_`/`org_`/`key_`), internal record IDs `ExternalIdentityId`/`MembershipId`/`AuditEventId` (`extid_`/`mem_`/`aud_`), `ActorId` union, `ProviderSubject` (plain string) | Phase 02 storage keys |
| `app/models/timestamps.py` | `UtcDatetime` (reject-naive input, UTC `Z` ISO-8601 JSON), `utc_now`, `ensure_utc`, `to_utc_rfc3339` | Phase 02 round-trips |
| `app/models/pagination.py` | `Page[T]`, `PageParams`, `Cursor`, `clamp_limit`, bound constants | Phase 02 adapters |
| `app/models/errors.py` | `Error`/`FieldError` envelope + `ErrorCode` (no HTTP status encoded) | wired to HTTP by `app/api/errors.py` |
| `app/models/enums.py` | All pinned `StrEnum` sets (see Conventions) | Phase 02 stores as strings; Phase 05 branches |
| `app/models/{user,external_identity,organization,membership}.py` | §4 identity entities, `extra="forbid"`, exact field lists | Phase 02 rows; Phase 03 provisioning |
| `app/models/{api_key,audit_event,authorization_context}.py` | §4 credential/audit entities + §10 context (actor-type/actor-id consistency rule) | Phase 02 rows; Phases 04/05 services |
| `app/api/schemas/*` | Versioned request/response models for §14/§15 payloads | Phase 04/05 routers |
| `app/api/schemas/manifest.py` | Frozen endpoint manifest: `API_V1_PREFIX`, `EndpointSpec`, `ENDPOINTS` (all 10 §14 routes), `endpoint_for` | Phase 04/05 mounting |
| `app/main.py` | `create_app(routers=...)` factory + module-level `app` (uvicorn target) | Phase 04/05 registration |

### Conventions

| Topic | Rule |
| --- | --- |
| ID prefixes | `usr_`/`org_`/`key_` are the only application identities (usable as `actor_id` and §14 path parameters). `extid_`/`mem_`/`aud_` record IDs are internal: never in paths, never in response payloads. Provider subjects (Cognito `sub`, Shopify IDs) are constrained strings, never coerced into ID types. |
| Enum values | `UserStatus {active, disabled}` · `OrganizationStatus {active, disabled}` · `MembershipStatus {active, disabled}` (member removal = physical delete; `disabled` is a suspension) · `ApiKeyStatus {active, revoked}` (expiry is **derived** from `expires_at` at verification, never a stored status) · `MembershipRole {owner, admin, member, viewer}` · `OrganizationType {personal, customer, internal}` · `ApiKeyEnvironment {live, test}` · `IdentityProvider {cognito, shopify, google, microsoft, oidc}` |
| Scope pattern | `^[a-z][a-z0-9]*(:[a-z][a-z0-9]*){2}$` — exactly three lowercase `product:resource:action` segments. Single source: `SCOPE_PATTERN`/`Scope` in `app/models/api_key.py`; API schemas reuse `Scope` and must never re-declare the regex. |
| Timestamps | Naive datetimes rejected on input; JSON serializes as UTC ISO-8601 with `Z` suffix so SQLite/DynamoDB round-trips stay comparable. |
| Page limits | `limit` default 20, min 1, max 100; out-of-range requests are **clamped**, never a 422. |
| Cursor opacity | `cursor`/`next_cursor` are opaque strings (≤ 2048 chars). Only `app/storage` adapters generate or decode cursor content; nothing above an adapter may parse, construct, or depend on it (AGENTS.md). |
| Error envelope | `{"code", "message", "field_errors", "request_id"}` with stable codes `validation_error`, `unauthenticated`, `forbidden`, `not_found`, `conflict`, `internal_error`. `field_errors` entries carry only `field` + `message` (never submitted values). HTTP status mapping lives solely in `app/api/errors.py` (422 validation, 400/401/403/404/409 table, unmapped <500 → `validation_error`, ≥500 → `internal_error`). |
| Versioning | Every §14 route lives under `API_V1_PREFIX = "/v1"`. `/health` is operational, outside the manifest and the versioned surface. |

### Mounting convention (Phase 04/05)

- Routers land in `app/api/<resource>.py` and are attached by passing them
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
  tests in `tests/unit/test_endpoint_manifest.py`.

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
`app/api/schemas/manifest.py`'s docstring register). §15's
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
uv run uvicorn app.main:app --reload   # health-only skeleton; no DB/AWS config
```
