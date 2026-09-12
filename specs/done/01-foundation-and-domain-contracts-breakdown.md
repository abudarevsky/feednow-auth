# Phase 01 breakdown — commit-sized tasks

Source contract: `01-foundation-and-domain-contracts.md`. One numbered task = one commit by an implementation agent. Phase 01 non-goals apply throughout: no storage adapter, no Cognito validation, no endpoint behavior, no CDK. Precondition: `git init` the scaffold and make an initial commit — the repo is not yet a git work tree, so "one task = one commit" has no substrate (see Escalations).

## Planner decisions (interpretation of contract)

- **Python version:** the contract's goal line says "3.13" while its acceptance criterion pins "3.14.5"; the spec floor is "3.13+". Resolution: the acceptance criterion binds the *dev-toolchain declaration*, the spec binds *compatibility*. Set `requires-python = ">=3.13"`, `.python-version = 3.14.5`, and commit `uv.lock`. Do **not** use `requires-python = "==3.14.*"` — it silently narrows spec compatibility and could break Phase 07 if the Lambda runtime is 3.13.
- **Tooling:** `uv` (installed, 0.9.17) is the declared manager; commands documented in README.
- **ID prefixes:** spec fixes `usr_`, `org_`, `key_` — the only prefixes ever used as application identity (AGENTS.md). Spec §4 also gives `id` to ExternalIdentity, Membership, and AuditEvent without fixing prefixes. Phase 01 defines `extid_`, `mem_`, `aud_` for those record IDs; they stay internal (never appear as `actor_id` in §10 or in §14 path parameters). Kept because Phase 02 stores these rows and Phase 02/03 write audit events, so the contract must be stable now. Flagged as a spec-revision proposal (Escalations).
- **ID generation deferred:** Phase 01 ships prefix-validating value types only. Concrete generation strategies (ULID-style `key_id` per §8, user/org entropy source) belong to owner phases 03/05; do not add a generator here so Phase 01 cannot become the de facto entropy contract.
- **Enum values (pinned now; spec names them but does not enumerate; Phase 02 stores them as strings and Phase 05 branches on them):** `UserStatus {active, disabled}`; `OrganizationStatus {active, disabled}`; `MembershipStatus {active, disabled}` with member removal = physical delete (the storage contract already has `delete_membership`); `ApiKeyStatus {active, revoked}` with expiry derived from `expires_at` at verification time — never a stored status (avoids a background-job contract); `MembershipRole {owner, admin, member, viewer}`; `OrganizationType {personal, customer, internal}`; `ApiKeyEnvironment {live, test}` (from `fn_live_`/`fn_test_`); `IdentityProvider {cognito, shopify, google, microsoft, oidc}` (all five named in spec §4).
- **Scope pattern:** `^[a-z][a-z0-9]*(:[a-z][a-z0-9]*){2}$` — exactly three lowercase `product:resource:action` segments; all §9 examples match. The regex lives solely on the `Scope` value type in `app/models` (single source; API schemas reuse it — no duplicated pattern). "No commercial plans in scopes" is a design/review rule, not a runtime denylist — document this so Phase 05 does not add one.
- **boto3:** not a Phase 01 dependency at all. Enforced by a subprocess-isolated import check (task 6), **not** an in-process `sys.modules` assertion — the latter is process-global and order-dependent, and will produce false failures in Phase 06 when boto3 legitimately becomes a lazily-imported adapter dependency.
- **Mount contract:** no route stubs in Phase 01 (endpoint behavior is a non-goal), but Phase 04/05 mount against a frozen manifest: every §14 endpoint's method, path, request/response models, success status (deletes = 204), and pagination usage are declared in `app/api/schemas/manifest.py` under versioned prefix `/v1`. Routers land in `app/api/<resource>.py` and register through `create_app`'s documented extension point.
- **Derived payloads:** where §14/§15 define no body (e.g. `GET /v1/me`, organization create, member add), Phase 01 derives minimal payloads from endpoint semantics, lists every derived field in the manifest docstring, and flags them as Phase 01 contract additions (Escalations). §15's key-creation request/response is copied verbatim, not derived.
- **Timestamps:** models reject naive datetimes on input and serialize as UTC ISO-8601; storage round-trips must stay comparable across adapters.
- **Pagination:** `Page[T]` carries an opaque cursor string and bounded `limit`; only adapters generate or decode cursor content (AGENTS.md: pagination tokens never leak above an adapter).

## Tasks

1. **Tooling scaffold and package tree**
   - Files: `pyproject.toml`, `.python-version`, `uv.lock`, `.gitignore`, `app/__init__.py`, `app/{api,auth,models,services,storage}/__init__.py`, `tests/{unit,integration}/__init__.py`, `tests/conftest.py`, `README.md`; remove `.gitkeep` only where a real file replaces it (keep placeholders under `tests/storage_contract/` and `deploy/`).
   - Content: project metadata; `requires-python = ">=3.13"`; `.python-version = 3.14.5`; runtime deps `fastapi`, `pydantic>=2,<3`; dev deps `uvicorn`, `pytest`, `httpx`, `ruff`; ruff config; `.gitignore` covering `.venv`, caches, `.env`; README with `uv sync` / `uv run pytest` / `uv run ruff check .` / `uv run uvicorn app.main:app --reload` (uvicorn entry exists from task 6).
   - Verify: `uv sync && uv run python -V` reports 3.14.5; `uv run ruff check . && uv run pytest` green (empty-suite pass acceptable); `uv.lock` present in the commit.

2. **Conventions module: IDs, timestamps, pagination, errors**
   - Files: `app/models/ids.py`, `app/models/timestamps.py`, `app/models/pagination.py`, `app/models/errors.py` + unit tests in `tests/unit/`.
   - Content: prefix-validated, typed ID value objects — application-identity `UserId`/`OrganizationId`/ApiKey-id (`usr_`/`org_`/`key_`) kept distinct from record IDs (`extid_`/`mem_`/`aud_`); provider subjects are plain constrained strings, never ID value types. UTC timestamp helpers enforcing the reject-naive rule. `Page[T]` with opaque cursor + bounded `limit` (default and max pinned, e.g. 20/100). `Error`/`FieldError` envelope with stable machine-readable codes.
   - Verify: unit tests — wrong-prefix rejection per type, provider-subject string never coerced to `UserId`, naive datetime rejected, UTC serialization, limit default/max clamping, cursor treated as an opaque string, error JSON shape stable.

3. **Enums and identity entities**
   - Files: `app/models/enums.py`, `app/models/{user,external_identity,organization,membership}.py`, exports in `app/models/__init__.py` + unit tests.
   - Content: all enum sets exactly as pinned in Planner decisions; `User`, `ExternalIdentity`, `Organization`, `Membership` with fields exactly per spec §4 (no more, no fewer); uniqueness note for `(provider, provider_subject, provider_tenant)` documented on `ExternalIdentity` (enforcement is Phase 02 storage, not a Phase 01 model constraint). `extra="forbid"` on every model.
   - Verify: round-trip serialization; unknown enum strings rejected; extra fields forbidden; `User.id` (`usr_`) distinct from `ExternalIdentity.provider_subject`; §4 field-list equality test per entity.

4. **Credential, audit, and authorization entities**
   - Files: `app/models/{api_key,audit_event,authorization_context}.py`, exports in `app/models/__init__.py` + unit tests.
   - Content: `ApiKey` with the full §4 field list (id, organization_id, created_by_user_id, name, key_id, key_prefix, secret_hash, environment, scopes, status, created_at, last_used_at, expires_at, revoked_at) — among secret-bearing fields only `secret_hash` exists; **no plaintext-secret field may exist on the model**. `Scope` value type with the single-source regex. `AuditEvent` per §4 with `metadata` typed as a JSON-safe mapping and a documented no-secrets rule (AGENTS.md; runtime redaction is owner-phase work). `AuthorizationContext` with exactly the §10 fields: `actor_type` (user|api_key), `actor_id`, `organization_id`, `roles`, `scopes`.
   - Verify: §4/§10 field-list equality tests; `ApiKey(..., secret="x")` raises via `extra="forbid"` and no field name outside {`secret_hash`} matches secret/token/plaintext patterns; Scope accepts every §9 example and rejects 2-segment, 4-segment, uppercase, and empty segments; `actor_id`/`organization_id` typed as the task-2 ID objects.

5. **Versioned API schemas and endpoint manifest**
   - Files: `app/api/schemas/__init__.py`, `app/api/schemas/{common,me,organizations,members,api_keys,manifest}.py` + unit tests.
   - Content: request/response models for all §14 endpoints (`/v1/me`, organizations get/list/create, members list/create/remove, api-keys list/create/revoke); §15 payloads verbatim; derived payloads per the Decisions rule. `ApiKeyCreateRequest` validates environment enum + `Scope` list; `ApiKeyCreatedResponse` (`id`, `name`, `key`, `created_at`) is the only type exposing the full key, documented one-time; `ApiKeySummary` exposes prefix/status/scopes/timestamps only — never `secret_hash`, never plaintext. List endpoints return `Page[...]`; DELETE responses are 204/no-body. `manifest.py` freezes method + path + request/response models + success status per endpoint under `/v1` (constant `API_V1_PREFIX`).
   - Verify: tests — summary/list models have no secret or hash fields (field-name introspection + `extra="forbid"`); unknown response fields forbidden; creation request rejects invalid environment and invalid scopes; manifest covers every §14 endpoint with 204 on both deletes.

6. **FastAPI skeleton, health endpoint, and no-AWS proof**
   - Files: `app/main.py` (`create_app` factory accepting an optional router sequence as the documented mounting extension point, plus module-level `app = create_app()` for uvicorn), `app/api/health.py`, exception handlers mapping `errors.py` codes + integration test in `tests/integration/`.
   - Content: app boots with no DB/AWS configuration; `/health` returns 200 JSON; `RequestValidationError` maps to the `Error` envelope; no §14 routers mounted (owner phases add them).
   - Verify: TestClient GET `/health` with `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` removed from the environment; subprocess-isolated check `python -c "import sys, app.main; assert 'boto3' not in sys.modules"` (fresh interpreter, so test order cannot skew the result); validation-error envelope shape asserted.

7. **Handoff documentation and green sweep**
   - Files: `README.md` ("Phase 01 contracts" section), status/evidence notes appended to this breakdown file.
   - Content: exact modules Phase 02 codes against (`app/models/*`, `app/api/schemas/*` incl. manifest and mounting convention); conventions table (prefixes, enum values, scope regex, timestamp rule, Page limits, cursor opacity boundary); planner decisions incl. the review-only plan-scope rule for scopes; every derived-payload addition listed for spec revision; run commands.
   - Verify: full `uv run pytest` + `uv run ruff check .` green; record command output summary as phase evidence.

## Definition of done check (maps to acceptance criteria)

- [x] Python 3.14.5 reproducibly declared via `.python-version` + committed `uv.lock`, spec-compatible `requires-python` (task 1)
- [x] App imports and exposes health without AWS credentials or a DB connection; boto3-free import proven in isolation (task 6)
- [x] Every §4 entity modeled with exact fields; internal IDs distinct from provider subjects (tasks 3–4)
- [x] No secrets/hashes/tokens in schemas except the one-time creation response (tasks 4–5)
- [x] Focused unit tests for serialization and invalid enum/shape rejection (tasks 2–5)
- [x] Handoff: contract modules, conventions, and mount contract documented (task 7)

## Escalations (planner action, not implementation work)

- **Spec-revision proposals** (per delivery-map review rule — record explicitly; do not leave Phase 02+ citing only a breakdown): (1) `extid_`/`mem_`/`aud_` record-ID prefixes; (2) pinned enum values incl. `ApiKeyStatus {active, revoked}` + derived-expiry semantics and membership physical-delete semantics; (3) derived request/response payloads for §14 endpoints not covered by §15.
- **Contract inconsistency to fix at next contract edit:** the phase goal says "Python 3.13" while the acceptance criterion says "Python 3.14.5"; resolved above without editing the contract, but the goal line should be aligned.
- **Operational:** the repo is not yet a git work tree; `git init` + initial scaffold commit required before task 1 lands as a commit.

## Completion evidence

**Status: Phase 01 COMPLETE (2026-09-12).** Precondition resolved — repo initialized; scaffold landed as commit `351757d`. Tasks 1–7 each landed as exactly one commit:

| Task | Commit |
| --- | --- |
| 1 — Tooling scaffold and package tree | `b03d079` |
| 2 — Conventions: IDs, timestamps, pagination, errors | `e503493` |
| 3 — Enums and identity entities | `3812def` |
| 4 — Credential, audit, and authorization entities | `e64eb16` |
| 5 — Versioned API schemas and endpoint manifest | `e8fc010` |
| 6 — FastAPI skeleton, health endpoint, no-AWS proof | `374f6ee` |
| 7 — Handoff documentation and green sweep | this commit |

Green sweep (task 7, recorded from the working tree at task 6 HEAD):

```text
$ uv run python -V
Python 3.14.5
$ uv run pytest
335 passed, 2 warnings in 0.63s          # 326 unit + 9 integration
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
55 files already formatted
$ env -u AWS_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY \
    -u AWS_SESSION_TOKEN uv run python \
    -c "import sys, app.main; assert 'boto3' not in sys.modules"
exit 0                                    # no-AWS boot proof, isolated interpreter
```

The 2 pytest warnings are both third-party deprecations raised while importing
the Starlette/FastAPI test client (`StarletteDeprecationWarning` about
`httpx` at `fastapi/testclient.py:1`; an `anyio.BlockingPortal` alias
`DeprecationWarning` at `starlette/testclient.py:53`) — neither originates
from this repo's code.

Review sign-offs (per-task @reviewer runs): task 5 — APPROVED after one
major fix landed pre-commit (`scopes` made required on `ApiKeyCreateRequest`
to match the stated contract); task 6 — APPROVED with no critical/major
issues, contract-text nits fixed pre-commit. The three spec-revision
proposals above remain planner actions; they are enumerated for consumers in
the README "Phase 01 contracts (handoff)" derived register (payloads and
success statuses are additionally listed in
`app/api/schemas/manifest.py`'s docstring register).
