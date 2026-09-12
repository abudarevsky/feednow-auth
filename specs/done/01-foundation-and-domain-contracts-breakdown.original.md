# Phase 01 breakdown — commit-sized tasks

Source contract: `01-foundation-and-domain-contracts.md`. One numbered task = one commit by an implementation agent. Phase 01 non-goals apply throughout: no storage adapter, no Cognito validation, no endpoint behavior, no CDK.

## Planner decisions (interpretation of contract)

- **Python version:** goal line says "3.13", acceptance criterion pins "3.14.5". The acceptance criterion is the contract; local toolchain is 3.14.5. Pin `requires-python = "==3.14.*"` + `.python-version = 3.14.5`. Spec floor "3.13+" remains a compatibility note only.
- **Tooling:** `uv` (already installed) is the declared manager; commands documented in README.
- **New ID prefixes:** spec fixes `usr_`, `org_`, `key_`. Phase 01 additionally defines `extid_` (ExternalIdentity), `mem_` (Membership), `aud_` (AuditEvent) as contract for later phases.
- **Scope pattern:** `^[a-z][a-z0-9]*(:[a-z][a-z0-9]*){2}$` (product:resource:action, lowercase). Commercial-plan names must fail as invalid scopes only via review, not runtime denylists.
- **boto3:** not a Phase 01 dependency at all; enforced by an import test, not a lint plugin.

## Tasks

1. **Tooling scaffold and package tree**
   - Files: `pyproject.toml`, `.python-version`, `app/__init__.py`, `app/{api,auth,models,services,storage}/__init__.py`, `tests/conftest.py`, `README.md`; remove replaced `.gitkeep` files.
   - Content: project metadata, runtime deps (`fastapi`, `pydantic>=2`), dev deps (`uvicorn`, `pytest`, `httpx`, `ruff`), ruff config, README with `uv sync` / `uv run pytest` / `uv run ruff check .` / local `uvicorn app.main:app`.
   - Verify: `uv sync && uv run ruff check . && uv run pytest` (empty-suite pass acceptable).

2. **Conventions module: IDs, timestamps, pagination, errors**
   - Files: `app/models/ids.py`, `app/models/pagination.py`, `app/models/errors.py` + unit tests in `tests/unit/`.
   - Content: prefix-validated ID value types (`usr_`, `org_`, `key_`, `extid_`, `mem_`, `aud_`); timezone-aware UTC timestamp convention; `Page[T]` with opaque cursor string and bounded `limit`; `Error`/`FieldError` envelope with stable machine-readable codes.
   - Verify: unit tests — wrong-prefix rejection, naive-datetime handling, limit defaults/max, cursor treated as opaque, error JSON shape.

3. **Domain entities and enums**
   - Files: `app/models/enums.py`, `app/models/{user,external_identity,organization,membership,api_key,audit_event,authorization_context}.py`, exports in `app/models/__init__.py` + unit tests.
   - Content: entities per spec §4 fields exactly; enums for statuses, `MembershipRole`, `OrganizationType`, `ApiKeyEnvironment`; `Scope` value type; `ApiKey` carries only `key_id`/`key_prefix`/`secret_hash` — no plaintext secret field exists; `AuthorizationContext` per spec §10 (actor_type user|api_key, roles, scopes).
   - Verify: round-trip serialization; unknown enum strings rejected; `extra="forbid"`; test proving no `ApiKey` field can hold a plaintext secret; internal `User.id` distinct from `provider_subject`.

4. **Versioned API request/response schemas**
   - Files: `app/api/schemas/{common,me,organizations,members,api_keys}.py` + unit tests.
   - Content: models for spec §14 endpoints (`/v1/me`, organizations get/list/create, members list/create/remove, api-keys list/create/revoke) per §15 payloads; `ApiKeyCreatedResponse` is the only type exposing the full `key` string (one-time, documented); `ApiKeySummary` exposes prefix/masked only, never `secret_hash`; delete = 204 contract.
   - Verify: tests — summary/list models have no secret or hash fields; creation request validates environment enum + scope pattern; unknown response fields forbidden.

5. **FastAPI skeleton and health endpoint**
   - Files: `app/main.py` (`create_app` factory), `app/api/health.py`, exception handlers mapping `errors.py` codes + integration test in `tests/integration/`.
   - Content: app boots with no DB/AWS config; `/health` returns 200 JSON; no endpoint routers mounted (owner phases add them).
   - Verify: TestClient GET `/health` with AWS/DB env vars cleared; assert `boto3` not in `sys.modules` after importing the app.

6. **Handoff documentation and green sweep**
   - Files: `README.md` ("Phase 01 contracts" section), status/evidence notes appended to this breakdown file.
   - Content: document the exact modules Phase 02 codes against (`app/models/*`, `app/api/schemas/*`), conventions table, planner decisions above, and how to run everything.
   - Verify: full `uv run pytest` + `uv run ruff check .` green; record command output summary as phase evidence.

## Definition of done check (maps to acceptance criteria)

- [ ] Python 3.14.5 reproducibly declared (task 1)
- [ ] App imports, health endpoint, no AWS/DB dependency (task 5)
- [ ] Every spec entity modeled; internal IDs distinct from provider subjects (task 3)
- [ ] No secrets/hashes/tokens in schemas except one-time creation response (task 4)
- [ ] Focused unit tests for serialization and invalid enum/shape rejection (tasks 2–4)

## Completion evidence

_(implementation agent: append test/lint output here per phase)_
