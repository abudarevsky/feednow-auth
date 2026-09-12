# Operations

## Setup and development

```bash
uv sync
uv run pytest
uv run pytest src/tests/storage_contract   # storage conformance only
uv run ruff check .
uv run ruff format --check .
uv run feednow-auth
```

The project targets Python 3.13+ and pins the development toolchain to
3.14.5. Production serving is declared as `uvicorn[standard]`, so Uvicorn
uses `uvloop` when the platform supports it.

## Verified behavior

Phase 01 exposes `/health` and generated FastAPI documentation. Phase 02 adds
the storage boundary: the `Storage` contract, the SQLite adapter behind
`open_sqlite_storage`, and the adapter-neutral conformance suite. The service
still does not provide provider validation, resource CRUD, HTTP routes over
storage, or deployment behavior. Do not infer those capabilities from a passing
health check or a green conformance run.

## Verification

```bash
uv run pytest -q --tb=short
uv run pytest src/tests/storage_contract -q   # SQLite conformance entry
uv run ruff check .
uv run ruff format --check .
git diff --check
```

Report test results, third-party warnings, environment blocks, and any
unperformed remote or deployment checks separately.
