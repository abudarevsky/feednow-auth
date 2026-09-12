# Operations

## Setup and development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run feednow-auth
```

The project targets Python 3.13+ and pins the development toolchain to
3.14.5. Production serving is declared as `uvicorn[standard]`, so Uvicorn
uses `uvloop` when the platform supports it.

## Verified behavior

Phase 01 currently exposes `/health` and generated FastAPI documentation. It
does not provide storage, provider validation, resource CRUD, or deployment
behavior. Do not infer those capabilities from a passing health check.

## Verification

```bash
uv run pytest -q --tb=short
uv run ruff check .
uv run ruff format --check .
git diff --check
```

Report test results, third-party warnings, environment blocks, and any
unperformed remote or deployment checks separately.
