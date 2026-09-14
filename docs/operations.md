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

## DynamoDB Local (Phase 06 harness)

Adapter tests marked `dynamodb_local` skip with an explicit reason unless
`FEEDNOW_DYNAMODB_LOCAL_ENDPOINT` is set and reachable, so the default
`uv run pytest` stays green on machines without Docker. To run them:

```bash
docker run --rm -d --name feednow-dynamodb-local -p 8000:8000 \
  amazon/dynamodb-local:2.6.0 \
  -jar DynamoDBLocal.jar -inMemory -sharedDb

FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest -m dynamodb_local

docker stop feednow-dynamodb-local
```

The harness (`src/tests/support/dynamodb_local.py`) authenticates with fixed
dummy credentials against any region and creates/deletes the seven adapter
tables under a fresh random prefix per test, so runs are isolated without
truncation races. moto is not used: DynamoDB Local is the real transactional
oracle for conformance evidence.

## Verified behavior

Phases 01–05 expose `/health` and the ten mounted §14 routes over the
storage boundary: the `Storage` contract, the SQLite adapter behind
`open_sqlite_storage`, and the adapter-neutral conformance suite. Phase 06
adds the production DynamoDB adapter behind `open_dynamodb_storage` (schema,
IAM matrix, and limitations in
[docs/phases/06-dynamodb.md](phases/06-dynamodb.md)); the same suite runs
against DynamoDB Local through the marker-gated entry. The service still
does not deploy to AWS (Phase 07) or expose an audit read surface
(Phase 08). Do not infer those capabilities from a passing health check or
a green conformance run.

## Verification

```bash
uv run pytest -q --tb=short                       # default env: DynamoDB Local cases skip by name
uv run pytest src/tests/storage_contract -q       # SQLite conformance entry (64)
uv run ruff check .
uv run ruff format --check .
git diff --check

# With DynamoDB Local running (see above):
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest -q                                # full suite, gated cases included
FEEDNOW_DYNAMODB_LOCAL_ENDPOINT=http://localhost:8000 \
  uv run pytest src/tests/storage_contract -q     # both adapter entries (64 + 63)
```

Report test results, third-party warnings, environment blocks, and any
unperformed remote or deployment checks separately.
