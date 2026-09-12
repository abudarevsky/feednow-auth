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
uv run uvicorn app.main:app --reload   # run the service (entry lands in Phase 01 task 6)
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
