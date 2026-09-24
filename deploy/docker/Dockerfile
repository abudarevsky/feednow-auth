# syntax=docker/dockerfile:1

# feednow-auth container image (Phase 10 local Cognito compose recovery).
#
# Build context MUST be the repository root:
#   docker build --target prod -f deploy/docker/Dockerfile -t feednow-auth:prod .
#   docker build --target dev  -f deploy/docker/Dockerfile -t feednow-auth:dev  .
#
# The root .dockerignore keeps the context minimal: it excludes src/tests/ and
# narrows deploy/ to exactly the local composition root
# (deploy/docker/local_runtime.py) and its OAuth callback capture page
# (deploy/docker/oauth_callback.py). No .env, pepper value, client ID/secret,
# or token is ever copied, and no secret is set via ENV/ARG in any stage.

# ---------------------------------------------------------------------------
# base: runtime dependencies, the installed `app` package, and the local
# composition files shared by every stage.
# ---------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS base

# Keep the virtualenv outside /app so a dev bind-mount of the repo root onto
# /app can never hide the installed dependencies.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app

# Dependency layer first for build-cache reuse (project itself not yet built).
# README.md is required by hatchling to resolve the project metadata.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

# Application source, then install the project (dev groups stay excluded).
COPY src/ src/
RUN uv sync --frozen --no-dev

# Local composition root + callback page into /app/deploy/docker/.
# The .dockerignore whitelist restricts this glob to exactly those two files.
COPY deploy/docker/*.py deploy/docker/

# The current ghcr.io/astral-sh/uv:python3.14-bookworm-slim digest ships no
# `user` account, so create the uid-1000 non-root account, then provide a
# writable SQLite directory it owns.
RUN useradd --uid 1000 --create-home --shell /bin/bash user \
    && mkdir -p /data && chown user:user /data

EXPOSE 8000

# ---------------------------------------------------------------------------
# prod: production-like runtime. The default CMD serves the import-safe
# factory app (health + API routers only; never the local /oauth/callback).
# Compose files override `command` per journey.
# ---------------------------------------------------------------------------
FROM base AS prod

# Same non-root account created in `base`.
USER user

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", \
     "--port", "8000", "--no-access-log"]

# ---------------------------------------------------------------------------
# dev: same layout, plus the dev dependency groups so `pytest`/`ruff` exist
# in the image for in-container test runs against the bind-mounted repo.
# ---------------------------------------------------------------------------
FROM base AS dev

# Re-resolve with dev groups included (uv.lock is unchanged; --frozen holds).
RUN uv sync --frozen

USER user
