# feednow-auth

`feednow-auth` is the backend service for FeedNow application identity,
organization membership, authorization, API credentials, and audit records.
Cognito establishes external identity; the service owns FeedNow users,
organizations, memberships, sessions, and authorization decisions.

The browser application is a separate static project. Browser requests use the
backend API; Cognito token exchange, session cookies, API-key verification, and
persistence stay on the backend.

## Documentation

See [the service documentation](docs/README.md) for architecture,
authentication, browser sessions, authorization, credentials, storage,
operations, and current limitations.

## Development

The project requires Python 3.13 or newer and uses `uv`:

```bash
uv sync
uv run feednow-auth
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

For the local account UI and Cognito-backed API, configure
`deploy/docker/.env` from `.env.example`, then run:

```bash
./deploy/docker/run-dev.sh --ui
```

See [operations](docs/operations.md) and [Cognito setup](docs/cognito.md) for
configuration, emulator, deployment, and operator procedures.
