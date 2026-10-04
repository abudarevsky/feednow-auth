# Local Cognito journey

Copy `.env.example` to `.env`, set the non-production Cognito values and a
locally generated pepper, then run:

```bash
docker compose --profile cognito up --build
./cognito-login.sh --provider Google
```

The `run-dev.sh` wrapper reuses existing images by default. Add `--build` to
rebuild images and force-recreate selected containers:

```bash
./deploy/docker/run-dev.sh --dynamodb-local --build
```

The composition performs a short local-only volume initialization before the
non-root app starts. It preserves the SQLite database while repairing the
volume ownership needed for first-login provisioning.

Register `http://localhost:8000/oauth/cli-callback` as an additional Cognito
callback URL for the local CLI flow. Use `./cognito-login.sh` for the Cognito email/password page. The script only
prints the final `/v1/me` JSON; its authorization URL and operational messages
go to stderr.
