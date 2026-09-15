#!/usr/bin/env python3
"""CDK entrypoint for the feednow-auth infrastructure.

Loads non-secret deployment inputs from the (never committed)
``deploy/aws/cdk/.env`` without overriding the shell, requires
``FEEDNOW_ENV`` (dev|staging|prod), ``CDK_DEFAULT_ACCOUNT``, ``AWS_REGION``,
and ``COGNITO_CALLBACK_URLS`` (comma-separated HTTPS OAuth redirect URIs),
then synthesizes :class:`FeedNowAuthStack` bound to an explicit
:class:`aws_cdk.Environment`.
"""

from __future__ import annotations

import os
from pathlib import Path

import aws_cdk as cdk
from feednow_auth_stack import FeedNowAuthEnv, FeedNowAuthStack

REQUIRED_INPUTS = ("FEEDNOW_ENV", "CDK_DEFAULT_ACCOUNT", "AWS_REGION", "COGNITO_CALLBACK_URLS")


def load_cdk_env(env_path: Path | None = None) -> None:
    """Load deployment inputs from the CDK directory without overriding the shell."""
    path = Path(__file__).resolve().parent / ".env" if env_path is None else env_path
    if not path.exists():
        return

    for line in path.read_text().splitlines():
        key, separator, value = line.strip().partition("=")
        if not separator or not key or key.startswith("#") or os.getenv(key):
            continue
        os.environ[key] = value.strip().strip("\"'")


def require_inputs() -> dict[str, str]:
    """Return the required non-secret inputs or exit with a clear message."""
    missing = [name for name in REQUIRED_INPUTS if not os.getenv(name)]
    if missing:
        msg = (
            f"Missing required CDK inputs: {', '.join(missing)}. "
            "Set them in the shell or in deploy/aws/cdk/.env (see .env.example)."
        )
        raise SystemExit(msg)
    return {name: str(os.environ[name]) for name in REQUIRED_INPUTS}


def main() -> None:
    load_cdk_env()
    inputs = require_inputs()
    try:
        feednow_env = FeedNowAuthEnv(inputs["FEEDNOW_ENV"])
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    app = cdk.App()
    FeedNowAuthStack(
        app,
        feednow_env.stack_name,
        feednow_env=feednow_env,
        cognito_callback_urls=inputs["COGNITO_CALLBACK_URLS"],
        env=cdk.Environment(
            account=inputs["CDK_DEFAULT_ACCOUNT"],
            region=inputs["AWS_REGION"],
        ),
    )
    app.synth()


if __name__ == "__main__":
    main()
