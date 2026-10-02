#!/usr/bin/env python3
"""CDK entrypoint for the feednow-auth infrastructure.

Loads non-secret deployment inputs from the environment-specific (never
committed) ``deploy/aws/cdk/.env.<environment>`` without overriding the shell,
requires
``FEEDNOW_ENV`` (dev|staging|prod), ``CDK_DEFAULT_ACCOUNT``, ``AWS_REGION``,
and ``ACCOUNT_ORIGIN`` (the HTTPS origin served by the account UI). It then
synthesizes :class:`FeedNowAuthStack` bound to an explicit
:class:`aws_cdk.Environment`. ``FEEDNOW_COGNITO_CALLBACK_URLS`` can optionally
override the callback derived from the account origin.
"""

from __future__ import annotations

import os
from pathlib import Path

import aws_cdk as cdk
from feednow_auth_stack import FeedNowAuthEnv, FeedNowAuthStack

REQUIRED_INPUTS = ("FEEDNOW_ENV", "AWS_REGION", "ACCOUNT_ORIGIN")
ALLOWED_ENV_FILE_KEYS = frozenset(
    {
        "FEEDNOW_ENV",
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "ACCOUNT_BASE_URL",
        "ACCOUNT_ORIGIN",
        "VISPECTOR_BASE_URL",
        "FEEDNOW_VISPECTOR_URL",
        "ACCOUNT_DOMAIN_NAME",
        "ACM_CERTIFICATE_ARN",
        "ROUTE53_HOSTED_ZONE_ID",
        "FEEDNOW_COGNITO_CALLBACK_URLS",
        "FEEDNOW_COGNITO_DOMAIN",
        "FEEDNOW_COGNITO_USER_POOL_ID",
        "FEEDNOW_COGNITO_CLIENT_ID",
        "FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64",
        "FEEDNOW_PEPPER_CIPHERTEXT_B64",
    }
)


def load_cdk_env(env_path: Path | None = None) -> None:
    """Load the selected environment's inputs without overriding the shell."""
    if env_path is None:
        environment = os.getenv("FEEDNOW_ENV", "")
        if environment not in {"dev", "staging", "prod"}:
            raise SystemExit("Set FEEDNOW_ENV to dev, staging, or prod before loading CDK inputs")
        path = Path(__file__).resolve().parent / f".env.{environment}"
    else:
        path = env_path
    if not path.exists():
        raise SystemExit(f"Missing environment configuration: {path}")

    for line in path.read_text().splitlines():
        key, separator, value = line.strip().partition("=")
        if not separator or not key or key.startswith("#"):
            continue
        if key not in ALLOWED_ENV_FILE_KEYS:
            raise SystemExit(f"Unsupported or sensitive setting {key} in {path}")
        if os.getenv(key):
            continue
        os.environ[key] = value.strip().strip("\"'")
    if not os.getenv("ACCOUNT_ORIGIN") and os.getenv("ACCOUNT_BASE_URL"):
        os.environ["ACCOUNT_ORIGIN"] = os.environ["ACCOUNT_BASE_URL"].rstrip("/")
    if not os.getenv("FEEDNOW_VISPECTOR_URL") and os.getenv("VISPECTOR_BASE_URL"):
        os.environ["FEEDNOW_VISPECTOR_URL"] = os.environ["VISPECTOR_BASE_URL"].rstrip("/")


def require_inputs() -> dict[str, str]:
    """Return the required non-secret inputs or exit with a clear message."""
    if not os.getenv("CDK_DEFAULT_ACCOUNT") and os.getenv("AWS_ACCOUNT_ID"):
        os.environ["CDK_DEFAULT_ACCOUNT"] = os.environ["AWS_ACCOUNT_ID"]
    required = (*REQUIRED_INPUTS, "CDK_DEFAULT_ACCOUNT")
    missing = [name for name in required if not os.getenv(name)]
    missing.extend(
        name
        for name in ("FEEDNOW_COGNITO_USER_POOL_ID", "FEEDNOW_COGNITO_CLIENT_ID")
        if not os.getenv(name)
    )
    if missing:
        msg = (
            f"Missing required CDK inputs: {', '.join(missing)}. "
        "Set them in the shell or in deploy/aws/cdk/.env.<environment> (see .env.example)."
        )
        raise SystemExit(msg)
    return {name: str(os.environ[name]) for name in required}


def main() -> None:
    # FEEDNOW_ENV must be supplied by the deployment command so selecting an
    # environment never depends on a config file's implicit default.
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
        cognito_callback_urls=os.getenv("FEEDNOW_COGNITO_CALLBACK_URLS"),
        cognito_domain=os.getenv("FEEDNOW_COGNITO_DOMAIN"),
        account_origin=inputs["ACCOUNT_ORIGIN"],
        vispector_url=os.getenv("FEEDNOW_VISPECTOR_URL"),
        existing_user_pool_id=os.getenv("FEEDNOW_COGNITO_USER_POOL_ID"),
        existing_client_id=os.getenv("FEEDNOW_COGNITO_CLIENT_ID"),
        env=cdk.Environment(
            account=inputs["CDK_DEFAULT_ACCOUNT"],
            region=inputs["AWS_REGION"],
        ),
    )
    app.synth()


if __name__ == "__main__":
    main()
