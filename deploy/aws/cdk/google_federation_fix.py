"""Entrypoint for the CDK overlay targeting the existing dev Cognito pool."""

from __future__ import annotations

import os

import aws_cdk as cdk
from google_federation_fix_stack import GoogleFederationFixStack


def main() -> None:
    required = (
        "CDK_DEFAULT_ACCOUNT",
        "AWS_REGION",
        "GOOGLE_FIX_USER_POOL_ID",
        "GOOGLE_FIX_CLIENT_ID",
    )
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise SystemExit(f"Missing required inputs: {', '.join(missing)}")
    app = cdk.App()
    GoogleFederationFixStack(
        app,
        "FeedNowAuthGoogleFederationFix-dev",
        user_pool_id=str(os.environ["GOOGLE_FIX_USER_POOL_ID"]),
        client_id=str(os.environ["GOOGLE_FIX_CLIENT_ID"]),
        implementation_version=os.getenv(
            "GOOGLE_FIX_IMPLEMENTATION_VERSION", "google-email-proof-v1"
        ),
        env=cdk.Environment(
            account=os.environ["CDK_DEFAULT_ACCOUNT"],
            region=os.environ["AWS_REGION"],
        ),
    )
    app.synth()


if __name__ == "__main__":
    main()
