"""Tests for the AWS SDK adapter kept outside the application package."""

from __future__ import annotations

from typing import Any

import cognito_trigger_lambda
from app.auth.cognito_triggers import PRE_AUTHENTICATION_SOURCE


def _event(source: str) -> dict[str, Any]:
    return {
        "version": "1",
        "region": "eu-north-1",
        "userPoolId": "eu-north-1_EXAMPLE",
        "userName": "local-user",
        "triggerSource": source,
        "callerContext": {"clientId": "public-client"},
        "request": {"userAttributes": {"email": "person@example.com"}},
        "response": {},
    }


def test_signup_trigger_is_handled_without_an_aws_client() -> None:
    event = _event("PreSignUp_SignUp")
    assert cognito_trigger_lambda.handler(event) == event


def test_pre_auth_trigger_is_handled_without_network_access() -> None:
    event = _event(PRE_AUTHENTICATION_SOURCE)
    assert cognito_trigger_lambda.handler(event) == event
