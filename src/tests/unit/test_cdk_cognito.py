"""Cognito must be provisioned and configured outside the FeedNow CDK stack."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

CDK_DIR = Path(__file__).resolve().parents[3] / "deploy" / "aws" / "cdk"
spec = importlib.util.spec_from_file_location(
    "feednow_cdk_cognito_stack", CDK_DIR / "feednow_auth_stack.py"
)
assert spec is not None and spec.loader is not None
stack_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = stack_module
spec.loader.exec_module(stack_module)
FeedNowAuthStack = stack_module.FeedNowAuthStack
parse_cognito_callback_urls = stack_module.parse_cognito_callback_urls
ENVIRONMENTS = ("dev", "staging", "prod")


def _stack(env_name: str) -> FeedNowAuthStack:
    return FeedNowAuthStack(
        cdk.App(),
        f"FeedNowAuth-{env_name}",
        feednow_env=env_name,
        account_origin="https://account.example.invalid",
        existing_user_pool_id=f"eu-north-1_{env_name}",
        existing_client_id=f"{env_name}client",
        env=cdk.Environment(account="123456789012", region="eu-north-1"),
    )


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_stack_never_creates_or_mutates_cognito_resources(env_name: str) -> None:
    template = Template.from_stack(_stack(env_name)).to_json()
    resources: Mapping[str, Any] = template.get("Resources", {})
    cognito_types = {
        "AWS::Cognito::UserPool",
        "AWS::Cognito::UserPoolClient",
        "AWS::Cognito::UserPoolDomain",
        "AWS::Lambda::Permission",
    }
    assert not any(item["Type"] in cognito_types for item in resources.values())
    assert not any(
        item["Type"] == "AWS::Lambda::Function"
        and item["Properties"].get("Handler") == "cognito_trigger_lambda.handler"
        for item in resources.values()
    )
    outputs = template["Outputs"]
    assert outputs["CognitoUserPoolId"]["Value"] == f"eu-north-1_{env_name}"
    assert outputs["CognitoClientId"]["Value"] == f"{env_name}client"
    assert "https://cognito-idp.${region}.amazonaws.com/${pool_id}" in json.dumps(
        outputs["CognitoIssuerUrl"]["Value"]
    )


@pytest.mark.parametrize("missing", ["pool", "client", "both"])
def test_stack_requires_user_provisioned_pool_and_client(missing: str) -> None:
    kwargs: dict[str, str] = {}
    if missing not in {"pool", "both"}:
        kwargs["existing_user_pool_id"] = "eu-north-1_existing"
    if missing not in {"client", "both"}:
        kwargs["existing_client_id"] = "existingclient"
    with pytest.raises(ValueError, match="user-provisioned Cognito pool and client"):
        FeedNowAuthStack(
            cdk.App(),
            "MissingCognitoImport",
            feednow_env="prod",
            account_origin="https://account.example.invalid",
            **kwargs,
        )


def test_callback_url_input_is_normalized() -> None:
    assert parse_cognito_callback_urls(
        " https://a.example.invalid/cb ,,https://b.example.invalid/logout,https://a.example.invalid/cb"
    ) == ("https://a.example.invalid/cb", "https://b.example.invalid/logout")
    assert parse_cognito_callback_urls(["https://a.example.invalid/cb"]) == (
        "https://a.example.invalid/cb",
    )
    assert parse_cognito_callback_urls(None) == ()
