"""Synthesis contract for the additive Cognito federation-fix stack."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import aws_cdk as cdk
from aws_cdk.assertions import Template

STACK_PATH = (
    Path(__file__).resolve().parents[3]
    / "deploy"
    / "aws"
    / "cdk"
    / "google_federation_fix_stack.py"
)
spec = importlib.util.spec_from_file_location("google_federation_fix_stack_test", STACK_PATH)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

GoogleFederationFixStack = module.GoogleFederationFixStack


def _template() -> Template:
    stack = GoogleFederationFixStack(
        cdk.App(),
        "FeedNowAuthGoogleFederationFix-dev",
        user_pool_id="eu-north-1_EXAMPLE",
        client_id="public-client-id",
        env=cdk.Environment(account="123456789012", region="eu-north-1"),
    )
    return Template.from_stack(stack)


def test_overlay_does_not_create_or_replace_the_existing_pool_or_client() -> None:
    template = _template()
    template.resource_count_is("AWS::Cognito::UserPool", 0)
    template.resource_count_is("AWS::Cognito::UserPoolClient", 0)
    template.resource_count_is("AWS::Lambda::Permission", 1)
    template.has_output("GoogleFederationPoolId", {})


def test_trigger_role_has_no_cognito_admin_write_permission() -> None:
    resources = _template().find_resources("AWS::IAM::Policy")
    statements: list[dict[str, Any]] = []
    for resource in resources.values():
        document = resource["Properties"]["PolicyDocument"]
        statements.extend(document.get("Statement", []))
    admin = [
        statement
        for statement in statements
        if "cognito-idp:AdminUpdateUserAttributes"
        in (statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]])
    ]
    assert admin == []
