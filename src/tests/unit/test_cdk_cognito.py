"""Unit proofs for the Phase 07 Cognito resources (task 3).

The stack must declare exactly one user pool, one public app client, and one
hosted domain per environment:

* pool: email is the only sign-in attribute (``UsernameAttributes=["email"]``),
  self-service sign-up is on, and password reset uses the ``verified_email``
  recovery mechanism with Cognito's default email templates (no SES sender,
  hence no custom ``EmailConfiguration``);
* client: ``feednow-auth-<env>``, ``GenerateSecret=false`` (public PKCE
  client), ``AllowedOAuthFlows=["code"]`` with ``openid``/``email``/``profile``
  scopes, callback and logout URIs taken from the required
  ``COGNITO_CALLBACK_URLS`` input, and ``ExplicitAuthFlows`` carrying
  ``ALLOW_USER_PASSWORD_AUTH`` (task-7 smoke path) plus
  ``ALLOW_REFRESH_TOKEN_AUTH``;
* domain: prefix ``feednow-auth-<env>``;
* outputs: pool id, issuer URL (``Fn::Sub``, because the pool id is an
  unresolved token), and client id are all present and non-empty.

An empty ``COGNITO_CALLBACK_URLS`` must fail at synth time with a message that
names the input, since CDK validates OAuth redirect URIs during synthesis.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

CDK_DIR = Path(__file__).resolve().parents[3] / "deploy" / "aws" / "cdk"


def _load_module(name: str, path: Path) -> ModuleType:
    """Import a CDK file under a fixed name without mutating the global ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Loaded under a unique name: ``test_cdk_app.py`` and ``test_cdk_dynamodb.py``
# cache the same file and pytest may run any of the three first.
stack_module = _load_module("feednow_cdk_cognito_stack", CDK_DIR / "feednow_auth_stack.py")
FeedNowAuthStack = stack_module.FeedNowAuthStack
parse_cognito_callback_urls = stack_module.parse_cognito_callback_urls

ENVIRONMENTS = ("dev", "staging", "prod")

CALLBACK_URLS = [
    "https://app.example.invalid/oauth/callback",
    "https://app.example.invalid/logout",
]


@functools.cache
def _stack(env_name: str, *callback_urls: str) -> FeedNowAuthStack:
    urls = list(callback_urls) or list(CALLBACK_URLS)
    return FeedNowAuthStack(
        cdk.App(),
        f"FeedNowAuth-{env_name}",
        feednow_env=env_name,
        cognito_callback_urls=urls,
        env=cdk.Environment(account="123456789012", region="eu-north-1"),
    )


@functools.cache
def _template(env_name: str) -> Template:
    return Template.from_stack(_stack(env_name))


def _single(env_name: str, resource_type: str) -> Mapping[str, Any]:
    """The one and only properties block of ``resource_type`` in the stack."""
    found = _template(env_name).find_resources(resource_type)
    assert len(found) == 1, f"expected exactly one {resource_type}, found {len(found)}"
    return next(iter(found.values()))["Properties"]


def _pool(env_name: str) -> Mapping[str, Any]:
    return _single(env_name, "AWS::Cognito::UserPool")


def _client(env_name: str) -> Mapping[str, Any]:
    return _single(env_name, "AWS::Cognito::UserPoolClient")


def _domain(env_name: str) -> Mapping[str, Any]:
    return _single(env_name, "AWS::Cognito::UserPoolDomain")


def _outputs(env_name: str) -> Mapping[str, Any]:
    return _template(env_name).to_json().get("Outputs", {})


# --- User pool: email-only sign-in, self sign-up, verified-email recovery ----


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_pool_signs_in_with_email_only(env_name: str) -> None:
    assert _pool(env_name)["UsernameAttributes"] == ["email"]


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_pool_self_sign_up_is_enabled_and_email_is_auto_verified(env_name: str) -> None:
    properties = _pool(env_name)
    assert properties["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": False}
    assert properties["AutoVerifiedAttributes"] == ["email"]


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_pool_recovers_password_by_verified_email_with_default_templates(env_name: str) -> None:
    properties = _pool(env_name)
    assert properties["AccountRecoverySetting"] == {
        "RecoveryMechanisms": [{"Name": "verified_email", "Priority": 1}]
    }
    # Cognito default email style: no developer SES configuration is granted.
    assert "EmailConfiguration" not in properties


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_pool_is_retained_in_prod_and_destroyed_elsewhere(env_name: str) -> None:
    expected = "Retain" if env_name == "prod" else "Delete"
    for resource in _template(env_name).find_resources("AWS::Cognito::UserPool").values():
        assert resource["DeletionPolicy"] == expected


# --- App client: public PKCE authorization-code client -----------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_client_is_public_and_named_per_env(env_name: str) -> None:
    properties = _client(env_name)
    assert properties["GenerateSecret"] is False
    assert properties["ClientName"] == f"feednow-auth-{env_name}"


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_client_uses_authorization_code_grant_with_pkce_scopes(env_name: str) -> None:
    properties = _client(env_name)
    assert properties["AllowedOAuthFlowsUserPoolClient"] is True
    assert properties["AllowedOAuthFlows"] == ["code"]
    assert sorted(properties["AllowedOAuthScopes"]) == ["email", "openid", "profile"]


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_client_explicit_auth_flows_cover_password_and_refresh(env_name: str) -> None:
    flows = _client(env_name)["ExplicitAuthFlows"]
    assert "ALLOW_USER_PASSWORD_AUTH" in flows
    assert "ALLOW_REFRESH_TOKEN_AUTH" in flows


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_client_redirect_uris_come_from_the_input(env_name: str) -> None:
    properties = _client(env_name)
    assert properties["CallbackURLs"] == CALLBACK_URLS
    assert properties["LogoutURLs"] == CALLBACK_URLS


def test_client_redirect_uris_follow_a_different_input() -> None:
    other = ["https://other.example.invalid/cb"]
    template = Template.from_stack(_stack("dev", *other))
    properties = next(iter(template.find_resources("AWS::Cognito::UserPoolClient").values()))[
        "Properties"
    ]
    assert properties["CallbackURLs"] == other
    assert properties["LogoutURLs"] == other


# --- Hosted domain ------------------------------------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_hosted_domain_prefix_is_environment_bound(env_name: str) -> None:
    assert _domain(env_name)["Domain"] == f"feednow-auth-{env_name}"


def test_domain_prefixes_differ_per_env() -> None:
    domains = {_domain(env_name)["Domain"] for env_name in ENVIRONMENTS}
    assert domains == {"feednow-auth-dev", "feednow-auth-staging", "feednow-auth-prod"}


# --- Outputs: pool id, issuer URL, client id ---------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_cognito_outputs_are_present_and_non_empty(env_name: str) -> None:
    outputs = _outputs(env_name)
    for name in ("CognitoUserPoolId", "CognitoIssuerUrl", "CognitoClientId"):
        assert name in outputs, f"{name} output missing"
        assert outputs[name]["Value"], f"{name} output is empty"


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_issuer_output_is_a_substituted_cognito_id_url(env_name: str) -> None:
    value = _outputs(env_name)["CognitoIssuerUrl"]["Value"]
    # The pool id is an unresolved token, so the URL must be built by Fn::Sub.
    assert "Fn::Sub" in value
    template, variables = value["Fn::Sub"]
    assert template == "https://cognito-idp.${region}.amazonaws.com/${pool_id}"
    assert variables["region"] == "eu-north-1"
    assert "Ref" in variables["pool_id"]


# --- COGNITO_CALLBACK_URLS is required at synth time --------------------------


@pytest.mark.parametrize("empty", [None, "", "  ", ",", ", ,", []])
def test_stack_requires_at_least_one_callback_url(empty: Any) -> None:
    with pytest.raises(ValueError, match="COGNITO_CALLBACK_URLS"):
        FeedNowAuthStack(
            cdk.App(), "FeedNowAuth-dev", feednow_env="dev", cognito_callback_urls=empty
        )


def test_callback_url_input_is_normalized() -> None:
    assert parse_cognito_callback_urls(
        " https://a.example.invalid/cb ,,https://b.example.invalid/logout,https://a.example.invalid/cb"
    ) == ("https://a.example.invalid/cb", "https://b.example.invalid/logout")
    assert parse_cognito_callback_urls(["https://a.example.invalid/cb"]) == (
        "https://a.example.invalid/cb",
    )
    assert parse_cognito_callback_urls(None) == ()


def test_stack_exposes_the_resolved_callback_urls() -> None:
    stack = _stack("dev", "https://a.example.invalid/cb,https://b.example.invalid/cb")
    assert stack.cognito_callback_urls == (
        "https://a.example.invalid/cb",
        "https://b.example.invalid/cb",
    )


# --- No secret material anywhere in the template ------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_template_carries_no_client_secret(env_name: str) -> None:
    assert _client(env_name)["GenerateSecret"] is False
    rendered = json.dumps(_template(env_name).to_json())
    assert "ClientSecret" not in rendered
    assert '"GenerateSecret": true' not in rendered
