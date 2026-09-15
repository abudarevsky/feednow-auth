"""Unit proofs for the Phase 07 task-6 Lambda + HTTP API wiring.

The stack must synthesize exactly one runtime ``AWS::Lambda::Function``
(python3.13, x86_64, 512 MB, 30 s, handler ``handler.handler``) that runs
as the task-4 least-privilege role and carries exactly the five
``FEEDNOW_*`` keys of the task-5 boot contract, with values that reference
the pool/client/secret/table resources (never literals that could drift,
never secret material). The ``AWS::ApiGatewayV2`` side must carry the
``ANY /`` and ``ANY /{proxy+}`` Lambda-proxy routes on the ``$default``
stage, per-route invoke permissions scoped to the function ARN, and a
custom access-log format whose only ``$context`` tokens are request id,
http method, path, status, and integration latency -- a negative proof
that no ``requestHeader``/``requestQueryString`` token (bearer tokens,
query parameters) can ever reach CloudWatch.

The bundling class is proven hermetically: ``subprocess.run`` is faked, so
the tests assert the exact ``uv`` manylinux invocation and the copied
bundle layout without installing anything or requiring Docker. The real
bundle runs during ``Template.from_stack`` synth (cached per environment
via ``functools.cache``), which is what the task's Docker-free synth
evidence exercises.
"""

from __future__ import annotations

import functools
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

REPO_ROOT = Path(__file__).resolve().parents[3]
CDK_DIR = REPO_ROOT / "deploy" / "aws" / "cdk"
RUNTIME_DIR = REPO_ROOT / "deploy" / "aws" / "runtime"
LAMBDA_REQUIREMENTS = RUNTIME_DIR.parent / "lambda-requirements.txt"

ENVIRONMENTS = ("dev", "staging", "prod")
ACCOUNT = "123456789012"
REGION = "eu-north-1"
CALLBACK_URLS = ["https://app.example.invalid/oauth/callback"]


def _load_module(name: str, path: Path) -> ModuleType:
    """Import a deploy file under a fixed name without mutating the global ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Loaded under unique names: the other CDK test modules cache the same file
# and pytest may run any of them first. ``secrets_pepper`` is registered
# under its own name first so ``handler``'s top-level import resolves
# (the pattern test_runtime_handler.py establishes).
stack_module = _load_module("feednow_cdk_lambda_api_stack", CDK_DIR / "feednow_auth_stack.py")
_load_module("secrets_pepper", RUNTIME_DIR / "secrets_pepper.py")
runtime_handler = _load_module("feednow_cdk_lambda_api_runtime_handler", RUNTIME_DIR / "handler.py")

FeedNowAuthStack = stack_module.FeedNowAuthStack
_LocalBundling = stack_module._LocalBundling

#: The five runtime keys, pinned against the task-5 boot contract so the
#: duplicated names in the stack module can never drift.
CONFIG_KEYS = tuple(runtime_handler.REQUIRED_ENV_KEYS)

#: The only ``$context`` tokens the access-log format may reference.
ALLOWED_CONTEXT_TOKENS = frozenset(
    {
        "$context.requestId",
        "$context.httpMethod",
        "$context.path",
        "$context.status",
        "$context.integrationLatency",
    }
)


@functools.cache
def _stack(env_name: str) -> FeedNowAuthStack:
    return FeedNowAuthStack(
        cdk.App(),
        f"FeedNowAuth-{env_name}",
        feednow_env=env_name,
        cognito_callback_urls=CALLBACK_URLS,
        env=cdk.Environment(account=ACCOUNT, region=REGION),
    )


@functools.cache
def _template(env_name: str) -> Template:
    return Template.from_stack(_stack(env_name))


def _single(env_name: str, resource_type: str) -> tuple[str, Mapping[str, Any]]:
    resources = _template(env_name).find_resources(resource_type)
    assert len(resources) == 1, f"exactly one {resource_type} is expected, got {len(resources)}"
    return next(iter(resources.items()))


def _function(env_name: str) -> tuple[str, Mapping[str, Any]]:
    return _single(env_name, "AWS::Lambda::Function")


def _function_properties(env_name: str) -> Mapping[str, Any]:
    return _function(env_name)[1]["Properties"]


def _environment_variables(env_name: str) -> Mapping[str, Any]:
    return _function_properties(env_name)["Environment"]["Variables"]


# --- The runtime function shape -------------------------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_function_shape_matches_the_runtime_contract(env_name: str) -> None:
    properties = _function_properties(env_name)
    assert properties["FunctionName"] == f"feednow-auth-{env_name}"
    assert properties["Runtime"] == "python3.13"
    assert properties["Architectures"] == ["x86_64"]
    assert properties["MemorySize"] == 512
    assert properties["Timeout"] == 30
    assert properties["Handler"] == "handler.handler"


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_function_runs_as_the_task4_role(env_name: str) -> None:
    role_id, role = _single(env_name, "AWS::IAM::Role")
    assert role["Properties"]["RoleName"] == f"feednow-auth-{env_name}-lambda"
    assert _function_properties(env_name)["Role"] == {"Fn::GetAtt": [role_id, "Arn"]}


# --- The five FEEDNOW_* env vars reference the stack resources -------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_function_environment_is_exactly_the_five_runtime_keys(env_name: str) -> None:
    variables = _environment_variables(env_name)
    assert set(variables) == set(CONFIG_KEYS)
    # The stack-level constants are the same names the handler reads.
    assert {
        stack_module.LAMBDA_REGION_ENV,
        stack_module.LAMBDA_TABLE_PREFIX_ENV,
        stack_module.LAMBDA_ISSUERS_ENV,
        stack_module.LAMBDA_CLIENT_IDS_ENV,
        stack_module.LAMBDA_PEPPER_SECRET_ID_ENV,
    } == set(CONFIG_KEYS)


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_region_and_table_prefix_env_vars(env_name: str) -> None:
    variables = _environment_variables(env_name)
    assert variables["FEEDNOW_DYNAMODB_REGION"] == REGION
    prefix = variables["FEEDNOW_TABLE_PREFIX"]
    assert prefix == f"feednow-auth-{env_name}-"
    # The prefix resolves through every task-2 table's physical name.
    tables = _template(env_name).find_resources("AWS::DynamoDB::Table")
    assert len(tables) == 7
    for resource in tables.values():
        assert resource["Properties"]["TableName"].startswith(prefix)


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_cognito_env_vars_reference_the_pool_and_client(env_name: str) -> None:
    pool_id, _pool = _single(env_name, "AWS::Cognito::UserPool")
    client_id, _client = _single(env_name, "AWS::Cognito::UserPoolClient")
    variables = _environment_variables(env_name)
    # The issuer URL is Fn::Sub over the pool id (unresolved at synth time).
    issuer = variables["FEEDNOW_COGNITO_ISSUERS"]
    template, substitutions = issuer["Fn::Sub"]
    assert template == "https://cognito-idp.${region}.amazonaws.com/${pool_id}"
    assert substitutions["pool_id"] == {"Ref": pool_id}
    # CloudFormation Refs on a UserPoolClient resolve to its client id.
    assert variables["FEEDNOW_COGNITO_CLIENT_IDS"] == {"Ref": client_id}


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_pepper_env_var_is_the_task4_secret_name_not_material(env_name: str) -> None:
    secret_id, secret = _single(env_name, "AWS::SecretsManager::Secret")
    variables = _environment_variables(env_name)
    # A name, never secret material: CDK derives the name from the secret's
    # own ARN (Ref) via Split/Select rejoin, so the env var references the
    # task-4 secret resource and the literal name is only the resource's
    # Name property -- no ARN literal and no generated value anywhere.
    assert secret["Properties"]["Name"] == f"feednow-auth/{env_name}/api-pepper"
    value = variables["FEEDNOW_PEPPER_SECRET_ID"]
    raw = json.dumps(value)
    assert f'"Ref": "{secret_id}"' in raw
    assert value["Fn::Join"][0] == "-"  # name rejoin, not an "arn:" string
    assert "arn:" not in raw
    assert "GenerateSecretString" not in raw


# --- The HTTP API: stage, routes, integration, permissions -----------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_http_api_has_the_default_stage_named_after_the_handler_constant(env_name: str) -> None:
    assert runtime_handler.API_STAGE == stack_module.API_STAGE == "$default"
    _stage_id, stage = _single(env_name, "AWS::ApiGatewayV2::Stage")
    assert stage["Properties"]["StageName"] == "$default"
    assert stage["Properties"]["AutoDeploy"] is True


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_any_routes_on_root_and_proxy_cover_every_path(env_name: str) -> None:
    routes = _template(env_name).find_resources("AWS::ApiGatewayV2::Route")
    assert {route["Properties"]["RouteKey"] for route in routes.values()} == {
        "ANY /",
        "ANY /{proxy+}",
    }


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_integration_is_lambda_proxy_2_0_to_the_function(env_name: str) -> None:
    function_id, _function_resource = _function(env_name)
    _integration_id, integration = _single(env_name, "AWS::ApiGatewayV2::Integration")
    properties = integration["Properties"]
    assert properties["IntegrationType"] == "AWS_PROXY"
    assert properties["PayloadFormatVersion"] == "2.0"
    assert properties["IntegrationUri"] == {"Fn::GetAtt": [function_id, "Arn"]}


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_invoke_permissions_are_scoped_to_the_function_arn(env_name: str) -> None:
    function_id, _function_resource = _function(env_name)
    _api_id, _api = _single(env_name, "AWS::ApiGatewayV2::Api")
    permissions = _template(env_name).find_resources("AWS::Lambda::Permission")
    # One per route (the shared integration binds each route separately).
    assert len(permissions) == 2
    for permission in permissions.values():
        properties = permission["Properties"]
        assert properties["Action"] == "lambda:InvokeFunction"
        assert properties["FunctionName"] == {"Fn::GetAtt": [function_id, "Arn"]}
        assert properties["Principal"] == "apigateway.amazonaws.com"
        # Source is this API's execute-api ARN only, never "*".
        rendered = json_render(properties["SourceArn"])
        assert "execute-api" in rendered
        assert f"${{{_api_id}}}" in rendered


def json_render(value: Any) -> str:
    """Flatten a synthesized (sub/join/ref) value into a comparable string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "Fn::Sub" in value:
            sub = value["Fn::Sub"]
            template, mapping = (sub, {}) if isinstance(sub, str) else sub
            for key, item in mapping.items():
                template = template.replace(f"${{{key}}}", json_render(item))
            return template
        if "Fn::Join" in value:
            separator, parts = value["Fn::Join"]
            return separator.join(json_render(part) for part in parts)
        if "Ref" in value:
            return f"${{{value['Ref']}}}"
    raise AssertionError(f"unexpected value shape: {value!r}")


# --- Redaction-safe access logs ---------------------------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_access_log_format_carries_only_the_five_safe_tokens(env_name: str) -> None:
    _log_id, _log_group = _single(env_name, "AWS::Logs::LogGroup")
    _stage_id, stage = _single(env_name, "AWS::ApiGatewayV2::Stage")
    settings = stage["Properties"]["AccessLogSettings"]
    assert settings["DestinationArn"] == {"Fn::GetAtt": [_log_id, "Arn"]}
    assert settings["Format"] == stack_module.API_ACCESS_LOG_FORMAT
    tokens = frozenset(re.findall(r"\$context\.[A-Za-z.]+", settings["Format"]))
    assert tokens == ALLOWED_CONTEXT_TOKENS


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_access_log_format_never_references_headers_or_query_strings(env_name: str) -> None:
    _stage_id, stage = _single(env_name, "AWS::ApiGatewayV2::Stage")
    fmt: str = stage["Properties"]["AccessLogSettings"]["Format"]
    for forbidden in ("requestHeader", "requestQueryString", "requestBody", "$context.error"):
        assert forbidden not in fmt, f"redaction-unsafe token in access log format: {forbidden}"


# --- The Docker-free local bundling class -----------------------------------------

EXPECTED_UV_COMMAND = [
    "uv",
    "pip",
    "install",
    "--python-version",
    "3.13",
    "--python-platform",
    "x86_64-manylinux2014",
    "--only-binary",
    ":all:",
    "-r",
    str(LAMBDA_REQUIREMENTS),
    "--target",
]


def test_bundling_copies_runtime_modules_app_and_installs_manylinux_wheels(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> None:
        captured.append(list(command))

    monkeypatch.setattr(stack_module.subprocess, "run", fake_run)

    assert _LocalBundling().try_bundle(str(tmp_path), image=None) is True

    # The install command is the exact uv manylinux invocation.
    assert captured == [[*EXPECTED_UV_COMMAND, str(tmp_path)]]
    # Handler modules land at the bundle root (handler.handler must resolve) ...
    assert (tmp_path / "handler.py").is_file()
    assert (tmp_path / "secrets_pepper.py").is_file()
    assert not list(tmp_path.rglob("__pycache__"))
    # ... and src/app is copied as app/ (the handler's `from app...` imports).
    assert (tmp_path / "app" / "main.py").is_file()
    assert (tmp_path / "app" / "storage" / "dynamodb.py").is_file()


def test_bundling_surfaces_dependency_install_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def failing_run(command: list[str], **kwargs: Any) -> None:
        raise subprocess.CalledProcessError(1, command, stderr="No matching distribution found")

    monkeypatch.setattr(stack_module.subprocess, "run", failing_run)

    with pytest.raises(
        RuntimeError,
        match=r"Lambda dependency installation failed:\nNo matching distribution found",
    ):
        _LocalBundling().try_bundle(str(tmp_path), image=None)


def test_bundling_reports_a_missing_uv_executable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def missing_uv(command: list[str], **kwargs: Any) -> None:
        raise FileNotFoundError("uv")

    monkeypatch.setattr(stack_module.subprocess, "run", missing_uv)

    with pytest.raises(RuntimeError, match="uv executable was not found"):
        _LocalBundling().try_bundle(str(tmp_path), image=None)
