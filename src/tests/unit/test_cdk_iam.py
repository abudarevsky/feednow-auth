"""Unit proofs for the Phase 07 pepper secret and Lambda role (task 4).

The stack must synthesize exactly one generated ``AWS::SecretsManager::Secret``
named ``feednow-auth/<env>/api-pepper`` (``GenerateStringKey="pepper"``,
48-byte length, punctuation excluded, no literal ``SecretString`` anywhere in
the template) and exactly one Lambda execution ``AWS::IAM::Role`` whose inline
policy carries *precisely* the consolidated per-resource grants of the IAM
matrix in docs/phases/06-dynamodb.md:

* table ARNs get exactly their matrix row, with the transactional actions
  (``PutItem``/``ConditionCheckItem``) only in statements pinned by
  ``"StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}``;
* GSI ARNs get ``Query`` only;
* ``secretsmanager:GetSecretValue`` on the pepper secret ARN only;
* ``logs:CreateLogStream``/``logs:PutLogEvents`` on the function's log group
  ARN pattern only.

Negative proofs: no wildcard actions or resources, no ``dynamodb:Scan`` or
table-admin actions, no non-``GetSecretValue`` Secrets Manager action,
per-resource action-set equality, and no literal secret value in the template.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
import json
import re
import sys
from collections.abc import Iterator, Mapping
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


# Loaded under a unique name: the other CDK test modules cache the same file
# and pytest may run any of them first.
stack_module = _load_module("feednow_cdk_iam_stack", CDK_DIR / "feednow_auth_stack.py")
FeedNowAuthStack = stack_module.FeedNowAuthStack

ENVIRONMENTS = ("dev", "staging", "prod")
ACCOUNT = "123456789012"
REGION = "eu-north-1"
CALLBACK_URLS = ["https://app.example.invalid/oauth/callback"]

#: The consolidated per-resource matrix, transcribed verbatim from
#: docs/phases/06-dynamodb.md "Least-privilege IAM matrix" (keyed by the
#: unsuffixed table name; physical names are ``feednow-auth-<env>-<name>``).
TABLE_MATRIX: Mapping[str, frozenset[str]] = {
    "users": frozenset({"GetItem", "PutItem", "ConditionCheckItem"}),
    "organizations": frozenset({"GetItem", "PutItem", "BatchGetItem", "ConditionCheckItem"}),
    "external_identities": frozenset({"PutItem"}),
    "audit_events": frozenset({"PutItem"}),
    "api_keys": frozenset({"GetItem", "PutItem", "UpdateItem", "Query"}),
    "memberships": frozenset({"GetItem", "PutItem", "DeleteItem", "Query"}),
    "unique_constraints": frozenset({"GetItem", "PutItem"}),
}

#: GSI ARNs get ``Query`` only (the base-table ``Query`` half of a GSI query
#: is already inside the table row above).
INDEX_MATRIX: Mapping[tuple[str, str], frozenset[str]] = {
    ("api_keys", "by-organization"): frozenset({"Query"}),
    ("memberships", "by-organization"): frozenset({"Query"}),
    ("memberships", "by-user"): frozenset({"Query"}),
}

#: The adapter performs these only inside ``TransactWriteItems``, so every
#: grant of them must carry this exact condition.
TRANSACTIONAL_ACTIONS = frozenset({"PutItem", "ConditionCheckItem"})
ENCLOSING_OPERATION_CONDITION: Mapping[str, Any] = {
    "StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}
}

#: Actions the runtime role must never hold (docs/phases/06-dynamodb.md
#: hardening note: table admin belongs to the deploy path only).
FORBIDDEN_DYNAMODB_ACTIONS = frozenset(
    {
        "dynamodb:Scan",
        "dynamodb:CreateTable",
        "dynamodb:DeleteTable",
        "dynamodb:DescribeTable",
        "dynamodb:PutResourcePolicy",
        "dynamodb:UpdateTable",
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


def _render(value: Any) -> str:
    """Flatten a synthesized (sub)template value into a comparable string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "Fn::GetAtt" in value:
            logical_id, attribute = value["Fn::GetAtt"]
            return f"Fn::GetAtt:{logical_id}:{attribute}"
        if "Fn::Join" in value:
            separator, parts = value["Fn::Join"]
            return separator.join(_render(part) for part in parts)
        if "Ref" in value:
            return f"${{{value['Ref']}}}"
    raise AssertionError(f"unexpected value shape: {value!r}")


def _actions(statement: Mapping[str, Any]) -> list[str]:
    action = statement["Action"]
    return [action] if isinstance(action, str) else list(action)


def _resources(statement: Mapping[str, Any]) -> list[str]:
    resource = statement["Resource"]
    resources = [resource] if isinstance(resource, (str, dict)) else list(resource)
    return [_render(item) for item in resources]


def _statements(env_name: str) -> list[Mapping[str, Any]]:
    """The statements of the single inline policy attached to the runtime role."""
    policies = _template(env_name).find_resources("AWS::IAM::Policy")
    assert len(policies) == 1, "the runtime role must carry exactly one inline policy"
    policy = next(iter(policies.values()))
    assert policy["Properties"]["Roles"] == [{"Ref": _role_logical_id(env_name)}]
    document = policy["Properties"]["PolicyDocument"]
    assert document["Version"] == "2012-10-17"
    return list(document["Statement"])


def _role_logical_id(env_name: str) -> str:
    roles = _template(env_name).find_resources("AWS::IAM::Role")
    assert len(roles) == 1, "exactly one role (the Lambda execution role) is expected"
    return next(iter(roles))


def _secret_logical_id(env_name: str) -> str:
    secrets = _template(env_name).find_resources("AWS::SecretsManager::Secret")
    assert len(secrets) == 1, "exactly one secret (the generated pepper) is expected"
    return next(iter(secrets))


def _table_logical_ids(env_name: str) -> Mapping[str, str]:
    """logical id -> unsuffixed table name, for the seven schema tables."""
    prefix = f"feednow-auth-{env_name}-"
    mapping = {}
    for logical_id, resource in _template(env_name).find_resources("AWS::DynamoDB::Table").items():
        name = resource["Properties"]["TableName"]
        assert name.startswith(prefix)
        mapping[logical_id] = name.removeprefix(prefix)
    assert len(mapping) == 7
    return mapping


def _classify(env_name: str, rendered: str) -> str:
    """Canonical key for a policy resource: table:/index:/secret:/logs:."""
    tables = _table_logical_ids(env_name)
    if rendered.startswith("Fn::GetAtt:"):
        head, _, index_suffix = rendered.partition("/index/")
        logical_id, _attribute = head.removeprefix("Fn::GetAtt:").split(":")
        table_name = tables[logical_id]
        if index_suffix:
            return f"index:{table_name}/index/{index_suffix}"
        return f"table:{table_name}"
    if rendered == f"${{{_secret_logical_id(env_name)}}}":
        # ``Ref`` on an AWS::SecretsManager::Secret resolves to its full ARN.
        return "secret"
    if ":logs:" in rendered:
        return "logs"
    raise AssertionError(f"unrecognized resource reference: {rendered!r}")


def _dynamodb_grants(env_name: str) -> Mapping[str, Mapping[str, set[str]]]:
    """Per-resource dynamodb actions, split by whether the statement carried
    the ``EnclosingOperation`` pin. Any other condition fails the proof."""
    grants: dict[str, dict[str, set[str]]] = {}
    for statement in _statements(env_name):
        actions = _actions(statement)
        dynamo = [action for action in actions if action.startswith("dynamodb:")]
        if not dynamo:
            continue
        assert len(dynamo) == len(actions), "a statement must not mix dynamodb and other services"
        assert statement["Effect"] == "Allow"
        condition = statement.get("Condition")
        if condition is not None:
            assert condition == ENCLOSING_OPERATION_CONDITION
        bucket = "pinned" if condition is not None else "plain"
        for resource in _resources(statement):
            key = _classify(env_name, resource)
            per_resource = grants.setdefault(key, {"plain": set(), "pinned": set()})
            per_resource[bucket].update(action.removeprefix("dynamodb:") for action in dynamo)
    return grants


def _non_dynamodb_statements(env_name: str) -> Iterator[Mapping[str, Any]]:
    for statement in _statements(env_name):
        if not any(action.startswith("dynamodb:") for action in _actions(statement)):
            yield statement


# --- The generated pepper secret ----------------------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_pepper_secret_is_generated_not_literal(env_name: str) -> None:
    properties = _template(env_name).find_resources("AWS::SecretsManager::Secret")[
        _secret_logical_id(env_name)
    ]["Properties"]
    assert properties["Name"] == f"feednow-auth/{env_name}/api-pepper"
    # The CloudFormation property is named PasswordLength; it is the
    # generator's ByteLength (48 clears the 32-byte runtime floor).
    assert properties["GenerateSecretString"] == {
        "GenerateStringKey": "pepper",
        "PasswordLength": 48,
        "ExcludePunctuation": True,
        "SecretStringTemplate": "{}",
    }
    assert "SecretString" not in properties


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_pepper_secret_is_retained_in_prod_and_destroyed_elsewhere(env_name: str) -> None:
    expected = "Retain" if env_name == "prod" else "Delete"
    resource = _template(env_name).find_resources("AWS::SecretsManager::Secret")[
        _secret_logical_id(env_name)
    ]
    assert resource["DeletionPolicy"] == expected


# --- The execution role identity ------------------------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_role_is_lambda_only_and_carries_no_managed_policies(env_name: str) -> None:
    properties = _template(env_name).find_resources("AWS::IAM::Role")[_role_logical_id(env_name)][
        "Properties"
    ]
    assert properties["RoleName"] == f"feednow-auth-{env_name}-lambda"
    trust = properties["AssumeRolePolicyDocument"]["Statement"]
    assert len(trust) == 1
    assert trust[0]["Action"] == "sts:AssumeRole"
    assert trust[0]["Principal"] == {"Service": "lambda.amazonaws.com"}
    # AWSLambdaBasicExecutionRole would wildcard the log group: nothing managed.
    assert "ManagedPolicyArns" not in properties
    assert "Policies" not in properties


# --- Positive: per-resource matrix grants ---------------------------------------


@pytest.mark.parametrize("table_name", sorted(TABLE_MATRIX))
def test_table_grants_equal_the_matrix_row_exactly(table_name: str) -> None:
    row = TABLE_MATRIX[table_name]
    for env_name in ENVIRONMENTS:
        grant = _dynamodb_grants(env_name)[f"table:{table_name}"]
        assert grant["plain"] == row - TRANSACTIONAL_ACTIONS
        assert grant["pinned"] == row & TRANSACTIONAL_ACTIONS


@pytest.mark.parametrize("table_name", sorted(TABLE_MATRIX))
def test_transactional_grants_are_pinned_to_transact_write_items(table_name: str) -> None:
    transactional = TABLE_MATRIX[table_name] & TRANSACTIONAL_ACTIONS
    if not transactional:  # pragma: no cover - every table row has one today
        return
    for env_name in ENVIRONMENTS:
        grant = _dynamodb_grants(env_name)[f"table:{table_name}"]
        # The transactional actions appear *only* under the condition.
        assert grant["pinned"] == transactional
        assert not grant["plain"] & TRANSACTIONAL_ACTIONS


@pytest.mark.parametrize(("table_name", "index_name"), sorted(INDEX_MATRIX))
def test_gsi_grants_are_query_only(table_name: str, index_name: str) -> None:
    for env_name in ENVIRONMENTS:
        grant = _dynamodb_grants(env_name)[f"index:{table_name}/index/{index_name}"]
        assert grant["plain"] == INDEX_MATRIX[(table_name, index_name)]
        assert not grant["pinned"]


def test_no_dynamodb_resource_outside_the_matrix() -> None:
    for env in ENVIRONMENTS:
        expected = {f"table:{name}" for name in TABLE_MATRIX} | {
            f"index:{table}/index/{index}" for table, index in INDEX_MATRIX
        }
        assert set(_dynamodb_grants(env)) == expected


# --- Positive: pepper and log grants ---------------------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_secretsmanager_grant_is_get_secret_value_on_the_pepper_arn_only(env_name: str) -> None:
    grants: dict[str, set[str]] = {}
    secret_resources = 0
    for statement in _non_dynamodb_statements(env_name):
        assert statement["Effect"] == "Allow"
        for action in _actions(statement):
            if action.startswith("secretsmanager:"):
                # every secretsmanager statement is scoped to the pepper only
                assert [_classify(env_name, r) for r in _resources(statement)] == ["secret"]
                secret_resources += 1
        for resource in _resources(statement):
            grants.setdefault(_classify(env_name, resource), set()).update(_actions(statement))
    assert secret_resources == 1, "exactly one secretsmanager statement (the pepper)"
    assert grants["secret"] == {"secretsmanager:GetSecretValue"}


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_logs_grant_is_scoped_to_the_function_log_group_pattern(env_name: str) -> None:
    logs_statements = [
        statement
        for statement in _non_dynamodb_statements(env_name)
        if any(action.startswith("logs:") for action in _actions(statement))
    ]
    assert len(logs_statements) == 1
    statement = logs_statements[0]
    assert sorted(_actions(statement)) == ["logs:CreateLogStream", "logs:PutLogEvents"]
    assert _resources(statement) == [
        f"arn:${{AWS::Partition}}:logs:{REGION}:{ACCOUNT}"
        f":log-group:/aws/lambda/feednow-auth-{env_name}:*"
    ]


# --- Negative: wildcard, scan/admin, foreign secretsmanager actions --------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_no_wildcard_actions_or_bare_wildcard_resources(env_name: str) -> None:
    for statement in _statements(env_name):
        for action in _actions(statement):
            assert action != "*", "wildcard action"
            assert not action.endswith(":*"), f"wildcard action family: {action}"
        for resource in _resources(statement):
            assert resource != "*", "wildcard resource"


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_no_scan_or_table_admin_actions(env_name: str) -> None:
    granted = {action for statement in _statements(env_name) for action in _actions(statement)}
    assert not granted & FORBIDDEN_DYNAMODB_ACTIONS


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_no_non_get_secret_value_secretsmanager_action(env_name: str) -> None:
    granted = {
        action
        for statement in _statements(env_name)
        for action in _actions(statement)
        if action.startswith("secretsmanager:")
    }
    assert granted == {"secretsmanager:GetSecretValue"}


# --- Negative: no literal secret material anywhere in the template ----------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_template_carries_no_literal_secret_value(env_name: str) -> None:
    template = _template(env_name).to_json()

    def walk(node: Any) -> Iterator[Any]:
        yield node
        if isinstance(node, Mapping):
            for key, value in node.items():
                assert key != "SecretString", "literal secret value property in the template"
                yield from walk(value)
        elif isinstance(node, list):
            yield from (item for value in node for item in walk(value))

    for node in walk(template):
        if isinstance(node, str):
            # A generated secret is 48 base64 chars; no such literal may
            # appear anywhere (names, keys, and templates are all shorter).
            assert not re.fullmatch(r"[A-Za-z0-9+/=]{44,}", node), "literal secret candidate"
    # The pepper is never an output; only the three Cognito outputs exist.
    assert set(template.get("Outputs", {})) == {
        "CognitoUserPoolId",
        "CognitoIssuerUrl",
        "CognitoClientId",
    }
    assert "api-pepper" in json.dumps(template)  # the name is fine; the value is not
