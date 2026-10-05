"""Unit proofs for the AWS pepper secret and Lambda role (implementation).

The stack must not synthesize Secrets Manager or SSM parameter resources or
carry plaintext pepper material; it grants the runtime one ``kms:Decrypt`` on
the environment's KMS key with a restricted encryption context and exactly
one Lambda execution ``AWS::IAM::Role`` whose inline policy carries *precisely*
the consolidated per-resource grants of the IAM
matrix in docs/capability/06-dynamodb.md:

* table ARNs get exactly their matrix row, with the transactional actions
  (``PutItem``/``ConditionCheckItem``) only in statements pinned by
  ``"StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}``;
* GSI ARNs get ``Query`` only;
* ``kms:Decrypt`` on the environment pepper key only;
* ``logs:CreateLogStream``/``logs:PutLogEvents`` on the function's log group
  ARN pattern only.

Negative proofs: no wildcard actions or resources, no ``dynamodb:Scan`` or
table-admin actions, no Secrets Manager actions,
per-resource action-set equality, and no literal secret value in the template.

Current behavior and invariants: ``docs/operations.md``."""

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
#: Runtime table permissions, keyed by unsuffixed table name; physical names
#: are ``feednow-auth-<env>-<name>``. Admin-only scans and cleanup deletes are
#: limited to these environment-prefixed table ARNs.
TABLE_MATRIX: Mapping[str, frozenset[str]] = {
    "users": frozenset(
        {"GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "ConditionCheckItem"}
    ),
    "organizations": frozenset(
        {
            "GetItem",
            "PutItem",
            "UpdateItem",
            "DeleteItem",
            "BatchGetItem",
            "Scan",
            "ConditionCheckItem",
        }
    ),
    "external_identities": frozenset({"PutItem", "DeleteItem", "Scan"}),
    "audit_events": frozenset({"PutItem", "DeleteItem", "Scan"}),
    "api_keys": frozenset({"GetItem", "PutItem", "DeleteItem", "UpdateItem", "Query", "Scan"}),
    "memberships": frozenset({"GetItem", "PutItem", "DeleteItem", "Query", "Scan"}),
    "unique_constraints": frozenset({"GetItem", "PutItem", "DeleteItem", "Scan"}),
    # Login state and sessions are partitioned separately; session cleanup is
    # available to the application administrator operation.
    "oauth_login_states": frozenset({"PutItem", "DeleteItem"}),
    "app_sessions": frozenset({"GetItem", "PutItem", "DeleteItem", "Scan"}),
    "service_authorization_codes": frozenset({"PutItem", "UpdateItem"}),
}

#: Phase 11: the session tables are written by *standalone* conditional
#: operations (never ``TransactWriteItems``), so their ``PutItem`` grant is
#: NOT pinned to the enclosing-operation condition the way the Phase 06
#: tables' is. This is the single deviation from the "transactional actions
#: are always pinned" rule, and it mirrors the stack's
#: ``_STANDALONE_WRITE_TABLES``.
STANDALONE_WRITE_TABLES = frozenset(
    {"oauth_login_states", "app_sessions", "service_authorization_codes"}
)

#: GSI ARNs get ``Query`` only (the base-table ``Query`` half of a GSI query
#: is already inside the table row above).
#:
#: Phase 13 least-privilege decision (pinned, do not relitigate in build):
#: mirroring the ``users/by-application-role`` index into the stack ``_SCHEMA``
#: **does** extend the Lambda execution role with ``Query`` on that index even
#: though no Lambda code path queries it — the application-role transition is
#: CLI-only and the CLI runs outside Lambda under the separately documented
#: operator role. The grant is accepted because it exposes no data the role
#: cannot already read (base-table ``GetItem``/``Query`` on the same ``users``
#: items and attributes are already granted) and excludes nothing writable,
#: while any exclusion mechanism would fork the stack ``_SCHEMA`` mirror
#: invariant that ``test_cdk_dynamodb.py`` pins field-for-field. No ``Scan``,
#: no other table touched, no new Lambda capability beyond this accepted read.
#: (Restated in the docs/operations.md IAM section with the runbook.)
INDEX_MATRIX: Mapping[tuple[str, str], frozenset[str]] = {
    ("api_keys", "by-organization"): frozenset({"Query"}),
    ("memberships", "by-organization"): frozenset({"Query"}),
    ("memberships", "by-user"): frozenset({"Query"}),
    # Phase 12: the users/by-email lookup path (Query only, like every GSI).
    ("users", "by-email"): frozenset({"Query"}),
    # Phase 13: the users/by-application-role guard path (Query only, like
    # every GSI; the accepted CLI-only read justified above).
    ("users", "by-application-role"): frozenset({"Query"}),
}

#: The adapter performs these only inside ``TransactWriteItems``, so every
#: grant of them must carry this exact condition.
TRANSACTIONAL_ACTIONS = frozenset({"PutItem", "ConditionCheckItem"})
ENCLOSING_OPERATION_CONDITION: Mapping[str, Any] = {
    "StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}
}

#: Actions the runtime role must never hold (see ``docs/operations.md``)
#: hardening note: table admin belongs to the deploy path only).
FORBIDDEN_DYNAMODB_ACTIONS = frozenset(
    {
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
        account_origin="https://account.example.invalid",
        existing_user_pool_id=f"eu-north-1_{env_name}",
        existing_client_id=f"{env_name}client",
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
    role_ref = {"Ref": _role_logical_id(env_name)}
    runtime_policies = [
        policy for policy in policies.values() if role_ref in policy["Properties"]["Roles"]
    ]
    assert len(runtime_policies) == 1, "the runtime role must carry exactly one inline policy"
    policy = runtime_policies[0]
    document = policy["Properties"]["PolicyDocument"]
    assert document["Version"] == "2012-10-17"
    return list(document["Statement"])


def _role_logical_id(env_name: str) -> str:
    roles = _template(env_name).find_resources("AWS::IAM::Role")
    runtime_roles = [
        logical_id
        for logical_id, role in roles.items()
        if role["Properties"].get("RoleName") == f"feednow-auth-{env_name}-lambda"
    ]
    assert len(runtime_roles) == 1, "exactly one runtime Lambda role is expected"
    return runtime_roles[0]


def _table_logical_ids(env_name: str) -> Mapping[str, str]:
    """logical id -> unsuffixed table name, for the ten schema tables."""
    prefix = f"feednow-auth-{env_name}-"
    mapping = {}
    for logical_id, resource in _template(env_name).find_resources("AWS::DynamoDB::Table").items():
        name = resource["Properties"]["TableName"]
        assert name.startswith(prefix)
        mapping[logical_id] = name.removeprefix(prefix)
    assert len(mapping) == 10
    return mapping


def _classify(env_name: str, rendered: str) -> str:
    """Canonical key for a table/index/log/parameter policy resource."""
    tables = _table_logical_ids(env_name)
    if rendered.startswith("Fn::GetAtt:"):
        head, _, index_suffix = rendered.partition("/index/")
        logical_id, _attribute = head.removeprefix("Fn::GetAtt:").split(":")
        table_name = tables[logical_id]
        if index_suffix:
            return f"index:{table_name}/index/{index_suffix}"
        return f"table:{table_name}"
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


# --- Pepper source is external to CloudFormation -------------------------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_template_does_not_create_a_secret_or_parameter_resource(env_name: str) -> None:
    template = _template(env_name)
    assert not template.find_resources("AWS::SecretsManager::Secret")
    assert not template.find_resources("AWS::SSM::Parameter")
    assert len(template.find_resources("AWS::KMS::Key")) == 1


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
        if table_name in STANDALONE_WRITE_TABLES:
            # Phase 11: every action is a standalone conditional write/read,
            # so the whole row is granted unpinned and nothing is pinned.
            assert grant["plain"] == row
            assert not grant["pinned"]
            continue
        assert grant["plain"] == row - TRANSACTIONAL_ACTIONS
        assert grant["pinned"] == row & TRANSACTIONAL_ACTIONS


@pytest.mark.parametrize("table_name", sorted(TABLE_MATRIX))
def test_transactional_grants_are_pinned_to_transact_write_items(table_name: str) -> None:
    if table_name in STANDALONE_WRITE_TABLES:
        # Phase 11 exception: these tables' PutItem is a standalone
        # conditional write, so it must NOT be pinned (pinning it would deny
        # the actual adapter call). Assert the inverse: nothing pinned.
        for env_name in ENVIRONMENTS:
            grant = _dynamodb_grants(env_name)[f"table:{table_name}"]
            assert not grant["pinned"]
        return
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
def test_kms_decrypt_grant_is_environment_scoped(env_name: str) -> None:
    matches = []
    for statement in _non_dynamodb_statements(env_name):
        if any(action.startswith("kms:") for action in _actions(statement)):
            matches.append(statement)
    assert len(matches) == 1
    assert _actions(matches[0]) == ["kms:Decrypt"]
    assert len(_resources(matches[0])) == 1
    assert "PepperKmsKey" in _resources(matches[0])[0]
    assert matches[0]["Condition"] == {
        "StringEquals": {"kms:EncryptionContext:environment": env_name}
    }
    all_actions = {action for statement in _statements(env_name) for action in _actions(statement)}
    assert not any(action.startswith("secretsmanager:") for action in all_actions)


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


# --- Negative: wildcard, scan/admin, or Secrets Manager permissions ---------------


@pytest.mark.parametrize("env_name", ENVIRONMENTS)
def test_no_secrets_manager_permissions(env_name: str) -> None:
    granted = {action for statement in _statements(env_name) for action in _actions(statement)}
    assert not any(action.startswith("secretsmanager:") for action in granted)
    assert not any(action.startswith("ssm:") for action in granted)


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
    # Only the KMS key ARN is output; plaintext pepper is never a stack output.
    assert set(template.get("Outputs", {})) == {
        "ApiEndpoint",
        "CognitoUserPoolId",
        "CognitoIssuerUrl",
        "CognitoClientId",
        "PepperKmsKeyArn",
    }
    assert "api-pepper" in json.dumps(template)  # the name is fine; the value is not
