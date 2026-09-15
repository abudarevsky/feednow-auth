"""Unit proofs for the Phase 07 CDK DynamoDB tables (task 2).

The stack must declare the seven Phase 06 ``SCHEMA`` tables verbatim:
``aws_cdk.assertions.Template`` finds exactly 7 ``AWS::DynamoDB::Table``
per environment with the runtime schema's partition/sort keys and GSI
names/key schemas (ALL projection), the physical names carry the
environment's ``table_prefix``, billing is ``PAY_PER_REQUEST`` everywhere
with no drift, there is no customer-managed ``EncryptionKey``, removal is
``DESTROY`` for dev/staging and ``RETAIN`` for prod, and point-in-time
recovery is enabled for prod only.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import aws_cdk as cdk
from aws_cdk.assertions import Template

from app.storage.dynamodb import SCHEMA, IndexSpec, TableSpec

CDK_DIR = Path(__file__).resolve().parents[3] / "deploy" / "aws" / "cdk"


def _load_module(name: str, path: Path) -> ModuleType:
    """Import a CDK file under a fixed name without mutating the global ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Loaded under a unique name: ``test_cdk_app.py`` caches the same file as
# ``feednow_auth_stack`` and pytest may run either file first.
stack_module = _load_module("feednow_cdk_dynamodb_stack", CDK_DIR / "feednow_auth_stack.py")
FeedNowAuthStack = stack_module.FeedNowAuthStack

ENVIRONMENTS = ("dev", "staging", "prod")

# Task 3 made COGNITO_CALLBACK_URLS a required synth input; the DynamoDB
# proofs do not care about its value, only that the stack synthesizes.
CALLBACK_URLS = ["https://app.example.invalid/oauth/callback"]


@functools.cache
def _template(env_name: str) -> Template:
    app = cdk.App()
    stack = FeedNowAuthStack(
        app,
        f"FeedNowAuth-{env_name}",
        feednow_env=env_name,
        cognito_callback_urls=CALLBACK_URLS,
        env=cdk.Environment(account="123456789012", region="eu-north-1"),
    )
    return Template.from_stack(stack)


def _tables(env_name: str) -> Mapping[str, Mapping[str, Any]]:
    """The synthesized ``AWS::DynamoDB::Table`` resources keyed by logical id."""
    return _template(env_name).find_resources("AWS::DynamoDB::Table")


def _table_by_name(env_name: str, table_name: str) -> Mapping[str, Any]:
    matches = [
        resource["Properties"]
        for resource in _tables(env_name).values()
        if resource["Properties"]["TableName"] == table_name
    ]
    assert len(matches) == 1, f"expected exactly one table named {table_name!r}"
    return matches[0]


def _key_schema(partition_key: str, sort_key: str | None) -> list[dict[str, str]]:
    schema = [{"AttributeName": partition_key, "KeyType": "HASH"}]
    if sort_key is not None:
        schema.append({"AttributeName": sort_key, "KeyType": "RANGE"})
    return schema


def _gsi_schema(indexes: tuple[IndexSpec, ...]) -> list[dict[str, Any]]:
    return [
        {
            "IndexName": index.name,
            "KeySchema": _key_schema(index.partition_key, index.sort_key),
            "Projection": {"ProjectionType": "ALL"},
        }
        for index in indexes
    ]


def _spec_key_names(spec: TableSpec) -> set[str]:
    names = {spec.partition_key}
    if spec.sort_key is not None:
        names.add(spec.sort_key)
    for index in spec.indexes:
        names.update((index.partition_key, index.sort_key))
    return names


# --- Verbatim transcription of the runtime schema -----------------------------


def test_cdk_schema_copy_matches_runtime_schema() -> None:
    """The stack's private transcription equals ``SCHEMA`` field-for-field."""
    cdk_schema = stack_module._SCHEMA
    assert [(s.name, s.partition_key, s.sort_key) for s in cdk_schema] == [
        (s.name, s.partition_key, s.sort_key) for s in SCHEMA
    ]
    for cdk_spec, runtime_spec in zip(cdk_schema, SCHEMA, strict=True):
        assert [(i.name, i.partition_key, i.sort_key) for i in cdk_spec.indexes] == [
            (i.name, i.partition_key, i.sort_key) for i in runtime_spec.indexes
        ]


# --- Resource count and physical names ----------------------------------------


def test_template_declares_exactly_seven_tables() -> None:
    for env_name in ENVIRONMENTS:
        assert len(_tables(env_name)) == 7, f"{env_name} must declare exactly 7 tables"


def test_table_names_carry_the_env_prefix() -> None:
    for env_name in ENVIRONMENTS:
        prefix = f"feednow-auth-{env_name}-"
        stack = FeedNowAuthStack(
            cdk.App(),
            f"FeedNowAuth-{env_name}",
            feednow_env=env_name,
            cognito_callback_urls=CALLBACK_URLS,
        )
        assert stack.table_prefix == prefix
        names = {resource["Properties"]["TableName"] for resource in _tables(env_name).values()}
        assert names == {f"{prefix}{spec.name}" for spec in SCHEMA}


def test_prefix_differs_per_env() -> None:
    names = {
        env_name: frozenset(
            resource["Properties"]["TableName"] for resource in _tables(env_name).values()
        )
        for env_name in ENVIRONMENTS
    }
    assert names["dev"] != names["staging"] != names["prod"]
    assert not names["dev"] & names["staging"] & names["prod"]


# --- Key schemas and GSIs, transcribed from the runtime SCHEMA -----------------


def test_base_key_schemas_match_runtime_schema() -> None:
    for env_name in ENVIRONMENTS:
        for spec in SCHEMA:
            properties = _table_by_name(env_name, f"feednow-auth-{env_name}-{spec.name}")
            assert properties["KeySchema"] == _key_schema(spec.partition_key, spec.sort_key)
            assert {
                (definition["AttributeName"], definition["AttributeType"])
                for definition in properties["AttributeDefinitions"]
            } == {(name, "S") for name in _spec_key_names(spec)}


def test_gsi_names_key_schemas_and_projection_match_runtime_schema() -> None:
    for env_name in ENVIRONMENTS:
        for spec in SCHEMA:
            properties = _table_by_name(env_name, f"feednow-auth-{env_name}-{spec.name}")
            indexes = properties.get("GlobalSecondaryIndexes", [])
            assert len(indexes) == len(spec.indexes), f"{spec.name} GSI count drifted"
            for index in _gsi_schema(spec.indexes):
                assert index in indexes, f"{spec.name} missing GSI {index['IndexName']!r}"


# --- Billing, encryption, and capacity drift ---------------------------------


def test_billing_is_pay_per_request_with_no_capacity_drift() -> None:
    for env_name in ENVIRONMENTS:
        for properties in (table["Properties"] for table in _tables(env_name).values()):
            assert properties["BillingMode"] == "PAY_PER_REQUEST"
            for forbidden in ("ProvisionedThroughput", "ReadCapacityUnits", "WriteCapacityUnits"):
                assert forbidden not in properties


def test_no_customer_managed_encryption_key() -> None:
    for env_name in ENVIRONMENTS:
        for properties in (table["Properties"] for table in _tables(env_name).values()):
            assert "SSESpecification" not in properties


# --- Removal policy and point-in-time recovery per environment ----------------


def test_removal_policy_destroys_non_prod_and_retains_prod() -> None:
    for env_name in ENVIRONMENTS:
        expected = "Retain" if env_name == "prod" else "Delete"
        for resource in _tables(env_name).values():
            assert resource.get("DeletionPolicy") == expected, f"{env_name} removal drifted"


def test_point_in_time_recovery_enabled_for_prod_only() -> None:
    for env_name in ENVIRONMENTS:
        for properties in (table["Properties"] for table in _tables(env_name).values()):
            recovery = properties.get("PointInTimeRecoverySpecification")
            if env_name == "prod":
                assert recovery == {"PointInTimeRecoveryEnabled": True}
            else:
                assert not recovery or not recovery.get("PointInTimeRecoveryEnabled")
