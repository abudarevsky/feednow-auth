"""Tests for the idempotent, settings-preserving Cognito CDK overlay provider."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

PROVIDER_PATH = (
    Path(__file__).resolve().parents[3]
    / "deploy"
    / "aws"
    / "cdk"
    / "google_federation_fix_provider"
    / "handler.py"
)
SPEC = importlib.util.spec_from_file_location("google_federation_fix_provider", PROVIDER_PATH)
assert SPEC is not None and SPEC.loader is not None
provider = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provider)

POOL_ID = "eu-north-1_EXAMPLE"
CLIENT_ID = "public-client-id"
TRIGGER_ARN = "arn:aws:lambda:eu-north-1:123456789012:function:google-trigger"


class FakeCognito:
    def __init__(self) -> None:
        self.pool = {
            "Id": POOL_ID,
            "Name": "existing-pool",
            "AutoVerifiedAttributes": ["email"],
            "LambdaConfig": {"PostConfirmation": "arn:post-confirmation"},
            "Schema": [],
        }
        self.app_client = {
            "UserPoolId": POOL_ID,
            "ClientId": CLIENT_ID,
            "ClientName": "existing-client",
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthScopes": ["openid", "email", "profile"],
            "ReadAttributes": ["email", "email_verified"],
            "WriteAttributes": ["email"],
            # A provider secret can appear in Describe responses; it must not
            # be forwarded to UpdateUserPoolClient or returned by the handler.
            "ClientSecret": "must-not-be-copied",
        }
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def describe_user_pool(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("describe_user_pool", kwargs))
        return {"UserPool": dict(self.pool)}

    def add_custom_attributes(self, **kwargs: Any) -> None:
        self.calls.append(("add_custom_attributes", kwargs))
        self.pool["Schema"].append(
            {
                "Name": "custom:g_verified",
                "AttributeDataType": "String",
                "Mutable": True,
            }
        )

    def describe_user_pool_client(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("describe_user_pool_client", kwargs))
        return {"UserPoolClient": dict(self.app_client)}

    def update_user_pool_client(self, **kwargs: Any) -> None:
        self.calls.append(("update_user_pool_client", kwargs))

    def update_identity_provider(self, **kwargs: Any) -> None:
        self.calls.append(("update_identity_provider", kwargs))

    def update_user_pool(self, **kwargs: Any) -> None:
        self.calls.append(("update_user_pool", kwargs))
        self.pool.update(kwargs)


def test_configure_adds_only_google_proof_mapping_and_preserves_pool_settings() -> None:
    cognito = FakeCognito()
    provider._configure(
        cognito,
        {"PoolId": POOL_ID, "ClientId": CLIENT_ID, "TriggerArn": TRIGGER_ARN},
    )

    updates = {name: values for name, values in cognito.calls if name.startswith("update_")}
    assert updates["update_user_pool"]["AutoVerifiedAttributes"] == ["email"]
    assert updates["update_user_pool"]["LambdaConfig"] == {
        "PostConfirmation": "arn:post-confirmation",
        "PreSignUp": TRIGGER_ARN,
        "PreAuthentication": TRIGGER_ARN,
    }
    assert updates["update_user_pool_client"]["WriteAttributes"] == [
        "custom:g_verified",
        "email",
    ]
    assert "ClientSecret" not in updates["update_user_pool_client"]
    assert updates["update_identity_provider"]["AttributeMapping"] == {
        "email": "email",
        "custom:g_verified": "email_verified",
        "username": "sub",
    }


def test_existing_custom_attribute_is_not_added_twice() -> None:
    cognito = FakeCognito()
    cognito.pool["Schema"] = [
        {
            "Name": "custom:g_verified",
            "AttributeDataType": "String",
            "Mutable": True,
        }
    ]
    provider._ensure_custom_attribute(cognito, POOL_ID)
    assert not any(name == "add_custom_attributes" for name, _ in cognito.calls)


def test_delete_detaches_only_its_own_triggers() -> None:
    cognito = FakeCognito()
    cognito.pool["LambdaConfig"].update(
        {"PreSignUp": TRIGGER_ARN, "PreAuthentication": TRIGGER_ARN}
    )
    provider._detach(cognito, {"PoolId": POOL_ID, "TriggerArn": TRIGGER_ARN})
    updates = [values for name, values in cognito.calls if name == "update_user_pool"]
    assert updates == [
        {
            "AutoVerifiedAttributes": ["email"],
            "LambdaConfig": {"PostConfirmation": "arn:post-confirmation"},
            "UserPoolId": POOL_ID,
        }
    ]


def test_cloudformation_entrypoint_hides_provider_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class Boto3Stub(ModuleType):
        def client(self, service_name: str) -> FakeCognito:
            assert service_name == "cognito-idp"
            raise RuntimeError("sensitive response data")

    monkeypatch.setitem(sys.modules, "boto3", Boto3Stub("boto3"))
    with pytest.raises(RuntimeError, match=re.escape("Google federation configuration failed")):
        provider.handler(
            {
                "RequestType": "Create",
                "ResourceProperties": {
                    "PoolId": POOL_ID,
                    "ClientId": CLIENT_ID,
                    "TriggerArn": TRIGGER_ARN,
                },
            }
        )
