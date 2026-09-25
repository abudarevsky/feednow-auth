"""Safely attach the Google verification flow to a pre-existing Cognito pool.

The provider preserves every UpdateUserPool/UpdateUserPoolClient field
returned by Describe*, changes only the trigger, client attribute permissions,
custom proof attribute, and Google attribute mapping, and never logs response
data (which can contain identity-provider credentials).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

_POOL_UPDATE_FIELDS = frozenset(
    {
        "AccountRecoverySetting",
        "AdminCreateUserConfig",
        "AutoVerifiedAttributes",
        "DeletionProtection",
        "DeviceConfiguration",
        "EmailConfiguration",
        "EmailVerificationMessage",
        "EmailVerificationSubject",
        "IssuerConfiguration",
        "KeyConfiguration",
        "LambdaConfig",
        "MfaConfiguration",
        "Policies",
        "PoolName",
        "SmsAuthenticationMessage",
        "SmsConfiguration",
        "SmsVerificationMessage",
        "UserAttributeUpdateSettings",
        "UserPoolAddOns",
        "UserPoolTags",
        "UserPoolTier",
        "VerificationMessageTemplate",
    }
)
_CLIENT_UPDATE_FIELDS = frozenset(
    {
        "AccessTokenValidity",
        "AllowedOAuthFlows",
        "AllowedOAuthFlowsUserPoolClient",
        "AllowedOAuthScopes",
        "AnalyticsConfiguration",
        "AuthSessionValidity",
        "CallbackURLs",
        "ClientName",
        "DefaultRedirectURI",
        "EnablePropagateAdditionalUserContextData",
        "EnableTokenRevocation",
        "ExplicitAuthFlows",
        "IdTokenValidity",
        "LogoutURLs",
        "PreventUserExistenceErrors",
        "ReadAttributes",
        "RefreshTokenRotation",
        "RefreshTokenValidity",
        "SupportedIdentityProviders",
        "TokenValidityUnits",
        "WriteAttributes",
    }
)
_CUSTOM_ATTRIBUTE = {
    "Name": "g_verified",
    "AttributeDataType": "String",
    "Mutable": True,
    "StringAttributeConstraints": {"MinLength": "4", "MaxLength": "5"},
}
_GOOGLE_MAPPING = {
    "email": "email",
    "custom:g_verified": "email_verified",
    "username": "sub",
}
_STANDARD_MAPPING = {
    "email": "email",
    "email_verified": "email_verified",
    "username": "sub",
}


class _SafeStepError(RuntimeError):
    """Sanitized stage and AWS error code, safe for CloudFormation events."""

    def __init__(self, stage: str, error_code: str = "Unknown") -> None:
        safe_code = error_code if error_code.replace("_", "").isalnum() else "Unknown"
        super().__init__(f"Google federation step failed: {stage} ({safe_code})")


def _step(stage: str, action: Callable[[], Any]) -> Any:
    try:
        return action()
    except Exception as error:
        response = getattr(error, "response", None)
        details = response.get("Error", {}) if isinstance(response, Mapping) else {}
        code = details.get("Code", "Unknown") if isinstance(details, Mapping) else "Unknown"
        raise _SafeStepError(stage, str(code)) from None


def _required(properties: Mapping[str, Any], key: str) -> str:
    value = properties.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError("federation custom resource properties are invalid")
    return value


def _ensure_custom_attribute(client: Any, pool_id: str) -> None:
    pool = client.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    schema = pool.get("Schema") or []
    existing = next(
        (
            attribute
            for attribute in schema
            if str(attribute.get("Name", "")).removeprefix("custom:") == "g_verified"
        ),
        None,
    )
    if existing is not None:
        if existing.get("AttributeDataType") != "String" or existing.get("Mutable") is not True:
            raise ValueError("existing Google verification attribute has incompatible settings")
        return
    client.add_custom_attributes(UserPoolId=pool_id, CustomAttributes=[dict(_CUSTOM_ATTRIBUTE)])


def _update_client(client: Any, pool_id: str, client_id: str) -> None:
    current = client.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    parameters = {
        key: current[key]
        for key in _CLIENT_UPDATE_FIELDS
        if key in current and current[key] is not None
    }
    parameters["UserPoolId"] = pool_id
    parameters["ClientId"] = client_id
    # Cognito requires a client write grant for every mapped destination.
    # Keep the app's existing writable attributes and add only this evidence
    # field; when permissions were at the broad default, use the app's
    # current profile contract (email only) rather than retaining broad writes.
    prior_write = current.get("WriteAttributes")
    parameters["WriteAttributes"] = sorted(
        set(prior_write if isinstance(prior_write, list) else ["email"])
        | {"email", "custom:g_verified"}
    )
    # Preserve a custom read allowlist when present. The default Cognito read
    # policy already exposes the standard email and email_verified claims.
    client.update_user_pool_client(**parameters)


def _update_pool(client: Any, pool_id: str, trigger_arn: str, *, detach: bool) -> None:
    current = client.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    lambda_config = dict(current.get("LambdaConfig") or {})
    if detach:
        for key in ("PreSignUp", "PreAuthentication"):
            if lambda_config.get(key) == trigger_arn:
                lambda_config.pop(key)
    else:
        lambda_config["PreSignUp"] = trigger_arn
        lambda_config["PreAuthentication"] = trigger_arn

    parameters = {
        key: current[key]
        for key in _POOL_UPDATE_FIELDS
        if key in current and current[key] is not None
    }
    parameters["UserPoolId"] = pool_id
    parameters["LambdaConfig"] = lambda_config
    client.update_user_pool(**parameters)


def _configure(client: Any, properties: Mapping[str, Any]) -> None:
    pool_id = _required(properties, "PoolId")
    client_id = _required(properties, "ClientId")
    trigger_arn = _required(properties, "TriggerArn")
    _step("custom-attribute", lambda: _ensure_custom_attribute(client, pool_id))
    _step("app-client", lambda: _update_client(client, pool_id, client_id))
    _step(
        "google-mapping",
        lambda: client.update_identity_provider(
            UserPoolId=pool_id,
            ProviderName="Google",
            AttributeMapping=dict(_GOOGLE_MAPPING),
        ),
    )
    _step("user-pool-triggers", lambda: _update_pool(client, pool_id, trigger_arn, detach=False))


def _detach(client: Any, properties: Mapping[str, Any]) -> None:
    pool_id = _required(properties, "PoolId")
    trigger_arn = _required(properties, "TriggerArn")
    # Leave the dedicated mapping, client grant, and custom schema in place:
    # custom Cognito attributes cannot be removed. Existing verified users
    # remain verified; without the trigger, new Google sign-ins fail closed.
    _update_pool(client, pool_id, trigger_arn, detach=True)


def handler(event: Mapping[str, Any], context: object = None) -> dict[str, Any]:
    """CloudFormation custom-resource entry point; emits no user/secret data."""
    del context
    try:
        request_type = event.get("RequestType")
        properties = event.get("ResourceProperties")
        if request_type not in {"Create", "Update", "Delete"} or not isinstance(
            properties, Mapping
        ):
            raise ValueError("custom resource event is invalid")
        import boto3

        cognito = boto3.client("cognito-idp")
        if request_type == "Delete":
            _detach(cognito, properties)
        else:
            _configure(cognito, properties)
        return {
            "PhysicalResourceId": f"google-email-proof:{_required(properties, 'PoolId')}",
            "Data": {"configured": "true"},
        }
    except _SafeStepError:
        raise
    except Exception:
        # CloudFormation may log provider errors; do not pass through SDK
        # responses that can contain user-pool or IdP details.
        raise RuntimeError("Google federation configuration failed") from None
