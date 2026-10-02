"""Credential-safe AWS operations for FeedNow environments."""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import subprocess
from getpass import getpass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import boto3
from botocore.exceptions import ClientError

ENVIRONMENTS = {"dev", "staging", "prod"}
ENV_FILE_KEYS = frozenset(
    {
        "FEEDNOW_ENV",
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "ACCOUNT_BASE_URL",
        "ACCOUNT_ORIGIN",
        "VISPECTOR_BASE_URL",
        "FEEDNOW_VISPECTOR_URL",
        "ACCOUNT_DOMAIN_NAME",
        "ACM_CERTIFICATE_ARN",
        "ROUTE53_HOSTED_ZONE_ID",
        "FEEDNOW_COGNITO_CALLBACK_URLS",
        "FEEDNOW_COGNITO_DOMAIN",
        "FEEDNOW_COGNITO_USER_POOL_ID",
        "FEEDNOW_COGNITO_CLIENT_ID",
        "FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64",
        "FEEDNOW_PEPPER_CIPHERTEXT_B64",
    }
)


def load_settings(root: Path, environment: str) -> dict[str, str]:
    path = root / "deploy" / "aws" / "cdk" / f".env.{environment}"
    if not path.is_file():
        raise SystemExit(f"Missing environment configuration: {path}")
    settings: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key.replace("_", "").isalnum() or not key.isupper():
            raise SystemExit(f"Invalid environment configuration in {path}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key in {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
        }:
            raise SystemExit(f"{key} must not be stored in {path}")
        if key not in ENV_FILE_KEYS:
            raise SystemExit(f"Unsupported or sensitive setting {key} in {path}")
        settings[key] = value
    if settings.get("FEEDNOW_ENV") != environment:
        raise SystemExit(f"FEEDNOW_ENV in {path} must equal {environment}")
    account = settings.get("AWS_ACCOUNT_ID", "")
    if not account.isdigit() or len(account) != 12:
        raise SystemExit(f"AWS_ACCOUNT_ID in {path} must be a 12-digit account ID")
    if not settings.get("AWS_REGION"):
        raise SystemExit(f"AWS_REGION is required in {path}")
    return settings


def aws_session(profile: str, settings: dict[str, str]) -> boto3.Session:
    """Use AWS CLI's credential chain, including login-provider profiles.

    Botocore's login provider requires the optional awscrt dependency. The AWS
    CLI already supports this profile type, so export its short-lived
    credentials in process and pass them directly to boto3 without persisting
    or printing them.
    """
    try:
        exported = subprocess.run(
            ["aws", "configure", "export-credentials", "--profile", profile, "--format", "process"],
            check=True,
            capture_output=True,
            text=True,
        )
        credentials = json.loads(exported.stdout)
        access_key = credentials["AccessKeyId"]
        secret_key = credentials["SecretAccessKey"]
        if not isinstance(access_key, str) or not isinstance(secret_key, str):
            raise ValueError("credential fields must be strings")
        token = credentials.get("SessionToken")
        if token is not None and not isinstance(token, str):
            raise ValueError("session token must be a string")
    except (FileNotFoundError, subprocess.CalledProcessError, KeyError, TypeError, ValueError):
        raise SystemExit(
            f"Could not obtain credentials from AWS CLI profile {profile}; "
            "verify `aws configure export-credentials --profile <profile> --format process` works"
        ) from None
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=token,
        region_name=settings["AWS_REGION"],
    )
    identity = session.client("sts").get_caller_identity()
    actual = identity.get("Account", "")
    if actual != settings["AWS_ACCOUNT_ID"]:
        raise SystemExit(
            f"AWS account mismatch for profile {profile}: expected {settings['AWS_ACCOUNT_ID']}, "
            f"received {actual}"
        )
    return session


def _save_ciphertext(
    root: Path,
    environment: str,
    ciphertext_b64: str,
    setting: str = "FEEDNOW_PEPPER_CIPHERTEXT_B64",
) -> None:
    """Persist only KMS ciphertext in the ignored environment file."""
    path = root / "deploy" / "aws" / "cdk" / f".env.{environment}"
    lines = path.read_text().splitlines()
    entry = f"{setting}={ciphertext_b64}"
    replaced = False
    for index, line in enumerate(lines):
        if line.partition("=")[0].strip() == setting:
            lines[index] = entry
            replaced = True
    if not replaced:
        lines.append(entry)
    path.write_text("\n".join(lines) + "\n")


def ensure_cognito_client_secret_ciphertext(
    session: boto3.Session, root: Path, environment: str
) -> bool:
    """Encrypt an existing app-client secret for Lambda without exposing it."""
    settings = load_settings(root, environment)
    setting = "FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64"
    if settings.get(setting):
        return False
    pool_id = stack_output(session, environment, "CognitoUserPoolId")
    client_id = stack_output(session, environment, "CognitoClientId")
    try:
        client = session.client("cognito-idp")
        user_pool_client = client.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id
        )["UserPoolClient"]
    except Exception:
        raise SystemExit("Could not inspect the existing Cognito app client") from None
    client_secret = user_pool_client.get("ClientSecret")
    if not isinstance(client_secret, str) or not client_secret:
        print("Existing Cognito app client has no client secret; no ciphertext is needed.")
        return False
    key_arn = stack_output(session, environment, "PepperKmsKeyArn")
    try:
        encrypted = session.client("kms").encrypt(
            KeyId=key_arn,
            Plaintext=client_secret.encode("utf-8"),
            EncryptionContext={"environment": environment},
        )
        ciphertext = base64.b64encode(encrypted["CiphertextBlob"]).decode("ascii")
    except Exception:
        raise SystemExit(
            "Could not encrypt Cognito app-client secret with the environment KMS key"
        ) from None
    _save_ciphertext(root, environment, ciphertext, setting)
    print("KMS-encrypted Cognito app-client secret saved to ignored environment config")
    return True


def recover_pepper_ciphertext(session: boto3.Session, root: Path, environment: str) -> bool:
    """Restore ciphertext from the deployed Lambda into local ignored config."""
    settings = load_settings(root, environment)
    if settings.get("FEEDNOW_PEPPER_CIPHERTEXT_B64"):
        return True
    try:
        response = session.client("lambda").get_function_configuration(
            FunctionName=f"feednow-auth-{environment}"
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise SystemExit("Could not inspect deployed Lambda configuration") from None
    ciphertext = response.get("Environment", {}).get("Variables", {}).get(
        "FEEDNOW_PEPPER_CIPHERTEXT_B64", ""
    )
    if not ciphertext:
        return False
    try:
        base64.b64decode(ciphertext, validate=True)
    except ValueError:
        raise SystemExit("Deployed API-key pepper ciphertext is malformed") from None
    _save_ciphertext(root, environment, ciphertext)
    print("Recovered KMS-encrypted API-key pepper ciphertext into ignored environment config")
    return True


def ensure_pepper_ciphertext(session: boto3.Session, root: Path, environment: str) -> None:
    """Encrypt the pepper with the stack key and persist only ciphertext locally."""
    settings = load_settings(root, environment)
    if settings.get("FEEDNOW_PEPPER_CIPHERTEXT_B64"):
        return
    if recover_pepper_ciphertext(session, root, environment):
        return
    key_arn = stack_output(session, environment, "PepperKmsKeyArn")
    if environment == "dev":
        # Preserve API-key validity while migrating from the legacy source.
        try:
            legacy = session.client("secretsmanager").get_secret_value(
                SecretId=f"feednow-auth/{environment}/api-pepper"
            )
            payload = json.loads(legacy.get("SecretString", ""))
            value = payload.get("pepper") if isinstance(payload, dict) else None
        except Exception:
            raise SystemExit(
                "Existing development pepper could not be read; no new pepper was created"
            ) from None
        if not isinstance(value, str) or len(value.encode("utf-8")) < 32:
            raise SystemExit("Existing development pepper has an invalid shape")
    else:
        value = secrets.token_urlsafe(48)
    try:
        encrypted = session.client("kms").encrypt(
            KeyId=key_arn,
            Plaintext=value.encode("utf-8"),
            EncryptionContext={"environment": environment},
        )
        ciphertext = base64.b64encode(encrypted["CiphertextBlob"]).decode("ascii")
    except Exception:
        raise SystemExit("Could not encrypt API-key pepper with the environment KMS key") from None
    _save_ciphertext(root, environment, ciphertext)
    print("KMS-encrypted API-key pepper ciphertext saved to ignored environment config")
    if environment == "dev":
        print("Keep the legacy value until existing API keys pass verification.")


def stack_output(session: boto3.Session, environment: str, key: str) -> str:
    response = session.client("cloudformation").describe_stacks(
        StackName=f"FeedNowAuth-{environment}"
    )
    outputs = response["Stacks"][0].get("Outputs", [])
    value = next((output["OutputValue"] for output in outputs if output["OutputKey"] == key), "")
    if not value:
        raise SystemExit(f"Stack output {key} is missing")
    return value


def ensure_google_client(
    session: boto3.Session,
    pool_id: str,
    client_id: str,
    *,
    callback_urls: list[str],
    logout_urls: list[str],
) -> None:
    client = session.client("cognito-idp")
    try:
        current = client.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
            "UserPoolClient"
        ]
        providers = current.get("SupportedIdentityProviders", [])
        fields = (
            "AccessTokenValidity", "AllowedOAuthFlows", "AllowedOAuthScopes",
            "AllowedOAuthFlowsUserPoolClient", "AnalyticsConfiguration", "AuthSessionValidity",
            "CallbackURLs", "ClientName", "DefaultRedirectURI",
            "EnablePropagateAdditionalUserContextData",
            "EnableTokenRevocation", "ExplicitAuthFlows", "IdTokenValidity", "LogoutURLs",
            "PreventUserExistenceErrors", "ReadAttributes", "RefreshTokenRotation",
            "RefreshTokenValidity", "SupportedIdentityProviders", "TokenValidityUnits",
            "WriteAttributes",
        )
        request = {key: current[key] for key in fields if key in current}
        request["UserPoolId"] = pool_id
        request["ClientId"] = client_id
        request["AllowedOAuthFlows"] = list(
            dict.fromkeys([*(current.get("AllowedOAuthFlows") or []), "code"])
        )
        request["AllowedOAuthFlowsUserPoolClient"] = True
        request["AllowedOAuthScopes"] = list(
            dict.fromkeys(
                [*(current.get("AllowedOAuthScopes") or []), "openid", "email", "profile"]
            )
        )
        request["SupportedIdentityProviders"] = sorted(set(providers) | {"Google"})
        request["CallbackURLs"] = list(
            dict.fromkeys([*(current.get("CallbackURLs") or []), *callback_urls])
        )
        request["LogoutURLs"] = list(
            dict.fromkeys([*(current.get("LogoutURLs") or []), *logout_urls])
        )
        prior_write_attributes = current.get("WriteAttributes")
        if isinstance(prior_write_attributes, list):
            request["WriteAttributes"] = sorted(
                set(prior_write_attributes) | {"email", "custom:g_verified"}
            )
        if (
            request["SupportedIdentityProviders"] == providers
            and request["AllowedOAuthFlows"] == current.get("AllowedOAuthFlows", [])
            and request["AllowedOAuthFlowsUserPoolClient"]
            == current.get("AllowedOAuthFlowsUserPoolClient", False)
            and request["AllowedOAuthScopes"] == current.get("AllowedOAuthScopes", [])
            and request["CallbackURLs"] == current.get("CallbackURLs", [])
            and request["LogoutURLs"] == current.get("LogoutURLs", [])
            and request.get("WriteAttributes") == current.get("WriteAttributes")
        ):
            return
        client.update_user_pool_client(**request)
    except ClientError as exc:
        raise SystemExit(
            _google_client_error("enabling Google on the Cognito app client", exc)
        ) from None
    except Exception:
        raise SystemExit("Google provider could not be enabled on the Cognito app client") from None


def _oauth_redirect_settings(settings: dict[str, str]) -> tuple[list[str], list[str]]:
    environment = settings["FEEDNOW_ENV"]
    origin = (settings.get("ACCOUNT_ORIGIN") or settings.get("ACCOUNT_BASE_URL") or "").rstrip("/")
    parsed_origin = urlsplit(origin)
    local_dev = (
        environment == "dev"
        and parsed_origin.scheme == "http"
        and parsed_origin.hostname in {"localhost", "127.0.0.1", "::1", "[::1]"}
    )
    if (
        not parsed_origin.netloc
        or parsed_origin.path
        or parsed_origin.query
        or parsed_origin.fragment
        or (parsed_origin.scheme != "https" and not local_dev)
    ):
        raise SystemExit(
            "ACCOUNT_BASE_URL must be an HTTPS origin (dev may use localhost HTTP)"
        )

    configured_callbacks = settings.get("FEEDNOW_COGNITO_CALLBACK_URLS", "")
    callbacks = [item.strip() for item in configured_callbacks.split(",") if item.strip()]
    if not callbacks:
        callbacks = [f"{origin}/api/oauth/callback"]
    for callback in callbacks:
        parsed = urlsplit(callback)
        local_callback = (
            environment == "dev"
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1", "[::1]"}
        )
        if not parsed.netloc or (parsed.scheme != "https" and not local_callback):
            raise SystemExit(
                "FEEDNOW_COGNITO_CALLBACK_URLS entries must be HTTPS "
                "(dev may use localhost HTTP)"
            )
    return callbacks, [f"{origin}/login"]


def _cognito_domain(settings: dict[str, str], region: str) -> str:
    """Return the configured existing Cognito domain, or its legacy default."""
    domain = settings.get("FEEDNOW_COGNITO_DOMAIN", "").strip().rstrip("/")
    if not domain:
        return f"https://feednow-auth-{settings['FEEDNOW_ENV']}.auth.{region}.amazoncognito.com"
    parsed = urlsplit(domain)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise SystemExit("FEEDNOW_COGNITO_DOMAIN must be an HTTPS origin")
    return domain


def ensure_oauth_redirects(
    session: boto3.Session, environment: str, settings: dict[str, str]
) -> None:
    """Add this environment's OAuth callback/logout URLs to its existing app client."""
    pool_id = stack_output(session, environment, "CognitoUserPoolId")
    client_id = stack_output(session, environment, "CognitoClientId")
    callback_urls, logout_urls = _oauth_redirect_settings(settings)
    client = session.client("cognito-idp")
    try:
        current = client.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
            "UserPoolClient"
        ]
        fields = (
            "AccessTokenValidity", "AllowedOAuthFlows", "AllowedOAuthScopes",
            "AllowedOAuthFlowsUserPoolClient", "AnalyticsConfiguration", "AuthSessionValidity",
            "CallbackURLs", "ClientName", "DefaultRedirectURI",
            "EnablePropagateAdditionalUserContextData",
            "EnableTokenRevocation", "ExplicitAuthFlows", "IdTokenValidity", "LogoutURLs",
            "PreventUserExistenceErrors", "ReadAttributes", "RefreshTokenRotation",
            "RefreshTokenValidity", "SupportedIdentityProviders", "TokenValidityUnits",
            "WriteAttributes",
        )
        request = {key: current[key] for key in fields if key in current}
        request["UserPoolId"] = pool_id
        request["ClientId"] = client_id
        request["AllowedOAuthFlows"] = list(
            dict.fromkeys([*(current.get("AllowedOAuthFlows") or []), "code"])
        )
        request["AllowedOAuthFlowsUserPoolClient"] = True
        request["AllowedOAuthScopes"] = list(
            dict.fromkeys(
                [*(current.get("AllowedOAuthScopes") or []), "openid", "email", "profile"]
            )
        )
        request["CallbackURLs"] = list(
            dict.fromkeys([*(current.get("CallbackURLs") or []), *callback_urls])
        )
        request["LogoutURLs"] = list(
            dict.fromkeys([*(current.get("LogoutURLs") or []), *logout_urls])
        )
        if (
            request["AllowedOAuthFlows"] != current.get("AllowedOAuthFlows", [])
            or request["AllowedOAuthFlowsUserPoolClient"]
            != current.get("AllowedOAuthFlowsUserPoolClient", False)
            or request["AllowedOAuthScopes"] != current.get("AllowedOAuthScopes", [])
            or request["CallbackURLs"] != current.get("CallbackURLs", [])
            or request["LogoutURLs"] != current.get("LogoutURLs", [])
        ):
            client.update_user_pool_client(**request)
    except ClientError as exc:
        raise SystemExit(
            _google_client_error("configuring app-client redirects", exc)
        ) from None
    except Exception:
        raise SystemExit(
            "Could not configure redirects on the existing Cognito app client"
        ) from None
    print(f"OAuth app-client settings configured for {environment} Cognito client {client_id}.")


def rotate_google_credentials(session: boto3.Session, environment: str) -> None:
    pool_id = stack_output(session, environment, "CognitoUserPoolId")
    client = session.client("cognito-idp")
    try:
        provider = client.describe_identity_provider(UserPoolId=pool_id, ProviderName="Google")[
            "IdentityProvider"
        ]
    except Exception:
        raise SystemExit("Cognito Google provider lookup failed") from None
    details = dict(provider.get("ProviderDetails", {}))
    if not details.get("client_id"):
        raise SystemExit("Google provider has no client ID; configure the provider before rotation")
    secret = getpass("New Google OAuth client secret: ")
    if not secret:
        raise SystemExit("Google OAuth client secret cannot be empty")
    details["client_secret"] = secret
    request: dict[str, Any] = {
        "UserPoolId": pool_id,
        "ProviderName": "Google",
        "ProviderDetails": details,
    }
    if provider.get("AttributeMapping"):
        request["AttributeMapping"] = provider["AttributeMapping"]
    if provider.get("IdpIdentifiers"):
        request["IdpIdentifiers"] = provider["IdpIdentifiers"]
    try:
        client.update_identity_provider(**request)
    except Exception:
        raise SystemExit("Google OAuth credentials could not be updated") from None
    print(f"Google OAuth credentials updated for {environment} Cognito pool {pool_id}.")


def configure_google(
    session: boto3.Session, environment: str, settings: dict[str, str]
) -> None:
    pool_id = stack_output(session, environment, "CognitoUserPoolId")
    client_id = stack_output(session, environment, "CognitoClientId")
    region = str(session.region_name or "")
    print(
        "Google Console authorized redirect URI: "
        f"{_cognito_domain(settings, region)}/oauth2/idpresponse"
    )
    oauth_client_id = input("Google OAuth client ID: ").strip()
    oauth_secret = getpass("Google OAuth client secret: ")
    if not oauth_client_id or not oauth_secret:
        raise SystemExit("Google OAuth client ID and secret are required")
    callback_urls, logout_urls = _oauth_redirect_settings(settings)
    client = session.client("cognito-idp")
    try:
        pool = client.describe_user_pool(UserPoolId=pool_id)["UserPool"]
        schema = pool.get("Schema") or []
        verified_attribute = next(
            (
                attribute
                for attribute in schema
                if str(attribute.get("Name", "")).removeprefix("custom:") == "g_verified"
            ),
            None,
        )
        if verified_attribute is None:
            try:
                client.add_custom_attributes(
                    UserPoolId=pool_id,
                    CustomAttributes=[
                        {
                            "Name": "g_verified",
                            "AttributeDataType": "String",
                            "Mutable": True,
                            "StringAttributeConstraints": {
                                "MinLength": "4",
                                "MaxLength": "5",
                            },
                        }
                    ],
                )
            except ClientError as exc:
                details = exc.response.get("Error", {})
                message = str(details.get("Message", "")).lower()
                if not (
                    details.get("Code") == "InvalidParameterException"
                    and "attribute name is not unique" in message
                    and "g_verified" in message
                ):
                    raise
        elif (
            verified_attribute.get("AttributeDataType") != "String"
            or verified_attribute.get("Mutable") is not True
        ):
            raise SystemExit(
                "Existing Cognito custom:g_verified attribute must be a mutable string"
            )
    except SystemExit:
        raise
    except ClientError as exc:
        raise SystemExit(
            _google_client_error("preparing the existing user pool", exc, oauth_secret)
        ) from None
    except Exception:
        raise SystemExit(
            "Google configuration could not inspect the existing Cognito pool"
        ) from None
    try:
        existing = client.describe_identity_provider(UserPoolId=pool_id, ProviderName="Google")[
            "IdentityProvider"
        ]
        client.update_identity_provider(
            UserPoolId=pool_id,
            ProviderName="Google",
            ProviderDetails={
                **existing.get("ProviderDetails", {}),
                "client_id": oauth_client_id,
                "client_secret": oauth_secret,
                "authorize_scopes": "openid email profile",
            },
            AttributeMapping={
                "email": "email",
                "custom:g_verified": "email_verified",
                "username": "sub",
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise SystemExit(
                _google_client_error("updating the existing IdP", exc, oauth_secret)
            ) from None
        try:
            client.create_identity_provider(
                UserPoolId=pool_id,
                ProviderName="Google",
                ProviderType="Google",
                ProviderDetails={
                    "client_id": oauth_client_id,
                    "client_secret": oauth_secret,
                    "authorize_scopes": "openid email profile",
                },
                AttributeMapping={
                    "email": "email",
                    "custom:g_verified": "email_verified",
                    "username": "sub",
                },
            )
        except ClientError as exc:
            raise SystemExit(
                _google_client_error("creating the IdP on the existing pool", exc, oauth_secret)
            ) from None
        except Exception:
            raise SystemExit(
                "Google identity provider could not be configured (unexpected error)"
            ) from None
    except Exception:
        raise SystemExit(
            "Google identity provider could not be configured (unexpected error)"
        ) from None
    ensure_google_client(
        session,
        pool_id,
        client_id,
        callback_urls=callback_urls,
        logout_urls=logout_urls,
    )
    print(
        f"Google federation configured for {environment} Cognito pool {pool_id} "
        f"and client {client_id}."
    )


def _google_client_error(action: str, exc: ClientError, *sensitive_values: str) -> str:
    """Show the Cognito error code/message without echoing submitted credentials."""
    details = exc.response.get("Error", {})
    code = str(details.get("Code", "Unknown"))
    message = str(details.get("Message", "No error message returned"))
    for value in sensitive_values:
        if value:
            message = message.replace(value, "[REDACTED]")
    return f"Google configuration failed while {action} ({code}): {message}"


def ensure_google(
    session: boto3.Session,
    environment: str,
    settings: dict[str, str],
    *,
    reset: bool = False,
) -> None:
    if reset:
        configure_google(session, environment, settings)
        return
    pool_id = stack_output(session, environment, "CognitoUserPoolId")
    client_id = stack_output(session, environment, "CognitoClientId")
    callback_urls, logout_urls = _oauth_redirect_settings(settings)
    client = session.client("cognito-idp")
    try:
        client.describe_identity_provider(UserPoolId=pool_id, ProviderName="Google")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise SystemExit("Could not verify the Google identity provider") from None
        configure_google(session, environment, settings)
        return
    except Exception:
        raise SystemExit("Could not verify the Google identity provider") from None
    ensure_google_client(
        session,
        pool_id,
        client_id,
        callback_urls=callback_urls,
        logout_urls=logout_urls,
    )
    print(f"Google federation is already configured for {environment} Cognito pool {pool_id}.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="Standard AWS CLI profile")
    parser.add_argument("--env", required=True, choices=sorted(ENVIRONMENTS))
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Restart Google provider configuration (ensure-google only)",
    )
    parser.add_argument(
        "command",
        choices=(
            "recover-pepper-ciphertext",
            "ensure-pepper-ciphertext",
            "ensure-cognito-client-secret-ciphertext",
            "ensure-google",
            "ensure-oauth-redirects",
            "configure-google",
            "rotate-google-credentials",
        ),
    )
    args = parser.parse_args()
    if args.reset and args.command != "ensure-google":
        parser.error("--reset is only valid with ensure-google")
    root = Path(__file__).resolve().parents[2]
    settings = load_settings(root, args.env)
    session = aws_session(args.profile, settings)
    if args.command == "recover-pepper-ciphertext":
        if not recover_pepper_ciphertext(session, root, args.env):
            raise SystemExit(3)
    elif args.command == "ensure-pepper-ciphertext":
        ensure_pepper_ciphertext(session, root, args.env)
    elif args.command == "ensure-cognito-client-secret-ciphertext":
        ensure_cognito_client_secret_ciphertext(session, root, args.env)
    elif args.command == "configure-google":
        configure_google(session, args.env, settings)
    elif args.command == "ensure-google":
        ensure_google(session, args.env, settings, reset=args.reset)
    elif args.command == "ensure-oauth-redirects":
        ensure_oauth_redirects(session, args.env, settings)
    else:
        rotate_google_credentials(session, args.env)


if __name__ == "__main__":
    main()
