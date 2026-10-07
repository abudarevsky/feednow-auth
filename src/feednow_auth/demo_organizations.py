"""Operator lifecycle for one Cognito login per demo organization."""

from __future__ import annotations

import re
import secrets
import string
import uuid
from typing import Any

from app.models.audit_event import AuditEvent
from app.models.enums import (
    ApplicationRole,
    IdentityProvider,
    MembershipRole,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity
from app.models.ids import OrganizationId
from app.models.organization import Organization
from app.models.organization_onboarding import OrganizationOnboardingRequest
from app.models.pagination import PageParams
from app.models.timestamps import utc_now
from app.models.user import User
from app.services.idgen import new_audit_event_id, new_external_identity_id, new_user_id
from app.services.organization import (
    build_organization_batch,
    new_organization_creation_ids,
    organization_slug_from_name,
)
from app.storage.contract import EntityNotFoundError
from app.storage.local_admin import LocalAdminStorage

_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DEMO_METADATA = {"feednow_demo_provisioning": "true"}
_DEMO_EMAIL_DOMAIN = "demo.feednow.io"
_SYMBOLS = "!@#$%^&*()-_=+[]{}.,?"


class DemoProvisioningError(Exception):
    """A safe operator-facing demo provisioning/configuration failure."""


def validate_demo_slug(slug: str) -> str:
    value = slug.strip()
    if not _SLUG_RE.fullmatch(value):
        raise DemoProvisioningError(
            "slug must be 1-63 lowercase letters, numbers, or hyphens and "
            "cannot start or end with a hyphen"
        )
    return value


def _demo_login_identifier(slug: str, *, email_sign_in: bool) -> str:
    """Return the pool's login identifier without requiring a real mailbox."""
    return f"{slug}@{_DEMO_EMAIL_DOMAIN}" if email_sign_in else slug


def _pool_configuration(
    client: Any, pool_id: str, client_id: str
) -> tuple[dict[str, Any], bool, bool]:
    try:
        pool = client.describe_user_pool(UserPoolId=pool_id)["UserPool"]
        app_client = client.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
            "UserPoolClient"
        ]
    except Exception as exc:
        raise DemoProvisioningError(
            "could not inspect Cognito pool configuration; verify the pool and app-client settings"
        ) from exc
    username_attributes = pool.get("UsernameAttributes") or []
    email_sign_in = "email" in username_attributes
    if username_attributes and not email_sign_in:
        raise DemoProvisioningError(
            "managed demos require Cognito username or email sign-in; "
            "this pool only supports phone-number sign-in"
        )
    required_email = any(
        item.get("Name") == "email" and item.get("Required") is True
        for item in pool.get("SchemaAttributes", [])
    )
    required_unprovided = {
        item.get("Name")
        for item in pool.get("SchemaAttributes", [])
        if item.get("Required") is True
    } - {"email", "name", "sub"}
    if required_unprovided:
        raise DemoProvisioningError(
            "Cognito has required profile attributes incompatible with managed demo identities"
        )
    factors = pool.get("Policies", {}).get("SignInPolicy", {}).get("AllowedFirstAuthFactors")
    if factors and "PASSWORD" not in factors:
        raise DemoProvisioningError("Cognito pool does not permit username/password authentication")
    if not app_client.get("AllowedOAuthFlowsUserPoolClient") or "code" not in app_client.get(
        "AllowedOAuthFlows", []
    ):
        raise DemoProvisioningError(
            "the configured Cognito app client must retain its authorization-code login flow"
        )
    return pool.get("Policies", {}).get("PasswordPolicy", {}), email_sign_in, required_email


def _generate_password(policy: dict[str, Any]) -> str:
    minimum = max(16, int(policy.get("MinimumLength", 8)))
    if minimum > 256:
        raise DemoProvisioningError("Cognito password policy exceeds the supported password length")
    groups: list[str] = []
    if policy.get("RequireLowercase"):
        groups.append(string.ascii_lowercase)
    if policy.get("RequireUppercase"):
        groups.append(string.ascii_uppercase)
    if policy.get("RequireNumbers"):
        groups.append(string.digits)
    if policy.get("RequireSymbols"):
        groups.append(_SYMBOLS)
    alphabet = string.ascii_letters + string.digits + _SYMBOLS
    values = [secrets.choice(group) for group in groups]
    values.extend(secrets.choice(alphabet) for _ in range(max(32, minimum) - len(values)))
    secrets.SystemRandom().shuffle(values)
    return "".join(values)


def _cognito_client(region: str) -> Any:
    import boto3

    return boto3.client("cognito-idp", region_name=region)


def _pool_ids() -> tuple[str, str, str]:
    import os

    pool_id = os.environ.get("FEEDNOW_COGNITO_USER_POOL_ID", "").strip()
    client_id = os.environ.get("FEEDNOW_COGNITO_CLIENT_ID", "").strip()
    region = os.environ.get("AWS_REGION", "").strip()
    if not pool_id or not client_id or not region:
        raise DemoProvisioningError(
            "Cognito pool, client, and region configuration are required; use --profile and --env"
        )
    return pool_id, client_id, region


def create_demo_organization(
    storage: LocalAdminStorage,
    *,
    name: str,
    slug: str | None,
) -> tuple[Organization, str, str]:
    display_name = name.strip()
    if not display_name or len(display_name) > 255:
        raise DemoProvisioningError("organization name must contain 1-255 characters")
    demo_slug = validate_demo_slug(
        slug if slug is not None else organization_slug_from_name(display_name)
    )
    if not storage.is_organization_slug_available(demo_slug):
        raise DemoProvisioningError("organization slug is already in use")
    if any(user.username == demo_slug for user in storage.list_users()):
        raise DemoProvisioningError("a FeedNow user already uses this username")

    pool_id, client_id, region = _pool_ids()
    cognito = _cognito_client(region)
    policy, email_sign_in, required_email = _pool_configuration(cognito, pool_id, client_id)
    login_identifier = _demo_login_identifier(demo_slug, email_sign_in=email_sign_in)
    cognito_attributes = [{"Name": "name", "Value": display_name}]
    if email_sign_in or required_email:
        synthetic_email = f"{demo_slug}@{_DEMO_EMAIL_DOMAIN}"
        cognito_attributes.extend(
            [
                {"Name": "email", "Value": synthetic_email},
                {"Name": "email_verified", "Value": "true"},
            ]
        )
    try:
        cognito.admin_get_user(UserPoolId=pool_id, Username=login_identifier)
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "UserNotFoundException":
            raise DemoProvisioningError("could not verify Cognito username availability") from exc
    else:
        raise DemoProvisioningError("a Cognito user already uses this username")

    password = _generate_password(policy)
    cognito_created = False
    organization_created = False
    user_id = new_user_id()
    organization_id: OrganizationId | None = None
    try:
        cognito.admin_create_user(
            UserPoolId=pool_id,
            Username=login_identifier,
            TemporaryPassword=password,
            MessageAction="SUPPRESS",
            UserAttributes=cognito_attributes,
            ClientMetadata=_DEMO_METADATA,
        )
        cognito_created = True
        cognito.admin_set_user_password(
            UserPoolId=pool_id,
            Username=login_identifier,
            Password=password,
            Permanent=True,
        )
        cognito_user = cognito.admin_get_user(UserPoolId=pool_id, Username=login_identifier)
        attributes = {
            item["Name"]: item["Value"] for item in cognito_user.get("UserAttributes", [])
        }
        subject = attributes.get("sub")
        if not subject or cognito_user.get("UserStatus") != "CONFIRMED":
            raise DemoProvisioningError("Cognito did not confirm the managed demo user")

        now = utc_now()
        user = User(
            id=user_id,
            display_name=display_name,
            username=login_identifier,
            email=None,
            status=UserStatus.ACTIVE,
            application_role=ApplicationRole.USER,
            created_at=now,
            updated_at=now,
        )
        batch = build_organization_batch(
            creator_user_id=user_id,
            name=display_name,
            slug=demo_slug,
            organization_type=OrganizationType.DEMO,
            now=now,
            ids=new_organization_creation_ids(),
        )
        organization_id = batch.organization.id
        identity = ExternalIdentity(
            id=new_external_identity_id(),
            user_id=user_id,
            provider=IdentityProvider.COGNITO,
            provider_subject=subject,
            provider_tenant=None,
            created_at=now,
        )
        user_created_audit = AuditEvent(
            id=new_audit_event_id(),
            organization_id=organization_id,
            actor_type="user",
            actor_id=user_id,
            action="user.created",
            target_type="user",
            target_id=str(user_id),
            metadata={"provider": "cognito"},
            created_at=now,
        )
        onboarding_request = OrganizationOnboardingRequest(
            request_id=(
                "onb_"
                + uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"feednow-vispector-onboarding:{organization_id}",
                ).hex
            ),
            organization_id=organization_id,
            bootstrap_version="starter-v1",
            created_at=now,
            updated_at=now,
        )
        provisioned = storage.provision_user(
            user=user,
            identity=identity,
            organization=batch.organization,
            membership=batch.membership,
            audit_events=(user_created_audit, *batch.audit_events),
            onboarding_request=onboarding_request,
        )
        organization_created = True
        return provisioned.organization, login_identifier, password
    except Exception as exc:
        cleanup_failures: list[str] = []
        if organization_created and organization_id is not None:
            try:
                storage.admin_delete_organization(organization_id)
            except Exception:
                cleanup_failures.append(f"FeedNow organization {organization_id}")
        if cognito_created:
            try:
                cognito.admin_delete_user(UserPoolId=pool_id, Username=login_identifier)
            except Exception:
                cleanup_failures.append(f"Cognito login {login_identifier}")
        if cleanup_failures:
            raise DemoProvisioningError(
                "demo provisioning failed; cleanup is required for: " + ", ".join(cleanup_failures)
            ) from exc
        if isinstance(exc, DemoProvisioningError):
            raise
        raise DemoProvisioningError(
            "demo provisioning failed; created resources were rolled back"
        ) from exc


def delete_demo_organization(storage: LocalAdminStorage, *, slug: str) -> None:
    username = validate_demo_slug(slug)
    try:
        organization = storage.get_organization_by_slug(username)
    except EntityNotFoundError as exc:
        raise DemoProvisioningError("demo organization was not found") from exc
    if organization.type is not OrganizationType.DEMO:
        raise DemoProvisioningError("refusing to delete an organization that is not type demo")
    memberships = storage.list_memberships(organization.id, PageParams(limit=2)).items
    if len(memberships) != 1 or memberships[0].role is not MembershipRole.OWNER:
        raise DemoProvisioningError(
            "demo organization does not have its single managed owner identity"
        )
    user = storage.get_user(memberships[0].user_id)

    pool_id, client_id, region = _pool_ids()
    cognito = _cognito_client(region)
    _, email_sign_in, _ = _pool_configuration(cognito, pool_id, client_id)
    login_identifier = _demo_login_identifier(username, email_sign_in=email_sign_in)
    if user.username != login_identifier:
        raise DemoProvisioningError(
            "demo organization login does not match its configured Cognito identifier"
        )
    try:
        cognito.admin_delete_user(UserPoolId=pool_id, Username=login_identifier)
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "UserNotFoundException":
            raise DemoProvisioningError(
                "Cognito user could not be deleted; FeedNow organization was retained"
            ) from exc
    try:
        storage.admin_delete_organization(organization.id)
    except Exception as exc:
        raise DemoProvisioningError(
            f"Cognito login {login_identifier} was deleted, but FeedNow organization "
            f"{organization.id} needs cleanup; rerun demo delete"
        ) from exc


def reset_demo_password(storage: LocalAdminStorage, *, slug: str) -> tuple[str, str]:
    """Generate and apply a new permanent Cognito password for a demo owner."""
    demo_slug = validate_demo_slug(slug)
    try:
        organization = storage.get_organization_by_slug(demo_slug)
    except EntityNotFoundError as exc:
        raise DemoProvisioningError("demo organization was not found") from exc
    if organization.type is not OrganizationType.DEMO:
        raise DemoProvisioningError(
            "refusing to reset a login for an organization that is not type demo"
        )
    memberships = storage.list_memberships(organization.id, PageParams(limit=2)).items
    if len(memberships) != 1 or memberships[0].role is not MembershipRole.OWNER:
        raise DemoProvisioningError(
            "demo organization does not have its single managed owner identity"
        )
    user = storage.get_user(memberships[0].user_id)
    if not user.username:
        raise DemoProvisioningError("demo organization owner has no managed login identifier")

    pool_id, client_id, region = _pool_ids()
    cognito = _cognito_client(region)
    policy, _, _ = _pool_configuration(cognito, pool_id, client_id)
    try:
        cognito.admin_get_user(UserPoolId=pool_id, Username=user.username)
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") == "UserNotFoundException":
            raise DemoProvisioningError(
                "Cognito login for this demo organization was not found"
            ) from exc
        raise DemoProvisioningError("could not verify the Cognito demo login") from exc

    password = _generate_password(policy)
    try:
        cognito.admin_set_user_password(
            UserPoolId=pool_id,
            Username=user.username,
            Password=password,
            Permanent=True,
        )
    except Exception as exc:
        raise DemoProvisioningError("Cognito could not reset the demo login password") from exc
    return user.username, password


def list_demo_organizations(storage: LocalAdminStorage) -> list[tuple[str, str, str]]:
    page = storage.admin_search_organizations("", PageParams(limit=100))
    results: list[tuple[str, str, str]] = []
    while True:
        for organization in page.items:
            if organization.type is OrganizationType.DEMO:
                state = "enabled" if organization.enabled else "disabled"
                memberships = storage.list_memberships(organization.id, PageParams(limit=2)).items
                if len(memberships) != 1 or memberships[0].role is not MembershipRole.OWNER:
                    raise DemoProvisioningError(
                        "demo organization does not have its single managed owner identity"
                    )
                user = storage.get_user(memberships[0].user_id)
                if not user.username:
                    raise DemoProvisioningError(
                        "demo organization owner has no managed login identifier"
                    )
                results.append((organization.name, user.username, state))
        if page.next_cursor is None:
            break
        page = storage.admin_search_organizations(
            "", PageParams(limit=100, cursor=page.next_cursor)
        )
    return results


__all__ = [
    "DemoProvisioningError",
    "create_demo_organization",
    "delete_demo_organization",
    "list_demo_organizations",
    "reset_demo_password",
    "validate_demo_slug",
]
