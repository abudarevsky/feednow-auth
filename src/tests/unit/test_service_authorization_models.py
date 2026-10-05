from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.models.service_authorization import ServiceAuthorizationCode, ServiceRegistration
from app.models.enums import MembershipRole
from app.services.service_authorization import service_permissions_for_role

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def test_registered_service_accepts_only_origin_and_callback_policy() -> None:
    service = ServiceRegistration(
        service_id="vispector",
        display_name="Vispector",
        allowed_origins=("https://inspect.example.test",),
        callback_path="/auth/feednow/callback",
        enabled=True,
        allowed_permissions=("projects:read", "projects:write", "inspect"),
        credential_reference="feednow/vispector/service-credential",
    )

    assert service.service_id == "vispector"
    assert service.allowed_origins == ("https://inspect.example.test",)


@pytest.mark.parametrize(
    "origin",
    (
        "https://user:password@inspect.example.test",
        "https://inspect.example.test/path",
        "javascript:alert(1)",
        "https://inspect.example.test?next=elsewhere",
    ),
)
def test_registered_service_rejects_non_origin_destinations(origin: str) -> None:
    with pytest.raises(ValidationError):
        ServiceRegistration(
            service_id="vispector",
            display_name="Vispector",
            allowed_origins=(origin,),
            callback_path="/auth/callback",
            enabled=True,
            allowed_permissions=("inspect",),
            credential_reference="service/credential",
        )


def test_authorization_code_stores_digest_and_expiry_bound_context() -> None:
    code = ServiceAuthorizationCode(
        code_digest="a" * 64,
        service_id="vispector",
        user_id="usr_test_0001",
        organization_id="org_test_0001",
        permissions=("projects:read", "inspect"),
        permission_version="membership-v1",
        expires_at=NOW + timedelta(minutes=2),
    )

    assert code.consumed_at is None
    assert code.permissions == ("projects:read", "inspect")
    assert "raw_code" not in code.model_dump()


def test_authorization_code_rejects_non_digest_and_duplicate_permissions() -> None:
    values = {
        "code_digest": "raw-secret",
        "service_id": "vispector",
        "user_id": "usr_test_0001",
        "organization_id": "org_test_0001",
        "permissions": ("inspect", "inspect"),
        "permission_version": "membership-v1",
        "expires_at": NOW + timedelta(minutes=2),
    }

    with pytest.raises(ValidationError):
        ServiceAuthorizationCode(**values)

    with pytest.raises(ValidationError):
        ServiceAuthorizationCode(**(values | {"code_digest": "a" * 64}))


@pytest.mark.parametrize(
    ("role", "expected"),
    (
        (MembershipRole.OWNER, ("inspect", "projects:read", "projects:write")),
        (MembershipRole.ORG_ADMIN, ("inspect", "projects:read", "projects:write")),
        (MembershipRole.MEMBER, ("inspect", "projects:read")),
        (MembershipRole.VIEWER, ("projects:read",)),
    ),
)
def test_role_mapping_is_sorted_and_respects_service_allowlist(role, expected) -> None:
    allowed = ("projects:read", "projects:write", "inspect", "system:admin")
    assert service_permissions_for_role(role, allowed) == expected
