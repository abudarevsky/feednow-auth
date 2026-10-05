from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from app.api.service_auth import build_service_auth_router
from app.api.session_support import install_session_csrf_middleware, session_csrf_token
from app.auth.pepper import StaticPepper
from app.auth.session import SESSION_COOKIE_NAME, SessionManager
from app.main import create_app
from app.models.enums import (
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.ids import MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.service_authorization import ServiceRegistration
from app.models.user import User
from app.storage.sqlite import open_sqlite_storage

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
USER_ID = UserId("usr_handoff_0001")
ORG_ID = OrganizationId("org_handoff_0001")
SERVICE_CREDENTIAL = "registered-service-secret"


def _registered_service(*, enabled: bool = True) -> ServiceRegistration:
    return ServiceRegistration(
        service_id="vispector",
        display_name="Vispector",
        allowed_origins=("https://inspect.example.test",),
        callback_path="/auth/feednow/callback",
        enabled=enabled,
        allowed_permissions=("projects:read", "projects:write", "inspect"),
        credential_reference="service/vispector/credential",
    )


def _client(tmp_path, *, role: MembershipRole = MembershipRole.MEMBER):
    storage = open_sqlite_storage(tmp_path / "handoff.sqlite")
    user = User(
        id=USER_ID,
        display_name="Handoff User",
        email="handoff@example.test",
        status=UserStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )
    organization = Organization(
        id=ORG_ID,
        name="Handoff Organization",
        slug="handoff-organization",
        type=OrganizationType.CUSTOMER,
        status=OrganizationStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )
    membership = Membership(
        id=MembershipId("mem_handoff_0001"),
        organization_id=ORG_ID,
        user_id=USER_ID,
        role=role,
        status=MembershipStatus.ACTIVE,
        created_at=NOW,
    )
    storage.create_user(user)
    storage.create_organization(organization)
    storage.create_membership(membership)
    session_manager = SessionManager(storage)
    session = session_manager.issue(USER_ID)
    pepper = StaticPepper(b"handoff-test-pepper-at-least-32-bytes")
    router = build_service_auth_router(
        storage,
        pepper,
        service_credential=SERVICE_CREDENTIAL,
        service_registration=_registered_service(),
        session_manager=session_manager,
    )
    application = create_app(routers=[router])
    install_session_csrf_middleware(application, pepper, session_manager)
    client = TestClient(application, follow_redirects=False)
    client.cookies.set(SESSION_COOKIE_NAME, session)
    csrf_token = session_csrf_token(pepper.current(), session)
    client.cookies.set("feednow_csrf", csrf_token)
    return client, storage, {"X-CSRF-Token": csrf_token}


def test_handoff_redirects_only_to_registered_callback_and_exchange_is_single_use(tmp_path) -> None:
    client, storage, csrf_headers = _client(tmp_path)
    try:
        response = client.post(
            "/v1/oauth/service-handoff",
            headers=csrf_headers,
            json={
                "service_id": "vispector",
                "state": "browser-state-123456",
            },
        )
        assert response.status_code == 303
        location = urlsplit(response.headers["location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            "https://inspect.example.test/auth/feednow/callback"
        )
        code = parse_qs(location.query)["code"][0]
        assert parse_qs(location.query)["state"] == ["browser-state-123456"]
        assert USER_ID not in response.headers["location"]

        exchange = {
            "service_id": "vispector",
            "code": code,
        }
        headers = {"Authorization": f"Bearer {SERVICE_CREDENTIAL}"}
        result = client.post(
            "/v1/service-auth/authorization-codes/exchange", json=exchange, headers=headers
        )
        assert result.status_code == 200
        assert result.json() == {
            "user_id": str(USER_ID),
            "organization_id": str(ORG_ID),
            "service": "vispector",
            "permissions": ["inspect", "projects:read"],
            "permission_version": "member:2026-10-04T12:00:00Z",
        }
        replay = client.post(
            "/v1/service-auth/authorization-codes/exchange", json=exchange, headers=headers
        )
        assert replay.status_code == 401
        assert replay.json()["message"] == "invalid authorization code"
    finally:
        storage.close()


def test_handoff_rejects_unregistered_service_and_missing_session(tmp_path) -> None:
    client, storage, _ = _client(tmp_path)
    try:
        client.cookies.clear()
        response = client.post(
            "/v1/oauth/service-handoff",
            json={
                "service_id": "unknown",
                "organization_id": str(ORG_ID),
                "state": "browser-state-123456",
            },
        )
        assert response.status_code == 401
    finally:
        storage.close()
