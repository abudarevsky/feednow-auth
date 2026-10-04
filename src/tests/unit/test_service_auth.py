from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.api.service_auth import build_service_auth_router
from app.auth.credentials import build_literal, hash_secret
from app.auth.pepper import StaticPepper
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import ApiKeyEnvironment, ApiKeyStatus, OrganizationStatus, OrganizationType
from app.models.ids import ApiKeyId, OrganizationId, UserId
from app.models.organization import Organization

NOW = datetime(2026, 10, 1, tzinfo=UTC)
PEPPER = StaticPepper(b"unit-service-auth-pepper-0123456789")
SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"
KEY_ID = "01JXYZ7KA20MB63PCQ8VNDWFTG"


class StubStorage:
    def __init__(
        self,
        *,
        service_id: str = "vispector",
        org_status: OrganizationStatus = OrganizationStatus.ACTIVE,
        scopes: list[str] | None = None,
    ):
        self.api_key = ApiKey(
            id=ApiKeyId("key_01JXYZ7KA20MB63PCQ8VNDWFTG"),
            organization_id=OrganizationId("org_01JXYZ7KA20MB63PCQ8VNDWFTG"),
            service_id=service_id,
            created_by_user_id=UserId("usr_01JXYZ7KA20MB63PCQ8VNDWFTG"),
            name="test key",
            key_id=KEY_ID,
            key_prefix="fn_live_test",
            secret_hash=hash_secret(PEPPER.current(), SECRET),
            environment=ApiKeyEnvironment.LIVE,
            scopes=(["vispector:inspection:run"] if scopes is None else scopes),
            status=ApiKeyStatus.ACTIVE,
            created_at=NOW,
        )
        self.organization = Organization(
            id=self.api_key.organization_id,
            name="Test org",
            slug="test-org",
            type=OrganizationType.CUSTOMER,
            status=org_status,
            created_at=NOW,
            updated_at=NOW,
        )

    def get_api_key_by_key_id(self, key_id: str) -> ApiKey:
        if key_id != KEY_ID:
            from app.storage.contract import EntityNotFoundError

            raise EntityNotFoundError("missing")
        return self.api_key

    def get_organization(self, organization_id: OrganizationId) -> Organization:
        return self.organization


def _client(storage: StubStorage) -> TestClient:
    return TestClient(
        create_app(
            routers=[
                build_service_auth_router(storage, PEPPER, service_credential="service-secret")
            ]
        )
    )


def test_valid_vispector_key_returns_safe_permission_context() -> None:
    client = _client(StubStorage())
    response = client.post(
        "/v1/service-auth/api-keys/validate",
        headers={"Authorization": "Bearer service-secret"},
        json={"key": build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)},
    )
    assert response.status_code == 200
    assert response.json() == {
        "actor_type": "api_key",
        "actor_id": "key_01JXYZ7KA20MB63PCQ8VNDWFTG",
        "user_id": "usr_01JXYZ7KA20MB63PCQ8VNDWFTG",
        "organization_id": "org_01JXYZ7KA20MB63PCQ8VNDWFTG",
        "service": "vispector",
        "permissions": ["inspect"],
        "expires_at": None,
    }
    assert SECRET not in response.text


def test_service_credential_and_key_failures_are_distinct_authz_outcomes() -> None:
    client = _client(StubStorage())
    body = {"key": build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)}
    assert client.post("/v1/service-auth/api-keys/validate", json=body).status_code == 401
    assert (
        client.post(
            "/v1/service-auth/api-keys/validate",
            headers={"Authorization": "Bearer wrong-service-secret"},
            json=body,
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/v1/service-auth/api-keys/validate",
            headers={"Authorization": "Bearer service-secret"},
            json={"key": "invalid"},
        ).status_code
        == 401
    )
    client = _client(StubStorage(service_id="another"))
    assert (
        client.post(
            "/v1/service-auth/api-keys/validate",
            headers={"Authorization": "Bearer service-secret"},
            json=body,
        ).status_code
        == 403
    )


def test_disabled_organization_is_denied() -> None:
    client = _client(StubStorage(org_status=OrganizationStatus.DISABLED))
    response = client.post(
        "/v1/service-auth/api-keys/validate",
        headers={"Authorization": "Bearer service-secret"},
        json={"key": build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)},
    )
    assert response.status_code == 403


def test_unmapped_scopes_do_not_grant_service_access() -> None:
    client = _client(StubStorage(scopes=["vispector:future:unknown"]))
    response = client.post(
        "/v1/service-auth/api-keys/validate",
        headers={"Authorization": "Bearer service-secret"},
        json={"key": build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)},
    )
    assert response.status_code == 403


def test_service_key_requires_exactly_the_inspection_scope() -> None:
    for scopes in (
        [],
        ["vispector:projects:read"],
        ["vispector:inspection:run", "vispector:projects:read"],
        ["vispector:inspection:run", "vispector:inspection:run"],
    ):
        client = _client(StubStorage(scopes=scopes))
        response = client.post(
            "/v1/service-auth/api-keys/validate",
            headers={"Authorization": "Bearer service-secret"},
            json={"key": build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)},
        )
        assert response.status_code == 403
