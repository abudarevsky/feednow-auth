"""DynamoDB Local proof for the service API-key validation route."""

from collections.abc import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.api.service_auth import build_service_auth_router
from app.api.session_support import install_session_csrf_middleware, session_csrf_token
from app.auth.credentials import build_literal, hash_secret
from app.auth.pepper import StaticPepper
from app.auth.session import SESSION_COOKIE_NAME, SessionManager
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import ApiKeyEnvironment, MembershipRole, MembershipStatus
from app.models.ids import MembershipId, OrganizationId
from app.models.membership import Membership
from app.models.service_authorization import ServiceRegistration
from app.storage.dynamodb import DynamoDbStorage
from tests.storage_contract.suite import (
    make_api_key,
    make_organization,
    make_user,
)
from tests.support import dynamodb_local as local

pytestmark = pytest.mark.dynamodb_local

PEPPER = StaticPepper(b"integration-dynamodb-service-auth-pepper")
SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"
KEY_SEGMENT = "01JXYZ7KA20MB63PCQ8VNDWFTG"


@pytest.fixture
def ddb_storage() -> Iterator[DynamoDbStorage]:
    endpoint = local.require_local_endpoint()
    resource = local.make_dynamodb_resource(endpoint)
    prefix = local.random_table_prefix()
    local.create_tables(prefix, resource=resource)
    storage = local.make_dynamodb_storage(prefix, resource=local.make_dynamodb_resource(endpoint))
    try:
        yield storage
    finally:
        storage.close()
        local.delete_tables(prefix, resource=resource)


def test_validation_route_reads_key_and_organization_from_dynamodb_local(
    ddb_storage: DynamoDbStorage,
) -> None:
    user = make_user()
    organization = make_organization()
    ddb_storage.create_user(user)
    ddb_storage.create_organization(organization)
    key = make_api_key(
        organization_id=str(organization.id),
        created_by_user_id=str(user.id),
        credential_segment=KEY_SEGMENT,
        scopes=["vispector:inspection:run"],
    ).model_copy(update={"secret_hash": hash_secret(PEPPER.current(), SECRET)})
    ddb_storage.create_api_key(ApiKey.model_validate(key.model_dump()))

    app = create_app(
        routers=[
            build_service_auth_router(
                ddb_storage, PEPPER, service_credential="local-service-secret"
            )
        ]
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/service-auth/api-keys/validate",
            headers={"Authorization": "Bearer local-service-secret"},
            json={"key": build_literal(ApiKeyEnvironment.LIVE, KEY_SEGMENT, SECRET)},
        )

    assert response.status_code == 200, response.text
    assert response.json()["organization_id"] == str(OrganizationId(organization.id))
    assert response.json()["permissions"] == ["inspect"]
    assert SECRET not in response.text


def test_handoff_code_is_exchanged_once_against_dynamodb_local(
    ddb_storage: DynamoDbStorage,
) -> None:
    user = make_user()
    organization = make_organization()
    membership = Membership(
        id=MembershipId("mem_dynamodb_handoff_1"),
        organization_id=organization.id,
        user_id=user.id,
        role=MembershipRole.MEMBER,
        status=MembershipStatus.ACTIVE,
        created_at=user.created_at,
    )
    ddb_storage.create_user(user)
    ddb_storage.create_organization(organization)
    ddb_storage.create_membership(membership)
    session_manager = SessionManager(ddb_storage)
    session_id = session_manager.issue(user.id)
    registration = ServiceRegistration(
        service_id="vispector",
        display_name="Vispector",
        allowed_origins=("https://inspect.example.test",),
        callback_path="/auth/feednow/callback",
        enabled=True,
        allowed_permissions=("projects:read", "projects:write", "inspect"),
        credential_reference="service/vispector/credential",
    )
    app = create_app(
        routers=[
            build_service_auth_router(
                ddb_storage,
                PEPPER,
                service_credential="local-service-secret",
                service_registration=registration,
                session_manager=session_manager,
            )
        ]
    )
    install_session_csrf_middleware(app, PEPPER, session_manager)
    csrf = session_csrf_token(PEPPER.current(), session_id)
    with TestClient(app, follow_redirects=False) as client:
        client.cookies.set(SESSION_COOKIE_NAME, session_id)
        client.cookies.set("feednow_csrf", csrf)
        handoff = client.post(
            "/v1/oauth/service-handoff",
            headers={"X-CSRF-Token": csrf},
            json={
                "service_id": "vispector",
                "organization_id": str(organization.id),
                "state": "browser-state-123456",
            },
        )
        assert handoff.status_code == 303, handoff.text
        code = parse_qs(urlsplit(handoff.headers["location"]).query)["code"][0]
        assert parse_qs(urlsplit(handoff.headers["location"]).query)["state"] == [
            "browser-state-123456"
        ]
        exchange = {
            "service_id": "vispector",
            "code": code,
        }
        headers = {"Authorization": "Bearer local-service-secret"}
        result = client.post(
            "/v1/service-auth/authorization-codes/exchange",
            headers=headers,
            json=exchange,
        )
        replay = client.post(
            "/v1/service-auth/authorization-codes/exchange",
            headers=headers,
            json=exchange,
        )

    assert result.status_code == 200, result.text
    assert result.json()["permissions"] == ["inspect", "projects:read"]
    assert replay.status_code == 401
