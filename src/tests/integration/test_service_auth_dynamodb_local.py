"""DynamoDB Local proof for the service API-key validation route."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.api.service_auth import build_service_auth_router
from app.auth.credentials import build_literal, hash_secret
from app.auth.pepper import StaticPepper
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import ApiKeyEnvironment
from app.models.ids import OrganizationId
from app.storage.dynamodb import DynamoDbStorage
from tests.storage_contract.suite import make_api_key, make_organization, make_user
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
