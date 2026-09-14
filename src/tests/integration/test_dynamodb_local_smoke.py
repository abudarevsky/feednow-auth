"""DynamoDB Local smoke test: create/ping/delete the seven harness tables.

Marker-gated (``dynamodb_local``): skips with an explicit reason unless
``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and reachable, so the default
suite is unaffected on machines without Docker. Run it with the command in
``docs/operations.md``; it proves the harness lifecycle itself (table create
with GSIs, a data-path round trip, deletion) before any adapter exists.
"""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError

from tests.support import dynamodb_local as local

pytestmark = pytest.mark.dynamodb_local


def test_create_ping_and_delete_tables_against_local() -> None:
    endpoint = local.require_local_endpoint()
    resource = local.make_dynamodb_resource(endpoint)
    prefix = local.random_table_prefix()
    names = local.table_names(prefix)
    client = resource.meta.client
    try:
        local.create_tables(prefix, resource=resource)
        for name in names:
            description = client.describe_table(TableName=name)["Table"]
            assert description["TableStatus"] == "ACTIVE"
        # Data-path ping on the users base table (put/get round trip).
        users = resource.Table(f"{prefix}users")
        users.put_item(Item={"pk": "usr_smoke", "ping": "pong"})
        assert users.get_item(Key={"pk": "usr_smoke"})["Item"]["ping"] == "pong"
        # GSI ping: the by-user index must be queryable on memberships.
        memberships = resource.Table(f"{prefix}memberships")
        response = memberships.query(
            IndexName="by-user",
            KeyConditionExpression="#gu = :u",
            ExpressionAttributeNames={"#gu": "g_user"},
            ExpressionAttributeValues={":u": "usr_smoke"},
        )
        assert response["Items"] == []
    finally:
        local.delete_tables(prefix, resource=resource)
    for name in names:
        with pytest.raises(ClientError) as excinfo:
            client.describe_table(TableName=name)
        assert excinfo.value.response["Error"]["Code"] == "ResourceNotFoundException"
