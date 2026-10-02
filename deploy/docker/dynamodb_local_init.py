"""Create the FeedNow table schema in the local DynamoDB service."""

from __future__ import annotations

import os
import time

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from app.storage.dynamodb import SCHEMA


def main() -> None:
    endpoint = os.environ["FEEDNOW_DYNAMODB_ENDPOINT"]
    region = os.environ["FEEDNOW_DYNAMODB_REGION"]
    prefix = os.environ["FEEDNOW_TABLE_PREFIX"]
    client = boto3.client("dynamodb", endpoint_url=endpoint, region_name=region)

    deadline = time.monotonic() + 60
    while True:
        try:
            client.list_tables(Limit=1)
            break
        except EndpointConnectionError:
            if time.monotonic() >= deadline:
                raise RuntimeError("DynamoDB Local did not become available") from None
            time.sleep(1)

    existing = set(client.list_tables().get("TableNames", []))
    for spec in SCHEMA:
        table_name = f"{prefix}{spec.name}"
        if table_name in existing:
            continue
        try:
            client.create_table(**spec.create_parameters(prefix))
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ResourceInUseException":
                raise

    waiter = client.get_waiter("table_exists")
    for spec in SCHEMA:
        waiter.wait(TableName=f"{prefix}{spec.name}")
    print(f"DynamoDB Local is ready with {len(SCHEMA)} FeedNow tables")


if __name__ == "__main__":
    main()
