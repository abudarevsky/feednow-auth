"""DynamoDB Local test harness: env gating, endpoint probe, and table lifecycle.

Per the Phase 06 harness decision (breakdown decision 8), DynamoDB Local tests
are **opt-in**: they carry the ``dynamodb_local`` marker and skip with an
explicit reason unless ``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and the
endpoint is reachable, so the default ``uv run pytest`` stays green on
machines without Docker. The server is expected to run ``-inMemory
-sharedDb``; this harness authenticates with fixed dummy credentials only
(DynamoDB Local 2.x format-validates the access key but never contacts AWS).

Isolation follows the conformance suite's fixture contract ("initialized
adapter with all tables empty, per test"): each test creates the seven
adapter tables under a fresh random prefix and deletes them on teardown —
deterministic, no truncation races.

The table spec is the adapter's :data:`app.storage.dynamodb.SCHEMA` — the
single source of the seven-table names and key schemas (breakdown decision 2),
re-exported here as :data:`TABLE_SPECS` so the harness and the adapter can never
drift. ``make_dynamodb_storage`` builds an adapter under a fresh prefix through
the documented factory.
"""

from __future__ import annotations

import os
import re
import secrets
import socket
from typing import Any, Final
from urllib.parse import urlsplit

import boto3
import pytest
from botocore.exceptions import ClientError

from app.storage.dynamodb import (
    SCHEMA,
    DynamoDbStorage,
    IndexSpec,
    TableSpec,
    open_dynamodb_storage,
)

#: Environment variable that must point at a running DynamoDB Local.
ENDPOINT_ENV_VAR: Final = "FEEDNOW_DYNAMODB_LOCAL_ENDPOINT"

#: Fixed dummy credentials; DynamoDB Local 2.x accepts (and format-validates)
#: any access key with the ``AKIA``/``ASIA`` prefix, never a real AWS account.
DUMMY_ACCESS_KEY_ID: Final = "AKIATESTTESTTESTTESTTEST"
DUMMY_SECRET_ACCESS_KEY: Final = "test-secret-key-for-local-testing-only"

#: Any region works against Local; pinned so ARNs/clients are deterministic.
DEFAULT_REGION: Final = "us-east-1"

#: TCP connect timeout for the reachability probe (loopback is instant).
PROBE_TIMEOUT_SECONDS: Final = 1.0

#: Waiter pacing for create/delete confirmation (Local confirms in ~ms).
#: Keys are capitalized because botocore reads ``Delay``/``MaxAttempts``
#: from ``WaiterConfig``; lowercase names would be silently ignored.
WAITER_CONFIG: Final = {"Delay": 0.1, "MaxAttempts": 100}

#: Characters DynamoDB permits in table names (3-255 long).
_TABLE_NAME_PATTERN: Final = re.compile(r"^[a-zA-Z0-9_.\-]{3,255}$")

#: The seven-table schema, imported from the adapter (the single source). The
#: ``IndexSpec``/``TableSpec`` types and their ``create_parameters`` builder
#: live in :mod:`app.storage.dynamodb`; re-exported here so the harness and the
#: adapter can never drift.
TABLE_SPECS: Final[tuple[TableSpec, ...]] = SCHEMA


# -- endpoint gating ----------------------------------------------------------


def configured_endpoint() -> str | None:
    """The configured DynamoDB Local endpoint, or ``None`` if unset/blank."""
    return os.environ.get(ENDPOINT_ENV_VAR, "").strip() or None


def probe_endpoint(endpoint: str, *, timeout: float = PROBE_TIMEOUT_SECONDS) -> bool:
    """Whether a TCP connection to ``endpoint``'s host:port succeeds.

    A connect-level probe (not an HTTP/API call) so it answers "is a server
    listening here?" without depending on DynamoDB request semantics; any
    accepted connection counts, and unparseable endpoints are unreachable.
    """
    parts = urlsplit(endpoint)
    host = parts.hostname
    if host is None:
        return False
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def skip_reason() -> str | None:
    """Why DynamoDB Local tests must skip, or ``None`` if the server is ready."""
    endpoint = configured_endpoint()
    if endpoint is None:
        return (
            f"{ENDPOINT_ENV_VAR} is not set; start DynamoDB Local and export the "
            "endpoint (see docs/operations.md)"
        )
    if not probe_endpoint(endpoint):
        return f"DynamoDB Local is not reachable at {endpoint} (see docs/operations.md)"
    return None


def require_local_endpoint() -> str:
    """The endpoint for marker-gated tests; ``pytest.skip`` with the reason."""
    reason = skip_reason()
    if reason is not None:
        pytest.skip(reason)
    endpoint = configured_endpoint()
    assert endpoint is not None  # skip_reason() returned None only if set
    return endpoint


# -- resource and table lifecycle ----------------------------------------------


def make_dynamodb_resource(endpoint_url: str) -> Any:
    """A boto3 DynamoDB resource pointed at Local with dummy credentials.

    Returns ``Any`` deliberately: boto3 resources are untyped at the
    ``resource()`` factory and the adapter's injected-resource seam (task 2)
    accepts the same shape. Construction performs no network I/O.
    """
    return boto3.resource(
        "dynamodb",
        endpoint_url=endpoint_url,
        region_name=DEFAULT_REGION,
        aws_access_key_id=DUMMY_ACCESS_KEY_ID,
        aws_secret_access_key=DUMMY_SECRET_ACCESS_KEY,
    )


def random_table_prefix() -> str:
    """A fresh random prefix so concurrent/per-test runs never collide."""
    return f"feednow-auth-test-{secrets.token_hex(4)}-"


def table_names(prefix: str) -> tuple[str, ...]:
    """The fully prefixed names of the seven harness tables."""
    return tuple(f"{prefix}{spec.name}" for spec in TABLE_SPECS)


def create_tables(prefix: str, *, resource: Any | None = None) -> None:
    """Create all seven tables under ``prefix`` and wait until ACTIVE.

    ``resource`` is the injectable seam for unit tests; when omitted, a
    resource is built for the configured (and required) Local endpoint.
    """
    if resource is None:
        resource = make_dynamodb_resource(require_local_endpoint())
    client = resource.meta.client
    for spec in TABLE_SPECS:
        client.create_table(**spec.create_parameters(prefix))
    waiter = client.get_waiter("table_exists")
    for name in table_names(prefix):
        waiter.wait(TableName=name, WaiterConfig=WAITER_CONFIG)


def delete_tables(prefix: str, *, resource: Any | None = None) -> None:
    """Delete all seven tables under ``prefix`` and confirm they are gone.

    Teardown-tolerant: a table that never materialized (partial setup) is
    skipped rather than failing the teardown over the real test error.
    """
    if resource is None:
        resource = make_dynamodb_resource(require_local_endpoint())
    client = resource.meta.client
    for name in table_names(prefix):
        try:
            client.delete_table(TableName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
    waiter = client.get_waiter("table_not_exists")
    for name in table_names(prefix):
        waiter.wait(TableName=name, WaiterConfig=WAITER_CONFIG)


def make_dynamodb_storage(
    prefix: str,
    *,
    resource: Any | None = None,
    endpoint_url: str | None = None,
) -> DynamoDbStorage:
    """An adapter under ``prefix``, built through the documented factory.

    ``resource`` is the injectable seam (unit tests pass a fake; no live calls).
    When omitted, a resource is built for ``endpoint_url`` or the configured
    Local endpoint. The caller owns table creation (``create_tables``) and must
    ``close()`` the adapter and ``delete_tables`` on teardown.
    """
    if resource is None:
        resource = make_dynamodb_resource(endpoint_url or require_local_endpoint())
    return open_dynamodb_storage(table_prefix=prefix, dynamodb_resource=resource)


__all__ = [
    "DEFAULT_REGION",
    "DUMMY_ACCESS_KEY_ID",
    "DUMMY_SECRET_ACCESS_KEY",
    "ENDPOINT_ENV_VAR",
    "PROBE_TIMEOUT_SECONDS",
    "TABLE_SPECS",
    "WAITER_CONFIG",
    "IndexSpec",
    "TableSpec",
    "configured_endpoint",
    "create_tables",
    "delete_tables",
    "make_dynamodb_resource",
    "make_dynamodb_storage",
    "probe_endpoint",
    "random_table_prefix",
    "require_local_endpoint",
    "skip_reason",
    "table_names",
]
