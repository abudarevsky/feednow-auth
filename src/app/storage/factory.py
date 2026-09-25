"""CLI-facing storage factory (Phase 13 task 2).

``app.storage.__init__`` stays adapter-free, so this is a new submodule
imported by explicit path (``from app.storage.factory import create_storage``)
by the administration CLI. The factory is the single place that turns
deployment configuration into a :class:`~app.storage.contract.Storage`
instance without ever constructing a FastAPI app: it imports only
``app.storage.*`` modules, never ``app.main`` or ``app.auth.cognito``, and
reads no Cognito/pepper configuration (spec 13 required behavior 5).

Design pinned by the breakdown:

- Settings are frozen dataclasses; there is deliberately no
  ``dynamodb_resource`` seam in the public settings (tests inject at the
  ``open_*`` level instead).
- :func:`storage_settings_from_env` is pure: the caller passes the mapping
  (e.g. ``os.environ``); no ``os.environ`` read happens inside, so CLI tests
  inject environments without touching the process.
- Every rejection raises ``ValueError`` with a fixed, safe message that names
  only the expected variables — never a provided value, path, or region.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from app.storage.contract import Storage
from app.storage.dynamodb import open_dynamodb_storage
from app.storage.sqlite import open_sqlite_storage

#: Environment keys consumed by :func:`storage_settings_from_env`.
BACKEND_ENV = "FEEDNOW_STORAGE_BACKEND"
SQLITE_PATH_ENV = "FEEDNOW_SQLITE_PATH"
DYNAMODB_REGION_ENV = "FEEDNOW_DYNAMODB_REGION"
DYNAMODB_TABLE_PREFIX_ENV = "FEEDNOW_TABLE_PREFIX"
DYNAMODB_ENDPOINT_ENV = "FEEDNOW_DYNAMODB_ENDPOINT"

#: Fixed, value-free rejection messages (log-safe by construction).
_BACKEND_REQUIRED = "FEEDNOW_STORAGE_BACKEND must be exactly 'sqlite' or 'dynamodb'"
_SQLITE_PATH_REQUIRED = "FEEDNOW_SQLITE_PATH is required for the sqlite backend"
_DYNAMODB_REGION_REQUIRED = "FEEDNOW_DYNAMODB_REGION is required for the dynamodb backend"
_DYNAMODB_PREFIX_REQUIRED = "FEEDNOW_TABLE_PREFIX is required for the dynamodb backend"
_UNSUPPORTED_SETTINGS = "unsupported storage settings type"


@dataclass(frozen=True)
class SqliteStorageSettings:
    """Filesystem location for the SQLite adapter."""

    path: str | Path


@dataclass(frozen=True)
class DynamoDbStorageSettings:
    """Connection shape for the DynamoDB adapter.

    ``endpoint_url`` is ``None`` for real AWS and a Local endpoint for the
    harness; ``table_prefix`` is environment-parameterized (``dev``/``staging``
    /``prod``) and may legitimately be the empty string (no prefix).
    """

    endpoint_url: str | None
    region: str
    table_prefix: str


def create_storage(settings: SqliteStorageSettings | DynamoDbStorageSettings) -> Storage:
    """Build the adapter named by ``settings``, typed as the storage contract.

    Dispatch is by settings type only; an unknown settings type raises
    ``ValueError`` with the fixed :data:`_UNSUPPORTED_SETTINGS` message.
    """
    if isinstance(settings, SqliteStorageSettings):
        return open_sqlite_storage(settings.path)
    if isinstance(settings, DynamoDbStorageSettings):
        return open_dynamodb_storage(
            endpoint_url=settings.endpoint_url,
            region=settings.region,
            table_prefix=settings.table_prefix,
        )
    raise ValueError(_UNSUPPORTED_SETTINGS)


def storage_settings_from_env(
    environ: Mapping[str, str],
) -> SqliteStorageSettings | DynamoDbStorageSettings:
    """Derive settings from ``environ`` without reading the process environment.

    ``FEEDNOW_STORAGE_BACKEND`` is required and must match ``sqlite`` or
    ``dynamodb`` exactly (no case folding or stripping). ``sqlite`` requires a
    non-empty ``FEEDNOW_SQLITE_PATH``. ``dynamodb`` requires a non-empty
    ``FEEDNOW_DYNAMODB_REGION`` and a present ``FEEDNOW_TABLE_PREFIX`` (empty
    string means no prefix), and takes an optional ``FEEDNOW_DYNAMODB_ENDPOINT``
    (present and non-empty → DynamoDB Local, absent or empty → AWS).
    """
    backend = environ.get(BACKEND_ENV)
    if backend == "sqlite":
        path = environ.get(SQLITE_PATH_ENV)
        if not path:
            raise ValueError(_SQLITE_PATH_REQUIRED)
        return SqliteStorageSettings(path=path)
    if backend == "dynamodb":
        region = environ.get(DYNAMODB_REGION_ENV)
        if not region:
            raise ValueError(_DYNAMODB_REGION_REQUIRED)
        table_prefix = environ.get(DYNAMODB_TABLE_PREFIX_ENV)
        if table_prefix is None:
            raise ValueError(_DYNAMODB_PREFIX_REQUIRED)
        endpoint_url = environ.get(DYNAMODB_ENDPOINT_ENV) or None
        return DynamoDbStorageSettings(
            endpoint_url=endpoint_url,
            region=region,
            table_prefix=table_prefix,
        )
    raise ValueError(_BACKEND_REQUIRED)


__all__ = [
    "BACKEND_ENV",
    "DYNAMODB_ENDPOINT_ENV",
    "DYNAMODB_REGION_ENV",
    "DYNAMODB_TABLE_PREFIX_ENV",
    "SQLITE_PATH_ENV",
    "DynamoDbStorageSettings",
    "SqliteStorageSettings",
    "create_storage",
    "storage_settings_from_env",
]
