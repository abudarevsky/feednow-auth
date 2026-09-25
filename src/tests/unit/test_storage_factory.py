"""Unit proofs for the CLI-facing storage factory (Phase 13 task 2).

Covers the breakdown contract:

- ``create_storage`` dispatches by settings type to the documented ``open_*``
  entry points, forwarding the DynamoDB connection shape, and rejects unknown
  settings with a fixed-message ``ValueError``.
- ``storage_settings_from_env`` is pure (the caller owns the mapping; a
  conflicting ``os.environ`` provably does not leak in) and enforces the
  required/optional env matrix with exact-match backend validation.
- Rejection messages are fixed and safe: they never echo a provided value.
- The factory module's own imports touch only ``app.storage.*`` (spec 13
  required behavior 5: no FastAPI app, no ``app.main``, no Cognito/pepper).
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from pathlib import Path
from typing import Any

import pytest

import app.storage.factory as factory
from app.storage.dynamodb import DynamoDbStorage
from app.storage.factory import (
    DynamoDbStorageSettings,
    SqliteStorageSettings,
    create_storage,
    storage_settings_from_env,
)
from app.storage.sqlite import SQLiteStorage

# Hostile values planted in negative-path environments: none may be echoed
# back in a rejection message (fixed, log-safe reasons only).
_LEAKY = "s3cr3t-/opt/private/app.db-eu-secret-1"


class _NotSettings:
    """Unknown object for the dispatch-rejection proof."""


# ---------------------------------------------------------------------------
# create_storage dispatch
# ---------------------------------------------------------------------------


def test_create_storage_dispatches_sqlite_with_path(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []
    sentinel = object()

    def _fake_open(path: Any) -> object:
        calls.append((path,))
        return sentinel

    monkeypatch.setattr(factory, "open_sqlite_storage", _fake_open)
    settings = SqliteStorageSettings(path=Path("/tmp/x.db"))

    assert create_storage(settings) is sentinel
    assert calls == [(settings.path,)]


def test_create_storage_dispatches_dynamodb_with_full_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, Any] = {}
    sentinel = object()

    def _fake_open(**kwargs: Any) -> object:
        calls.update(kwargs)
        return sentinel

    monkeypatch.setattr(factory, "open_dynamodb_storage", _fake_open)
    settings = DynamoDbStorageSettings(
        endpoint_url="http://localhost:8000",
        region="us-east-1",
        table_prefix="dev-",
    )

    assert create_storage(settings) is sentinel
    assert calls == {
        "endpoint_url": "http://localhost:8000",
        "region": "us-east-1",
        "table_prefix": "dev-",
    }


def test_create_storage_rejects_unknown_settings_type() -> None:
    with pytest.raises(ValueError, match="unsupported storage settings type"):
        create_storage(_NotSettings())  # type: ignore[arg-type]


def test_create_storage_real_sqlite_and_dynamodb_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No dispatch monkeypatching: the documented entry points are exercised
    # for real. SQLite construction runs migrations on a temp file. DynamoDB
    # resource construction performs no network I/O; static dummy
    # credentials keep the default credential chain in the env provider so
    # no profile/credential lookup happens during the test.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    sqlite_storage = create_storage(SqliteStorageSettings(path=tmp_path / "factory.db"))
    assert isinstance(sqlite_storage, SQLiteStorage)

    dynamo_storage = create_storage(
        DynamoDbStorageSettings(
            endpoint_url="http://localhost:8000",
            region="us-east-1",
            table_prefix="unit-",
        )
    )
    assert isinstance(dynamo_storage, DynamoDbStorage)
    assert dynamo_storage.table_prefix == "unit-"


# ---------------------------------------------------------------------------
# storage_settings_from_env: accepted matrix
# ---------------------------------------------------------------------------


def test_env_sqlite_returns_path_settings() -> None:
    settings = storage_settings_from_env(
        {"FEEDNOW_STORAGE_BACKEND": "sqlite", "FEEDNOW_SQLITE_PATH": "/data/feednow-auth.db"}
    )
    assert settings == SqliteStorageSettings(path="/data/feednow-auth.db")


def test_env_dynamodb_with_endpoint_targets_local() -> None:
    settings = storage_settings_from_env(
        {
            "FEEDNOW_STORAGE_BACKEND": "dynamodb",
            "FEEDNOW_DYNAMODB_REGION": "us-east-1",
            "FEEDNOW_TABLE_PREFIX": "dev-",
            "FEEDNOW_DYNAMODB_ENDPOINT": "http://localhost:8000",
        }
    )
    assert settings == DynamoDbStorageSettings(
        endpoint_url="http://localhost:8000",
        region="us-east-1",
        table_prefix="dev-",
    )


def test_env_dynamodb_without_endpoint_targets_aws() -> None:
    settings = storage_settings_from_env(
        {
            "FEEDNOW_STORAGE_BACKEND": "dynamodb",
            "FEEDNOW_DYNAMODB_REGION": "eu-west-1",
            "FEEDNOW_TABLE_PREFIX": "prod-",
        }
    )
    assert isinstance(settings, DynamoDbStorageSettings)
    assert settings.endpoint_url is None


def test_env_dynamodb_empty_prefix_is_accepted_as_no_prefix() -> None:
    settings = storage_settings_from_env(
        {
            "FEEDNOW_STORAGE_BACKEND": "dynamodb",
            "FEEDNOW_DYNAMODB_REGION": "us-east-1",
            "FEEDNOW_TABLE_PREFIX": "",
        }
    )
    assert settings == DynamoDbStorageSettings(
        endpoint_url=None,
        region="us-east-1",
        table_prefix="",
    )


def test_env_dynamodb_empty_endpoint_falls_back_to_aws() -> None:
    settings = storage_settings_from_env(
        {
            "FEEDNOW_STORAGE_BACKEND": "dynamodb",
            "FEEDNOW_DYNAMODB_REGION": "us-east-1",
            "FEEDNOW_TABLE_PREFIX": "dev-",
            "FEEDNOW_DYNAMODB_ENDPOINT": "",
        }
    )
    assert isinstance(settings, DynamoDbStorageSettings)
    assert settings.endpoint_url is None


# ---------------------------------------------------------------------------
# storage_settings_from_env: rejections (fixed safe messages, exact match)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "environ",
    [
        {},  # backend missing entirely
        {"FEEDNOW_STORAGE_BACKEND": ""},  # empty is not a backend
        {"FEEDNOW_STORAGE_BACKEND": "SQLite"},  # exact match only, no case folding
        {"FEEDNOW_STORAGE_BACKEND": " sqlite "},  # no stripping
        {"FEEDNOW_STORAGE_BACKEND": "postgres"},  # unknown backend
        {"FEEDNOW_STORAGE_BACKEND": "dynamo"},  # near-miss backend
    ],
)
def test_env_backend_must_be_exact(environ: dict[str, str]) -> None:
    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env(environ)
    assert str(excinfo.value) == factory._BACKEND_REQUIRED


def test_env_sqlite_requires_non_empty_path() -> None:
    base = {"FEEDNOW_STORAGE_BACKEND": "sqlite"}
    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env(base)
    assert str(excinfo.value) == factory._SQLITE_PATH_REQUIRED

    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env({**base, "FEEDNOW_SQLITE_PATH": ""})
    assert str(excinfo.value) == factory._SQLITE_PATH_REQUIRED


def test_env_dynamodb_requires_region_and_prefix() -> None:
    base = {"FEEDNOW_STORAGE_BACKEND": "dynamodb"}
    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env({**base, "FEEDNOW_TABLE_PREFIX": "dev-"})
    assert str(excinfo.value) == factory._DYNAMODB_REGION_REQUIRED

    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env(
            {**base, "FEEDNOW_DYNAMODB_REGION": "", "FEEDNOW_TABLE_PREFIX": "dev-"}
        )
    assert str(excinfo.value) == factory._DYNAMODB_REGION_REQUIRED

    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env({**base, "FEEDNOW_DYNAMODB_REGION": "us-east-1"})
    assert str(excinfo.value) == factory._DYNAMODB_PREFIX_REQUIRED


def test_env_rejections_never_echo_provided_values() -> None:
    # Bad backend carrying leaky values in every other key.
    leaky_backend = {
        "FEEDNOW_STORAGE_BACKEND": _LEAKY,
        "FEEDNOW_SQLITE_PATH": _LEAKY,
        "FEEDNOW_DYNAMODB_REGION": _LEAKY,
        "FEEDNOW_TABLE_PREFIX": _LEAKY,
    }
    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env(leaky_backend)
    assert str(excinfo.value) == factory._BACKEND_REQUIRED

    # sqlite with a missing path; the leaky region/prefix keys are irrelevant.
    leaky_sqlite = {
        "FEEDNOW_STORAGE_BACKEND": "sqlite",
        "FEEDNOW_DYNAMODB_REGION": _LEAKY,
        "FEEDNOW_TABLE_PREFIX": _LEAKY,
    }
    with pytest.raises(ValueError) as excinfo:
        storage_settings_from_env(leaky_sqlite)
    assert str(excinfo.value) == factory._SQLITE_PATH_REQUIRED
    assert _LEAKY not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Purity and immutability
# ---------------------------------------------------------------------------


def test_settings_from_env_ignores_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The function must read only the passed mapping, never os.environ.
    monkeypatch.setenv("FEEDNOW_STORAGE_BACKEND", "dynamodb")
    monkeypatch.setenv("FEEDNOW_DYNAMODB_REGION", "conflicting-region")
    settings = storage_settings_from_env(
        {"FEEDNOW_STORAGE_BACKEND": "sqlite", "FEEDNOW_SQLITE_PATH": "/data/a.db"}
    )
    assert settings == SqliteStorageSettings(path="/data/a.db")


def test_settings_dataclasses_are_frozen() -> None:
    sqlite_settings = SqliteStorageSettings(path="/data/a.db")
    with pytest.raises(dataclasses.FrozenInstanceError):
        sqlite_settings.path = "/data/b.db"  # type: ignore[misc]

    dynamo_settings = DynamoDbStorageSettings(
        endpoint_url=None, region="us-east-1", table_prefix=""
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        dynamo_settings.region = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Import closure: factory touches only app.storage.*
# ---------------------------------------------------------------------------


def test_factory_module_imports_only_app_storage() -> None:
    source_path = inspect.getsourcefile(factory)
    assert source_path is not None
    tree = ast.parse(Path(source_path).read_text(encoding="utf-8"))

    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            imported.append(node.module)

    app_imports = [name for name in imported if name == "app" or name.startswith("app.")]
    assert app_imports, "the factory must import the storage contract/adapters"
    assert all(name.startswith("app.storage") for name in app_imports), app_imports
    # Belt and braces on the forbidden closure members (spec 13 behavior 5).
    forbidden = ("app.main", "app.api", "app.auth", "fastapi")
    assert not any(name == f or name.startswith(f + ".") for name in imported for f in forbidden)


def test_os_environ_is_not_read_inside_the_factory_module() -> None:
    # Purity proof: the module never imports ``os``, so an ``os.environ`` read
    # is structurally impossible (the docstring may still mention it).
    source_path = inspect.getsourcefile(factory)
    assert source_path is not None
    tree = ast.parse(Path(source_path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] != "os" for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            assert node.module.split(".")[0] != "os"
