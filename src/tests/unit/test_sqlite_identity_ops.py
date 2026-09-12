"""Unit tests for the Phase 02 task-3 SQLite error translation (identity ops).

Scope per the breakdown: storage *behavior* (duplicates, rollback, lookups)
is owned by the conformance suite; this module pins the adapter-internal
sqlite3→domain translation table only — including the contract-pinned rule
that PRIMARY KEY collisions surface as ``DuplicateEntityError`` with
``kind="entity_id"`` and that no raw driver error or SQL constraint text
ever escapes the adapter.

Violations are produced against the *real* schema (a live adapter
connection) so the messages translated are the ones SQLite actually emits,
not hand-written approximations.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

import app.storage.contract as contract
from app.models import ExternalIdentity, IdentityProvider, User, UserStatus
from app.models.ids import ExternalIdentityId, UserId
from app.storage import sqlite as sqlite_adapter
from app.storage.sqlite import (
    SQLiteStorage,
    encode_provider_tenant,
    encode_timestamp,
)

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)


def make_user(user_id: str = "usr_test_0001", email: str = "test@example.com") -> User:
    return User(
        id=UserId(user_id),
        display_name="Test User",
        email=email,
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_identity(
    user_id: str = "usr_test_0001",
    identity_id: str = "extid_test_0001",
    tenant: str | None = None,
) -> ExternalIdentity:
    return ExternalIdentity(
        id=ExternalIdentityId(identity_id),
        user_id=UserId(user_id),
        provider=IdentityProvider.COGNITO,
        provider_subject="subject-cognito-0001",
        provider_tenant=tenant,
        created_at=_T0,
    )


def _insert_user(conn: sqlite3.Connection, user: User) -> None:
    conn.execute(
        "INSERT INTO users (id, display_name, email, status, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(user.id),
            user.display_name,
            user.email,
            str(user.status),
            encode_timestamp(user.created_at),
            encode_timestamp(user.updated_at),
        ),
    )


def _insert_identity(conn: sqlite3.Connection, identity: ExternalIdentity) -> None:
    conn.execute(
        "INSERT INTO external_identities"
        " (id, user_id, provider, provider_subject, provider_tenant, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(identity.id),
            str(identity.user_id),
            str(identity.provider),
            identity.provider_subject,
            encode_provider_tenant(identity.provider_tenant),
            encode_timestamp(identity.created_at),
        ),
    )


def _capture_integrity_error(conn: sqlite3.Connection, statement: str, params: tuple) -> Exception:
    """Run a raw violating insert and return the raised driver error."""
    try:
        conn.execute(statement, params)
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        return exc
    raise AssertionError("expected sqlite3.IntegrityError, insert succeeded")


@pytest.fixture
def storage(tmp_path) -> SQLiteStorage:  # type: ignore[no-untyped-def]
    adapter = SQLiteStorage(tmp_path / "identity-ops.sqlite")
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# 1. The translation table covers every unique constraint in the task-2 DDL
# ---------------------------------------------------------------------------


def test_translation_table_covers_all_ddl_unique_constraints() -> None:
    mapped = set(sqlite_adapter._UNIQUE_KIND_BY_COLUMNS)
    assert mapped == {
        ("api_keys", ("id",)),
        ("api_keys", ("key_id",)),
        ("audit_events", ("id",)),
        ("external_identities", ("id",)),
        ("external_identities", ("provider", "provider_subject", "provider_tenant")),
        ("memberships", ("id",)),
        ("memberships", ("organization_id", "user_id")),
        ("organizations", ("id",)),
        ("organizations", ("slug",)),
        ("users", ("id",)),
        ("users", ("email",)),
    }
    kinds = set(sqlite_adapter._UNIQUE_KIND_BY_COLUMNS.values())
    assert kinds == set(contract.DuplicateEntityKind)


# ---------------------------------------------------------------------------
# 2. Real driver errors translate to the pinned domain vocabulary
# ---------------------------------------------------------------------------


def test_users_primary_key_violation_translates_to_entity_id(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    _insert_user(conn, make_user())
    conn.commit()
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO users (id, display_name, email, status, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            "usr_test_0001",
            "Other",
            "other@example.com",
            "active",
            encode_timestamp(_T0),
            encode_timestamp(_T0),
        ),
    )
    assert isinstance(exc, sqlite3.IntegrityError)
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.ENTITY_ID


def test_users_email_violation_translates_to_user_email(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    _insert_user(conn, make_user())
    conn.commit()
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO users (id, display_name, email, status, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            "usr_test_0002",
            "Other",
            "test@example.com",
            "active",
            encode_timestamp(_T0),
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.USER_EMAIL


def test_identity_tuple_violation_translates_to_external_identity(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    _insert_user(conn, make_user())
    _insert_user(conn, make_user("usr_test_0002", "other@example.com"))
    _insert_identity(conn, make_identity(tenant="shop-a.example.myshopify.com"))
    conn.commit()
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO external_identities"
        " (id, user_id, provider, provider_subject, provider_tenant, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            "extid_test_0002",
            "usr_test_0002",
            "cognito",
            "subject-cognito-0001",
            "shop-a.example.myshopify.com",
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.EXTERNAL_IDENTITY


def test_identity_primary_key_violation_translates_to_entity_id(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    _insert_user(conn, make_user())
    _insert_user(conn, make_user("usr_test_0002", "other@example.com"))
    _insert_identity(conn, make_identity(tenant="shop-a.example.myshopify.com"))
    conn.commit()
    # Same extid_ record id, different user and tuple: the PK index fires and
    # must surface as entity_id, not external_identity.
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO external_identities"
        " (id, user_id, provider, provider_subject, provider_tenant, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            "extid_test_0001",
            "usr_test_0002",
            "cognito",
            "subject-cognito-0002",
            "shop-a.example.myshopify.com",
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.ENTITY_ID


def test_identity_foreign_key_violation_translates_to_reference_not_found(
    storage: SQLiteStorage,
) -> None:
    exc = _capture_integrity_error(
        storage._connection(),
        "INSERT INTO external_identities"
        " (id, user_id, provider, provider_subject, provider_tenant, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            "extid_test_0009",
            "usr_ghost_0001",
            "cognito",
            "subject-cognito-0009",
            "",
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.ReferenceNotFoundError)


def test_unmapped_integrity_failure_becomes_generic_storage_error(
    storage: SQLiteStorage,
) -> None:
    # NOT NULL (and any other unmapped integrity failure) must still be a
    # domain StorageError — never the raw driver exception.
    exc = _capture_integrity_error(
        storage._connection(),
        "INSERT INTO users (id, display_name, email, status, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        ("usr_test_0010", None, "null@example.com", "active", "", ""),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.StorageError)
    assert not isinstance(
        translated,
        (contract.DuplicateEntityError, contract.ReferenceNotFoundError),
    )


# ---------------------------------------------------------------------------
# 3. No driver text leaks above the translation
# ---------------------------------------------------------------------------


def test_non_integrity_driver_errors_translate_to_generic_storage_error() -> None:
    # OperationalError (lock timeout, disk fault, ...) must also surface as a
    # domain StorageError with no driver text — the contract admits no raw
    # sqlite3 exception above the adapter.
    translated = sqlite_adapter._translate_driver_error(
        sqlite3.OperationalError("database is locked")
    )
    assert isinstance(translated, contract.StorageError)
    assert not isinstance(
        translated,
        (contract.DuplicateEntityError, contract.ReferenceNotFoundError),
    )
    assert "locked" not in str(translated)
    # Integrity failures keep their precise mapping through the generic path.
    exact = sqlite_adapter._translate_driver_error(
        sqlite3.IntegrityError("UNIQUE constraint failed: users.email")
    )
    assert isinstance(exact, contract.DuplicateEntityError)
    assert exact.kind is contract.DuplicateEntityKind.USER_EMAIL


@pytest.mark.parametrize(
    "message",
    [
        "UNIQUE constraint failed: users.email",
        "UNIQUE constraint failed: users.id",
        "UNIQUE constraint failed: external_identities.provider, "
        "external_identities.provider_subject, external_identities.provider_tenant",
        "FOREIGN KEY constraint failed",
        "NOT NULL constraint failed: users.display_name",
    ],
)
def test_translated_messages_never_embed_sql_or_driver_text(message: str) -> None:
    translated = sqlite_adapter._translate_integrity_error(sqlite3.IntegrityError(message))
    assert isinstance(translated, contract.StorageError)
    text = str(translated).lower()
    for leak in ("constraint failed", "unique", "foreign key", "insert", "table", "pragma"):
        assert leak not in text, (message, text)


def test_translation_recognizes_errorname_even_without_known_message() -> None:
    # Defensive path: a driver error carrying the FK ``sqlite_errorname``
    # translates even if the human-readable message were ever to change
    # shape (the subclass attribute shadows the driver's read-only one).
    class SpoofedForeignKey(sqlite3.IntegrityError):
        sqlite_errorname = "SQLITE_CONSTRAINT_FOREIGNKEY"  # type: ignore[assignment]

    translated = sqlite_adapter._translate_integrity_error(
        SpoofedForeignKey("some future sqlite wording")
    )
    assert isinstance(translated, contract.ReferenceNotFoundError)
