"""Unit tests for the Phase 02 task-6 SQLite audit-append operation.

Scope per the breakdown: storage *behavior* (duplicate rejection, FK
enforcement end-to-end) is owned by the conformance suite; this module pins
the adapter-internal pieces only — the sqlite3→domain translation for the
constraints task 6 exercises (produced against the *real* schema so the
messages are the ones SQLite actually emits), the row→domain mapper
read-back, the exact stored values (compact metadata JSON, verbatim
``actor_type`` strings, NULL optional targets, fixed-width timestamps), the
metadata codec round-trip through the ``AuditMetadata = dict[str,
JsonValue]`` boundary (nested objects/arrays and non-string scalars), the
fail-loud tripwire on corrupt stored values via ``model_validate``, and the
rollback discipline on a rejected append.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

import app.storage.contract as contract
from app.models import (
    ActorType,
    AuditEvent,
    Organization,
    OrganizationStatus,
    OrganizationType,
    User,
    UserStatus,
)
from app.models.ids import ApiKeyId, AuditEventId, OrganizationId, UserId
from app.storage import sqlite as sqlite_adapter
from app.storage.sqlite import SQLiteStorage, encode_timestamp

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)
_T2 = datetime(2026, 9, 12, 11, 0, 0, 654321, tzinfo=UTC)

#: Raw insert mirroring the task-2 DDL — used to produce *driver-real*
#: integrity errors for the translation table and to plant corrupt stored
#: rows that no adapter method could have written.
_AUDIT_INSERT = (
    "INSERT INTO audit_events"
    " (id, organization_id, actor_type, actor_id, action, target_type,"
    " target_id, metadata, created_at)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def make_user(user_id: str = "usr_test_0001", email: str = "test@example.com") -> User:
    return User(
        id=UserId(user_id),
        display_name="Test User",
        email=email,
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_organization(
    organization_id: str = "org_test_0001",
    slug: str = "test-org",
    created_at: datetime = _T0,
) -> Organization:
    return Organization(
        id=OrganizationId(organization_id),
        name="Test Org",
        slug=slug,
        type=OrganizationType.PERSONAL,
        status=OrganizationStatus.ACTIVE,
        created_at=created_at,
        updated_at=created_at,
    )


def make_audit_event(
    *,
    audit_id: str = "aud_test_0001",
    organization_id: str = "org_test_0001",
    actor_type: ActorType = "user",
    actor_id: str = "usr_test_0001",
    action: str = "user.provisioned",
    target_type: str | None = "user",
    target_id: str | None = "usr_test_0001",
    metadata: dict[str, Any] | None = None,
    created_at: datetime = _T2,
) -> AuditEvent:
    """Fully formed event; the actor-id cast mirrors the §10 consistency rule
    the model validator already enforces (``user`` ↔ ``usr_``,
    ``api_key`` ↔ ``key_``)."""
    return AuditEvent(
        id=AuditEventId(audit_id),
        organization_id=OrganizationId(organization_id),
        actor_type=actor_type,
        actor_id=ApiKeyId(actor_id) if actor_type == "api_key" else UserId(actor_id),
        action=action,
        target_type=target_type,
        target_id=target_id,
        metadata=metadata if metadata is not None else {"conformance": True},
        created_at=created_at,
    )


def _capture_integrity_error(conn: sqlite3.Connection, params: tuple) -> Exception:
    """Run a raw violating insert and return the raised driver error."""
    try:
        conn.execute(_AUDIT_INSERT, params)
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        return exc
    raise AssertionError("expected sqlite3.IntegrityError, insert succeeded")


def _audit_row(storage: SQLiteStorage, audit_id: str) -> sqlite3.Row:
    row = (
        storage._connection()
        .execute(
            "SELECT * FROM audit_events WHERE id = ?",
            (audit_id,),
        )
        .fetchone()
    )
    assert row is not None
    return row


@pytest.fixture
def storage(tmp_path) -> SQLiteStorage:  # type: ignore[no-untyped-def]
    adapter = SQLiteStorage(tmp_path / "audit-ops.sqlite")
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# 1. Real driver errors for the task-6 constraints translate to the pinned
#    domain vocabulary (no SQL constraint text escapes the adapter)
# ---------------------------------------------------------------------------


def test_audit_primary_key_violation_translates_to_entity_id(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    storage.create_organization(make_organization())
    storage.append_audit_event(make_audit_event())
    # Same aud_ id, different action text: the PK collision is what the
    # driver reports, and the contract pins it as a domain conflict.
    exc = _capture_integrity_error(
        conn,
        (
            "aud_test_0001",
            "org_test_0001",
            "user",
            "usr_test_0001",
            "membership.removed",
            None,
            None,
            "{}",
            encode_timestamp(_T2),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.ENTITY_ID


def test_audit_foreign_key_violation_translates_to_reference_not_found(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    exc = _capture_integrity_error(
        conn,
        (
            "aud_test_0009",
            "org_ghost_0001",
            "user",
            "usr_test_0001",
            "user.provisioned",
            None,
            None,
            "{}",
            encode_timestamp(_T2),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.ReferenceNotFoundError)


# ---------------------------------------------------------------------------
# 2. Exact stored values (SQLite-specific row checks; the contract has no
#    read surface for rows, so this stays adapter-side)
# ---------------------------------------------------------------------------


def test_append_returns_none_and_stores_exact_row(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    event = make_audit_event(metadata={"z_key": 1, "a_key": [1, {"nested": True}]})
    assert storage.append_audit_event(event) is None
    row = _audit_row(storage, "aud_test_0001")
    assert row["organization_id"] == "org_test_0001"
    assert row["actor_type"] == "user"
    assert row["actor_id"] == "usr_test_0001"
    assert row["action"] == "user.provisioned"
    assert row["target_type"] == "user"
    assert row["target_id"] == "usr_test_0001"
    # Compact JSON TEXT: insertion order preserved verbatim (no sort_keys),
    # no whitespace — the same codec discipline as scopes.
    assert row["metadata"] == '{"z_key":1,"a_key":[1,{"nested":true}]}'
    assert row["created_at"] == "2026-09-12T11:00:00.654321Z"


def test_api_key_actor_and_null_targets_store_verbatim(storage: SQLiteStorage) -> None:
    storage.create_organization(make_organization())
    # Not every audited action names a distinct target row (§4), and the
    # actor may be an API key (§10): both must store exactly as given.
    event = make_audit_event(
        actor_type="api_key",
        actor_id="key_test_0001",
        action="authorization.denied",
        target_type=None,
        target_id=None,
        metadata={},
        created_at=_T1,
    )
    storage.append_audit_event(event)
    row = _audit_row(storage, "aud_test_0001")
    assert row["actor_type"] == "api_key"
    assert row["actor_id"] == "key_test_0001"
    assert row["target_type"] is None
    assert row["target_id"] is None
    assert row["metadata"] == "{}"
    assert row["created_at"] == "2026-09-12T10:00:00.123456Z"


# ---------------------------------------------------------------------------
# 3. Row→domain mapper read-back and metadata exact round-trip (the §16
#    payload boundary: nested objects/arrays and non-string scalars)
# ---------------------------------------------------------------------------


def test_mapper_read_back_equals_the_appended_event(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    event = make_audit_event()
    storage.append_audit_event(event)
    assert sqlite_adapter.audit_event_from_row(_audit_row(storage, "aud_test_0001")) == event


def test_metadata_round_trips_nested_and_non_string_scalars(storage: SQLiteStorage) -> None:
    storage.create_organization(make_organization())
    metadata: dict[str, Any] = {
        "count": 3,
        "ratio": 0.5,
        "enabled": True,
        "deleted": None,
        "tags": ["a", "b", "a"],
        "nested": {"inner": [1, {"deep": "value"}], "flag": False},
        "unicode": "inspección ✓",
    }
    event = make_audit_event(metadata=metadata)
    storage.append_audit_event(event)
    row = _audit_row(storage, "aud_test_0001")
    # Codec level: decode(encode(x)) is exact, including key order, array
    # order, duplicates, and every non-string scalar type.
    assert sqlite_adapter.decode_json_column(row["metadata"]) == metadata
    # Domain level: the reconstructed AuditEvent carries the identical dict.
    assert sqlite_adapter.audit_event_from_row(row).metadata == metadata


# ---------------------------------------------------------------------------
# 4. Corrupt stored values fail loudly via model_validate (documented
#    tripwire, never silent coercion) — rows planted raw, since no adapter
#    write could produce them
# ---------------------------------------------------------------------------


def test_corrupt_actor_type_fails_loudly_on_read_back(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    storage.create_organization(make_organization())
    conn.execute(
        _AUDIT_INSERT,
        (
            "aud_test_0005",
            "org_test_0001",
            "robot",
            "usr_test_0001",
            "user.provisioned",
            None,
            None,
            "{}",
            encode_timestamp(_T2),
        ),
    )
    conn.commit()
    with pytest.raises(ValidationError):
        sqlite_adapter.audit_event_from_row(_audit_row(storage, "aud_test_0005"))


def test_corrupt_id_prefix_fails_loudly_on_read_back(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    storage.create_organization(make_organization())
    conn.execute(
        _AUDIT_INSERT,
        (
            "not_an_audit_id",
            "org_test_0001",
            "user",
            "usr_test_0001",
            "user.provisioned",
            None,
            None,
            "{}",
            encode_timestamp(_T2),
        ),
    )
    conn.commit()
    with pytest.raises(ValidationError):
        sqlite_adapter.audit_event_from_row(_audit_row(storage, "not_an_audit_id"))


def test_malformed_metadata_json_fails_loudly_on_decode(storage: SQLiteStorage) -> None:
    # decode_json_column is the shared codec for scopes/metadata: stored text
    # that is not JSON raises (ValueError), never a silent default.
    with pytest.raises(ValueError):
        sqlite_adapter.decode_json_column("{not json")


# ---------------------------------------------------------------------------
# 5. Rejected appends roll back and leave the thread-local connection usable
#    (the suite proves the domain error; this proves the transaction
#    discipline inside the adapter)
# ---------------------------------------------------------------------------


def test_rejected_append_rolls_back_and_connection_stays_usable(storage: SQLiteStorage) -> None:
    storage.create_organization(make_organization())
    with pytest.raises(contract.ReferenceNotFoundError):
        storage.append_audit_event(make_audit_event(organization_id="org_ghost_0001"))
    count = storage._connection().execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    assert count == 0
    # A valid append afterwards works on the same connection (the failed
    # implicit transaction was rolled back, not left open).
    assert storage.append_audit_event(make_audit_event()) is None
    assert _audit_row(storage, "aud_test_0001")["organization_id"] == "org_test_0001"
    # And the now-persisted id is protected by the same translated conflict.
    with pytest.raises(contract.DuplicateEntityError) as excinfo:
        storage.append_audit_event(make_audit_event())
    assert excinfo.value.kind is contract.DuplicateEntityKind.ENTITY_ID
    assert storage._connection().execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
