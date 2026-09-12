"""Unit tests for the Phase 02 task-5 SQLite API-key operations.

Scope per the breakdown: storage *behavior* (duplicate rejection, org
scoping, tenancy non-filtering, CAS idempotency end-to-end) is owned by the
conformance suite; this module pins the adapter-internal pieces only — the
sqlite3→domain translation for the constraints task 5 exercises (produced
against the *real* schema so the messages are the ones SQLite actually
emits), the revocation CAS path (conditional-update rowcount →
idempotent-success/not-found translation, including the stored-row
discipline), the keyset cursor wiring of ``list_api_keys``, the
defense-in-depth limit re-clamp, and the exact stored values (JSON scopes,
enum strings, NULL optional timestamps).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

import app.storage.contract as contract
from app.models import (
    ApiKey,
    ApiKeyEnvironment,
    ApiKeyStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
    User,
    UserStatus,
)
from app.models.ids import ApiKeyId, OrganizationId, UserId
from app.models.pagination import MAX_PAGE_LIMIT, PageParams
from app.storage import sqlite as sqlite_adapter
from app.storage.sqlite import (
    CURSOR_SCOPE_API_KEYS,
    CURSOR_SCOPE_MEMBERSHIPS,
    SQLiteStorage,
    decode_cursor,
    encode_cursor,
    encode_timestamp,
)

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)
_T2 = datetime(2026, 9, 12, 11, 0, 0, 654321, tzinfo=UTC)


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


def make_api_key(
    key_id: str = "key_test_0001",
    organization_id: str = "org_test_0001",
    created_by_user_id: str = "usr_test_0001",
    credential_segment: str = "01JTESTKEYID",
    scopes: list[str] | None = None,
    created_at: datetime = _T1,
) -> ApiKey:
    return ApiKey(
        id=ApiKeyId(key_id),
        organization_id=OrganizationId(organization_id),
        created_by_user_id=UserId(created_by_user_id),
        name="unit-key",
        key_id=credential_segment,
        key_prefix=f"fn_live_{credential_segment[:5]}",
        secret_hash="b" * 64,
        environment=ApiKeyEnvironment.LIVE,
        scopes=scopes if scopes is not None else ["vispector:inspection:read"],
        status=ApiKeyStatus.ACTIVE,
        created_at=created_at,
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
    adapter = SQLiteStorage(tmp_path / "api-key-ops.sqlite")
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# 1. Real driver errors for the task-5 constraints translate to the pinned
#    domain vocabulary (no SQL constraint text escapes the adapter)
# ---------------------------------------------------------------------------


def test_credential_segment_violation_translates_to_api_key_id(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_api_key(make_api_key())
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO api_keys"
        " (id, organization_id, created_by_user_id, name, key_id, key_prefix,"
        " secret_hash, environment, scopes, status, created_at, last_used_at,"
        " expires_at, revoked_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "key_test_0002",
            "org_test_0001",
            "usr_test_0001",
            "other",
            "01JTESTKEYID",
            "fn_live_01JTE",
            "b" * 64,
            "live",
            '["vispector:inspection:read"]',
            "active",
            encode_timestamp(_T1),
            None,
            None,
            None,
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.API_KEY_ID


def test_api_key_primary_key_violation_translates_to_entity_id(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_api_key(make_api_key())
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO api_keys"
        " (id, organization_id, created_by_user_id, name, key_id, key_prefix,"
        " secret_hash, environment, scopes, status, created_at, last_used_at,"
        " expires_at, revoked_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "key_test_0001",
            "org_test_0001",
            "usr_test_0001",
            "other",
            "01JOTHERSEGMENT",
            "fn_live_01JOT",
            "b" * 64,
            "live",
            '["vispector:inspection:read"]',
            "active",
            encode_timestamp(_T1),
            None,
            None,
            None,
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.ENTITY_ID


@pytest.mark.parametrize(
    ("organization_id", "created_by_user_id"),
    [("org_ghost_0001", "usr_test_0001"), ("org_test_0001", "usr_ghost_0001")],
)
def test_api_key_foreign_key_violations_translate_to_reference_not_found(
    storage: SQLiteStorage,
    organization_id: str,
    created_by_user_id: str,
) -> None:
    conn = storage._connection()
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO api_keys"
        " (id, organization_id, created_by_user_id, name, key_id, key_prefix,"
        " secret_hash, environment, scopes, status, created_at, last_used_at,"
        " expires_at, revoked_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "key_test_0009",
            organization_id,
            created_by_user_id,
            "orphan",
            "01JORPHANSEG",
            "fn_live_01JOR",
            "b" * 64,
            "live",
            "[]",
            "active",
            encode_timestamp(_T1),
            None,
            None,
            None,
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.ReferenceNotFoundError)


# ---------------------------------------------------------------------------
# 2. Revocation CAS: conditional-update rowcount → hit / idempotent-success /
#    not-found translation, with stored-row discipline (SQLite-internal
#    guarantees; the suite owns the end-to-end concurrency behavior)
# ---------------------------------------------------------------------------


def _api_key_row(storage: SQLiteStorage, key_id: str) -> sqlite3.Row:
    row = storage._connection().execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
    assert row is not None
    return row


def test_revoke_hit_writes_status_and_caller_revoked_at(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_api_key(make_api_key())
    revoked = storage.revoke_api_key(ApiKeyId("key_test_0001"), revoked_at=_T2)
    assert revoked.status is ApiKeyStatus.REVOKED
    assert revoked.revoked_at == _T2
    # Row-level proof the CAS UPDATE (not any read-side coercion) wrote the
    # caller's fixed-width timestamp and exact enum string.
    row = _api_key_row(storage, "key_test_0001")
    assert row["status"] == "revoked"
    assert row["revoked_at"] == "2026-09-12T11:00:00.654321Z"
    assert row["created_at"] == "2026-09-12T10:00:00.123456Z"


def test_revoke_miss_on_revoked_key_is_idempotent_and_untouched(
    storage: SQLiteStorage,
) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_api_key(make_api_key())
    first = storage.revoke_api_key(ApiKeyId("key_test_0001"), revoked_at=_T1)
    # Zero-rowcount CAS on an existing (revoked) key: idempotent success
    # returning stored truth; the loser's distinct revoked_at never touches
    # the row.
    second = storage.revoke_api_key(ApiKeyId("key_test_0001"), revoked_at=_T2)
    assert second == first
    assert second.revoked_at == _T1
    assert _api_key_row(storage, "key_test_0001")["revoked_at"] == "2026-09-12T10:00:00.123456Z"


def test_revoke_miss_on_absent_key_raises_and_writes_nothing(
    storage: SQLiteStorage,
) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    with pytest.raises(contract.EntityNotFoundError):
        storage.revoke_api_key(ApiKeyId("key_missing_0001"), revoked_at=_T1)
    count = storage._connection().execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    assert count == 0


def test_revoke_preserves_unrelated_columns(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    api_key = make_api_key(scopes=["vispector:inspection:run", "vispector:inspection:read"])
    storage.create_api_key(api_key)
    revoked = storage.revoke_api_key(api_key.id, revoked_at=_T2)
    # The CAS UPDATE touches only status/revoked_at; everything else is the
    # originally persisted data (storage mints nothing).
    assert revoked == api_key.model_copy(update={"status": ApiKeyStatus.REVOKED, "revoked_at": _T2})


# ---------------------------------------------------------------------------
# 3. list_api_keys cursor discipline (SQLite-internal guarantees; the suite
#    owns the end-to-end organization-scoped behavior)
# ---------------------------------------------------------------------------


def test_list_api_keys_cursor_position_matches_last_returned_row(
    storage: SQLiteStorage,
) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_api_key(make_api_key(key_id="key_test_0001", created_at=_T0))
    storage.create_api_key(
        make_api_key(
            key_id="key_test_0002",
            credential_segment="01JSEGMENT02",
            created_at=_T1,
        )
    )
    storage.create_api_key(
        make_api_key(
            key_id="key_test_0003",
            credential_segment="01JSEGMENT03",
            created_at=_T2,
        )
    )
    page = storage.list_api_keys(OrganizationId("org_test_0001"), PageParams(limit=2))
    assert [api_key.id for api_key in page.items] == [
        ApiKeyId("key_test_0001"),
        ApiKeyId("key_test_0002"),
    ]
    assert page.next_cursor is not None
    assert decode_cursor(CURSOR_SCOPE_API_KEYS, page.next_cursor) == (_T1, "key_test_0002")


def test_foreign_scope_cursors_are_rejected_by_list_api_keys(
    storage: SQLiteStorage,
) -> None:
    memberships_cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T0, "mem_test_0001")
    api_keys_cursor = encode_cursor(CURSOR_SCOPE_API_KEYS, _T0, "key_test_0001")
    # The cursor is decoded (and rejected) before any SQL runs, so an empty
    # database still surfaces the domain InvalidCursorError, not a miss.
    with pytest.raises(contract.InvalidCursorError):
        storage.list_api_keys(
            OrganizationId("org_test_0001"),
            PageParams(limit=5, cursor=memberships_cursor),
        )
    # ...and the same-scope cursor decodes cleanly (no false rejection).
    page = storage.list_api_keys(
        OrganizationId("org_test_0001"),
        PageParams(limit=5, cursor=api_keys_cursor),
    )
    assert page.items == []


def test_adapter_reclamps_out_of_range_limit_for_api_keys(
    storage: SQLiteStorage,
) -> None:
    # PageParams clamps at validation time, so a normal caller can never
    # deliver an out-of-range limit; the adapter re-clamps anyway. Bypass
    # validation with model_construct to prove the internal clamp runs.
    params = PageParams.model_construct(limit=MAX_PAGE_LIMIT + 50, cursor=None)
    page = storage.list_api_keys(OrganizationId("org_test_0001"), params)
    assert page.limit == MAX_PAGE_LIMIT
    assert page.items == []


# ---------------------------------------------------------------------------
# 4. Exact stored values (SQLite-specific row checks; the contract has no
#    read surface for rows, so this stays adapter-side)
# ---------------------------------------------------------------------------


def test_api_key_stores_exact_enum_strings_and_compact_scopes_json(
    storage: SQLiteStorage,
) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    api_key = make_api_key(
        scopes=[
            "vispector:inspection:run",
            "vispector:inspection:read",
            "vispector:inspection:read",
        ]
    )
    storage.create_api_key(api_key)
    row = _api_key_row(storage, "key_test_0001")
    assert row["environment"] == "live"
    assert row["status"] == "active"
    # Compact JSON TEXT: order and duplicates preserved verbatim, no
    # sort_keys, no whitespace.
    assert row["scopes"] == (
        '["vispector:inspection:run","vispector:inspection:read","vispector:inspection:read"]'
    )
    assert row["created_at"] == "2026-09-12T10:00:00.123456Z"


def test_api_key_optional_timestamps_store_as_null(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_api_key(make_api_key())
    row = _api_key_row(storage, "key_test_0001")
    assert row["last_used_at"] is None
    assert row["expires_at"] is None
    assert row["revoked_at"] is None


def test_api_key_optional_timestamps_round_trip_when_present(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    api_key = make_api_key().model_copy(
        update={"last_used_at": _T0, "expires_at": _T2, "revoked_at": None}
    )
    storage.create_api_key(api_key)
    stored = storage.get_api_key(api_key.id)
    assert stored == api_key
    row = _api_key_row(storage, "key_test_0001")
    assert row["last_used_at"] == "2026-09-12T10:00:00.000000Z"
    assert row["expires_at"] == "2026-09-12T11:00:00.654321Z"
    assert row["revoked_at"] is None
