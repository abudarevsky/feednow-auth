"""Unit tests for the Phase 02 task-2 SQLite core (schema, connection, codecs).

Scope per the breakdown: pure helpers and adapter plumbing only — codecs,
mappers, DDL/PRAGMA behavior, cursor encoding, thread-local connections, and
the factory surface. Storage *behavior* (duplicates, CAS, pagination,
provisioning) is owned by the conformance suite added in task 3+; there are
deliberately no behavior tests here.

Verify lines covered:

1. Schema init is idempotent on the same file (plus the five unique indexes
   and ``user_version`` stamp; an unknown stamped version is rejected).
2. FK enforcement is live even after prior DML on the connection — a raw
   FK-violating insert raises, proving the PRAGMA was not no-oped.
3. Timestamp round-trip preserves microseconds and zero-µs values stay
   fixed-width (chronological sort == lexicographic sort on a mixed sample).
4. Cursor round-trip and tamper rejection (plus the foreign-scope rule).
5. Mappers reject corrupt enums/prefixes (and rebuild domain objects from
   real rows).
6. The factory object is ``Storage``-compatible against the task-1 stub check
   (``isinstance`` under ``runtime_checkable``); the skeleton tripwire now
   asserts the completed surface — with task 7 landed, no protocol method may
   remain a ``NotImplementedError`` stub.
"""

from __future__ import annotations

import base64
import inspect
import sqlite3
import threading
from datetime import UTC, datetime, timedelta, timezone
from typing import get_protocol_members

import pytest
from pydantic import ValidationError

import app.storage.contract as contract
from app.models import (
    ApiKey,
    ApiKeyEnvironment,
    ApiKeyStatus,
    AuditEvent,
    ExternalIdentity,
    IdentityProvider,
    Membership,
    MembershipRole,
    MembershipStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
    User,
    UserStatus,
)
from app.models.ids import (
    ApiKeyId,
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    UserId,
)
from app.storage import sqlite as sqlite_adapter
from app.storage.sqlite import (
    CURSOR_SCOPE_API_KEYS,
    CURSOR_SCOPE_MEMBERSHIPS,
    SCHEMA_VERSION,
    SQLiteStorage,
    api_key_from_row,
    audit_event_from_row,
    decode_cursor,
    decode_json_column,
    decode_provider_tenant,
    decode_timestamp,
    encode_cursor,
    encode_json_column,
    encode_provider_tenant,
    encode_timestamp,
    external_identity_from_row,
    membership_from_row,
    open_sqlite_storage,
    organization_from_row,
    user_from_row,
)

# ---------------------------------------------------------------------------
# Deterministic domain builders (literal prefix-valid ids, fixed timestamps —
# the same rule the conformance-suite builders follow).
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)


def make_user(user_id: str = "usr_test_0001", email: str = "test@example.com") -> User:
    return User(
        id=UserId(user_id),
        display_name="Test User",
        email=email,
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_identity(user: User | None = None, tenant: str | None = None) -> ExternalIdentity:
    owner = user or make_user()
    return ExternalIdentity(
        id=ExternalIdentityId("extid_test_0001"),
        user_id=owner.id,
        provider=IdentityProvider.COGNITO,
        provider_subject="11111111-2222-3333-4444-555555555555",
        provider_tenant=tenant,
        created_at=_T0,
    )


def make_organization() -> Organization:
    return Organization(
        id=OrganizationId("org_test_0001"),
        name="Test Org",
        slug="test-org",
        type=OrganizationType.PERSONAL,
        status=OrganizationStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_membership() -> Membership:
    return Membership(
        id=MembershipId("mem_test_0001"),
        organization_id=OrganizationId("org_test_0001"),
        user_id=UserId("usr_test_0001"),
        role=MembershipRole.OWNER,
        status=MembershipStatus.ACTIVE,
        created_at=_T0,
    )


def make_api_key() -> ApiKey:
    return ApiKey(
        id=ApiKeyId("key_test_0001"),
        organization_id=OrganizationId("org_test_0001"),
        created_by_user_id=UserId("usr_test_0001"),
        name="ci",
        key_id="01JTESTKEYID",
        key_prefix="fn_live_01J",
        secret_hash="a" * 64,
        environment=ApiKeyEnvironment.LIVE,
        scopes=[
            "vispector:inspection:run",
            "vispector:inspection:read",
            "vispector:inspection:run",
        ],
        status=ApiKeyStatus.ACTIVE,
        created_at=_T1,
    )


def make_audit_event() -> AuditEvent:
    return AuditEvent(
        id=AuditEventId("aud_test_0001"),
        organization_id=OrganizationId("org_test_0001"),
        actor_type="user",
        actor_id=UserId("usr_test_0001"),
        action="user.provisioned",
        metadata={"nested": {"list": [1, 2.5, True, None]}},
        created_at=_T0,
    )


# ---------------------------------------------------------------------------
# Raw-row helpers: task 2 has no contract write methods yet, so tests insert
# through the adapter's own connection using the codecs under test.
# ---------------------------------------------------------------------------


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


def _insert_organization(conn: sqlite3.Connection, organization: Organization) -> None:
    conn.execute(
        "INSERT INTO organizations"
        " (id, name, slug, type, status, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(organization.id),
            organization.name,
            organization.slug,
            str(organization.type),
            str(organization.status),
            encode_timestamp(organization.created_at),
            encode_timestamp(organization.updated_at),
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


def _insert_membership(conn: sqlite3.Connection, membership: Membership) -> None:
    conn.execute(
        "INSERT INTO memberships (id, organization_id, user_id, role, status, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(membership.id),
            str(membership.organization_id),
            str(membership.user_id),
            str(membership.role),
            str(membership.status),
            encode_timestamp(membership.created_at),
        ),
    )


def _insert_api_key(conn: sqlite3.Connection, api_key: ApiKey) -> None:
    conn.execute(
        "INSERT INTO api_keys"
        " (id, organization_id, created_by_user_id, name, key_id, key_prefix, secret_hash,"
        "  environment, scopes, status, created_at, last_used_at, expires_at, revoked_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(api_key.id),
            str(api_key.organization_id),
            str(api_key.created_by_user_id),
            api_key.name,
            api_key.key_id,
            api_key.key_prefix,
            api_key.secret_hash,
            str(api_key.environment),
            encode_json_column(api_key.scopes),
            str(api_key.status),
            encode_timestamp(api_key.created_at),
            None if api_key.last_used_at is None else encode_timestamp(api_key.last_used_at),
            None if api_key.expires_at is None else encode_timestamp(api_key.expires_at),
            None if api_key.revoked_at is None else encode_timestamp(api_key.revoked_at),
        ),
    )


def _insert_audit_event(conn: sqlite3.Connection, event: AuditEvent) -> None:
    conn.execute(
        "INSERT INTO audit_events"
        " (id, organization_id, actor_type, actor_id, action, target_type, target_id,"
        "  metadata, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(event.id),
            str(event.organization_id),
            event.actor_type,
            str(event.actor_id),
            event.action,
            event.target_type,
            event.target_id,
            encode_json_column(event.metadata),
            encode_timestamp(event.created_at),
        ),
    )


def _seed_all(conn: sqlite3.Connection) -> None:
    """Insert one row per table (parents first) and commit."""
    _insert_user(conn, make_user())
    _insert_organization(conn, make_organization())
    _insert_identity(conn, make_identity())
    _insert_membership(conn, make_membership())
    _insert_api_key(conn, make_api_key())
    _insert_audit_event(conn, make_audit_event())
    conn.commit()


def _fetch_one(conn: sqlite3.Connection, table: str) -> sqlite3.Row:
    return conn.execute(f"SELECT * FROM {table}").fetchone()


@pytest.fixture
def storage(tmp_path) -> SQLiteStorage:  # type: ignore[no-untyped-def]
    adapter = SQLiteStorage(tmp_path / "core.sqlite")
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# 1. Schema init: idempotent, complete, version-stamped
# ---------------------------------------------------------------------------


def test_schema_init_is_idempotent_on_the_same_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "twice.sqlite"
    first = SQLiteStorage(path)
    first.close()
    # Reopening an initialized file must not raise or recreate anything.
    second = SQLiteStorage(path)
    second._ensure_schema(second._connection())
    version = second._connection().execute("PRAGMA user_version").fetchone()[0]
    assert version == SCHEMA_VERSION
    second.close()


def test_schema_creates_six_tables_and_five_unique_indexes(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    objects = conn.execute("SELECT type, name FROM sqlite_master").fetchall()
    names = {(row["type"], row["name"]) for row in objects}
    for table in (
        "users",
        "external_identities",
        "organizations",
        "memberships",
        "api_keys",
        "audit_events",
    ):
        assert ("table", table) in names, table
    for index in sqlite_adapter.UNIQUE_INDEX_NAMES:
        assert ("index", index) in names, index
    assert len(sqlite_adapter.UNIQUE_INDEX_NAMES) == 5
    assert len(sqlite_adapter.TABLE_NAMES) == 6


def test_unique_indexes_are_effective_at_the_constraint_level(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # A UNIQUE index must actually reject a duplicate tuple, including the
    # ''-normalized tenant (proves the indexed columns, not just their names).
    storage = SQLiteStorage(tmp_path / "unique.sqlite")
    conn = storage._connection()
    _insert_user(conn, make_user())
    _insert_user(conn, make_user(user_id="usr_test_0002", email="other@example.com"))
    _insert_identity(conn, make_identity())
    # Same (provider, subject, tenant=None→'') tuple under a different,
    # existing user: the identity UNIQUE index, not the FK, must reject it.
    with pytest.raises(sqlite3.IntegrityError):
        _insert_identity(
            conn,
            make_identity(user=make_user(user_id="usr_test_0002"), tenant=None),
        )
    conn.rollback()
    storage.close()


def test_unknown_stamped_schema_version_is_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "future.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 42")
    conn.commit()
    conn.close()
    with pytest.raises(contract.StorageError, match="unsupported schema version"):
        SQLiteStorage(path)


# ---------------------------------------------------------------------------
# 2. PRAGMA discipline and FK enforcement
# ---------------------------------------------------------------------------


def test_pragmas_are_active_on_every_connection(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_fk_enforcement_is_live_even_after_prior_dml(storage: SQLiteStorage) -> None:
    # The PRAGMA must not have been no-oped by the implicit transaction DML
    # opens: insert + commit first, then an FK-violating raw insert still
    # raises FOREIGN KEY.
    conn = storage._connection()
    _insert_user(conn, make_user())
    conn.commit()
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        conn.execute(
            "INSERT INTO external_identities"
            " (id, user_id, provider, provider_subject, provider_tenant, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                "extid_orphan_1",
                "usr_does_not_exist",
                "cognito",
                "subject-1",
                "",
                encode_timestamp(_T0),
            ),
        )
    conn.rollback()


def test_worker_thread_connections_get_the_same_pragmas(storage: SQLiteStorage) -> None:
    results: dict[str, tuple[int, str, int]] = {}

    def worker(name: str) -> None:
        conn = storage._connection()
        results[name] = (
            conn.execute("PRAGMA foreign_keys").fetchone()[0],
            conn.execute("PRAGMA journal_mode").fetchone()[0],
            conn.execute("PRAGMA busy_timeout").fetchone()[0],
        )

    threads = [threading.Thread(target=worker, args=(name,)) for name in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == {"a": (1, "wal", 5000), "b": (1, "wal", 5000)}


def test_connections_are_thread_local(storage: SQLiteStorage) -> None:
    main_conn = storage._connection()
    other: dict[str, sqlite3.Connection] = {}
    thread = threading.Thread(target=lambda: other.setdefault("conn", storage._connection()))
    thread.start()
    thread.join()
    assert other["conn"] is not main_conn
    assert storage._connection() is main_conn


# ---------------------------------------------------------------------------
# 3. Timestamp codec: fixed-width, microsecond-preserving, sortable
# ---------------------------------------------------------------------------


def test_timestamp_round_trip_preserves_microseconds() -> None:
    for value in (_T0, _T1, datetime(2026, 1, 2, 3, 4, 5, 1, tzinfo=UTC)):
        encoded = encode_timestamp(value)
        assert encoded.endswith("Z")
        assert decode_timestamp(encoded) == value


def test_zero_microsecond_values_stay_fixed_width() -> None:
    encoded_zero = encode_timestamp(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))
    encoded_micro = encode_timestamp(datetime(2026, 1, 1, 0, 0, 0, 1, tzinfo=UTC))
    assert encoded_zero == "2026-01-01T00:00:00.000000Z"
    assert len(encoded_zero) == len(encoded_micro) == 27


def test_mixed_sample_sorts_chronologically_and_lexicographically_alike() -> None:
    sample = [
        datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
        datetime(2026, 1, 1, 0, 0, 0, 999999, tzinfo=UTC),
        datetime(2026, 3, 1, 12, 0, 0, 1, tzinfo=UTC),
        datetime(2025, 12, 31, 23, 59, 59, 500000, tzinfo=UTC),
        datetime(2026, 2, 28, 23, 1, 0, tzinfo=UTC),
        datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
    ]
    encoded = [encode_timestamp(value) for value in sample]
    assert len(set(map(len, encoded))) == 1
    chronological = sorted(sample)
    lexicographic = [decode_timestamp(text) for text in sorted(encoded)]
    assert chronological == lexicographic


def test_non_utc_offsets_are_normalized_to_utc_on_encode() -> None:
    plus_two = datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    assert encode_timestamp(plus_two) == "2026-09-12T10:00:00.000000Z"


def test_decode_rejects_naive_and_malformed_stored_text() -> None:
    with pytest.raises(ValueError, match="naive"):
        decode_timestamp("2026-09-12T10:00:00")
    with pytest.raises(ValueError):
        decode_timestamp("not-a-timestamp")


# ---------------------------------------------------------------------------
# 4. Tenant and JSON codecs
# ---------------------------------------------------------------------------


def test_tenant_normalization_round_trip() -> None:
    assert encode_provider_tenant(None) == ""
    assert decode_provider_tenant("") is None
    for tenant in ("shop.example.myshopify.com", "a"):
        assert decode_provider_tenant(encode_provider_tenant(tenant)) == tenant


def test_json_codecs_round_trip_scopes_exactly() -> None:
    scopes = ["vispector:inspection:run", "vispector:inspection:read", "vispector:inspection:run"]
    assert decode_json_column(encode_json_column(scopes)) == scopes


def test_json_codecs_round_trip_nested_metadata() -> None:
    metadata = {
        "nested": {"list": [1, 2.5, True, None, {"deep": "value"}]},
        "count": 0,
        "unicode": "ünïcødé",
    }
    assert decode_json_column(encode_json_column(metadata)) == metadata


# ---------------------------------------------------------------------------
# 5. Keyset cursors: opaque round-trip, tamper/foreign rejection
# ---------------------------------------------------------------------------


def test_cursor_round_trip_returns_the_position_key() -> None:
    cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T1, "mem_test_0001")
    assert isinstance(cursor, str) and cursor
    created_at, entity_id = decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, cursor)
    assert created_at == _T1
    assert entity_id == "mem_test_0001"


def test_cursor_is_opaque_text_without_readable_position() -> None:
    cursor = encode_cursor(CURSOR_SCOPE_API_KEYS, _T1, "key_test_0001")
    assert "2026-09-12" not in cursor
    assert "key_test_0001" not in cursor


def test_foreign_scope_cursor_is_rejected() -> None:
    memberships_cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T0, "mem_test_0001")
    with pytest.raises(contract.InvalidCursorError, match="different list"):
        decode_cursor(CURSOR_SCOPE_API_KEYS, memberships_cursor)


@pytest.mark.parametrize(
    "tampered",
    [
        "",
        "!!!not-base64!!!",
        "zzzz",
        "c2NvcGVk",  # valid base64 of "scoped": decodes, but is not JSON
    ],
)
def test_malformed_or_tampered_cursors_raise_invalid_cursor(tampered: str) -> None:
    with pytest.raises(contract.InvalidCursorError):
        decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, tampered)


@pytest.mark.parametrize(
    "payload",
    [
        "[1,2]",  # not an object
        '{"scope":"memberships"}',  # missing position fields
        '{"scope":"memberships","created_at":"x","id":5}',  # non-string id
        '{"scope":"memberships","created_at":"2026-01-01T00:00:00","id":"mem_test_0001"}',
        # naive (Z-less) stored position
    ],
)
def test_structurally_invalid_cursor_payloads_are_rejected(payload: str) -> None:
    token = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    with pytest.raises(contract.InvalidCursorError):
        decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, token)


def test_truncation_and_extension_of_a_real_cursor_are_rejected() -> None:
    cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T1, "mem_test_0001")
    for tampered in (cursor[:-2], cursor + "AAAA", cursor[: len(cursor) // 2] + "%%"):
        with pytest.raises(contract.InvalidCursorError):
            decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, tampered)


# ---------------------------------------------------------------------------
# 6. Row → domain mappers
# ---------------------------------------------------------------------------


def test_mappers_rebuild_domain_objects_from_real_rows(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    _seed_all(conn)
    assert user_from_row(_fetch_one(conn, "users")) == make_user()
    assert organization_from_row(_fetch_one(conn, "organizations")) == make_organization()
    assert external_identity_from_row(_fetch_one(conn, "external_identities")) == make_identity()
    assert membership_from_row(_fetch_one(conn, "memberships")) == make_membership()
    assert api_key_from_row(_fetch_one(conn, "api_keys")) == make_api_key()
    assert audit_event_from_row(_fetch_one(conn, "audit_events")) == make_audit_event()


def test_identity_mapper_restores_none_tenant_from_normalized_empty(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    _insert_user(conn, make_user())
    _insert_identity(conn, make_identity(tenant=None))
    conn.commit()
    row = _fetch_one(conn, "external_identities")
    assert row["provider_tenant"] == ""
    assert external_identity_from_row(row).provider_tenant is None


def test_mapper_rejects_corrupt_enum_and_id_prefix(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    _insert_user(conn, make_user())
    conn.commit()
    conn.execute("UPDATE users SET status = 'banana'")
    conn.commit()
    with pytest.raises(ValidationError):
        user_from_row(_fetch_one(conn, "users"))
    conn.execute("UPDATE users SET status = 'active', id = 'bogus_0001'")
    conn.commit()
    with pytest.raises(ValidationError):
        user_from_row(_fetch_one(conn, "users"))


def test_mapper_rejects_corrupt_timestamp_tripwire(storage: SQLiteStorage) -> None:
    conn = storage._connection()
    _insert_user(conn, make_user())
    conn.commit()
    conn.execute("UPDATE users SET created_at = 'yesterday'")
    conn.commit()
    with pytest.raises(ValueError, match="isoformat"):
        user_from_row(_fetch_one(conn, "users"))


# ---------------------------------------------------------------------------
# 7. Factory surface and task-2 boundary
# ---------------------------------------------------------------------------


def test_factory_returns_storage_compatible_object(tmp_path) -> None:  # type: ignore[no-untyped-def]
    storage = open_sqlite_storage(tmp_path / "factory.sqlite")
    # Same isinstance check the task-1 stub satisfies (runtime_checkable).
    assert isinstance(storage, contract.Storage)
    storage.close()


def test_closed_instance_is_not_reusable(tmp_path) -> None:  # type: ignore[no-untyped-def]
    storage = SQLiteStorage(tmp_path / "closed.sqlite")
    storage.close()
    with pytest.raises(contract.StorageError, match="closed"):
        storage._connection()


def test_contract_surface_has_no_remaining_stubs() -> None:
    # The task-2 skeleton existed so a forgotten method failed loudly with
    # NotImplementedError; task 7 completed the surface with provision_user.
    # Definition-of-done tripwire (acceptance: "all 18 contract methods
    # implemented"): every Storage protocol member is implemented on the
    # adapter — no method may still be a stub.
    members = get_protocol_members(contract.Storage)
    assert len(members) == 18, members
    for name in sorted(members):
        method = getattr(SQLiteStorage, name)
        assert "raise NotImplementedError" not in inspect.getsource(method), name
