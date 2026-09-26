"""Unit tests for the Phase 02 task-2 SQLite core (schema, connection, codecs).

Scope per the breakdown: pure helpers and adapter plumbing only — codecs,
mappers, DDL/PRAGMA behavior, cursor encoding, thread-local connections, and
the factory surface. Storage *behavior* (duplicates, CAS, pagination,
provisioning) is owned by the conformance suite added in task 3+; there are
deliberately no behavior tests here.

Verify lines covered:

1. Schema init is idempotent on the same file (plus the four unique indexes
   and ``user_version`` stamp; an unknown stamped version is rejected, the
   Phase 12 ``1 → 2`` migration brings a hand-built v1 file forward with data
   retained and the email constraint retired, and the Phase 13 ``2 → 3``
   migration adds the ``users_application_role_lookup`` index — the ordered
   chain carries a v1 file all the way to the current stamp).
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
from pathlib import Path
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
    OrganizationNameStatus,
    OrganizationStatus,
    OrganizationType,
    User,
    UserStatus,
)
from app.models.enums import ApplicationRole
from app.models.ids import (
    ApiKeyId,
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    UserId,
)
from app.models.pagination import PageParams
from app.storage import sqlite as sqlite_adapter
from app.storage.sqlite import (
    CURSOR_SCOPE_API_KEYS,
    CURSOR_SCOPE_MEMBERSHIPS,
    SCHEMA_VERSION,
    SQLiteStorage,
    api_key_from_row,
    app_session_from_row,
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
    oauth_login_state_from_row,
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


def test_local_admin_counts_search_and_organization_rename(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    organization = make_organization()
    storage.create_organization(organization)
    storage.create_membership(make_membership())
    second = organization.model_copy(
        update={
            "id": OrganizationId("org_test_0002"),
            "name": "Acme Construction",
            "slug": "acme-construction",
            "created_at": _T1,
            "updated_at": _T1,
        }
    )
    storage.create_organization(second)

    page = storage.admin_search_organizations("CONSTRUCT", PageParams(limit=1))
    assert [item.name for item in page.items] == ["Acme Construction"]
    assert page.next_cursor is None
    assert storage.admin_summary() == {"organization_count": 2, "active_membership_count": 1}

    renamed = organization.model_copy(
        update={
            "name": "Confirmed Name",
            "name_status": OrganizationNameStatus.CONFIRMED,
            "updated_at": _T1,
        }
    )
    stored = storage.update_organization(renamed)
    assert stored.name == "Confirmed Name"
    assert stored.name_status is OrganizationNameStatus.CONFIRMED
    assert stored.created_at == _T0


def test_schema_creates_eight_tables_and_four_unique_indexes(storage: SQLiteStorage) -> None:
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
        "oauth_login_states",
        "app_sessions",
    ):
        assert ("table", table) in names, table
    for index in sqlite_adapter.UNIQUE_INDEX_NAMES:
        assert ("index", index) in names, index
    # Phase 12: users_email_unique is gone (email is non-unique); the
    # remaining four unique indexes still exist, and the plain
    # users_email_lookup index backs the exact-lookup read. Phase 13 adds a
    # second plain users index: users_application_role_lookup backs the
    # active-admin guard in transition_application_role (a lookup, never a
    # constraint, so UNIQUE_INDEX_NAMES stays at four).
    assert len(sqlite_adapter.UNIQUE_INDEX_NAMES) == 4
    assert ("index", "users_email_lookup") in names
    assert ("index", "users_email_unique") not in names
    assert ("index", "users_application_role_lookup") in names
    assert len(sqlite_adapter.TABLE_NAMES) == 8


def test_phase_11_session_tables_are_added_to_a_pre_phase_11_database(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    # A database initialized *before* Phase 11 (six base tables, stamped at
    # SCHEMA_VERSION, no session tables) must gain the two additive tables on
    # the next open — CREATE TABLE IF NOT EXISTS at open, no data migration
    # and no version bump.
    path = tmp_path / "pre-phase-11.sqlite"
    conn = sqlite3.connect(path)
    for statement in sqlite_adapter._SCHEMA_STATEMENTS:
        conn.execute(statement)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    conn.close()
    storage = SQLiteStorage(path)
    try:
        tables = {
            row["name"]
            for row in storage._connection()
            .execute("SELECT type, name FROM sqlite_master WHERE type = 'table'")
            .fetchall()
        }
        assert {"oauth_login_states", "app_sessions"} <= tables
        version = storage._connection().execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
    finally:
        storage.close()


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
# 1b. Phase 12: the ordered 1→2 migration of a hand-built v1 file
# ---------------------------------------------------------------------------

#: The exact pre-Phase-12 (v1) base DDL: six tables, no ``application_role``
#: column, and the unique email index. Pinned here as a test fixture (not
#: imported from the adapter, which now carries the v2 shape) so the
#: migration is proven against the real historical file layout.
_V1_SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS users (
        id           TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        email        TEXT NOT NULL,
        status       TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (email)",
    """
    CREATE TABLE IF NOT EXISTS external_identities (
        id               TEXT PRIMARY KEY,
        user_id          TEXT NOT NULL REFERENCES users (id),
        provider         TEXT NOT NULL,
        provider_subject TEXT NOT NULL,
        provider_tenant  TEXT NOT NULL,
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS external_identities_tuple_unique "
    "ON external_identities (provider, provider_subject, provider_tenant)",
    """
    CREATE TABLE IF NOT EXISTS organizations (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        slug       TEXT NOT NULL,
        type       TEXT NOT NULL,
        status     TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS organizations_slug_unique ON organizations (slug)",
    """
    CREATE TABLE IF NOT EXISTS memberships (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations (id),
        user_id         TEXT NOT NULL REFERENCES users (id),
        role            TEXT NOT NULL,
        status          TEXT NOT NULL,
        created_at      TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS memberships_pair_unique "
    "ON memberships (organization_id, user_id)",
    """
    CREATE TABLE IF NOT EXISTS api_keys (
        id                 TEXT PRIMARY KEY,
        organization_id    TEXT NOT NULL REFERENCES organizations (id),
        created_by_user_id TEXT NOT NULL REFERENCES users (id),
        name               TEXT NOT NULL,
        key_id             TEXT NOT NULL,
        key_prefix         TEXT NOT NULL,
        secret_hash        TEXT NOT NULL,
        environment        TEXT NOT NULL,
        scopes             TEXT NOT NULL,
        status             TEXT NOT NULL,
        created_at         TEXT NOT NULL,
        last_used_at       TEXT,
        expires_at         TEXT,
        revoked_at         TEXT
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS api_keys_key_id_unique ON api_keys (key_id)",
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations (id),
        actor_type      TEXT NOT NULL,
        actor_id        TEXT NOT NULL,
        action          TEXT NOT NULL,
        target_type     TEXT,
        target_id       TEXT,
        metadata        TEXT NOT NULL,
        created_at      TEXT NOT NULL
    )
    """,
)

_V1_SEED_USERS = (
    ("usr_test_0001", "first@example.test"),
    ("usr_test_0002", "second@example.test"),
)


def _build_v1_file(path: Path, users: tuple[tuple[str, str], ...]) -> None:
    """Hand-build a stamped v1 database (old DDL, unique email index, seed
    rows written through the v1 column list — no ``application_role``)."""
    conn = sqlite3.connect(path)
    for statement in _V1_SCHEMA_STATEMENTS:
        conn.execute(statement)
    for user_id, email in users:
        conn.execute(
            "INSERT INTO users (id, display_name, email, status, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                user_id,
                f"Seeded {user_id}",
                email,
                "active",
                encode_timestamp(_T0),
                encode_timestamp(_T0),
            ),
        )
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()


def test_v1_file_migrates_to_v2_at_open_backfilling_roles(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # The name keeps its Phase 12 spelling; since Phase 13 the ordered chain
    # runs 1 → 2 → 3, so the file lands on SCHEMA_VERSION (3) with both the
    # email-lookup swap and the application-role index applied.
    path = tmp_path / "v1-migration.sqlite"
    _build_v1_file(path, _V1_SEED_USERS)

    storage = SQLiteStorage(path)
    try:
        conn = storage._connection()
        # Reopened at the current stamp (the chain landed on SCHEMA_VERSION).
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 5
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        # Roles backfilled to 'user' by the ALTER TABLE column default...
        assert [row["application_role"] for row in rows] == ["user", "user"]
        # ...and the pre-existing data survived the ALTER/DROP/CREATE chain intact.
        assert [(row["id"], row["email"], row["display_name"]) for row in rows] == [
            ("usr_test_0001", "first@example.test", "Seeded usr_test_0001"),
            ("usr_test_0002", "second@example.test", "Seeded usr_test_0002"),
        ]
        assert [row["created_at"] for row in rows] == [encode_timestamp(_T0)] * 2
        # Index swaps: the non-unique lookups exist (Phase 12 email, Phase 13
        # role), the unique email constraint is gone.
        indexes = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
        assert "users_email_lookup" in indexes
        assert "users_application_role_lookup" in indexes
        assert "users_email_unique" not in indexes
        # Migrated rows read back as domain objects with the default role,
        # and the flipped constraint holds on a migrated file: a second user
        # may share an address.
        assert storage.get_user(UserId("usr_test_0001")).application_role is ApplicationRole.USER
        storage.create_user(
            User(
                id=UserId("usr_test_0003"),
                display_name="Shadow",
                email="first@example.test",
                status=UserStatus.ACTIVE,
                created_at=_T0,
                updated_at=_T0,
            )
        )
        assert [user.id for user in storage.list_users_by_email("first@example.test")] == [
            UserId("usr_test_0001"),
            UserId("usr_test_0003"),
        ]
    finally:
        storage.close()

    # Second open is a no-op: nothing left to migrate, no error, data kept.
    reopened = SQLiteStorage(path)
    try:
        conn = reopened._connection()
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3
        indexes = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
        assert "users_email_lookup" in indexes
        assert "users_application_role_lookup" in indexes
        assert "users_email_unique" not in indexes
    finally:
        reopened.close()


def test_v4_file_migrates_suspension_timestamp_as_null(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "v4-suspension.sqlite"
    conn = sqlite3.connect(path)
    for statement in sqlite_adapter._SCHEMA_STATEMENTS:
        conn.execute(statement)
    conn.execute("ALTER TABLE organizations DROP COLUMN suspended_at")
    organization = make_organization()
    conn.execute(
        "INSERT INTO organizations "
        "(id, name, slug, type, status, name_status, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(organization.id),
            organization.name,
            organization.slug,
            str(organization.type),
            str(organization.status),
            str(organization.name_status),
            encode_timestamp(organization.created_at),
            encode_timestamp(organization.updated_at),
        ),
    )
    conn.execute("PRAGMA user_version = 4")
    conn.commit()
    conn.close()

    storage = SQLiteStorage(path)
    try:
        assert storage.get_organization(organization.id).suspended_at is None
        assert storage._connection().execute("PRAGMA user_version").fetchone()[0] == 5
    finally:
        storage.close()


# ---------------------------------------------------------------------------
# 1c. Phase 13: the ordered 2→3 migration of a hand-built v2 file
# ---------------------------------------------------------------------------


def test_v2_file_migrates_to_v3_at_open_adding_the_role_index(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # A file at the Phase 12 stamp (v3 DDL minus the role index, stamped 2)
    # is brought forward by the 2 → 3 migration: the non-unique
    # users_application_role_lookup index appears, data is retained, and the
    # stamp lands on SCHEMA_VERSION.
    path = tmp_path / "v2-migration.sqlite"
    conn = sqlite3.connect(path)
    for statement in sqlite_adapter._SCHEMA_STATEMENTS:
        conn.execute(statement)
    conn.execute("ALTER TABLE organizations DROP COLUMN suspended_at")
    conn.execute("ALTER TABLE organizations DROP COLUMN name_status")
    conn.execute("ALTER TABLE api_keys DROP COLUMN service_id")
    conn.execute("DROP INDEX users_application_role_lookup")
    _insert_user(conn, make_user())
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    storage = SQLiteStorage(path)
    try:
        conn = storage._connection()
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 5
        indexes = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
        assert "users_application_role_lookup" in indexes
        assert "users_email_lookup" in indexes
        # Data retained across the migration.
        assert storage.get_user(UserId("usr_test_0001")) == make_user()
    finally:
        storage.close()


@pytest.mark.parametrize("stamped", [6, 7, 42])
def test_stamps_outside_the_known_set_are_rejected(tmp_path, stamped: int) -> None:  # type: ignore[no-untyped-def]
    # Only 0 (fresh init), 1 through 4 (known migration stamps), and 5
    # (current) are accepted; anything else still fails loudly, never
    # reinterpreted.
    path = tmp_path / f"stamp-{stamped}.sqlite"
    conn = sqlite3.connect(path)
    for statement in _V1_SCHEMA_STATEMENTS:
        conn.execute(statement)
    conn.execute(f"PRAGMA user_version = {stamped}")
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


def test_session_mappers_rebuild_domain_objects_from_real_rows(
    storage: SQLiteStorage,
) -> None:
    # Phase 11: the two new mappers rebuild through model_validate from rows
    # written with the same fixed-width timestamp encoding the contract
    # methods use (microseconds preserved).
    live = datetime(2100, 1, 1, 0, 0, 0, 123456, tzinfo=UTC)
    conn = storage._connection()
    conn.execute(
        "INSERT INTO oauth_login_states"
        " (state_id, code_verifier, return_url, expires_at) VALUES (?, ?, ?, ?)",
        ("state_test_0000001", "verifier-" + "0" * 34, "/dashboard", encode_timestamp(live)),
    )
    conn.execute(
        "INSERT INTO app_sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
        ("sess_test_0000001", "usr_test_0001", encode_timestamp(live)),
    )
    conn.commit()
    state = oauth_login_state_from_row(_fetch_one(conn, "oauth_login_states"))
    assert state.state_id == "state_test_0000001"
    assert state.expires_at == live
    session = app_session_from_row(_fetch_one(conn, "app_sessions"))
    assert session.user_id == UserId("usr_test_0001")
    assert session.expires_at == live


def test_session_mappers_reject_corrupt_stored_timestamp(
    storage: SQLiteStorage,
) -> None:
    # Corrupt stored values fail loudly (contract tripwire) on the new mappers
    # exactly as on the Phase 02 ones.
    conn = storage._connection()
    conn.execute(
        "INSERT INTO app_sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
        ("sess_test_0000001", "usr_test_0001", "yesterday"),
    )
    conn.commit()
    with pytest.raises(ValueError, match="isoformat"):
        app_session_from_row(_fetch_one(conn, "app_sessions"))


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
    # NotImplementedError; task 7 completed the surface with provision_user,
    # Phase 04 task 1 added provision_organization, Phase 11 task 6 added
    # the four login-state/session operations, Phase 12 task 2 added
    # list_users_by_email, and Phase 13 task 1 added
    # transition_application_role (all implemented).
    # Definition-of-done tripwire (acceptance: "all contract methods
    # implemented"): every Storage protocol member is implemented on the
    # adapter — no method may still be a stub.
    members = get_protocol_members(contract.Storage)
    assert len(members) == 28, members
    for name in sorted(members):
        method = getattr(SQLiteStorage, name)
        assert "raise NotImplementedError" not in inspect.getsource(method), name
