"""Unit tests for the Phase 02 task-4 SQLite organization/membership ops.

Scope per the breakdown: storage *behavior* (duplicates, active-membership
filtering, organization scoping, physical delete) is owned by the conformance
suite; this module pins the adapter-internal pieces only — the sqlite3→domain
translation for the constraints task 4 exercises (produced against the *real*
schema so the translated messages are the ones SQLite actually emits), the
keyset ``_build_page`` helper (probe-row trimming, cursor position, scope
tag), the defense-in-depth limit re-clamp, and exact enum string storage.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

import app.storage.contract as contract
from app.models import (
    Membership,
    MembershipRole,
    MembershipStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
    User,
    UserStatus,
)
from app.models.ids import MembershipId, OrganizationId, UserId
from app.models.pagination import MAX_PAGE_LIMIT, Page, PageParams
from app.storage import sqlite as sqlite_adapter
from app.storage.sqlite import (
    CURSOR_SCOPE_API_KEYS,
    CURSOR_SCOPE_MEMBERSHIPS,
    CURSOR_SCOPE_USER_ORGANIZATIONS,
    SQLiteStorage,
    _build_page,
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


def make_membership(
    membership_id: str = "mem_test_0001",
    organization_id: str = "org_test_0001",
    user_id: str = "usr_test_0001",
    status: MembershipStatus = MembershipStatus.ACTIVE,
    created_at: datetime = _T0,
) -> Membership:
    return Membership(
        id=MembershipId(membership_id),
        organization_id=OrganizationId(organization_id),
        user_id=UserId(user_id),
        role=MembershipRole.OWNER,
        status=status,
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
    adapter = SQLiteStorage(tmp_path / "membership-ops.sqlite")
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# 1. Real driver errors for the task-4 constraints translate to the pinned
#    domain vocabulary (no SQL constraint text escapes the adapter)
# ---------------------------------------------------------------------------


def test_organization_slug_violation_translates_to_organization_slug(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    storage.create_organization(make_organization())
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO organizations"
        " (id, name, slug, type, status, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "org_test_0002",
            "Other Org",
            "test-org",
            "customer",
            "active",
            encode_timestamp(_T0),
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.ORGANIZATION_SLUG


def test_organization_primary_key_violation_translates_to_entity_id(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    storage.create_organization(make_organization())
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO organizations"
        " (id, name, slug, type, status, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "org_test_0001",
            "Other Org",
            "other-slug",
            "customer",
            "active",
            encode_timestamp(_T0),
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.ENTITY_ID


def test_membership_pair_violation_translates_to_membership(
    storage: SQLiteStorage,
) -> None:
    conn = storage._connection()
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_membership(make_membership())
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO memberships"
        " (id, organization_id, user_id, role, status, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            "mem_test_0002",
            "org_test_0001",
            "usr_test_0001",
            "member",
            "active",
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.DuplicateEntityError)
    assert translated.kind is contract.DuplicateEntityKind.MEMBERSHIP


@pytest.mark.parametrize(
    ("organization_id", "user_id"),
    [("org_ghost_0001", "usr_test_0001"), ("org_test_0001", "usr_ghost_0001")],
)
def test_membership_foreign_key_violations_translate_to_reference_not_found(
    storage: SQLiteStorage,
    organization_id: str,
    user_id: str,
) -> None:
    conn = storage._connection()
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    exc = _capture_integrity_error(
        conn,
        "INSERT INTO memberships"
        " (id, organization_id, user_id, role, status, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            "mem_test_0009",
            organization_id,
            user_id,
            "owner",
            "active",
            encode_timestamp(_T0),
        ),
    )
    translated = sqlite_adapter._translate_integrity_error(exc)
    assert isinstance(translated, contract.ReferenceNotFoundError)


# ---------------------------------------------------------------------------
# 2. _build_page: limit+1 probe discipline and cursor position
# ---------------------------------------------------------------------------


def _org_position(organization: Organization) -> tuple[datetime, str]:
    return organization.created_at, str(organization.id)


def _org_page(organizations: list[Organization], limit: int) -> Page[Organization]:
    return _build_page(
        organizations,
        scope=CURSOR_SCOPE_USER_ORGANIZATIONS,
        limit=limit,
        position=_org_position,
    )


def test_build_page_trims_probe_row_and_encodes_last_returned_position() -> None:
    organizations = [
        make_organization("org_test_0001", "a", _T0),
        make_organization("org_test_0002", "b", _T1),
        make_organization("org_test_0003", "c", _T2),
    ]
    page = _org_page(organizations, limit=2)
    assert page.items == organizations[:2]
    assert page.limit == 2
    assert page.next_cursor is not None
    # The cursor points at the last *returned* row (never the probe row) and
    # round-trips through the same scope to that (created_at, id) position.
    assert decode_cursor(CURSOR_SCOPE_USER_ORGANIZATIONS, page.next_cursor) == (
        _T1,
        "org_test_0002",
    )


def test_build_page_exact_fit_has_no_cursor() -> None:
    # A limit+1 fetch returning exactly ``limit`` rows means the probe found
    # nothing: the last page must report next_cursor=None.
    organizations = [
        make_organization("org_test_0001", "a", _T0),
        make_organization("org_test_0002", "b", _T1),
    ]
    page = _org_page(organizations, limit=2)
    assert page.items == organizations
    assert page.next_cursor is None


def test_build_page_empty_fetch_returns_empty_page() -> None:
    page = _org_page([], limit=5)
    assert page.items == []
    assert page.limit == 5
    assert page.next_cursor is None


# ---------------------------------------------------------------------------
# 3. Adapter list cursor discipline (SQLite-internal guarantees; the suite
#    owns the end-to-end traversal behavior)
# ---------------------------------------------------------------------------


def test_list_memberships_cursor_position_matches_last_returned_row(
    storage: SQLiteStorage,
) -> None:
    storage.create_organization(make_organization())
    storage.create_user(make_user())
    storage.create_user(make_user("usr_test_0002", "two@example.com"))
    storage.create_user(make_user("usr_test_0003", "three@example.com"))
    storage.create_membership(make_membership(membership_id="mem_test_0001", created_at=_T0))
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            user_id="usr_test_0002",
            status=MembershipStatus.DISABLED,
            created_at=_T1,
        )
    )
    storage.create_membership(
        make_membership(membership_id="mem_test_0003", user_id="usr_test_0003", created_at=_T2)
    )
    page = storage.list_memberships(OrganizationId("org_test_0001"), PageParams(limit=2))
    assert [membership.id for membership in page.items] == [
        MembershipId("mem_test_0001"),
        MembershipId("mem_test_0002"),
    ]
    assert page.next_cursor is not None
    assert decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, page.next_cursor) == (
        _T1,
        "mem_test_0002",
    )


def test_foreign_scope_cursors_are_rejected_by_both_membership_lists(
    storage: SQLiteStorage,
) -> None:
    memberships_cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T0, "mem_test_0001")
    organizations_cursor = encode_cursor(CURSOR_SCOPE_USER_ORGANIZATIONS, _T0, "org_test_0001")
    api_keys_cursor = encode_cursor(CURSOR_SCOPE_API_KEYS, _T0, "key_test_0001")
    user_id = UserId("usr_test_0001")
    organization_id = OrganizationId("org_test_0001")
    # The cursor is decoded (and rejected) before any SQL runs, so an empty
    # database still surfaces the domain InvalidCursorError, not a miss.
    for foreign in (memberships_cursor, api_keys_cursor):
        with pytest.raises(contract.InvalidCursorError):
            storage.list_user_organizations(user_id, PageParams(limit=5, cursor=foreign))
    for foreign in (organizations_cursor, api_keys_cursor):
        with pytest.raises(contract.InvalidCursorError):
            storage.list_memberships(organization_id, PageParams(limit=5, cursor=foreign))


def test_adapter_reclamps_out_of_range_limit_as_defense_in_depth(
    storage: SQLiteStorage,
) -> None:
    # PageParams clamps at validation time, so a normal caller can never
    # deliver an out-of-range limit; the adapter re-clamps anyway. Bypass
    # validation with model_construct to prove the internal clamp runs.
    params = PageParams.model_construct(limit=MAX_PAGE_LIMIT + 50, cursor=None)
    page = storage.list_memberships(OrganizationId("org_test_0001"), params)
    assert page.limit == MAX_PAGE_LIMIT
    assert page.items == []


# ---------------------------------------------------------------------------
# 4. Exact stored values (SQLite-specific row checks; the contract has no
#    read surface for rows, so this stays adapter-side)
# ---------------------------------------------------------------------------


def test_membership_status_and_role_store_exact_enum_strings(storage: SQLiteStorage) -> None:
    storage.create_user(make_user())
    storage.create_organization(make_organization())
    storage.create_membership(make_membership(status=MembershipStatus.DISABLED, created_at=_T1))
    row = (
        storage._connection()
        .execute(
            "SELECT role, status, created_at FROM memberships WHERE id = ?",
            ("mem_test_0001",),
        )
        .fetchone()
    )
    assert row["role"] == "owner"
    assert row["status"] == "disabled"
    assert row["created_at"] == "2026-09-12T10:00:00.123456Z"


def test_organization_stores_exact_round_trip_values(storage: SQLiteStorage) -> None:
    organization = make_organization(created_at=_T2)
    storage.create_organization(organization)
    row = (
        storage._connection()
        .execute(
            "SELECT type, status, created_at, updated_at FROM organizations WHERE id = ?",
            ("org_test_0001",),
        )
        .fetchone()
    )
    assert row["type"] == "personal"
    assert row["status"] == "active"
    assert row["created_at"] == row["updated_at"] == "2026-09-12T11:00:00.654321Z"
