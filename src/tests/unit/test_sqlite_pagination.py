"""Unit tests for the Phase 02 task-8 pagination determinism pass.

End-to-end traversal semantics (full-order walks, clamped-limit echoes,
foreign/garbage cursors, keyset-under-insert) are owned by the conformance
suite; this module pins the SQLite-internal guarantees the suite cannot
express adapter-neutrally: keyset tie-breaking through the real SQL on
identical ``created_at`` rows, chronological == lexicographic order for mixed
zero-microsecond/microsecond stored TEXT, a cursor positioned beyond the end
of the data, and the adapter's minimum-side limit re-clamp (task 4's unit
file already covers the maximum side).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

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
from app.models.pagination import MIN_PAGE_LIMIT, PageParams
from app.storage.sqlite import (
    CURSOR_SCOPE_MEMBERSHIPS,
    SQLiteStorage,
    decode_cursor,
    encode_cursor,
    encode_timestamp,
)

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)  # zero microseconds
_T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)
_T2 = datetime(2026, 9, 12, 11, 0, 0, 654321, tzinfo=UTC)
_T3 = datetime(2026, 9, 12, 11, 0, 0, tzinfo=UTC)  # same second as _T2, zero µs


def make_user(user_id: str = "usr_test_0001") -> User:
    return User(
        id=UserId(user_id),
        display_name="Test User",
        email=f"{user_id}@example.test",
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_organization(organization_id: str = "org_test_0001") -> Organization:
    return Organization(
        id=OrganizationId(organization_id),
        name="Test Org",
        slug=f"org-{organization_id}",
        type=OrganizationType.PERSONAL,
        status=OrganizationStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_membership(
    membership_id: str = "mem_test_0001",
    user_id: str = "usr_test_0001",
    created_at: datetime = _T0,
) -> Membership:
    return Membership(
        id=MembershipId(membership_id),
        organization_id=OrganizationId("org_test_0001"),
        user_id=UserId(user_id),
        role=MembershipRole.MEMBER,
        status=MembershipStatus.ACTIVE,
        created_at=created_at,
    )


@pytest.fixture
def storage(tmp_path) -> SQLiteStorage:  # type: ignore[no-untyped-def]
    adapter = SQLiteStorage(tmp_path / "pagination.sqlite")
    yield adapter
    adapter.close()


def _seed_org_and_users(storage: SQLiteStorage, count: int) -> None:
    storage.create_organization(make_organization())
    for index in range(count):
        storage.create_user(make_user(user_id=f"usr_test_{index + 1:04d}"))


# ---------------------------------------------------------------------------
# 1. Tie-breaking through the real SQL: identical created_at rows walk in id
#    order, and every cursor names the last *returned* position
# ---------------------------------------------------------------------------


def test_identical_created_at_rows_traverse_in_id_order(storage: SQLiteStorage) -> None:
    _seed_org_and_users(storage, 3)
    for index in (1, 2, 3):
        storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                user_id=f"usr_test_{index:04d}",
                created_at=_T1,
            )
        )
    cursor: str | None = None
    visited: list[MembershipId] = []
    for _ in range(4):  # one iteration more than the page count: proves termination
        page = storage.list_memberships(
            OrganizationId("org_test_0001"),
            PageParams(limit=1, cursor=cursor),
        )
        visited.extend(membership.id for membership in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert visited == [
        MembershipId("mem_test_0001"),
        MembershipId("mem_test_0002"),
        MembershipId("mem_test_0003"),
    ]


def test_tie_page_cursor_decodes_to_last_returned_position(storage: SQLiteStorage) -> None:
    # Two rows share created_at; a page ending mid-tie must encode the id
    # tiebreaker so the next page resumes inside the tie, not around it.
    _seed_org_and_users(storage, 2)
    for index in (1, 2):
        storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                user_id=f"usr_test_{index:04d}",
                created_at=_T1,
            )
        )
    page = storage.list_memberships(OrganizationId("org_test_0001"), PageParams(limit=1))
    assert [membership.id for membership in page.items] == [MembershipId("mem_test_0001")]
    assert page.next_cursor is not None
    assert decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, page.next_cursor) == (_T1, "mem_test_0001")
    second = storage.list_memberships(
        OrganizationId("org_test_0001"),
        PageParams(limit=1, cursor=page.next_cursor),
    )
    assert [membership.id for membership in second.items] == [MembershipId("mem_test_0002")]
    assert second.next_cursor is None


# ---------------------------------------------------------------------------
# 2. Mixed-precision timestamps: chronological order == lexicographic order
#    of the stored fixed-width TEXT (the property keyset pagination relies on)
# ---------------------------------------------------------------------------


def test_mixed_precision_timestamps_traverse_chronologically(storage: SQLiteStorage) -> None:
    _seed_org_and_users(storage, 4)
    # id order deliberately contradicts chronological order: mem_0001 is the
    # *latest* row and mem_0004 the earliest, with the zero-µs/microsecond
    # same-second pair (_T3 vs _T2) in the middle.
    rows = (
        ("mem_test_0001", _T2),
        ("mem_test_0002", _T3),
        ("mem_test_0003", _T1),
        ("mem_test_0004", _T0),
    )
    for index, (membership_id, created_at) in enumerate(rows, start=1):
        storage.create_membership(
            make_membership(
                membership_id=membership_id,
                user_id=f"usr_test_{index:04d}",
                created_at=created_at,
            )
        )
    cursor: str | None = None
    visited: list[MembershipId] = []
    while True:
        page = storage.list_memberships(
            OrganizationId("org_test_0001"),
            PageParams(limit=1, cursor=cursor),
        )
        visited.extend(membership.id for membership in page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    assert visited == [
        MembershipId("mem_test_0004"),
        MembershipId("mem_test_0003"),
        MembershipId("mem_test_0002"),
        MembershipId("mem_test_0001"),
    ]
    # The raw column order agrees with the domain order: fixed-width TEXT
    # sorts lexicographically exactly as it sorts chronologically.
    stored = [
        row["created_at"]
        for row in storage._connection()
        .execute("SELECT created_at FROM memberships ORDER BY created_at ASC, id ASC")
        .fetchall()
    ]
    assert stored == [encode_timestamp(value) for value in (_T0, _T1, _T3, _T2)]


# ---------------------------------------------------------------------------
# 3. A cursor positioned beyond the end of the data is an empty final page,
#    not an error (the position may legitimately have been deleted since)
# ---------------------------------------------------------------------------


def test_cursor_past_the_end_returns_empty_final_page(storage: SQLiteStorage) -> None:
    _seed_org_and_users(storage, 1)
    storage.create_membership(make_membership())
    future = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T2, "mem_test_9999")
    page = storage.list_memberships(
        OrganizationId("org_test_0001"),
        PageParams(limit=5, cursor=future),
    )
    assert page.items == []
    assert page.limit == 5
    assert page.next_cursor is None


# ---------------------------------------------------------------------------
# 4. Defense-in-depth re-clamp on the minimum side (task 4's file pins the
#    maximum side; PageParams validation is bypassed to reach the adapter)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("requested_limit", [0, -5])
def test_adapter_reclamps_limit_below_one_to_the_minimum(
    storage: SQLiteStorage,
    requested_limit: int,
) -> None:
    _seed_org_and_users(storage, 3)
    for index in (1, 2, 3):
        storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                user_id=f"usr_test_{index:04d}",
                created_at=_T1,
            )
        )
    params = PageParams.model_construct(limit=requested_limit, cursor=None)
    page = storage.list_memberships(OrganizationId("org_test_0001"), params)
    assert page.limit == MIN_PAGE_LIMIT
    assert len(page.items) == MIN_PAGE_LIMIT
    # Clamping to 1 still leaves a valid continuation cursor.
    assert page.next_cursor is not None
    assert decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, page.next_cursor) == (_T1, "mem_test_0001")
