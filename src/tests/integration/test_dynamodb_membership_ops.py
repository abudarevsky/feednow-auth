"""DynamoDB Local proofs for the organizations + memberships operations (task 4).

Marker-gated (``dynamodb_local``): every test here skips with an explicit reason
unless ``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and reachable, so the default
suite stays green without Docker (``docs/operations.md`` carries the run
command).

These are **direct adapter calls**, not the conformance suite (task 8 runs the
shared 60 cases unchanged): the point is to pin the DynamoDB translation of the
15 org/membership behaviors on the real transactional path — the native
``(organization_id, user_id)`` pair key (decision 2), the ``membership_id``
guard constraint, the ``org_created_at`` denormalization behind the by-user
GSI, the single ``BatchGetItem`` read-back with the trim-before-fetch
batch-boundary rule, the conditional-delete non-idempotency, and keyset
continuation under server-side filtering. Domain inputs come from the suite's
own deterministic builders so the fixtures match the conformance cases exactly.
Every failure path asserts the domain error *class*, the conflict *kind*, an
echo-free message, and — by scanning the tables directly — that the rejected
batch left no residue.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from storage_contract.suite import T0, T1, T2, T3, make_membership, make_organization, make_user

from app.models.enums import MembershipRole, MembershipStatus
from app.models.ids import MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.pagination import Page, PageParams
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    EntityNotFoundError,
    InvalidCursorError,
    ReferenceNotFoundError,
)
from app.storage.dynamodb import (
    SCHEMA,
    ConstraintKind,
    DynamoDbStorage,
    encode_constraint_key,
    encode_timestamp,
)
from tests.support import dynamodb_local as local

pytestmark = pytest.mark.dynamodb_local

# ---------------------------------------------------------------------------
# Harness: one fresh set of seven tables per test (the suite's isolation rule),
# plus raw scans that bypass the adapter under test so residue proofs cannot be
# satisfied by the same code path they audit. The adapter gets its **own** boto3
# resource so ``close()`` in teardown cannot take the harness client with it.
# ---------------------------------------------------------------------------


class _LocalTables:
    """Raw access to one prefixed table set (bypasses the adapter entirely)."""

    def __init__(self, resource: Any, prefix: str) -> None:
        self._resource = resource
        self.prefix = prefix

    def items(self, table: str) -> list[dict[str, Any]]:
        """Every item in one table, strongly consistent."""
        scan = self._resource.Table(f"{self.prefix}{table}").scan(ConsistentRead=True)
        items: list[dict[str, Any]] = list(scan["Items"])
        while scan.get("LastEvaluatedKey"):
            scan = self._resource.Table(f"{self.prefix}{table}").scan(
                ConsistentRead=True, ExclusiveStartKey=scan["LastEvaluatedKey"]
            )
            items.extend(scan["Items"])
        return items

    def item(self, table: str, key: Mapping[str, str]) -> dict[str, Any] | None:
        """One item by full primary key, or ``None`` when absent."""
        response = self._resource.Table(f"{self.prefix}{table}").get_item(
            Key=dict(key), ConsistentRead=True
        )
        item: dict[str, Any] | None = response.get("Item")
        return item


class _DynamoDb:
    """The adapter under test plus its raw table view."""

    def __init__(self, storage: DynamoDbStorage, tables: _LocalTables) -> None:
        self.storage = storage
        self.tables = tables

    def assert_no_leak(self, error: Exception) -> None:
        """No table name, prefix, or driver text may reach a domain message."""
        text = str(error)
        assert self.tables.prefix not in text
        for spec in SCHEMA:
            assert f"{self.tables.prefix}{spec.name}" not in text
        assert "dynamodb" not in text.lower()


@pytest.fixture
def ddb() -> Iterator[_DynamoDb]:
    """Initialized adapter with all seven tables empty (per test)."""
    endpoint = local.require_local_endpoint()
    harness = local.make_dynamodb_resource(endpoint)
    prefix = local.random_table_prefix()
    local.create_tables(prefix, resource=harness)
    storage = local.make_dynamodb_storage(prefix, resource=local.make_dynamodb_resource(endpoint))
    try:
        yield _DynamoDb(storage, _LocalTables(harness, prefix))
    finally:
        storage.close()
        local.delete_tables(prefix, resource=harness)


def _slug_constraint_pk(slug: str) -> str:
    return encode_constraint_key(ConstraintKind.ORGANIZATION_SLUG, slug)


def _membership_guard_pk(membership_id: str) -> str:
    return encode_constraint_key(ConstraintKind.MEMBERSHIP_ID, membership_id)


def _membership_key(organization_id: str, user_id: str) -> dict[str, str]:
    return {"organization_id": organization_id, "user_id": user_id}


def _drain(
    fetch: Callable[[PageParams], Page[Any]],
    *,
    limit: int,
    start_cursor: str | None = None,
) -> list[Page[Any]]:
    """Follow ``next_cursor`` to exhaustion (mirrors the suite's drain helper)."""
    pages: list[Page[Any]] = []
    cursor = start_cursor
    for _ in range(100):
        page = fetch(PageParams(limit=limit, cursor=cursor))
        pages.append(page)
        if page.next_cursor is None:
            return pages
        cursor = page.next_cursor
    raise AssertionError("cursor traversal did not terminate within 100 pages")


# ---------------------------------------------------------------------------
# Organizations: create/round-trip, not-found, and the two conflict kinds
# ---------------------------------------------------------------------------


def test_create_organization_returns_and_persists_the_domain_organization(
    ddb: _DynamoDb,
) -> None:
    organization = make_organization()
    assert ddb.storage.create_organization(organization) == organization
    assert ddb.storage.get_organization(organization.id) == organization
    # Both items landed: the base record and the slug constraint guard.
    assert [item["pk"] for item in ddb.tables.items("organizations")] == [str(organization.id)]
    constraint = ddb.tables.item(
        "unique_constraints", {"pk": _slug_constraint_pk(organization.slug)}
    )
    assert constraint is not None
    assert constraint["pk"] == f"organization_slug#org-{organization.id}"
    assert constraint["kind"] == ConstraintKind.ORGANIZATION_SLUG.value
    assert constraint["entity_id"] == str(organization.id)
    # Decision 2: only the email/identity-tuple items carry ``user_id``.
    assert set(constraint) == {"pk", "kind", "entity_id"}


def test_get_unknown_organization_raises_entity_not_found(ddb: _DynamoDb) -> None:
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.get_organization(OrganizationId("org_missing_0001"))
    ddb.assert_no_leak(excinfo.value)


def test_duplicate_slug_raises_organization_slug_conflict(ddb: _DynamoDb) -> None:
    first = make_organization()
    ddb.storage.create_organization(first)
    # Slug is a constraint, never an identity: a different ``org_`` id with a
    # taken slug is rejected as a domain conflict.
    duplicate = make_organization(organization_id="org_test_0002", slug=first.slug)
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_organization(duplicate)
    assert excinfo.value.kind is DuplicateEntityKind.ORGANIZATION_SLUG
    ddb.assert_no_leak(excinfo.value)
    # The whole transaction rolled back: the winner is intact and the rejected
    # id was never consumed, so a clean (slug-distinct) insert of it succeeds.
    assert ddb.storage.get_organization(first.id) == first
    ddb.storage.create_organization(make_organization(organization_id="org_test_0002"))
    assert len(ddb.tables.items("organizations")) == 2
    assert len(ddb.tables.items("unique_constraints")) == 2


def test_duplicate_organization_id_raises_entity_id_conflict(ddb: _DynamoDb) -> None:
    first = make_organization()
    ddb.storage.create_organization(first)
    # Same ``org_`` id, different slug: the base put's condition fails first in
    # submission order, so this is a record-id conflict, not a slug one.
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_organization(make_organization(slug="another-slug"))
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(excinfo.value)
    assert ddb.storage.get_organization(first.id) == first
    # And the rejected slug's constraint item was never written.
    assert (
        ddb.tables.item("unique_constraints", {"pk": _slug_constraint_pk("another-slug")}) is None
    )


# ---------------------------------------------------------------------------
# Memberships: native pair, guard constraint, denormalized ordering, FK checks
# ---------------------------------------------------------------------------


def test_create_membership_persists_pair_and_denormalized_ordering(ddb: _DynamoDb) -> None:
    user = make_user()
    organization = make_organization(created_at=T0)
    ddb.storage.create_user(user)
    ddb.storage.create_organization(organization)
    membership = make_membership(created_at=T1)
    assert ddb.storage.create_membership(membership) == membership
    # Lookup is keyed by the (organization, user) tuple, never the mem_ id.
    stored = ddb.storage.get_membership(organization_id=organization.id, user_id=user.id)
    assert type(stored) is Membership
    assert stored == membership
    assert stored.role is MembershipRole.OWNER
    raw = ddb.tables.item("memberships", _membership_key(str(organization.id), str(user.id)))
    assert raw is not None
    assert raw["id"] == str(membership.id)
    assert raw["created_at"] == encode_timestamp(T1)
    # by-organization GSI keys order by the *membership* timestamp.
    assert raw["g_org"] == str(organization.id)
    assert raw["g_created"] == f"{encode_timestamp(T1)}#{membership.id}"
    # by-user GSI keys carry the *organization* timestamp (decision 2's
    # denormalization: org is T0, the membership is T1 — the sort key must
    # prove which one it used).
    assert raw["g_user"] == str(user.id)
    assert raw["g_org_created"] == f"{encode_timestamp(T0)}#{organization.id}"
    guard = ddb.tables.item("unique_constraints", {"pk": _membership_guard_pk(str(membership.id))})
    assert guard is not None
    assert guard["kind"] == ConstraintKind.MEMBERSHIP_ID.value
    assert guard["entity_id"] == str(membership.id)
    assert set(guard) == {"pk", "kind", "entity_id"}


def test_duplicate_membership_pair_raises_membership_conflict(ddb: _DynamoDb) -> None:
    user = make_user()
    organization = make_organization()
    ddb.storage.create_user(user)
    ddb.storage.create_organization(organization)
    ddb.storage.create_membership(make_membership())
    # Same (org, user) pair under a different mem_ id and role: the *native*
    # pair condition rejects it as kind="membership" (decision 3's exception —
    # the membership base put is not an entity_id conflict).
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_membership(
            make_membership(membership_id="mem_test_0002", role=MembershipRole.MEMBER)
        )
    assert excinfo.value.kind is DuplicateEntityKind.MEMBERSHIP
    ddb.assert_no_leak(excinfo.value)
    # Rolled back: the loser's guard item was never written and its record id
    # is unconsumed (a fresh-pair insert with it succeeds).
    assert (
        ddb.tables.item("unique_constraints", {"pk": _membership_guard_pk("mem_test_0002")}) is None
    )
    other_user = make_user(user_id="usr_test_0002")
    ddb.storage.create_user(other_user)
    ddb.storage.create_membership(
        make_membership(membership_id="mem_test_0002", user_id="usr_test_0002")
    )


def test_duplicate_membership_record_id_raises_entity_id_conflict(ddb: _DynamoDb) -> None:
    # A taken ``mem_`` id on a *fresh* pair: the native pair condition passes,
    # the guard constraint fails, and the conflict is kind="entity_id".
    user = make_user()
    other_user = make_user(user_id="usr_test_0002")
    first_org = make_organization()
    second_org = make_organization(organization_id="org_test_0002")
    for entity in (user, other_user):
        ddb.storage.create_user(entity)
    for entity in (first_org, second_org):
        ddb.storage.create_organization(entity)
    ddb.storage.create_membership(make_membership())
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_membership(
            make_membership(organization_id="org_test_0002", user_id="usr_test_0002")
        )
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(excinfo.value)
    # The fresh pair left no residue: neither the base item nor a second guard.
    with pytest.raises(EntityNotFoundError):
        ddb.storage.get_membership(organization_id=second_org.id, user_id=other_user.id)
    assert len(ddb.tables.items("memberships")) == 1


def test_get_unknown_membership_tuple_raises_entity_not_found(ddb: _DynamoDb) -> None:
    user = make_user()
    organization = make_organization()
    ddb.storage.create_user(user)
    ddb.storage.create_organization(organization)
    # Both parents exist but no membership row: a miss raises, never None.
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.get_membership(organization_id=organization.id, user_id=user.id)
    ddb.assert_no_leak(excinfo.value)
    with pytest.raises(EntityNotFoundError):
        ddb.storage.get_membership(
            organization_id=OrganizationId("org_ghost_0001"),
            user_id=UserId("usr_ghost_0001"),
        )


def test_membership_for_unknown_user_raises_reference_not_found(ddb: _DynamoDb) -> None:
    organization = make_organization()
    ddb.storage.create_organization(organization)
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.create_membership(make_membership(user_id="usr_ghost_0001"))
    ddb.assert_no_leak(excinfo.value)
    # DynamoDB has no foreign keys: the user ConditionCheck must leave the
    # base item *and* the guard constraint unwritten.
    assert ddb.tables.items("memberships") == []
    assert (
        ddb.tables.item("unique_constraints", {"pk": _membership_guard_pk("mem_test_0001")}) is None
    )


def test_membership_for_unknown_organization_raises_reference_not_found(ddb: _DynamoDb) -> None:
    user = make_user()
    ddb.storage.create_user(user)
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.create_membership(make_membership(organization_id="org_ghost_0001"))
    ddb.assert_no_leak(excinfo.value)
    assert ddb.tables.items("memberships") == []
    assert (
        ddb.tables.item("unique_constraints", {"pk": _membership_guard_pk("mem_test_0001")}) is None
    )


# ---------------------------------------------------------------------------
# Listings: active filter, organization scoping, statuses, physical delete
# ---------------------------------------------------------------------------


def test_list_user_organizations_hides_disabled_memberships(ddb: _DynamoDb) -> None:
    # A disabled membership is a suspension: the organization disappears from
    # the domain list even though the membership item still resolves — and,
    # raw-table proof, even though its by-user GSI keys are fully present.
    user = make_user()
    active_org = make_organization(organization_id="org_test_0001")
    suspended_org = make_organization(organization_id="org_test_0002")
    ddb.storage.create_user(user)
    ddb.storage.create_organization(active_org)
    ddb.storage.create_organization(suspended_org)
    ddb.storage.create_membership(make_membership())
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0002",
            user_id="usr_test_0001",
            status=MembershipStatus.DISABLED,
        )
    )
    page = ddb.storage.list_user_organizations(user.id, PageParams(limit=10))
    assert [organization.id for organization in page.items] == [active_org.id]
    assert page.next_cursor is None
    suspended_raw = ddb.tables.item(
        "memberships", _membership_key("org_test_0002", "usr_test_0001")
    )
    assert suspended_raw is not None and suspended_raw["g_user"] == "usr_test_0001"
    assert (
        ddb.storage.get_membership(organization_id=suspended_org.id, user_id=user.id).status
        is MembershipStatus.DISABLED
    )


def test_user_organization_lists_never_intersect(ddb: _DynamoDb) -> None:
    user_a = make_user()
    user_b = make_user(user_id="usr_test_0002")
    org_a = make_organization(organization_id="org_test_0001")
    org_b = make_organization(organization_id="org_test_0002")
    for entity in (user_a, user_b, org_a, org_b):
        if isinstance(entity, Organization):
            ddb.storage.create_organization(entity)
        else:
            ddb.storage.create_user(entity)
    ddb.storage.create_membership(make_membership(organization_id="org_test_0001"))
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0002",
            user_id="usr_test_0002",
        )
    )
    ids_a = [
        organization.id
        for organization in ddb.storage.list_user_organizations(
            user_a.id, PageParams(limit=10)
        ).items
    ]
    ids_b = [
        organization.id
        for organization in ddb.storage.list_user_organizations(
            user_b.id, PageParams(limit=10)
        ).items
    ]
    assert ids_a == [org_a.id]
    assert ids_b == [org_b.id]
    assert not set(ids_a) & set(ids_b)


def test_list_memberships_is_organization_scoped_with_all_statuses(ddb: _DynamoDb) -> None:
    # list_memberships shows ALL statuses (unlike the active-membership filter
    # of list_user_organizations) but only for the given organization.
    user_1 = make_user()
    user_2 = make_user(user_id="usr_test_0002")
    user_3 = make_user(user_id="usr_test_0003")
    org_1 = make_organization(organization_id="org_test_0001")
    org_2 = make_organization(organization_id="org_test_0002")
    for user in (user_1, user_2, user_3):
        ddb.storage.create_user(user)
    for organization in (org_1, org_2):
        ddb.storage.create_organization(organization)
    ddb.storage.create_membership(make_membership(organization_id="org_test_0001"))
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0001",
            user_id="usr_test_0002",
            role=MembershipRole.MEMBER,
            status=MembershipStatus.DISABLED,
            created_at=T1,
        )
    )
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0003",
            organization_id="org_test_0002",
            user_id="usr_test_0003",
        )
    )
    page = ddb.storage.list_memberships(org_1.id, PageParams(limit=10))
    assert [membership.user_id for membership in page.items] == [user_1.id, user_2.id]
    assert page.items[1].status is MembershipStatus.DISABLED
    other_page = ddb.storage.list_memberships(org_2.id, PageParams(limit=10))
    assert [membership.user_id for membership in other_page.items] == [user_3.id]


def test_delete_membership_is_physical_and_not_idempotent(ddb: _DynamoDb) -> None:
    user = make_user()
    organization = make_organization()
    ddb.storage.create_user(user)
    ddb.storage.create_organization(organization)
    ddb.storage.create_membership(make_membership())
    ddb.storage.delete_membership(organization_id=organization.id, user_id=user.id)
    # Physical delete: the item is gone from both lookup paths.
    assert (
        ddb.tables.item("memberships", _membership_key(str(organization.id), str(user.id))) is None
    )
    with pytest.raises(EntityNotFoundError):
        ddb.storage.get_membership(organization_id=organization.id, user_id=user.id)
    assert ddb.storage.list_user_organizations(user.id, PageParams(limit=10)).items == []
    # A second delete raises: removal is not idempotent (conditional delete,
    # decision 3's single-item discipline).
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.delete_membership(organization_id=organization.id, user_id=user.id)
    ddb.assert_no_leak(excinfo.value)
    # The pair is free again for a fresh membership under a new mem_ id.
    ddb.storage.create_membership(make_membership(membership_id="mem_test_0002"))


# ---------------------------------------------------------------------------
# Multi-page keyset traversal (both lists) and cursor hygiene
# ---------------------------------------------------------------------------


def test_list_user_organizations_traverses_multiple_pages_in_order(ddb: _DynamoDb) -> None:
    user = make_user()
    ddb.storage.create_user(user)
    org_early = make_organization(organization_id="org_test_0001", created_at=T0)
    org_late = make_organization(organization_id="org_test_0002", created_at=T1)
    org_last = make_organization(organization_id="org_test_0003", created_at=T2)
    for organization in (org_early, org_late, org_last):
        ddb.storage.create_organization(organization)
    for index, organization in enumerate((org_early, org_late, org_last), start=1):
        ddb.storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                organization_id=str(organization.id),
                user_id="usr_test_0001",
            )
        )
    first = ddb.storage.list_user_organizations(user.id, PageParams(limit=2))
    assert [organization.id for organization in first.items] == [org_early.id, org_late.id]
    assert first.limit == 2
    assert first.next_cursor is not None
    second = ddb.storage.list_user_organizations(
        user.id,
        PageParams(limit=2, cursor=first.next_cursor),
    )
    assert [organization.id for organization in second.items] == [org_last.id]
    assert second.next_cursor is None


def test_list_memberships_traverses_multiple_pages_in_order(ddb: _DynamoDb) -> None:
    organization = make_organization()
    ddb.storage.create_organization(organization)
    users = (
        make_user(user_id="usr_test_0001"),
        make_user(user_id="usr_test_0002"),
        make_user(user_id="usr_test_0003"),
    )
    for user in users:
        ddb.storage.create_user(user)
    ddb.storage.create_membership(make_membership(membership_id="mem_test_0001", created_at=T0))
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            user_id="usr_test_0002",
            role=MembershipRole.MEMBER,
            created_at=T1,
        )
    )
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0003",
            user_id="usr_test_0003",
            role=MembershipRole.VIEWER,
            created_at=T2,
        )
    )
    first = ddb.storage.list_memberships(organization.id, PageParams(limit=2))
    assert [membership.id for membership in first.items] == [
        MembershipId("mem_test_0001"),
        MembershipId("mem_test_0002"),
    ]
    assert first.next_cursor is not None
    second = ddb.storage.list_memberships(
        organization.id,
        PageParams(limit=2, cursor=first.next_cursor),
    )
    assert [membership.id for membership in second.items] == [MembershipId("mem_test_0003")]
    assert second.next_cursor is None


def _seed_two_pages_per_list(ddb: _DynamoDb) -> None:
    """Seed enough data that both membership lists can issue a limit=1 cursor."""
    ddb.storage.create_user(make_user())
    ddb.storage.create_user(make_user(user_id="usr_test_0002"))
    ddb.storage.create_organization(make_organization(organization_id="org_test_0001"))
    ddb.storage.create_organization(
        make_organization(organization_id="org_test_0002", created_at=T1)
    )
    ddb.storage.create_membership(make_membership())
    ddb.storage.create_membership(
        make_membership(membership_id="mem_test_0002", organization_id="org_test_0002")
    )
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0003",
            organization_id="org_test_0001",
            user_id="usr_test_0002",
        )
    )


def test_cursors_are_list_scoped_and_garbage_is_rejected(ddb: _DynamoDb) -> None:
    _seed_two_pages_per_list(ddb)
    user_orgs_cursor = ddb.storage.list_user_organizations(
        UserId("usr_test_0001"), PageParams(limit=1)
    ).next_cursor
    memberships_cursor = ddb.storage.list_memberships(
        OrganizationId("org_test_0001"), PageParams(limit=1)
    ).next_cursor
    assert user_orgs_cursor is not None
    assert memberships_cursor is not None
    # A cursor issued for one list is invalid for the other (list-scope tag).
    with pytest.raises(InvalidCursorError) as cross_scope:
        ddb.storage.list_memberships(
            OrganizationId("org_test_0001"), PageParams(limit=1, cursor=user_orgs_cursor)
        )
    ddb.assert_no_leak(cross_scope.value)
    with pytest.raises(InvalidCursorError):
        ddb.storage.list_user_organizations(
            UserId("usr_test_0001"), PageParams(limit=1, cursor=memberships_cursor)
        )
    for token in ("not-a-cursor-!!!", "AAAAAAAA", memberships_cursor[:-4]):
        with pytest.raises(InvalidCursorError):
            ddb.storage.list_memberships(
                OrganizationId("org_test_0001"), PageParams(limit=1, cursor=token)
            )
        with pytest.raises(InvalidCursorError):
            ddb.storage.list_user_organizations(
                UserId("usr_test_0001"), PageParams(limit=1, cursor=token)
            )


def test_inserts_between_pages_neither_duplicate_nor_skip(ddb: _DynamoDb) -> None:
    # Decision 5's core risk: the resume key is derived from the last
    # *returned* item, so rows landing after the cursor but before the next
    # unvisited item are delivered exactly once in (created_at, id) order.
    organization = make_organization()
    ddb.storage.create_organization(organization)
    timestamps = [datetime(2026, 9, 12, 10 + index, 0, 0, tzinfo=UTC) for index in range(5)]
    for index in range(5):
        user_id = f"usr_test_{index + 1:04d}"
        ddb.storage.create_user(make_user(user_id=user_id))
        ddb.storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index + 1:04d}",
                user_id=user_id,
                created_at=timestamps[index],
            )
        )
    first = ddb.storage.list_memberships(organization.id, PageParams(limit=2))
    assert [membership.id for membership in first.items] == [
        MembershipId("mem_test_0001"),
        MembershipId("mem_test_0002"),
    ]
    assert first.next_cursor is not None
    # Two rows land *after* the cursor but before the next unvisited item.
    for index in (6, 7):
        user_id = f"usr_test_{index:04d}"
        ddb.storage.create_user(make_user(user_id=user_id))
        ddb.storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                user_id=user_id,
                created_at=timestamps[1] + timedelta(seconds=index - 5),
            )
        )
    pages = _drain(
        lambda page: ddb.storage.list_memberships(organization.id, page),
        limit=2,
        start_cursor=first.next_cursor,
    )
    continuation = [membership.id for page in pages for membership in page.items]
    assert continuation == [
        MembershipId("mem_test_0006"),
        MembershipId("mem_test_0007"),
        MembershipId("mem_test_0003"),
        MembershipId("mem_test_0004"),
        MembershipId("mem_test_0005"),
    ]
    assert pages[-1].next_cursor is None
    visited = [membership.id for membership in first.items] + continuation
    assert len(visited) == len(set(visited)), "an item was visited on two pages"


# ---------------------------------------------------------------------------
# Read-back proofs (decision 2's payload and batch-boundary bullets)
# ---------------------------------------------------------------------------


def test_user_organizations_read_back_preserves_payloads_and_gsi_order(ddb: _DynamoDb) -> None:
    # The page items are the *full stored organizations* (field-for-field
    # model equality, not just ids) in GSI (org_created_at, org_id) order:
    # the T1 pair tie-breaks by id, and T3 (zero-microsecond) sorts *before*
    # T2 — traversal order deliberately differs from insertion and id order.
    user = make_user()
    ddb.storage.create_user(user)
    organizations = (
        make_organization(organization_id="org_test_0001", created_at=T0),
        make_organization(organization_id="org_test_0002", created_at=T1),
        make_organization(organization_id="org_test_0003", created_at=T1),
        make_organization(organization_id="org_test_0004", created_at=T2),
        make_organization(organization_id="org_test_0005", created_at=T3),
    )
    for organization in organizations:
        ddb.storage.create_organization(organization)
    for index, organization in enumerate(organizations, start=1):
        ddb.storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                organization_id=str(organization.id),
                user_id="usr_test_0001",
            )
        )
    # A suspended membership hides its organization on *every* page: org_0006
    # shares T3 with org_0005, so a leak would land mid-traversal.
    ddb.storage.create_organization(
        make_organization(organization_id="org_test_0006", created_at=T3)
    )
    ddb.storage.create_membership(
        make_membership(
            membership_id="mem_test_0006",
            organization_id="org_test_0006",
            user_id="usr_test_0001",
            status=MembershipStatus.DISABLED,
        )
    )
    pages = _drain(
        lambda page: ddb.storage.list_user_organizations(user.id, page),
        limit=2,
    )
    ids = [organization.id for page in pages for organization in page.items]
    assert ids == [
        OrganizationId("org_test_0001"),
        OrganizationId("org_test_0002"),
        OrganizationId("org_test_0003"),
        OrganizationId("org_test_0005"),
        OrganizationId("org_test_0004"),
    ]
    assert len(ids) == len(set(ids)), "pages overlapped: an item was visited twice"
    assert [len(page.items) for page in pages] == [2, 2, 1]
    assert all(page.limit == 2 for page in pages)
    assert pages[-1].next_cursor is None
    delivered = [organization for page in pages for organization in page.items]
    for organization in delivered:
        assert type(organization) is Organization
    # Field-for-field equality with the seeded (== stored) domain models.
    assert delivered == [
        organizations[0],
        organizations[1],
        organizations[2],
        organizations[4],
        organizations[3],
    ]


def test_limit_100_read_back_trims_probe_before_batching() -> None:
    # Decision 2's batch-boundary rule: the probe-row trim happens on the
    # *membership* items first, and only the trimmed page's ids are read back.
    # A naive limit+1-key batch would ValidationException at limit=100.
    endpoint = local.require_local_endpoint()
    harness = local.make_dynamodb_resource(endpoint)
    prefix = local.random_table_prefix()
    local.create_tables(prefix, resource=harness)
    calls: list[list[dict[str, str]]] = []

    class _RecordingClient:
        """Forwards everything to the real client, recording BatchGetItem keys."""

        def __init__(self, client: Any) -> None:
            self._client = client

        def batch_get_item(self, **kwargs: Any) -> Any:
            for table_request in kwargs.get("RequestItems", {}).values():
                calls.append(list(table_request.get("Keys", [])))
            return self._client.batch_get_item(**kwargs)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._client, name)

    class _RecordingResource:
        """A resource whose client records BatchGetItem calls (probe harness)."""

        def __init__(self, resource: Any) -> None:
            self._resource = resource
            self.meta = SimpleNamespace(client=_RecordingClient(resource.meta.client))

        def Table(self, name: str) -> Any:
            return self._resource.Table(name)

    storage = local.make_dynamodb_storage(
        prefix, resource=_RecordingResource(local.make_dynamodb_resource(endpoint))
    )
    try:
        ddb_user = make_user()
        storage.create_user(ddb_user)
        for index in range(1, 102):
            storage.create_organization(
                make_organization(
                    organization_id=f"org_test_{index:04d}",
                    created_at=datetime(2026, 9, 12, 10, 0, 0, index, tzinfo=UTC),
                )
            )
            storage.create_membership(
                make_membership(
                    membership_id=f"mem_test_{index:04d}",
                    organization_id=f"org_test_{index:04d}",
                    user_id="usr_test_0001",
                )
            )
        page = storage.list_user_organizations(ddb_user.id, PageParams(limit=100))
        assert len(page.items) == 100
        assert page.items[-1].id == OrganizationId("org_test_0100")
        assert page.next_cursor is not None
        # Exactly one BatchGetItem for the page, within the 100-key cap, and
        # the probe row's organization (101st in order) was never fetched.
        assert len(calls) == 1
        assert len(calls[0]) <= 100
        fetched = {key["pk"] for key in calls[0]}
        assert fetched == {f"org_test_{index:04d}" for index in range(1, 101)}
        assert "org_test_0101" not in fetched
    finally:
        storage.close()
        local.delete_tables(prefix, resource=harness)
