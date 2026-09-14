"""DynamoDB Local proofs for the API-keys operations, incl. the revoke CAS (task 5).

Marker-gated (``dynamodb_local``): every test here skips with an explicit reason
unless ``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and reachable, so the default
suite stays green without Docker (``docs/operations.md`` carries the run
command).

These are **direct adapter calls**, not the conformance suite (task 8 runs the
shared 60 cases unchanged): the point is to pin the DynamoDB translation of the
14 key behaviors on the real transactional path — the ``key_`` base put + §8
``api_key_id`` segment constraint + organization/creator ``ConditionCheck``s in
one ``TransactWriteItems`` (decision 3), the key-only constraint lookup behind
``get_api_key_by_key_id`` (decision 2), the org-**un**filtered identity read the
contract pins, native-L ``scopes`` round-trip (decision 6), the by-organization
GSI keyset traversal, and decision 4's conditional-update CAS field-for-field
(only ``status``/``revoked_at`` written; stored-truth idempotency; absence is
absence). Domain inputs come from the suite's own deterministic builders so the
fixtures match the conformance cases exactly. Every failure path asserts the
domain error *class*, the conflict *kind*, an echo-free message, and — by
scanning the tables directly — that the rejected batch left no residue.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timedelta
from typing import Any

import pytest
from storage_contract.suite import (
    T0,
    T1,
    T2,
    T3,
    T4,
    make_api_key,
    make_membership,
    make_organization,
    make_user,
)

from app.models.api_key import ApiKey
from app.models.enums import ApiKeyStatus
from app.models.ids import ApiKeyId, OrganizationId
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
    encode_sort_key,
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


def _seed_key_owner(ddb: _DynamoDb) -> None:
    """Create the default builder user + organization for key cases."""
    ddb.storage.create_user(make_user())
    ddb.storage.create_organization(make_organization())


def _segment_constraint_pk(segment: str) -> str:
    return encode_constraint_key(ConstraintKind.API_KEY_ID, segment)


def _after_t1(minutes: int) -> datetime:
    """Distinct increasing timestamps for cursor-scope seeding (T1 + n minutes)."""
    return T1 + timedelta(minutes=minutes)


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
# Create + the two point lookups: transaction shape, constraint item, round-trip
# ---------------------------------------------------------------------------


def test_create_api_key_returns_and_persists_for_both_lookups(ddb: _DynamoDb) -> None:
    _seed_key_owner(ddb)
    api_key = make_api_key()
    # Caller-echo: storage mints nothing, the returned entity is exactly the input.
    assert ddb.storage.create_api_key(api_key) == api_key
    by_identity = ddb.storage.get_api_key(api_key.id)
    by_segment = ddb.storage.get_api_key_by_key_id(api_key.key_id)
    assert by_identity == api_key
    assert by_segment == api_key
    assert type(by_identity) is ApiKey
    # Base item: pk is the key_ identity, GSI keys carry the org scope and the
    # (created_at, id) sort position, and the credential segment is an
    # ordinary attribute (the uniqueness is the constraint item's job).
    raw = ddb.tables.item("api_keys", {"pk": str(api_key.id)})
    assert raw is not None
    assert raw["key_id"] == api_key.key_id
    assert raw["g_org"] == str(api_key.organization_id)
    assert raw["g_created"] == encode_sort_key(api_key.created_at, str(api_key.id))
    assert raw["status"] == str(ApiKeyStatus.ACTIVE)
    # Decision 6: optional timestamps are absent attributes, not NULLs.
    assert "revoked_at" not in raw and "expires_at" not in raw and "last_used_at" not in raw
    # Constraint item (decision 2): key-only, maps to kind="api_key_id", and —
    # unlike the email/identity items — carries no user_id.
    constraint = ddb.tables.item(
        "unique_constraints", {"pk": _segment_constraint_pk(api_key.key_id)}
    )
    assert constraint is not None
    assert constraint["pk"] == f"api_key_id#{api_key.key_id}"
    assert constraint["kind"] == ConstraintKind.API_KEY_ID.value
    assert constraint["entity_id"] == str(api_key.id)
    assert set(constraint) == {"pk", "kind", "entity_id"}


def test_get_unknown_api_key_raises_entity_not_found(ddb: _DynamoDb) -> None:
    # Both lookup paths miss loudly: never a None return (identity read by a
    # fresh key_ id, segment read through the constraint table).
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.get_api_key(ApiKeyId("key_missing_0001"))
    ddb.assert_no_leak(excinfo.value)
    with pytest.raises(EntityNotFoundError) as segment:
        ddb.storage.get_api_key_by_key_id("01JNEVERISSUED")
    ddb.assert_no_leak(segment.value)


def test_api_key_scopes_round_trip_exactly(ddb: _DynamoDb) -> None:
    # Order and duplicates are preserved verbatim (normalization is Phase 05
    # domain work); decision 6 stores the list as a native DynamoDB L.
    _seed_key_owner(ddb)
    scopes = [
        "vispector:inspection:run",
        "vispector:inspection:read",
        "vispector:inspection:read",
        "feednow:billing:read",
    ]
    api_key = make_api_key(scopes=scopes)
    ddb.storage.create_api_key(api_key)
    assert ddb.storage.get_api_key(api_key.id).scopes == scopes
    assert ddb.storage.get_api_key_by_key_id(api_key.key_id).scopes == scopes
    raw = ddb.tables.item("api_keys", {"pk": str(api_key.id)})
    assert raw is not None
    assert raw["scopes"] == scopes  # a list, not a JSON string


# ---------------------------------------------------------------------------
# Conflicts: segment duplicate, record-id duplicate, both FK parents
# ---------------------------------------------------------------------------


def test_duplicate_credential_segment_raises_api_key_id_conflict(ddb: _DynamoDb) -> None:
    _seed_key_owner(ddb)
    first = make_api_key()
    ddb.storage.create_api_key(first)
    # Same §8 segment under a fresh key_ id: the base put's condition passes,
    # the constraint put fails — positionally mapped to kind="api_key_id".
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_api_key(make_api_key(key_id="key_test_0002"))
    assert excinfo.value.kind is DuplicateEntityKind.API_KEY_ID
    ddb.assert_no_leak(excinfo.value)
    # Rolled back: the loser's base row was never written and its key_ id is
    # unconsumed (a fresh-segment insert under it succeeds).
    assert ddb.storage.get_api_key(first.id) == first
    assert len(ddb.tables.items("api_keys")) == 1
    ddb.storage.create_api_key(
        make_api_key(key_id="key_test_0002", credential_segment="01JOTHERSEGMENT")
    )
    assert len(ddb.tables.items("api_keys")) == 2


def test_duplicate_api_key_record_id_raises_entity_id_conflict(ddb: _DynamoDb) -> None:
    _seed_key_owner(ddb)
    first = make_api_key()
    ddb.storage.create_api_key(first)
    # Same key_ id, different segment: the base put fails first in submission
    # order (mirroring SQLite), so this is a record-id conflict, not a
    # segment one.
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_api_key(make_api_key(credential_segment="01JOTHERSEGMENT"))
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(excinfo.value)
    assert ddb.storage.get_api_key(first.id) == first
    # And the rejected segment's constraint item was never written.
    assert (
        ddb.tables.item("unique_constraints", {"pk": _segment_constraint_pk("01JOTHERSEGMENT")})
        is None
    )


def test_api_key_for_unknown_organization_raises_reference_not_found(ddb: _DynamoDb) -> None:
    ddb.storage.create_user(make_user())
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.create_api_key(
            make_api_key(organization_id="org_ghost_0001", created_by_user_id="usr_test_0001")
        )
    ddb.assert_no_leak(excinfo.value)
    # DynamoDB has no foreign keys: the org ConditionCheck must leave the base
    # item *and* the segment constraint unwritten.
    assert ddb.tables.items("api_keys") == []
    assert (
        ddb.tables.item("unique_constraints", {"pk": _segment_constraint_pk("01JTESTKEYID")})
        is None
    )


def test_api_key_for_unknown_creator_raises_reference_not_found(ddb: _DynamoDb) -> None:
    ddb.storage.create_organization(make_organization())
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.create_api_key(
            make_api_key(organization_id="org_test_0001", created_by_user_id="usr_ghost_0001")
        )
    ddb.assert_no_leak(excinfo.value)
    assert ddb.tables.items("api_keys") == []
    assert (
        ddb.tables.item("unique_constraints", {"pk": _segment_constraint_pk("01JTESTKEYID")})
        is None
    )


# ---------------------------------------------------------------------------
# Reads: org scoping of the list, unfiltered identity read (contract-pinned)
# ---------------------------------------------------------------------------


def test_list_api_keys_is_organization_scoped(ddb: _DynamoDb) -> None:
    _seed_key_owner(ddb)
    other_org = make_organization(organization_id="org_test_0002")
    ddb.storage.create_organization(other_org)
    ddb.storage.create_api_key(
        make_api_key(key_id="key_test_0001", organization_id="org_test_0001", created_at=T1)
    )
    ddb.storage.create_api_key(
        make_api_key(
            key_id="key_test_0002",
            organization_id="org_test_0001",
            credential_segment="01JSEGMENTAB",
            created_at=T2,
        )
    )
    ddb.storage.create_api_key(
        make_api_key(
            key_id="key_test_0003",
            organization_id="org_test_0002",
            credential_segment="01JSEGMENTBA",
            created_at=T0,
        )
    )
    page = ddb.storage.list_api_keys(OrganizationId("org_test_0001"), PageParams(limit=10))
    # (created_at, id) ascending, and no foreign-organization rows.
    assert [api_key.id for api_key in page.items] == [
        ApiKeyId("key_test_0001"),
        ApiKeyId("key_test_0002"),
    ]
    other_page = ddb.storage.list_api_keys(other_org.id, PageParams(limit=10))
    assert [api_key.id for api_key in other_page.items] == [ApiKeyId("key_test_0003")]


def test_get_api_key_is_not_org_filtered_by_contract(ddb: _DynamoDb) -> None:
    # Pinned key-read tenancy rule: get_api_key takes only the key_ identity
    # and returns the full row regardless of organization — the §8
    # verification path must resolve the org *from* the key.
    _seed_key_owner(ddb)
    foreign_org = make_organization(organization_id="org_test_0002")
    ddb.storage.create_organization(foreign_org)
    api_key = make_api_key(organization_id="org_test_0002")
    ddb.storage.create_api_key(api_key)
    stored = ddb.storage.get_api_key(api_key.id)
    assert stored == api_key
    assert stored.organization_id == foreign_org.id


def test_list_api_keys_traverses_multiple_pages_in_keyset_order(ddb: _DynamoDb) -> None:
    # Mirrors the suite's traversal case: T0 tie breaks by id, and T3
    # (zero-microsecond) sorts *before* T2's same-second microsecond value —
    # order deliberately differs from insertion and id order.
    _seed_key_owner(ddb)
    keys = (
        make_api_key(key_id="key_test_0001", credential_segment="01JSEG0001", created_at=T2),
        make_api_key(key_id="key_test_0002", credential_segment="01JSEG0002", created_at=T0),
        make_api_key(key_id="key_test_0003", credential_segment="01JSEG0003", created_at=T0),
        make_api_key(key_id="key_test_0004", credential_segment="01JSEG0004", created_at=T3),
        make_api_key(key_id="key_test_0005", credential_segment="01JSEG0005", created_at=T4),
    )
    for api_key in keys:
        ddb.storage.create_api_key(api_key)
    pages = _drain(
        lambda page: ddb.storage.list_api_keys(OrganizationId("org_test_0001"), page),
        limit=2,
    )
    ids = [api_key.id for page in pages for api_key in page.items]
    assert ids == [
        ApiKeyId("key_test_0002"),
        ApiKeyId("key_test_0003"),
        ApiKeyId("key_test_0004"),
        ApiKeyId("key_test_0001"),
        ApiKeyId("key_test_0005"),
    ]
    assert len(ids) == len(set(ids)), "pages overlapped: a key was visited twice"
    assert [len(page.items) for page in pages] == [2, 2, 1]
    assert all(page.limit == 2 for page in pages)
    assert pages[-1].next_cursor is None


def test_api_key_cursors_are_list_scoped_and_garbage_is_rejected(ddb: _DynamoDb) -> None:
    _seed_key_owner(ddb)
    # Two memberships so list_memberships can also issue a limit=1 cursor.
    ddb.storage.create_user(make_user(user_id="usr_test_0002"))
    ddb.storage.create_membership(make_membership())
    ddb.storage.create_membership(
        make_membership(membership_id="mem_test_0002", user_id="usr_test_0002")
    )
    for index in (1, 2):
        ddb.storage.create_api_key(
            make_api_key(
                key_id=f"key_test_{index:04d}",
                credential_segment=f"01JSEGMENT0{index}",
                created_at=_after_t1(index),
            )
        )
    keys_cursor = ddb.storage.list_api_keys(
        OrganizationId("org_test_0001"), PageParams(limit=1)
    ).next_cursor
    memberships_cursor = ddb.storage.list_memberships(
        OrganizationId("org_test_0001"), PageParams(limit=1)
    ).next_cursor
    assert keys_cursor is not None
    assert memberships_cursor is not None
    # A cursor issued for one list is invalid for the other (list-scope tag).
    with pytest.raises(InvalidCursorError) as cross_scope:
        ddb.storage.list_api_keys(
            OrganizationId("org_test_0001"), PageParams(limit=1, cursor=memberships_cursor)
        )
    ddb.assert_no_leak(cross_scope.value)
    with pytest.raises(InvalidCursorError):
        ddb.storage.list_memberships(
            OrganizationId("org_test_0001"), PageParams(limit=1, cursor=keys_cursor)
        )
    for token in ("not-a-cursor-!!!", "AAAAAAAA", keys_cursor[:-4]):
        with pytest.raises(InvalidCursorError):
            ddb.storage.list_api_keys(
                OrganizationId("org_test_0001"), PageParams(limit=1, cursor=token)
            )


# ---------------------------------------------------------------------------
# Revoke CAS (decision 4): field-for-field, stored truth, absence is absence
# ---------------------------------------------------------------------------


def test_revoke_api_key_sets_status_and_revoked_at(ddb: _DynamoDb) -> None:
    _seed_key_owner(ddb)
    api_key = make_api_key()
    ddb.storage.create_api_key(api_key)
    before = ddb.tables.item("api_keys", {"pk": str(api_key.id)})
    assert before is not None
    revoked = ddb.storage.revoke_api_key(api_key.id, revoked_at=T2)
    assert revoked.status is ApiKeyStatus.REVOKED
    assert revoked.revoked_at == T2
    assert revoked.created_at == api_key.created_at
    assert revoked == ddb.storage.get_api_key(api_key.id)
    # Decision 4 mirrors SQLite field-for-field: exactly status and revoked_at
    # change — no updated_at appears, and the GSI sort keys are untouched.
    after = ddb.tables.item("api_keys", {"pk": str(api_key.id)})
    assert after is not None
    assert after["status"] == str(ApiKeyStatus.REVOKED)
    assert after["revoked_at"] == encode_timestamp(T2)
    changed = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
    assert changed == {"status", "revoked_at"}


def test_revoke_unknown_api_key_raises_entity_not_found(ddb: _DynamoDb) -> None:
    # Only the active→revoked CAS is idempotent; absence is absence.
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.revoke_api_key(ApiKeyId("key_missing_0001"), revoked_at=T2)
    ddb.assert_no_leak(excinfo.value)


def test_duplicate_revocation_preserves_the_first_revoked_at(ddb: _DynamoDb) -> None:
    _seed_key_owner(ddb)
    api_key = make_api_key()
    ddb.storage.create_api_key(api_key)
    first = ddb.storage.revoke_api_key(api_key.id, revoked_at=T1)
    # The second call carries a *distinct* literal revoked_at so
    # first-write-wins is observable, not coincidental: the CAS condition
    # fails, stored truth comes back — idempotent success, no error.
    second = ddb.storage.revoke_api_key(api_key.id, revoked_at=T2)
    assert second == first
    assert second.revoked_at == T1
    assert ddb.storage.get_api_key(api_key.id).revoked_at == T1


def test_concurrent_revocations_preserve_the_first_revoked_at(ddb: _DynamoDb) -> None:
    # Barrier, never sleeps (breakdown concurrency discipline). The two
    # racing calls carry distinct literal revoked_at values so the winner is
    # observable, not coincidental: the loser's CAS misses and returns the
    # winner's stored truth (decision 4's race-window rule).
    _seed_key_owner(ddb)
    api_key = make_api_key()
    ddb.storage.create_api_key(api_key)
    barrier = threading.Barrier(2)
    results: dict[str, ApiKey] = {}
    failures: dict[str, BaseException] = {}

    def revoke(token: str, revoked_at: datetime) -> None:
        try:
            barrier.wait()
            results[token] = ddb.storage.revoke_api_key(api_key.id, revoked_at=revoked_at)
        except Exception as exc:  # recorded; asserted empty on the main thread below
            failures[token] = exc

    threads = [
        threading.Thread(target=revoke, args=("early", T1)),
        threading.Thread(target=revoke, args=("late", T2)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == {}
    assert results["early"] == results["late"]
    assert results["early"].status is ApiKeyStatus.REVOKED
    assert results["early"].revoked_at in (T1, T2)
    assert ddb.storage.get_api_key(api_key.id).revoked_at == results["early"].revoked_at


def test_revoked_key_still_resolves_by_segment_with_stored_truth(ddb: _DynamoDb) -> None:
    # §13's "revoked key is rejected" maps to storage truthfulness: the
    # constraint-backed point lookup keeps resolving with status=revoked and
    # revoked_at set — the datum Phase 05 verification rejects on (status is
    # data, not deletion). The constraint item survives the CAS untouched.
    _seed_key_owner(ddb)
    api_key = make_api_key()
    ddb.storage.create_api_key(api_key)
    ddb.storage.revoke_api_key(api_key.id, revoked_at=T2)
    resolved = ddb.storage.get_api_key_by_key_id(api_key.key_id)
    assert resolved.status is ApiKeyStatus.REVOKED
    assert resolved.revoked_at == T2
    assert resolved.secret_hash == api_key.secret_hash
    constraint = ddb.tables.item(
        "unique_constraints", {"pk": _segment_constraint_pk(api_key.key_id)}
    )
    assert constraint is not None
    assert constraint["entity_id"] == str(api_key.id)
    # list_api_keys shows ALL statuses, including the revoked row.
    page = ddb.storage.list_api_keys(OrganizationId("org_test_0001"), PageParams(limit=10))
    assert [api_key.id for api_key in page.items] == [api_key.id]
