"""Unit tests for the Phase 04 task-1 SQLite ``provision_organization`` compound.

Scope mirrors ``test_sqlite_provision.py``: cross-adapter *behavior* (atomic
read-back, conflict kinds, rollback) is owned by the conformance suite; this
module pins the SQLite-internal pieces only — the row-level stored truth of a
batch write (shared-helper encoding: fixed-width timestamps, compact metadata
JSON), the transaction discipline around ``BEGIN IMMEDIATE`` (a failed batch
never leaves the thread-local connection inside an open transaction and never
persists a partial row), the deliberate **absence** of race-convergence
mapping (a slug conflict stays a plain ``organization_slug`` duplicate, never
``DuplicateExternalIdentityError``), and the mid-batch non-integrity
driver-error path.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

import app.storage.contract as contract
from app.models import (
    AuditEvent,
    Membership,
    MembershipRole,
    MembershipStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
    User,
    UserStatus,
)
from app.models.ids import AuditEventId, MembershipId, OrganizationId, UserId
from app.storage.sqlite import TABLE_NAMES, SQLiteStorage

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)
_T2 = datetime(2026, 9, 12, 11, 0, 0, 654321, tzinfo=UTC)


def make_user(user_id: str = "usr_test_0001") -> User:
    return User(
        id=UserId(user_id),
        display_name=f"Test user {user_id}",
        email=f"{user_id}@example.test",
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_organization(organization_id: str = "org_test_0001") -> Organization:
    return Organization(
        id=OrganizationId(organization_id),
        name=f"Test org {organization_id}",
        slug=f"org-{organization_id}",
        type=OrganizationType.CUSTOMER,
        status=OrganizationStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_membership(
    *,
    membership_id: str = "mem_test_0001",
    organization_id: str = "org_test_0001",
    user_id: str = "usr_test_0001",
) -> Membership:
    return Membership(
        id=MembershipId(membership_id),
        organization_id=OrganizationId(organization_id),
        user_id=UserId(user_id),
        role=MembershipRole.OWNER,
        status=MembershipStatus.ACTIVE,
        created_at=_T0,
    )


def make_audit_event(
    *,
    audit_id: str = "aud_test_0001",
    organization_id: str = "org_test_0001",
    metadata: dict[str, Any] | None = None,
    created_at: datetime = _T2,
) -> AuditEvent:
    return AuditEvent(
        id=AuditEventId(audit_id),
        organization_id=OrganizationId(organization_id),
        actor_type="user",
        actor_id=UserId("usr_test_0001"),
        action="organization.created",
        metadata=metadata if metadata is not None else {"type": "customer"},
        created_at=created_at,
    )


def _batch(
    *,
    organization: Organization,
    membership: Membership | None = None,
    audit_events: Sequence[AuditEvent] | None = None,
) -> dict[str, Any]:
    """A consistent owner-membership batch for ``organization`` (defaults
    derive from the organization id so happy-path calls stay readable)."""
    organization_id = str(organization.id)
    return {
        "organization": organization,
        "membership": membership
        if membership is not None
        else make_membership(organization_id=organization_id),
        "audit_events": audit_events
        if audit_events is not None
        else [make_audit_event(organization_id=organization_id)],
    }


def _table_counts(storage: SQLiteStorage) -> dict[str, int]:
    conn = storage._connection()
    return {
        table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLE_NAMES
    }


@pytest.fixture
def storage(tmp_path) -> SQLiteStorage:  # type: ignore[no-untyped-def]
    adapter = SQLiteStorage(tmp_path / "provision_org.sqlite")
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# 1. Happy path: row-level stored truth (the batch shares the standalone
#    row-insert helpers, so the stored encoding must be identical)
# ---------------------------------------------------------------------------


def test_org_batch_stores_rows_exactly_like_standalone_paths(storage: SQLiteStorage) -> None:
    owner = make_user()
    storage.create_user(owner)
    storage.provision_organization(
        **_batch(
            organization=make_organization(),
            audit_events=[
                make_audit_event(metadata={"z_key": 1, "a_key": [1, {"nested": True}]}),
                make_audit_event(audit_id="aud_test_0002", created_at=_T1),
            ],
        )
    )
    conn = storage._connection()
    assert _table_counts(storage) == {
        "users": 1,
        "external_identities": 0,
        "organizations": 1,
        "memberships": 1,
        "api_keys": 0,
        "audit_events": 2,
    }
    organization_row = conn.execute("SELECT created_at, updated_at FROM organizations").fetchone()
    # The fixed-width timestamp codec applies to the batch path exactly as to
    # create_organization.
    assert (
        organization_row["created_at"]
        == organization_row["updated_at"]
        == "2026-09-12T10:00:00.000000Z"
    )
    audit_rows = conn.execute("SELECT metadata FROM audit_events ORDER BY id").fetchall()
    # Both events landed, metadata through the exact JSON codec (same helper
    # as the standalone append path).
    assert audit_rows[0]["metadata"] == '{"z_key":1,"a_key":[1,{"nested":true}]}'
    assert audit_rows[1]["metadata"] == '{"type":"customer"}'


def test_org_batch_result_is_frozen_caller_echo(storage: SQLiteStorage) -> None:
    owner = make_user()
    storage.create_user(owner)
    first = make_audit_event()
    second = make_audit_event(audit_id="aud_test_0002", created_at=_T1)
    organization = make_organization()
    result = storage.provision_organization(
        **_batch(organization=organization, audit_events=[first, second])
    )
    assert isinstance(result, contract.ProvisionedOrganization)
    # Caller-echo: the exact supplied objects, audit events as an ordered
    # tuple (storage mints nothing and re-reads nothing).
    assert result.organization is organization
    assert result.audit_events == (first, second)
    with pytest.raises(ValidationError):
        result.organization = make_organization("org_test_0002")  # frozen bundle


def test_org_batch_requires_audit_events_keyword_argument(storage: SQLiteStorage) -> None:
    owner = make_user()
    storage.create_user(owner)
    batch = _batch(organization=make_organization())
    del batch["audit_events"]
    # Required keyword-only: no default may let a caller silently skip the
    # §16 creation events.
    with pytest.raises(TypeError):
        storage.provision_organization(**batch)  # type: ignore[call-arg]


def test_org_batch_accepts_explicit_empty_audit_batch(storage: SQLiteStorage) -> None:
    # Presence is contract-enforced; content policy is Phase 04 service work,
    # so an explicit empty batch is a legal (if odd) write.
    owner = make_user()
    storage.create_user(owner)
    result = storage.provision_organization(
        **_batch(organization=make_organization(), audit_events=[])
    )
    assert result.audit_events == ()
    assert _table_counts(storage)["audit_events"] == 0


# ---------------------------------------------------------------------------
# 2. No race-convergence mapping: every conflict keeps its plain translated
#    kind (unlike provision_user's email/identity-tuple race error).
# ---------------------------------------------------------------------------


def test_org_batch_slug_conflict_stays_plain_duplicate_never_race(
    storage: SQLiteStorage,
) -> None:
    owner = make_user()
    storage.create_user(owner)
    existing = make_organization()
    storage.create_organization(existing)
    conflicting = make_organization("org_test_0002").model_copy(update={"slug": existing.slug})
    with pytest.raises(contract.DuplicateEntityError) as excinfo:
        storage.provision_organization(
            **_batch(
                organization=conflicting,
                audit_events=[make_audit_event(audit_id="aud_test_0002")],
            )
        )
    error = excinfo.value
    assert error.kind is contract.DuplicateEntityKind.ORGANIZATION_SLUG
    assert not isinstance(error, contract.DuplicateExternalIdentityError)


# ---------------------------------------------------------------------------
# 3. Failure paths: full rollback, no open transaction left behind, and the
#    connection stays usable (single-transaction discipline around the batch)
# ---------------------------------------------------------------------------


def test_failed_org_batch_leaves_no_partial_rows_and_no_open_transaction(
    storage: SQLiteStorage,
) -> None:
    # The batch's membership references a user that does not exist: the FK
    # rejects it *after* the organization row was already inserted, so only a
    # real rollback can explain the empty tables.
    with pytest.raises(contract.ReferenceNotFoundError):
        storage.provision_organization(
            **_batch(
                organization=make_organization(),
                membership=make_membership(user_id="usr_ghost_0001"),
            )
        )
    conn = storage._connection()
    assert conn.in_transaction is False
    assert _table_counts(storage) == dict.fromkeys(TABLE_NAMES, 0)
    # The thread-local connection stays usable: a clean batch afterwards
    # commits on the same connection.
    storage.create_user(make_user())
    storage.provision_organization(**_batch(organization=make_organization()))
    assert _table_counts(storage)["organizations"] == 1


def test_duplicate_audit_id_within_org_batch_raises_entity_id_and_rolls_back(
    storage: SQLiteStorage,
) -> None:
    owner = make_user()
    storage.create_user(owner)
    event = make_audit_event()
    with pytest.raises(contract.DuplicateEntityError) as excinfo:
        storage.provision_organization(
            **_batch(organization=make_organization(), audit_events=[event, event])
        )
    assert excinfo.value.kind is contract.DuplicateEntityKind.ENTITY_ID
    assert not isinstance(excinfo.value, contract.DuplicateExternalIdentityError)
    # The batch's own rows are gone (the seeded owner user is not part of it).
    counts = _table_counts(storage)
    assert counts["organizations"] == counts["memberships"] == counts["audit_events"] == 0


def test_mid_batch_driver_error_translates_generically_and_rolls_back(
    storage: SQLiteStorage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A non-integrity driver failure mid-batch (lock timeout shape): the
    # contract's "no sqlite3 error escapes" rule plus full rollback, proved
    # against the real transaction by failing after the organization row was
    # already written.
    def boom(_self: SQLiteStorage, _conn: sqlite3.Connection, _membership: Membership) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(SQLiteStorage, "_insert_membership_row", boom)
    with pytest.raises(contract.StorageError) as excinfo:
        storage.provision_organization(**_batch(organization=make_organization()))
    error = excinfo.value
    assert not isinstance(error, contract.DuplicateEntityError)
    assert not isinstance(error, contract.ReferenceNotFoundError)
    assert "locked" not in str(error)  # no driver text leaks
    assert storage._connection().in_transaction is False
    assert _table_counts(storage) == dict.fromkeys(TABLE_NAMES, 0)
