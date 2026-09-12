"""Unit tests for the Phase 02 task-7 SQLite ``provision_user`` compound.

Scope per the breakdown: cross-adapter *behavior* (happy-path reads, race
mapping, rollback proofs, the barrier race) is owned by the conformance suite;
this module pins the SQLite-internal pieces only — the row-level stored truth
of a batch write (shared-helper encoding: normalized ``''`` tenant,
fixed-width timestamps, compact metadata JSON), the transaction discipline
around ``BEGIN IMMEDIATE`` (a failed batch never leaves the thread-local
connection inside an open transaction and never persists a partial row), the
provision-scoped race error mapping (the same UNIQUE that stays a plain
``user_email`` conflict on ``create_user`` maps to
``DuplicateExternalIdentityError`` only inside ``provision_user``), the
winner-resolution precedence (identity-tuple read first, users-by-email
fallback), and the mid-batch non-integrity driver-error path.
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
from app.models.ids import AuditEventId, ExternalIdentityId, MembershipId, OrganizationId, UserId
from app.storage import sqlite as sqlite_adapter
from app.storage.sqlite import TABLE_NAMES, SQLiteStorage

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)
_T2 = datetime(2026, 9, 12, 11, 0, 0, 654321, tzinfo=UTC)


def make_user(
    user_id: str = "usr_test_0001",
    email: str | None = None,
    created_at: datetime = _T0,
) -> User:
    return User(
        id=UserId(user_id),
        display_name=f"Test user {user_id}",
        email=email or f"{user_id}@example.test",
        status=UserStatus.ACTIVE,
        created_at=created_at,
        updated_at=created_at,
    )


def make_identity(
    *,
    identity_id: str = "extid_test_0001",
    user_id: str = "usr_test_0001",
    provider_subject: str = "subject-cognito-0001",
    provider_tenant: str | None = None,
) -> ExternalIdentity:
    return ExternalIdentity(
        id=ExternalIdentityId(identity_id),
        user_id=UserId(user_id),
        provider=IdentityProvider.COGNITO,
        provider_subject=provider_subject,
        provider_tenant=provider_tenant,
        created_at=_T0,
    )


def make_organization(organization_id: str = "org_test_0001") -> Organization:
    return Organization(
        id=OrganizationId(organization_id),
        name=f"Test org {organization_id}",
        slug=f"org-{organization_id}",
        type=OrganizationType.PERSONAL,
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
        action="user.provisioned",
        metadata=metadata if metadata is not None else {"conformance": True},
        created_at=created_at,
    )


def _batch(
    *,
    user: User,
    organization_id: str,
    identity: ExternalIdentity | None = None,
    membership: Membership | None = None,
    audit_events: Sequence[AuditEvent] | None = None,
) -> dict[str, Any]:
    """A consistent owner-provisioning batch for ``user`` (defaults derive
    from the user id so happy-path calls stay readable)."""
    organization = make_organization(organization_id)
    return {
        "user": user,
        "identity": identity if identity is not None else make_identity(user_id=str(user.id)),
        "organization": organization,
        "membership": membership
        if membership is not None
        else make_membership(organization_id=organization_id, user_id=str(user.id)),
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
    adapter = SQLiteStorage(tmp_path / "provision.sqlite")
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# 1. Happy path: row-level stored truth (the batch shares the standalone
#    row-insert helpers, so the stored encoding must be identical)
# ---------------------------------------------------------------------------


def test_provision_batch_stores_rows_exactly_like_standalone_paths(
    storage: SQLiteStorage,
) -> None:
    storage.provision_user(
        **_batch(
            user=make_user(),
            organization_id="org_test_0001",
            identity=make_identity(provider_tenant=None),
            audit_events=[
                make_audit_event(metadata={"z_key": 1, "a_key": [1, {"nested": True}]}),
                make_audit_event(audit_id="aud_test_0002", created_at=_T1),
            ],
        )
    )
    conn = storage._connection()
    assert _table_counts(storage) == {
        "users": 1,
        "external_identities": 1,
        "organizations": 1,
        "memberships": 1,
        "api_keys": 0,
        "audit_events": 2,
    }
    identity_row = conn.execute("SELECT * FROM external_identities").fetchone()
    # Tenant normalization and the fixed-width timestamp codec apply to the
    # batch path exactly as to create_external_identity.
    assert identity_row["provider_tenant"] == ""
    assert identity_row["created_at"] == "2026-09-12T10:00:00.000000Z"
    user_row = conn.execute("SELECT created_at, updated_at FROM users").fetchone()
    assert user_row["created_at"] == user_row["updated_at"] == "2026-09-12T10:00:00.000000Z"
    audit_rows = conn.execute("SELECT metadata FROM audit_events ORDER BY id").fetchall()
    # Both events landed, metadata through the exact JSON codec (same helper
    # as the standalone append path).
    assert audit_rows[0]["metadata"] == '{"z_key":1,"a_key":[1,{"nested":true}]}'
    assert audit_rows[1]["metadata"] == '{"conformance":true}'


def test_provision_result_is_frozen_caller_echo(storage: SQLiteStorage) -> None:
    first = make_audit_event()
    second = make_audit_event(audit_id="aud_test_0002", created_at=_T1)
    user = make_user()
    result = storage.provision_user(
        **_batch(user=user, organization_id="org_test_0001", audit_events=[first, second])
    )
    assert isinstance(result, contract.ProvisionedUser)
    # Caller-echo: the exact supplied objects, audit events as an ordered
    # tuple (storage mints nothing and re-reads nothing).
    assert result.user == user
    assert result.audit_events == (first, second)
    with pytest.raises(ValidationError):
        result.user = make_user(user_id="usr_test_0002")  # frozen bundle


def test_provision_requires_audit_events_keyword_argument(storage: SQLiteStorage) -> None:
    batch = _batch(user=make_user(), organization_id="org_test_0001")
    del batch["audit_events"]
    # Required keyword-only: no default may let a caller silently skip the
    # §16 provisioning events.
    with pytest.raises(TypeError):
        storage.provision_user(**batch)  # type: ignore[call-arg]


def test_provision_accepts_explicit_empty_audit_batch(storage: SQLiteStorage) -> None:
    # Presence is contract-enforced; content policy is Phase 03 service work,
    # so an explicit empty batch is a legal (if odd) write.
    result = storage.provision_user(
        **_batch(user=make_user(), organization_id="org_test_0001", audit_events=[])
    )
    assert result.audit_events == ()
    assert _table_counts(storage)["audit_events"] == 0


# ---------------------------------------------------------------------------
# 2. Race mapping is provision-scoped: the same users.email UNIQUE is a
#    plain user_email conflict on create_user and the race error inside
#    provision_user, with winner resolution precedence pinned.
# ---------------------------------------------------------------------------


def test_email_conflict_stays_plain_duplicate_outside_provision(storage: SQLiteStorage) -> None:
    first = make_user()
    storage.create_user(first)
    with pytest.raises(contract.DuplicateEntityError) as excinfo:
        storage.create_user(make_user(user_id="usr_test_0002", email=first.email))
    assert excinfo.value.kind is contract.DuplicateEntityKind.USER_EMAIL
    assert not isinstance(excinfo.value, contract.DuplicateExternalIdentityError)
    # Inside provision_user the same violation is §6's race (kind pinned to
    # external_identity), resolved to the winner via the email fallback
    # (this batch's identity tuple is fresh).
    with pytest.raises(contract.DuplicateExternalIdentityError) as excinfo:
        storage.provision_user(
            **_batch(
                user=make_user(user_id="usr_test_0002", email=first.email),
                organization_id="org_test_0002",
                identity=make_identity(
                    identity_id="extid_test_0002",
                    user_id="usr_test_0002",
                    provider_subject="subject-unique-0002",
                ),
            )
        )
    error = excinfo.value
    assert error.kind is contract.DuplicateEntityKind.EXTERNAL_IDENTITY
    assert error.existing_user_id == first.id


def test_race_resolution_prefers_identity_tuple_over_email(storage: SQLiteStorage) -> None:
    # Winner owns the identity tuple; the loser carries the *same tuple* but
    # a fresh email, so the identity UNIQUE (not users.email) fires first.
    winner = make_user()
    storage.create_user(winner)
    storage.create_external_identity(make_identity(user_id="usr_test_0001"))
    with pytest.raises(contract.DuplicateExternalIdentityError) as excinfo:
        storage.provision_user(
            **_batch(
                user=make_user(user_id="usr_test_0002"),
                organization_id="org_test_0002",
                identity=make_identity(identity_id="extid_test_0002", user_id="usr_test_0002"),
            )
        )
    # Resolved from the winner's identity row (tuple read), never the loser's
    # own supplied user id.
    assert excinfo.value.existing_user_id == winner.id
    # Full rollback: the user row written before the identity failure is gone.
    with pytest.raises(contract.EntityNotFoundError):
        storage.get_user(UserId("usr_test_0002"))
    with pytest.raises(contract.EntityNotFoundError):
        storage.get_organization(OrganizationId("org_test_0002"))
    assert storage.get_user(winner.id) == winner


def test_race_existing_user_id_is_none_when_nothing_resolves(
    storage: SQLiteStorage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The email UNIQUE can only fire when some row holds the email; the
    # adapter's post-rollback resolution is best-effort by contract. Inject
    # a driver-real email UNIQUE failure while guaranteeing both resolution
    # reads miss, pinning the ``existing_user_id=None`` fallback shape.
    def fake_resolve(
        _self: SQLiteStorage, _conn: sqlite3.Connection, **_kwargs: object
    ) -> UserId | None:
        return None

    monkeypatch.setattr(SQLiteStorage, "_resolve_provision_race_user_id", fake_resolve)
    first = make_user()
    storage.create_user(first)
    with pytest.raises(contract.DuplicateExternalIdentityError) as excinfo:
        storage.provision_user(
            **_batch(
                user=make_user(user_id="usr_test_0002", email=first.email),
                organization_id="org_test_0002",
                identity=make_identity(
                    identity_id="extid_test_0002",
                    user_id="usr_test_0002",
                    provider_subject="subject-unique-0002",
                ),
            )
        )
    assert excinfo.value.existing_user_id is None


# ---------------------------------------------------------------------------
# 3. Failure paths: full rollback, no open transaction left behind, and the
#    connection stays usable (single-transaction discipline around the batch)
# ---------------------------------------------------------------------------


def test_failed_batch_leaves_no_partial_rows_and_no_open_transaction(
    storage: SQLiteStorage,
) -> None:
    # The batch's identity references a user the batch does not create and
    # that does not exist: the FK rejects it *after* the user row was already
    # inserted, so only a real rollback can explain the empty tables.
    with pytest.raises(contract.ReferenceNotFoundError):
        storage.provision_user(
            **_batch(
                user=make_user(),
                organization_id="org_test_0001",
                identity=make_identity(user_id="usr_ghost_0001"),
            )
        )
    conn = storage._connection()
    assert conn.in_transaction is False
    assert _table_counts(storage) == dict.fromkeys(TABLE_NAMES, 0)
    # The thread-local connection stays usable: a clean batch afterwards
    # commits on the same connection.
    storage.provision_user(**_batch(user=make_user(), organization_id="org_test_0001"))
    assert _table_counts(storage)["users"] == 1


def test_duplicate_audit_id_within_batch_raises_entity_id_and_rolls_back(
    storage: SQLiteStorage,
) -> None:
    event = make_audit_event()
    with pytest.raises(contract.DuplicateEntityError) as excinfo:
        storage.provision_user(
            **_batch(
                user=make_user(),
                organization_id="org_test_0001",
                audit_events=[event, event],
            )
        )
    assert excinfo.value.kind is contract.DuplicateEntityKind.ENTITY_ID
    assert not isinstance(excinfo.value, contract.DuplicateExternalIdentityError)
    assert _table_counts(storage) == dict.fromkeys(TABLE_NAMES, 0)


def test_mid_batch_driver_error_translates_generically_and_rolls_back(
    storage: SQLiteStorage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A non-integrity driver failure mid-batch (lock timeout shape): the
    # contract's "no sqlite3 error escapes" rule plus full rollback, proved
    # against the real transaction by failing after three rows were written.
    def boom(_self: SQLiteStorage, _conn: sqlite3.Connection, _membership: Membership) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(SQLiteStorage, "_insert_membership_row", boom)
    with pytest.raises(contract.StorageError) as excinfo:
        storage.provision_user(**_batch(user=make_user(), organization_id="org_test_0001"))
    error = excinfo.value
    assert not isinstance(error, contract.DuplicateEntityError)
    assert not isinstance(error, contract.ReferenceNotFoundError)
    assert "locked" not in str(error)  # no driver text leaks
    assert storage._connection().in_transaction is False
    assert _table_counts(storage) == dict.fromkeys(TABLE_NAMES, 0)


def test_provision_conflicts_do_not_poison_standalone_writes(storage: SQLiteStorage) -> None:
    # After every rejected-batch shape the adapter still honors the
    # standalone paths exactly as the suite pins them (translation is
    # provision-scoped, connection state is clean).
    first = make_user()
    storage.create_user(first)
    with pytest.raises(contract.DuplicateExternalIdentityError):
        storage.provision_user(
            **_batch(
                user=make_user(user_id="usr_test_0002", email=first.email),
                organization_id="org_test_0002",
            )
        )
    organization = make_organization("org_test_0003")
    assert storage.create_organization(organization) == organization
    assert (
        sqlite_adapter._translate_driver_error(
            sqlite3.IntegrityError("UNIQUE constraint failed: organizations.slug")
        ).kind
        is contract.DuplicateEntityKind.ORGANIZATION_SLUG
    )
