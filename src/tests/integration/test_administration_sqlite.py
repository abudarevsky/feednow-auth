"""SQLite-backed acceptance proofs for the admin implementation administration service.

The stub suite (``test_administration_service.py``) proves the decision rules;
this module proves the same service against the **real storage and adminadapter**
(WAL, ``BEGIN IMMEDIATE``, FKs, the CAS transition) on tmp files, reading
committed truth back through a *separate* connection. Acceptance mapping
(design notes implementation "Verify"):

- **grant persists role + exactly one audit** — the ``users`` row flips to
  ``admin`` with the injected ``updated_at`` and one ``granted`` audit row
  commits in the same transaction;
- **repeat grant is a no-op** — still one audit row and the user's
  ``updated_at`` is untouched (the adapter skipped both writes; the service
  did not re-append);
- **revoke of the last ACTIVE admin raises with zero mutation** —
  ``LastActiveAdministratorError`` propagates untranslated and the full-table
  dump before/after is byte-identical;
- **ambiguous email** — two seeded same-email users raise
  ``AmbiguousAdministratorEmailError`` naming both ``usr_`` ids, storage
  untouched;
- **audit metadata** — the persisted row carries exactly the two-key
  secret-free shape ``{"from_role", "to_role"}`` with no email, sub, or
  token material anywhere in it.

Current behavior and invariants: ``docs/administration.md``."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.models.enums import (
    ApplicationRole,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.ids import AuditEventId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services.administration import (
    GRANT_ACTION,
    AdministratorNotFoundError,
    AmbiguousAdministratorEmailError,
    grant_administrator,
    resolve_unique_user,
    revoke_administrator,
)
from app.storage.contract import (
    LastActiveAdministratorError,
    RoleTransitionOutcome,
    Storage,
)
from app.storage.sqlite import TABLE_NAMES, encode_timestamp, open_sqlite_storage

_SEED_T0 = datetime(2026, 9, 20, 8, 0, 0, tzinfo=UTC)
_GRANT_NOW = datetime(2026, 9, 25, 10, 30, 0, tzinfo=UTC)
_SECOND_NOW = datetime(2026, 9, 25, 11, 0, 0, tzinfo=UTC)
_EMAIL = "bootstrap@example.test"
_AUDIT_ID = AuditEventId("aud_" + "a" * 32)
_REVOKE_AUDIT_ID = AuditEventId("aud_" + "b" * 32)


@pytest.fixture
def db_path(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path / "administration.sqlite"


def _rows(path: Path, table: str) -> list[dict[str, object]]:
    """Read a table through a fresh connection: committed truth only."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        # rowid keeps the snapshot ordering stable across connections without
        # assuming every table has an `id` column (session tables do not).
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]
    finally:
        conn.close()


def _dump(path: Path) -> dict[str, list[dict[str, object]]]:
    """Full snapshot of every stored table — the zero-mutation witness."""
    return {table: _rows(path, table) for table in TABLE_NAMES}


def _seed_user(
    storage: Storage,
    user_id: str,
    *,
    email: str = _EMAIL,
    application_role: ApplicationRole = ApplicationRole.USER,
    status: UserStatus = UserStatus.ACTIVE,
) -> User:
    user = User(
        id=UserId(user_id),
        display_name=f"operator {user_id}",
        email=email,
        status=status,
        application_role=application_role,
        created_at=_SEED_T0,
        updated_at=_SEED_T0,
    )
    storage.create_user(user)
    return user


def _seed_active_membership(
    storage: Storage,
    user_id: UserId,
    organization_id: str,
    *,
    created_at: datetime = _SEED_T0,
) -> None:
    """Give the user an ACTIVE membership so the audit anchor exists (FK)."""
    storage.create_organization(
        Organization(
            id=OrganizationId(organization_id),
            name=f"Org {organization_id}",
            slug=f"org-{organization_id}",
            type=OrganizationType.CUSTOMER,
            status=OrganizationStatus.ACTIVE,
            created_at=created_at,
            updated_at=created_at,
        )
    )
    storage.create_membership(
        Membership(
            id=MembershipId(f"mem_{str(user_id)[4:]}_{organization_id[4:]}"),
            organization_id=OrganizationId(organization_id),
            user_id=user_id,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            created_at=created_at,
        )
    )


def _grant(storage: Storage, email: str = _EMAIL, *, now: datetime = _GRANT_NOW):
    return grant_administrator(
        storage,
        email,
        now=lambda: now,
        ids=lambda: _AUDIT_ID,
    )


def _revoke(
    storage: Storage,
    email: str = _EMAIL,
    *,
    now: datetime = _GRANT_NOW,
    audit_id: AuditEventId = _REVOKE_AUDIT_ID,
):
    return revoke_administrator(storage, email, now=lambda: now, ids=lambda: audit_id)


# ---------------------------------------------------------------------------
# Grant: role + exactly one audit commit together
# ---------------------------------------------------------------------------


def test_grant_persists_role_and_exactly_one_audit(db_path: Path) -> None:
    storage = open_sqlite_storage(db_path)
    user = _seed_user(storage, "usr_grant_target")
    _seed_active_membership(storage, user.id, "org_anchor")

    result = _grant(storage)

    assert result.outcome is RoleTransitionOutcome.TRANSITIONED
    assert result.user.application_role is ApplicationRole.ADMIN
    assert result.user.updated_at == _GRANT_NOW

    users = _rows(db_path, "users")
    assert len(users) == 1
    stored = users[0]
    assert stored["application_role"] == "admin"
    assert stored["updated_at"] == encode_timestamp(_GRANT_NOW)

    audits = _rows(db_path, "audit_events")
    assert len(audits) == 1
    audit = audits[0]
    assert audit["id"] == str(_AUDIT_ID)
    assert audit["action"] == GRANT_ACTION
    assert audit["target_type"] == "user"
    assert audit["target_id"] == str(user.id)
    # Out-of-band self-actor and the earliest-active-organization anchor.
    assert audit["actor_type"] == "user"
    assert audit["actor_id"] == str(user.id)
    assert audit["organization_id"] == "org_anchor"


def test_grant_missing_email_raises_and_writes_nothing(db_path: Path) -> None:
    storage = open_sqlite_storage(db_path)
    user = _seed_user(storage, "usr_other", email="someone-else@example.test")
    _seed_active_membership(storage, user.id, "org_other")

    with pytest.raises(AdministratorNotFoundError):
        _grant(storage)

    assert all(row["application_role"] == "user" for row in _rows(db_path, "users"))
    assert _rows(db_path, "audit_events") == []


# ---------------------------------------------------------------------------
# Repeat grant: idempotent NO_CHANGE, no second audit, updated_at frozen
# ---------------------------------------------------------------------------


def test_repeat_grant_is_a_no_op_with_still_one_audit(db_path: Path) -> None:
    storage = open_sqlite_storage(db_path)
    user = _seed_user(storage, "usr_repeat_grant")
    _seed_active_membership(storage, user.id, "org_anchor")

    first = _grant(storage)
    assert first.outcome is RoleTransitionOutcome.TRANSITIONED
    updated_after_first = _rows(db_path, "users")[0]["updated_at"]

    # A second command on a different clock: the adapter must skip both
    # writes entirely (same aud_ id reuse is itself a duplicate-append
    # tripwire: a non-skipping adapter would collide and fail here).
    second = _grant(storage, now=_SECOND_NOW)
    assert second.outcome is RoleTransitionOutcome.NO_CHANGE
    assert second.user.updated_at == _GRANT_NOW

    audits = _rows(db_path, "audit_events")
    assert len(audits) == 1
    assert audits[0]["id"] == str(_AUDIT_ID)
    stored = _rows(db_path, "users")[0]
    assert stored["updated_at"] == updated_after_first
    assert stored["updated_at"] == encode_timestamp(_GRANT_NOW)
    assert stored["updated_at"] != encode_timestamp(_SECOND_NOW)


# ---------------------------------------------------------------------------
# Revoke the last ACTIVE admin: refusal, fully rolled back
# ---------------------------------------------------------------------------


def test_revoke_last_active_admin_raises_with_zero_mutation(db_path: Path) -> None:
    storage = open_sqlite_storage(db_path)
    user = _seed_user(storage, "usr_last_admin", application_role=ApplicationRole.ADMIN)
    _seed_active_membership(storage, user.id, "org_anchor")
    before = _dump(db_path)

    with pytest.raises(LastActiveAdministratorError):
        _revoke(storage)

    # The refusal is translated nowhere and mutates nothing: role, timestamps,
    # and audit count are byte-identical to the pre-call snapshot.
    assert _dump(db_path) == before
    assert _rows(db_path, "audit_events") == []
    assert _rows(db_path, "users")[0]["application_role"] == "admin"


# ---------------------------------------------------------------------------
# Ambiguous email: refuse with both usr_ ids, storage untouched
# ---------------------------------------------------------------------------


def test_ambiguous_email_raises_with_both_ids_and_leaves_storage_untouched(
    db_path: Path,
) -> None:
    storage = open_sqlite_storage(db_path)
    first = _seed_user(storage, "usr_dup_one")
    second = _seed_user(storage, "usr_dup_two")
    _seed_active_membership(storage, first.id, "org_dup_a")
    _seed_active_membership(storage, second.id, "org_dup_b")
    before = _dump(db_path)

    with pytest.raises(AmbiguousAdministratorEmailError) as excinfo:
        _grant(storage)

    message = str(excinfo.value)
    assert str(first.id) in message
    assert str(second.id) in message
    assert excinfo.value.count == 2
    # Resolution happens before any anchor/transition work: zero mutation.
    assert _dump(db_path) == before

    # The same rule governs the shared resolver itself.
    with pytest.raises(AmbiguousAdministratorEmailError):
        resolve_unique_user(storage, _EMAIL)


# ---------------------------------------------------------------------------
# Audit metadata: the exact two-key secret-free shape, on real rows
# ---------------------------------------------------------------------------


def test_audit_metadata_is_the_exact_two_key_secret_free_shape(db_path: Path) -> None:
    storage = open_sqlite_storage(db_path)
    user = _seed_user(storage, "usr_metadata")
    _seed_active_membership(storage, user.id, "org_anchor")

    _grant(storage)

    audits = _rows(db_path, "audit_events")
    assert len(audits) == 1
    raw = str(audits[0]["metadata"])
    metadata = json.loads(raw)
    assert metadata == {"from_role": "user", "to_role": "admin"}
    assert set(metadata) == {"from_role", "to_role"}
    # Secret-free: the whole persisted row (metadata JSON included) carries no
    # email, no provider subject, and no token material.
    assert _EMAIL not in raw
    assert "@" not in raw
    assert "sub" not in metadata
    assert "token" not in metadata
    assert "cognito" not in raw.lower()
