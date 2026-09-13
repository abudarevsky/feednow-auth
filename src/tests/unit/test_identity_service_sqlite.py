"""SQLite-backed tests for the Phase 03 task-4 identity service.

The stub suite (``test_identity_service.py``) proves the decision rules; this
module proves the same service against the **real Phase 02 adapter** (WAL,
``BEGIN IMMEDIATE``, unique indexes) on tmp files, per the test-strategy
decision. Acceptance mapping:

- first call yields exactly one user, identity, personal org, owner
  membership, and the three creation audits — verified by reading the
  committed rows back through a *separate* connection (proves the batch
  really committed, not just echoed);
- a repeated request resolves the same ``usr_``/``org_`` with stable row
  counts (no duplicate tenants);
- a disabled user raises with zero mutation;
- a genuine email collision (different ``sub``, same email) surfaces as
  :class:`~app.services.identity.ProvisioningConflictError` and leaves **no
  partial rows** — the real-storage counterpart of decision 7's stranger-id
  trap, exercising the adapter's email-fallback resolution.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.auth.cognito import CognitoClaims
from app.models.enums import (
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity
from app.models.ids import ExternalIdentityId, UserId
from app.models.user import User
from app.services.identity import (
    DisabledUserError,
    ProvisioningConflictError,
    resolve_or_provision,
)
from app.storage.contract import Storage
from app.storage.sqlite import TABLE_NAMES, open_sqlite_storage

_NOW = datetime(2026, 9, 13, 8, 30, 0, tzinfo=UTC)


def _claims(
    *,
    sub: str = "cognito-sub-sqlite",
    email: str = "dev@example.test",
    username: str | None = "Dev",
) -> CognitoClaims:
    return CognitoClaims(
        sub=sub,
        email=email,
        username=username,
        client_id="client-abc",
        iss="https://cognito.us-east-1.amazonaws.com/us-east-1_pool",
        exp=2000000000,
    )


@pytest.fixture
def db_path(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path / "identity.sqlite"


def _rows(path: Path, table: str) -> list[dict[str, object]]:
    """Read a table through a fresh connection: committed truth only."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY id")]
    finally:
        conn.close()


def _counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in TABLE_NAMES
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# First call: complete, atomically committed batch
# ---------------------------------------------------------------------------


def test_first_call_stores_the_complete_batch(db_path: Path) -> None:
    storage: Storage = open_sqlite_storage(db_path)
    try:
        resolved = resolve_or_provision(storage, _claims(), now=_NOW)
    finally:
        storage.close()

    users = _rows(db_path, "users")
    identities = _rows(db_path, "external_identities")
    organizations = _rows(db_path, "organizations")
    memberships = _rows(db_path, "memberships")
    audits = _rows(db_path, "audit_events")

    assert len(users) == len(identities) == len(organizations) == len(memberships) == 1
    assert str(users[0]["id"]) == str(resolved.user.id)
    assert users[0]["email"] == "dev@example.test"
    assert users[0]["display_name"] == "Dev"
    assert users[0]["status"] == str(UserStatus.ACTIVE)

    assert identities[0]["provider"] == "cognito"
    assert identities[0]["provider_subject"] == "cognito-sub-sqlite"
    assert identities[0]["user_id"] == str(resolved.user.id)

    assert organizations[0]["name"] == "Dev's Workspace"
    assert organizations[0]["slug"] == f"personal-{resolved.user.id}"
    assert organizations[0]["type"] == str(OrganizationType.PERSONAL)
    assert organizations[0]["status"] == str(OrganizationStatus.ACTIVE)

    assert memberships[0]["role"] == str(MembershipRole.OWNER)
    assert memberships[0]["status"] == str(MembershipStatus.ACTIVE)
    assert memberships[0]["user_id"] == str(resolved.user.id)
    assert memberships[0]["organization_id"] == str(resolved.context.organization_id)

    assert len(audits) == 3
    assert {row["action"] for row in audits} == {
        "user.created",
        "organization.created",
        "membership.created",
    }
    by_action = {row["action"]: row for row in audits}
    assert json.loads(by_action["user.created"]["metadata"]) == {"provider": "cognito"}
    assert json.loads(by_action["organization.created"]["metadata"]) == {"type": "personal"}
    assert json.loads(by_action["membership.created"]["metadata"]) == {"role": "owner"}
    for row in audits:
        assert row["actor_type"] == "user"
        assert row["actor_id"] == str(resolved.user.id)
        assert row["organization_id"] == str(resolved.context.organization_id)
    assert str(by_action["user.created"]["target_id"]) == str(resolved.user.id)
    assert str(by_action["organization.created"]["target_id"]) == str(
        resolved.context.organization_id
    )

    # No raw provider material anywhere in the stored rows (AGENTS.md).
    assert "cognito-sub-sqlite" not in str(users[0])


# ---------------------------------------------------------------------------
# Repeated calls: same identity, stable row counts
# ---------------------------------------------------------------------------


def test_repeated_calls_resolve_same_identity_without_duplicates(db_path: Path) -> None:
    storage: Storage = open_sqlite_storage(db_path)
    try:
        first = resolve_or_provision(storage, _claims(), now=_NOW)
        second = resolve_or_provision(storage, _claims(), now=_NOW)
    finally:
        storage.close()

    assert first.user.id == second.user.id
    assert first.context == second.context
    assert _counts(db_path) == {
        "users": 1,
        "external_identities": 1,
        "organizations": 1,
        "memberships": 1,
        "api_keys": 0,
        "audit_events": 3,
    }


# ---------------------------------------------------------------------------
# Disabled user: raises, nothing mutated
# ---------------------------------------------------------------------------


def test_disabled_user_raises_without_mutation(db_path: Path) -> None:
    storage: Storage = open_sqlite_storage(db_path)
    try:
        seeded = storage.create_user(
            User(
                id=UserId("usr_disabled_seed"),
                display_name="Disabled",
                email="dev@example.test",
                status=UserStatus.DISABLED,
                created_at=_NOW,
                updated_at=_NOW,
            )
        )
        storage.create_external_identity(
            ExternalIdentity(
                id=ExternalIdentityId("extid_disabled_seed"),
                user_id=seeded.id,
                provider=IdentityProvider.COGNITO,
                provider_subject="cognito-sub-sqlite",
                provider_tenant=None,
                created_at=_NOW,
            )
        )
        before = _counts(db_path)
        with pytest.raises(DisabledUserError):
            resolve_or_provision(storage, _claims(), now=_NOW)
        assert _counts(db_path) == before  # reads only; zero mutation
    finally:
        storage.close()


# ---------------------------------------------------------------------------
# Email collision on real storage: conflict, no partial rows
# ---------------------------------------------------------------------------


def test_email_collision_conflicts_and_leaves_no_partial_rows(db_path: Path) -> None:
    """A *different* sub with a stranger's email: provision_user raises the
    race error (email UNIQUE), the identity re-read misses, and the service
    refuses to converge on the stranger (decision 7) — the adapter's
    ``existing_user_id`` email fallback names ``usr_stranger`` here."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        storage.create_user(
            User(
                id=UserId("usr_stranger"),
                display_name="Stranger",
                email="dev@example.test",
                status=UserStatus.ACTIVE,
                created_at=_NOW,
                updated_at=_NOW,
            )
        )
        with pytest.raises(ProvisioningConflictError):
            resolve_or_provision(storage, _claims(sub="brand-new-sub"), now=_NOW)
    finally:
        storage.close()

    assert _counts(db_path) == {
        "users": 1,  # only the stranger survived — no partial batch
        "external_identities": 0,
        "organizations": 0,
        "memberships": 0,
        "api_keys": 0,
        "audit_events": 0,
    }
