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
- Phase 12 coexistence (different ``sub``, same email): the second login
  provisions a **second, independent user** with its own personal org and
  owner membership — email is no longer a conflict, the identity tuple is
  the only convergence key, and neither batch leaves partial rows;
- Phase 12 role persistence: a store-seeded ``application_role=ADMIN`` user
  comes back from the login hit path with role, status, email, and
  ``updated_at`` unchanged (set directly through the adapter; no service API
  grants roles);
- Phase 11's verified profile (task 5): the miss path provisions **only**
  from a gated :class:`~app.auth.cognito.CognitoProfile` (email and display
  name), a miss without a profile provider raises ``TokenValidationError``
  with no rows written, the hit path performs zero profile work and never
  overwrites the stored email, and a profile failing
  :func:`~app.auth.cognito.require_provisioning_profile` raises
  ``TokenValidationError`` with **no rows written**.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.auth.cognito import CognitoClaims, CognitoProfile
from app.auth.errors import TokenValidationError
from app.models.enums import (
    ApplicationRole,
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity
from app.models.ids import ExternalIdentityId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services.identity import (
    DisabledUserError,
    resolve_or_provision,
)
from app.storage.contract import Storage
from app.storage.sqlite import TABLE_NAMES, open_sqlite_storage

_NOW = datetime(2026, 9, 13, 8, 30, 0, tzinfo=UTC)


def _claims(
    *,
    sub: str = "cognito-sub-sqlite",
    email: str | None = "dev@example.test",
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
        resolved = resolve_or_provision(
            storage,
            _claims(),
            now=_NOW,
            profile_provider=lambda: _profile(email="dev@example.test", display_name="Dev"),
        )
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
        first = resolve_or_provision(
            storage, _claims(), now=_NOW, profile_provider=lambda: _profile()
        )
        # The second call is a hit: it needs no provider at all (task 5).
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
        "oauth_login_states": 0,
        "app_sessions": 0,
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
# Email coexistence on real storage (Phase 12): two users, two orgs, no
# partial rows
# ---------------------------------------------------------------------------


def test_email_coexistence_provisions_two_users_with_own_orgs(db_path: Path) -> None:
    """A *different* sub whose verified profile carries an existing user's
    email is a legitimate second shadow user: the service provisions it in
    full through the same batch path, the two users coexist with separate
    personal orgs, and nothing partial is left behind (Phase 12 retired the
    old email-collision conflict and the adapter's by-email fallback)."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        first = resolve_or_provision(
            storage,
            _claims(sub="cognito-sub-sqlite"),
            now=_NOW,
            profile_provider=lambda: _profile(sub="cognito-sub-sqlite", email="dev@example.test"),
        )
        second = resolve_or_provision(
            storage,
            _claims(sub="brand-new-sub", email=None),
            now=_NOW,
            profile_provider=lambda: _profile(sub="brand-new-sub", email="dev@example.test"),
        )
    finally:
        storage.close()

    assert first.user.id != second.user.id
    assert first.context.organization_id != second.context.organization_id
    assert _counts(db_path) == {
        "users": 2,  # both batches committed in full
        "external_identities": 2,
        "organizations": 2,  # each user owns its own personal org
        "memberships": 2,
        "api_keys": 0,
        "audit_events": 6,
        "oauth_login_states": 0,
        "app_sessions": 0,
    }
    users = {str(row["id"]): row["email"] for row in _rows(db_path, "users")}
    assert set(users) == {str(first.user.id), str(second.user.id)}
    assert set(users.values()) == {"dev@example.test"}  # shared address, two rows


# ---------------------------------------------------------------------------
# Phase 12: a store-granted ADMIN survives the login hit path unchanged
# ---------------------------------------------------------------------------


def test_admin_role_survives_login_hit_path_unchanged(db_path: Path) -> None:
    """A user seeded with ``application_role=ADMIN`` **directly through the
    adapter** (no service API grants roles) comes back from a login hit with
    role, status, email, and ``updated_at`` unchanged: login never rewrites
    or escalates the global role (spec 12 invariants 2—3)."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        seeded = storage.create_user(
            User(
                id=UserId("usr_admin_seed"),
                display_name="Admin",
                email="admin@example.test",
                status=UserStatus.ACTIVE,
                application_role=ApplicationRole.ADMIN,
                created_at=_NOW,
                updated_at=_NOW,
            )
        )
        storage.create_external_identity(
            ExternalIdentity(
                id=ExternalIdentityId("extid_admin_seed"),
                user_id=seeded.id,
                provider=IdentityProvider.COGNITO,
                provider_subject="cognito-sub-sqlite",
                provider_tenant=None,
                created_at=_NOW,
            )
        )
        storage.create_organization(
            Organization(
                id=OrganizationId("org_admin_seed"),
                name="Admin's Workspace",
                slug="personal-usr_admin_seed",
                type=OrganizationType.PERSONAL,
                status=OrganizationStatus.ACTIVE,
                created_at=_NOW,
                updated_at=_NOW,
            )
        )
        storage.create_membership(
            Membership(
                id=MembershipId("mem_admin_seed"),
                organization_id=OrganizationId("org_admin_seed"),
                user_id=seeded.id,
                role=MembershipRole.OWNER,
                status=MembershipStatus.ACTIVE,
                created_at=_NOW,
            )
        )
        later = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)
        resolved = resolve_or_provision(storage, _claims(), now=later)

        # The hit path returns the stored model byte-for-byte (role, status,
        # email, and updated_at included) and re-reads identical state.
        assert resolved.user == seeded
        assert resolved.user.application_role is ApplicationRole.ADMIN
        assert resolved.user.status is UserStatus.ACTIVE
        assert resolved.user.email == "admin@example.test"
        assert resolved.user.updated_at == _NOW
        assert storage.get_user(seeded.id) == seeded
    finally:
        storage.close()

    users = _rows(db_path, "users")
    assert len(users) == 1
    assert users[0]["application_role"] == "admin"  # persisted grant, not the default
    assert _counts(db_path) == {
        "users": 1,
        "external_identities": 1,
        "organizations": 1,
        "memberships": 1,
        "api_keys": 0,
        "audit_events": 0,  # zero writes: no provisioning, no login mutation
        "oauth_login_states": 0,
        "app_sessions": 0,
    }


# ---------------------------------------------------------------------------
# Phase 11: verified-profile seam on the provisioning path
# ---------------------------------------------------------------------------


def _profile(
    *,
    sub: str = "cognito-sub-sqlite",
    email: str | None = "verified@example.test",
    email_verified: bool = True,
    display_name: str | None = "Verified Person",
) -> CognitoProfile:
    return CognitoProfile(
        sub=sub,
        email=email,
        email_verified=email_verified,
        display_name=display_name,
    )


def test_first_login_with_profile_stores_profile_email_and_display_name(
    db_path: Path,
) -> None:
    """Miss path with a provider: profile wins for email and display name."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        resolved = resolve_or_provision(
            storage,
            _claims(email=None, username="Dev"),
            now=_NOW,
            profile_provider=lambda: _profile(),
        )
    finally:
        storage.close()

    users = _rows(db_path, "users")
    assert len(users) == 1
    assert str(users[0]["id"]) == str(resolved.user.id)
    assert users[0]["email"] == "verified@example.test"
    assert users[0]["display_name"] == "Verified Person"
    organizations = _rows(db_path, "organizations")
    assert organizations[0]["name"] == "Verified Person's Workspace"


def test_profile_display_name_falls_back_to_username_then_sub(db_path: Path) -> None:
    """Profile display_name None → claims.username; both None → claims.sub."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        resolve_or_provision(
            storage,
            _claims(sub="fallback-username", username="Dev"),
            now=_NOW,
            profile_provider=lambda: _profile(
                sub="fallback-username",
                email="fb-username@example.test",
                display_name=None,
            ),
        )
        resolve_or_provision(
            storage,
            _claims(sub="fallback-sub", username=None),
            now=_NOW,
            profile_provider=lambda: _profile(
                sub="fallback-sub",
                email="fb-sub@example.test",
                display_name=None,
            ),
        )
    finally:
        storage.close()

    users = {row["id"]: row["display_name"] for row in _rows(db_path, "users")}
    display_names = {
        row["provider_subject"]: users[row["user_id"]]
        for row in _rows(db_path, "external_identities")
    }
    assert display_names == {"fallback-username": "Dev", "fallback-sub": "fallback-sub"}


def test_hit_path_never_calls_profile_provider_and_keeps_stored_email(
    db_path: Path,
) -> None:
    """Second login: zero profile work, stored email untouched (no overwrite)."""
    storage: Storage = open_sqlite_storage(db_path)
    calls = 0
    try:
        resolve_or_provision(storage, _claims(), now=_NOW, profile_provider=lambda: _profile())

        def counting_provider() -> CognitoProfile:
            nonlocal calls
            calls += 1
            return _profile(email="someone-else@example.test")

        resolve_or_provision(storage, _claims(), now=_NOW, profile_provider=counting_provider)
    finally:
        storage.close()

    assert calls == 0
    users = _rows(db_path, "users")
    assert len(users) == 1
    assert users[0]["email"] == "verified@example.test"
    assert _counts(db_path) == {
        "users": 1,
        "external_identities": 1,
        "organizations": 1,
        "memberships": 1,
        "api_keys": 0,
        "audit_events": 3,
        "oauth_login_states": 0,
        "app_sessions": 0,
    }


def test_unverified_profile_gate_failure_provisions_nothing(db_path: Path) -> None:
    """email_verified False fails the gate before provision_user: zero rows."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        before = _counts(db_path)
        with pytest.raises(TokenValidationError, match="email is not verified"):
            resolve_or_provision(
                storage,
                _claims(),
                now=_NOW,
                profile_provider=lambda: _profile(email_verified=False),
            )
        assert _counts(db_path) == before  # gate ran before any write
    finally:
        storage.close()


def test_profile_subject_mismatch_provisions_nothing(db_path: Path) -> None:
    """A profile for another subject is refused; the email is never interpolated."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        with pytest.raises(TokenValidationError, match="subject does not match") as excinfo:
            resolve_or_provision(
                storage,
                _claims(sub="cognito-sub-sqlite"),
                now=_NOW,
                profile_provider=lambda: _profile(sub="someone-else"),
            )
        assert "someone-else" not in str(excinfo.value)
        assert "verified@example.test" not in str(excinfo.value)
        assert _counts(db_path) == {
            "users": 0,
            "external_identities": 0,
            "organizations": 0,
            "memberships": 0,
            "api_keys": 0,
            "audit_events": 0,
            "oauth_login_states": 0,
            "app_sessions": 0,
        }
    finally:
        storage.close()


def test_miss_without_profile_provider_provisions_nothing(db_path: Path) -> None:
    """Task 5: the claims-only fallback is gone — a first-login miss with no
    provider is a 401-class refusal (email-carrying claims included) and the
    store stays empty."""
    storage: Storage = open_sqlite_storage(db_path)
    try:
        with pytest.raises(
            TokenValidationError, match="verified profile required for provisioning"
        ):
            resolve_or_provision(storage, _claims(), now=_NOW)
        assert _counts(db_path) == {
            "users": 0,
            "external_identities": 0,
            "organizations": 0,
            "memberships": 0,
            "api_keys": 0,
            "audit_events": 0,
            "oauth_login_states": 0,
            "app_sessions": 0,
        }
    finally:
        storage.close()
