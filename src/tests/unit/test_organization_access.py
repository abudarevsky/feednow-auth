"""Unit tests for the Phase 04 task-3 shared organization-access dependency.

Per the breakdown, the probes run against a router defined **in this test
module** (the design rule is that *shipped* routers register manifest entries
only; nothing scans test modules), on the Phase 03 fake-verifier/real-SQLite
pattern. Acceptance-critical proofs:

1. Each of the five decision-4 denial outcomes (unknown org, no membership,
   inactive membership, inactive organization, insufficient role) answers the
   **byte-identical** 403 envelope — no existence oracle.
2. The audit row is present for the four org-exists cases (read directly
   from the SQLite file — no audit read surface in the contract) and
   **provably absent** for the unknown-org case.
3. An insufficient-role denial appends ``authorization.denied`` *before* the
   handler body runs — the probe handler records that it was never called.
4. The grant path exposes the resolved organization + membership to the
   handler.
5. Authentication failures (401) precede the dependency and are not denial
   audits; a request that will be denied still auto-provisions a first-seen
   identity (authn precedes authz, spec §6).
6. A denial whose audit append fails is a 500 (fail-closed), never a silent
   403.
"""

# No ``from __future__ import annotations`` here on purpose (the ``me.py``
# precedent): the probe handlers reference closure-local dependencies in
# ``Annotated[..., Depends(...)]`` position, which PEP 563 stringification
# could not resolve at import time.
import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.auth.cognito import CognitoClaims
from app.auth.errors import TokenValidationError
from app.auth.organization_access import (
    ORGANIZATION_FORBIDDEN_MESSAGE,
    OrganizationAccess,
    build_organization_admin_dependency,
    build_organization_member_dependency,
)
from app.main import create_app
from app.models.enums import (
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
from app.storage.contract import StorageError
from app.storage.sqlite import SQLiteStorage

_T0 = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Seeding helpers (create-only contract methods; role-matrix users are
# seeded, not provisioned — breakdown decision 9)
# ---------------------------------------------------------------------------


def seed_user(storage: SQLiteStorage, *, user_id: str, sub: str, email: str) -> User:
    user = User(
        id=UserId(user_id),
        display_name=f"seed {user_id}",
        email=email,
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )
    storage.create_user(user)
    storage.create_external_identity(
        ExternalIdentity(
            id=ExternalIdentityId(f"extid_{user_id.removeprefix('usr_')}"),
            user_id=UserId(user_id),
            provider=IdentityProvider.COGNITO,
            provider_subject=sub,
            provider_tenant=None,
            created_at=_T0,
        )
    )
    return user


def seed_org(
    storage: SQLiteStorage,
    *,
    organization_id: str,
    slug: str,
    created_at: datetime = _T0,
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
) -> Organization:
    organization = Organization(
        id=OrganizationId(organization_id),
        name=f"seed {organization_id}",
        slug=slug,
        type=OrganizationType.CUSTOMER,
        status=status,
        created_at=created_at,
        updated_at=created_at,
    )
    storage.create_organization(organization)
    return organization


def seed_membership(
    storage: SQLiteStorage,
    *,
    organization_id: str,
    user_id: str,
    role: MembershipRole,
    status: MembershipStatus = MembershipStatus.ACTIVE,
    membership_id: str = "mem_seed",
) -> Membership:
    membership = Membership(
        id=MembershipId(membership_id),
        organization_id=OrganizationId(organization_id),
        user_id=UserId(user_id),
        role=role,
        status=status,
        created_at=_T0,
    )
    storage.create_membership(membership)
    return membership


class FakeVerifier:
    """Token-string -> claims; anything unknown is a fixed 401 failure."""

    def __init__(self) -> None:
        self.claims_by_token: dict[str, CognitoClaims] = {}

    def verify(self, token: str) -> CognitoClaims:
        try:
            return self.claims_by_token[token]
        except KeyError as exc:
            raise TokenValidationError("token failed verification") from exc


class FailingAuditStorage:
    """Delegates everything but ``append_audit_event`` (raises StorageError)."""

    def __init__(self, inner: SQLiteStorage) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def append_audit_event(self, audit_event: Any) -> None:
        raise StorageError("storage write failed")


class Env:
    """Probe app + real SQLite + fake verifier; handler calls are recorded."""

    def __init__(self, db_path: Path, storage: SQLiteStorage | FailingAuditStorage) -> None:
        self.db_path = db_path
        self.storage = storage
        self.verifier = FakeVerifier()
        self.handler_calls: list[tuple[str, str]] = []
        self._next_token = 0
        member_dep = build_organization_member_dependency(
            storage, self.verifier, "get_organization"
        )
        admin_dep = build_organization_admin_dependency(storage, self.verifier, "create_member")

        router = APIRouter()

        def member_probe(
            organization_id: OrganizationId,
            access: Annotated[OrganizationAccess, Depends(member_dep)],
        ) -> dict[str, str]:
            self.handler_calls.append(("member", str(organization_id)))
            return {
                "organization": str(access.organization.id),
                "role": str(access.membership.role),
                "actor": str(access.identity.user.id),
            }

        def admin_probe(
            organization_id: OrganizationId,
            access: Annotated[OrganizationAccess, Depends(admin_dep)],
        ) -> dict[str, str]:
            self.handler_calls.append(("admin", str(organization_id)))
            return {
                "organization": str(access.organization.id),
                "role": str(access.membership.role),
            }

        router.add_api_route("/v1/probe/member/{organization_id}", member_probe, methods=["GET"])
        router.add_api_route("/v1/probe/admin/{organization_id}", admin_probe, methods=["GET"])
        self.client = TestClient(create_app(routers=[router]), raise_server_exceptions=False)

    def login(self, sub: str, email: str) -> str:
        self._next_token += 1
        token = f"tok-{self._next_token}"
        self.claims = CognitoClaims(
            sub=sub,
            email=email,
            username="probe-user",
            client_id="probe-client",
            iss="https://probe.example.test/pool",
            exp=int(_T0.timestamp()) + 3600,
        )
        self.verifier.claims_by_token[token] = self.claims
        return token

    def auth(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def denial_rows(self) -> list[dict[str, Any]]:
        """Read ``authorization.denied`` audit rows straight from the file."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT actor_id, organization_id, metadata FROM audit_events"
                " WHERE action = 'authorization.denied' ORDER BY created_at, id"
            ).fetchall()
        finally:
            conn.close()
        return [
            {
                "actor_id": row["actor_id"],
                "organization_id": row["organization_id"],
                "metadata": json.loads(row["metadata"]),
            }
            for row in rows
        ]


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    adapter = SQLiteStorage(tmp_path / "org_access.sqlite")
    built = Env(tmp_path / "org_access.sqlite", adapter)
    yield built
    adapter.close()


@pytest.fixture
def seeded(env: Env) -> Env:
    """Caller with memberships engineered for every decision-4 outcome.

    - ``org_a``: caller active **member** (earliest -> context anchor);
    - ``org_b``: active, caller has **no** membership (no_membership);
    - ``org_c``: active, caller's membership is **disabled**
      (inactive_membership);
    - ``org_d``: **disabled** org, caller holds an active viewer membership
      (inactive_organization);
    - ``org_e``: active, caller is an active **viewer** (insufficient_role
      for the admin probe);
    - ``org_owner``: caller is **owner** (admin probe grants).
    """
    seed_user(env.storage, user_id="usr_caller", sub="caller-sub", email="caller@example.test")
    seed_org(env.storage, organization_id="org_a", slug="org-a", created_at=_T0)
    seed_org(env.storage, organization_id="org_b", slug="org-b", created_at=_T0 + timedelta(1))
    seed_org(env.storage, organization_id="org_c", slug="org-c", created_at=_T0 + timedelta(2))
    seed_org(
        env.storage,
        organization_id="org_d",
        slug="org-d",
        created_at=_T0 + timedelta(3),
        status=OrganizationStatus.DISABLED,
    )
    seed_org(env.storage, organization_id="org_e", slug="org-e", created_at=_T0 + timedelta(4))
    seed_org(
        env.storage, organization_id="org_owner", slug="org-owner", created_at=_T0 + timedelta(5)
    )
    seed_membership(
        env.storage, organization_id="org_a", user_id="usr_caller", role=MembershipRole.MEMBER
    )
    seed_membership(
        env.storage,
        organization_id="org_c",
        user_id="usr_caller",
        role=MembershipRole.ADMIN,
        status=MembershipStatus.DISABLED,
        membership_id="mem_c",
    )
    seed_membership(
        env.storage,
        organization_id="org_d",
        user_id="usr_caller",
        role=MembershipRole.VIEWER,
        membership_id="mem_d",
    )
    seed_membership(
        env.storage,
        organization_id="org_e",
        user_id="usr_caller",
        role=MembershipRole.VIEWER,
        membership_id="mem_e",
    )
    seed_membership(
        env.storage,
        organization_id="org_owner",
        user_id="usr_caller",
        role=MembershipRole.OWNER,
        membership_id="mem_owner",
    )
    env.token = env.login("caller-sub", "caller@example.test")
    return env


# ---------------------------------------------------------------------------
# 4. Grant paths
# ---------------------------------------------------------------------------


def test_member_dependency_grants_any_active_role(seeded: Env) -> None:
    response = seeded.client.get("/v1/probe/member/org_e", headers=seeded.auth(seeded.token))
    assert response.status_code == 200
    assert response.json() == {
        "organization": "org_e",
        "role": "viewer",
        "actor": "usr_caller",
    }
    assert seeded.handler_calls == [("member", "org_e")]
    assert seeded.denial_rows() == []  # grants are never audited here


def test_admin_dependency_grants_owner_and_admin(seeded: Env) -> None:
    response = seeded.client.get("/v1/probe/admin/org_owner", headers=seeded.auth(seeded.token))
    assert response.status_code == 200
    assert response.json() == {"organization": "org_owner", "role": "owner"}
    assert seeded.denial_rows() == []


# ---------------------------------------------------------------------------
# 1/2/3. The five denial outcomes: one byte-identical 403, audited where the
#        FK allows, and never reaching the handler body
# ---------------------------------------------------------------------------


def test_five_denial_outcomes_share_one_byte_identical_403(seeded: Env) -> None:
    cases = [
        ("/v1/probe/member/org_ghost", "member", None),  # unknown org: no FK target
        ("/v1/probe/member/org_b", "member", "no_membership"),
        ("/v1/probe/member/org_c", "member", "inactive_membership"),
        ("/v1/probe/member/org_d", "member", "inactive_organization"),
        ("/v1/probe/admin/org_e", "admin", "insufficient_role"),
    ]
    bodies: list[bytes] = []
    for path, _probe, _reason in cases:
        response = seeded.client.get(path, headers=seeded.auth(seeded.token))
        assert response.status_code == 403, path
        bodies.append(response.content)
    # Byte-identical: the response alone can never distinguish the outcomes.
    assert all(body == bodies[0] for body in bodies)
    envelope = json.loads(bodies[0])
    assert envelope["code"] == "forbidden"
    assert envelope["message"] == ORGANIZATION_FORBIDDEN_MESSAGE
    # The handler body never ran for any denial (proof 3: the audit append
    # happens before the raise, and the probe records nothing).
    assert seeded.handler_calls == []
    # Audit rows: exactly one per org-exists denial, none for the unknown org.
    rows = seeded.denial_rows()
    assert [row["metadata"]["reason"] for row in rows] == [
        "no_membership",
        "inactive_membership",
        "inactive_organization",
        "insufficient_role",
    ]
    for row in rows:
        assert row["actor_id"] == "usr_caller"
        assert row["organization_id"] in {"org_b", "org_c", "org_d", "org_e"}
        assert set(row["metadata"]) == {"reason", "operation"}
    assert rows[0]["metadata"]["operation"] == "get_organization"  # member probe op id
    assert rows[3]["metadata"]["operation"] == "create_member"  # admin probe op id
    assert all("@" not in json.dumps(row) for row in rows)  # no email material


def test_unknown_organization_denial_leaves_no_audit_row(seeded: Env) -> None:
    response = seeded.client.get("/v1/probe/member/org_ghost", headers=seeded.auth(seeded.token))
    assert response.status_code == 403
    assert seeded.denial_rows() == []


# ---------------------------------------------------------------------------
# 5. Authentication precedes authorization
# ---------------------------------------------------------------------------


def test_unauthenticated_request_is_401_not_a_denial(seeded: Env) -> None:
    response = seeded.client.get("/v1/probe/member/org_a")
    assert response.status_code == 401
    assert json.loads(response.content)["code"] == "unauthenticated"
    assert seeded.denial_rows() == []
    assert seeded.handler_calls == []


def test_denied_first_seen_identity_still_provisions(env: Env) -> None:
    # Authn precedes authz (spec §6): a brand-new Cognito identity that will
    # be denied still completes provisioning (personal org + owner member-
    # ship + three creation audits) before the uniform 403 + denial audit.
    seed_user(env.storage, user_id="usr_host", sub="host-sub", email="host@example.test")
    seed_org(env.storage, organization_id="org_host", slug="org-host")
    seed_membership(
        env.storage, organization_id="org_host", user_id="usr_host", role=MembershipRole.OWNER
    )
    token = env.login("fresh-sub", "fresh@example.test")

    response = env.client.get("/v1/probe/member/org_host", headers=env.auth(token))

    assert response.status_code == 403
    assert json.loads(response.content)["message"] == ORGANIZATION_FORBIDDEN_MESSAGE
    resolved = env.storage.get_user_by_external_identity(
        provider=IdentityProvider.COGNITO, provider_subject="fresh-sub"
    )
    assert resolved.status is UserStatus.ACTIVE
    rows = env.denial_rows()
    assert len(rows) == 1
    assert rows[0]["metadata"] == {"reason": "no_membership", "operation": "get_organization"}
    assert rows[0]["organization_id"] == "org_host"


# ---------------------------------------------------------------------------
# 6. Fail-closed: a denial that cannot be audited is a 500, never a silent 403
# ---------------------------------------------------------------------------


def test_audit_append_failure_on_denial_is_fail_closed_500(tmp_path: Path) -> None:
    adapter = SQLiteStorage(tmp_path / "fail_audit.sqlite")
    env = Env(tmp_path / "fail_audit.sqlite", FailingAuditStorage(adapter))
    seed_user(adapter, user_id="usr_caller", sub="caller-sub", email="caller@example.test")
    # Anchor membership so the auth chain resolves; org_b stays a no-
    # membership denial whose audit append then fails.
    seed_org(adapter, organization_id="org_a", slug="org-a")
    seed_membership(
        adapter, organization_id="org_a", user_id="usr_caller", role=MembershipRole.MEMBER
    )
    seed_org(adapter, organization_id="org_b", slug="org-b")
    token = env.login("caller-sub", "caller@example.test")

    response = env.client.get("/v1/probe/member/org_b", headers=env.auth(token))

    assert response.status_code == 500
    assert json.loads(response.content)["code"] == "internal_error"
    assert env.handler_calls == []
    adapter.close()
