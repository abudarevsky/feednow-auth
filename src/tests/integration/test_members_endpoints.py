"""Integration tests for the member endpoints (Phase 04 task 5).

Same Phase 03-proven stack as the organization tests (decision 9): loopback
JWKS-signed tokens, real SQLite, seeded owner/admin/member/viewer matrix in
one organization plus an outsider with their own anchor organization. Audit
and mutation-count assertions read the SQLite file directly.

Acceptance mapping (AC 2/3/4/5 for the three member routes):

- list: any member role 200 (all statuses visible, org-scoped), outsider
  403 + ``authorization.denied``;
- add: owner & admin 201 with ``membership.created`` audit; member & viewer
  403 + ``insufficient_role`` audit; ``role=owner`` → 400; existing pair
  (active **and** disabled) → 409; unknown target ``usr_`` → 404;
- remove: admin removing member/viewer (and self) → 204 + ``membership.removed``
  carrying the role at removal; removing the **owner** → 409 whether by
  admin or the owner self; non-member → 404; member/viewer callers → 403 +
  audit;
- cross-tenant outsider attempts on all three routes answer the identical
  403 body with zero mutation;
- no response body carries ``mem_`` record ids or emails.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.members import build_members_router
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.jwks import CognitoJwksSource
from app.main import create_app
from app.models.enums import (
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.errors import Error
from app.models.external_identity import ExternalIdentity
from app.models.ids import ExternalIdentityId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.storage.sqlite import SQLiteStorage

ALLOWED_CLIENT = "members-app-client"
_T0 = datetime(2026, 9, 13, 15, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Seeding helpers (matrix users are seeded, never provisioned)
# ---------------------------------------------------------------------------


def seed_user(storage: SQLiteStorage, *, user_id: str, sub: str | None = None, email: str) -> User:
    user = User(
        id=UserId(user_id),
        display_name=f"seed {user_id}",
        email=email,
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )
    storage.create_user(user)
    if sub is not None:
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
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
) -> Organization:
    organization = Organization(
        id=OrganizationId(organization_id),
        name=f"seed {organization_id}",
        slug=slug,
        type=OrganizationType.CUSTOMER,
        status=status,
        created_at=_T0,
        updated_at=_T0,
    )
    storage.create_organization(organization)
    return organization


def seed_membership(
    storage: SQLiteStorage,
    *,
    organization_id: str,
    user_id: str,
    role: MembershipRole,
    membership_id: str,
    status: MembershipStatus = MembershipStatus.ACTIVE,
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


def rows(db_path: Path, table: str) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
    finally:
        conn.close()


def denial_rows(db_path: Path) -> list[dict[str, Any]]:
    audits = [
        row for row in rows(db_path, "audit_events") if row["action"] == "authorization.denied"
    ]
    return sorted(audits, key=lambda row: (row["created_at"], row["id"]))


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("members-pool-key-1")


class _Env:
    def __init__(self, db_path: Path, server: JwksTestServer, key: TestKey) -> None:
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[ALLOWED_CLIENT],
        )
        app = create_app(routers=[build_members_router(self.storage, verifier)])
        self.client = TestClient(app, raise_server_exceptions=False)
        self.issuer = issuer
        self.key = key

    def token(self, sub: str, email: str) -> str:
        now = int(time.time())
        return sign_token(
            {
                "sub": sub,
                "email": email,
                "username": f"user-{sub}",
                "client_id": ALLOWED_CLIENT,
                "iss": self.issuer,
                "token_use": "access",
                "exp": now + 3600,
                "iat": now,
            },
            kid=self.key.kid,
            key=self.key,
        )

    def auth(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def headers_for(self, role_or_name: str) -> dict[str, str]:
        sub = f"{role_or_name}-sub"
        return self.auth(self.token(sub, f"{role_or_name}@example.test"))

    def close(self) -> None:
        self.storage.close()


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_Env]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _Env(tmp_path / "members.sqlite", server, key)
        yield built
        built.close()


@pytest.fixture
def matrix(env: _Env) -> _Env:
    """org_team seeded with owner/admin/member/viewer + a suspended member."""
    seed_user(env.storage, user_id="usr_owner", sub="owner-sub", email="owner@example.test")
    seed_user(env.storage, user_id="usr_admin", sub="admin-sub", email="admin@example.test")
    seed_user(env.storage, user_id="usr_member", sub="member-sub", email="member@example.test")
    seed_user(env.storage, user_id="usr_viewer", sub="viewer-sub", email="viewer@example.test")
    seed_user(env.storage, user_id="usr_susp", sub="susp-sub", email="susp@example.test")
    seed_org(env.storage, organization_id="org_team", slug="team-org")
    seed_membership(
        env.storage,
        organization_id="org_team",
        user_id="usr_owner",
        role=MembershipRole.OWNER,
        membership_id="mem_owner",
    )
    seed_membership(
        env.storage,
        organization_id="org_team",
        user_id="usr_admin",
        role=MembershipRole.ADMIN,
        membership_id="mem_admin",
    )
    seed_membership(
        env.storage,
        organization_id="org_team",
        user_id="usr_member",
        role=MembershipRole.MEMBER,
        membership_id="mem_member",
    )
    seed_membership(
        env.storage,
        organization_id="org_team",
        user_id="usr_viewer",
        role=MembershipRole.VIEWER,
        membership_id="mem_viewer",
    )
    seed_membership(
        env.storage,
        organization_id="org_team",
        user_id="usr_susp",
        role=MembershipRole.MEMBER,
        membership_id="mem_susp",
        status=MembershipStatus.DISABLED,
    )
    # Outsider with their own anchor organization (auth-chain context).
    seed_user(env.storage, user_id="usr_outsider", sub="outsider-sub", email="out@example.test")
    seed_org(env.storage, organization_id="org_outside", slug="outside-org")
    seed_membership(
        env.storage,
        organization_id="org_outside",
        user_id="usr_outsider",
        role=MembershipRole.OWNER,
        membership_id="mem_outside",
    )
    # A target user with no memberships at all (addable).
    seed_user(env.storage, user_id="usr_new", email="new@example.test")
    return env


# ---------------------------------------------------------------------------
# GET .../members
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
def test_list_members_200_for_any_active_role_showing_all_statuses(matrix: _Env, role: str) -> None:
    response = matrix.client.get(
        "/v1/organizations/org_team/members", headers=matrix.headers_for(role)
    )
    assert response.status_code == 200
    page = response.json()
    listed = {item["user_id"]: item for item in page["items"]}
    assert set(listed) == {"usr_owner", "usr_admin", "usr_member", "usr_viewer", "usr_susp"}
    assert listed["usr_susp"]["status"] == "disabled"  # all statuses (decision 8)
    assert listed["usr_owner"]["role"] == "owner"
    # Org-scoped and record-id-free: no mem_ ids, no emails in any body.
    serialized = json.dumps(page)
    assert "mem_" not in serialized
    assert "@" not in serialized


def test_list_members_outsider_403_with_denial_audit(matrix: _Env) -> None:
    response = matrix.client.get(
        "/v1/organizations/org_team/members", headers=matrix.headers_for("outsider")
    )
    assert response.status_code == 403
    envelope = Error.model_validate(response.json())
    assert envelope.code == "forbidden"
    assert envelope.message == "you do not have permission to access this organization"
    audits = denial_rows(matrix.db_path)
    assert len(audits) == 1
    assert json.loads(audits[0]["metadata"]) == {
        "reason": "no_membership",
        "operation": "list_members",
    }


# ---------------------------------------------------------------------------
# POST .../members
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("caller", ["owner", "admin"])
def test_add_member_201_with_created_audit(matrix: _Env, caller: str) -> None:
    response = matrix.client.post(
        "/v1/organizations/org_team/members",
        headers=matrix.headers_for(caller),
        json={"user_id": "usr_new", "role": "member"},
    )
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"user_id", "role", "status", "created_at"}
    assert body["user_id"] == "usr_new"
    assert body["role"] == "member"
    assert body["status"] == "active"
    stored = [row for row in rows(matrix.db_path, "memberships") if row["user_id"] == "usr_new"]
    assert len(stored) == 1
    assert stored[0]["organization_id"] == "org_team"
    assert stored[0]["role"] == "member"
    assert stored[0]["status"] == "active"
    audits = [
        row for row in rows(matrix.db_path, "audit_events") if row["action"] == "membership.created"
    ]
    assert len(audits) == 1
    assert json.loads(audits[0]["metadata"]) == {"role": "member"}
    assert audits[0]["actor_id"] == f"usr_{caller}"
    assert audits[0]["target_type"] == "membership"
    assert audits[0]["target_id"] == stored[0]["id"]  # mem_ id lives only in the audit
    assert audits[0]["organization_id"] == "org_team"


@pytest.mark.parametrize("caller", ["member", "viewer"])
def test_add_member_by_low_rank_caller_is_403_with_audit_and_zero_write(
    matrix: _Env, caller: str
) -> None:
    before = len(rows(matrix.db_path, "memberships"))
    response = matrix.client.post(
        "/v1/organizations/org_team/members",
        headers=matrix.headers_for(caller),
        json={"user_id": "usr_new", "role": "member"},
    )
    assert response.status_code == 403
    audits = denial_rows(matrix.db_path)
    assert len(audits) == 1
    assert json.loads(audits[0]["metadata"]) == {
        "reason": "insufficient_role",
        "operation": "create_member",
    }
    assert len(rows(matrix.db_path, "memberships")) == before


def test_add_member_owner_role_is_400_with_zero_write(matrix: _Env) -> None:
    response = matrix.client.post(
        "/v1/organizations/org_team/members",
        headers=matrix.headers_for("admin"),
        json={"user_id": "usr_new", "role": "owner"},
    )
    assert response.status_code == 400
    envelope = Error.model_validate(response.json())
    assert envelope.code == "validation_error"
    assert envelope.message == "the owner role cannot be granted through the membership API"
    assert [row for row in rows(matrix.db_path, "memberships") if row["user_id"] == "usr_new"] == []


@pytest.mark.parametrize(
    ("target", "membership_id"),
    [("usr_member", "mem_member"), ("usr_susp", "mem_susp")],
    ids=["active pair", "disabled pair"],
)
def test_add_member_existing_pair_is_409(matrix: _Env, target: str, membership_id: str) -> None:
    before = len(rows(matrix.db_path, "memberships"))
    response = matrix.client.post(
        "/v1/organizations/org_team/members",
        headers=matrix.headers_for("admin"),
        json={"user_id": target, "role": "viewer"},
    )
    assert response.status_code == 409
    envelope = Error.model_validate(response.json())
    assert envelope.code == "conflict"
    assert envelope.message == "user is already a member of this organization"
    assert len(rows(matrix.db_path, "memberships")) == before
    assert [
        row for row in rows(matrix.db_path, "audit_events") if row["action"] == "membership.created"
    ] == []


def test_add_member_unknown_target_is_404_with_zero_write(matrix: _Env) -> None:
    response = matrix.client.post(
        "/v1/organizations/org_team/members",
        headers=matrix.headers_for("admin"),
        json={"user_id": "usr_ghost", "role": "member"},
    )
    assert response.status_code == 404
    envelope = Error.model_validate(response.json())
    assert envelope.code == "not_found"
    assert envelope.message == "target user does not exist"
    assert [
        row for row in rows(matrix.db_path, "memberships") if row["user_id"] == "usr_ghost"
    ] == []
    assert [
        row for row in rows(matrix.db_path, "audit_events") if row["action"] == "membership.created"
    ] == []


# ---------------------------------------------------------------------------
# DELETE .../members/{user_id}
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("caller", "target", "role_at_removal"),
    [
        ("admin", "usr_member", "member"),
        ("admin", "usr_viewer", "viewer"),
        ("admin", "usr_admin", "admin"),  # self-removal allowed (decision 3)
        ("owner", "usr_viewer", "viewer"),
    ],
)
def test_remove_member_204_empty_body_with_removed_audit(
    matrix: _Env, caller: str, target: str, role_at_removal: str
) -> None:
    response = matrix.client.delete(
        f"/v1/organizations/org_team/members/{target}", headers=matrix.headers_for(caller)
    )
    assert response.status_code == 204
    assert response.content == b""  # manifest-pinned: 204 has no body
    assert [row for row in rows(matrix.db_path, "memberships") if row["user_id"] == target] == []
    audits = [
        row for row in rows(matrix.db_path, "audit_events") if row["action"] == "membership.removed"
    ]
    assert len(audits) == 1
    assert json.loads(audits[0]["metadata"]) == {"role": role_at_removal}
    assert audits[0]["actor_id"] == f"usr_{caller}"
    assert audits[0]["target_id"] == f"mem_{target.removeprefix('usr_')}"


@pytest.mark.parametrize("caller", ["admin", "owner"], ids=["by admin", "by owner self"])
def test_remove_owner_is_409_and_immutable(matrix: _Env, caller: str) -> None:
    response = matrix.client.delete(
        "/v1/organizations/org_team/members/usr_owner", headers=matrix.headers_for(caller)
    )
    assert response.status_code == 409
    envelope = Error.model_validate(response.json())
    assert envelope.code == "conflict"
    assert envelope.message == "owner membership cannot be removed"
    assert [row for row in rows(matrix.db_path, "memberships") if row["user_id"] == "usr_owner"]
    assert [
        row for row in rows(matrix.db_path, "audit_events") if row["action"] == "membership.removed"
    ] == []


def test_remove_non_member_is_404(matrix: _Env) -> None:
    response = matrix.client.delete(
        "/v1/organizations/org_team/members/usr_outsider", headers=matrix.headers_for("admin")
    )
    assert response.status_code == 404
    envelope = Error.model_validate(response.json())
    assert envelope.code == "not_found"
    assert envelope.message == "user is not a member of this organization"


@pytest.mark.parametrize("caller", ["member", "viewer"])
def test_remove_by_low_rank_caller_is_403_with_audit_and_row_intact(
    matrix: _Env, caller: str
) -> None:
    response = matrix.client.delete(
        "/v1/organizations/org_team/members/usr_viewer", headers=matrix.headers_for(caller)
    )
    assert response.status_code == 403
    audits = denial_rows(matrix.db_path)
    assert len(audits) == 1
    assert json.loads(audits[0]["metadata"]) == {
        "reason": "insufficient_role",
        "operation": "remove_member",
    }
    assert [row for row in rows(matrix.db_path, "memberships") if row["user_id"] == "usr_viewer"]


# ---------------------------------------------------------------------------
# Cross-tenant: outsider on all three member routes
# ---------------------------------------------------------------------------


def test_outsider_denied_on_all_three_member_routes_with_zero_mutation(matrix: _Env) -> None:
    headers = matrix.headers_for("outsider")
    memberships_before = rows(matrix.db_path, "memberships")

    responses = [
        matrix.client.get("/v1/organizations/org_team/members", headers=headers),
        matrix.client.post(
            "/v1/organizations/org_team/members",
            headers=headers,
            json={"user_id": "usr_new", "role": "admin"},
        ),
        matrix.client.delete("/v1/organizations/org_team/members/usr_member", headers=headers),
    ]
    assert [response.status_code for response in responses] == [403, 403, 403]
    # Byte-identical body on every route (no oracle across operations).
    assert responses[0].content == responses[1].content == responses[2].content
    # Zero mutation: membership table untouched.
    assert rows(matrix.db_path, "memberships") == memberships_before
    audits = denial_rows(matrix.db_path)
    assert [json.loads(row["metadata"])["operation"] for row in audits] == [
        "list_members",
        "create_member",
        "remove_member",
    ]
    assert all(json.loads(row["metadata"])["reason"] == "no_membership" for row in audits)
    assert all(row["actor_id"] == "usr_outsider" for row in audits)


# ---------------------------------------------------------------------------
# Route/manifest wiring
# ---------------------------------------------------------------------------


def test_router_registers_manifest_entries_exactly(matrix: _Env) -> None:
    paths = matrix.client.app.openapi()["paths"]
    assert {p for p in paths if p.startswith("/v1")} == {
        "/v1/organizations/{organization_id}/members",
        "/v1/organizations/{organization_id}/members/{user_id}",
    }
    assert set(paths["/v1/organizations/{organization_id}/members"]) == {"get", "post"}
    assert set(paths["/v1/organizations/{organization_id}/members/{user_id}"]) == {"delete"}
