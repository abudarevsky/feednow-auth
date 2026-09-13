"""Integration tests for the organization endpoints (Phase 04 task 4).

Full stack, no live Cognito (Phase 03 test strategy, decision 9): signed
tokens from the loopback ``JwksTestServer``, real SQLite, and
``TestClient(create_app(routers=[build_organizations_router(...)]))`` driving
the frozen manifest routes. Role-matrix users are **seeded** (create-only
contract methods), never provisioned, and audit assertions read the SQLite
file directly (no audit read surface in the contract).

Acceptance mapping (AC 1/2/5 for the three organization routes):

- create 201 writes exactly org + owner membership + ``organization.created``
  / ``membership.created`` audits sharing one timestamp;
- ``type=personal|internal`` → 400 with **zero rows written**; taken slug
  (including a ``personal-*`` collision) → 409;
- list shows only the caller's active-membership orgs; limit clamps, cursor
  round-trips, a foreign cursor → 400;
- the owner/admin/member/viewer matrix gets 200 on GET /{id}, 200 on list,
  and 201 on create (authenticated-only per decision 3); outsider and
  unknown-organization attempts answer the byte-identical 403, the outsider
  denial audited and the unknown-org denial provably not;
- every error body validates against the frozen ``Error`` envelope.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.organizations import build_organizations_router
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
from app.storage.sqlite import CURSOR_SCOPE_MEMBERSHIPS, SQLiteStorage, encode_cursor

ALLOWED_CLIENT = "orgs-app-client"
_T0 = datetime(2026, 9, 13, 14, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Seeding helpers (role-matrix users are seeded, not provisioned)
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
    """Direct SQLite read (audit/mutation-count oracle; decision 9)."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Environment fixture: loopback JWKS + real SQLite + the organizations router
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("orgs-pool-key-1")


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
        app = create_app(routers=[build_organizations_router(self.storage, verifier)])
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

    def close(self) -> None:
        self.storage.close()


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_Env]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _Env(tmp_path / "orgs.sqlite", server, key)
        yield built
        built.close()


@pytest.fixture
def caller(env: _Env) -> tuple[_Env, str]:
    """A seeded user with one anchor membership (auth-chain context)."""
    seed_user(env.storage, user_id="usr_creator", sub="creator-sub", email="creator@example.test")
    seed_org(env.storage, organization_id="org_anchor", slug="anchor-org")
    seed_membership(
        env.storage,
        organization_id="org_anchor",
        user_id="usr_creator",
        role=MembershipRole.MEMBER,
        membership_id="mem_anchor",
    )
    return env, env.token("creator-sub", "creator@example.test")


# ---------------------------------------------------------------------------
# POST /v1/organizations
# ---------------------------------------------------------------------------


def test_create_returns_org_and_writes_owner_batch_atomically(caller: tuple[_Env, str]) -> None:
    env, token = caller
    response = env.client.post(
        "/v1/organizations",
        headers=env.auth(token),
        json={"name": "Acme", "slug": "acme", "type": "customer"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Acme"
    assert body["slug"] == "acme"
    assert body["type"] == "customer"
    assert body["status"] == "active"
    assert body["id"].startswith("org_")
    assert {"id", "name", "slug", "type", "status", "created_at", "updated_at"} == set(body)

    # Direct SQLite reads: exactly the batch, nothing else.
    org_rows = [row for row in rows(env.db_path, "organizations") if row["id"] == body["id"]]
    assert len(org_rows) == 1
    membership_rows = rows(env.db_path, "memberships")
    owner_rows = [row for row in membership_rows if row["organization_id"] == body["id"]]
    assert len(owner_rows) == 1
    assert owner_rows[0]["user_id"] == "usr_creator"
    assert owner_rows[0]["role"] == "owner"
    assert owner_rows[0]["status"] == "active"
    audits = [
        row for row in rows(env.db_path, "audit_events") if row["organization_id"] == body["id"]
    ]
    assert sorted(row["action"] for row in audits) == ["membership.created", "organization.created"]
    assert {row["created_at"] for row in audits} == {org_rows[0]["created_at"]}  # one clock read
    by_action = {row["action"]: row for row in audits}
    assert json.loads(by_action["organization.created"]["metadata"]) == {"type": "customer"}
    assert json.loads(by_action["membership.created"]["metadata"]) == {"role": "owner"}
    assert by_action["organization.created"]["actor_id"] == "usr_creator"
    assert by_action["organization.created"]["target_id"] == body["id"]
    assert by_action["membership.created"]["target_id"] == owner_rows[0]["id"]
    # The mem_ record id never leaks into the response (frozen schema).
    assert owner_rows[0]["id"] not in json.dumps(body)


@pytest.mark.parametrize("blocked_type", ["personal", "internal"])
def test_create_rejects_non_customer_types_with_zero_writes(
    caller: tuple[_Env, str], blocked_type: str
) -> None:
    env, token = caller
    before = {
        table: len(rows(env.db_path, table))
        for table in ("organizations", "memberships", "audit_events")
    }
    response = env.client.post(
        "/v1/organizations",
        headers=env.auth(token),
        json={"name": "Nope", "slug": "nope", "type": blocked_type},
    )
    assert response.status_code == 400
    envelope = Error.model_validate(response.json())
    assert envelope.code == "validation_error"
    assert envelope.message == "only customer organizations can be created through this API"
    after = {
        table: len(rows(env.db_path, table))
        for table in ("organizations", "memberships", "audit_events")
    }
    assert after == before  # guard runs before any storage touch


@pytest.mark.parametrize(
    "taken_slug",
    ["acme", "personal-usr_something"],
    ids=["plain", "personal-prefixed collision"],
)
def test_create_taken_slug_is_409_with_no_partial_rows(
    caller: tuple[_Env, str], taken_slug: str
) -> None:
    env, token = caller
    seed_org(env.storage, organization_id="org_taken", slug=taken_slug)
    response = env.client.post(
        "/v1/organizations",
        headers=env.auth(token),
        json={"name": "Clash", "slug": taken_slug, "type": "customer"},
    )
    assert response.status_code == 409
    envelope = Error.model_validate(response.json())
    assert envelope.code == "conflict"
    assert envelope.message == "organization slug is already taken"
    # The rejected batch consumed nothing: only the anchor + the seeded org.
    assert {row["id"] for row in rows(env.db_path, "organizations")} == {
        "org_anchor",
        "org_taken",
    }
    assert len(rows(env.db_path, "memberships")) == 1
    assert rows(env.db_path, "audit_events") == []


def test_create_requires_authentication(env: _Env) -> None:
    response = env.client.post("/v1/organizations", json={"name": "X", "slug": "x"})
    assert response.status_code == 401
    assert Error.model_validate(response.json()).code == "unauthenticated"
    assert rows(env.db_path, "organizations") == []


# ---------------------------------------------------------------------------
# GET /v1/organizations (list scoping + pagination)
# ---------------------------------------------------------------------------


def test_list_shows_only_the_callers_orgs(env: _Env) -> None:
    seed_user(env.storage, user_id="usr_one", sub="one-sub", email="one@example.test")
    seed_user(env.storage, user_id="usr_two", sub="two-sub", email="two@example.test")
    seed_org(env.storage, organization_id="org_one", slug="org-one")
    seed_org(env.storage, organization_id="org_two", slug="org-two")
    seed_membership(
        env.storage,
        organization_id="org_one",
        user_id="usr_one",
        role=MembershipRole.OWNER,
        membership_id="mem_one",
    )
    seed_membership(
        env.storage,
        organization_id="org_two",
        user_id="usr_two",
        role=MembershipRole.OWNER,
        membership_id="mem_two",
    )

    one = env.client.get(
        "/v1/organizations", headers=env.auth(env.token("one-sub", "one@example.test"))
    )
    two = env.client.get(
        "/v1/organizations", headers=env.auth(env.token("two-sub", "two@example.test"))
    )

    assert one.status_code == 200 and two.status_code == 200
    assert [item["id"] for item in one.json()["items"]] == ["org_one"]
    assert [item["id"] for item in two.json()["items"]] == ["org_two"]


def test_list_clamps_limit_round_trips_cursor_and_rejects_foreign(env: _Env) -> None:
    seed_user(env.storage, user_id="usr_paged", sub="paged-sub", email="paged@example.test")
    for index, organization_id in enumerate(("org_p1", "org_p2", "org_p3")):
        seed_org(
            env.storage,
            organization_id=organization_id,
            slug=f"paged-{index}",
            created_at=_T0 + timedelta(index),
        )
        seed_membership(
            env.storage,
            organization_id=organization_id,
            user_id="usr_paged",
            role=MembershipRole.MEMBER,
            membership_id=f"mem_p{index}",
        )
    headers = env.auth(env.token("paged-sub", "paged@example.test"))

    clamped = env.client.get("/v1/organizations?limit=1000", headers=headers)
    assert clamped.status_code == 200
    assert clamped.json()["limit"] == 100  # effective size echoed

    first = env.client.get("/v1/organizations?limit=2", headers=headers)
    assert first.status_code == 200
    page_one = first.json()
    assert [item["id"] for item in page_one["items"]] == ["org_p1", "org_p2"]
    assert page_one["next_cursor"] is not None

    second = env.client.get(
        f"/v1/organizations?limit=2&cursor={page_one['next_cursor']}", headers=headers
    )
    assert second.status_code == 200
    page_two = second.json()
    assert [item["id"] for item in page_two["items"]] == ["org_p3"]
    assert page_two["next_cursor"] is None

    # A cursor issued for a different list (memberships scope) is foreign: 400.
    foreign = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T0, "mem_p0")
    rejected = env.client.get(f"/v1/organizations?cursor={foreign}", headers=headers)
    assert rejected.status_code == 400
    assert Error.model_validate(rejected.json()).code == "validation_error"


# ---------------------------------------------------------------------------
# GET /v1/organizations/{organization_id} — AC-5 role matrix + uniform denial
# ---------------------------------------------------------------------------


@pytest.fixture
def matrix(env: _Env) -> _Env:
    """One organization seeded with owner/admin/member/viewer + an outsider."""
    roles = ["owner", "admin", "member", "viewer"]
    for role in roles:
        seed_user(
            env.storage,
            user_id=f"usr_{role}",
            sub=f"{role}-sub",
            email=f"{role}@example.test",
        )
    seed_org(env.storage, organization_id="org_matrix", slug="matrix-org")
    for index, role in enumerate(roles):
        seed_membership(
            env.storage,
            organization_id="org_matrix",
            user_id=f"usr_{role}",
            role=MembershipRole(role),
            membership_id=f"mem_matrix_{index}",
        )
    seed_user(env.storage, user_id="usr_outsider", sub="outsider-sub", email="out@example.test")
    seed_org(env.storage, organization_id="org_outside", slug="outside-org")
    seed_membership(
        env.storage,
        organization_id="org_outside",
        user_id="usr_outsider",
        role=MembershipRole.OWNER,
        membership_id="mem_outside",
    )
    return env


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
def test_get_organization_200_for_every_active_role(matrix: _Env, role: str) -> None:
    headers = matrix.auth(matrix.token(f"{role}-sub", f"{role}@example.test"))
    response = matrix.client.get("/v1/organizations/org_matrix", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == "org_matrix"
    assert _denial_rows(matrix) == []  # grants are never denial-audited


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
def test_list_200_for_every_role_showing_only_own_orgs(matrix: _Env, role: str) -> None:
    headers = matrix.auth(matrix.token(f"{role}-sub", f"{role}@example.test"))
    response = matrix.client.get("/v1/organizations", headers=headers)
    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == ["org_matrix"]


@pytest.mark.parametrize("role", ["owner", "admin", "member", "viewer"])
def test_create_201_for_every_authenticated_role(matrix: _Env, role: str) -> None:
    # Decision 3: creation requires only authentication; the creator becomes
    # owner through the batch regardless of their role elsewhere.
    headers = matrix.auth(matrix.token(f"{role}-sub", f"{role}@example.test"))
    response = matrix.client.post(
        "/v1/organizations",
        headers=headers,
        json={"name": f"New {role}", "slug": f"new-{role}", "type": "customer"},
    )
    assert response.status_code == 201
    owners = [
        row
        for row in rows(matrix.db_path, "memberships")
        if row["organization_id"] == response.json()["id"]
    ]
    assert [(row["user_id"], row["role"]) for row in owners] == [(f"usr_{role}", "owner")]


def _denial_rows(env: _Env) -> list[dict[str, Any]]:
    return [
        row for row in rows(env.db_path, "audit_events") if row["action"] == "authorization.denied"
    ]


def test_outsider_get_is_byte_identical_403_with_denial_audit(matrix: _Env) -> None:
    outsider_headers = matrix.auth(matrix.token("outsider-sub", "out@example.test"))
    denied = matrix.client.get("/v1/organizations/org_matrix", headers=outsider_headers)
    unknown = matrix.client.get("/v1/organizations/org_ghost", headers=outsider_headers)

    assert denied.status_code == 403 and unknown.status_code == 403
    # One fixed body for both shapes: no existence oracle (decision 4).
    assert denied.content == unknown.content
    envelope = Error.model_validate(denied.json())
    assert envelope.code == "forbidden"
    assert envelope.message == "you do not have permission to access this organization"

    rows_audited = _denial_rows(matrix)
    assert len(rows_audited) == 1  # the unknown-org denial is unauditable
    denial = rows_audited[0]
    assert denial["actor_id"] == "usr_outsider"
    assert denial["organization_id"] == "org_matrix"
    assert json.loads(denial["metadata"]) == {
        "reason": "no_membership",
        "operation": "get_organization",
    }
    assert "@" not in json.dumps(denial)  # no email material in any field


def test_get_organization_denied_for_disabled_membership(matrix: _Env) -> None:
    # An outsider whose org is disabled elsewhere still sees the uniform 403
    # with the inactive_membership reason when their target membership row
    # is disabled: seed a second caller with a disabled matrix membership.
    seed_user(matrix.storage, user_id="usr_suspended", sub="susp-sub", email="susp@example.test")
    seed_org(matrix.storage, organization_id="org_home", slug="home-org")
    seed_membership(
        matrix.storage,
        organization_id="org_home",
        user_id="usr_suspended",
        role=MembershipRole.ADMIN,
        membership_id="mem_home",
    )
    seed_membership(
        matrix.storage,
        organization_id="org_matrix",
        user_id="usr_suspended",
        role=MembershipRole.ADMIN,
        membership_id="mem_matrix_susp",
        status=MembershipStatus.DISABLED,
    )
    response = matrix.client.get(
        "/v1/organizations/org_matrix",
        headers=matrix.auth(matrix.token("susp-sub", "susp@example.test")),
    )
    assert response.status_code == 403
    denial = _denial_rows(matrix)[-1]
    assert json.loads(denial["metadata"]) == {
        "reason": "inactive_membership",
        "operation": "get_organization",
    }


# ---------------------------------------------------------------------------
# Route/manifest wiring
# ---------------------------------------------------------------------------


def test_router_registers_manifest_entries_exactly(caller: tuple[_Env, str]) -> None:
    env, _token = caller
    paths = env.client.app.openapi()["paths"]
    assert {p for p in paths if p.startswith("/v1")} == {
        "/v1/organizations",
        "/v1/organizations/{organization_id}",
    }
    assert set(paths["/v1/organizations"]) == {"get", "post"}
    assert "get" in paths["/v1/organizations/{organization_id}"]
