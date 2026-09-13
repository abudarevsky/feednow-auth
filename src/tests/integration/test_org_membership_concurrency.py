"""Concurrency and duplicate-request acceptance proofs (Phase 04 task 6).

The AGENTS.md concurrency mandate ("provisioning … define and test atomicity
and duplicate-request behavior") at the HTTP seam, on the Phase 03 task-6
pattern: ``threading.Barrier`` (never sleeps), 20 parameterized repeats for
stability, and final counts asserted through **direct** SQLite reads on a
fresh connection.

Cases:

1. **8 threads ``POST /v1/organizations`` with the same slug** — exactly one
   201; the losers get the plain 409 (decision 2: ``provision_organization``
   has *no* race-convergence semantics, a slug conflict is never a converge);
   the winner's batch wrote exactly one organization, one owner membership,
   and two audits — nothing from the rejected batches survives.
2. **8 threads add the same target user** — exactly one 201, seven 409
   (pair UNIQUE), one ``membership.created`` audit.
3. **Two threads remove one pair** — exactly one 204 and one 404: the
   contract pins ``delete_membership`` as non-idempotent, and the service
   translates the loser's miss into ``MemberNotFoundError`` (behavior
   proven, documented in the phase handoff); exactly one
   ``membership.removed`` audit.

Lock handling relies entirely on the adapter's existing
``busy_timeout=5000`` + ``BEGIN IMMEDIATE`` discipline — nothing is added
to production code here.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.members import build_members_router
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
from app.models.external_identity import ExternalIdentity
from app.models.ids import ExternalIdentityId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.storage.sqlite import SQLiteStorage

_REPEATS = 20
_THREADS = 8
_T0 = datetime(2026, 9, 13, 16, 0, 0, tzinfo=UTC)
_ALLOWED_CLIENT = "race-client"


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("org-race-key-1")


@pytest.fixture(scope="module")
def server(key: TestKey) -> Iterator[JwksTestServer]:
    with JwksTestServer({"pool-a": [key]}) as running:
        yield running


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_user(storage: SQLiteStorage, user_id: str, sub: str, email: str) -> None:
    storage.create_user(
        User(
            id=UserId(user_id),
            display_name=f"race {user_id}",
            email=email,
            status=UserStatus.ACTIVE,
            created_at=_T0,
            updated_at=_T0,
        )
    )
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


def _seed_org(storage: SQLiteStorage, organization_id: str, slug: str) -> None:
    storage.create_organization(
        Organization(
            id=OrganizationId(organization_id),
            name=f"race {organization_id}",
            slug=slug,
            type=OrganizationType.CUSTOMER,
            status=OrganizationStatus.ACTIVE,
            created_at=_T0,
            updated_at=_T0,
        )
    )


def _seed_membership(
    storage: SQLiteStorage,
    organization_id: str,
    user_id: str,
    role: MembershipRole,
    membership_id: str,
) -> None:
    storage.create_membership(
        Membership(
            id=MembershipId(membership_id),
            organization_id=OrganizationId(organization_id),
            user_id=UserId(user_id),
            role=role,
            status=MembershipStatus.ACTIVE,
            created_at=_T0,
        )
    )


class _RaceEnv:
    """Routers + real SQLite + signed token for one race database."""

    def __init__(self, path: Path, server: JwksTestServer, key: TestKey) -> None:
        self.path = path
        self.storage = SQLiteStorage(path)
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[_ALLOWED_CLIENT],
        )
        app = create_app(
            routers=[
                build_organizations_router(self.storage, verifier),
                build_members_router(self.storage, verifier),
            ]
        )
        self.client = TestClient(app, raise_server_exceptions=False)
        now = int(time.time())
        self.token = sign_token(
            {
                "sub": "race-caller-sub",
                "email": "race@example.test",
                "username": "race-caller",
                "client_id": _ALLOWED_CLIENT,
                "iss": issuer,
                "token_use": "access",
                "exp": now + 3600,
                "iat": now,
            },
            kid=key.kid,
            key=key,
        )
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def close(self) -> None:
        self.storage.close()


def _table_counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "users",
                "external_identities",
                "organizations",
                "memberships",
                "api_keys",
                "audit_events",
            )
        }
    finally:
        conn.close()


def _audit_actions(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [row[0] for row in conn.execute("SELECT action FROM audit_events")]
    finally:
        conn.close()


def _barrier_requests(
    env: _RaceEnv,
    method: str,
    path: str,
    *,
    json_body: dict[str, object] | None,
    threads: int,
) -> list[int]:
    """Fire ``threads`` identical requests released together; return statuses."""
    barrier = threading.Barrier(threads)
    statuses: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        request = getattr(env.client, method)
        # httpx's delete() takes no json= kwarg; only send a body when asked.
        body = {} if json_body is None else {"json": json_body}
        response = request(path, headers=env.headers, **body)
        with lock:
            statuses.append(response.status_code)

    runners = [threading.Thread(target=worker) for _ in range(threads)]
    for runner in runners:
        runner.start()
    for runner in runners:
        runner.join()
    assert len(statuses) == threads
    return statuses


# ---------------------------------------------------------------------------
# Case 1: slug race — exactly one org, losers 409, no converge
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("repeat", range(_REPEATS))
def test_concurrent_same_slug_creates_exactly_one_organization(
    server: JwksTestServer, key: TestKey, tmp_path: Path, repeat: int
) -> None:
    race_dir = tmp_path / f"slug-{repeat}"
    race_dir.mkdir()
    env = _RaceEnv(race_dir / "slug_race.sqlite", server, key)
    try:
        _seed_user(env.storage, "usr_caller", "race-caller-sub", "race@example.test")
        _seed_org(env.storage, "org_anchor", "anchor-slug")
        _seed_membership(
            env.storage, "org_anchor", "usr_caller", MembershipRole.MEMBER, "mem_anchor"
        )
        # Main-thread warm-up read: initializes the file/WAL outside the
        # timed window (Phase 03 task-6 discipline).
        assert env.client.get("/v1/organizations", headers=env.headers).status_code == 200

        statuses = _barrier_requests(
            env,
            "post",
            "/v1/organizations",
            json_body={"name": "Raced", "slug": "raced-slug", "type": "customer"},
            threads=_THREADS,
        )
    finally:
        env.close()

    assert sorted(statuses, reverse=True) == [409] * (_THREADS - 1) + [201]
    counts = _table_counts(env.path)
    assert counts["organizations"] == 2  # anchor + the single winner
    assert counts["memberships"] == 2  # anchor + the winner's owner membership
    assert counts["audit_events"] == 2  # only the winner's batch audited
    assert sorted(_audit_actions(env.path)) == ["membership.created", "organization.created"]
    conn = sqlite3.connect(env.path)
    try:
        raced = conn.execute("SELECT id FROM organizations WHERE slug = 'raced-slug'").fetchall()
        assert len(raced) == 1
        owners = conn.execute(
            "SELECT user_id, role FROM memberships WHERE organization_id = ?", (raced[0][0],)
        ).fetchall()
    finally:
        conn.close()
    assert owners == [("usr_caller", "owner")]


# ---------------------------------------------------------------------------
# Case 2: duplicate add-member — one membership, losers 409
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("repeat", range(_REPEATS))
def test_concurrent_duplicate_member_grant_writes_exactly_one_membership(
    server: JwksTestServer, key: TestKey, tmp_path: Path, repeat: int
) -> None:
    race_dir = tmp_path / f"add-{repeat}"
    race_dir.mkdir()
    env = _RaceEnv(race_dir / "add_race.sqlite", server, key)
    try:
        _seed_user(env.storage, "usr_caller", "race-caller-sub", "race@example.test")
        _seed_user(env.storage, "usr_target", "target-sub", "target@example.test")
        _seed_org(env.storage, "org_team", "team-slug")
        _seed_membership(env.storage, "org_team", "usr_caller", MembershipRole.ADMIN, "mem_admin")
        assert (
            env.client.get("/v1/organizations/org_team/members", headers=env.headers).status_code
            == 200
        )

        statuses = _barrier_requests(
            env,
            "post",
            "/v1/organizations/org_team/members",
            json_body={"user_id": "usr_target", "role": "member"},
            threads=_THREADS,
        )
    finally:
        env.close()

    assert sorted(statuses, reverse=True) == [409] * (_THREADS - 1) + [201]
    counts = _table_counts(env.path)
    assert counts["memberships"] == 2  # admin caller + exactly one target grant
    assert counts["audit_events"] == 1  # exactly one membership.created
    assert _audit_actions(env.path) == ["membership.created"]
    conn = sqlite3.connect(env.path)
    try:
        target_rows = conn.execute(
            "SELECT role, status FROM memberships WHERE user_id = 'usr_target'"
        ).fetchall()
    finally:
        conn.close()
    assert target_rows == [("member", "active")]


# ---------------------------------------------------------------------------
# Case 3: concurrent remove — one 204, one 404 (delete is non-idempotent)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("repeat", range(_REPEATS))
def test_concurrent_removal_of_one_pair_yields_one_204_and_one_404(
    server: JwksTestServer, key: TestKey, tmp_path: Path, repeat: int
) -> None:
    race_dir = tmp_path / f"remove-{repeat}"
    race_dir.mkdir()
    env = _RaceEnv(race_dir / "remove_race.sqlite", server, key)
    try:
        _seed_user(env.storage, "usr_caller", "race-caller-sub", "race@example.test")
        _seed_user(env.storage, "usr_victim", "victim-sub", "victim@example.test")
        _seed_org(env.storage, "org_team", "team-slug")
        _seed_membership(env.storage, "org_team", "usr_caller", MembershipRole.ADMIN, "mem_admin")
        _seed_membership(env.storage, "org_team", "usr_victim", MembershipRole.MEMBER, "mem_victim")
        assert (
            env.client.get("/v1/organizations/org_team/members", headers=env.headers).status_code
            == 200
        )

        statuses = _barrier_requests(
            env,
            "delete",
            "/v1/organizations/org_team/members/usr_victim",
            json_body=None,
            threads=2,
        )
    finally:
        env.close()

    # Contract-pinned: delete_membership is non-idempotent; the service
    # translates the loser's miss to 404 (documented behavior).
    assert sorted(statuses) == [204, 404]
    counts = _table_counts(env.path)
    assert counts["memberships"] == 1  # only the admin caller remains
    assert _audit_actions(env.path) == ["membership.removed"]  # exactly one
