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

Phase 05 task 5 **extends** this file additively (see the ``KeyEnv`` probes
at the bottom): the Phase 04 suite above runs against the ``pepper_source =
None`` default unchanged — that is the byte-stability proof — while the new
section exercises the principal dispatch, the ``human_only`` refusal, and
the scope dependency's API-key branch.
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
from app.auth.credentials import build_literal, hash_secret
from app.auth.errors import TokenValidationError
from app.auth.organization_access import (
    ORGANIZATION_FORBIDDEN_MESSAGE,
    OrganizationAccess,
    PrincipalAccess,
    build_organization_admin_dependency,
    build_organization_member_dependency,
    build_organization_scope_dependency,
)
from app.auth.pepper import StaticPepper
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity
from app.models.ids import ApiKeyId, ExternalIdentityId, MembershipId, OrganizationId, UserId
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


# ---------------------------------------------------------------------------
# Phase 05 task 5 (additive): principal dispatch wired into the access seams.
# Everything above this line is the unchanged Phase 04 suite (the byte-stable
# ``pepper_source=None`` regression proof); the probes below wire a
# ``StaticPepper`` into the member/admin factories and mount the new scope
# dependency, exercising the decision-6 branches:
#
# - key + required scope -> 200 (``PrincipalAccess`` carries the key principal);
# - key without the scope -> 403 audited ``insufficient_scope`` (``key_`` actor);
# - foreign key -> 403 audited ``organization_mismatch`` (path-org FK target);
# - precedence: org status -> mismatch -> scope;
# - key on the member/admin factories -> 403 audited ``human_only`` **after**
#   the org fetch (unknown org still answers the same 403, provably no row);
# - key on an unwired factory -> uniform 401 (JWT path, Phase 04 behavior);
# - human on the scope factory -> ``required_scope`` ignored, rank rules govern;
# - every denial body byte-identical to the pinned Phase 04 403.
# ---------------------------------------------------------------------------

# Same fixed 32-byte test pepper as the task-1/2/3 suites (never production).
_PEPPER = b"unit-test-pepper-32-bytes-fixed!"

# 26-char Crockford segments (distinct, underscore-free by charset).
_KEY_ID_A = "01JXYZ7KA20MB63PCQ8VNDWFTG"  # org_a, carries the run scope
_KEY_ID_B = "01JXYZ7KA20MB63PCQ8VNDWFTH"  # org_b, carries the run scope
_KEY_ID_NS = "01JXYZ7KA20MB63PCQ8VNDWFTJ"  # org_a, lacks the run scope
_KEY_ID_DIS = "01JXYZ7KA20MB63PCQ8VNDWFTK"  # org_d (disabled), carries the scope
_SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"

_KEY_A = "key_" + "a" * 32
_KEY_B = "key_" + "b" * 32
_KEY_NS = "key_" + "c" * 32
_KEY_DIS = "key_" + "d" * 32

_RUN_SCOPE = "vispector:inspection:run"


def seed_api_key(
    storage: SQLiteStorage,
    *,
    api_key_id: str,
    organization_id: str,
    key_id_segment: str,
    scopes: list[str],
) -> str:
    """Seed a live-environment key row; return its full literal.

    Keys are **seeded directly** (decision 12: no create API path exists yet).
    The plaintext literal exists only in this test's hands — the row carries
    just the peppered HMAC.
    """
    storage.create_api_key(
        ApiKey(
            id=ApiKeyId(api_key_id),
            organization_id=OrganizationId(organization_id),
            created_by_user_id=UserId("usr_caller"),
            name="probe key",
            key_id=key_id_segment,
            key_prefix=f"fn_live_{key_id_segment}_a8f32x...",
            secret_hash=hash_secret(_PEPPER, _SECRET),
            environment=ApiKeyEnvironment.LIVE,
            scopes=scopes,
            status=ApiKeyStatus.ACTIVE,
            created_at=_T0,
        )
    )
    return build_literal(ApiKeyEnvironment.LIVE, key_id_segment, _SECRET)


class KeyEnv:
    """Probe app with ``pepper_source`` wired, plus an unwired member twin.

    Denial rows are read directly from SQLite and include ``actor_type`` —
    the decision-7 generalization proof (a ``key_`` actor is audited as
    ``api_key``).
    """

    def __init__(self, db_path: Path, storage: SQLiteStorage) -> None:
        self.db_path = db_path
        self.storage = storage
        self.verifier = FakeVerifier()
        self.handler_calls: list[tuple[str, str]] = []
        self._next_token = 0
        pepper = StaticPepper(_PEPPER)
        member_dep = build_organization_member_dependency(
            storage, self.verifier, "get_organization", pepper_source=pepper
        )
        admin_dep = build_organization_admin_dependency(
            storage, self.verifier, "create_member", pepper_source=pepper
        )
        unwired_member_dep = build_organization_member_dependency(
            storage, self.verifier, "get_organization"
        )
        scope_dep = build_organization_scope_dependency(
            storage, self.verifier, pepper, _RUN_SCOPE, "run_inspection"
        )

        router = APIRouter()

        def member_probe(
            organization_id: OrganizationId,
            access: Annotated[OrganizationAccess, Depends(member_dep)],
        ) -> dict[str, str]:
            self.handler_calls.append(("member", str(organization_id)))
            return {"actor": str(access.identity.user.id)}

        def admin_probe(
            organization_id: OrganizationId,
            access: Annotated[OrganizationAccess, Depends(admin_dep)],
        ) -> dict[str, str]:
            self.handler_calls.append(("admin", str(organization_id)))
            return {"actor": str(access.identity.user.id)}

        def unwired_member_probe(
            organization_id: OrganizationId,
            access: Annotated[OrganizationAccess, Depends(unwired_member_dep)],
        ) -> dict[str, str]:
            self.handler_calls.append(("unwired", str(organization_id)))
            return {"actor": str(access.identity.user.id)}

        def scope_probe(
            organization_id: OrganizationId,
            access: Annotated[PrincipalAccess, Depends(scope_dep)],
        ) -> dict[str, Any]:
            self.handler_calls.append(("scope", str(organization_id)))
            context = access.principal.context
            return {
                "actor": str(context.actor_id),
                "actor_type": context.actor_type,
                "organization": str(access.organization.id),
                "roles": [role.value for role in context.roles],
                "scopes": list(context.scopes),
            }

        router.add_api_route("/v1/keyprobe/member/{organization_id}", member_probe, methods=["GET"])
        router.add_api_route("/v1/keyprobe/admin/{organization_id}", admin_probe, methods=["GET"])
        router.add_api_route(
            "/v1/keyprobe/unwired/{organization_id}", unwired_member_probe, methods=["GET"]
        )
        router.add_api_route("/v1/keyprobe/scope/{organization_id}", scope_probe, methods=["GET"])
        self.client = TestClient(create_app(routers=[router]), raise_server_exceptions=False)

    def login(self, sub: str, email: str) -> str:
        self._next_token += 1
        token = f"tok-{self._next_token}"
        self.verifier.claims_by_token[token] = CognitoClaims(
            sub=sub,
            email=email,
            username="probe-user",
            client_id="probe-client",
            iss="https://probe.example.test/pool",
            exp=int(_T0.timestamp()) + 3600,
        )
        return token

    def auth(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def denial_rows(self) -> list[dict[str, Any]]:
        """Read ``authorization.denied`` rows (with ``actor_type``) from the file."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT actor_id, actor_type, organization_id, metadata FROM audit_events"
                " WHERE action = 'authorization.denied' ORDER BY created_at, id"
            ).fetchall()
        finally:
            conn.close()
        return [
            {
                "actor_id": row["actor_id"],
                "actor_type": row["actor_type"],
                "organization_id": row["organization_id"],
                "metadata": json.loads(row["metadata"]),
            }
            for row in rows
        ]


@pytest.fixture
def keyed(tmp_path: Path) -> Iterator[KeyEnv]:
    """Caller is a member of ``org_a`` only; ``org_b`` active, ``org_d`` disabled.

    Keys: ``key_a``/``key_ns`` on ``org_a`` (with/without the run scope),
    ``key_b`` on ``org_b``, ``key_dis`` on the disabled ``org_d``.
    """
    db_path = tmp_path / "key_access.sqlite"
    adapter = SQLiteStorage(db_path)
    built = KeyEnv(db_path, adapter)
    seed_user(adapter, user_id="usr_caller", sub="caller-sub", email="caller@example.test")
    seed_org(adapter, organization_id="org_a", slug="key-org-a")
    seed_org(adapter, organization_id="org_b", slug="key-org-b", created_at=_T0 + timedelta(1))
    seed_org(
        adapter,
        organization_id="org_d",
        slug="key-org-d",
        created_at=_T0 + timedelta(2),
        status=OrganizationStatus.DISABLED,
    )
    seed_membership(
        adapter, organization_id="org_a", user_id="usr_caller", role=MembershipRole.MEMBER
    )
    built.literal_a = seed_api_key(
        adapter,
        api_key_id=_KEY_A,
        organization_id="org_a",
        key_id_segment=_KEY_ID_A,
        scopes=[_RUN_SCOPE],
    )
    built.literal_b = seed_api_key(
        adapter,
        api_key_id=_KEY_B,
        organization_id="org_b",
        key_id_segment=_KEY_ID_B,
        scopes=[_RUN_SCOPE],
    )
    built.literal_ns = seed_api_key(
        adapter,
        api_key_id=_KEY_NS,
        organization_id="org_a",
        key_id_segment=_KEY_ID_NS,
        scopes=["vispector:inspection:read"],
    )
    built.literal_dis = seed_api_key(
        adapter,
        api_key_id=_KEY_DIS,
        organization_id="org_d",
        key_id_segment=_KEY_ID_DIS,
        scopes=[_RUN_SCOPE],
    )
    built.token = built.login("caller-sub", "caller@example.test")
    yield built
    adapter.close()


# --- Scope dependency: grants ------------------------------------------------


def test_key_with_required_scope_grants_scope_probe(keyed: KeyEnv) -> None:
    response = keyed.client.get("/v1/keyprobe/scope/org_a", headers=keyed.auth(keyed.literal_a))
    assert response.status_code == 200
    assert response.json() == {
        "actor": _KEY_A,
        "actor_type": "api_key",
        "organization": "org_a",
        "roles": [],
        "scopes": [_RUN_SCOPE],
    }
    assert keyed.handler_calls == [("scope", "org_a")]
    assert keyed.denial_rows() == []  # grants are never audited


def test_key_grants_in_its_own_org_without_any_human_membership(keyed: KeyEnv) -> None:
    # The caller has **no** membership in org_b: the key branch never
    # consults human membership (decision 6 — tenancy comes from the row).
    response = keyed.client.get("/v1/keyprobe/scope/org_b", headers=keyed.auth(keyed.literal_b))
    assert response.status_code == 200
    assert response.json()["actor"] == _KEY_B
    assert keyed.denial_rows() == []


def test_human_on_scope_probe_ignores_required_scope(keyed: KeyEnv) -> None:
    # Human contexts carry scopes == []; the grant proves required_scope is
    # never consulted for people (roles govern, decision 6).
    response = keyed.client.get("/v1/keyprobe/scope/org_a", headers=keyed.auth(keyed.token))
    assert response.status_code == 200
    assert response.json() == {
        "actor": "usr_caller",
        "actor_type": "user",
        "organization": "org_a",
        "roles": ["member"],
        "scopes": [],
    }
    assert keyed.denial_rows() == []


# --- Scope dependency: denials, precedence, and audits ------------------------


def _assert_uniform_403(response: Any) -> None:
    assert response.status_code == 403
    envelope = json.loads(response.content)
    assert envelope["code"] == "forbidden"
    assert envelope["message"] == ORGANIZATION_FORBIDDEN_MESSAGE


def test_key_without_required_scope_is_audited_insufficient_scope(keyed: KeyEnv) -> None:
    response = keyed.client.get("/v1/keyprobe/scope/org_a", headers=keyed.auth(keyed.literal_ns))
    _assert_uniform_403(response)
    assert keyed.handler_calls == []
    (row,) = keyed.denial_rows()
    assert row == {
        "actor_id": _KEY_NS,
        "actor_type": "api_key",
        "organization_id": "org_a",
        "metadata": {"reason": "insufficient_scope", "operation": "run_inspection"},
    }


def test_foreign_key_denial_is_audited_organization_mismatch(keyed: KeyEnv) -> None:
    response = keyed.client.get("/v1/keyprobe/scope/org_b", headers=keyed.auth(keyed.literal_a))
    _assert_uniform_403(response)
    assert keyed.handler_calls == []
    (row,) = keyed.denial_rows()
    # The audit targets the **path** organization (the row exists — the FK
    # is valid); the actor is the foreign ``key_`` identity.
    assert row == {
        "actor_id": _KEY_A,
        "actor_type": "api_key",
        "organization_id": "org_b",
        "metadata": {"reason": "organization_mismatch", "operation": "run_inspection"},
    }


def test_key_denial_precedence_status_then_mismatch_then_scope(keyed: KeyEnv) -> None:
    # key_ns (org_a, no run scope) on foreign org_b -> mismatch outranks scope.
    mismatch = keyed.client.get("/v1/keyprobe/scope/org_b", headers=keyed.auth(keyed.literal_ns))
    # key_ns on the disabled org_d -> org status outranks everything.
    inactive = keyed.client.get("/v1/keyprobe/scope/org_d", headers=keyed.auth(keyed.literal_ns))
    _assert_uniform_403(mismatch)
    _assert_uniform_403(inactive)
    rows = keyed.denial_rows()
    assert [row["metadata"]["reason"] for row in rows] == [
        "organization_mismatch",
        "inactive_organization",
    ]
    assert rows[1] == {
        "actor_id": _KEY_NS,
        "actor_type": "api_key",
        "organization_id": "org_d",
        "metadata": {"reason": "inactive_organization", "operation": "run_inspection"},
    }


def test_disabled_org_with_key_is_audited_inactive_organization(keyed: KeyEnv) -> None:
    # org_d is disabled yet the key matches it and carries the scope: the
    # status gate fires first, under the key_ actor (decision-7 generalization).
    response = keyed.client.get("/v1/keyprobe/scope/org_d", headers=keyed.auth(keyed.literal_dis))
    _assert_uniform_403(response)
    (row,) = keyed.denial_rows()
    assert row == {
        "actor_id": _KEY_DIS,
        "actor_type": "api_key",
        "organization_id": "org_d",
        "metadata": {"reason": "inactive_organization", "operation": "run_inspection"},
    }


def test_unknown_org_with_key_leaves_no_audit_row(keyed: KeyEnv) -> None:
    # The §16 structural exception holds for key actors too: the same 403,
    # provably no audit row (the FK has no target).
    response = keyed.client.get("/v1/keyprobe/scope/org_ghost", headers=keyed.auth(keyed.literal_a))
    _assert_uniform_403(response)
    assert keyed.denial_rows() == []
    assert keyed.handler_calls == []


# --- Member/admin factories: human_only refusal and the unwired default ------


def test_key_on_member_and_admin_probes_is_audited_human_only(keyed: KeyEnv) -> None:
    member = keyed.client.get("/v1/keyprobe/member/org_a", headers=keyed.auth(keyed.literal_a))
    admin = keyed.client.get("/v1/keyprobe/admin/org_a", headers=keyed.auth(keyed.literal_a))
    _assert_uniform_403(member)
    _assert_uniform_403(admin)
    assert keyed.handler_calls == []
    rows = keyed.denial_rows()
    assert [(row["metadata"]["reason"], row["metadata"]["operation"]) for row in rows] == [
        ("human_only", "get_organization"),
        ("human_only", "create_member"),
    ]
    for row in rows:
        assert row["actor_id"] == _KEY_A
        assert row["actor_type"] == "api_key"
        assert row["organization_id"] == "org_a"


def test_human_only_refusal_runs_after_the_org_fetch_unknown_org_no_row(keyed: KeyEnv) -> None:
    # Ordering pinned by decision 6: on an unknown organization the refusal
    # still answers the uniform 403 with provably **no** audit row.
    response = keyed.client.get(
        "/v1/keyprobe/member/org_ghost", headers=keyed.auth(keyed.literal_a)
    )
    _assert_uniform_403(response)
    assert keyed.denial_rows() == []


def test_key_on_unwired_probe_is_401_jwt_path(keyed: KeyEnv) -> None:
    # pepper_source not wired -> the factory composes exactly the Phase 03
    # chain: the fn_ literal simply fails JWT verification -> uniform 401
    # (Phase 04 behavior; the credential never reaches the key seam).
    response = keyed.client.get("/v1/keyprobe/unwired/org_a", headers=keyed.auth(keyed.literal_a))
    assert response.status_code == 401
    assert json.loads(response.content)["code"] == "unauthenticated"
    assert keyed.denial_rows() == []
    assert keyed.handler_calls == []


def test_human_denials_on_scope_probe_follow_member_rank_rules(keyed: KeyEnv) -> None:
    # Caller has no membership in org_b -> the Phase 04 no_membership denial,
    # audited under the usr_ actor with the scope factory's operation id.
    response = keyed.client.get("/v1/keyprobe/scope/org_b", headers=keyed.auth(keyed.token))
    _assert_uniform_403(response)
    (row,) = keyed.denial_rows()
    assert row == {
        "actor_id": "usr_caller",
        "actor_type": "user",
        "organization_id": "org_b",
        "metadata": {"reason": "no_membership", "operation": "run_inspection"},
    }


def test_all_task5_denials_are_byte_identical_to_the_phase_04_403(keyed: KeyEnv) -> None:
    cases = [
        ("/v1/keyprobe/scope/org_a", keyed.literal_a, None),  # granted — excluded below
        ("/v1/keyprobe/scope/org_a", keyed.literal_ns, "insufficient_scope"),
        ("/v1/keyprobe/scope/org_b", keyed.literal_a, "organization_mismatch"),
        ("/v1/keyprobe/scope/org_d", keyed.literal_dis, "inactive_organization"),
        ("/v1/keyprobe/scope/org_ghost", keyed.literal_a, None),  # §16 exception
        ("/v1/keyprobe/member/org_a", keyed.literal_a, "human_only"),
    ]
    bodies: list[bytes] = []
    for path, literal, _reason in cases:
        response = keyed.client.get(path, headers=keyed.auth(literal))
        if response.status_code == 200:
            continue  # the grant case contributes no body
        bodies.append(response.content)
    # A Phase 04 human denial on the same app: the bodies must be identical.
    bodies.append(
        keyed.client.get("/v1/keyprobe/scope/org_b", headers=keyed.auth(keyed.token)).content
    )
    assert len(bodies) == 6  # 5 key denials + 1 human denial
    assert all(body == bodies[0] for body in bodies)
    envelope = json.loads(bodies[0])
    assert envelope["code"] == "forbidden"
    assert envelope["message"] == ORGANIZATION_FORBIDDEN_MESSAGE
