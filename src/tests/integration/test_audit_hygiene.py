"""Audit-hygiene acceptance sweep (Phase 04 task 6; extended by Phase 05 task 7).

Runs the **full mutation + denial battery** for Phase 04 against the real
stack (provisioning via ``/v1/me``, organization create, member add/remove,
and one denial for each of the four decision-4 reasons), then reads *every*
audit row directly from the SQLite file and proves the AGENTS.md no-secrets
rule and the §16 vocabulary pin:

- every ``action`` is inside the §16 set (Phase 05 adds the two ``api_key.*``
  actions; the pinned-metadata table below carries them);
- every ``metadata`` key set is exactly the decision-4/7 pinned shape for
  its action — nothing extra can sneak in;
- no row contains email material (``@``), the provider ``sub`` sentinel, the
  JWT itself, or any bearer/token marker;
- every actor is a ``usr_`` application identity with ``actor_type=user``.

The Phase 05 extension (task 7) mounts the keys router on the same
environment and runs a **mixed-actor battery**: ``api_key.created``,
``api_key.revoked``, and the ``human_only`` denial audited under a ``key_``
actor — the same vocabulary/metadata/no-secrets sweep must hold when both
actor kinds write to one database (the other two new denial reasons,
``organization_mismatch`` and ``insufficient_scope``, need the scope probe
and are pinned by ``test_api_key_secrecy.py`` and ``test_api_key_auth_matrix.py``).
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
from fastapi import APIRouter
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.keys import build_api_keys_router
from app.api.me import build_me_router
from app.api.members import build_members_router
from app.api.organizations import build_organizations_router
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.credentials import parse_literal
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper
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

_T0 = datetime(2026, 9, 13, 17, 0, 0, tzinfo=UTC)
_ALLOWED_CLIENT = "hygiene-client"

#: Fixed 32+-byte test pepper for the Phase 05 keys-router extension (never
#: production, same discipline as the other Phase 05 suites).
_PEPPER = b"integration-hygiene-pepper-0123456789ab"

#: UUID-shaped provider subject: unmistakably identifiable if it ever leaked
#: into an audit field (the "sub-like material" check).
_SENTINEL_SUB = "123e4567-e89b-12d3-a456-426614174099"
_SENTINEL_EMAIL = "hygiene-victim@example.test"

#: §16 vocabulary (the full set; Phase 04 can only produce the first five).
_SPEC_16_ACTIONS = {
    "user.created",
    "organization.created",
    "membership.created",
    "membership.removed",
    "api_key.created",
    "api_key.revoked",
    "authorization.denied",
}

#: Decision-4/7 pinned metadata key sets, per action (Phase 05 adds the two
#: ``api_key.*`` shapes pinned by decisions 9/10).
_PINNED_METADATA_KEYS: dict[str, set[str]] = {
    "user.created": {"provider"},
    "organization.created": {"type"},
    "membership.created": {"role"},
    "membership.removed": {"role"},
    "api_key.created": {"environment", "scopes"},
    "api_key.revoked": set(),
    "authorization.denied": {"reason", "operation"},
}


def _seed_user(storage: SQLiteStorage, user_id: str, sub: str, email: str) -> None:
    storage.create_user(
        User(
            id=UserId(user_id),
            display_name=f"hygiene {user_id}",
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


def _seed_org(
    storage: SQLiteStorage,
    organization_id: str,
    slug: str,
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
) -> None:
    storage.create_organization(
        Organization(
            id=OrganizationId(organization_id),
            name=f"hygiene {organization_id}",
            slug=slug,
            type=OrganizationType.CUSTOMER,
            status=status,
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
    status: MembershipStatus = MembershipStatus.ACTIVE,
) -> None:
    storage.create_membership(
        Membership(
            id=MembershipId(membership_id),
            organization_id=OrganizationId(organization_id),
            user_id=UserId(user_id),
            role=role,
            status=status,
            created_at=_T0,
        )
    )


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("hygiene-key-1")


class _HygieneEnv:
    def __init__(
        self,
        db_path: Path,
        server: JwksTestServer,
        key: TestKey,
        *,
        pepper_source: StaticPepper | None = None,
    ) -> None:
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[_ALLOWED_CLIENT],
        )
        routers: list[APIRouter] = [
            build_me_router(self.storage, verifier),
            build_organizations_router(self.storage, verifier),
            build_members_router(self.storage, verifier),
        ]
        if pepper_source is not None:
            # Phase 05 task-7 extension: the keys router with the pepper wired,
            # so the key-refusal (``human_only``) branch is live on these routes.
            routers.append(build_api_keys_router(self.storage, verifier, pepper_source))
        app = create_app(routers=routers)
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
                "client_id": _ALLOWED_CLIENT,
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
def env(tmp_path: Path, key: TestKey) -> Iterator[_HygieneEnv]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _HygieneEnv(tmp_path / "hygiene.sqlite", server, key)
        yield built
        built.close()


@pytest.fixture
def key_env(tmp_path: Path, key: TestKey) -> Iterator[_HygieneEnv]:
    """Same stack plus the keys router (pepper wired — the Phase 05 extension)."""
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _HygieneEnv(
            tmp_path / "hygiene_keys.sqlite",
            server,
            key,
            pepper_source=StaticPepper(_PEPPER),
        )
        yield built
        built.close()


def _all_audit_rows(db_path: Path) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM audit_events").fetchall()]
    finally:
        conn.close()


def test_full_battery_audits_stay_in_vocabulary_and_secret_free(env: _HygieneEnv) -> None:
    # --- seed the cast -----------------------------------------------------
    # admin: anchor A (context), org_team (owner), org_E (disabled member),
    # org_D (active member of a *disabled* organization).
    _seed_user(env.storage, "usr_admin", "admin-sub", "admin@example.test")
    _seed_user(env.storage, "usr_viewer", "viewer-sub", "viewer@example.test")
    _seed_user(env.storage, "usr_new", "new-sub", "new@example.test")
    _seed_user(env.storage, "usr_outsider", _SENTINEL_SUB, _SENTINEL_EMAIL)
    _seed_org(env.storage, "org_a", "anchor-a")
    _seed_org(env.storage, "org_team", "team")
    _seed_org(env.storage, "org_outside", "outside")
    _seed_org(env.storage, "org_e", "suspended")
    _seed_org(env.storage, "org_d", "dead-org", status=OrganizationStatus.DISABLED)
    _seed_membership(env.storage, "org_a", "usr_admin", MembershipRole.MEMBER, "mem_a")
    _seed_membership(env.storage, "org_team", "usr_admin", MembershipRole.OWNER, "mem_team_admin")
    _seed_membership(
        env.storage, "org_team", "usr_viewer", MembershipRole.VIEWER, "mem_team_viewer"
    )
    _seed_membership(
        env.storage,
        "org_e",
        "usr_admin",
        MembershipRole.ADMIN,
        "mem_e",
        status=MembershipStatus.DISABLED,
    )
    _seed_membership(env.storage, "org_d", "usr_admin", MembershipRole.MEMBER, "mem_d")
    _seed_membership(
        env.storage, "org_outside", "usr_outsider", MembershipRole.OWNER, "mem_outside"
    )

    admin_token = env.token("admin-sub", "admin@example.test")
    viewer_token = env.token("viewer-sub", "viewer@example.test")
    outsider_token = env.token(_SENTINEL_SUB, _SENTINEL_EMAIL)
    fresh_token = env.token("fresh-hygiene-sub", "fresh@example.test")

    # --- mutation battery ---------------------------------------------------
    assert env.client.get("/v1/me", headers=env.auth(fresh_token)).status_code == 200
    created = env.client.post(
        "/v1/organizations",
        headers=env.auth(admin_token),
        json={"name": "Hygiene Org", "slug": "hygiene-org", "type": "customer"},
    )
    assert created.status_code == 201
    added = env.client.post(
        "/v1/organizations/org_team/members",
        headers=env.auth(admin_token),
        json={"user_id": "usr_new", "role": "member"},
    )
    assert added.status_code == 201
    removed = env.client.delete(
        "/v1/organizations/org_team/members/usr_new", headers=env.auth(admin_token)
    )
    assert removed.status_code == 204

    # --- denial battery: all four decision-4 reasons -------------------------
    denials = [
        env.client.get("/v1/organizations/org_team", headers=env.auth(outsider_token)),
        env.client.post(
            "/v1/organizations/org_team/members",
            headers=env.auth(viewer_token),
            json={"user_id": "usr_outsider", "role": "member"},
        ),
        env.client.get("/v1/organizations/org_e", headers=env.auth(admin_token)),
        env.client.get("/v1/organizations/org_d", headers=env.auth(admin_token)),
    ]
    assert [response.status_code for response in denials] == [403, 403, 403, 403]

    # --- sweep every audit row ----------------------------------------------
    rows_a = _all_audit_rows(env.db_path)
    assert rows_a, "the battery must have audited"
    actions = {row["action"] for row in rows_a}
    assert actions <= _SPEC_16_ACTIONS, f"off-vocabulary actions: {actions - _SPEC_16_ACTIONS}"
    assert actions == {
        "user.created",
        "organization.created",
        "membership.created",
        "membership.removed",
        "authorization.denied",
    }
    serialized_all = json.dumps(rows_a)
    for row in rows_a:
        assert row["action"] in _PINNED_METADATA_KEYS, row["action"]
        metadata = json.loads(row["metadata"])
        assert set(metadata) == _PINNED_METADATA_KEYS[row["action"]], row
        assert row["actor_type"] == "user"
        assert str(row["actor_id"]).startswith("usr_")
        assert str(row["organization_id"]).startswith("org_")
    # No secret/PII material anywhere in any row (AGENTS.md / acceptance 4).
    assert "@" not in serialized_all
    assert _SENTINEL_SUB not in serialized_all
    assert _SENTINEL_EMAIL not in serialized_all
    assert outsider_token not in serialized_all
    assert admin_token not in serialized_all
    assert "bearer" not in serialized_all.lower()
    assert "eyJ" not in serialized_all  # JWT segment shape
    assert _ALLOWED_CLIENT not in serialized_all

    # Denial coverage: exactly the four reasons, correct operations.
    denial_meta = [
        json.loads(row["metadata"]) for row in rows_a if row["action"] == "authorization.denied"
    ]
    assert {item["reason"] for item in denial_meta} == {
        "no_membership",
        "insufficient_role",
        "inactive_membership",
        "inactive_organization",
    }
    assert {item["operation"] for item in denial_meta} == {
        "get_organization",
        "create_member",
    }


def test_mutation_audits_target_the_right_records(env: _HygieneEnv) -> None:
    # Target pinning per decision 7, checked on a focused mutation sequence.
    _seed_user(env.storage, "usr_admin", "admin-sub", "admin@example.test")
    _seed_user(env.storage, "usr_target", "target-sub", "target@example.test")
    _seed_org(env.storage, "org_a", "anchor-a")
    _seed_membership(env.storage, "org_a", "usr_admin", MembershipRole.MEMBER, "mem_a")
    admin_token = env.token("admin-sub", "admin@example.test")

    created = env.client.post(
        "/v1/organizations",
        headers=env.auth(admin_token),
        json={"name": "Targeted", "slug": "targeted", "type": "customer"},
    )
    assert created.status_code == 201
    organization_id = created.json()["id"]
    added = env.client.post(
        f"/v1/organizations/{organization_id}/members",
        headers=env.auth(admin_token),
        json={"user_id": "usr_target", "role": "viewer"},
    )
    assert added.status_code == 201
    removed = env.client.delete(
        f"/v1/organizations/{organization_id}/members/usr_target", headers=env.auth(admin_token)
    )
    assert removed.status_code == 204

    rows_a = {
        row["action"]: row
        for row in _all_audit_rows(env.db_path)
        if row["organization_id"] == organization_id
    }
    assert rows_a["organization.created"]["target_type"] == "organization"
    assert rows_a["organization.created"]["target_id"] == organization_id
    assert json.loads(rows_a["organization.created"]["metadata"]) == {"type": "customer"}
    assert rows_a["membership.removed"]["target_type"] == "membership"
    assert rows_a["membership.removed"]["target_id"].startswith("mem_")
    assert json.loads(rows_a["membership.removed"]["metadata"]) == {"role": "viewer"}
    # The mem_ record id appears ONLY in audits, never in a response body.
    assert rows_a["membership.removed"]["target_id"] not in added.text


def test_mixed_actor_battery_stays_in_vocabulary_and_secret_free(
    key_env: _HygieneEnv,
) -> None:
    """Phase 05 task-7 extension: the same sweep with both actor kinds writing.

    ``api_key.created``, ``api_key.revoked``, and the ``human_only`` denial
    (a key bearer refused on a management route, audited under the ``key_``
    actor) land in one database next to the human mutations; the §16
    vocabulary, the pinned metadata shapes, and the no-credential-material
    rule must all hold unchanged.
    """
    _seed_user(key_env.storage, "usr_admin", "admin-sub", "admin@example.test")
    _seed_org(key_env.storage, "org_team", "team")
    _seed_membership(key_env.storage, "org_team", "usr_admin", MembershipRole.OWNER, "mem_team")
    admin_token = key_env.token("admin-sub", "admin@example.test")
    headers = key_env.auth(admin_token)

    created = key_env.client.post(
        "/v1/organizations/org_team/api-keys",
        headers=headers,
        json={"name": "hygiene key", "environment": "live", "scopes": ["vispector:inspection:run"]},
    )
    assert created.status_code == 201
    body = created.json()
    literal = str(body["key"])
    parts = parse_literal(literal)

    # AC 4's escalation proof: the minted key itself is refused on the list
    # route (uniform 403) and the refusal is audited under the key identity.
    denied = key_env.client.get(
        "/v1/organizations/org_team/api-keys", headers=key_env.auth(literal)
    )
    assert denied.status_code == 403

    revoked = key_env.client.delete(
        f"/v1/organizations/org_team/api-keys/{body['id']}", headers=headers
    )
    assert revoked.status_code == 204

    rows_a = _all_audit_rows(key_env.db_path)
    actions = {row["action"] for row in rows_a}
    assert actions <= _SPEC_16_ACTIONS, f"off-vocabulary actions: {actions - _SPEC_16_ACTIONS}"
    assert actions == {"api_key.created", "api_key.revoked", "authorization.denied"}
    serialized = json.dumps(rows_a)
    for row in rows_a:
        assert row["action"] in _PINNED_METADATA_KEYS, row["action"]
        metadata = json.loads(row["metadata"])
        assert set(metadata) == _PINNED_METADATA_KEYS[row["action"]], row
        assert str(row["organization_id"]).startswith("org_")
        # Actor identity/type agreement for both actor kinds (decision 7).
        if row["actor_type"] == "user":
            assert str(row["actor_id"]).startswith("usr_")
        else:
            assert row["actor_type"] == "api_key"
            assert str(row["actor_id"]).startswith("key_")

    created_rows = [row for row in rows_a if row["action"] == "api_key.created"]
    assert len(created_rows) == 1
    assert json.loads(created_rows[0]["metadata"]) == {
        "environment": "live",
        "scopes": ["vispector:inspection:run"],
    }
    assert created_rows[0]["target_type"] == "api_key"
    assert created_rows[0]["target_id"] == body["id"]
    revoked_rows = [row for row in rows_a if row["action"] == "api_key.revoked"]
    assert [json.loads(row["metadata"]) for row in revoked_rows] == [{}]
    assert revoked_rows[0]["target_id"] == body["id"]

    denial_meta = [
        json.loads(row["metadata"]) for row in rows_a if row["action"] == "authorization.denied"
    ]
    assert denial_meta == [{"reason": "human_only", "operation": "list_api_keys"}]
    assert {row["actor_id"] for row in rows_a if row["actor_type"] == "api_key"} == {body["id"]}

    # No credential material rides any audit row (AGENTS.md; the literal, the
    # secret, the §8 segment, and the pepper all stay out of metadata), and
    # the human JWT stays out too.
    for material in (literal, parts.secret, parts.key_id, _PEPPER.decode()):
        assert material not in serialized
    assert admin_token not in serialized
    assert "@" not in serialized
    assert "bearer" not in serialized.lower()
    assert "eyJ" not in serialized
