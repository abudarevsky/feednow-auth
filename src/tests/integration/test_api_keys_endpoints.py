"""Integration tests for the API-key endpoints (Phase 05 task 6).

Same Phase 03/04-proven stack as the member tests (decision 12): loopback
JWKS-signed tokens, real SQLite, seeded owner/admin/member/viewer matrix in
``org_team`` plus an outsider anchoring ``org_outside``, and a
:class:`~app.auth.pepper.StaticPepper` wired into
:func:`~app.api.keys.build_api_keys_router` (so the management routes carry
the live key-rejection branch, decision 8). Seeded keys are written directly
through the contract (no API path exists for pre-existing or revoked rows);
audit and row assertions read the SQLite file directly.

Acceptance mapping (task-6 Verify bullets):

- create: 201 body is exactly ``{id, name, key, created_at}`` and the
  returned literal verifies through :func:`~app.auth.api_key_auth.verify_api_key`;
  the stored row carries only the peppered HMAC (raw-file sweep proves no
  plaintext/literal bytes); the ``api_key.created`` audit is exact
  (sorted-unique scopes, human ``usr_`` actor, ``key_`` target);
- the full literal appears in **no** other response (list bodies swept);
- list: all statuses, org-scoped, masked ``key_prefix`` only, limit/cursor
  round-trip, foreign cursor → 400;
- role matrix: owner/admin 201/204; member/viewer 403 + ``insufficient_role``
  audit; outsider 403 + ``no_membership`` audit; an API-key bearer on all
  three routes → 403 + ``human_only`` audit under the ``key_`` actor
  (no-escalation proof);
- revoke: 204 empty body; second revoke → 204 with a **second truthful**
  audit and the original ``revoked_at`` preserved; subsequent
  ``verify_api_key`` → the one uniform 401; list shows ``status=revoked`` +
  ``revoked_at``; foreign/unknown key → byte-identical 404s with zero
  ``api_key.revoked`` rows;
- invalid scope shape → 422; every error body validates against the frozen
  ``Error`` envelope.
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

from app.api.keys import build_api_keys_router
from app.auth.api_key_auth import (
    API_KEY_AUTHENTICATION_MESSAGE,
    ApiKeyAuthenticationError,
    verify_api_key,
)
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.credentials import hash_secret, parse_literal
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    IdentityProvider,
    MembershipRole,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.errors import Error
from app.models.external_identity import ExternalIdentity
from app.models.ids import (
    ApiKeyId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    UserId,
)
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services.api_key_service import build_key_prefix
from app.storage.sqlite import CURSOR_SCOPE_MEMBERSHIPS, SQLiteStorage, encode_cursor

ALLOWED_CLIENT = "keys-app-client"
_T0 = datetime(2026, 9, 14, 9, 0, 0, tzinfo=UTC)

# Same fixed 32-byte test pepper as the task-1/2/3/5 suites (never production).
PEPPER = b"integration-api-keys-pepper-32b!"

# 26-char Crockford key-id segments (underscore-free by charset, decision 2).
SEG_A = "01JXYZ7KA20MB63PCQ8VNDWFTG"
SEG_B = "01JXYZ7KA20MB63PCQ8VNDWFTH"
SEG_C = "01JXYZ7KA20MB63PCQ8VNDWFTJ"
SEG_OUTSIDE = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
SEED_SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"

RUN_SCOPE = "vispector:inspection:run"
READ_SCOPE = "vispector:inspection:read"


# ---------------------------------------------------------------------------
# Seeding helpers (matrix users/orgs/memberships and pre-existing keys are
# seeded directly — the Phase 04 pattern; expiry/revocation have no API path)
# ---------------------------------------------------------------------------


def seed_user(storage: SQLiteStorage, *, user_id: str, sub: str | None, email: str) -> User:
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


def seed_org(storage: SQLiteStorage, *, organization_id: str, slug: str) -> Organization:
    organization = Organization(
        id=OrganizationId(organization_id),
        name=f"seed {organization_id}",
        slug=slug,
        type=OrganizationType.CUSTOMER,
        status=OrganizationStatus.ACTIVE,
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
) -> Membership:
    membership = Membership(
        id=MembershipId(membership_id),
        organization_id=OrganizationId(organization_id),
        user_id=UserId(user_id),
        role=role,
        status="active",
        created_at=_T0,
    )
    storage.create_membership(membership)
    return membership


def seed_key(
    storage: SQLiteStorage,
    *,
    api_key_id: str,
    organization_id: str,
    key_id_segment: str,
    created_at: datetime = _T0,
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE,
    revoked_at: datetime | None = None,
) -> ApiKey:
    """Write a complete key row with the peppered HMAC of the shared test secret."""
    key = ApiKey(
        id=ApiKeyId(api_key_id),
        organization_id=OrganizationId(organization_id),
        created_by_user_id=UserId("usr_owner"),
        name=f"seeded {api_key_id}",
        key_id=key_id_segment,
        key_prefix=build_key_prefix(ApiKeyEnvironment.LIVE, key_id_segment, SEED_SECRET),
        secret_hash=hash_secret(PEPPER, SEED_SECRET),
        environment=ApiKeyEnvironment.LIVE,
        scopes=[READ_SCOPE],
        status=status,
        created_at=created_at,
        revoked_at=revoked_at,
    )
    return storage.create_api_key(key)


def rows(db_path: Path, table: str) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
    finally:
        conn.close()


def audits(db_path: Path, action: str) -> list[dict[str, Any]]:
    found = [row for row in rows(db_path, "audit_events") if row["action"] == action]
    return sorted(found, key=lambda row: (row["created_at"], row["id"]))


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


class _Env:
    def __init__(self, db_path: Path, server: JwksTestServer, key: TestKey) -> None:
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        self.pepper = StaticPepper(PEPPER)
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[ALLOWED_CLIENT],
        )
        self.verifier = verifier
        app = create_app(routers=[build_api_keys_router(self.storage, verifier, self.pepper)])
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

    def create_key(
        self,
        caller: str = "owner",
        *,
        organization_id: str = "org_team",
        name: str = "ci runner",
        environment: str = "live",
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        response = self.client.post(
            f"/v1/organizations/{organization_id}/api-keys",
            headers=self.headers_for(caller),
            json={
                "name": name,
                "environment": environment,
                "scopes": scopes if scopes is not None else [RUN_SCOPE, READ_SCOPE, RUN_SCOPE],
            },
        )
        assert response.status_code == 201, response.content
        return response.json()

    def close(self) -> None:
        self.storage.close()


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("keys-pool-key-1")


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_Env]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _Env(tmp_path / "api_keys.sqlite", server, key)
        yield built
        built.close()


@pytest.fixture
def matrix(env: _Env) -> _Env:
    """org_team seeded with owner/admin/member/viewer + outsider on org_outside."""
    seed_user(env.storage, user_id="usr_owner", sub="owner-sub", email="owner@example.test")
    seed_user(env.storage, user_id="usr_admin", sub="admin-sub", email="admin@example.test")
    seed_user(env.storage, user_id="usr_member", sub="member-sub", email="member@example.test")
    seed_user(env.storage, user_id="usr_viewer", sub="viewer-sub", email="viewer@example.test")
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
    return env


# ---------------------------------------------------------------------------
# POST .../api-keys — creation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("caller", ["owner", "admin"])
def test_create_201_exact_body_and_literal_verifies(matrix: _Env, caller: str) -> None:
    body = matrix.create_key(caller)
    # Frozen §15 response: exactly these four fields (no scopes, no prefix).
    assert set(body) == {"id", "name", "key", "created_at"}
    assert body["id"].startswith("key_")
    assert body["name"] == "ci runner"
    literal = body["key"]
    assert literal.startswith("fn_live_")

    # The returned literal authenticates through the task-3 seam.
    verified = verify_api_key(matrix.storage, matrix.pepper, literal)
    assert verified.api_key.id == body["id"]
    assert verified.context.actor_type == "api_key"
    assert verified.context.actor_id == body["id"]
    assert verified.context.organization_id == "org_team"
    assert verified.context.roles == []
    assert verified.context.scopes == [READ_SCOPE, RUN_SCOPE]  # sorted-unique

    # Row truth: only the peppered HMAC is stored; scopes normalized.
    stored = [row for row in rows(matrix.db_path, "api_keys") if row["id"] == body["id"]]
    assert len(stored) == 1
    row = stored[0]
    secret = parse_literal(literal).secret
    assert row["secret_hash"] == hash_secret(PEPPER, secret)
    assert json.loads(row["scopes"]) == [READ_SCOPE, RUN_SCOPE]
    assert row["organization_id"] == "org_team"
    assert row["created_by_user_id"] == f"usr_{caller}"
    assert row["status"] == "active"
    assert row["environment"] == "live"
    assert row["expires_at"] is None
    assert row["key_prefix"] == build_key_prefix(ApiKeyEnvironment.LIVE, row["key_id"], secret)
    assert len(row["key_prefix"]) == 44  # decision 2: 8+26+1+6+3

    # Exact ``api_key.created`` audit (decision 9): non-secret metadata only.
    created = audits(matrix.db_path, "api_key.created")
    assert len(created) == 1
    assert json.loads(created[0]["metadata"]) == {
        "environment": "live",
        "scopes": [READ_SCOPE, RUN_SCOPE],
    }
    assert created[0]["actor_type"] == "user"
    assert created[0]["actor_id"] == f"usr_{caller}"
    assert created[0]["target_type"] == "api_key"
    assert created[0]["target_id"] == body["id"]
    assert created[0]["organization_id"] == "org_team"


def test_create_persists_no_plaintext_anywhere(matrix: _Env) -> None:
    body = matrix.create_key()
    literal = body["key"]
    secret = parse_literal(literal).secret
    # Exercise the read paths too, then sweep the raw database file.
    assert (
        matrix.client.get(
            "/v1/organizations/org_team/api-keys", headers=matrix.headers_for("viewer")
        ).status_code
        == 200
    )
    raw = matrix.db_path.read_bytes()
    for material in (literal.encode(), secret.encode(), PEPPER):
        assert material not in raw


def test_create_member_and_viewer_403_with_audit_and_zero_write(matrix: _Env) -> None:
    before = rows(matrix.db_path, "api_keys")
    for caller in ("member", "viewer"):
        response = matrix.client.post(
            "/v1/organizations/org_team/api-keys",
            headers=matrix.headers_for(caller),
            json={"name": "sneaky", "environment": "live", "scopes": [RUN_SCOPE]},
        )
        assert response.status_code == 403
        envelope = Error.model_validate(response.json())
        assert envelope.code == "forbidden"
    denied = audits(matrix.db_path, "authorization.denied")
    assert [json.loads(row["metadata"]) for row in denied] == [
        {"reason": "insufficient_role", "operation": "create_api_key"},
        {"reason": "insufficient_role", "operation": "create_api_key"},
    ]
    assert all(row["actor_id"] in {"usr_member", "usr_viewer"} for row in denied)
    assert rows(matrix.db_path, "api_keys") == before
    assert audits(matrix.db_path, "api_key.created") == []


@pytest.mark.parametrize("bad_scope", ["Bogus_Scope", "vispector:inspection", "vispector:*"])
def test_create_invalid_scope_shape_is_422(matrix: _Env, bad_scope: str) -> None:
    response = matrix.client.post(
        "/v1/organizations/org_team/api-keys",
        headers=matrix.headers_for("admin"),
        json={"name": "bad", "environment": "live", "scopes": [bad_scope]},
    )
    assert response.status_code == 422
    envelope = Error.model_validate(response.json())
    assert envelope.code == "validation_error"
    assert envelope.field_errors is not None
    assert envelope.field_errors[0].field == "body.scopes.0"
    assert rows(matrix.db_path, "api_keys") == []


def test_create_invalid_environment_is_422(matrix: _Env) -> None:
    response = matrix.client.post(
        "/v1/organizations/org_team/api-keys",
        headers=matrix.headers_for("admin"),
        json={"name": "bad", "environment": "staging", "scopes": []},
    )
    assert response.status_code == 422
    assert Error.model_validate(response.json()).code == "validation_error"
    assert rows(matrix.db_path, "api_keys") == []


def test_empty_scopes_list_is_valid_and_persisted(matrix: _Env) -> None:
    body = matrix.create_key(scopes=[])
    stored = [row for row in rows(matrix.db_path, "api_keys") if row["id"] == body["id"]]
    assert json.loads(stored[0]["scopes"]) == []
    verified = verify_api_key(matrix.storage, matrix.pepper, body["key"])
    assert verified.context.scopes == []


# ---------------------------------------------------------------------------
# GET .../api-keys — listing
# ---------------------------------------------------------------------------


def test_list_shows_all_statuses_org_scoped_and_masked(matrix: _Env) -> None:
    seed_key(
        matrix.storage,
        api_key_id="key_seed_a",
        organization_id="org_team",
        key_id_segment=SEG_A,
    )
    seed_key(
        matrix.storage,
        api_key_id="key_seed_b",
        organization_id="org_team",
        key_id_segment=SEG_B,
        created_at=_T0 + timedelta(minutes=1),
        status=ApiKeyStatus.REVOKED,
        revoked_at=_T0 + timedelta(minutes=2),
    )
    seed_key(
        matrix.storage,
        api_key_id="key_outside",
        organization_id="org_outside",
        key_id_segment=SEG_OUTSIDE,
    )
    created = matrix.create_key(
        scopes=[RUN_SCOPE],
    )

    response = matrix.client.get(
        "/v1/organizations/org_team/api-keys", headers=matrix.headers_for("viewer")
    )
    assert response.status_code == 200
    page = response.json()
    listed = {item["id"]: item for item in page["items"]}
    # All statuses, org-scoped: the foreign seeded key is absent.
    assert set(listed) == {"key_seed_a", "key_seed_b", created["id"]}
    assert listed["key_seed_b"]["status"] == "revoked"
    assert listed["key_seed_b"]["revoked_at"] is not None
    assert listed["key_seed_a"]["status"] == "active"
    # Frozen summary shape: masked identification only.
    for item in page["items"]:
        assert set(item) == {
            "id",
            "name",
            "environment",
            "key_prefix",
            "status",
            "scopes",
            "created_at",
            "last_used_at",
            "expires_at",
            "revoked_at",
        }
        assert item["key_prefix"].endswith("...")
    # The full literal and its secret appear in no list body (one-crossing sweep).
    serialized = json.dumps(page)
    assert created["key"] not in serialized
    assert parse_literal(created["key"]).secret not in serialized
    assert "secret_hash" not in serialized


def test_list_limit_clamps_and_cursor_round_trips(matrix: _Env) -> None:
    for index, segment in enumerate((SEG_A, SEG_B, SEG_C)):
        seed_key(
            matrix.storage,
            api_key_id=f"key_page_{index}",
            organization_id="org_team",
            key_id_segment=segment,
            created_at=_T0 + timedelta(minutes=index),
        )
    headers = matrix.headers_for("member")
    first = matrix.client.get("/v1/organizations/org_team/api-keys?limit=1", headers=headers)
    assert first.status_code == 200
    page_one = first.json()
    assert [item["id"] for item in page_one["items"]] == ["key_page_0"]
    assert page_one["limit"] == 1
    assert page_one["next_cursor"] is not None
    second = matrix.client.get(
        f"/v1/organizations/org_team/api-keys?limit=1&cursor={page_one['next_cursor']}",
        headers=headers,
    )
    assert second.status_code == 200
    assert [item["id"] for item in second.json()["items"]] == ["key_page_1"]

    # A cursor issued for a different list (memberships scope) is foreign: 400.
    foreign = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, _T0, "mem_p0")
    rejected = matrix.client.get(
        f"/v1/organizations/org_team/api-keys?cursor={foreign}", headers=headers
    )
    assert rejected.status_code == 400
    envelope = Error.model_validate(rejected.json())
    assert envelope.code == "validation_error"
    assert envelope.message == "pagination cursor is invalid"


def test_list_outsider_403_with_denial_audit_and_zero_mutation(matrix: _Env) -> None:
    seed_key(
        matrix.storage,
        api_key_id="key_seed_a",
        organization_id="org_team",
        key_id_segment=SEG_A,
    )
    response = matrix.client.get(
        "/v1/organizations/org_team/api-keys", headers=matrix.headers_for("outsider")
    )
    assert response.status_code == 403
    envelope = Error.model_validate(response.json())
    assert envelope.code == "forbidden"
    assert envelope.message == "you do not have permission to access this organization"
    denied = audits(matrix.db_path, "authorization.denied")
    assert len(denied) == 1
    assert json.loads(denied[0]["metadata"]) == {
        "reason": "no_membership",
        "operation": "list_api_keys",
    }
    assert denied[0]["actor_id"] == "usr_outsider"
    # Untouched: the seeded key is the only row.
    assert [row["id"] for row in rows(matrix.db_path, "api_keys")] == ["key_seed_a"]


# ---------------------------------------------------------------------------
# DELETE .../api-keys/{key_id} — revocation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("caller", ["owner", "admin"])
def test_revoke_204_idempotent_second_call_with_truthful_audits(matrix: _Env, caller: str) -> None:
    created = matrix.create_key()
    key_id = created["id"]
    literal = created["key"]

    first = matrix.client.delete(
        f"/v1/organizations/org_team/api-keys/{key_id}", headers=matrix.headers_for(caller)
    )
    assert first.status_code == 204
    assert first.content == b""  # manifest-pinned: 204 has no body
    stored = next(row for row in rows(matrix.db_path, "api_keys") if row["id"] == key_id)
    assert stored["status"] == "revoked"
    assert stored["revoked_at"] is not None
    revoked_at_after_first = stored["revoked_at"]

    # Duplicate revoke: idempotent success, original revoked_at preserved.
    second = matrix.client.delete(
        f"/v1/organizations/org_team/api-keys/{key_id}", headers=matrix.headers_for(caller)
    )
    assert second.status_code == 204
    stored = next(row for row in rows(matrix.db_path, "api_keys") if row["id"] == key_id)
    assert stored["revoked_at"] == revoked_at_after_first

    # Each processed call appended exactly one truthful audit (decision 10).
    revoked_audits = audits(matrix.db_path, "api_key.revoked")
    assert len(revoked_audits) == 2
    for row in revoked_audits:
        assert json.loads(row["metadata"]) == {}
        assert row["actor_type"] == "user"
        assert row["actor_id"] == f"usr_{caller}"
        assert row["target_type"] == "api_key"
        assert row["target_id"] == key_id
        assert row["organization_id"] == "org_team"

    # "Immediately effective": the literal now fails the uniform 401 seam.
    with pytest.raises(ApiKeyAuthenticationError) as raised:
        verify_api_key(matrix.storage, matrix.pepper, literal)
    assert str(raised.value) == API_KEY_AUTHENTICATION_MESSAGE

    # And the list reflects the lifecycle.
    page = matrix.client.get(
        "/v1/organizations/org_team/api-keys", headers=matrix.headers_for("viewer")
    ).json()
    item = next(entry for entry in page["items"] if entry["id"] == key_id)
    assert item["status"] == "revoked"
    assert item["revoked_at"] is not None


def test_revoke_member_and_viewer_403_with_audit_and_key_intact(matrix: _Env) -> None:
    created = matrix.create_key()
    for caller in ("member", "viewer"):
        response = matrix.client.delete(
            f"/v1/organizations/org_team/api-keys/{created['id']}",
            headers=matrix.headers_for(caller),
        )
        assert response.status_code == 403
    denied = audits(matrix.db_path, "authorization.denied")
    assert [json.loads(row["metadata"])["reason"] for row in denied] == [
        "insufficient_role",
        "insufficient_role",
    ]
    assert [json.loads(row["metadata"])["operation"] for row in denied] == [
        "revoke_api_key",
        "revoke_api_key",
    ]
    stored = next(row for row in rows(matrix.db_path, "api_keys") if row["id"] == created["id"])
    assert stored["status"] == "active"
    assert audits(matrix.db_path, "api_key.revoked") == []


def test_revoke_foreign_and_unknown_key_answer_byte_identical_404s(matrix: _Env) -> None:
    # A real key, but in another organization (seeded directly).
    seed_key(
        matrix.storage,
        api_key_id="key_outside",
        organization_id="org_outside",
        key_id_segment=SEG_OUTSIDE,
    )
    unknown = "key_" + "f" * 32  # valid ApiKeyId shape, never issued
    headers = matrix.headers_for("admin")
    foreign = matrix.client.delete(
        "/v1/organizations/org_team/api-keys/key_outside", headers=headers
    )
    missing = matrix.client.delete(
        f"/v1/organizations/org_team/api-keys/{unknown}", headers=headers
    )
    assert foreign.status_code == missing.status_code == 404
    # No cross-org existence oracle: byte-identical bodies.
    assert foreign.content == missing.content
    envelope = Error.model_validate(foreign.json())
    assert envelope.code == "not_found"
    assert envelope.message == "API key not found"
    # The foreign row is untouched and no CAS/audit ran on either path.
    stored = next(row for row in rows(matrix.db_path, "api_keys") if row["id"] == "key_outside")
    assert stored["status"] == "active"
    assert stored["revoked_at"] is None
    assert audits(matrix.db_path, "api_key.revoked") == []


def test_revoke_malformed_key_id_path_is_422(matrix: _Env) -> None:
    response = matrix.client.delete(
        "/v1/organizations/org_team/api-keys/not_a_key_id", headers=matrix.headers_for("admin")
    )
    assert response.status_code == 422
    assert Error.model_validate(response.json()).code == "validation_error"


# ---------------------------------------------------------------------------
# API-key bearers on management routes — the no-escalation matrix (AC 4)
# ---------------------------------------------------------------------------


def test_api_key_bearer_on_all_three_routes_403_human_only(matrix: _Env) -> None:
    created = matrix.create_key(scopes=[RUN_SCOPE, READ_SCOPE])
    key_headers = matrix.auth(created["key"])

    responses = [
        matrix.client.get("/v1/organizations/org_team/api-keys", headers=key_headers),
        matrix.client.post(
            "/v1/organizations/org_team/api-keys",
            headers=key_headers,
            json={"name": "escalation", "environment": "live", "scopes": [RUN_SCOPE]},
        ),
        matrix.client.delete(
            f"/v1/organizations/org_team/api-keys/{created['id']}", headers=key_headers
        ),
    ]
    assert [response.status_code for response in responses] == [403, 403, 403]
    # The one uniform Phase 04 403 body, byte-identical across routes.
    assert responses[0].content == responses[1].content == responses[2].content
    assert Error.model_validate(responses[0].json()).message == (
        "you do not have permission to access this organization"
    )

    denied = audits(matrix.db_path, "authorization.denied")
    assert [json.loads(row["metadata"]) for row in denied] == [
        {"reason": "human_only", "operation": "list_api_keys"},
        {"reason": "human_only", "operation": "create_api_key"},
        {"reason": "human_only", "operation": "revoke_api_key"},
    ]
    # Audited under the ``key_`` actor (decision 7 generalization) — the key
    # never borrowed the creator's roles, and created no second key.
    assert all(row["actor_type"] == "api_key" for row in denied)
    assert all(row["actor_id"] == created["id"] for row in denied)
    assert len(rows(matrix.db_path, "api_keys")) == 1


def test_revoked_bearer_key_uniform_401_with_zero_denial_audit(matrix: _Env) -> None:
    # Authentication failures are 401 with zero audit rows (decision 12):
    # a revoked key's literal on a management route never reaches authz.
    created = matrix.create_key()
    key_id = created["id"]
    matrix.storage.revoke_api_key(ApiKeyId(key_id), revoked_at=_T0)
    response = matrix.client.get(
        "/v1/organizations/org_team/api-keys", headers=matrix.auth(created["key"])
    )
    assert response.status_code == 401
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
    assert envelope.message == API_KEY_AUTHENTICATION_MESSAGE
    assert audits(matrix.db_path, "authorization.denied") == []


# ---------------------------------------------------------------------------
# Route/manifest wiring
# ---------------------------------------------------------------------------


def test_router_registers_manifest_entries_exactly(matrix: _Env) -> None:
    paths = matrix.client.app.openapi()["paths"]
    assert {p for p in paths if p.startswith("/v1")} == {
        "/v1/organizations/{organization_id}/api-keys",
        "/v1/organizations/{organization_id}/api-keys/{key_id}",
    }
    collection = paths["/v1/organizations/{organization_id}/api-keys"]
    assert set(collection) == {"get", "post"}
    assert collection["get"]["responses"]["200"]["description"]
    assert collection["post"]["responses"]["201"]["description"]
    item = paths["/v1/organizations/{organization_id}/api-keys/{key_id}"]
    assert set(item) == {"delete"}
    assert item["delete"]["responses"]["204"]["description"]
