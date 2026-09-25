"""HTTP acceptance proofs for the Phase 13 task-4 global-administrator
dependency (:func:`app.auth.application_access.build_application_admin_dependency`).

A **throwaway probe router** mounted on a test-only app (the
``test_principal_dispatch``/``test_api_key_auth_matrix`` pattern — this
dependency is mounted on **no** production route; the frozen manifest is
unchanged) exercises the spec-13 required-behavior-6 matrix over the real
HTTP seam: signed-JWT humans, live API keys (one created by an ADMIN user),
and unauthenticated bearers.

Proofs:

- the ADMIN human reaches the handler (200, actor = the ``usr_``);
- ordinary humans and **every** key variant — including an admin-owned key
  with real scopes — answer the same uniform 403 (``forbidden`` + the one
  fixed module message), byte-identical bodies, no role/key/identity
  material echoed (the endpoint is no oracle);
- authentication precedes authorization: a missing header is the 401 class,
  provably before any role decision;
- the whole matrix mutates nothing and appends zero audit rows (the gate is
  read-only; denial auditing is not this seam's job — spec 13 pins the
  reviewed audit to the administration transition).
"""

# No ``from __future__ import annotations`` here on purpose (the
# ``organization_access`` precedent): the probe handler's
# ``Annotated[..., Depends(admin_dep)]`` references a closure local that
# PEP 563 stringification could not resolve at import time.

import sqlite3
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.auth.application_access import (
    APPLICATION_ADMIN_FORBIDDEN_MESSAGE,
    build_application_admin_dependency,
)
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.credentials import build_literal, hash_secret
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper
from app.auth.principal import Principal
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    ApplicationRole,
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.errors import Error
from app.models.external_identity import ExternalIdentity
from app.models.ids import ApiKeyId, ExternalIdentityId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.storage.sqlite import SQLiteStorage

ALLOWED_CLIENT = "admin-gate-client"
_T0 = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)

# Fixed test pepper (>= 32 bytes, never production).
PEPPER = b"integration-admin-gate-pepper-0123456789ab"

# 26-char Crockford segments (underscore-free by charset).
SEG_PLAIN = "01JXYZ7KA20MB63PCQ8VNDWFTG"  # created by the ordinary user
SEG_ADMIN_OWNED = "01JXYZ7KA20MB63PCQ8VNDWFTH"  # created by the ADMIN user
SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"

RUN_SCOPE = "vispector:inspection:run"

#: Credential/identity material that must never ride a response body.
FORBIDDEN_MATERIAL = (
    SECRET.encode(),
    PEPPER,
    SEG_PLAIN.encode(),
    SEG_ADMIN_OWNED.encode(),
    b"usr_admin",
    b"usr_regular",
    b"admin@example.test",
    b"regular@example.test",
)


class _GateEnv:
    """Test-only app: one probe route on the admin dependency, real SQLite."""

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
        admin_dep = build_application_admin_dependency(self.storage, verifier, self.pepper)

        probe = APIRouter()

        def admin_probe(principal: Annotated[Principal, Depends(admin_dep)]) -> dict[str, str]:
            """Reached only by application admins."""
            return {"actor": str(principal.context.actor_id)}

        probe.add_api_route("/v1/probe/application-admin", admin_probe, methods=["GET"])
        app = create_app(routers=[probe])
        self.client = TestClient(app, raise_server_exceptions=False)
        self.issuer = issuer
        self.key = key

    def seed_cast(self) -> None:
        """Two humans (ADMIN/USER), one org anchoring both, two live keys."""
        for user, sub in (
            (
                User(
                    id=UserId("usr_admin"),
                    display_name="seed admin",
                    email="admin@example.test",
                    status=UserStatus.ACTIVE,
                    application_role=ApplicationRole.ADMIN,
                    created_at=_T0,
                    updated_at=_T0,
                ),
                "admin-sub",
            ),
            (
                User(
                    id=UserId("usr_regular"),
                    display_name="seed regular",
                    email="regular@example.test",
                    status=UserStatus.ACTIVE,
                    application_role=ApplicationRole.USER,
                    created_at=_T0,
                    updated_at=_T0,
                ),
                "regular-sub",
            ),
        ):
            self.storage.create_user(user)
            self.storage.create_external_identity(
                ExternalIdentity(
                    id=ExternalIdentityId(f"extid_{user.id.removeprefix('usr_')}"),
                    user_id=user.id,
                    provider=IdentityProvider.COGNITO,
                    provider_subject=sub,
                    provider_tenant=None,
                    created_at=_T0,
                )
            )
        self.storage.create_organization(
            Organization(
                id=OrganizationId("org_gate"),
                name="seed org_gate",
                slug="admin-gate-org",
                type=OrganizationType.CUSTOMER,
                status=OrganizationStatus.ACTIVE,
                created_at=_T0,
                updated_at=_T0,
            )
        )
        for user_id in (UserId("usr_admin"), UserId("usr_regular")):
            self.storage.create_membership(
                Membership(
                    id=MembershipId(f"mem_{user_id.removeprefix('usr_')}"),
                    organization_id=OrganizationId("org_gate"),
                    user_id=user_id,
                    role=MembershipRole.MEMBER,
                    status=MembershipStatus.ACTIVE,
                    created_at=_T0,
                )
            )
        for api_key_id, segment, owner in (
            (ApiKeyId("key_plain"), SEG_PLAIN, UserId("usr_regular")),
            # The escalation shape: the creating user holds ADMIN.
            (ApiKeyId("key_admin_owned"), SEG_ADMIN_OWNED, UserId("usr_admin")),
        ):
            self.storage.create_api_key(
                ApiKey(
                    id=api_key_id,
                    organization_id=OrganizationId("org_gate"),
                    created_by_user_id=owner,
                    name=f"seeded {api_key_id}",
                    key_id=segment,
                    key_prefix=f"fn_live_{segment}_a8f32x...",
                    secret_hash=hash_secret(PEPPER, SECRET),
                    environment=ApiKeyEnvironment.LIVE,
                    scopes=[RUN_SCOPE],
                    status=ApiKeyStatus.ACTIVE,
                    created_at=_T0,
                )
            )

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

    def auth(self, bearer: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {bearer}"}

    def probe(self, bearer: str | None) -> Any:
        headers = self.auth(bearer) if bearer is not None else {}
        return self.client.get("/v1/probe/application-admin", headers=headers)

    def close(self) -> None:
        self.storage.close()


def table_dump(db_path: Path, table: str) -> list[tuple[object, ...]]:
    """Full verbatim contents of one table, for before/after equality."""
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
    finally:
        conn.close()


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("admin-gate-key-1")


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_GateEnv]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _GateEnv(tmp_path / "application_admin_gate.sqlite", server, key)
        built.seed_cast()
        yield built
        built.close()


# ---------------------------------------------------------------------------
# 200 anchor: the ADMIN human reaches the handler
# ---------------------------------------------------------------------------


def test_admin_human_grants_the_probe(env: _GateEnv) -> None:
    response = env.probe(env.token("admin-sub", "admin@example.test"))
    assert response.status_code == 200
    assert response.json() == {"actor": "usr_admin"}
    # The gate is read-only: no audit row exists after a granted request.
    assert table_dump(env.db_path, "audit_events") == []


def test_admin_human_grant_mutates_nothing(env: _GateEnv) -> None:
    before = {t: table_dump(env.db_path, t) for t in ("users", "api_keys", "audit_events")}
    response = env.probe(env.token("admin-sub", "admin@example.test"))
    assert response.status_code == 200
    after = {t: table_dump(env.db_path, t) for t in ("users", "api_keys", "audit_events")}
    assert after == before


# ---------------------------------------------------------------------------
# Uniform 403: ordinary humans and every key variant, one byte-identical body
# ---------------------------------------------------------------------------


def _denial_requests(env: _GateEnv) -> dict[str, Any]:
    return {
        "ordinary_human": env.probe(env.token("regular-sub", "regular@example.test")),
        "key_by_regular": env.probe(build_literal(ApiKeyEnvironment.LIVE, SEG_PLAIN, SECRET)),
        "key_by_admin": env.probe(build_literal(ApiKeyEnvironment.LIVE, SEG_ADMIN_OWNED, SECRET)),
    }


def test_ordinary_human_is_the_uniform_403(env: _GateEnv) -> None:
    response = env.probe(env.token("regular-sub", "regular@example.test"))
    assert response.status_code == 403
    envelope = Error.model_validate(response.json())
    assert envelope.code == "forbidden"
    assert envelope.message == APPLICATION_ADMIN_FORBIDDEN_MESSAGE


def test_active_key_with_scopes_is_the_uniform_403_not_a_401(env: _GateEnv) -> None:
    """Authentication succeeded (the key verifies against the peppered row);
    the role gate denies — keys never borrow a human application role."""
    response = env.probe(build_literal(ApiKeyEnvironment.LIVE, SEG_PLAIN, SECRET))
    assert response.status_code == 403
    envelope = Error.model_validate(response.json())
    assert envelope.code == "forbidden"
    assert envelope.message == APPLICATION_ADMIN_FORBIDDEN_MESSAGE


def test_key_created_by_an_admin_is_the_uniform_403(env: _GateEnv) -> None:
    """Spec 13 required behavior 6: every API key fails, **including keys
    owned by admins** (the key branch yields no user; contexts stay roleless)."""
    response = env.probe(build_literal(ApiKeyEnvironment.LIVE, SEG_ADMIN_OWNED, SECRET))
    assert response.status_code == 403
    envelope = Error.model_validate(response.json())
    assert envelope.code == "forbidden"
    assert envelope.message == APPLICATION_ADMIN_FORBIDDEN_MESSAGE


def test_every_denial_is_indistinguishable_and_credential_free(env: _GateEnv) -> None:
    responses = _denial_requests(env)
    contents = {name: response.content for name, response in responses.items()}
    # Oracle-freedom on the message axis: one byte-identical body everywhere.
    assert len(set(contents.values())) == 1, contents
    body = responses["ordinary_human"].content
    for material in FORBIDDEN_MATERIAL:
        assert material not in body
    # Role values are not echoed as words either (grant/deny leak nothing).
    text = body.decode().lower()
    assert '"admin"' not in text and " role" not in text


def test_denial_matrix_writes_no_audit_and_mutates_nothing(env: _GateEnv) -> None:
    before = {t: table_dump(env.db_path, t) for t in ("users", "api_keys", "audit_events")}
    responses = _denial_requests(env)
    assert [r.status_code for r in responses.values()] == [403, 403, 403]
    after = {t: table_dump(env.db_path, t) for t in ("users", "api_keys", "audit_events")}
    assert after == before
    assert after["audit_events"] == []


# ---------------------------------------------------------------------------
# Authentication precedes authorization
# ---------------------------------------------------------------------------


def test_missing_header_is_the_401_class(env: _GateEnv) -> None:
    response = env.probe(None)
    assert response.status_code == 401
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
    assert envelope.message != APPLICATION_ADMIN_FORBIDDEN_MESSAGE


def test_unverifiable_bearer_is_the_401_class(env: _GateEnv) -> None:
    response = env.probe("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature")
    assert response.status_code == 401
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
