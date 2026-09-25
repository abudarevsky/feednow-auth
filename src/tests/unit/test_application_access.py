"""Unit tests for the Phase 13 task-4 global-administrator dependency
(:mod:`app.auth.application_access`).

The gate is exercised **directly against the returned dependency callable**
(the ``test_principal_dispatch`` pattern: a minimal fake ``Request`` over
real SQLite + a recording verifier + ``StaticPepper``), resolving the
composed seam first and feeding the gate its ``Principal`` — the same graph
order FastAPI uses — so the chain below it is the published one and only
this module's decision is under test:

- grant: human principal with ``application_role is ApplicationRole.ADMIN``
  — the same :class:`Principal` object is handed through verbatim;
- uniform denial: ordinary humans and **every** API-key variant (including
  a key created by an ADMIN user) answer the one fixed 403 message —
  structurally, because the key branch yields ``principal.user is None``
  and API-key contexts stay roleless (spec 12 invariant 7; spec 13
  required behavior 6);
- oracle-freedom: every denial body is the same constant and carries no
  role, key, email, or ``usr_``/``key_`` material;
- authentication still precedes authorization: header/JWT/key failures keep
  the published 401 mapping (a revoked key never reaches the role gate),
  and a first-login human auto-provisions before being denied as a
  ``USER``;
- the seam never audits (no ``operation_id`` by design) and never mutates
  on denial.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

from app.auth.application_access import (
    APPLICATION_ADMIN_FORBIDDEN_MESSAGE,
    build_application_admin_dependency,
)
from app.auth.cognito import CognitoClaims, CognitoProfile
from app.auth.credentials import build_literal, hash_secret
from app.auth.dependencies import build_current_principal
from app.auth.errors import TokenValidationError
from app.auth.pepper import StaticPepper
from app.auth.principal import Principal
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
from app.models.external_identity import ExternalIdentity
from app.models.ids import ApiKeyId, ExternalIdentityId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.storage.sqlite import SQLiteStorage

# Same fixed 32-byte test pepper as the Phase 05/13 suites (never production).
PEPPER = b"unit-test-pepper-32-bytes-fixed!"

# 26-char Crockford segments (underscore-free by charset).
KEY_ID = "01JXYZ7KA20MB63PCQ8VNDWFTG"
ADMIN_KEY_ID = "01JXYZ7KA20MB63PCQ8VNDWFTH"  # created by the ADMIN user
SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"

JWTISH_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature"

ADMIN_USER = UserId("usr_" + "a" * 32)
REGULAR_USER = UserId("usr_" + "r" * 32)
ORG = OrganizationId("org_" + "a" * 32)
KEY = ApiKeyId("key_" + "a" * 32)
ADMIN_KEY = ApiKeyId("key_" + "b" * 32)
_T0 = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
_SCOPES = ["vispector:inspection:run"]

#: Anything that must never ride a denial message (identity/credential
#: material the gate knows but refuses to echo). Role *values* are checked
#: as whole words separately (the fixed message's "administer" is a
#: capability description, not a role echo).
FORBIDDEN_FRAGMENTS = (
    str(ADMIN_USER),
    str(REGULAR_USER),
    "admin@example.test",
    "regular@example.test",
    KEY_ID,
    ADMIN_KEY_ID,
    SECRET,
    str(KEY),
    str(ADMIN_KEY),
)


class FakeRequest:
    """Only the surface ``_extract_bearer_token`` reads: the auth header."""

    def __init__(self, authorization: str | None = None) -> None:
        self.headers: dict[str, str] = {}
        if authorization is not None:
            self.headers["authorization"] = authorization


class RecordingVerifier:
    """Token -> claims with a call log (the Phase 03 fake-verifier seam)."""

    def __init__(self) -> None:
        self.claims_by_token: dict[str, CognitoClaims] = {}
        self.verified: list[str] = []

    def verify(self, token: str) -> CognitoClaims:
        self.verified.append(token)
        try:
            return self.claims_by_token[token]
        except KeyError as exc:
            raise TokenValidationError("token failed verification") from exc


class RecordingProfileSource:
    """Phase 11 double: records ``(token, expected_sub)`` per fetch."""

    def __init__(self, email: str = "first-login@example.test") -> None:
        self.email = email
        self.calls: list[tuple[str, str]] = []

    def fetch(self, access_token: str, expected_sub: str) -> CognitoProfile:
        self.calls.append((access_token, expected_sub))
        return CognitoProfile(
            sub=expected_sub,
            email=self.email,
            email_verified=True,
            display_name=None,
        )


def _claims(sub: str, email: str) -> CognitoClaims:
    return CognitoClaims(
        sub=sub,
        email=email,
        username="admin-gate-user",
        client_id="probe-client",
        iss="https://probe.example.test/pool",
        exp=int(_T0.timestamp()) + 3600,
    )


def _user(user_id: UserId, email: str, role: ApplicationRole) -> User:
    return User(
        id=user_id,
        display_name=f"seed {user_id}",
        email=email,
        status=UserStatus.ACTIVE,
        application_role=role,
        created_at=_T0,
        updated_at=_T0,
    )


def _api_key(
    *,
    api_key_id: ApiKeyId,
    key_id: str,
    created_by: UserId,
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE,
) -> ApiKey:
    return ApiKey(
        id=api_key_id,
        organization_id=ORG,
        created_by_user_id=created_by,
        name="admin gate probe",
        key_id=key_id,
        key_prefix=f"fn_live_{key_id}_a8f32x...",
        secret_hash=hash_secret(PEPPER, SECRET),
        environment=ApiKeyEnvironment.LIVE,
        scopes=list(_SCOPES),
        status=status,
        created_at=_T0,
    )


class GateEnv:
    """Real SQLite + recording seams + the built admin dependency."""

    def __init__(self, db_path: Path, profile_source: Any = None) -> None:
        self.db_path = db_path
        self.adapter = SQLiteStorage(db_path)
        self.verifier = RecordingVerifier()
        self.pepper = StaticPepper(PEPPER)
        self.profile_source = profile_source
        # The seam the dependency composes, built identically: FastAPI would
        # resolve it first, so the direct call below feeds it the fake request
        # and hands the resulting Principal to the gate (same graph order).
        self.current_principal = build_current_principal(
            self.adapter, self.verifier, self.pepper, profile_source
        )
        self.admin_dependency = build_application_admin_dependency(
            self.adapter, self.verifier, self.pepper, profile_source
        )
        self._seed()

    def _seed(self) -> None:
        for user, sub in (
            (_user(ADMIN_USER, "admin@example.test", ApplicationRole.ADMIN), "admin-sub"),
            (_user(REGULAR_USER, "regular@example.test", ApplicationRole.USER), "regular-sub"),
        ):
            self.adapter.create_user(user)
            self.adapter.create_external_identity(
                ExternalIdentity(
                    id=ExternalIdentityId(f"extid_{user.id.removeprefix('usr_')}"),
                    user_id=user.id,
                    provider=IdentityProvider.COGNITO,
                    provider_subject=sub,
                    provider_tenant=None,
                    created_at=_T0,
                )
            )
        self.adapter.create_organization(
            Organization(
                id=ORG,
                name="seed org",
                slug="admin-gate-org",
                type=OrganizationType.CUSTOMER,
                status=OrganizationStatus.ACTIVE,
                created_at=_T0,
                updated_at=_T0,
            )
        )
        # Anchor memberships so both human contexts resolve (earliest org).
        for user_id in (ADMIN_USER, REGULAR_USER):
            self.adapter.create_membership(
                Membership(
                    id=MembershipId(f"mem_{user_id.removeprefix('usr_')}"),
                    organization_id=ORG,
                    user_id=user_id,
                    role=MembershipRole.MEMBER,
                    status=MembershipStatus.ACTIVE,
                    created_at=_T0,
                )
            )
        self.adapter.create_api_key(
            _api_key(api_key_id=KEY, key_id=KEY_ID, created_by=REGULAR_USER)
        )
        # The escalation probe: a key whose creating user **is** an admin.
        self.adapter.create_api_key(
            _api_key(api_key_id=ADMIN_KEY, key_id=ADMIN_KEY_ID, created_by=ADMIN_USER)
        )
        self.adapter.create_api_key(
            _api_key(
                api_key_id=ApiKeyId("key_" + "c" * 32),
                key_id="01JXYZ7KA20MB63PCQ8VNDWFTJ",
                created_by=ADMIN_USER,
                status=ApiKeyStatus.REVOKED,
            )
        )
        self.verifier.claims_by_token[JWTISH_TOKEN] = _claims("admin-sub", "admin@example.test")
        self.verifier.claims_by_token["tok-regular"] = _claims(
            "regular-sub", "regular@example.test"
        )

    def close(self) -> None:
        self.adapter.close()

    def call(self, authorization: str | None) -> Principal:
        principal = self.current_principal(FakeRequest(authorization))
        return self.admin_dependency(principal)

    def bearer(self, token: str) -> str:
        return f"Bearer {token}"

    def live_literal(self, key_id: str = KEY_ID) -> str:
        return build_literal(ApiKeyEnvironment.LIVE, key_id, SECRET)

    def audit_rows(self) -> list[tuple[Any, ...]]:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute("SELECT id, action FROM audit_events").fetchall()
        finally:
            conn.close()


@pytest.fixture
def env(tmp_path: Path) -> Iterator[GateEnv]:
    built = GateEnv(tmp_path / "application_access.sqlite")
    yield built
    built.close()


# ---------------------------------------------------------------------------
# Grant: the ADMIN human passes and the Principal rides through verbatim
# ---------------------------------------------------------------------------


def test_admin_human_is_granted_the_same_principal(env: GateEnv) -> None:
    principal = env.current_principal(FakeRequest(env.bearer(JWTISH_TOKEN)))
    granted = env.admin_dependency(principal)

    # Verbatim pass-through: the dispatch's Principal object itself.
    assert granted is principal
    assert granted.user is not None
    assert granted.user.id == ADMIN_USER
    assert granted.user.application_role is ApplicationRole.ADMIN
    assert granted.api_key is None
    assert granted.context.actor_id == ADMIN_USER
    # The human chain ran; the credential seam never saw the token.
    assert env.verifier.verified == [JWTISH_TOKEN]


def test_factory_is_pure_wiring(env: GateEnv) -> None:
    """Construction performed no I/O: nothing verified, no audit rows."""
    assert env.verifier.verified == []
    assert env.audit_rows() == []


# ---------------------------------------------------------------------------
# Uniform denial: every non-admin outcome, one fixed credential-free 403
# ---------------------------------------------------------------------------


def _assert_uniform_403(excinfo: pytest.ExceptionInfo[HTTPException]) -> None:
    assert excinfo.value.status_code == 403
    assert excinfo.value.detail == APPLICATION_ADMIN_FORBIDDEN_MESSAGE


def test_ordinary_human_is_the_uniform_403(env: GateEnv) -> None:
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer("tok-regular"))
    _assert_uniform_403(excinfo)


def test_api_key_is_the_uniform_403_not_a_401(env: GateEnv) -> None:
    """Authentication succeeded (valid key, real scopes); the role gate denies."""
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer(env.live_literal()))
    _assert_uniform_403(excinfo)
    # The key never borrows a human path: the JWT verifier was never consulted.
    assert env.verifier.verified == []


def test_key_created_by_an_admin_user_is_still_the_uniform_403(env: GateEnv) -> None:
    """Spec 13 required behavior 6: keys owned by admins fail structurally
    (``principal.user is None`` on the key branch — no reverse lookup)."""
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer(env.live_literal(ADMIN_KEY_ID)))
    _assert_uniform_403(excinfo)


def test_every_denial_shares_one_message_free_of_material(env: GateEnv) -> None:
    """One body for every denial shape, echoing no role/key/identity data."""
    denials = ["tok-regular", env.live_literal(), env.live_literal(ADMIN_KEY_ID)]
    details = []
    for bearer in denials:
        with pytest.raises(HTTPException) as excinfo:
            env.call(env.bearer(bearer))
        assert excinfo.value.status_code == 403
        details.append(excinfo.value.detail)
    assert set(details) == {APPLICATION_ADMIN_FORBIDDEN_MESSAGE}
    message = APPLICATION_ADMIN_FORBIDDEN_MESSAGE.lower()
    # No role value rides the message as a word (grant/deny are indistinguishable).
    assert re.search(r"\b(admin|user)\b", message) is None
    for fragment in FORBIDDEN_FRAGMENTS:
        assert fragment.lower() not in message, fragment


def test_denials_never_audit_and_never_mutate(env: GateEnv) -> None:
    """This seam carries no ``operation_id``: denial is a bare 403 (the
    reviewed audit belongs to the administration transition, spec 13)."""
    for bearer in ("tok-regular", env.live_literal()):
        with pytest.raises(HTTPException):
            env.call(env.bearer(bearer))
    assert env.audit_rows() == []
    # The gate is read-only: both probe users keep their seeded roles.
    assert env.adapter.get_user(ADMIN_USER).application_role is ApplicationRole.ADMIN
    assert env.adapter.get_user(REGULAR_USER).application_role is ApplicationRole.USER


# ---------------------------------------------------------------------------
# Authentication precedes authorization (published mapping preserved)
# ---------------------------------------------------------------------------


def test_missing_header_fails_with_401_before_the_gate(env: GateEnv) -> None:
    with pytest.raises(HTTPException) as excinfo:
        env.call(None)
    assert excinfo.value.status_code == 401
    assert env.verifier.verified == []


def test_unverifiable_jwt_token_still_401(env: GateEnv) -> None:
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer("eyJunknown.unverified.token"))
    assert excinfo.value.status_code == 401


def test_revoked_key_is_the_authentication_401_not_the_role_403(env: GateEnv) -> None:
    """Class boundary: a revoked key never reaches the role gate (uniform
    401 from the composed chain, distinct from this module's 403)."""
    revoked_key_id = "01JXYZ7KA20MB63PCQ8VNDWFTJ"
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer(env.live_literal(revoked_key_id)))
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail != APPLICATION_ADMIN_FORBIDDEN_MESSAGE


# ---------------------------------------------------------------------------
# profile_source forwarding: first-login human provisions, then is denied
# ---------------------------------------------------------------------------


def test_first_login_human_provisions_then_faces_the_uniform_403(
    tmp_path: Path,
) -> None:
    """Authn-before-authz is unchanged by the gate: the identity miss runs
    the profile seam and auto-provisions (``USER`` default), and the very
    same request is then denied with the fixed 403."""
    source = RecordingProfileSource()
    built = GateEnv(tmp_path / "application_access_profile.sqlite", profile_source=source)
    try:
        built.verifier.claims_by_token["tok-newcomer"] = _claims(
            "newcomer-sub", "claims-only@example.test"
        )
        with pytest.raises(HTTPException) as excinfo:
            built.call(built.bearer("tok-newcomer"))
        _assert_uniform_403(excinfo)
        assert source.calls == [("tok-newcomer", "newcomer-sub")]
        provisioned = built.adapter.list_users_by_email("first-login@example.test")
        assert [user.application_role for user in provisioned] == [ApplicationRole.USER]
    finally:
        built.close()
