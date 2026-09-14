"""Unit tests for the Phase 05 task-5 principal dispatch (:mod:`app.auth.principal`
and :func:`app.auth.dependencies.build_current_principal`).

Proves the decision-6 boundary directly against the dependency callable
(a minimal fake ``Request`` — the chain below it is real SQLite + the task-3
verification seam):

- the :class:`Principal` invariant: **exactly one** of ``user``/``api_key``
  is set (both-``None`` and both-set are programming errors);
- **prefix dispatch is total and collision-free**: a JWT-looking bearer
  (``eyJ…``) is never parsed as a credential — the §8 point lookup never
  runs — and an ``fn_live_``/``fn_test_`` literal is never sent to the JWT
  verifier;
- the human path wraps the **unchanged Phase 03 chain**: same
  ``ResolvedIdentity`` user/context, same failure mapping (disabled user →
  403, missing/malformed header → 401 before any dispatch);
- the API-key path yields ``Principal(user=None, api_key=row)`` with the
  §10 context (``actor_type="api_key"``, ``roles == []``, stored scopes),
  and every authentication failure — revoked, unknown, malformed — is the
  one uniform **401** carrying :data:`API_KEY_AUTHENTICATION_MESSAGE`
  (decision 4); a non-``EntityNotFoundError`` ``StorageError`` propagates
  untranslated (decision 11 → 500, never a misleading 401).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

from app.auth.api_key_auth import API_KEY_AUTHENTICATION_MESSAGE
from app.auth.cognito import CognitoClaims
from app.auth.credentials import build_literal, hash_secret
from app.auth.dependencies import API_KEY_BEARER_PREFIXES, build_current_principal
from app.auth.errors import TokenValidationError
from app.auth.pepper import StaticPepper
from app.auth.principal import Principal
from app.models.api_key import ApiKey
from app.models.authorization_context import AuthorizationContext
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

# Same fixed 32-byte test pepper as the task-1/2/3 suites (never production).
PEPPER = b"unit-test-pepper-32-bytes-fixed!"

# 26-char Crockford segments (underscore-free by charset, decision 2).
LIVE_KEY_ID = "01JXYZ7KA20MB63PCQ8VNDWFTG"
TEST_KEY_ID = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
REVOKED_KEY_ID = "01JXYZ7KA20MB63PCQ8VNDWFTH"
SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"

# A JWS-shaped bearer: real compact tokens always start ``eyJ`` (base64url of
# ``{"``) — the collision-free side of the decision-6 dispatch.
JWTISH_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature"

CALLER = UserId("usr_" + "c" * 32)
DISABLED_USER = UserId("usr_" + "d" * 32)
ORG = OrganizationId("org_" + "a" * 32)
LIVE_KEY = ApiKeyId("key_" + "a" * 32)
TEST_KEY = ApiKeyId("key_" + "b" * 32)
REVOKED_KEY = ApiKeyId("key_" + "c" * 32)
_T0 = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)
_SCOPES = ["vispector:inspection:run"]


class FakeRequest:
    """Only the surface ``_extract_bearer_token`` reads: the auth header."""

    def __init__(self, authorization: str | None = None) -> None:
        self.headers: dict[str, str] = {}
        if authorization is not None:
            self.headers["authorization"] = authorization


class RecordingVerifier:
    """Token -> claims with a call log: proves what reaches the JWT verifier."""

    def __init__(self) -> None:
        self.claims_by_token: dict[str, CognitoClaims] = {}
        self.verified: list[str] = []

    def verify(self, token: str) -> CognitoClaims:
        self.verified.append(token)
        try:
            return self.claims_by_token[token]
        except KeyError as exc:
            raise TokenValidationError("token failed verification") from exc


class RecordingStorage:
    """Delegates everything to real SQLite; counts/fails the §8 point lookup."""

    def __init__(self, inner: SQLiteStorage) -> None:
        self._inner = inner
        self.key_lookups = 0
        self.fail_key_lookups = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def get_api_key_by_key_id(self, key_id: str) -> ApiKey:
        self.key_lookups += 1
        if self.fail_key_lookups:
            raise StorageError("backend down")
        return self._inner.get_api_key_by_key_id(key_id)


def _claims(sub: str, email: str) -> CognitoClaims:
    return CognitoClaims(
        sub=sub,
        email=email,
        username="dispatch-user",
        client_id="probe-client",
        iss="https://probe.example.test/pool",
        exp=int(_T0.timestamp()) + 3600,
    )


def _api_key(
    *,
    api_key_id: ApiKeyId,
    key_id: str,
    environment: ApiKeyEnvironment,
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE,
) -> ApiKey:
    return ApiKey(
        id=api_key_id,
        organization_id=ORG,
        created_by_user_id=CALLER,
        name="dispatch probe",
        key_id=key_id,
        key_prefix=f"fn_{environment.value}_{key_id}_a8f32x...",
        secret_hash=hash_secret(PEPPER, SECRET),
        environment=environment,
        scopes=list(_SCOPES),
        status=status,
        created_at=_T0,
    )


class DispatchEnv:
    """Real SQLite + recording seams + the built ``current_principal`` dependency."""

    def __init__(self, db_path: Path) -> None:
        self.adapter = SQLiteStorage(db_path)
        self.storage = RecordingStorage(self.adapter)
        self.verifier = RecordingVerifier()
        self.pepper = StaticPepper(PEPPER)
        self.current_principal = build_current_principal(self.storage, self.verifier, self.pepper)
        self._seed()

    def _seed(self) -> None:
        for user_id, sub, email, status in (
            (CALLER, "caller-sub", "caller@example.test", UserStatus.ACTIVE),
            (DISABLED_USER, "disabled-sub", "disabled@example.test", UserStatus.DISABLED),
        ):
            self.adapter.create_user(
                User(
                    id=user_id,
                    display_name=f"seed {user_id}",
                    email=email,
                    status=status,
                    created_at=_T0,
                    updated_at=_T0,
                )
            )
            self.adapter.create_external_identity(
                ExternalIdentity(
                    id=ExternalIdentityId(f"extid_{user_id.removeprefix('usr_')}"),
                    user_id=user_id,
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
                slug="dispatch-org",
                type=OrganizationType.CUSTOMER,
                status=OrganizationStatus.ACTIVE,
                created_at=_T0,
                updated_at=_T0,
            )
        )
        # Anchor membership so the human context resolves (earliest active org).
        self.adapter.create_membership(
            Membership(
                id=MembershipId("mem_anchor"),
                organization_id=ORG,
                user_id=CALLER,
                role=MembershipRole.MEMBER,
                status=MembershipStatus.ACTIVE,
                created_at=_T0,
            )
        )
        self.adapter.create_api_key(
            _api_key(api_key_id=LIVE_KEY, key_id=LIVE_KEY_ID, environment=ApiKeyEnvironment.LIVE)
        )
        self.adapter.create_api_key(
            _api_key(api_key_id=TEST_KEY, key_id=TEST_KEY_ID, environment=ApiKeyEnvironment.TEST)
        )
        self.adapter.create_api_key(
            _api_key(
                api_key_id=REVOKED_KEY,
                key_id=REVOKED_KEY_ID,
                environment=ApiKeyEnvironment.LIVE,
                status=ApiKeyStatus.REVOKED,
            )
        )
        self.verifier.claims_by_token[JWTISH_TOKEN] = _claims("caller-sub", "caller@example.test")
        self.verifier.claims_by_token["tok-disabled"] = _claims(
            "disabled-sub", "disabled@example.test"
        )

    def close(self) -> None:
        self.adapter.close()

    def call(self, authorization: str | None) -> Principal:
        return self.current_principal(FakeRequest(authorization))

    def bearer(self, token: str) -> str:
        return f"Bearer {token}"

    def live_literal(self) -> str:
        return build_literal(ApiKeyEnvironment.LIVE, LIVE_KEY_ID, SECRET)

    def test_literal(self) -> str:
        return build_literal(ApiKeyEnvironment.TEST, TEST_KEY_ID, SECRET)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[DispatchEnv]:
    built = DispatchEnv(tmp_path / "principal_dispatch.sqlite")
    yield built
    built.close()


# ---------------------------------------------------------------------------
# Principal invariant (decision 6)
# ---------------------------------------------------------------------------


def _human_context() -> AuthorizationContext:
    return AuthorizationContext(
        actor_type="user",
        actor_id=CALLER,
        organization_id=ORG,
        roles=[MembershipRole.MEMBER],
        scopes=[],
    )


def test_principal_rejects_no_actor() -> None:
    with pytest.raises(ValueError, match="exactly one actor"):
        Principal(user=None, api_key=None, context=_human_context())


def test_principal_rejects_both_actors() -> None:
    with pytest.raises(ValueError, match="exactly one actor"):
        Principal(
            user=User(
                id=CALLER,
                display_name="x",
                email="x@example.test",
                status=UserStatus.ACTIVE,
                created_at=_T0,
                updated_at=_T0,
            ),
            api_key=_api_key(
                api_key_id=LIVE_KEY, key_id=LIVE_KEY_ID, environment=ApiKeyEnvironment.LIVE
            ),
            context=_human_context(),
        )


def test_principal_invariant_message_carries_no_model_content() -> None:
    """The invariant failure names only which fields were set (no email/leak)."""
    with pytest.raises(ValueError) as excinfo:
        Principal(user=None, api_key=None, context=_human_context())
    assert str(excinfo.value) == (
        "Principal requires exactly one actor set: user=None, api_key=None"
    )


# ---------------------------------------------------------------------------
# Dispatch boundary: eyJ… never parsed as key, fn_… never sent to the verifier
# ---------------------------------------------------------------------------


def test_prefix_constants_are_the_two_environment_literals() -> None:
    assert API_KEY_BEARER_PREFIXES == ("fn_live_", "fn_test_")


def test_human_token_wraps_the_unchanged_phase_03_identity(env: DispatchEnv) -> None:
    principal = env.call(env.bearer(JWTISH_TOKEN))

    assert principal.user is not None
    assert principal.user.id == CALLER
    assert principal.api_key is None
    assert principal.context.actor_type == "user"
    assert principal.context.actor_id == CALLER
    assert principal.context.organization_id == ORG
    assert principal.context.roles == [MembershipRole.MEMBER]
    assert principal.context.scopes == []
    # The JWT verifier ran; the credential seam never saw the token.
    assert env.verifier.verified == [JWTISH_TOKEN]
    assert env.storage.key_lookups == 0


def test_api_key_literal_never_reaches_the_jwt_verifier(env: DispatchEnv) -> None:
    principal = env.call(env.bearer(env.live_literal()))

    assert principal.user is None
    assert principal.api_key is not None
    assert principal.api_key.id == LIVE_KEY
    assert principal.context.actor_type == "api_key"
    assert principal.context.actor_id == LIVE_KEY
    assert principal.context.organization_id == ORG
    assert principal.context.roles == []
    assert principal.context.scopes == _SCOPES
    assert env.verifier.verified == []  # fn_ literal never sent to the JWT verifier
    assert env.storage.key_lookups == 1


def test_test_environment_prefix_also_dispatches_to_the_key_path(env: DispatchEnv) -> None:
    principal = env.call(env.bearer(env.test_literal()))

    assert principal.api_key is not None
    assert principal.api_key.id == TEST_KEY
    assert principal.api_key.environment is ApiKeyEnvironment.TEST
    assert env.verifier.verified == []


# ---------------------------------------------------------------------------
# API-key failures: the one uniform 401 (decision 4)
# ---------------------------------------------------------------------------


def _assert_uniform_401(excinfo: pytest.ExceptionInfo[HTTPException]) -> None:
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == API_KEY_AUTHENTICATION_MESSAGE


def test_revoked_key_is_the_uniform_401(env: DispatchEnv) -> None:
    literal = build_literal(ApiKeyEnvironment.LIVE, REVOKED_KEY_ID, SECRET)
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer(literal))
    _assert_uniform_401(excinfo)
    assert env.verifier.verified == []


def test_unknown_key_is_the_uniform_401(env: DispatchEnv) -> None:
    literal = build_literal(ApiKeyEnvironment.LIVE, "01JXYZ7KA20MB63PCQ8VNDWFT9", SECRET)
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer(literal))
    _assert_uniform_401(excinfo)


def test_malformed_fn_literal_is_the_uniform_401(env: DispatchEnv) -> None:
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer("fn_live_short_secret"))
    _assert_uniform_401(excinfo)
    # Format failure precedes any storage read (decision 4 step (a)).
    assert env.storage.key_lookups == 0


def test_wrong_secret_is_the_uniform_401(env: DispatchEnv) -> None:
    literal = build_literal(ApiKeyEnvironment.LIVE, LIVE_KEY_ID, SECRET[:-1] + "Z")
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer(literal))
    _assert_uniform_401(excinfo)


def test_key_backend_outage_propagates_untranslated(env: DispatchEnv) -> None:
    """Decision 11: a StorageError on the key branch is never a 401."""
    env.storage.fail_key_lookups = True
    with pytest.raises(StorageError):
        env.call(env.bearer(env.live_literal()))


# ---------------------------------------------------------------------------
# Human-path mapping is preserved exactly (Phase 03 regression)
# ---------------------------------------------------------------------------


def test_missing_header_fails_before_any_dispatch(env: DispatchEnv) -> None:
    with pytest.raises(HTTPException) as excinfo:
        env.call(None)
    assert excinfo.value.status_code == 401
    assert env.verifier.verified == []
    assert env.storage.key_lookups == 0


def test_unverifiable_jwt_token_still_401(env: DispatchEnv) -> None:
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer("eyJunknown.unverified.token"))
    assert excinfo.value.status_code == 401
    assert env.verifier.verified == ["eyJunknown.unverified.token"]


def test_disabled_user_still_maps_to_403(env: DispatchEnv) -> None:
    with pytest.raises(HTTPException) as excinfo:
        env.call(env.bearer("tok-disabled"))
    assert excinfo.value.status_code == 403
    assert env.storage.key_lookups == 0
