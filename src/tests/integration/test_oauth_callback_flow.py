"""Integration proofs for ``GET /oauth/callback`` (Phase 11 breakdown task 12).

Full journey on the real stack minus live Cognito: a loopback JWKS server
signs real RS256 tokens, the real :class:`~app.auth.cognito.CognitoAccessTokenVerifier`
and SQLite storage back the flow, and doubles stand in for the token
endpoint and the user-info profile source. The task-12 mapping table is the
contract, so every branch is pinned:

- (a) provider ``error`` / missing ``code``/``state`` → 401, provider text
  never echoed, login state never consumed;
- (b) unknown / expired / replayed state → 401 fixed message;
- (c) exchange failure → 503 before the verifier is reached;
- (d) token validation failure → 401, JWKS outage → 503, zero user-table
  writes either way;
- (e) profile subject/verification/shape failure → 401, outage → 503;
- (f) disabled user → 403; a different ``sub`` sharing an existing user's
  email provisions a second, independent user (Phase 12), never a 409;
- (g) success → 302 to the stored return URL with the ``feednow_session``
  cookie (``HttpOnly; SameSite=Lax; Path=/``; ``Secure`` caller-controlled),
  and a withdrawn return origin → 400 with **no** session issued.

Mocked native and Google-federated journeys are covered, plus the secrecy
sweep: code, state, verifier, tokens, and email appear in no log record,
error envelope, or redirect target.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.oauth import (
    CALLBACK_PATH,
    LOGIN_PATH,
    LOGIN_STATE_INVALID_MESSAGE,
    PROVIDER_REJECTED_MESSAGE,
    RETURN_URL_REJECTED_MESSAGE,
    build_oauth_router,
)
from app.auth.cognito import CognitoAccessTokenVerifier, CognitoProfile
from app.auth.errors import TokenProviderUnavailableError
from app.auth.jwks import CognitoJwksSource
from app.auth.session import SESSION_COOKIE_NAME, SessionManager
from app.main import create_app
from app.models.enums import IdentityProvider, UserStatus
from app.models.errors import Error
from app.models.external_identity import ExternalIdentity
from app.models.ids import ExternalIdentityId, UserId
from app.models.session import OAuthLoginState
from app.models.timestamps import utc_now
from app.models.user import User
from app.storage.sqlite import open_sqlite_storage

AUTHORIZE_URL = "https://auth.example.test/oauth2/authorize"
REDIRECT_URI = "https://app.example.test/oauth/callback"
ALLOWED_CLIENT = "callback-flow-client"
LANDING_URL = "https://app.example.test/home"
ALLOWED_ORIGINS = ("https://app.example.test",)

NATIVE_SUB = "callback-native-sub"
NATIVE_EMAIL = "native@example.test"
GOOGLE_SUB = "google-federated-sub"
GOOGLE_EMAIL = "google@example.test"
RETURN_URL = "/dashboard"

# Unmistakable sentinels for the secrecy sweep (never echoed anywhere).
TEST_CODE = "one-time-code-NEVER-ECHO"


class RecordingStorage:
    """Delegating wrapper counting every storage call (mutation-proof oracle)."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(name)
            return attr(*args, **kwargs)

        return wrapper


class FakeTokenEndpoint:
    """Token-exchange double: records the (code, redirect_uri, verifier)
    triple it receives and answers with a canned token or a canned failure."""

    def __init__(self) -> None:
        self.token: str | None = None
        self.error: Exception | None = None
        self.calls: list[tuple[str, str, str]] = []

    def exchange(self, code: str, redirect_uri: str, code_verifier: str) -> str:
        self.calls.append((code, redirect_uri, code_verifier))
        if self.error is not None:
            raise self.error
        assert self.token is not None, "test forgot to wire the provider's token"
        return self.token


class FakeProfileSource:
    """User-info double: canned verified profiles keyed by ``expected_sub``."""

    def __init__(self) -> None:
        self.profiles: dict[str, CognitoProfile] = {}
        self.error: Exception | None = None
        self.fetched_subjects: list[str] = []

    def fetch(self, access_token: str, expected_sub: str) -> CognitoProfile:
        assert access_token  # the route must forward the exchanged token
        self.fetched_subjects.append(expected_sub)
        if self.error is not None:
            raise self.error
        return self.profiles[expected_sub]


class _SilenceLogger(logging.Filter):
    """Drop records from one named logger (the *client-side* httpx echo)."""

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def filter(self, record: logging.LogRecord) -> bool:
        return record.name != self._name


class _Env:
    """One assembled journey environment: server, storage, doubles, client."""

    def __init__(
        self,
        db_path: Path,
        server: JwksTestServer,
        key: TestKey,
        *,
        allowed_origins: tuple[str, ...] = ALLOWED_ORIGINS,
        cookie_secure: bool = False,
    ) -> None:
        self.db_path = db_path
        self.server = server
        self.key = key
        self.issuer = server.issuer("pool-a")
        self.storage = RecordingStorage(open_sqlite_storage(db_path))
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([self.issuer]),
            allowed_issuers=[self.issuer],
            allowed_client_ids=[ALLOWED_CLIENT],
        )
        self.token_endpoint = FakeTokenEndpoint()
        self.profile_source = FakeProfileSource()
        self.sessions = SessionManager(self.storage)
        router = build_oauth_router(
            self.storage,
            verifier,
            self.token_endpoint,
            self.profile_source,
            self.sessions,
            authorize_url=AUTHORIZE_URL,
            client_id=ALLOWED_CLIENT,
            redirect_uri=REDIRECT_URI,
            landing_url=LANDING_URL,
            allowed_return_origins=allowed_origins,
            cookie_secure=cookie_secure,
        )
        self.client = TestClient(create_app(routers=[router]), raise_server_exceptions=False)

    # -- journey helpers ------------------------------------------------------

    def start_login(self, next_value: str = RETURN_URL) -> str:
        response = self.client.get(f"{LOGIN_PATH}?next={next_value}", follow_redirects=False)
        assert response.status_code == 302
        query = parse_qs(urlsplit(response.headers["location"]).query)
        return query["state"][0]

    def callback(self, state: str, *, code: str = TEST_CODE) -> Any:
        return self.client.get(f"{CALLBACK_PATH}?code={code}&state={state}", follow_redirects=False)

    def peek_state(self, state_id: str) -> sqlite3.Row | None:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(
                "SELECT * FROM oauth_login_states WHERE state_id = ?", (state_id,)
            ).fetchone()
        finally:
            conn.close()

    def access_token(self, sub: str = NATIVE_SUB, *, exp_offset: int = 3600) -> str:
        now = int(time.time())
        return sign_token(
            {
                "sub": sub,
                "username": f"user-{sub}",
                "client_id": ALLOWED_CLIENT,
                "iss": self.issuer,
                "token_use": "access",
                "exp": now + exp_offset,
                "iat": now,
            },
            kid=self.key.kid,
            key=self.key,
        )

    def seed_user(
        self,
        user_id: str,
        sub: str,
        email: str,
        status: UserStatus = UserStatus.ACTIVE,
    ) -> None:
        self.storage.create_user(
            User(
                id=UserId(user_id),
                display_name=f"seed {user_id}",
                email=email,
                status=status,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
        )
        self.storage.create_external_identity(
            ExternalIdentity(
                id=ExternalIdentityId(f"extid_{user_id.removeprefix('usr_')}"),
                user_id=UserId(user_id),
                provider=IdentityProvider.COGNITO,
                provider_subject=sub,
                provider_tenant=None,
                created_at=utc_now(),
            )
        )

    def table_rows(self, table: str) -> list[sqlite3.Row]:
        assert table in {"users", "app_sessions", "oauth_login_states"}  # fixed test tables
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(f"SELECT * FROM {table}").fetchall()
        finally:
            conn.close()

    def close(self) -> None:
        self.storage._inner.close()


def _profile(
    sub: str, email: str | None, *, verified: bool = True, display_name: str | None = None
) -> CognitoProfile:
    return CognitoProfile(sub=sub, email=email, email_verified=verified, display_name=display_name)


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("callback-flow-key")


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_Env]:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _Env(tmp_path / "flow.sqlite", server, key)
        yield built
        built.close()


def _wire_native(env: _Env) -> str:
    """Point the doubles at the standard native-user journey; return the token."""
    token = env.access_token()
    env.token_endpoint.token = token
    env.profile_source.profiles[NATIVE_SUB] = _profile(NATIVE_SUB, NATIVE_EMAIL)
    return token


# ---------------------------------------------------------------------------
# (g) success journeys
# ---------------------------------------------------------------------------


def test_native_journey_provisions_issues_session_and_redirects(env: _Env) -> None:
    state = env.start_login()
    row = env.peek_state(state)
    assert row is not None
    token = _wire_native(env)

    response = env.callback(state)

    assert response.status_code == 302
    assert response.headers["location"] == RETURN_URL
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE_NAME}=")
    assert "Max-Age=1800" in cookie
    assert "Path=/" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert "Secure" not in cookie  # local default until task 13 pins it

    # PKCE binding: the exchange received exactly the stored verifier and the
    # configured redirect URI.
    assert env.token_endpoint.calls == [(TEST_CODE, REDIRECT_URI, row["code_verifier"])]
    assert env.profile_source.fetched_subjects == [NATIVE_SUB]

    # The user was provisioned from the verified profile (email) with the
    # claims username fallback for the display name.
    users = env.table_rows("users")
    assert len(users) == 1
    assert users[0]["email"] == NATIVE_EMAIL
    assert users[0]["display_name"] == f"user-{NATIVE_SUB}"

    # The cookie maps to a live session for exactly that user.
    session_id = cookie.split(";")[0].split("=", 1)[1]
    stored = env.storage.get_app_session(session_id)
    assert stored is not None
    assert str(stored.user_id) == users[0]["id"]

    # Single-use state: consumed by the winning callback.
    assert env.peek_state(state) is None

    # No flow material in the redirect response.
    for material in (TEST_CODE, row["code_verifier"], token, NATIVE_EMAIL):
        assert material not in response.text
        assert material not in response.headers["location"]


def test_google_federated_journey_uses_profile_display_name(env: _Env) -> None:
    state = env.start_login()
    token = env.access_token(GOOGLE_SUB)
    env.token_endpoint.token = token
    env.profile_source.profiles[GOOGLE_SUB] = _profile(
        GOOGLE_SUB, GOOGLE_EMAIL, display_name="Google User"
    )

    response = env.callback(state)

    assert response.status_code == 302
    users = env.table_rows("users")
    assert len(users) == 1
    assert users[0]["email"] == GOOGLE_EMAIL
    assert users[0]["display_name"] == "Google User"


def test_returning_user_receives_a_session_without_reprovisioning(env: _Env) -> None:
    _wire_native(env)
    first = env.callback(env.start_login())
    assert first.status_code == 302

    second = env.callback(env.start_login())

    assert second.status_code == 302
    assert env.storage.calls.count("provision_user") == 1  # exactly once ever
    assert len(env.table_rows("users")) == 1
    assert len(env.table_rows("app_sessions")) == 2  # one session per journey


def test_secure_cookie_flag_follows_deployment_config(tmp_path: Path, key: TestKey) -> None:
    with JwksTestServer({"pool-a": [key]}) as server:
        built = _Env(tmp_path / "secure.sqlite", server, key, cookie_secure=True)
        try:
            _wire_native(built)
            response = built.callback(built.start_login())
            assert "Secure" in response.headers["set-cookie"]
        finally:
            built.close()


# ---------------------------------------------------------------------------
# (a) provider redirect failures
# ---------------------------------------------------------------------------


def test_provider_error_parameter_is_401_and_never_consumes_the_state(env: _Env) -> None:
    state = env.start_login()

    response = env.client.get(
        f"{CALLBACK_PATH}?error=access_denied&error_description=PROVIDER-TEXT-{TEST_CODE}"
        f"&code={TEST_CODE}&state={state}",
        follow_redirects=False,
    )

    assert response.status_code == 401
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
    assert envelope.message == PROVIDER_REJECTED_MESSAGE
    # Provider text and the request's own material are never echoed.
    assert "PROVIDER-TEXT" not in response.text
    assert "access_denied" not in response.text
    assert TEST_CODE not in response.text
    # (a) precedes (b): the login state is untouched.
    assert "consume_oauth_login_state" not in env.storage.calls
    assert env.peek_state(state) is not None


@pytest.mark.parametrize(
    "query",
    [
        "",
        f"code={TEST_CODE}",
        f"state={'s' * 43}",
        f"code=&state={'s' * 43}",
    ],
)
def test_missing_code_or_state_is_401(env: _Env, query: str) -> None:
    response = env.client.get(f"{CALLBACK_PATH}?{query}", follow_redirects=False)

    assert response.status_code == 401
    assert Error.model_validate(response.json()).message == PROVIDER_REJECTED_MESSAGE
    assert env.storage.calls == []


# ---------------------------------------------------------------------------
# (b) login-state failures
# ---------------------------------------------------------------------------


def test_unknown_state_is_401(env: _Env) -> None:
    response = env.callback("never-minted-state-id-0000000000000000000")

    assert response.status_code == 401
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
    assert envelope.message == LOGIN_STATE_INVALID_MESSAGE
    assert env.token_endpoint.calls == []


def test_replayed_state_is_401(env: _Env) -> None:
    _wire_native(env)
    state = env.start_login()
    assert env.callback(state).status_code == 302

    replay = env.callback(state)

    assert replay.status_code == 401
    assert Error.model_validate(replay.json()).message == LOGIN_STATE_INVALID_MESSAGE
    assert len(env.token_endpoint.calls) == 1  # the replay never reached the exchange


def test_expired_state_is_401(env: _Env) -> None:
    env.storage.save_oauth_login_state(
        OAuthLoginState(
            state_id="expired-state-id-00000000000000000000000",
            code_verifier="v" * 96,
            return_url=RETURN_URL,
            expires_at=utc_now() - timedelta(seconds=5),
        )
    )

    response = env.callback("expired-state-id-00000000000000000000000")

    assert response.status_code == 401
    assert Error.model_validate(response.json()).message == LOGIN_STATE_INVALID_MESSAGE
    assert env.token_endpoint.calls == []


# ---------------------------------------------------------------------------
# (c) exchange failure
# ---------------------------------------------------------------------------


def test_exchange_failure_is_503_before_any_verification_or_user_write(env: _Env) -> None:
    state = env.start_login()
    env.token_endpoint.error = TokenProviderUnavailableError("token endpoint is down")

    response = env.callback(state)

    assert response.status_code == 503
    assert Error.model_validate(response.json()).code == "internal_error"
    assert TEST_CODE not in response.text
    # The verifier was never reached: zero JWKS traffic, zero user-table work.
    assert env.server.requests_for("pool-a") == 0
    assert "get_user_by_external_identity" not in env.storage.calls
    assert "provision_user" not in env.storage.calls


# ---------------------------------------------------------------------------
# (d) token validation failures
# ---------------------------------------------------------------------------


def test_garbage_access_token_is_401_without_user_storage_touches(env: _Env) -> None:
    state = env.start_login()
    env.token_endpoint.token = "not.a.jwt"

    response = env.callback(state)

    assert response.status_code == 401
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
    assert "not.a.jwt" not in response.text
    assert "get_user_by_external_identity" not in env.storage.calls
    assert "provision_user" not in env.storage.calls


@pytest.mark.parametrize(
    ("sub", "issuer", "exp_offset"),
    [
        (NATIVE_SUB, None, -120),  # expired beyond the 60s leeway
        ("other-issuer-sub", "https://foreign.example.test/pool", 3600),  # wrong issuer
    ],
)
def test_rejected_access_tokens_are_401(
    env: _Env, sub: str, issuer: str | None, exp_offset: int
) -> None:
    state = env.start_login()
    if issuer is None:
        token = env.access_token(sub, exp_offset=exp_offset)
    else:
        now = int(time.time())
        token = sign_token(
            {
                "sub": sub,
                "username": "x",
                "client_id": ALLOWED_CLIENT,
                "iss": issuer,
                "token_use": "access",
                "exp": now + exp_offset,
                "iat": now,
            },
            kid=env.key.kid,
            key=env.key,
        )
    env.token_endpoint.token = token

    response = env.callback(state)

    assert response.status_code == 401
    assert Error.model_validate(response.json()).code == "unauthenticated"
    assert token not in response.text
    assert "provision_user" not in env.storage.calls


def test_jwks_outage_is_503(env: _Env) -> None:
    state = env.start_login()
    env.token_endpoint.token = env.access_token()
    env.server.stop()  # provider outage between exchange and verification

    response = env.callback(state)

    assert response.status_code == 503
    assert Error.model_validate(response.json()).code == "internal_error"
    assert "provision_user" not in env.storage.calls
    assert env.profile_source.fetched_subjects == []  # 503 precedes profile work


# ---------------------------------------------------------------------------
# (e) profile failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("profile", "reason"),
    [
        (_profile("stranger-sub", NATIVE_EMAIL), "profile subject does not match the token"),
        (_profile(NATIVE_SUB, NATIVE_EMAIL, verified=False), "profile email is not verified"),
        (_profile(NATIVE_SUB, None), "profile is missing the email claim"),
    ],
)
def test_profile_gate_failures_are_401_before_resolution(
    env: _Env, profile: CognitoProfile, reason: str
) -> None:
    state = env.start_login()
    env.token_endpoint.token = env.access_token()
    env.profile_source.profiles[NATIVE_SUB] = profile

    response = env.callback(state)

    assert response.status_code == 401
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
    assert envelope.message == reason
    # The identity-tuple read decides whether profile fetching is needed; the
    # invalid profile must prevent the first-user provisioning batch.
    assert "get_user_by_external_identity" in env.storage.calls
    assert "provision_user" not in env.storage.calls


def test_profile_outage_is_503(env: _Env) -> None:
    state = env.start_login()
    env.token_endpoint.token = env.access_token()
    env.profile_source.error = TokenProviderUnavailableError(
        "profile endpoint could not be reached"
    )

    response = env.callback(state)

    assert response.status_code == 503
    assert Error.model_validate(response.json()).code == "internal_error"
    assert "provision_user" not in env.storage.calls


# ---------------------------------------------------------------------------
# (f) identity resolution: disabled stays 403; a shared email coexists (12)
# ---------------------------------------------------------------------------


def test_disabled_user_is_403(env: _Env) -> None:
    env.seed_user("usr_disabled_cb", NATIVE_SUB, "seed@example.test", status=UserStatus.DISABLED)
    _wire_native(env)
    state = env.start_login()

    response = env.callback(state)

    assert response.status_code == 403
    envelope = Error.model_validate(response.json())
    assert envelope.code == "forbidden"
    assert envelope.message == "user account is disabled"
    assert env.storage.calls.count("provision_user") == 0
    assert env.storage.calls.count("create_app_session") == 0


def test_email_coexistence_provisions_second_user(env: _Env) -> None:
    """Phase 12: a stranger already owns this email under a different sub.
    The callback no longer 409s — the new sub provisions its own user
    through one full batch and receives a session; the identity tuple, not
    the email, is the convergence key, and the stranger is untouched."""
    env.seed_user("usr_stranger_cb", "stranger-sub", NATIVE_EMAIL)
    state = env.start_login()
    env.token_endpoint.token = env.access_token("collision-sub")
    env.profile_source.profiles["collision-sub"] = _profile("collision-sub", NATIVE_EMAIL)

    response = env.callback(state)

    assert response.status_code == 302
    assert response.headers["location"] == RETURN_URL
    assert env.storage.calls.count("provision_user") == 1  # one full batch
    assert env.storage.calls.count("create_organization") == 0  # not standalone
    users = env.table_rows("users")
    assert len(users) == 2  # the seeded stranger and the new shadow user
    assert {row["email"] for row in users} == {NATIVE_EMAIL}
    assert env.table_rows("app_sessions")  # the new user got its own session
    stranger = env.storage.get_user(UserId("usr_stranger_cb"))
    assert stranger.display_name == "seed usr_stranger_cb"  # never merged/overwritten


# ---------------------------------------------------------------------------
# (g) return-target re-validation
# ---------------------------------------------------------------------------


def test_withdrawn_return_origin_is_400_and_issues_no_session(env: _Env) -> None:
    # A state saved while the origin was allow-listed, now out of policy.
    state_id = "withdrawn-origin-state-id-0000000000000000"
    env.storage.save_oauth_login_state(
        OAuthLoginState(
            state_id=state_id,
            code_verifier="v" * 96,
            return_url="https://withdrawn.example/x",
            expires_at=utc_now() + timedelta(seconds=600),
        )
    )
    _wire_native(env)

    response = env.callback(state_id)

    assert response.status_code == 400
    envelope = Error.model_validate(response.json())
    assert envelope.code == "validation_error"
    assert envelope.message == RETURN_URL_REJECTED_MESSAGE
    assert "withdrawn.example" not in response.text
    assert env.storage.calls.count("create_app_session") == 0
    assert env.table_rows("app_sessions") == []


# ---------------------------------------------------------------------------
# Secrecy sweep (acceptance: token/code/state/verifier/email hygiene)
# ---------------------------------------------------------------------------


def test_flow_material_appears_in_no_log_record_or_response(
    env: _Env, caplog: pytest.LogCaptureFixture
) -> None:
    state = env.start_login()
    row = env.peek_state(state)
    assert row is not None
    token = _wire_native(env)

    with caplog.at_level(logging.INFO), caplog.filtering(_SilenceLogger("httpx")):
        success = env.callback(state)
        failure = env.callback(state)  # replay branch

    assert success.status_code == 302
    assert failure.status_code == 401
    materials = (TEST_CODE, state, row["code_verifier"], token, NATIVE_EMAIL)
    for record in caplog.records:
        message = record.getMessage()
        for material in materials:
            assert material not in message
    joined = "\n".join(record.getMessage() for record in caplog.records)
    for material in materials:
        assert material not in joined
        assert material not in success.text
        assert material not in failure.text
