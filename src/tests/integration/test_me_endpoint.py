"""Integration tests for ``GET /v1/me`` (Phase 03 task 5).

Full stack, no live Cognito pool (acceptance criterion 5): the loopback JWKS
test server signs real RS256 tokens, real SQLite persists the provisioning
batch, and ``TestClient(create_app(routers=[build_me_router(...)]))`` drives
the frozen Phase 01 envelope. Acceptance mapping:

- each 401 variant (missing/malformed header, expired, wrong issuer, wrong
  client, ``token_use=id``, garbage token, forged signature) asserts **zero
  calls** on a recording storage wrapper — "rejected without storage mutation";
- named non-401 cases: ``test_disabled_user_403``,
  ``test_email_coexistence_provisions_second_user`` (Phase 12: a shared
  email provisions a second user, it no longer 409s), ``test_jwks_down_503``
  — all seeded with existing create methods only;
- the happy path returns ``usr_``/profile fields and the body carries no
  ``sub``, no ``client_id``, no token bytes; repeated requests provision
  exactly once; every error body validates against the frozen ``Error`` model.

Phase 11 (tasks 4/5): first-login provisioning reads the email from the
verified user-info profile, so the environment wires a fake
:class:`~app.auth.cognito.ProfileSource`; named tests prove the hit path
makes **zero** user-info requests, the profile email (not the claims email)
lands on the created user, and a bearer-only first login with no profile
source is refused 401 without touching storage.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.me import build_me_router
from app.auth.cognito import CognitoAccessTokenVerifier, CognitoProfile
from app.auth.errors import TokenProviderUnavailableError
from app.auth.jwks import CognitoJwksSource
from app.main import create_app
from app.models.enums import IdentityProvider, UserStatus
from app.models.errors import Error
from app.models.external_identity import ExternalIdentity
from app.models.ids import ExternalIdentityId, UserId
from app.models.timestamps import utc_now
from app.models.user import User
from app.storage.contract import Storage
from app.storage.sqlite import open_sqlite_storage

ALLOWED_CLIENT = "me-app-client"
SUBJECT = "me-subject-1"
EMAIL = "me-user@example.test"


class RecordingStorage:
    """Delegating wrapper counting every storage call (mutation-proof oracle)."""

    def __init__(self, inner: Storage) -> None:
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

    @property
    def total_calls(self) -> int:
        return len(self.calls)


class FakeProfileSource:
    """In-process user-info double: canned verified profile per subject.

    Records only the ``expected_sub`` of each fetch (never token material),
    so tests can prove the hit path performs zero user-info requests.
    """

    def __init__(self, emails: dict[str, str]) -> None:
        self.emails = emails
        self.fetched_subjects: list[str] = []

    def fetch(self, access_token: str, expected_sub: str) -> CognitoProfile:
        assert access_token  # the chain must forward the raw bearer token
        self.fetched_subjects.append(expected_sub)
        return CognitoProfile(
            sub=expected_sub,
            email=self.emails[expected_sub],
            email_verified=True,
            display_name=None,
        )


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("me-pool-key-1")


class _Env:
    """One assembled test environment: server, storage, client, signing key."""

    def __init__(
        self,
        server: JwksTestServer,
        storage: RecordingStorage,
        client: TestClient,
        key: TestKey,
        profile_source: FakeProfileSource,
    ) -> None:
        self.server = server
        self.storage = storage
        self.client = client
        self.key = key
        self.profile_source = profile_source

    @property
    def issuer(self) -> str:
        return self.server.issuer("pool-a")

    def token(
        self,
        *,
        sub: str = SUBJECT,
        email: str = EMAIL,
        client_id: str = ALLOWED_CLIENT,
        issuer: str | None = None,
        token_use: str = "access",
        exp_offset: int = 3600,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub,
            "email": email,
            "username": "me-user",
            "client_id": client_id,
            "iss": issuer if issuer is not None else self.issuer,
            "token_use": token_use,
            "exp": now + exp_offset,
            "iat": now,
        }
        return sign_token(claims, kid=self.key.kid, key=self.key)

    def auth(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}


def _build_env(tmp_path: Path, key: TestKey, server: JwksTestServer) -> _Env:
    issuer = server.issuer("pool-a")
    verifier = CognitoAccessTokenVerifier(
        CognitoJwksSource([issuer]),
        allowed_issuers=[issuer],
        allowed_client_ids=[ALLOWED_CLIENT],
    )
    storage = RecordingStorage(open_sqlite_storage(tmp_path / "me.sqlite"))
    profile_source = FakeProfileSource({SUBJECT: EMAIL})
    router = build_me_router(storage, verifier, profile_source=profile_source)
    client = TestClient(create_app(routers=[router]), raise_server_exceptions=False)
    return _Env(server, storage, client, key, profile_source)


@pytest.fixture
def env(tmp_path: Path, key: TestKey) -> Iterator[_Env]:
    with JwksTestServer({"pool-a": [key]}) as server:
        yield _build_env(tmp_path, key, server)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_me_provisions_once_and_returns_internal_identity(env: _Env) -> None:
    response = env.client.get("/v1/me", headers=env.auth(env.token()))

    assert response.status_code == 200
    body = response.json()
    assert body["id"].startswith("usr_")
    assert body["display_name"] == "me-user"
    assert body["email"] == EMAIL
    assert body["status"] == "active"
    # Phase 12: a first-provisioned user projects the USER application role
    # (the model default is the only reachable value pre-persistence).
    assert body["application_role"] == "user"
    assert {
        "id",
        "display_name",
        "email",
        "status",
        "application_role",
        "created_at",
        "updated_at",
    } == set(body)

    # No provider material anywhere in the response (AGENTS.md / acceptance 4).
    serialized = json.dumps(body)
    assert SUBJECT not in serialized
    assert ALLOWED_CLIENT not in serialized
    assert env.token() not in serialized
    assert "cognito" not in serialized.lower()
    # Phase 12: the role is internal vocabulary — no provider identity keys
    # (``sub``, provider names, external-identity material) ride along.
    assert not {"sub", "provider", "provider_subject", "external_identities"} & set(body)

    # Exactly one provisioning write; repeat requests converge on the same user.
    assert env.storage.calls.count("provision_user") == 1
    assert env.profile_source.fetched_subjects == [SUBJECT]  # one user-info fetch
    second = env.client.get("/v1/me", headers=env.auth(env.token()))
    assert second.status_code == 200
    assert second.json()["id"] == body["id"]
    assert env.storage.calls.count("provision_user") == 1  # still exactly once
    assert env.storage.calls.count("get_user_by_external_identity") == 2  # hit path
    assert env.profile_source.fetched_subjects == [SUBJECT]  # zero fetches on the hit


def test_first_login_provisions_with_profile_email_not_claims_email(env: _Env) -> None:
    """Phase 11 task 4/5: the stored email comes from the verified user-info
    profile; the access-token ``email`` claim is never used for creation."""
    env.profile_source.emails["profile-wins-sub"] = "profile@example.test"
    token = env.token(sub="profile-wins-sub", email="claims-only@example.test")

    response = env.client.get("/v1/me", headers=env.auth(token))

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "profile@example.test"
    # display_name: profile has none → falls back to the claims username.
    assert body["display_name"] == "me-user"
    assert env.profile_source.fetched_subjects == ["profile-wins-sub"]


def test_first_login_user_info_outage_is_503_without_provisioning(
    tmp_path: Path, key: TestKey
) -> None:
    """A provider outage on the miss path is the published **503** (same
    vocabulary as a JWKS outage), never a bare 500, and never a write."""

    class _DownProfileSource:
        def fetch(self, access_token: str, expected_sub: str) -> CognitoProfile:
            raise TokenProviderUnavailableError("profile endpoint could not be reached")

    with JwksTestServer({"pool-a": [key]}) as server:
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[ALLOWED_CLIENT],
        )
        storage = RecordingStorage(open_sqlite_storage(tmp_path / "outage.sqlite"))
        router = build_me_router(storage, verifier, profile_source=_DownProfileSource())
        client = TestClient(create_app(routers=[router]), raise_server_exceptions=False)
        now = int(time.time())
        token = sign_token(
            {
                "sub": SUBJECT,
                "username": "me-user",
                "client_id": ALLOWED_CLIENT,
                "iss": issuer,
                "token_use": "access",
                "exp": now + 3600,
                "iat": now,
            },
            kid=key.kid,
            key=key,
        )

        response = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 503
        assert Error.model_validate(response.json()).code == "internal_error"
        assert storage.calls.count("provision_user") == 0  # outage never writes
        assert token not in response.text


def test_first_login_without_profile_source_is_401(tmp_path: Path, key: TestKey) -> None:
    """Task 5's rollback shape: with no user-info configuration a bearer-only
    first login is refused 401 with zero writes (never provisioned from
    claims)."""
    with JwksTestServer({"pool-a": [key]}) as server:
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[ALLOWED_CLIENT],
        )
        storage = RecordingStorage(open_sqlite_storage(tmp_path / "no-source.sqlite"))
        client = TestClient(
            create_app(routers=[build_me_router(storage, verifier)]),
            raise_server_exceptions=False,
        )
        now = int(time.time())
        token = sign_token(
            {
                "sub": SUBJECT,
                "username": "me-user",
                "client_id": ALLOWED_CLIENT,
                "iss": issuer,
                "token_use": "access",
                "exp": now + 3600,
                "iat": now,
            },
            kid=key.kid,
            key=key,
        )

        response = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 401
        assert Error.model_validate(response.json()).code == "unauthenticated"
        # The refusal happens on the miss path: one identity read, zero writes.
        assert storage.calls.count("get_user_by_external_identity") == 1
        assert storage.calls.count("provision_user") == 0
        assert "cognito.invalid" not in response.text


# ---------------------------------------------------------------------------
# 401 variants: rejected without storage mutation
# ---------------------------------------------------------------------------


def _expect_401(env: _Env, headers: dict[str, str] | None, token: str | None = None) -> None:
    response = env.client.get("/v1/me", headers=headers or {})
    assert response.status_code == 401, response.text
    envelope = Error.model_validate(response.json())
    assert envelope.code == "unauthenticated"
    assert env.storage.total_calls == 0  # acceptance: rejection never touches storage
    if token is not None:
        assert token not in response.text  # no token material in the message


def test_missing_header_401(env: _Env) -> None:
    _expect_401(env, None)


def test_non_bearer_scheme_401(env: _Env) -> None:
    _expect_401(env, {"Authorization": "Basic dXNlcjpwYXNz"})


def test_empty_bearer_credential_401(env: _Env) -> None:
    _expect_401(env, {"Authorization": "Bearer "})


def test_bearer_with_trailing_garbage_401(env: _Env) -> None:
    token = env.token()
    _expect_401(env, {"Authorization": f"bearer {token} extra"}, token)


def test_lowercase_scheme_is_accepted(env: _Env) -> None:
    """Scheme matching is case-insensitive; this must NOT be a 401."""
    response = env.client.get("/v1/me", headers={"Authorization": f"bearer {env.token()}"})
    assert response.status_code == 200


def test_garbage_token_401(env: _Env) -> None:
    _expect_401(env, env.auth("not.a.jwt"), "not.a.jwt")


def test_expired_token_401(env: _Env) -> None:
    token = env.token(exp_offset=-120)  # beyond the 60s leeway
    _expect_401(env, env.auth(token), token)


def test_wrong_issuer_401(env: _Env) -> None:
    token = env.token(issuer="https://evil.example.com/pool")
    _expect_401(env, env.auth(token), token)


def test_prefix_spoofed_issuer_401(env: _Env) -> None:
    token = env.token(issuer=f"{env.issuer}-evil")
    _expect_401(env, env.auth(token), token)


def test_wrong_client_401(env: _Env) -> None:
    token = env.token(client_id="other-client")
    _expect_401(env, env.auth(token), token)


def test_id_token_use_401(env: _Env) -> None:
    token = env.token(token_use="id")
    _expect_401(env, env.auth(token), token)


def test_forged_signature_401(tmp_path: Path, key: TestKey) -> None:
    """A token signed by a *different* RSA key under the same kid passes the
    issuer/kid stages and fails at the signature — still zero storage calls."""
    forged_key = generate_test_key(key.kid)  # same kid, different key material
    with JwksTestServer({"pool-a": [key]}) as server:  # server publishes the real key
        env = _build_env(tmp_path, forged_key, server)
        _expect_401(env, env.auth(env.token()), env.token())


# ---------------------------------------------------------------------------
# Named non-401 outcomes
# ---------------------------------------------------------------------------


def test_disabled_user_403(env: _Env) -> None:
    """Seed a disabled user + identity directly (create-only methods)."""
    env.storage.create_user(
        User(
            id=UserId("usr_disabled_me"),
            display_name="Disabled",
            email="other@example.test",
            status=UserStatus.DISABLED,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
    )
    env.storage.create_external_identity(
        ExternalIdentity(
            id=ExternalIdentityId("extid_disabled_me"),
            user_id=UserId("usr_disabled_me"),
            provider=IdentityProvider.COGNITO,
            provider_subject=SUBJECT,
            provider_tenant=None,
            created_at=utc_now(),
        )
    )
    response = env.client.get("/v1/me", headers=env.auth(env.token(email="other@example.test")))

    assert response.status_code == 403
    assert Error.model_validate(response.json()).code == "forbidden"
    assert env.storage.calls.count("provision_user") == 0  # never mutates on rejection
    assert env.profile_source.fetched_subjects == []  # hit path: zero user-info requests


def test_email_coexistence_provisions_second_user(env: _Env) -> None:
    """Phase 12: a stranger already owns this email under a different sub —
    that no longer blocks provisioning. The login creates a second,
    independent user through one full batch (own personal org, own
    membership); the identity tuple, not the email, is the convergence key,
    and the stranger is untouched."""
    stranger = env.storage.create_user(
        User(
            id=UserId("usr_stranger_me"),
            display_name="Stranger",
            email=EMAIL,
            status=UserStatus.ACTIVE,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
    )
    response = env.client.get("/v1/me", headers=env.auth(env.token()))

    assert response.status_code == 200
    body = response.json()
    assert body["id"].startswith("usr_")
    assert body["id"] != str(stranger.id)
    assert body["email"] == EMAIL
    # Exactly one provisioning write, committed in full (no standalone
    # organization write — the compound is the batch), and the stranger's
    # row is unchanged.
    assert env.storage.calls.count("provision_user") == 1
    assert env.storage.calls.count("create_user") == 1  # only the stranger seed
    assert env.storage.calls.count("create_organization") == 0
    assert env.storage.get_user(stranger.id) == stranger


def test_jwks_down_503(tmp_path: Path, key: TestKey) -> None:
    server = JwksTestServer({"pool-a": [key]})
    server.start()
    issuer = server.issuer("pool-a")
    verifier = CognitoAccessTokenVerifier(
        CognitoJwksSource([issuer]),
        allowed_issuers=[issuer],
        allowed_client_ids=[ALLOWED_CLIENT],
    )
    storage = RecordingStorage(open_sqlite_storage(tmp_path / "down.sqlite"))
    app = create_app(routers=[build_me_router(storage, verifier)])
    client = TestClient(app, raise_server_exceptions=False)
    now = int(time.time())
    token = sign_token(
        {
            "sub": SUBJECT,
            "email": EMAIL,
            "username": "me-user",
            "client_id": ALLOWED_CLIENT,
            "iss": issuer,
            "token_use": "access",
            "exp": now + 3600,
        },
        kid=key.kid,
        key=key,
    )
    server.stop()  # provider outage before the first fetch

    response = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 503
    assert Error.model_validate(response.json()).code == "internal_error"
    assert storage.total_calls == 0  # outage never reaches storage
    assert token not in response.text
    storage._inner.close()


# ---------------------------------------------------------------------------
# Route/manifest wiring
# ---------------------------------------------------------------------------


def test_router_registers_manifest_entry_exactly(env: _Env) -> None:
    paths = env.client.app.openapi()["paths"]
    assert {p for p in paths if p.startswith("/v1")} == {"/v1/me"}
    get = paths["/v1/me"]["get"]
    assert "200" in get["responses"]
    reference = get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert reference.endswith("MeResponse")
