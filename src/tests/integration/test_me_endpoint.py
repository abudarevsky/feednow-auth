"""Integration tests for ``GET /v1/me`` (Phase 03 task 5).

Full stack, no live Cognito pool (acceptance criterion 5): the loopback JWKS
test server signs real RS256 tokens, real SQLite persists the provisioning
batch, and ``TestClient(create_app(routers=[build_me_router(...)]))`` drives
the frozen Phase 01 envelope. Acceptance mapping:

- each 401 variant (missing/malformed header, expired, wrong issuer, wrong
  client, ``token_use=id``, garbage token, forged signature) asserts **zero
  calls** on a recording storage wrapper — "rejected without storage mutation";
- named non-401 cases: ``test_disabled_user_403``, ``test_email_collision_409``,
  ``test_jwks_down_503`` — all seeded with existing create methods only;
- the happy path returns ``usr_``/profile fields and the body carries no
  ``sub``, no ``client_id``, no token bytes; repeated requests provision
  exactly once; every error body validates against the frozen ``Error`` model.
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
from app.auth.cognito import CognitoAccessTokenVerifier
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
    ) -> None:
        self.server = server
        self.storage = storage
        self.client = client
        self.key = key

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
    app = create_app(routers=[build_me_router(storage, verifier)])
    return _Env(server, storage, TestClient(app, raise_server_exceptions=False), key)


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
    assert {"id", "display_name", "email", "status", "created_at", "updated_at"} == set(body)

    # No provider material anywhere in the response (AGENTS.md / acceptance 4).
    serialized = json.dumps(body)
    assert SUBJECT not in serialized
    assert ALLOWED_CLIENT not in serialized
    assert env.token() not in serialized
    assert "cognito" not in serialized.lower()

    # Exactly one provisioning write; repeat requests converge on the same user.
    assert env.storage.calls.count("provision_user") == 1
    second = env.client.get("/v1/me", headers=env.auth(env.token()))
    assert second.status_code == 200
    assert second.json()["id"] == body["id"]
    assert env.storage.calls.count("provision_user") == 1  # still exactly once
    assert env.storage.calls.count("get_user_by_external_identity") == 2  # hit path


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


def test_email_collision_409(env: _Env) -> None:
    """A stranger owns the email under a different sub: the batch races the
    email UNIQUE, the identity re-read misses, and the service refuses to
    converge on the stranger (decision 7) -> 409, no partial rows."""
    env.storage.create_user(
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

    assert response.status_code == 409
    assert Error.model_validate(response.json()).code == "conflict"
    assert env.storage.calls.count("provision_user") == 1  # the failed attempt only
    assert env.storage.calls.count("create_user") == 1  # only the stranger seed
    assert env.storage.calls.count("create_organization") == 0  # no partial batch


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
