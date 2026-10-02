"""Integration proofs for ``GET /oauth/login`` (session design notes implementation).

Drives the implementation route through ``TestClient(create_app(routers=[...]))``
with a real SQLite storage behind a recording wrapper and **tripwire**
doubles for every callback-only dependency (verifier, token endpoint,
profile source, session manager) — login initiation must touch exactly one
storage operation (``save_oauth_login_state``) and zero provider/session
machinery. Proven here:

1. The 302 authorize redirect carries the fixed PKCE parameter set
   (``response_type=code``, ``client_id``, configured ``redirect_uri``,
   ``scope=openid email profile``, ``state``, ``code_challenge_method=S256``,
   ``code_challenge``) and never the verifier itself.
2. The stored :class:`~app.models.session.OAuthLoginState` binds the minted
   verifier to the challenge (S256 recomputation), keeps the requested
   return URL, and expires ~600 seconds out.
3. ``next`` accepts same-origin relative paths and exact-allowlist origins;
   foreign origins, prefix-spoofs, credentials-in-URL, non-http(s) schemes,
   protocol-relative/backslash smuggling, oversized, and empty values all
   fail **400** ``validation_error`` with the fixed message, zero storage
   writes, and the submitted value never echoed.
4. Every login mints a fresh state and verifier; the routes stay out of the
   OpenAPI schema and the frozen ``/v1`` manifest.
5. Constructor validation fails fast on bad approved configuration.

Current behavior and invariants: ``docs/architecture.md``."""

from __future__ import annotations

import base64
import hashlib
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.api.oauth import (
    LOGIN_PATH,
    LOGIN_STATE_TTL_SECONDS,
    OAUTH_SCOPE,
    RETURN_URL_REJECTED_MESSAGE,
    build_oauth_router,
)
from app.main import create_app
from app.models.errors import Error
from app.storage.sqlite import open_sqlite_storage

AUTHORIZE_URL = "https://auth.example.test/oauth2/authorize"
REDIRECT_URI = "https://app.example.test/oauth/callback"
CLIENT_ID = "login-init-client"
LANDING_URL = "https://app.example.test/home"
ALLOWED_ORIGINS = ("https://app.example.test", "https://admin.example.test")


class RecordingStorage:
    """Delegating wrapper counting every storage call (write-proof oracle)."""

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


class _Tripwire:
    """Callback-only dependency: any attribute access is a implementation failure."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"login initiation must not touch {name}")


class _Env:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.storage = RecordingStorage(open_sqlite_storage(db_path))
        router = build_oauth_router(
            self.storage,
            _Tripwire(),
            _Tripwire(),
            _Tripwire(),
            _Tripwire(),
            authorize_url=AUTHORIZE_URL,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            landing_url=LANDING_URL,
            allowed_return_origins=ALLOWED_ORIGINS,
        )
        self.client = TestClient(create_app(routers=[router]), raise_server_exceptions=False)

    def close(self) -> None:
        self.storage._inner.close()


@pytest.fixture
def env(tmp_path: Path) -> Iterator[_Env]:
    built = _Env(tmp_path / "login.sqlite")
    yield built
    built.close()


def _authorize_params(location: str) -> dict[str, str]:
    """Split the 302 target into base URL and single-valued query params."""
    parsed = urlsplit(location)
    assert parsed.query, "the redirect must carry the authorization request"
    params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    return {"_base": f"{parsed.scheme}://{parsed.netloc}{parsed.path}", **params}


def _peek_state_row(db_path: Path, state_id: str) -> sqlite3.Row | None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM oauth_login_states WHERE state_id = ?", (state_id,)
        ).fetchone()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Happy initiation
# ---------------------------------------------------------------------------


def test_login_redirects_to_provider_with_the_fixed_pkce_request(env: _Env) -> None:
    response = env.client.get(LOGIN_PATH, follow_redirects=False)

    assert response.status_code == 302
    params = _authorize_params(response.headers["location"])
    assert params.pop("_base") == "https://auth.example.test/oauth2/authorize"
    assert params == {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": OAUTH_SCOPE,
        "state": params["state"],
        "code_challenge_method": "S256",
        "code_challenge": params["code_challenge"],
    }
    # 43-char urlsafe state and 43-char base64url S256 challenge; the raw
    # verifier never rides the redirect.
    assert len(params["state"]) == 43
    assert len(params["code_challenge"]) == 43
    assert "code_verifier" not in response.headers["location"]
    assert env.storage.calls == ["save_oauth_login_state"]


def test_stored_state_binds_verifier_to_challenge_and_expires(env: _Env) -> None:
    response = env.client.get(LOGIN_PATH, follow_redirects=False)
    state_id = _authorize_params(response.headers["location"])["state"]

    row = _peek_state_row(env.db_path, state_id)
    assert row is not None
    assert row["return_url"] == LANDING_URL  # default next = configured landing
    verifier = row["code_verifier"]
    assert 43 <= len(verifier) <= 128
    assert set(verifier) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    assert _authorize_params(response.headers["location"])["code_challenge"] == (
        challenge.rstrip(b"=").decode("ascii")
    )
    expires_at = datetime.fromisoformat(row["expires_at"])
    remaining = (expires_at - datetime.now(UTC)).total_seconds()
    assert LOGIN_STATE_TTL_SECONDS - 5 <= remaining <= LOGIN_STATE_TTL_SECONDS


def test_each_login_mints_a_fresh_state_and_verifier(env: _Env) -> None:
    first = _authorize_params(
        env.client.get(LOGIN_PATH, follow_redirects=False).headers["location"]
    )
    second = _authorize_params(
        env.client.get(LOGIN_PATH, follow_redirects=False).headers["location"]
    )

    assert first["state"] != second["state"]
    assert first["code_challenge"] != second["code_challenge"]
    assert env.storage.calls.count("save_oauth_login_state") == 2
    conn = sqlite3.connect(env.db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM oauth_login_states").fetchone()[0] == 2
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Accepted next values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "next_value",
    [
        "/dashboard",
        "/",
        "/search?q=hello+world",
        "https://app.example.test/deep/path?x=1#frag",
        "https://admin.example.test/team",
        "HTTPS://APP.EXAMPLE.TEST/CaseInsensitiveOrigin",
    ],
)
def test_allowed_next_values_are_stored_verbatim(env: _Env, next_value: str) -> None:
    response = env.client.get(
        f"{LOGIN_PATH}?next={quote(next_value, safe='')}", follow_redirects=False
    )

    assert response.status_code == 302
    state_id = _authorize_params(response.headers["location"])["state"]
    row = _peek_state_row(env.db_path, state_id)
    assert row is not None
    assert row["return_url"] == next_value


# ---------------------------------------------------------------------------
# Rejected next values: 400 validation_error, fixed message, value unechoed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("next_value", "echo_sentinel"),
    [
        ("https://evil.example/x", "evil.example"),
        ("https://app.example.test.evil/x", "app.example.test.evil"),
        ("//admin.example.test/x", "admin.example.test"),
        ("javascript:alert(1)", "javascript"),
        ("data:text/html,hi", "data:"),
        ("ftp://app.example.test/x", "ftp"),
        ("https://user:pass@app.example.test/x", "user:pass"),
        ("/\\evil.example", "evil.example"),
        ("/ok\r\nSet-Cookie: x=1", "Set-Cookie"),
        ("https://app.example.test/" + "a" * 2100, "aaaa"),
        ("/" + "b" * 3000, "bbbb"),
        ("app.example.test/x", "app.example.test/x"),
    ],
)
def test_rejected_next_values_fail_400_without_echo_or_writes(
    env: _Env, next_value: str, echo_sentinel: str
) -> None:
    response = env.client.get(
        f"{LOGIN_PATH}?next={quote(next_value, safe='')}", follow_redirects=False
    )

    assert response.status_code == 400, next_value
    envelope = Error.model_validate(response.json())
    assert envelope.code == "validation_error"
    assert envelope.message == RETURN_URL_REJECTED_MESSAGE
    assert echo_sentinel not in response.text  # the submitted value is never echoed
    assert env.storage.calls == []  # zero storage writes on rejection


def test_empty_next_is_rejected(env: _Env) -> None:
    response = env.client.get(f"{LOGIN_PATH}?next=", follow_redirects=False)

    assert response.status_code == 400
    assert Error.model_validate(response.json()).code == "validation_error"
    assert env.storage.calls == []


# ---------------------------------------------------------------------------
# Route placement and constructor validation
# ---------------------------------------------------------------------------


def test_oauth_routes_stay_out_of_schema_and_manifest(env: _Env) -> None:
    paths = env.client.app.openapi()["paths"]

    assert LOGIN_PATH not in paths  # include_in_schema=False
    assert "/oauth/callback" not in paths
    assert {p for p in paths if p.startswith("/v1")} == set()  # outside the frozen manifest


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"authorize_url": "http://auth.example.test/oauth2/authorize"}, "HTTPS"),
        ({"authorize_url": AUTHORIZE_URL + "?x=1"}, "query"),
        ({"redirect_uri": "https://app.example.test/cb?x=1"}, "query"),
        ({"redirect_uri": "not-a-url"}, "absolute"),
        ({"client_id": ""}, "non-empty"),
        ({"allowed_return_origins": ()}, "at least one"),
        ({"allowed_return_origins": ("https://app.example.test/path")}, "bare"),
        ({"allowed_return_origins": ("ftp://app.example.test",)}, "bare"),
        ({"landing_url": "https://evil.example/home"}, "allowed return URL"),
    ],
)
def test_constructor_validates_approved_configuration(
    tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    config: dict[str, Any] = {
        "authorize_url": AUTHORIZE_URL,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "landing_url": LANDING_URL,
        "allowed_return_origins": ALLOWED_ORIGINS,
    }
    config.update(overrides)
    with pytest.raises(ValueError, match=message):
        build_oauth_router(
            open_sqlite_storage(tmp_path / "ctor.sqlite"),
            _Tripwire(),
            _Tripwire(),
            _Tripwire(),
            _Tripwire(),
            **config,
        )


def test_login_state_expiry_constant_is_ten_minutes() -> None:
    assert LOGIN_STATE_TTL_SECONDS == 600
    assert timedelta(seconds=LOGIN_STATE_TTL_SECONDS) == timedelta(minutes=10)
