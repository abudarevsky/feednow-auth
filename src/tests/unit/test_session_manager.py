"""Unit proofs for the session implementation session issuer/verifier and cookie policy.

The module under test (``src/app/auth/session.py``) is proven against the
real SQLite adapter (tmp file) plus small fakes for clock/expiry edges:

1. ``issue`` mints a 43-char opaque id (``secrets.token_urlsafe(32)``),
   persists an ``AppSession`` mapping it to the internal ``usr_`` identity
   with ``expires_at = utc_now() + ttl``, and never embeds the user id in
   the session id (no claims).
2. ``verify`` resolves live sessions, returns ``None`` for unknown/expired
   ids, and never raises for caller-controlled garbage — out-of-bounds or
   non-string ids fail closed without touching storage.
3. The cookie policy is fixed: ``feednow_session`` name, ``HttpOnly``,
   ``SameSite=Lax``, ``Path=/``, ``Max-Age`` mirroring the TTL, ``Secure``
   only when the caller (deployment config) asks; ``read_session_cookie``
   returns the raw value or ``None`` (absent/empty).
4. Secrecy: the module imports no logging (AST proof) and emits zero log
   records across a full issue/verify cycle (caplog proof).

Current behavior and invariants: ``docs/architecture.md``."""

from __future__ import annotations

import ast
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

import pytest
from fastapi import Request
from pydantic import ValidationError

import app.auth.session as session_module
from app.auth.session import (
    DEFAULT_SESSION_TTL_SECONDS,
    SESSION_COOKIE_NAME,
    SESSION_ID_MAX_LENGTH,
    SESSION_ID_MIN_LENGTH,
    SessionManager,
    build_session_cookie,
    read_session_cookie,
)
from app.models.ids import UserId
from app.models.session import AppSession
from app.storage.sqlite import SQLiteStorage

USER_ID: Final = UserId("usr_session_owner")


@pytest.fixture
def storage(tmp_path) -> SQLiteStorage:  # type: ignore[no-untyped-def]
    adapter = SQLiteStorage(tmp_path / "sessions.sqlite")
    yield adapter
    adapter.close()


class _FakeStorage:
    """Dict-backed storage double: records lookups, never filters expiry."""

    def __init__(self) -> None:
        self.sessions: dict[str, AppSession] = {}
        self.get_calls = 0

    def create_app_session(self, session: AppSession) -> AppSession:
        self.sessions[session.session_id] = session
        return session

    def get_app_session(self, session_id: str) -> AppSession | None:
        self.get_calls += 1
        return self.sessions.get(session_id)


def _request_with_cookie(value: str | None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if value is not None:
        headers.append((b"cookie", f"{SESSION_COOKIE_NAME}={value}".encode()))
    return Request({"type": "http", "headers": headers})


# ---------------------------------------------------------------------------
# 1. issue: opaque minting + persisted AppSession
# ---------------------------------------------------------------------------


def test_issue_mints_opaque_id_and_persists_session(storage: SQLiteStorage) -> None:
    manager = SessionManager(storage)
    before = datetime.now(UTC)
    session_id = manager.issue(USER_ID)
    after = datetime.now(UTC)

    # 43 chars of URL-safe base64 (secrets.token_urlsafe(32)); opaque, no
    # structure, and never a JWT-style dotted token.
    assert isinstance(session_id, str)
    assert len(session_id) == 43
    assert "." not in session_id
    assert str(USER_ID) not in session_id  # carries no claims

    stored = storage.get_app_session(session_id)
    assert stored is not None
    assert stored.user_id == USER_ID
    assert before + timedelta(seconds=1800) <= stored.expires_at <= after + timedelta(seconds=1800)


def test_issue_returns_distinct_ids_each_call(storage: SQLiteStorage) -> None:
    manager = SessionManager(storage)
    ids = {manager.issue(USER_ID) for _ in range(10)}
    assert len(ids) == 10
    assert all(manager.verify(sid) == USER_ID for sid in ids)


def test_issue_honors_configured_ttl(storage: SQLiteStorage) -> None:
    manager = SessionManager(storage, ttl_seconds=60)
    before = datetime.now(UTC)
    session_id = manager.issue(USER_ID)
    stored = storage.get_app_session(session_id)
    assert stored is not None
    assert stored.expires_at <= before + timedelta(seconds=61)


def test_issue_rejects_invalid_user_id_before_storage(storage: SQLiteStorage) -> None:
    fake = _FakeStorage()
    manager = SessionManager(fake)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        manager.issue("not-an-internal-id")  # type: ignore[arg-type]
    assert fake.sessions == {}


# ---------------------------------------------------------------------------
# 2. constructor: TTL validation and default
# ---------------------------------------------------------------------------


def test_default_ttl_is_thirty_minutes(storage: SQLiteStorage) -> None:
    assert DEFAULT_SESSION_TTL_SECONDS == 1800
    assert SessionManager(storage).ttl_seconds == 1800


@pytest.mark.parametrize("ttl", [0, -1, "1800", True, None])
def test_constructor_rejects_non_positive_ttl(storage: SQLiteStorage, ttl: object) -> None:
    with pytest.raises(ValueError, match="ttl_seconds must be a positive integer"):
        SessionManager(storage, ttl_seconds=ttl)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 3. verify: live/unknown/expired/garbage
# ---------------------------------------------------------------------------


def test_verify_resolves_live_session(storage: SQLiteStorage) -> None:
    manager = SessionManager(storage)
    session_id = manager.issue(USER_ID)
    resolved = manager.verify(session_id)
    assert resolved == USER_ID
    assert isinstance(resolved, UserId)


def test_verify_unknown_session_returns_none(storage: SQLiteStorage) -> None:
    manager = SessionManager(storage)
    assert manager.verify("u" * 43) is None


def test_verify_expired_session_returns_none(storage: SQLiteStorage, monkeypatch) -> None:
    manager = SessionManager(storage, ttl_seconds=60)
    session_id = manager.issue(USER_ID)
    # Advance the service clock past absolute expiry (reads are not writes:
    # nothing is mutated; the session simply stops resolving).
    future = datetime.now(UTC) + timedelta(seconds=61)
    monkeypatch.setattr(session_module, "utc_now", lambda: future)
    assert manager.verify(session_id) is None


def test_verify_rechecks_expiry_even_if_adapter_returns_expired_row() -> None:
    fake = _FakeStorage()
    manager = SessionManager(fake)  # type: ignore[arg-type]
    stale = AppSession(
        session_id="s" * 43,
        user_id=USER_ID,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    fake.sessions[stale.session_id] = stale
    assert manager.verify(stale.session_id) is None


@pytest.mark.parametrize(
    "garbage",
    [
        None,
        12345,
        b"bytes-not-str",
        "",
        "u" * (SESSION_ID_MIN_LENGTH - 1),  # below the minted-id floor
        "u" * (SESSION_ID_MAX_LENGTH + 1),  # above the ceiling
    ],
)
def test_verify_never_raises_for_garbage_without_touching_storage(garbage: object) -> None:
    fake = _FakeStorage()
    manager = SessionManager(fake)  # type: ignore[arg-type]
    assert manager.verify(garbage) is None  # type: ignore[arg-type]
    assert fake.get_calls == 0


def test_verify_wellformed_but_unknown_id_returns_none(storage: SQLiteStorage) -> None:
    # In-bounds, string, correctly shaped — reaches storage, still None.
    manager = SessionManager(storage)
    assert manager.verify("A" * 43) is None


# ---------------------------------------------------------------------------
# 4. cookie policy
# ---------------------------------------------------------------------------


def test_cookie_name_is_fixed() -> None:
    assert SESSION_COOKIE_NAME == "feednow_session"


def test_build_session_cookie_secure_variant_is_exact() -> None:
    cookie = build_session_cookie("abc123", max_age=1800, secure=True)
    assert cookie == (
        "feednow_session=abc123; Max-Age=1800; Path=/; HttpOnly; SameSite=Lax; Secure"
    )


@pytest.mark.parametrize("secure", [True, False])
def test_build_session_cookie_always_carries_policy_attributes(secure: bool) -> None:
    cookie = build_session_cookie("xyz", max_age=60, secure=secure)
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=60" in cookie
    assert cookie.startswith(f"{SESSION_COOKIE_NAME}=xyz;")
    if not secure:
        # Secure is caller-controlled (deployment config) — absent when False.
        assert "Secure" not in cookie


def test_read_session_cookie_round_trip_with_manager(storage: SQLiteStorage) -> None:
    manager = SessionManager(storage, ttl_seconds=90)
    session_id = manager.issue(USER_ID)
    cookie = build_session_cookie(session_id, max_age=manager.ttl_seconds, secure=False)
    # Strip the Set-Cookie attributes back to name=value for the request side.
    raw_value = cookie.split(";")[0].split("=", 1)[1]
    request = _request_with_cookie(raw_value)
    assert read_session_cookie(request) == session_id
    assert manager.verify(read_session_cookie(request)) == USER_ID


def test_read_session_cookie_absent_or_empty_returns_none() -> None:
    assert read_session_cookie(_request_with_cookie(None)) is None
    assert read_session_cookie(_request_with_cookie("")) is None
    request = Request({"type": "http", "headers": [(b"cookie", b"other=1")]})
    assert read_session_cookie(request) is None
    empty = Request({"type": "http", "headers": [(b"cookie", b"feednow_session=")]})
    assert read_session_cookie(empty) is None


# ---------------------------------------------------------------------------
# 5. secrecy: no logging, static and dynamic
# ---------------------------------------------------------------------------


def test_session_module_imports_no_logging() -> None:
    """AST proof: the module has no logging import and no logger reference.

    The session id is bearer material; the contract forbids logging anywhere in
    the module, so this guards the boundary rather than one call site.
    """
    tree = ast.parse(Path(session_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] != "logging" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root != "logging"
        elif isinstance(node, ast.Attribute):
            assert node.attr != "getLogger"


def test_issue_and_verify_emit_no_log_records(
    storage: SQLiteStorage, caplog: pytest.LogCaptureFixture
) -> None:
    manager = SessionManager(storage)
    with caplog.at_level(logging.DEBUG):
        session_id = manager.issue(USER_ID)
        assert manager.verify(session_id) == USER_ID
        assert manager.verify("t" * 43) is None
        assert manager.verify("garbage") is None
    assert caplog.records == []
    # The minted id appears in no captured output even if a framework logged.
    assert session_id not in caplog.text
