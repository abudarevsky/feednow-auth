"""Application session issuer/verifier and cookie policy (Phase 11 task 9).

This module owns the *opaque* server-side session behind the
``feednow_session`` cookie. It is deliberately component-level only: mounting
cookie-based authentication of ``/v1/*`` routes is **not** part of this phase
(the callback route of task 12 is the sole issuer in this phase's surface).

Contract (breakdown task 9):

- :class:`SessionManager` is the issuer/verifier over the storage contract:

  - ``issue(user_id) -> str`` mints a fresh session id from
    ``secrets.token_urlsafe(32)`` (43 chars, no claims, no structure) and
    persists an :class:`~app.models.session.AppSession` with
    ``expires_at = utc_now() + ttl_seconds``. Storage mints nothing — the
    manager populates every field (contract rule).
  - ``verify(session_id) -> UserId | None`` resolves a live session to its
    internal ``usr_`` identity. Unknown, expired, or malformed
    caller-controlled input yields ``None`` and never raises: the session id
    arrives from a cookie, so it is attacker material and must fail closed.

- Cookie policy lives here as pure helpers so the route layer cannot invent
  its own attributes: :data:`SESSION_COOKIE_NAME`,
  :func:`build_session_cookie` (always ``HttpOnly; SameSite=Lax; Path=/``;
  the ``Secure`` flag is caller-controlled by deployment config, per task
  13's ``FEEDNOW_COOKIE_SECURE``), and :func:`read_session_cookie`.

Secrecy rules (AGENTS.md): the session id is a bearer credential, so this
module imports **no logging** and never writes the id, the user id, or any
cookie string to logs or exception text. The id carries no claims — it is a
lookup key, never a token to parse; authorization re-reads user status
independently of the session row.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Final

from fastapi import Request

from app.models.ids import UserId
from app.models.session import AppSession
from app.models.timestamps import utc_now
from app.storage.contract import Storage

#: Name of the application session cookie (spec §session boundary). Fixed:
#: the browser-visible half of the session contract.
SESSION_COOKIE_NAME: Final = "feednow_session"

#: Length bounds mirrored from ``app.models.session.SessionId`` so a
#: truncated or forged caller-supplied id fails closed inside the verifier
#: before it ever reaches storage (the issuer mints 43 chars, comfortably
#: inside both bounds).
SESSION_ID_MIN_LENGTH: Final = 16
SESSION_ID_MAX_LENGTH: Final = 255

#: Default session lifetime: 30 minutes of idle-free absolute expiry.
#: Refresh/extension is out of scope for this phase.
DEFAULT_SESSION_TTL_SECONDS: Final = 1800


class SessionManager:
    """Issues and verifies opaque application sessions over the contract.

    Constructed once per app with the storage adapter and the configured
    TTL; holds no per-session state, so it is safe to share across
    requests. The manager never logs and never raises for caller-controlled
    input on the verify path.
    """

    def __init__(self, storage: Storage, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> None:
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            # Fixed message: boot-time misconfiguration fails fast; no
            # session material is ever involved here.
            raise ValueError("ttl_seconds must be a positive integer")
        self._storage = storage
        self._ttl_seconds = ttl_seconds

    @property
    def ttl_seconds(self) -> int:
        """The configured absolute session lifetime, in seconds."""
        return self._ttl_seconds

    def issue(self, user_id: UserId) -> str:
        """Mint a new session for ``user_id`` and return its opaque id.

        The id is ``secrets.token_urlsafe(32)`` (43 characters, URL-safe,
        no claims). The persisted :class:`AppSession` carries the internal
        ``usr_`` identity and an absolute ``expires_at`` derived from the
        service clock. The model boundary validates ``user_id``, so an
        invalid identity raises :class:`~pydantic.ValidationError` before
        any storage write.
        """
        session_id = secrets.token_urlsafe(32)
        session = AppSession(
            session_id=session_id,
            user_id=user_id,
            expires_at=utc_now() + timedelta(seconds=self._ttl_seconds),
        )
        self._storage.create_app_session(session)
        return session_id

    def verify(self, session_id: str) -> UserId | None:
        """Resolve a session id to its live user, or ``None``.

        Never raises for caller-controlled input: a non-string, a short or
        over-long id, unknown, or expired sessions all return ``None``.
        Storage's own expiry filter is mirrored here so a session at/past
        ``expires_at`` is ``None`` regardless of adapter clock behavior
        ("reads are not writes" — checking expiry never mutates storage).
        """
        if not isinstance(session_id, str):
            return None
        if not SESSION_ID_MIN_LENGTH <= len(session_id) <= SESSION_ID_MAX_LENGTH:
            return None
        stored = self._storage.get_app_session(session_id)
        if stored is None:
            return None
        if stored.expires_at <= utc_now():
            return None
        return stored.user_id


def build_session_cookie(value: str, *, max_age: int, secure: bool) -> str:
    """Render the ``Set-Cookie`` value for a session id.

    The policy attributes are fixed — ``HttpOnly``, ``SameSite=Lax``,
    ``Path=/`` — and ``Max-Age`` mirrors the configured TTL. ``Secure`` is
    caller-controlled (deployment config, task 13's ``FEEDNOW_COOKIE_SECURE``)
    because local HTTP development cannot use it. The minted id is
    URL-safe base64 (no ``;``/whitespace), so no quoting or escaping is
    applied.
    """
    attributes = [
        f"{SESSION_COOKIE_NAME}={value}",
        f"Max-Age={max_age}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
    ]
    if secure:
        attributes.append("Secure")
    return "; ".join(attributes)


def read_session_cookie(request: Request) -> str | None:
    """Extract the raw session cookie from a request, or ``None``.

    Returns the unverified value (or ``None`` when absent/empty); callers
    must pass it through :meth:`SessionManager.verify` before trusting it.
    """
    value = request.cookies.get(SESSION_COOKIE_NAME)
    if not value:
        return None
    return value


__all__ = [
    "DEFAULT_SESSION_TTL_SECONDS",
    "SESSION_COOKIE_NAME",
    "SESSION_ID_MAX_LENGTH",
    "SESSION_ID_MIN_LENGTH",
    "SessionManager",
    "build_session_cookie",
    "read_session_cookie",
]
