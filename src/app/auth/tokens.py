"""Internal JWT access-token generation with role-based claims.

This module owns *issuance* of the service's own signed JWTs. It is the
generation counterpart to the Phase 03 verification chain
(:mod:`app.auth.cognito`), which verifies **Cognito** tokens and stays
unchanged here: nothing in this module parses, validates, or accepts a token,
so a minted token can never bootstrap itself through the Cognito verifier.
The opaque ``feednow_session`` cookie (:mod:`app.auth.session`) also remains
the browser session carrier — this module neither replaces nor reads it.

Contract:

- :class:`JwtTokenIssuer` is constructed once per app with the signing key,
  issuer, audience, and TTL; :meth:`JwtTokenIssuer.issue` mints a fresh
  ``HS256`` token for one :class:`~app.models.user.User` and returns the
  encoded string. The algorithm is pinned to :data:`JWT_ALGORITHM` — there is
  no caller-selectable ``alg``, so the ``none``/algorithm-confusion forgery
  class the Cognito verifier defends against cannot be produced here.
- **Subject is always the internal FeedNow ID.** ``sub`` is ``user.id``
  (``usr_``); email, display name, and any provider ``sub`` are never claims
  (AGENTS.md: internal IDs are the application identity).
- **Role-based claims keep the two vocabularies separate** (spec 12
  invariant 1): :data:`APPLICATION_ROLE_CLAIM` carries the user's single
  global :class:`~app.models.enums.ApplicationRole`, while
  :data:`ROLES_CLAIM` carries the organization-local
  :class:`~app.models.enums.MembershipRole` values the caller supplies for
  the request's organization context (deduplicated, deterministic
  declaration order). The two claims never share a value source, and an
  :class:`~app.models.enums.ApplicationRole` can never be smuggled into the
  membership list despite the coincident ``"admin"`` string.
- The issuer accepts a ``User`` only — an API key can never be a JWT subject,
  so key principals stay roleless (spec 12 invariant 7) by construction.
- Registered claims: ``iss``/``aud`` (constructor config), ``iat``/``exp``
  (service clock, ``exp = iat + ttl_seconds``), and ``jti``
  (``secrets.token_urlsafe(16)``, fresh per call) for replay detection.

Secrecy rules (AGENTS.md): a minted token is bearer credential material, so
this module imports **no logging**, never persists a token, and every
constructor/validation failure raises a fixed message that echoes no key,
claim, or input fragment.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from typing import Final

import jwt

from app.models.enums import ApplicationRole, MembershipRole
from app.models.timestamps import utc_now
from app.models.user import User

#: The one signing algorithm this issuer ever uses (256-bit HMAC).
JWT_ALGORITHM: Final = "HS256"

#: RFC 7518 floor for an HS256 secret: 256 bits. Enforced at construction so
#: a weak key fails fast, mirroring the pepper source's minimum-length rule.
MIN_SIGNING_KEY_BYTES: Final = 32

#: Default absolute token lifetime: 30 minutes, mirroring the session TTL.
DEFAULT_JWT_TTL_SECONDS: Final = 1800

#: Claim name carrying the user's global application role value.
APPLICATION_ROLE_CLAIM: Final = "application_role"

#: Claim name carrying the organization-local membership role values.
ROLES_CLAIM: Final = "roles"

#: Fixed, input-free failure messages (no key material or claim content can
#: ever ride a construction error).
SIGNING_KEY_TOO_SHORT_MESSAGE: Final = "signing key must encode to at least 32 bytes"
SIGNING_KEY_TYPE_MESSAGE: Final = "signing_key must be str or bytes"
ISSUER_MESSAGE: Final = "issuer must be a non-empty string"
AUDIENCE_MESSAGE: Final = "audience must be a non-empty string"
TTL_MESSAGE: Final = "ttl_seconds must be a positive integer"
USER_TYPE_MESSAGE: Final = "user must be a User instance"
MEMBERSHIP_ROLES_MESSAGE: Final = "membership_roles must contain only MembershipRole values"

#: Deterministic claim order for membership roles: enum declaration order
#: (``owner``, ``admin``, ``member``, ``viewer``), never caller order.
_ROLE_ORDER: Final = {role: index for index, role in enumerate(MembershipRole)}


def _coerce_membership_roles(membership_roles: Iterable[MembershipRole]) -> list[str]:
    """Validate, deduplicate, and order membership roles for the claim.

    Accepts :class:`~app.models.enums.MembershipRole` members and their exact
    string values (the same coercion style as
    :func:`app.auth.credentials.build_literal`); rejects everything else —
    including :class:`~app.models.enums.ApplicationRole` members, which are
    ``str`` subclasses with colliding values — with one fixed message that
    echoes no input.
    """
    known = {role.value: role for role in MembershipRole}
    collected: set[MembershipRole] = set()
    for role in membership_roles:
        if isinstance(role, MembershipRole):
            collected.add(role)
        elif isinstance(role, ApplicationRole):
            # Explicit pre-check: ApplicationRole is a StrEnum whose values
            # overlap this vocabulary ("admin"); it must never coerce across
            # the boundary (spec 12 invariant 1).
            raise ValueError(MEMBERSHIP_ROLES_MESSAGE)
        elif isinstance(role, str) and role in known:
            collected.add(known[role])
        else:
            raise ValueError(MEMBERSHIP_ROLES_MESSAGE)
    return [role.value for role in sorted(collected, key=lambda role: _ROLE_ORDER[role])]


class JwtTokenIssuer:
    """Issues internal ``HS256`` JWTs whose claims are the user's roles.

    Constructed once per app with deployment configuration; holds no
    per-token state, so it is safe to share across requests. The signing key
    is stored as encoded bytes and never appears in any exception, repr, or
    log (this module logs nothing).
    """

    def __init__(
        self,
        *,
        signing_key: str | bytes,
        issuer: str,
        audience: str,
        ttl_seconds: int = DEFAULT_JWT_TTL_SECONDS,
    ) -> None:
        """Validate all issuer configuration up front (fail fast at boot).

        Raises:
            TypeError: ``signing_key`` is neither ``str`` nor ``bytes``.
            ValueError: the key encodes below :data:`MIN_SIGNING_KEY_BYTES`,
                ``issuer``/``audience`` are blank, or ``ttl_seconds`` is not
                a positive ``int``. Every message is fixed and input-free.
        """
        if isinstance(signing_key, str):
            key_bytes = signing_key.encode("utf-8")
        elif isinstance(signing_key, (bytes, bytearray, memoryview)):
            key_bytes = bytes(signing_key)
        else:
            raise TypeError(SIGNING_KEY_TYPE_MESSAGE)
        if len(key_bytes) < MIN_SIGNING_KEY_BYTES:
            raise ValueError(SIGNING_KEY_TOO_SHORT_MESSAGE)
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError(ISSUER_MESSAGE)
        if not isinstance(audience, str) or not audience.strip():
            raise ValueError(AUDIENCE_MESSAGE)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError(TTL_MESSAGE)
        self._signing_key = key_bytes
        self._issuer = issuer
        self._audience = audience
        self._ttl_seconds = ttl_seconds

    @property
    def issuer(self) -> str:
        """The ``iss`` claim value every minted token carries."""
        return self._issuer

    @property
    def audience(self) -> str:
        """The ``aud`` claim value every minted token carries."""
        return self._audience

    @property
    def ttl_seconds(self) -> int:
        """The configured absolute token lifetime, in seconds."""
        return self._ttl_seconds

    def issue(
        self,
        user: User,
        membership_roles: Iterable[MembershipRole] = (),
    ) -> str:
        """Mint a signed access token for ``user`` and return the encoded JWT.

        Claims: ``sub`` = the internal ``usr_`` identity (never email or a
        provider subject), ``iss``/``aud`` from configuration, ``iat``/``exp``
        from the service clock (``exp = iat + ttl_seconds``), a fresh ``jti``,
        :data:`APPLICATION_ROLE_CLAIM` = the user's global role, and
        :data:`ROLES_CLAIM` = the deduplicated, deterministically ordered
        organization-local membership roles supplied by the caller (empty by
        default). The token is returned to the caller only — it is never
        persisted or logged here.

        Raises:
            TypeError: ``user`` is not a :class:`~app.models.user.User`.
            ValueError: ``membership_roles`` contains anything outside the
                :class:`~app.models.enums.MembershipRole` vocabulary
                (fixed message, no input echo).
        """
        if not isinstance(user, User):
            raise TypeError(USER_TYPE_MESSAGE)
        roles = _coerce_membership_roles(membership_roles)
        issued_at = int(utc_now().timestamp())
        claims: dict[str, object] = {
            "sub": str(user.id),
            "iss": self._issuer,
            "aud": self._audience,
            "iat": issued_at,
            "exp": issued_at + self._ttl_seconds,
            "jti": secrets.token_urlsafe(16),
            APPLICATION_ROLE_CLAIM: user.application_role.value,
            ROLES_CLAIM: roles,
        }
        return jwt.encode(claims, self._signing_key, algorithm=JWT_ALGORITHM)


__all__ = [
    "APPLICATION_ROLE_CLAIM",
    "AUDIENCE_MESSAGE",
    "DEFAULT_JWT_TTL_SECONDS",
    "ISSUER_MESSAGE",
    "JWT_ALGORITHM",
    "MEMBERSHIP_ROLES_MESSAGE",
    "MIN_SIGNING_KEY_BYTES",
    "ROLES_CLAIM",
    "SIGNING_KEY_TOO_SHORT_MESSAGE",
    "SIGNING_KEY_TYPE_MESSAGE",
    "TTL_MESSAGE",
    "USER_TYPE_MESSAGE",
    "JwtTokenIssuer",
]
