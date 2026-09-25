"""Internal JWT access-token generation and application-role validation.

This module owns both halves of the service's own signed JWTs:
:class:`JwtTokenIssuer` mints them and :class:`JwtTokenVerifier` accepts
them — the verifier is the single place that validates a token's
application-role claims against the closed domain vocabularies. The
Phase 03 verification chain (:mod:`app.auth.cognito`) stays unchanged
and separate: it accepts only ``RS256`` Cognito access tokens, so a
token minted here can never bootstrap itself through the Cognito
verifier, and a Cognito token can never be accepted here (this verifier
pins ``HS256`` plus its own issuer/audience). The opaque
``feednow_session`` cookie (:mod:`app.auth.session`) also remains the
browser session carrier — this module neither replaces nor reads it.

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
- :class:`JwtTokenVerifier` is the validation counterpart: constructed
  once per app with the same signing key, issuer, and audience (plus a
  clock leeway); :meth:`JwtTokenVerifier.verify` fails closed at every
  stage with a fixed, input-free
  :class:`~app.auth.errors.TokenValidationError` and returns the frozen
  :class:`JwtClaims` value object. **Application roles are validated,
  never trusted**: ``application_role`` must name exactly one
  :class:`~app.models.enums.ApplicationRole` value and ``roles`` must be
  a JSON list of exact :class:`~app.models.enums.MembershipRole` values;
  anything else — missing, mistyped, unknown, wrong case, or a value
  smuggled across the vocabulary boundary (spec 12 invariant 1) —
  rejects the token. ``sub`` must be a valid internal ``usr_`` identity
  (AGENTS.md: internal IDs are the application identity). Verification
  touches no storage and resolves no user; projecting verified claims
  into an authorization decision is the consumer's job.

Secrecy rules (AGENTS.md): a minted token is bearer credential material,
so this module imports **no logging**, never persists a token, and every
constructor, validation, or verification failure raises a fixed message
that echoes no key, claim, or input fragment.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidSignatureError,
    MissingRequiredClaimError,
    PyJWTError,
)
from jwt.utils import base64url_decode

from app.auth.errors import TokenValidationError
from app.models.enums import ApplicationRole, MembershipRole
from app.models.ids import UserId
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

#: Default clock leeway for verification, mirroring the Cognito verifier's
#: fixed 60-second window.
DEFAULT_JWT_LEEWAY_SECONDS: Final = 60

#: ``jti`` length bound: a replay-detection id is a short random string;
#: anything longer is corrupt or hostile.
_JTI_MAX_LENGTH: Final = 255

#: Fixed, input-free verification failure messages. A rejected token is
#: never described by its own content.
LEEWAY_MESSAGE: Final = "leeway_seconds must be a non-negative integer"
TOKEN_TYPE_MESSAGE: Final = "token must be a string"
TOKEN_MALFORMED_MESSAGE: Final = "token is not a well-formed JWT"
TOKEN_ALGORITHM_MESSAGE: Final = "token algorithm is not allowed"
ISSUER_CLAIM_MESSAGE: Final = "token issuer is not allowed"
AUDIENCE_CLAIM_MESSAGE: Final = "token audience is not allowed"
TOKEN_EXPIRED_MESSAGE: Final = "token has expired"
TOKEN_NOT_YET_VALID_MESSAGE: Final = "token is not yet valid"
TOKEN_SIGNATURE_MESSAGE: Final = "token signature is invalid"
MISSING_CLAIM_MESSAGE: Final = "token is missing a required claim"
VALIDATION_FAILED_MESSAGE: Final = "token failed validation"
APPLICATION_ROLE_CLAIM_MISSING_MESSAGE: Final = "token is missing the application_role claim"
APPLICATION_ROLE_CLAIM_INVALID_MESSAGE: Final = "token application_role claim is invalid"
ROLES_CLAIM_MISSING_MESSAGE: Final = "token is missing the roles claim"
ROLES_CLAIM_INVALID_MESSAGE: Final = "token roles claim is invalid"

#: Deterministic claim order for membership roles: enum declaration order
#: (``owner``, ``admin``, ``member``, ``viewer``), never caller order.
_ROLE_ORDER: Final = {role: index for index, role in enumerate(MembershipRole)}


def _encode_signing_key(signing_key: str | bytes) -> bytes:
    """Validate and encode the shared HS256 key (issuer and verifier).

    Raises:
        TypeError: ``signing_key`` is neither ``str`` nor ``bytes``.
        ValueError: the key encodes below :data:`MIN_SIGNING_KEY_BYTES`.
        Both messages are fixed and input-free.
    """
    if isinstance(signing_key, str):
        key_bytes = signing_key.encode("utf-8")
    elif isinstance(signing_key, (bytes, bytearray, memoryview)):
        key_bytes = bytes(signing_key)
    else:
        raise TypeError(SIGNING_KEY_TYPE_MESSAGE)
    if len(key_bytes) < MIN_SIGNING_KEY_BYTES:
        raise ValueError(SIGNING_KEY_TOO_SHORT_MESSAGE)
    return key_bytes


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
        self._signing_key = _encode_signing_key(signing_key)
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError(ISSUER_MESSAGE)
        if not isinstance(audience, str) or not audience.strip():
            raise ValueError(AUDIENCE_MESSAGE)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError(TTL_MESSAGE)
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


@dataclass(frozen=True)
class JwtClaims:
    """Verified internal JWT claims — the verifier's only output shape.

    Immutable value object; no raw token material is retained. The role
    fields are **validated enums**, not strings:
    :attr:`application_role` is the single global
    :class:`~app.models.enums.ApplicationRole` and :attr:`roles` the
    organization-local :class:`~app.models.enums.MembershipRole` values,
    so no consumer can ever observe an unvalidated or cross-vocabulary
    role (spec 12 invariant 1). ``sub`` is the internal ``usr_`` identity.
    """

    sub: UserId
    iss: str
    aud: str
    iat: int
    exp: int
    jti: str
    application_role: ApplicationRole
    roles: tuple[MembershipRole, ...]


class JwtTokenVerifier:
    """Verifies internal ``HS256`` JWTs and validates their role claims.

    The exact counterpart of :class:`JwtTokenIssuer`: constructed once per
    app with the same signing key, issuer, and audience configuration.
    :meth:`verify` runs this pinned order, failing closed at every stage
    with a fixed, input-free :class:`~app.auth.errors.TokenValidationError`
    (the auth boundary's 401-mapped vocabulary):

    1. **Structure** — three base64url segments whose header and payload
       decode as JSON objects (manual unverified decode, mirroring the
       Cognito verifier so no time check can mask the ordered stages).
    2. **Header** — ``alg`` must be the exact string ``"HS256"`` before
       any HMAC is computed: ``none``/``RS256``/other-algorithm forgeries
       reject here.
    3. **Issuer** — exact match against the configured issuer on the
       unverified payload (never PyJWT's ``issuer=`` option, the same
       defense-in-depth as the Cognito verifier), so a foreign-issuer
       token is refused before signature work.
    4. **Decode** — ``jwt.decode`` pinned to :data:`JWT_ALGORITHM` with
       the configured audience and leeway; library failures map one-by-one
       to fixed reasons.
    5. **Claims** — ``sub`` must be a valid internal ``usr_`` identity,
       ``iat``/``exp`` positive integers, ``jti`` a bounded non-empty
       string, then the **application-role validation**: the
       ``application_role`` claim must name exactly one
       :class:`~app.models.enums.ApplicationRole` value and the ``roles``
       claim must be a JSON list whose every member names a
       :class:`~app.models.enums.MembershipRole` value. Unknown, missing,
       mistyped, or case-shifted values are rejections — the two closed
       vocabularies can never be crossed or extended through a token
       (spec 12 invariant 1).

    Verification is not authentication: this class touches no storage and
    resolves no user; it only decides whether the token's own claims are
    acceptable and projects them to :class:`JwtClaims`. Holds no per-token
    state, so it is safe to share across requests, and it logs nothing.
    """

    def __init__(
        self,
        *,
        signing_key: str | bytes,
        issuer: str,
        audience: str,
        leeway_seconds: int = DEFAULT_JWT_LEEWAY_SECONDS,
    ) -> None:
        """Validate all verifier configuration up front (fail fast at boot).

        Raises:
            TypeError: ``signing_key`` is neither ``str`` nor ``bytes``.
            ValueError: the key encodes below :data:`MIN_SIGNING_KEY_BYTES`,
                ``issuer``/``audience`` are blank, or ``leeway_seconds`` is
                not a non-negative ``int``. Every message is fixed and
                input-free.
        """
        self._signing_key = _encode_signing_key(signing_key)
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError(ISSUER_MESSAGE)
        if not isinstance(audience, str) or not audience.strip():
            raise ValueError(AUDIENCE_MESSAGE)
        if (
            not isinstance(leeway_seconds, int)
            or isinstance(leeway_seconds, bool)
            or leeway_seconds < 0
        ):
            raise ValueError(LEEWAY_MESSAGE)
        self._issuer = issuer
        self._audience = audience
        self._leeway_seconds = leeway_seconds

    @property
    def issuer(self) -> str:
        """The ``iss`` claim value this verifier accepts, exact match only."""
        return self._issuer

    @property
    def audience(self) -> str:
        """The ``aud`` claim value this verifier accepts, exact match only."""
        return self._audience

    @property
    def leeway_seconds(self) -> int:
        """The configured clock leeway applied to ``exp`` and ``iat``."""
        return self._leeway_seconds

    def verify(self, token: str) -> JwtClaims:
        """Verify ``token`` and return its validated, typed claims.

        :raises TokenValidationError: malformed/forged/expired token,
            disallowed algorithm, issuer, or audience, or an invalid
            claim/application-role shape (fixed safe reasons; see the
            pinned order in the class docstring).
        """
        header, payload = self._unpack_unverified(token)  # 1
        self._check_header(header)  # 2
        self._check_issuer(payload)  # 3
        verified = self._decode(token)  # 4
        return self._build_claims(verified)  # 5

    # -- stage 1: unverified structure -----------------------------------------

    @staticmethod
    def _unpack_unverified(token: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        """Decode header and payload **without any verification** (stages 2—3
        need them before the signature is checked).

        Manual base64url + JSON is deliberate — the same reasoning as the
        Cognito verifier: ``jwt.decode(verify_signature=False)`` would also
        enforce ``exp``/``iat`` here and mis-order the checks.
        """
        if not isinstance(token, str):
            raise TokenValidationError(TOKEN_TYPE_MESSAGE)
        malformed = TokenValidationError(TOKEN_MALFORMED_MESSAGE)
        segments = token.split(".")
        if len(segments) != 3:
            raise malformed
        try:
            header = json.loads(base64url_decode(segments[0]))
            payload = json.loads(base64url_decode(segments[1]))
        except (ValueError, TypeError):  # binascii.Error subclasses ValueError
            raise malformed from None
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise malformed
        return header, payload

    # -- stage 2: header algorithm pin ------------------------------------------

    @staticmethod
    def _check_header(header: Mapping[str, Any]) -> None:
        """Exact, case-sensitive ``alg`` match before any HMAC is computed.

        ``none`` and every non-``HS256`` algorithm (including the Cognito
        chain's ``RS256``) reject with one fixed reason; the issuer pins the
        same constant, so acceptance and generation can never drift.
        """
        alg = header.get("alg")
        if not isinstance(alg, str) or alg != JWT_ALGORITHM:
            raise TokenValidationError(TOKEN_ALGORITHM_MESSAGE)

    # -- stage 3: own exact-match issuer check -----------------------------------

    def _check_issuer(self, payload: Mapping[str, Any]) -> None:
        """Exact issuer equality on the unverified payload (never PyJWT
        ``issuer=``): a foreign issuer rejects before any signature work.
        """
        if "iss" not in payload or payload["iss"] is None:
            raise TokenValidationError("token is missing the issuer claim")
        issuer = payload["iss"]
        if not isinstance(issuer, str) or not issuer:
            raise TokenValidationError("token issuer claim is invalid")
        if issuer != self._issuer:
            raise TokenValidationError(ISSUER_CLAIM_MESSAGE)

    # -- stage 4: signature + time + audience via PyJWT ----------------------------

    def _decode(self, token: str) -> Mapping[str, Any]:
        """``jwt.decode`` with the pinned options; every library failure becomes
        a :class:`TokenValidationError` with a fixed reason (library messages,
        which can echo claim fragments, are chained as ``__cause__`` only).
        """
        try:
            verified: Mapping[str, Any] = jwt.decode(
                token,
                self._signing_key,
                algorithms=[JWT_ALGORITHM],
                audience=self._audience,
                leeway=self._leeway_seconds,
            )
        except ExpiredSignatureError as exc:
            raise TokenValidationError(TOKEN_EXPIRED_MESSAGE) from exc
        except ImmatureSignatureError as exc:
            raise TokenValidationError(TOKEN_NOT_YET_VALID_MESSAGE) from exc
        except InvalidSignatureError as exc:  # subclass of DecodeError: order matters
            raise TokenValidationError(TOKEN_SIGNATURE_MESSAGE) from exc
        except InvalidAlgorithmError as exc:  # fail-closed redundancy of stage 2
            raise TokenValidationError(TOKEN_ALGORITHM_MESSAGE) from exc
        except InvalidAudienceError as exc:
            raise TokenValidationError(AUDIENCE_CLAIM_MESSAGE) from exc
        except MissingRequiredClaimError as exc:
            raise TokenValidationError(MISSING_CLAIM_MESSAGE) from exc
        except DecodeError as exc:
            raise TokenValidationError(TOKEN_MALFORMED_MESSAGE) from exc
        except PyJWTError as exc:
            raise TokenValidationError(VALIDATION_FAILED_MESSAGE) from exc
        except Exception as exc:  # unexpected library behavior fails closed
            raise TokenValidationError(VALIDATION_FAILED_MESSAGE) from exc
        return verified

    # -- stage 5: claim-shape and application-role validation -----------------------

    def _build_claims(self, payload: Mapping[str, Any]) -> JwtClaims:
        """Validate every claim shape and build the frozen typed claims.

        The signature has already bound these values to this verifier's key,
        so shape failures here are fail-closed redundancy against issuer
        bugs — a token can still never smuggle a role the model layer would
        choke on with a 500.
        """
        raw_sub = self._require_str_claim(
            payload,
            "sub",
            missing_reason="token is missing the sub claim",
            invalid_reason="token sub claim is invalid",
        )
        try:
            sub = UserId(raw_sub)
        except ValueError:
            # Provider subjects and emails are not user identities (AGENTS.md):
            # anything outside the ``usr_`` shape rejects with a fixed reason.
            raise TokenValidationError("token sub claim is invalid") from None

        iss = self._require_str_claim(
            payload,
            "iss",
            missing_reason="token is missing the issuer claim",
            invalid_reason="token issuer claim is invalid",
        )
        if iss != self._issuer:
            raise TokenValidationError(ISSUER_CLAIM_MESSAGE)
        aud = self._require_str_claim(
            payload,
            "aud",
            missing_reason="token is missing the aud claim",
            invalid_reason="token aud claim is invalid",
        )
        if aud != self._audience:
            raise TokenValidationError(AUDIENCE_CLAIM_MESSAGE)

        iat = self._require_positive_int_claim(
            payload,
            "iat",
            missing_reason="token is missing the iat claim",
            invalid_reason="token iat claim is invalid",
        )
        exp = self._require_positive_int_claim(
            payload,
            "exp",
            missing_reason="token is missing the exp claim",
            invalid_reason="token exp claim is invalid",
        )
        jti = self._require_str_claim(
            payload,
            "jti",
            missing_reason="token is missing the jti claim",
            invalid_reason="token jti claim is invalid",
            max_length=_JTI_MAX_LENGTH,
        )

        application_role = self._validated_application_role(payload)
        roles = self._validated_membership_roles(payload)

        return JwtClaims(
            sub=sub,
            iss=iss,
            aud=aud,
            iat=iat,
            exp=exp,
            jti=jti,
            application_role=application_role,
            roles=roles,
        )

    @staticmethod
    def _validated_application_role(payload: Mapping[str, Any]) -> ApplicationRole:
        """Project the global role claim onto the closed ``ApplicationRole`` vocabulary.

        The claim must be present and name exactly one enum value. Anything
        else — absent, ``null``, non-string, a membership-only value such as
        ``"owner"``, an unknown string, or wrong case — is a rejection with a
        fixed reason: an unvalidated role can never reach a consumer, and a
        token can never invent a third role (spec 12 invariant 1).
        """
        if APPLICATION_ROLE_CLAIM not in payload or payload[APPLICATION_ROLE_CLAIM] is None:
            raise TokenValidationError(APPLICATION_ROLE_CLAIM_MISSING_MESSAGE)
        raw = payload[APPLICATION_ROLE_CLAIM]
        known = {role.value: role for role in ApplicationRole}
        if not isinstance(raw, str) or raw not in known:
            raise TokenValidationError(APPLICATION_ROLE_CLAIM_INVALID_MESSAGE)
        return known[raw]

    @staticmethod
    def _validated_membership_roles(payload: Mapping[str, Any]) -> tuple[MembershipRole, ...]:
        """Project the organization-local claim onto the closed ``MembershipRole`` vocabulary.

        The claim must be present and a JSON list of exact membership-role
        strings (duplicates are preserved as issued; the issuer
        canonicalizes). An application-only value such as ``"user"`` inside
        this list is a rejection — the vocabularies never cross despite the
        coincident ``"admin"`` string (spec 12 invariant 1).
        """
        if ROLES_CLAIM not in payload or payload[ROLES_CLAIM] is None:
            raise TokenValidationError(ROLES_CLAIM_MISSING_MESSAGE)
        raw = payload[ROLES_CLAIM]
        if not isinstance(raw, list):
            raise TokenValidationError(ROLES_CLAIM_INVALID_MESSAGE)
        known = {role.value: role for role in MembershipRole}
        collected: list[MembershipRole] = []
        for item in raw:
            if not isinstance(item, str) or item not in known:
                raise TokenValidationError(ROLES_CLAIM_INVALID_MESSAGE)
            collected.append(known[item])
        return tuple(collected)

    @staticmethod
    def _require_str_claim(
        payload: Mapping[str, Any],
        name: str,
        *,
        missing_reason: str,
        invalid_reason: str,
        max_length: int | None = None,
    ) -> str:
        """Return a non-empty, optionally bounded string claim or raise a fixed reason."""
        if name not in payload or payload[name] is None:
            raise TokenValidationError(missing_reason)
        value = payload[name]
        if (
            not isinstance(value, str)
            or not value
            or (max_length is not None and len(value) > max_length)
        ):
            raise TokenValidationError(invalid_reason)
        return value

    @staticmethod
    def _require_positive_int_claim(
        payload: Mapping[str, Any],
        name: str,
        *,
        missing_reason: str,
        invalid_reason: str,
    ) -> int:
        """Return a positive integer claim or raise a fixed reason."""
        if name not in payload or payload[name] is None:
            raise TokenValidationError(missing_reason)
        value = payload[name]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise TokenValidationError(invalid_reason)
        return value


__all__ = [
    "APPLICATION_ROLE_CLAIM",
    "APPLICATION_ROLE_CLAIM_INVALID_MESSAGE",
    "APPLICATION_ROLE_CLAIM_MISSING_MESSAGE",
    "AUDIENCE_CLAIM_MESSAGE",
    "AUDIENCE_MESSAGE",
    "DEFAULT_JWT_LEEWAY_SECONDS",
    "DEFAULT_JWT_TTL_SECONDS",
    "ISSUER_CLAIM_MESSAGE",
    "ISSUER_MESSAGE",
    "JWT_ALGORITHM",
    "LEEWAY_MESSAGE",
    "MEMBERSHIP_ROLES_MESSAGE",
    "MIN_SIGNING_KEY_BYTES",
    "MISSING_CLAIM_MESSAGE",
    "ROLES_CLAIM",
    "ROLES_CLAIM_INVALID_MESSAGE",
    "ROLES_CLAIM_MISSING_MESSAGE",
    "SIGNING_KEY_TOO_SHORT_MESSAGE",
    "SIGNING_KEY_TYPE_MESSAGE",
    "TOKEN_ALGORITHM_MESSAGE",
    "TOKEN_EXPIRED_MESSAGE",
    "TOKEN_MALFORMED_MESSAGE",
    "TOKEN_NOT_YET_VALID_MESSAGE",
    "TOKEN_SIGNATURE_MESSAGE",
    "TOKEN_TYPE_MESSAGE",
    "TTL_MESSAGE",
    "USER_TYPE_MESSAGE",
    "VALIDATION_FAILED_MESSAGE",
    "JwtClaims",
    "JwtTokenIssuer",
    "JwtTokenVerifier",
]
