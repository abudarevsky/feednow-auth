"""HTTP auth dependency chain for bearer-authenticated routes (identity).

The published identity chain, one seam per stage::

    Authorization header -> AccessTokenVerifier.verify -> resolve_or_provision
                         -> ResolvedIdentity(user, context)

:func:`build_current_user` closes over the injected :class:`Storage` and
:class:`AccessTokenVerifier` (no import-time environment reads; the initial
boot contract) and returns a FastAPI dependency yielding the resolved
:class:`~app.services.identity.ResolvedIdentity` — the same object API-key implementation
API-key path will produce from the other verifier seam.

API-key adds the sibling :func:`build_current_principal`, which
**dispatches on the bearer literal's prefix** (design notes design choice 6):
``fn_live_``/``fn_test_`` → the implementation API-key verification seam (failure →
the one uniform 401), anything else → the unchanged identity chain above.
Prefix collision is impossible: a JWS compact token always starts ``eyJ``
(base64url of ``{"``), never an ``fn_`` credential prefix, so the two
verifiers can never receive each other's input.

Failure mapping (design notes decision: HTTP mapping is implementation's job, joined
here and rendered through the frozen initial envelope by
:func:`app.api.errors.http_exception_handler`):

- missing/malformed bearer header, any :class:`~app.auth.errors.
  TokenValidationError` (including :class:`~app.auth.errors.UnknownKeyIdError`)
  → **401** ``unauthenticated``;
- :class:`~app.auth.errors.TokenProviderUnavailableError` → **503**
  ``internal_error`` (a provider outage is deliberately *not* a 401; the
  frozen envelope maps 503 to ``internal_error`` — no contract-revision code is
  invented here);
- :class:`~app.services.identity.DisabledUserError` /
  :class:`~app.services.identity.NoActiveOrganizationError` → **403**;
- :class:`~app.services.identity.ProvisioningConflictError` → **409**;
- :class:`~app.auth.api_key_auth.ApiKeyAuthenticationError` (API-key branch
  only) → **401** ``unauthenticated`` with the single fixed credential-free
  message (design choice 4); any other :class:`~app.storage.contract.StorageError`
  propagates untranslated → 500 (design choice 11).

Messages are the exceptions' fixed, safe reasons — never token, key, or
email material (AGENTS.md). Verification failures raise *before* any storage
touch, which is what makes the acceptance proof "rejected without storage
mutation" hold structurally, not just by test.

session (implementation) adds the optional ``profile_source`` seam to both
factories: when a :class:`~app.auth.cognito.ProfileSource` is configured, the
**human** branch closes the raw bearer token and the verified ``claims.sub``
into a ``profile_provider`` thunk handed to :func:`resolve_or_provision`, so
first-login provisioning fetches the authoritative user-info profile. The
thunk runs only on the identity-tuple miss path (a known user triggers zero
user-info requests), and the API-key branch never touches it. With no source
configured the chain behaves exactly as before session.

Current behavior and invariants: ``docs/authentication.md``."""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from fastapi import HTTPException, Request

from app.auth.api_key_auth import ApiKeyAuthenticationError, verify_api_key
from app.auth.cognito import AccessTokenVerifier, CognitoClaims, CognitoProfile, ProfileSource
from app.auth.credentials import ENVIRONMENT_PREFIXES
from app.auth.errors import TokenProviderUnavailableError, TokenValidationError
from app.auth.pepper import PepperSource
from app.auth.principal import Principal
from app.auth.session import SessionManager, read_session_cookie
from app.models.enums import UserStatus
from app.models.user import User
from app.services.identity import (
    DisabledUserError,
    NoActiveOrganizationError,
    ProvisioningConflictError,
    ResolvedIdentity,
    build_user_context,
    resolve_or_provision,
    resolve_user,
)
from app.storage.contract import EntityNotFoundError, Storage

#: Fixed safe messages for header-level failures (no caller text is echoed).
MISSING_HEADER_MESSAGE: Final = "authentication credentials not provided"
MALFORMED_HEADER_MESSAGE: Final = "authorization header must use the bearer scheme"

#: Bearer-literal prefixes that dispatch to the API-key verification branch
#: (decision 6). Derived from the single source in
#: :mod:`app.auth.credentials` so dispatch and parsing can never drift.
API_KEY_BEARER_PREFIXES: Final = tuple(ENVIRONMENT_PREFIXES.values())

#: Bearer scheme token, matched case-insensitively per RFC 7235.
_BEARER_PREFIX: Final = "bearer "


def _extract_bearer_token(request: Request) -> str:
    """Return the bearer token or raise 401 with a fixed safe reason.

    Case-insensitive scheme; the credential must be a single non-empty token
    with no internal whitespace — anything else is malformed and never
    forwarded to the verifier.
    """
    header = request.headers.get("authorization")
    if header is None:
        raise HTTPException(status_code=401, detail=MISSING_HEADER_MESSAGE)
    if not header.lower().startswith(_BEARER_PREFIX):
        raise HTTPException(status_code=401, detail=MALFORMED_HEADER_MESSAGE)
    token = header[len(_BEARER_PREFIX) :].strip()
    if not token or any(char.isspace() for char in token):
        raise HTTPException(status_code=401, detail=MALFORMED_HEADER_MESSAGE)
    return token


def _verify_token(verifier: AccessTokenVerifier, token: str) -> CognitoClaims:
    """Run the JWT verifier with the published failure mapping (401/503)."""
    try:
        return verifier.verify(token)
    except TokenProviderUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except TokenValidationError as exc:
        raise HTTPException(status_code=401, detail=exc.reason) from exc


def _profile_provider_for(
    profile_source: ProfileSource | None,
    token: str,
    claims: CognitoClaims,
) -> Callable[[], CognitoProfile] | None:
    """Close the verified token/subject into the miss-path profile thunk.

    ``None`` (no source configured) keeps today's chain shape; the service
    then refuses a first-login miss with its fixed 401-class error rather
    than provisioning from access-token claims.
    """
    if profile_source is None:
        return None
    return lambda: profile_source.fetch(token, claims.sub)


def _resolve_identity(
    storage: Storage,
    claims: CognitoClaims,
    profile_provider: Callable[[], CognitoProfile] | None = None,
) -> ResolvedIdentity:
    """Resolve-or-provision with the published domain-error mapping (403/409).

    The profile gate inside the service raises :class:`TokenValidationError`
    (→ 401, fixed safe reason) and a configured ``profile_source`` fetch can
    raise :class:`TokenProviderUnavailableError` (→ 503, the same outage
    vocabulary as the verifier stage) — both are mapped here so a first-login
    provider failure is never a bare 500.
    """
    try:
        return resolve_or_provision(storage, claims, profile_provider=profile_provider)
    except DisabledUserError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except NoActiveOrganizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ProvisioningConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except TokenProviderUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except TokenValidationError as exc:
        raise HTTPException(status_code=401, detail=exc.reason) from exc


def build_current_user(
    storage: Storage,
    verifier: AccessTokenVerifier,
    profile_source: ProfileSource | None = None,
    session_manager: SessionManager | None = None,
) -> Callable[..., ResolvedIdentity]:
    """Return the ``ResolvedIdentity`` dependency bound to ``storage``/``verifier``.

    The returned callable is the whole chain: bearer parse → verify →
    resolve-or-provision (with an optional session ``profile_source`` for
    first-login provisioning) → domain-error mapping. It is a pure wiring
    factory (no I/O at construction), so routers built from it stay
    import-safe.
    """

    def current_user(request: Request) -> ResolvedIdentity:
        """Execute the identity authentication chain for one request."""
        if session_manager is not None and not request.headers.get("authorization"):
            session_id = read_session_cookie(request)
            user_id = session_manager.verify(session_id) if session_id else None
            if user_id is not None:
                try:
                    user = storage.get_user(user_id)
                except EntityNotFoundError as exc:
                    raise HTTPException(status_code=401, detail=MISSING_HEADER_MESSAGE) from exc
                if user.status is not UserStatus.ACTIVE:
                    raise HTTPException(status_code=403, detail="user account is disabled")
                return ResolvedIdentity(user=user, context=build_user_context(storage, user))
        token = _extract_bearer_token(request)
        claims = _verify_token(verifier, token)
        return _resolve_identity(
            storage, claims, _profile_provider_for(profile_source, token, claims)
        )

    return current_user


def build_current_user_without_organization(
    storage: Storage,
    verifier: AccessTokenVerifier,
    profile_source: ProfileSource | None = None,
    session_manager: SessionManager | None = None,
) -> Callable[..., User]:
    """Authenticate and resolve a user without requiring active membership.

    This is reserved for global administration, which must remain reachable
    when an administrator suspends their final organization.
    """

    def current_user(request: Request) -> User:
        if session_manager is not None and not request.headers.get("authorization"):
            session_id = read_session_cookie(request)
            user_id = session_manager.verify(session_id) if session_id else None
            if user_id is not None:
                try:
                    user = storage.get_user(user_id)
                except EntityNotFoundError as exc:
                    raise HTTPException(status_code=401, detail=MISSING_HEADER_MESSAGE) from exc
                if user.status is not UserStatus.ACTIVE:
                    raise HTTPException(status_code=403, detail="user account is disabled")
                return user
        token = _extract_bearer_token(request)
        claims = _verify_token(verifier, token)
        try:
            return resolve_user(
                storage,
                claims,
                profile_provider=_profile_provider_for(profile_source, token, claims),
            )
        except DisabledUserError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ProvisioningConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except TokenProviderUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except TokenValidationError as exc:
            raise HTTPException(status_code=401, detail=exc.reason) from exc

    return current_user


def build_current_principal(
    storage: Storage,
    verifier: AccessTokenVerifier,
    pepper_source: PepperSource,
    profile_source: ProfileSource | None = None,
    session_manager: SessionManager | None = None,
) -> Callable[..., Principal]:
    """Return the ``Principal`` dependency: prefix-dispatched human-or-key auth.

    The dispatch is on the **literal prefix** only (design choice 6): a bearer
    token starting ``fn_live_``/``fn_test_`` goes to the API-key verification
    seam (:func:`~app.auth.api_key_auth.verify_api_key`); everything else
    goes to the unchanged identity chain, so a JWT-looking token is never
    parsed as a credential and an ``fn_`` literal is never sent to the JWT
    verifier. Both branches wrap their outcome in the same
    :class:`~app.auth.principal.Principal` (human path: the identity
    ``ResolvedIdentity`` pair verbatim; key path: the verified row plus its
    authorization-context contract context).

    Failure mapping matches the published seams: every API-key
    authentication failure is the one uniform **401** carrying
    :data:`~app.auth.api_key_auth.API_KEY_AUTHENTICATION_MESSAGE` (no branch
    message, no credential fragment — design choice 4); human-path and header
    failures keep the identity mapping exactly; any other ``StorageError``
    on the key branch propagates untranslated → 500 (design choice 11). The
    human branch alone consumes ``profile_source`` (session); the
    API-key branch never fetches a profile. Pure wiring factory, like
    :func:`build_current_user`.
    """

    def current_principal(request: Request) -> Principal:
        """Authenticate one request and wrap the outcome in a ``Principal``."""
        if session_manager is not None and not request.headers.get("authorization"):
            identity = build_current_user(storage, verifier, profile_source, session_manager)(
                request
            )
            return Principal(user=identity.user, api_key=None, context=identity.context)
        token = _extract_bearer_token(request)
        if token.startswith(API_KEY_BEARER_PREFIXES):
            return _api_key_principal(token)
        claims = _verify_token(verifier, token)
        identity = _resolve_identity(
            storage, claims, _profile_provider_for(profile_source, token, claims)
        )
        return Principal(user=identity.user, api_key=None, context=identity.context)

    def _api_key_principal(literal: str) -> Principal:
        try:
            verified = verify_api_key(storage, pepper_source, literal)
        except ApiKeyAuthenticationError as exc:
            # The one uniform 401: the exception's message is already the
            # fixed, credential-free constant (decision 4); str(exc) can
            # never echo key-id, secret, or pepper material.
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return Principal(user=None, api_key=verified.api_key, context=verified.context)

    return current_principal


__all__ = [
    "API_KEY_BEARER_PREFIXES",
    "MALFORMED_HEADER_MESSAGE",
    "MISSING_HEADER_MESSAGE",
    "build_current_principal",
    "build_current_user",
]
