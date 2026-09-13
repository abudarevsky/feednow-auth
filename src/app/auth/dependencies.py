"""HTTP auth dependency chain for bearer-authenticated routes (Phase 03 task 5).

The published Phase 03 chain, one seam per stage::

    Authorization header -> AccessTokenVerifier.verify -> resolve_or_provision
                         -> ResolvedIdentity(user, context)

:func:`build_current_user` closes over the injected :class:`Storage` and
:class:`AccessTokenVerifier` (no import-time environment reads; the Phase 01
boot contract) and returns a FastAPI dependency yielding the resolved
:class:`~app.services.identity.ResolvedIdentity` — the same object Phase 05's
API-key path will produce from the other verifier seam.

Failure mapping (breakdown decision: HTTP mapping is task 5's job, joined
here and rendered through the frozen Phase 01 envelope by
:func:`app.api.errors.http_exception_handler`):

- missing/malformed bearer header, any :class:`~app.auth.errors.
  TokenValidationError` (including :class:`~app.auth.errors.UnknownKeyIdError`)
  → **401** ``unauthenticated``;
- :class:`~app.auth.errors.TokenProviderUnavailableError` → **503**
  ``internal_error`` (a provider outage is deliberately *not* a 401; the
  frozen envelope maps 503 to ``internal_error`` — no spec-revision code is
  invented here);
- :class:`~app.services.identity.DisabledUserError` /
  :class:`~app.services.identity.NoActiveOrganizationError` → **403**;
- :class:`~app.services.identity.ProvisioningConflictError` → **409**.

Messages are the exceptions' fixed, safe reasons — never token, key, or
email material (AGENTS.md). Verification failures raise *before* any storage
touch, which is what makes the acceptance proof "rejected without storage
mutation" hold structurally, not just by test.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from fastapi import HTTPException, Request

from app.auth.cognito import AccessTokenVerifier, CognitoClaims
from app.auth.errors import TokenProviderUnavailableError, TokenValidationError
from app.services.identity import (
    DisabledUserError,
    NoActiveOrganizationError,
    ProvisioningConflictError,
    ResolvedIdentity,
    resolve_or_provision,
)
from app.storage.contract import Storage

#: Fixed safe messages for header-level failures (no caller text is echoed).
MISSING_HEADER_MESSAGE: Final = "authentication credentials not provided"
MALFORMED_HEADER_MESSAGE: Final = "authorization header must use the bearer scheme"

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


def build_current_user(
    storage: Storage,
    verifier: AccessTokenVerifier,
) -> Callable[..., ResolvedIdentity]:
    """Return the ``ResolvedIdentity`` dependency bound to ``storage``/``verifier``.

    The returned callable is the whole chain: bearer parse → verify →
    resolve-or-provision → domain-error mapping. It is a pure wiring factory
    (no I/O at construction), so routers built from it stay import-safe.
    """

    def current_user(request: Request) -> ResolvedIdentity:
        """Execute the Phase 03 authentication chain for one request."""
        claims = _verify(_extract_bearer_token(request))
        return _resolve(claims)

    def _verify(token: str) -> CognitoClaims:
        try:
            return verifier.verify(token)
        except TokenProviderUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except TokenValidationError as exc:
            raise HTTPException(status_code=401, detail=exc.reason) from exc

    def _resolve(claims: CognitoClaims) -> ResolvedIdentity:
        try:
            return resolve_or_provision(storage, claims)
        except DisabledUserError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except NoActiveOrganizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ProvisioningConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return current_user


__all__ = [
    "MALFORMED_HEADER_MESSAGE",
    "MISSING_HEADER_MESSAGE",
    "build_current_user",
]
