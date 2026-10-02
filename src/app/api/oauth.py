"""OAuth login flow: ``GET /oauth/login`` and ``GET /oauth/callback`` (session).

:func:`build_oauth_router` is the authorization-code + PKCE session boundary
(design notes tasks 11 and 12). Both routes are registered with
``include_in_schema=False`` and deliberately **outside** the frozen ``/v1``
ENDPOINTS manifest — WIP 11 scope 5 is the authorizing revision, and the
operational ``/health`` route is the mounting precedent (initial contract).

Login initiation (implementation):

1. ``next`` (default: the configured landing URL) is validated against an
   exact-origin allowlist plus same-origin relative paths. Credentials-in-URL,
   non-http(s) schemes, protocol-relative/backslash smuggling, and foreign
   origins are rejected with **400** ``validation_error`` and a fixed message
   — the submitted value is never echoed.
2. On accept, a fresh ``state`` (``secrets.token_urlsafe(32)``) and PKCE
   verifier (``secrets.token_urlsafe(64)`` → 86 chars, RFC 7636 unreserved
   charset) are minted, stored as an :class:`~app.models.session.OAuthLoginState`
   expiring in 600 seconds, and the browser is 302-redirected to the
   configured authorize URL with ``response_type=code``, ``client_id``, the
   configured ``redirect_uri``, ``scope=openid email profile``,
   ``code_challenge_method=S256``, and the ``code_challenge``. The verifier
   itself never leaves the server.

Callback (implementation) - the mapping table below **is** the contract:

=== ============================================= ===== =====================
Step failure                                      HTTP    code
=== ============================================= ===== =====================
(a) provider ``error`` / missing ``code``/``state``  401  ``unauthenticated``
(b) unknown / expired / already-replayed state       401  ``unauthenticated``
(c) token-endpoint exchange failure                  503  ``internal_error``
(d) access-token verification failure                401  ``unauthenticated``
(d) token provider unavailable (JWKS outage)         503  ``internal_error``
(e) profile shape / verification / subject failure   401  ``unauthenticated``
(e) profile provider unavailable                     503  ``internal_error``
(f) disabled user / no active organization           403  ``forbidden``
(f) provisioning conflict                            409  ``conflict``
(g) stored return URL no longer allow-listed         400  ``validation_error``
=== ============================================= ===== =====================

Every 401 carries a fixed message (``"login state is invalid or expired"``
for (b), a producer-pinned safe reason otherwise); provider text is never
echoed.

Success (g) issues an application session, sets the ``feednow_session``
cookie via :func:`~app.auth.session.build_session_cookie`, and 302s to the
stored return URL (re-validated against the same allowlist).

Secrecy (AGENTS.md): this module imports **no logging**; the authorization
code, login state, PKCE verifier, access token, and email appear in no log
record, error envelope, or redirect target — every failure message is a
fixed, safe constant or a producer-pinned fixed reason. All URLs and the
client id are approved configuration taken at construction; there are no
import-time environment reads (initial boot contract).

Current behavior and invariants: ``docs/architecture.md``."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Iterable
from datetime import timedelta
from typing import Final
from urllib.parse import SplitResult, urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.auth.cognito import (
    AccessTokenVerifier,
    ProfileSource,
)
from app.auth.errors import TokenProviderUnavailableError, TokenValidationError
from app.auth.session import SessionManager, build_session_cookie
from app.auth.token_exchange import CognitoTokenEndpoint
from app.models.session import OAuthLoginState
from app.models.timestamps import utc_now
from app.services.identity import (
    DisabledUserError,
    NoActiveOrganizationError,
    ProvisioningConflictError,
    resolve_or_provision,
)
from app.storage.contract import Storage

#: Served paths. ``/oauth/callback`` is the URI registered on the Cognito app
#: client (task 13/15 configuration); ``/oauth/login`` is the app-side entry.
LOGIN_PATH: Final = "/oauth/login"
CALLBACK_PATH: Final = "/oauth/callback"

#: Login-state lifetime: long enough for a Hosted UI round trip, short enough
#: that a captured authorize redirect is useless moments later.
LOGIN_STATE_TTL_SECONDS: Final = 600

#: OIDC scopes requested at authorization (spec §7: profile email is the
#: provisioning source, so ``email`` and ``profile`` ride with ``openid``).
OAUTH_SCOPE: Final = "openid email profile"

#: Fixed safe failure messages — no caller or provider material is ever
#: interpolated (the envelope echoes only these constants and producer-fixed
#: reasons).
RETURN_URL_REJECTED_MESSAGE: Final = "login return path is not allowed"
PROVIDER_REJECTED_MESSAGE: Final = "login was rejected by the identity provider"
LOGIN_STATE_INVALID_MESSAGE: Final = "login state is invalid or expired"

#: ``return_url`` bound mirroring ``app.models.session.ReturnUrl``
#: (max_length=2048) as a plain integer — the same decision-4 rule that keeps
#: the verifier free of domain types.
_RETURN_URL_MAX_LENGTH: Final = 2048

#: Mint sizes: state 32 bytes → 43 chars (``StateId`` floor is 16); verifier
#: 64 bytes -> 86 chars, inside RFC 7636's 43-128 unreserved window.
_STATE_ID_BYTES: Final = 32
_CODE_VERIFIER_BYTES: Final = 64

#: Schemes a return URL may use. The authorize/token endpoints are stricter
#: (HTTPS only) — see the validators below.
_ALLOWED_RETURN_SCHEMES: Final = frozenset({"http", "https"})


def _origin(scheme: str, netloc: str) -> str:
    """Normalized comparable origin (scheme and host are case-insensitive)."""
    return f"{scheme.lower()}://{netloc.lower()}"


def _has_forbidden_characters(candidate: str) -> bool:
    """Reject control characters and backslashes anywhere in a return URL.

    CR/LF/TAB and friends could split or forge a ``Location`` header value,
    and browsers normalize backslashes to slashes in paths — a ``/\host``
    "relative" path resolves to another origin. Spaces are legal inside
    query components, so they are not rejected here.
    """
    return any(ord(char) < 0x20 or ord(char) == 0x7F or char == "\\" for char in candidate)


def _is_allowed_return_url(candidate: str, allowed_origins: frozenset[str]) -> bool:
    """Decide whether ``candidate`` may receive the post-login redirect.

    Accepted shapes: same-origin absolute paths (single leading slash, never
    protocol-relative ``//host``) and absolute http(s) URLs whose **exact**
    origin is on the allowlist. Rejected: credentials in the URL, non-http(s)
    schemes, foreign or prefix-spoofed origins, oversized or control-bearing
    values. Matching is on the normalized ``scheme://host[:port]`` triple —
    never a prefix of it.
    """
    if not candidate or len(candidate) > _RETURN_URL_MAX_LENGTH:
        return False
    if _has_forbidden_characters(candidate):
        return False
    if candidate.startswith("/"):
        return not candidate.startswith("//")
    try:
        parsed = urlsplit(candidate)
    except ValueError:  # malformed port, invalid IPv6 literal, ...
        return False
    if parsed.scheme.lower() not in _ALLOWED_RETURN_SCHEMES or not parsed.netloc:
        return False
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return False
    return _origin(parsed.scheme, parsed.netloc) in allowed_origins


def _validated_origin(origin: str) -> str:
    """Pin one allowlist entry to a bare http(s) origin (no path or secrets).

    An allowlist entry carrying a path, query, fragment, or userinfo would
    silently widen exact-origin matching to prefix matching; construction
    refuses it instead of guessing intent.
    """
    try:
        parsed = urlsplit(origin)
    except ValueError as exc:
        raise ValueError("allowed return origins must be bare http(s) origins") from exc
    if (
        parsed.scheme.lower() not in _ALLOWED_RETURN_SCHEMES
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("allowed return origins must be bare http(s) origins")
    return _origin(parsed.scheme, parsed.netloc)


def _validated_authorize_url(authorize_url: str) -> SplitResult:
    """Pin the provider authorize endpoint: absolute HTTPS, no query/fragment.

    The route appends its own fixed parameter set, so an approved URL that
    already carries a query or fragment is a configuration error, never a
    merge.
    """
    try:
        parsed = urlsplit(authorize_url)
    except ValueError as exc:
        raise ValueError("authorize_url must be an absolute HTTPS URL") from exc
    if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("authorize_url must be an absolute HTTPS URL without query or fragment")
    return parsed


def _validated_redirect_uri(redirect_uri: str) -> str:
    """Pin the registered callback URI: absolute http(s), no query/fragment.

    HTTP stays legal because the local development Hosted UI redirect is
    ``http://localhost:8000/oauth/callback`` (WIP 09 pin); the value must
    still match the app-client registration exactly, so parameters are
    refused at construction.
    """
    try:
        parsed = urlsplit(redirect_uri)
    except ValueError as exc:
        raise ValueError("redirect_uri must be an absolute http(s) URL") from exc
    if (
        parsed.scheme.lower() not in _ALLOWED_RETURN_SCHEMES
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("redirect_uri must be an absolute http(s) URL without query or fragment")
    return redirect_uri


def _code_challenge(code_verifier: str) -> str:
    """RFC 7636 S256 challenge: base64url(SHA-256(verifier)) without padding."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_oauth_router(
    storage: Storage,
    verifier: AccessTokenVerifier,
    token_endpoint: CognitoTokenEndpoint,
    profile_source: ProfileSource,
    session_manager: SessionManager,
    *,
    authorize_url: str,
    client_id: str,
    redirect_uri: str,
    landing_url: str,
    allowed_return_origins: Iterable[str],
    cookie_secure: bool = False,
) -> APIRouter:
    """Build the ``/oauth/login`` + ``/oauth/callback`` router (tasks 11 and 12).

    Every dependency is injected and every URL is approved configuration
    validated at construction (fail-fast :class:`ValueError`), so a
    misconfigured session boundary never serves a request and no import-time
    environment read happens (initial boot contract). ``cookie_secure``
    mirrors the deployment transport (implementation's ``FEEDNOW_COOKIE_SECURE``);
    the fixed ``HttpOnly; SameSite=Lax; Path=/`` policy lives with the
    session module, not here.
    """
    origins = frozenset(_validated_origin(origin) for origin in allowed_return_origins)
    if not origins:
        raise ValueError("allowed_return_origins must contain at least one origin")
    authorize = _validated_authorize_url(authorize_url)
    redirect = _validated_redirect_uri(redirect_uri)
    if not isinstance(client_id, str) or not client_id:
        raise ValueError("client_id must be a non-empty string")
    if not _is_allowed_return_url(landing_url, origins):
        raise ValueError("landing_url must be an allowed return URL")
    authorize_base = authorize.geturl()

    router = APIRouter(tags=["oauth"])

    @router.get(LOGIN_PATH, include_in_schema=False)
    async def oauth_login(request: Request) -> RedirectResponse:
        """Validate ``next``, store a single-use login state, redirect to Cognito."""
        next_param = request.query_params.get("next")
        return_url = landing_url if next_param is None else next_param
        if not _is_allowed_return_url(return_url, origins):
            # Fixed message: the rejected value is caller material and is
            # never echoed back (open-redirect hygiene, task 11 contract).
            raise HTTPException(status_code=400, detail=RETURN_URL_REJECTED_MESSAGE)
        state_id = secrets.token_urlsafe(_STATE_ID_BYTES)
        code_verifier = secrets.token_urlsafe(_CODE_VERIFIER_BYTES)
        storage.save_oauth_login_state(
            OAuthLoginState(
                state_id=state_id,
                code_verifier=code_verifier,
                return_url=return_url,
                expires_at=utc_now() + timedelta(seconds=LOGIN_STATE_TTL_SECONDS),
            )
        )
        query = urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect,
                "scope": OAUTH_SCOPE,
                "state": state_id,
                "code_challenge_method": "S256",
                "code_challenge": _code_challenge(code_verifier),
                **(
                    {"prompt": "select_account"}
                    if request.query_params.get("select_account") == "true"
                    else {}
                ),
            }
        )
        return RedirectResponse(url=f"{authorize_base}?{query}", status_code=302)

    @router.get(CALLBACK_PATH, include_in_schema=False)
    async def oauth_callback(request: Request) -> RedirectResponse:
        """Complete the code exchange and mint the application session.

        The step order (a)—(g) and the status mapping are the implementation
        contract; every failure raises a fixed-message
        :class:`~fastapi.HTTPException` that the frozen initial envelope
        renders (400 ``validation_error``, 401 ``unauthenticated``,
        403 ``forbidden``, 409 ``conflict``, 503 ``internal_error``).
        """
        query = request.query_params
        code = query.get("code")
        state_id = query.get("state")
        # (a) The provider redirected back with an error, or without the
        # pair this route requires: a fixed 401 — error/error_description
        # text is never echoed.
        if query.get("error") is not None or not code or not state_id:
            raise HTTPException(status_code=401, detail=PROVIDER_REJECTED_MESSAGE)
        # (b) Single-use consumption (get-and-delete): unknown, expired, or
        # replayed states all return None and never proceed further.
        login_state = storage.consume_oauth_login_state(state_id)
        if login_state is None:
            raise HTTPException(status_code=401, detail=LOGIN_STATE_INVALID_MESSAGE)
        # (c) Redeem the code with the stored verifier at the fixed token
        # endpoint. The redirect_uri must be the exact authorize-time value.
        try:
            access_token = token_endpoint.exchange(code, redirect, login_state.code_verifier)
        except TokenProviderUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        # (d) JWT validation remains mandatory before any profile or user
        # storage work: signature/issuer/client/expiry failures are 401, a
        # JWKS outage is 503, and neither touches the user tables.
        try:
            claims = verifier.verify(access_token)
        except TokenProviderUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except TokenValidationError as exc:
            raise HTTPException(status_code=401, detail=exc.reason) from exc
        # (e) Resolve-or-provision. Its profile provider is lazy and runs only
        # when this Cognito subject is new; known identities must not be
        # rejected because an upstream IdP later changes email verification.
        # On a miss, resolve_or_provision gates the fetched profile before any
        # storage write, preserving the verified-email provisioning rule.
        try:
            identity = resolve_or_provision(
                storage,
                claims,
                profile_provider=lambda: profile_source.fetch(access_token, claims.sub),
            )
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
        # (g) Re-validate the stored target (the allowlist may have changed
        # mid-journey) **before** issuing a session, then set the cookie.
        return_url = login_state.return_url
        if not _is_allowed_return_url(return_url, origins):
            raise HTTPException(status_code=400, detail=RETURN_URL_REJECTED_MESSAGE)
        session_id = session_manager.issue(identity.user.id)
        response = RedirectResponse(url=return_url, status_code=302)
        response.headers["Set-Cookie"] = build_session_cookie(
            session_id,
            max_age=session_manager.ttl_seconds,
            secure=cookie_secure,
        )
        return response

    return router


__all__ = [
    "CALLBACK_PATH",
    "LOGIN_PATH",
    "LOGIN_STATE_INVALID_MESSAGE",
    "LOGIN_STATE_TTL_SECONDS",
    "OAUTH_SCOPE",
    "PROVIDER_REJECTED_MESSAGE",
    "RETURN_URL_REJECTED_MESSAGE",
    "build_oauth_router",
]
