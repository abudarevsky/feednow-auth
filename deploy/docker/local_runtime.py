"""Local-only SQLite and Cognito composition root.

This module is selected exclusively by ``docker compose --profile cognito``.
It mounts the callback capture page needed by the host-side login script; the
production application factory never imports or mounts that route.
"""

from __future__ import annotations

import base64
import os
from urllib.parse import urlencode

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.api.keys import build_api_keys_router
from app.api.me import build_me_router
from app.api.members import build_members_router
from app.api.organizations import build_organizations_router
from app.auth.cognito import CognitoAccessTokenVerifier, CognitoUserInfoClient, ProfileSource
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper
from app.auth.session import SessionManager, SESSION_COOKIE_NAME
from app.auth.token_exchange import CognitoTokenEndpoint
from app.auth.dependencies import build_current_user
from app.main import create_app
from app.storage.sqlite import open_sqlite_storage
from app.api.oauth import build_oauth_router
from fastapi import APIRouter, Request, Response
from oauth_callback import build_oauth_cli_callback_router


def _values(*names: str) -> tuple[str, ...]:
    """Return the first non-empty comma-separated local setting."""
    for name in names:
        values = tuple(
            dict.fromkeys(
                value.strip() for value in os.getenv(name, "").split(",") if value.strip()
            )
        )
        if values:
            return values
    return ()


def _pepper() -> bytes:
    """Decode the local pepper without placing its value in an error message."""
    raw = os.getenv("FEEDNOW_PEPPER_SECRET", "")
    if not raw:
        raise RuntimeError("FEEDNOW_PEPPER_SECRET is required for local Cognito")
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise RuntimeError("FEEDNOW_PEPPER_SECRET must be valid base64") from exc


def _profile_source() -> ProfileSource | None:
    """Build the verified user-info client when the local endpoint is configured.

    Phase 11 task 5: first-login provisioning reads the email from the
    user-info profile, so ``cognito-login.sh`` needs
    ``FEEDNOW_COGNITO_USERINFO_URL`` (a bearer-only first login without it
    fails 401). Unset keeps the pre-Phase-11 composition shape.
    """
    url = os.getenv("FEEDNOW_COGNITO_USERINFO_URL", "").strip()
    if not url:
        domain = os.getenv("FEEDNOW_COGNITO_DOMAIN", "").strip().rstrip("/")
        if domain:
            url = f"{domain}/oauth2/userInfo"
    return CognitoUserInfoClient(url) if url else None


def build_app() -> FastAPI:
    """Build the local authenticated API over SQLite and Cognito JWKS."""
    issuers = _values("FEEDNOW_COGNITO_ISSUERS", "FEEDNOW_COGNITO_ISSUER")
    client_ids = _values("FEEDNOW_COGNITO_CLIENT_IDS", "FEEDNOW_COGNITO_CLIENT_ID")
    if not issuers or not client_ids:
        raise RuntimeError(
            "FEEDNOW_COGNITO_ISSUER(S) and FEEDNOW_COGNITO_CLIENT_ID(S) are required"
        )

    storage = open_sqlite_storage(os.getenv("FEEDNOW_SQLITE_PATH", "/data/feednow-auth.db"))
    verifier = CognitoAccessTokenVerifier(CognitoJwksSource(issuers), issuers, client_ids)
    pepper = StaticPepper(_pepper())
    profile_source = _profile_source()
    session_manager = SessionManager(storage, int(os.getenv("FEEDNOW_SESSION_TTL_SECONDS", "28800")))
    domain = os.getenv("FEEDNOW_COGNITO_DOMAIN", "").rstrip("/")
    client_id = os.getenv("FEEDNOW_COGNITO_CLIENT_ID", "")
    redirect_uri = os.getenv("FEEDNOW_COGNITO_REDIRECT_URI", "http://localhost:8000/oauth/callback")
    frontend_url = os.getenv("FEEDNOW_FRONTEND_URL", "http://localhost:3000")
    logout_uri = os.getenv("FEEDNOW_COGNITO_LOGOUT_URI", "http://localhost:8000/logout")
    if not domain or not client_id or profile_source is None:
        missing = []
        if not domain:
            missing.append("FEEDNOW_COGNITO_DOMAIN")
        if not client_id:
            missing.append("FEEDNOW_COGNITO_CLIENT_ID")
        if profile_source is None:
            missing.append("FEEDNOW_COGNITO_USERINFO_URL (or FEEDNOW_COGNITO_DOMAIN)")
        raise RuntimeError("Missing local Cognito configuration: " + ", ".join(missing))
    session_router = APIRouter(tags=["local-session"])
    local_user = build_current_user(storage, verifier, profile_source, session_manager)

    # Browser paths have one /api prefix stripped by the Vite proxy, matching
    # the backend's established /v1 route convention.
    @session_router.get("/v1/services", include_in_schema=False)
    def services(request: Request) -> dict[str, list[dict[str, str]]]:
        local_user(request)
        return {"items": [{
            "id": "vispector", "name": "Vispector",
            "description": "Visual analysis and inspection",
            "url": os.getenv("FEEDNOW_VISPECTOR_URL", "http://localhost:5173"),
            "status": "active",
        }]}

    @session_router.post("/logout", include_in_schema=False)
    def logout(response: Response) -> dict[str, str]:
        # The UI clears the app cookie here, then performs a top-level
        # navigation to Cognito so the hosted-login cookie is cleared too.
        query = urlencode({"client_id": client_id, "logout_uri": logout_uri})
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return {"logout_url": f"{domain}/logout?{query}"}

    @session_router.get("/logout", include_in_schema=False)
    def finish_logout() -> RedirectResponse:
        """Return Cognito's allowed sign-out redirect to the local UI."""
        return RedirectResponse(f"{frontend_url}/login", status_code=302)

    return create_app(
        routers=[
            build_me_router(storage, verifier, profile_source=profile_source, session_manager=session_manager),
            build_organizations_router(storage, verifier, profile_source=profile_source, session_manager=session_manager),
            build_members_router(storage, verifier, profile_source=profile_source, session_manager=session_manager),
            build_api_keys_router(storage, verifier, pepper, profile_source=profile_source, session_manager=session_manager),
            build_oauth_router(
                storage, verifier, CognitoTokenEndpoint(
                    f"{domain}/oauth2/token", client_id,
                    client_secret=os.getenv("FEEDNOW_COGNITO_CLIENT_SECRET") or None,
                ),
                profile_source, session_manager, authorize_url=f"{domain}/oauth2/authorize",
                client_id=client_id, redirect_uri=redirect_uri, landing_url=f"{frontend_url}/account",
                allowed_return_origins=(frontend_url,), cookie_secure=False,
            ),
            build_oauth_cli_callback_router(),
            session_router,
        ]
    )


app = build_app()
