"""Session endpoints shared by local and AWS application runtimes."""

from __future__ import annotations

import hashlib
import hmac
import os
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from app.auth.cognito import AccessTokenVerifier, ProfileSource
from app.auth.dependencies import build_current_user
from app.auth.pepper import PepperSource
from app.auth.session import SESSION_COOKIE_NAME, SessionManager, read_session_cookie
from app.models.errors import Error, ErrorCode
from app.storage.contract import Storage


def session_csrf_token(secret: bytes, session_id: str) -> str:
    """Derive the readable double-submit token for an opaque session."""
    return hmac.new(secret, f"feednow-csrf:{session_id}".encode(), hashlib.sha256).hexdigest()


def build_session_support_router(
    storage: Storage,
    verifier: AccessTokenVerifier,
    pepper: PepperSource,
    profile_source: ProfileSource,
    session_manager: SessionManager,
    *,
    cognito_domain: str,
    client_id: str,
    frontend_url: str,
    cookie_secure: bool,
    cognito_logout_uri: str | None = None,
) -> APIRouter:
    """Build authenticated services, CSRF bootstrap, and Cognito logout routes."""
    router = APIRouter(tags=["account-session"])
    current_user = build_current_user(storage, verifier, profile_source, session_manager)
    domain = cognito_domain.rstrip("/")
    logout_uri = cognito_logout_uri or f"{frontend_url.rstrip('/')}/login"
    login_url = f"{frontend_url.rstrip('/')}/login"

    @router.get("/v1/services", include_in_schema=False)
    def services(request: Request) -> dict[str, list[dict[str, str]]]:
        current_user(request)
        service_url = os.getenv("FEEDNOW_VISPECTOR_URL", "").strip()
        if not service_url:
            return {"items": []}
        return {
            "items": [
                {
                    "id": "vispector",
                    "name": "Vispector",
                    "description": "Visual analysis and inspection",
                    "url": service_url,
                    "status": "active",
                }
            ]
        }

    @router.get("/v1/csrf", include_in_schema=False, status_code=204)
    def csrf_bootstrap(request: Request, response: Response) -> Response:
        current_user(request)
        session_id = read_session_cookie(request)
        if session_id is None:
            raise HTTPException(status_code=401, detail="session is required")
        token = session_csrf_token(pepper.current(), session_id)
        response.set_cookie(
            "feednow_csrf",
            token,
            max_age=session_manager.ttl_seconds,
            path="/",
            secure=cookie_secure,
            httponly=False,
            samesite="strict",
        )
        response.status_code = 204
        return response

    @router.post("/logout", include_in_schema=False)
    def logout(response: Response) -> dict[str, str]:
        response.delete_cookie(
            SESSION_COOKIE_NAME, path="/", secure=cookie_secure, httponly=True, samesite="lax"
        )
        response.delete_cookie(
            "feednow_csrf", path="/", secure=cookie_secure, httponly=False, samesite="strict"
        )
        query = urlencode({"client_id": client_id, "logout_uri": logout_uri})
        return {"logout_url": f"{domain}/logout?{query}"}

    @router.get("/logout", include_in_schema=False)
    def finish_logout() -> RedirectResponse:
        return RedirectResponse(login_url, status_code=302)

    return router


def install_session_csrf_middleware(
    application, pepper: PepperSource, session_manager: SessionManager
) -> None:
    """Require the session-bound double-submit token on authenticated writes."""

    @application.middleware("http")
    async def enforce_session_csrf(request: Request, call_next):
        session_id = read_session_cookie(request)
        unsafe = request.method.upper() not in {"GET", "HEAD", "OPTIONS"}
        if (
            unsafe
            and request.url.path.startswith("/v1/")
            and not request.url.path.startswith("/v1/service-auth/")
            and session_id
            and session_manager.verify(session_id)
        ):
            expected = session_csrf_token(pepper.current(), session_id)
            if not hmac.compare_digest(
                request.cookies.get("feednow_csrf", ""), expected
            ) or not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), expected):
                error = Error(
                    code=ErrorCode.FORBIDDEN,
                    message="CSRF validation failed",
                    request_id=request.headers.get("X-Request-ID"),
                )
                return JSONResponse(status_code=403, content=error.model_dump(mode="json"))
        return await call_next(request)
