"""Local-only storage and Cognito composition root.

This module is selected exclusively by ``docker compose --profile cognito``.
It mounts the callback capture page needed by the host-side login script; the
production application factory never imports or mounts that route.
"""

from __future__ import annotations

import base64
import os
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, HTTPException, Request
from oauth_callback import build_oauth_cli_callback_router

from app.api.admin import build_admin_router
from app.api.keys import build_api_keys_router
from app.api.me import build_me_router
from app.api.members import build_members_router
from app.api.oauth import build_oauth_router
from app.api.organizations import build_organizations_router
from app.api.service_auth import build_service_auth_router
from app.api.session_support import build_session_support_router, install_session_csrf_middleware
from app.auth.api_key_auth import ApiKeyAuthenticationError, verify_api_key
from app.auth.cognito import CognitoAccessTokenVerifier, CognitoUserInfoClient, ProfileSource
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper
from app.auth.session import SessionManager
from app.auth.token_exchange import CognitoTokenEndpoint
from app.main import create_app
from app.models.service_authorization import ServiceRegistration
from app.storage.factory import create_storage, storage_settings_from_env


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

    First-login provisioning reads email from the user-info profile, so
    ``cognito-login.sh`` needs
    ``FEEDNOW_COGNITO_USERINFO_URL`` (a bearer-only first login without it
    fails 401). When unset, the Cognito domain is used to derive the endpoint.
    """
    url = os.getenv("FEEDNOW_COGNITO_USERINFO_URL", "").strip()
    if not url:
        domain = os.getenv("FEEDNOW_COGNITO_DOMAIN", "").strip().rstrip("/")
        if domain:
            url = f"{domain}/oauth2/userInfo"
    return CognitoUserInfoClient(url) if url else None


def build_app() -> FastAPI:
    """Build the local authenticated API over configured storage and Cognito JWKS."""
    issuers = _values("FEEDNOW_COGNITO_ISSUERS", "FEEDNOW_COGNITO_ISSUER")
    client_ids = _values("FEEDNOW_COGNITO_CLIENT_IDS", "FEEDNOW_COGNITO_CLIENT_ID")
    if not issuers or not client_ids:
        raise RuntimeError(
            "FEEDNOW_COGNITO_ISSUER(S) and FEEDNOW_COGNITO_CLIENT_ID(S) are required"
        )

    storage_environment = dict(os.environ)
    storage_environment.setdefault("FEEDNOW_STORAGE_BACKEND", "sqlite")
    storage_environment.setdefault("FEEDNOW_SQLITE_PATH", "/data/feednow-auth.db")
    storage_settings = storage_settings_from_env(storage_environment)
    storage = create_storage(storage_settings)
    verifier = CognitoAccessTokenVerifier(CognitoJwksSource(issuers), issuers, client_ids)
    pepper = StaticPepper(_pepper())
    profile_source = _profile_source()
    session_manager = SessionManager(
        storage, int(os.getenv("FEEDNOW_SESSION_TTL_SECONDS", "28800"))
    )
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
    service_url = os.getenv("FEEDNOW_VISPECTOR_URL", "").strip()
    service_registration = None
    if service_url:
        parsed_service_url = urlsplit(service_url)
        if (
            parsed_service_url.scheme not in {"http", "https"}
            or not parsed_service_url.netloc
            or parsed_service_url.path not in {"", "/"}
            or parsed_service_url.query
            or parsed_service_url.fragment
            or parsed_service_url.username is not None
            or parsed_service_url.password is not None
        ):
            raise RuntimeError("FEEDNOW_VISPECTOR_URL must be an absolute origin URL")
        enabled_raw = os.getenv("FEEDNOW_VISPECTOR_ENABLED", "true").strip().lower()
        if enabled_raw not in {"true", "false"}:
            raise RuntimeError("FEEDNOW_VISPECTOR_ENABLED must be true or false")
        service_registration = ServiceRegistration(
            service_id="vispector",
            display_name="Vispector",
            allowed_origins=(f"{parsed_service_url.scheme}://{parsed_service_url.netloc}",),
            callback_path=os.getenv(
                "FEEDNOW_VISPECTOR_CALLBACK_PATH", "/auth/callback"
            ).strip(),
            enabled=enabled_raw == "true",
            allowed_permissions=_values("FEEDNOW_VISPECTOR_PERMISSIONS")
            or ("projects:read", "projects:write", "inspect"),
            credential_reference="local://feednow-vispector-service-secret",
        )
    session_router = APIRouter(tags=["local-session"])

    # Browser paths have one /api prefix stripped by the Vite proxy, matching
    # the backend's established /v1 route convention.
    @session_router.get("/v1/local/vispector/protected", include_in_schema=False)
    def protected_vispector_probe(request: Request) -> dict[str, str]:
        """Local acceptance endpoint proving regular API-key authentication."""
        authorization = request.headers.get("authorization", "")
        scheme, _, literal = authorization.partition(" ")
        if scheme.lower() != "bearer" or not literal:
            raise HTTPException(status_code=401, detail="invalid API key credentials")
        try:
            verified = verify_api_key(storage, pepper, literal)
        except ApiKeyAuthenticationError as exc:
            raise HTTPException(status_code=401, detail="invalid API key credentials") from exc
        if verified.api_key.service_id != "vispector":
            raise HTTPException(status_code=403, detail="service access denied")
        return {"service_id": "vispector", "status": "authenticated"}

    routers = [
        build_me_router(
            storage, verifier, profile_source=profile_source, session_manager=session_manager
        ),
        build_organizations_router(
            storage, verifier, profile_source=profile_source, session_manager=session_manager
        ),
        build_members_router(
            storage, verifier, profile_source=profile_source, session_manager=session_manager
        ),
        build_api_keys_router(
            storage,
            verifier,
            pepper,
            profile_source=profile_source,
            session_manager=session_manager,
        ),
        build_service_auth_router(
            storage,
            pepper,
            service_credential=os.getenv("FEEDNOW_VISPECTOR_SERVICE_SECRET", ""),
            service_registration=(
                service_registration if os.getenv("FEEDNOW_VISPECTOR_SERVICE_SECRET", "") else None
            ),
            session_manager=session_manager,
        ),
        build_oauth_router(
            storage,
            verifier,
            CognitoTokenEndpoint(
                f"{domain}/oauth2/token",
                client_id,
                client_secret=os.getenv("FEEDNOW_COGNITO_CLIENT_SECRET") or None,
            ),
            profile_source,
            session_manager,
            authorize_url=f"{domain}/oauth2/authorize",
            client_id=client_id,
            redirect_uri=redirect_uri,
            landing_url=f"{frontend_url}/account",
            allowed_return_origins=(frontend_url,),
            cookie_secure=False,
        ),
        build_oauth_cli_callback_router(),
        session_router,
        build_session_support_router(
            storage,
            verifier,
            pepper,
            profile_source,
            session_manager,
            cognito_domain=domain,
            client_id=client_id,
            frontend_url=frontend_url,
            cookie_secure=os.getenv("FEEDNOW_COOKIE_SECURE", "false").lower() == "true",
            cognito_logout_uri=logout_uri,
        ),
    ]
    routers.insert(
        0,
        build_admin_router(
            storage,
            verifier,
            profile_source=profile_source,
            session_manager=session_manager,
            pepper_source=pepper,
        ),
    )

    environment = os.getenv("FEEDNOW_ENV", "local").strip().lower()
    application = create_app(routers=routers, docs_enabled=environment != "prod")

    install_session_csrf_middleware(application, pepper, session_manager)
    return application


app = build_app()
