"""Local-only SQLite and Cognito composition root.

This module is selected exclusively by ``docker compose --profile cognito``.
It mounts the callback capture page needed by the host-side login script; the
production application factory never imports or mounts that route.
"""

from __future__ import annotations

import base64
import os

from fastapi import FastAPI

from app.api.keys import build_api_keys_router
from app.api.me import build_me_router
from app.api.members import build_members_router
from app.api.organizations import build_organizations_router
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper
from app.main import create_app
from app.storage.sqlite import open_sqlite_storage
from oauth_callback import build_oauth_callback_router


def _values(*names: str) -> tuple[str, ...]:
    """Return the first non-empty comma-separated local setting."""
    for name in names:
        values = tuple(
            dict.fromkeys(value.strip() for value in os.getenv(name, "").split(",") if value.strip())
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
    return create_app(
        routers=[
            build_me_router(storage, verifier),
            build_organizations_router(storage, verifier),
            build_members_router(storage, verifier),
            build_api_keys_router(storage, verifier, pepper),
            build_oauth_callback_router(),
        ]
    )


app = build_app()

