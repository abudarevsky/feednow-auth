#!/usr/bin/env python3
"""Lambda composition root for feednow-auth (Phase 07 task 5).

Boot contract (the Phase 01 rule, applied to the deployment entrypoint):
**importing this module reads no configuration and performs no AWS call.**
Everything happens in :func:`build_app`, which the module-level
:class:`~mangum.Mangum` adapter invokes through :class:`_LazyApp` on the
first request — Lambda's cold start. The five required ``FEEDNOW_*`` inputs
are read there, never at import, so a misconfigured deployment fails on the
first invocation with a message naming the missing key.

Phase 11 task 13 adds an **all-or-nothing session gate**: the seven
``SESSION_ENV_KEYS`` below. When every one is present, ``build_app`` also
mounts ``/oauth/login`` + ``/oauth/callback`` and passes the verified
user-info client to the four §14 routers; when **none** are present the
deployed surface is exactly the pre-phase-11 app (the rollback seam); a
partial set fails cold start naming the missing keys.

Wiring (spec §17, breakdown task 5, extended by task 13)::

    RuntimeConfig (env, with optional SessionRuntimeConfig)
      -> CognitoJwksSource -> CognitoAccessTokenVerifier
      -> open_dynamodb_storage(region=..., table_prefix=...)
      -> SecretsManagerPepper(FEEDNOW_PEPPER_SECRET_ID)   # one GetSecretValue
      -> build_me_router / build_organizations_router / build_members_router
         / build_api_keys_router(storage, verifier, pepper, profile_source)
      -> [gated] build_oauth_router(..., CognitoTokenEndpoint,
         CognitoUserInfoClient, SessionManager, approved URLs)
      -> create_app(routers=[...])

``src/app`` is not modified: this module is the only place that knows AWS
SDKs exist, which is what keeps the repo-wide no-``boto3`` proof green.

Stage note: the breakdown pins the adapter to the HTTP API ``$default``
stage. No released Mangum (0.5—0.22) accepts an ``api_stage`` keyword —
HTTP API v2 events carry the stage inside the payload and Mangum infers the
handler from it — so the stage is recorded as :data:`API_STAGE` (the value
the task-6 ``HttpApi`` creates) and the adapter is built with the plain
application instance.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from fastapi import FastAPI
from mangum import Mangum
from secrets_pepper import PEPPER_SECRET_ID_ENV, SecretsManagerPepper

from app.api.keys import build_api_keys_router
from app.api.me import build_me_router
from app.api.members import build_members_router
from app.api.oauth import build_oauth_router
from app.api.organizations import build_organizations_router
from app.auth.cognito import (
    AccessTokenVerifier,
    CognitoAccessTokenVerifier,
    CognitoUserInfoClient,
    ProfileSource,
)
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import PepperSource
from app.auth.session import SessionManager
from app.auth.token_exchange import CognitoTokenEndpoint
from app.main import create_app
from app.storage.contract import Storage
from app.storage.dynamodb import DynamoDbStorage, open_dynamodb_storage

#: The HTTP API stage the function is mounted on (Phase 07 task 6).
API_STAGE: Final = "$default"

#: Runtime configuration keys, all required, all non-secret names.
REGION_ENV: Final = "FEEDNOW_DYNAMODB_REGION"
TABLE_PREFIX_ENV: Final = "FEEDNOW_TABLE_PREFIX"
ISSUERS_ENV: Final = "FEEDNOW_COGNITO_ISSUERS"
CLIENT_IDS_ENV: Final = "FEEDNOW_COGNITO_CLIENT_IDS"

#: Every key :meth:`RuntimeConfig.from_environ` requires, in order.
REQUIRED_ENV_KEYS: Final = (
    REGION_ENV,
    TABLE_PREFIX_ENV,
    ISSUERS_ENV,
    CLIENT_IDS_ENV,
    PEPPER_SECRET_ID_ENV,
)

#: Phase 11 task 13: the session-flow gate. All seven must be present to
#: mount ``/oauth/login`` + ``/oauth/callback`` and wire user-info profile
#: provisioning; all seven absent is the rollback seam (pre-phase-11
#: surface); a partial set fails cold start naming the missing keys.
AUTHORIZE_URL_ENV: Final = "FEEDNOW_COGNITO_AUTHORIZE_URL"
TOKEN_ENDPOINT_ENV: Final = "FEEDNOW_COGNITO_TOKEN_ENDPOINT"
USERINFO_URL_ENV: Final = "FEEDNOW_COGNITO_USERINFO_URL"
OAUTH_REDIRECT_URL_ENV: Final = "FEEDNOW_OAUTH_REDIRECT_URL"
ALLOWED_RETURN_ORIGINS_ENV: Final = "FEEDNOW_ALLOWED_RETURN_ORIGINS"
SESSION_TTL_SECONDS_ENV: Final = "FEEDNOW_SESSION_TTL_SECONDS"
COOKIE_SECURE_ENV: Final = "FEEDNOW_COOKIE_SECURE"

SESSION_ENV_KEYS: Final = (
    AUTHORIZE_URL_ENV,
    TOKEN_ENDPOINT_ENV,
    USERINFO_URL_ENV,
    OAUTH_REDIRECT_URL_ENV,
    ALLOWED_RETURN_ORIGINS_ENV,
    SESSION_TTL_SECONDS_ENV,
    COOKIE_SECURE_ENV,
)


def _split_list(raw: str) -> tuple[str, ...]:
    """Normalize a comma-separated runtime input, preserving order."""
    entries = (item.strip() for item in raw.split(","))
    return tuple(dict.fromkeys(entry for entry in entries if entry))


@dataclass(frozen=True)
class SessionRuntimeConfig:
    """The seven session-flow inputs (task 13), parsed only when the gate is on.

    URL shapes are pinned further by the oauth router and the Cognito
    clients at construction (fail-fast at cold start); this dataclass only
    proves every key is present, non-blank, and of the right kind.
    """

    authorize_url: str
    token_endpoint_url: str
    userinfo_url: str
    redirect_uri: str
    allowed_return_origins: tuple[str, ...]
    session_ttl_seconds: int
    cookie_secure: bool


def _session_config(env: Mapping[str, str]) -> SessionRuntimeConfig | None:
    """Parse the all-or-nothing session gate from ``env``.

    Returns ``None`` when **no** session key is present — the rollback
    seam that keeps the deployed surface exactly pre-phase-11. A partial
    set is a misconfiguration, never a silent downgrade: the fixed error
    names only the missing keys (never any values).
    """
    raw = {key: (env.get(key) or "").strip() for key in SESSION_ENV_KEYS}
    if not any(raw.values()):
        return None
    missing = [key for key in SESSION_ENV_KEYS if not raw[key]]
    if missing:
        raise RuntimeError(f"missing required session configuration: {', '.join(missing)}")
    origins = _split_list(raw[ALLOWED_RETURN_ORIGINS_ENV])
    if not origins:
        raise RuntimeError(f"missing required session configuration: {ALLOWED_RETURN_ORIGINS_ENV}")
    try:
        ttl_seconds = int(raw[SESSION_TTL_SECONDS_ENV])
    except ValueError:
        # ``from None``: the int() failure quotes the offending value, and
        # the task-13 contract is key names only — never values (the same
        # suppression secrets_pepper applies to payload documents).
        raise RuntimeError(
            f"invalid session configuration: {SESSION_TTL_SECONDS_ENV} must be a positive integer"
        ) from None
    if ttl_seconds <= 0:
        raise RuntimeError(
            f"invalid session configuration: {SESSION_TTL_SECONDS_ENV} must be a positive integer"
        )
    cookie_secure = raw[COOKIE_SECURE_ENV].lower()
    if cookie_secure not in ("true", "false"):
        raise RuntimeError(
            f"invalid session configuration: {COOKIE_SECURE_ENV} must be true or false"
        )
    return SessionRuntimeConfig(
        authorize_url=raw[AUTHORIZE_URL_ENV],
        token_endpoint_url=raw[TOKEN_ENDPOINT_ENV],
        userinfo_url=raw[USERINFO_URL_ENV],
        redirect_uri=raw[OAUTH_REDIRECT_URL_ENV],
        allowed_return_origins=origins,
        session_ttl_seconds=ttl_seconds,
        cookie_secure=cookie_secure == "true",
    )


@dataclass(frozen=True)
class RuntimeConfig:
    """The five injected runtime inputs plus the optional session gate.

    Parsed and validated in :meth:`from_environ` — never at import.
    ``session`` is ``None`` whenever the task-13 gate keys are all absent
    (pre-phase-11 rollback surface).
    """

    region: str
    table_prefix: str
    cognito_issuers: tuple[str, ...]
    cognito_client_ids: tuple[str, ...]
    pepper_secret_id: str
    session: SessionRuntimeConfig | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> RuntimeConfig:
        """Read and validate the runtime inputs from ``environ``.

        ``environ`` defaults to :data:`os.environ`; tests pass a plain
        mapping. Every core key must yield at least one value: the
        allowlists are checked **after** comma normalization, so a
        blank-but-present ``FEEDNOW_COGNITO_ISSUERS`` fails here naming the
        key instead of surfacing deep inside the verifier. The seven session
        keys are all-or-nothing (:func:`_session_config`): none present
        yields the pre-phase-11 configuration, a partial set fails naming
        the missing keys. Failures name the offending keys and nothing
        else — no values, no defaults.
        """
        env = os.environ if environ is None else environ
        region = (env.get(REGION_ENV) or "").strip()
        table_prefix = (env.get(TABLE_PREFIX_ENV) or "").strip()
        pepper_secret_id = (env.get(PEPPER_SECRET_ID_ENV) or "").strip()
        issuers = _split_list(env.get(ISSUERS_ENV) or "")
        client_ids = _split_list(env.get(CLIENT_IDS_ENV) or "")
        missing = [
            name
            for name, value in (
                (REGION_ENV, region),
                (TABLE_PREFIX_ENV, table_prefix),
                (ISSUERS_ENV, issuers),
                (CLIENT_IDS_ENV, client_ids),
                (PEPPER_SECRET_ID_ENV, pepper_secret_id),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(f"missing required runtime configuration: {', '.join(missing)}")
        return cls(
            region=region,
            table_prefix=table_prefix,
            cognito_issuers=issuers,
            cognito_client_ids=client_ids,
            pepper_secret_id=pepper_secret_id,
            session=_session_config(env),
        )


# -- default component factories (the only AWS-touching code paths) ----------


def _default_storage(
    config: RuntimeConfig, *, dynamodb_resource: Any | None = None
) -> DynamoDbStorage:
    """Open the Phase 06 adapter for this environment (construction does no I/O)."""
    return open_dynamodb_storage(
        region=config.region,
        table_prefix=config.table_prefix,
        dynamodb_resource=dynamodb_resource,
    )


def _default_verifier(config: RuntimeConfig) -> AccessTokenVerifier:
    """Bind the issuer-scoped JWKS source to the Cognito access-token verifier."""
    return CognitoAccessTokenVerifier(
        CognitoJwksSource(config.cognito_issuers),
        config.cognito_issuers,
        config.cognito_client_ids,
    )


def _default_pepper(config: RuntimeConfig) -> PepperSource:
    """The Secrets Manager source: one ``GetSecretValue`` per container."""
    return SecretsManagerPepper(config.pepper_secret_id)


def build_app(
    *,
    environ: Mapping[str, str] | None = None,
    config: RuntimeConfig | None = None,
    storage_factory: Callable[..., Storage] = _default_storage,
    verifier_factory: Callable[[RuntimeConfig], AccessTokenVerifier] = _default_verifier,
    pepper_factory: Callable[[RuntimeConfig], PepperSource] = _default_pepper,
) -> FastAPI:
    """Compose the ASGI application — the cold-start entry point.

    Args:
        environ: Configuration source; defaults to :data:`os.environ`.
        config: Pre-parsed configuration; when given, ``environ`` is never
            read (the injection seam the unit proofs use).
        storage_factory / verifier_factory / pepper_factory: Component
            seams. The defaults build the real AWS-backed collaborators;
            tests inject fakes so route mounting is provable without I/O.

    Returns:
        The :func:`~app.main.create_app` application with exactly the four
        §14 routers mounted on top of the Phase 01 skeleton — plus, when
        the task-13 session gate is fully configured, the
        ``/oauth/login`` + ``/oauth/callback`` router and a verified
        user-info profile source on the four §14 routers. With the gate
        keys absent the returned surface is exactly the pre-phase-11 app.
    """
    resolved = config if config is not None else RuntimeConfig.from_environ(environ)
    storage = storage_factory(resolved)
    verifier = verifier_factory(resolved)
    pepper_source = pepper_factory(resolved)
    # Force the single pepper read *here*, at cold start: an unreadable or
    # undersized pepper must fail the invocation, never a first request.
    pepper_source.current()
    session = resolved.session
    userinfo_client = CognitoUserInfoClient(session.userinfo_url) if session is not None else None
    # Task 4/5 contract: with no profile source the bearer chain behaves
    # exactly as it did before Phase 11.
    profile_source: ProfileSource | None = userinfo_client
    routers = [
        build_me_router(storage, verifier, profile_source=profile_source),
        build_organizations_router(storage, verifier, profile_source=profile_source),
        build_members_router(storage, verifier, profile_source=profile_source),
        build_api_keys_router(storage, verifier, pepper_source, profile_source=profile_source),
    ]
    if session is not None and userinfo_client is not None:
        # The session boundary rides on the single configured app client
        # (the deployed pool registers one Hosted UI client; task 15 pins
        # its settings), and the first allowed return origin is the
        # default landing target for a bare ``/oauth/login``.
        client_id = resolved.cognito_client_ids[0]
        routers.append(
            build_oauth_router(
                storage,
                verifier,
                CognitoTokenEndpoint(session.token_endpoint_url, client_id),
                userinfo_client,
                SessionManager(storage, session.session_ttl_seconds),
                authorize_url=session.authorize_url,
                client_id=client_id,
                redirect_uri=session.redirect_uri,
                landing_url=session.allowed_return_origins[0],
                allowed_return_origins=session.allowed_return_origins,
                cookie_secure=session.cookie_secure,
            )
        )
    return create_app(routers=routers)


class _LazyApp:
    """ASGI 3 proxy that defers :func:`build_app` to the first invocation.

    Mangum stores the application instance at construction time, so a
    module-level ``handler`` can only be import-safe if the real app is
    resolved on first use. Resolution happens once per container under a
    lock; every later call is a plain attribute read.
    """

    def __init__(self, factory: Callable[[], FastAPI] = build_app) -> None:
        self._factory = factory
        self._app: FastAPI | None = None
        self._lock = threading.Lock()

    @property
    def built(self) -> bool:
        """True once the real application has been composed (test seam)."""
        return self._app is not None

    def _resolve(self) -> FastAPI:
        with self._lock:
            if self._app is None:
                self._app = self._factory()
        return self._app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        await self._resolve()(scope, receive, send)


#: Module-level application proxy: import-safe, composed on first request.
app = _LazyApp()

#: The Lambda handler (task 6 points ``Function.handler`` at ``handler.handler``).
handler = Mangum(app)


__all__ = [
    "API_STAGE",
    "REQUIRED_ENV_KEYS",
    "SESSION_ENV_KEYS",
    "RuntimeConfig",
    "SessionRuntimeConfig",
    "app",
    "build_app",
    "handler",
]
