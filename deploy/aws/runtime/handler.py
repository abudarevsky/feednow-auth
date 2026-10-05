#!/usr/bin/env python3
"""AWS Lambda composition root for feednow-auth.

Importing this module reads no configuration and performs no AWS calls.
``build_app`` validates runtime settings, constructs the DynamoDB and Cognito
adapters, and mounts the shared account routers. Production CDK supplies all
seven session settings; partial configuration fails during cold start. The
lazy Mangum adapter composes the application on the first invocation.

Local Docker and AWS share route and domain logic; only storage and cloud
resource construction differ. See ``docs/operations.md`` for deployment and
runtime configuration.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, cast
from urllib.parse import urlsplit

from fastapi import FastAPI
from kms_encrypted_cognito_client_secret import (
    COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV,
    KmsEncryptedCognitoClientSecret,
)
from kms_encrypted_pepper import (
    ENVIRONMENT_ENV,
    PEPPER_CIPHERTEXT_ENV,
    KmsEncryptedPepper,
)
from kms_encrypted_service_credential import (
    SERVICE_CREDENTIAL_CIPHERTEXT_ENV,
    KmsEncryptedServiceCredential,
)
from mangum import Mangum

from app.api.admin import build_admin_router
from app.api.keys import build_api_keys_router
from app.api.me import build_me_router
from app.api.members import build_members_router
from app.api.oauth import build_oauth_router
from app.api.organizations import build_organizations_router
from app.api.service_auth import build_service_auth_router
from app.api.session_support import build_session_support_router, install_session_csrf_middleware
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
from app.models.service_authorization import ServiceRegistration
from app.services.organization_onboarding import dispatch_organization_onboarding
from app.storage.contract import Storage
from app.storage.dynamodb import DynamoDbStorage, open_dynamodb_storage
from app.storage.local_admin import LocalAdminStorage

#: The HTTP API stage the function is mounted on.
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
    ENVIRONMENT_ENV,
    PEPPER_CIPHERTEXT_ENV,
)

#: All seven settings must be present to mount the OAuth session flow and
#: verified-profile provisioning; a partial set fails cold start.
AUTHORIZE_URL_ENV: Final = "FEEDNOW_COGNITO_AUTHORIZE_URL"
TOKEN_ENDPOINT_ENV: Final = "FEEDNOW_COGNITO_TOKEN_ENDPOINT"
USERINFO_URL_ENV: Final = "FEEDNOW_COGNITO_USERINFO_URL"
OAUTH_REDIRECT_URL_ENV: Final = "FEEDNOW_OAUTH_REDIRECT_URL"
ALLOWED_RETURN_ORIGINS_ENV: Final = "FEEDNOW_ALLOWED_RETURN_ORIGINS"
SESSION_TTL_SECONDS_ENV: Final = "FEEDNOW_SESSION_TTL_SECONDS"
COOKIE_SECURE_ENV: Final = "FEEDNOW_COOKIE_SECURE"
VISPECTOR_CALLBACK_PATH_ENV: Final = "FEEDNOW_VISPECTOR_CALLBACK_PATH"
VISPECTOR_ENABLED_ENV: Final = "FEEDNOW_VISPECTOR_ENABLED"
VISPECTOR_PERMISSIONS_ENV: Final = "FEEDNOW_VISPECTOR_PERMISSIONS"
VISPECTOR_URL_ENV: Final = "FEEDNOW_VISPECTOR_URL"

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
    """The seven session-flow inputs (implementation), parsed only when the gate is on.

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
    seam that keeps the deployed surface exactly pre-capability-11. A partial
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
        # sanitized KMS adapter applies to provider failures).
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


def _service_registration(env: Mapping[str, str]) -> ServiceRegistration | None:
    """Resolve the initial Vispector registration from public operator settings."""
    service_url = (env.get(VISPECTOR_URL_ENV) or "").strip()
    if not service_url:
        return None
    try:
        parsed = urlsplit(service_url)
    except ValueError:
        raise RuntimeError(f"invalid service registration: {VISPECTOR_URL_ENV}") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise RuntimeError(f"invalid service registration: {VISPECTOR_URL_ENV}")
    enabled_raw = (env.get(VISPECTOR_ENABLED_ENV) or "true").strip().lower()
    if enabled_raw not in {"true", "false"}:
        raise RuntimeError(f"invalid service registration: {VISPECTOR_ENABLED_ENV}")
    permissions = _split_list(
        env.get(VISPECTOR_PERMISSIONS_ENV) or "projects:read,projects:write,inspect"
    )
    callback_path = (env.get(VISPECTOR_CALLBACK_PATH_ENV) or "/auth/callback").strip()
    try:
        return ServiceRegistration(
            service_id="vispector",
            display_name="Vispector",
            allowed_origins=(f"{parsed.scheme}://{parsed.netloc}",),
            callback_path=callback_path,
            enabled=enabled_raw == "true",
            allowed_permissions=permissions,
            credential_reference="feednow/vispector/service-credential",
        )
    except ValueError:
        raise RuntimeError("invalid service registration configuration") from None


@dataclass(frozen=True)
class RuntimeConfig:
    """The five injected runtime inputs plus the optional session gate.

    Parsed and validated in :meth:`from_environ` — never at import.
    ``session`` is ``None`` whenever the implementation gate keys are all absent
    (pre-capability-11 rollback surface).
    """

    region: str
    table_prefix: str
    cognito_issuers: tuple[str, ...]
    cognito_client_ids: tuple[str, ...]
    environment: str
    pepper_ciphertext_b64: str
    session: SessionRuntimeConfig | None = None
    service_registration: ServiceRegistration | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> RuntimeConfig:
        """Read and validate the runtime inputs from ``environ``.

        ``environ`` defaults to :data:`os.environ`; tests pass a plain
        mapping. Every core key must yield at least one value: the
        allowlists are checked **after** comma normalization, so a
        blank-but-present ``FEEDNOW_COGNITO_ISSUERS`` fails here naming the
        key instead of surfacing deep inside the verifier. The seven session
        keys are all-or-nothing (:func:`_session_config`): none present
        yields the pre-capability-11 configuration, a partial set fails naming
        the missing keys. Failures name the offending keys and nothing
        else — no values, no defaults.
        """
        env = os.environ if environ is None else environ
        region = (env.get(REGION_ENV) or "").strip()
        table_prefix = (env.get(TABLE_PREFIX_ENV) or "").strip()
        environment = (env.get(ENVIRONMENT_ENV) or "").strip()
        pepper_ciphertext_b64 = (env.get(PEPPER_CIPHERTEXT_ENV) or "").strip()
        issuers = _split_list(env.get(ISSUERS_ENV) or "")
        client_ids = _split_list(env.get(CLIENT_IDS_ENV) or "")
        missing = [
            name
            for name, value in (
                (REGION_ENV, region),
                (TABLE_PREFIX_ENV, table_prefix),
                (ISSUERS_ENV, issuers),
                (CLIENT_IDS_ENV, client_ids),
                (ENVIRONMENT_ENV, environment),
                (PEPPER_CIPHERTEXT_ENV, pepper_ciphertext_b64),
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
            environment=environment,
            pepper_ciphertext_b64=pepper_ciphertext_b64,
            session=_session_config(env),
            service_registration=_service_registration(env),
        )


# -- default component factories (the only AWS-touching code paths) ----------


def _default_storage(
    config: RuntimeConfig, *, dynamodb_resource: Any | None = None
) -> DynamoDbStorage:
    """Open the DynamoDB adapter for this environment (construction does no I/O)."""
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
    """The KMS source: decrypt the Lambda-configured ciphertext once per container."""
    return KmsEncryptedPepper(config.pepper_ciphertext_b64, config.environment)


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
        API contract routers mounted on top of the initial skeleton — plus, when
        the implementation session gate is fully configured, the
        ``/oauth/login`` + ``/oauth/callback`` router and a verified
        user-info profile source on the four API contract routers. With the gate
        keys absent the returned surface is exactly the pre-capability-11 app.
    """
    resolved = config if config is not None else RuntimeConfig.from_environ(environ)
    env = os.environ if environ is None else environ
    storage = storage_factory(resolved)
    verifier = verifier_factory(resolved)
    pepper_source = pepper_factory(resolved)
    # Force the single pepper read *here*, at cold start: an unreadable or
    # undersized pepper must fail the invocation, never a first request.
    pepper_source.current()
    session = resolved.session
    userinfo_client = CognitoUserInfoClient(session.userinfo_url) if session is not None else None
    # Without a profile source the bearer-token identity chain remains active.
    profile_source: ProfileSource | None = userinfo_client
    session_manager = (
        SessionManager(storage, session.session_ttl_seconds) if session is not None else None
    )
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
            pepper_source,
            profile_source=profile_source,
            session_manager=session_manager,
        ),
    ]
    service_credential = ""
    # Preserve the injected-config composition seam: only read this optional
    # setting when configuration is sourced from the runtime environment.
    if (config is None or environ is not None) and (
        env.get(SERVICE_CREDENTIAL_CIPHERTEXT_ENV) or ""
    ).strip():
        service_credential = KmsEncryptedServiceCredential(
            environment=resolved.environment, environ=env
        ).current()
    routers.append(
        build_service_auth_router(
            storage,
            pepper_source,
            service_credential=service_credential,
            service_registration=(resolved.service_registration if service_credential else None),
            session_manager=session_manager,
        )
    )
    if session is not None and userinfo_client is not None:
        # The session boundary rides on the single configured app client
        # (the deployed pool registers one Hosted UI client; task 15 pins
        # its settings), and the first allowed return origin is the
        # default landing target for a bare ``/oauth/login``.
        client_id = resolved.cognito_client_ids[0]
        assert session_manager is not None
        routers.append(
            build_oauth_router(
                storage,
                verifier,
                CognitoTokenEndpoint(
                    session.token_endpoint_url,
                    client_id,
                    client_secret=(
                        KmsEncryptedCognitoClientSecret(environ=env).current()
                        if (env.get(COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV) or "").strip()
                        else None
                    ),
                ),
                userinfo_client,
                session_manager,
                authorize_url=session.authorize_url,
                client_id=client_id,
                redirect_uri=session.redirect_uri,
                landing_url=session.allowed_return_origins[0],
                allowed_return_origins=session.allowed_return_origins,
                cookie_secure=session.cookie_secure,
                onboarding_dispatch=(
                    lambda organization_id: dispatch_organization_onboarding(
                        storage,
                        organization_id,
                        base_url=(env.get(VISPECTOR_URL_ENV) or "").strip(),
                        service_credential=service_credential,
                    )
                )
                if service_credential
                and resolved.service_registration is not None
                and resolved.service_registration.enabled
                else None,
            )
        )
        domain = session.authorize_url.removesuffix("/oauth2/authorize")
        routers.append(
            build_session_support_router(
                storage,
                verifier,
                pepper_source,
                userinfo_client,
                session_manager,
                cognito_domain=domain,
                client_id=client_id,
                frontend_url=session.allowed_return_origins[0],
                cookie_secure=session.cookie_secure,
            )
        )
        routers.append(
            build_admin_router(
                cast(LocalAdminStorage, storage),
                verifier,
                profile_source=profile_source,
                session_manager=session_manager,
                pepper_source=pepper_source,
            )
        )
    application = create_app(routers=routers, docs_enabled=resolved.environment != "prod")
    if session is not None and session_manager is not None:
        install_session_csrf_middleware(application, pepper_source, session_manager)
    return application


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
