#!/usr/bin/env python3
"""Lambda composition root for feednow-auth (Phase 07 task 5).

Boot contract (the Phase 01 rule, applied to the deployment entrypoint):
**importing this module reads no configuration and performs no AWS call.**
Everything happens in :func:`build_app`, which the module-level
:class:`~mangum.Mangum` adapter invokes through :class:`_LazyApp` on the
first request — Lambda's cold start. The five ``FEEDNOW_*`` inputs are read
there, never at import, so a misconfigured deployment fails on the first
invocation with a message naming the missing key.

Wiring (spec §17, breakdown task 5)::

    RuntimeConfig (env)
      -> CognitoJwksSource -> CognitoAccessTokenVerifier
      -> open_dynamodb_storage(region=..., table_prefix=...)
      -> SecretsManagerPepper(FEEDNOW_PEPPER_SECRET_ID)   # one GetSecretValue
      -> build_me_router / build_organizations_router / build_members_router
         / build_api_keys_router(storage, verifier, pepper)
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
from app.api.organizations import build_organizations_router
from app.auth.cognito import AccessTokenVerifier, CognitoAccessTokenVerifier
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import PepperSource
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

#: Every key :meth:`RuntimeConfig.from_environ` reads, in order.
REQUIRED_ENV_KEYS: Final = (
    REGION_ENV,
    TABLE_PREFIX_ENV,
    ISSUERS_ENV,
    CLIENT_IDS_ENV,
    PEPPER_SECRET_ID_ENV,
)


def _split_list(raw: str) -> tuple[str, ...]:
    """Normalize a comma-separated runtime input, preserving order."""
    entries = (item.strip() for item in raw.split(","))
    return tuple(dict.fromkeys(entry for entry in entries if entry))


@dataclass(frozen=True)
class RuntimeConfig:
    """The five injected runtime inputs, parsed and validated (never at import)."""

    region: str
    table_prefix: str
    cognito_issuers: tuple[str, ...]
    cognito_client_ids: tuple[str, ...]
    pepper_secret_id: str

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> RuntimeConfig:
        """Read and validate the runtime inputs from ``environ``.

        ``environ`` defaults to :data:`os.environ`; tests pass a plain
        mapping. Every key must yield at least one value: the allowlists are
        checked **after** comma normalization, so a blank-but-present
        ``FEEDNOW_COGNITO_ISSUERS`` fails here naming the key instead of
        surfacing deep inside the verifier. Failures name the offending keys
        and nothing else — no values, no defaults.
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
        §14 routers mounted on top of the Phase 01 skeleton.
    """
    resolved = config if config is not None else RuntimeConfig.from_environ(environ)
    storage = storage_factory(resolved)
    verifier = verifier_factory(resolved)
    pepper_source = pepper_factory(resolved)
    # Force the single pepper read *here*, at cold start: an unreadable or
    # undersized pepper must fail the invocation, never a first request.
    pepper_source.current()
    return create_app(
        routers=[
            build_me_router(storage, verifier),
            build_organizations_router(storage, verifier),
            build_members_router(storage, verifier),
            build_api_keys_router(storage, verifier, pepper_source),
        ]
    )


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
    "RuntimeConfig",
    "app",
    "build_app",
    "handler",
]
