"""Application entrypoint: the ``create_app`` factory and the uvicorn target.

Boot contract (Phase 01 acceptance criteria): importing this module and
building the app requires **no database connection, no AWS credentials or
configuration, and no AWS SDK** — ``boto3`` must never appear in
``sys.modules`` as a consequence of importing ``app.main`` (proven by the
subprocess-isolated check in ``tests/integration/test_app_skeleton.py``).
Owner phases add configuration through explicit constructor parameters or
dependency injection, never through import-time environment reads.

Mounting extension point (frozen Phase 01 contract — see
``specs/wip/01-foundation-and-domain-contracts-breakdown.md`` task 5/6):

- Owner phases (04/05) implement §14 endpoints as ``APIRouter`` objects in
  ``app/api/<resource>.py`` and attach them by passing the routers to
  :func:`create_app` (e.g. ``create_app(routers=[organizations_router,
  api_keys_router])`` in the deployment entrypoint).
- Every route a router registers must appear in
  :data:`app.api.schemas.manifest.ENDPOINTS` with the same method, full
  ``/v1`` path, request/response models, and success status. A route that
  is not in the manifest may not be mounted without a spec revision.
- Phase 01 mounts **no** §14 routers (endpoint behavior is a non-goal);
  only the operational ``/health`` router is included, and it is
  deliberately outside the manifest.
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter, FastAPI

from app.api.errors import register_exception_handlers
from app.api.health import router as health_router

#: Service version reported in the OpenAPI document. Kept in lockstep with
#: ``[project] version`` in ``pyproject.toml``.
APP_VERSION = "0.1.0"


def create_app(routers: Sequence[APIRouter] | None = None) -> FastAPI:
    """Build the feednow-auth ASGI application.

    Args:
        routers: Optional sequence of resource routers to mount, in order
            (the documented extension point above). ``None`` — the default
            used by ``uvicorn app.main:app`` — yields the Phase 01 skeleton:
            health plus the error-envelope handlers, nothing else.

    Returns:
        A fully configured :class:`~fastapi.FastAPI` instance. Construction
        performs no I/O and reads no configuration.
    """
    application = FastAPI(
        title="feednow-auth",
        version=APP_VERSION,
        description="FeedNow application identity, tenancy, credentials, and audit service.",
    )
    register_exception_handlers(application)
    application.include_router(health_router)
    for router in routers or ():
        application.include_router(router)
    return application


#: Module-level instance for ``uvicorn app.main:app`` (README, task 1).
app = create_app()


def run() -> None:
    """Run the service through the installed ``feednow-auth`` command."""
    import uvicorn

    uvicorn.run("app.main:app")


__all__ = ["APP_VERSION", "app", "create_app", "run"]
