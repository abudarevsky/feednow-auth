"""Application entrypoint for the ASGI service. ``create_app`` mounts health and the explicitly supplied routers; importing the module performs no storage or cloud I/O.

Current behavior and invariants: ``docs/architecture.md``."""

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
            used by ``uvicorn app.main:app`` — yields the initial skeleton:
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
