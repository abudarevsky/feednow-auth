"""Operational health endpoint (Phase 01 task 6 skeleton).

``GET /health`` is deliberately **not** a spec §14 route: it is not in
:data:`app.api.schemas.manifest.ENDPOINTS` and lives outside the ``/v1``
prefix. It exists so deployment platforms (Lambda health checks, ALB probes
in later phases) can verify the process is alive without touching any
dependency.

Hard constraints (acceptance criteria):

- The handler must never touch a database, AWS SDK, or any configuration.
  If it ever needs a dependency, that belongs in a separate readiness
  endpoint owned by the phase that introduces the dependency.
- The response is a fixed, closed payload (``ApiSchema`` → ``extra="forbid"``)
  so monitors can parse it strictly.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter

from app.api.schemas.common import ApiSchema

#: Tag used for the operational route in the OpenAPI schema.
HEALTH_TAG = "health"


class HealthResponse(ApiSchema):
    """Body of ``GET /health``: a single constant status field."""

    status: Literal["ok"] = "ok"


router = APIRouter(tags=[HEALTH_TAG])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=200,
    summary="Liveness probe",
    description=(
        "Returns 200 as soon as the process can serve HTTP. No database "
        "connection, AWS credentials, or configuration are required."
    ),
)
async def health() -> HealthResponse:
    """Answer liveness checks with a constant JSON payload."""
    return HealthResponse()


__all__ = ["HEALTH_TAG", "HealthResponse", "router"]
