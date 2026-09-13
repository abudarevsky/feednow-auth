"""``GET /v1/me`` router (Phase 03 task 5; spec §14 "Current User").

:func:`build_me_router` is the documented mounting shape: a factory closing
over the injected :class:`~app.storage.contract.Storage` and
:class:`~app.auth.cognito.AccessTokenVerifier`, returning an
:class:`~fastapi.APIRouter` to hand to ``create_app(routers=[...])`` — the
Phase 01 boot contract (no import-time environment reads, no module-level
singletons) stays intact.

The route is registered **from the frozen manifest entry itself**
(:func:`~app.api.schemas.manifest.endpoint_for`), so method, path, success
status, and response model cannot drift from the §14 contract — the response
schema (:class:`~app.api.schemas.me.MeResponse`) is untouched by this phase.

The handler returns the caller's own :class:`~app.models.user.User` fields
only: the resolved ``AuthorizationContext`` (organization, roles) exists for
downstream routers, and provider material (``sub``, ``client_id``, tokens)
never enters the response — the §4/§10 identity rule (AGENTS.md) is the
acceptance criterion this endpoint is named for.
"""

# No ``from __future__ import annotations`` here on purpose: the route
# signature's ``Annotated[..., Depends(current_user)]`` references a closure
# local, and PEP 563 stringified annotations could not resolve it at import
# time (FastAPI would silently demote the parameter to a query model).
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.schemas.manifest import endpoint_for
from app.api.schemas.me import MeResponse
from app.auth.cognito import AccessTokenVerifier
from app.auth.dependencies import build_current_user
from app.services.identity import ResolvedIdentity
from app.storage.contract import Storage

#: The frozen §14 entry this router must register exactly.
_ME_SPEC = endpoint_for("get_current_user")


def build_me_router(storage: Storage, verifier: AccessTokenVerifier) -> APIRouter:
    """Build the ``GET /v1/me`` router bound to ``storage`` and ``verifier``.

    The auth chain (bearer → verify → resolve_or_provision → domain-error
    mapping) lives in :func:`app.auth.dependencies.build_current_user`; this
    module only joins it to the manifest-pinned route and the response shape.
    """
    router = APIRouter(tags=["identity"])
    current_user = build_current_user(storage, verifier)

    def get_current_user(
        identity: Annotated[ResolvedIdentity, Depends(current_user)],
    ) -> MeResponse:
        """Project the resolved user onto the derived ``MeResponse`` schema."""
        user = identity.user
        return MeResponse(
            id=user.id,
            display_name=user.display_name,
            email=user.email,
            status=user.status,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

    router.add_api_route(
        _ME_SPEC.path,
        get_current_user,
        methods=[_ME_SPEC.method],
        status_code=_ME_SPEC.success_status,
        response_model=_ME_SPEC.response_model,
    )
    return router


__all__ = ["build_me_router"]
