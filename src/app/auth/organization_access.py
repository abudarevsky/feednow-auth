"""Shared organization-access dependency (Phase 04 task 3; spec §9/§14).

The single authorization seam every organization-scoped router registers
through (breakdown decisions 4/5): it composes the published Phase 03
authentication chain with the pure decision-2/4 classification rules, so
routers carry **no** authz logic — they only mount manifest routes and
depend on what this module yields.

Pipeline of one request::

    bearer token -> build_current_user (401/403/409/503 mapping as published)
        -> get_organization + get_membership (tuple lookup, actor from context)
        -> classify_access (fixed precedence: org status, presence, status, rank)
        -> granted?  OrganizationAccess(identity, organization, membership)
           denied?   audit_denial (when the org row exists) -> uniform 403

Denial semantics (decision 4): unknown organization, inactive organization,
missing membership, inactive membership, and insufficient role all answer the
**same** 403 with one fixed message — deliberately mirroring Phase 03
decision 9's pinned explicit-org branch so the two seams never disagree and
no existence oracle leaks. Unknown-organization denials cannot be audited
(the audit→organization FK has no target; documented §16 exception); every
denial whose organization row exists appends ``authorization.denied`` with
exactly ``{"reason", "operation"}`` metadata **before** the 403 is raised —
and an append failure propagates as a 500 (fail-closed), never a silent 403.

Authentication precedes authorization (spec §6): a request that will be
denied still auto-provisions a first-seen Cognito identity — consistent with
``/v1/me`` and documented in the phase handoff.

Phase 05 extension point (decision 5): the dependency is keyed on the
resolved :class:`~app.models.authorization_context.AuthorizationContext`
actor, so the ``api_key`` branch joins here by resolving the key's
organization/roles instead of the human membership tuple; the ``user``
branch below is the only producer this phase.
"""

# No ``from __future__ import annotations`` here on purpose (the ``me.py``
# precedent): the dependency signatures reference closure locals in
# ``Annotated[..., Depends(...)]`` position, and PEP 563 stringified
# annotations could not resolve them at import time.
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import Depends, HTTPException

from app.auth.cognito import AccessTokenVerifier
from app.auth.dependencies import build_current_user
from app.models.enums import MembershipRole
from app.models.ids import OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.services.authorization import audit_denial, classify_access
from app.services.identity import ResolvedIdentity
from app.storage.contract import EntityNotFoundError, Storage

#: The one fixed 403 message for every denial shape (decision 4: uniform,
#: existence-oracle-free, identical body for unknown/inactive org, missing/
#: inactive membership, and insufficient role).
ORGANIZATION_FORBIDDEN_MESSAGE: Final = "you do not have permission to access this organization"


@dataclass(frozen=True)
class OrganizationAccess:
    """The granted access a protected handler receives: who, where, as what.

    ``identity`` is the full Phase 03 resolution (user + context) so handlers
    can reach the actor id; ``organization`` and ``membership`` are the
    already-authorized tenancy rows — handlers must not re-check them.
    """

    identity: ResolvedIdentity
    organization: Organization
    membership: Membership


def _build_organization_access_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    operation_id: str,
    min_role: MembershipRole,
) -> Callable[..., OrganizationAccess]:
    """Return the access dependency enforcing ``min_role`` (decision 3 rank).

    A pure wiring factory (no I/O at construction), like
    :func:`~app.auth.dependencies.build_current_user`. ``operation_id`` is
    the frozen manifest entry the route registered from — it is the only
    ``operation`` value that may enter a denial audit.
    """
    current_user = build_current_user(storage, verifier)

    def organization_access(
        organization_id: OrganizationId,
        identity: Annotated[ResolvedIdentity, Depends(current_user)],
    ) -> OrganizationAccess:
        """Authorize one organization-scoped request (both minimums)."""
        context = identity.context
        # Phase 04 produces human contexts only; the Phase 05 api_key branch
        # resolves here. Anything else is refused with the uniform denial.
        if context.actor_type != "user" or not isinstance(context.actor_id, UserId):
            raise HTTPException(status_code=403, detail=ORGANIZATION_FORBIDDEN_MESSAGE)
        actor_user_id = context.actor_id
        try:
            organization = storage.get_organization(organization_id)
        except EntityNotFoundError as exc:
            # Unknown organization: the same 403, provably no audit row —
            # the FK has no target (decision 4, escalated to §16).
            raise HTTPException(status_code=403, detail=ORGANIZATION_FORBIDDEN_MESSAGE) from exc
        try:
            membership: Membership | None = storage.get_membership(
                organization_id=organization.id, user_id=actor_user_id
            )
        except EntityNotFoundError:
            membership = None  # absent pair: a classification input, not an error
        decision = classify_access(organization, membership, min_role)
        if decision.is_granted and membership is not None:
            return OrganizationAccess(
                identity=identity, organization=organization, membership=membership
            )
        # Denial with an existing org row is always audited first; an append
        # failure propagates (fail-closed 500, never a silent 403).
        audit_denial(storage, actor_user_id, organization.id, decision.outcome, operation_id)
        raise HTTPException(status_code=403, detail=ORGANIZATION_FORBIDDEN_MESSAGE)

    return organization_access


def build_organization_member_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    operation_id: str,
) -> Callable[..., OrganizationAccess]:
    """Read access: any **active** membership (rank >= ``viewer``)."""
    return _build_organization_access_dependency(
        storage, verifier, operation_id, MembershipRole.VIEWER
    )


def build_organization_admin_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    operation_id: str,
) -> Callable[..., OrganizationAccess]:
    """Mutation access: rank >= ``admin`` (owner or admin only, decision 3)."""
    return _build_organization_access_dependency(
        storage, verifier, operation_id, MembershipRole.ADMIN
    )


__all__ = [
    "ORGANIZATION_FORBIDDEN_MESSAGE",
    "OrganizationAccess",
    "build_organization_admin_dependency",
    "build_organization_member_dependency",
]
