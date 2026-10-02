"""Shared organization-access dependency (organization; authorization contract/API contract;
API-key decisions 6/7/8 — the API-key branch is now live here).

The single authorization seam every organization-scoped router registers
through (design notes decisions 4/5): it composes the published identity
authentication chain — or, once a ``pepper_source`` is wired, the API-key
prefix-dispatching :func:`~app.auth.dependencies.build_current_principal` —
with the pure decision-2/4 classification rules, so routers carry **no**
authz logic — they only mount manifest routes and depend on what this module
yields.

Pipeline of one request::

    bearer token -> build_current_user | build_current_principal
                   (401/403/409/503 mapping as published)
        -> get_organization (unknown org -> uniform 403, provably no audit)
        -> human actor?  get_membership + classify_access
                         (fixed precedence: org status, presence, status, rank)
           granted?      OrganizationAccess(identity, organization, membership)
           denied?       audit_denial -> uniform 403
        -> api_key actor on a human-only route?
                         audit_denial(human_only) -> uniform 403

Denial semantics (design choice 4): unknown organization, inactive organization,
missing membership, inactive membership, insufficient role — and, from
API-key, ``human_only`` on the management factories plus ``organization_mismatch``
and ``insufficient_scope`` on the scope dependency — all answer the **same**
403 with one fixed message — deliberately mirroring identity design choice 9's
pinned explicit-org branch so the two seams never disagree and no existence
oracle leaks. Unknown-organization denials cannot be audited (the
audit→organization FK has no target; documented audit contract exception); every denial
whose organization row exists appends ``authorization.denied`` with exactly
``{"reason", "operation"}`` metadata **before** the 403 is raised — and an
append failure propagates as a 500 (fail-closed), never a silent 403. The
denial actor is any authorization-context contract identity (design choice 7): a ``key_`` actor is audited
as ``api_key`` via the generalized :func:`~app.services.authorization.audit_denial`.

Authentication precedes authorization (identity contract): a request that will be
denied still auto-provisions a first-seen Cognito identity — consistent with
``/v1/me`` and documented in the capability handoff.

API-key extension point (design choice 6), now implemented: the member/admin
factories gain a keyword-only ``pepper_source: PepperSource | None = None``.
When ``None`` they compose exactly the identity chain (byte-stable
regression — a ``fn_`` literal on those routes simply fails JWT verification
→ 401); when provided they compose ``build_current_principal`` and a
non-``user`` actor is refused with the uniform 403 **audited** ``human_only``
after the organization fetch (so the denial row has its FK target).
:func:`build_organization_scope_dependency` is the key-carrying seam for
product routes: human branch = organization member-rank rules (roles govern,
``required_scope`` never applies to humans); API-key branch = org status →
``organization_mismatch`` → ``insufficient_scope``, every denial the same
uniform 403 with its deterministic audit reason.

Current behavior and invariants: ``docs/authorization.md``."""

# No ``from __future__ import annotations`` here on purpose (the ``me.py``
# precedent): the dependency signatures reference closure locals in
# ``Annotated[..., Depends(...)]`` position, and PEP 563 stringified
# annotations could not resolve them at import time.
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Final, NoReturn

from fastapi import Depends, HTTPException

from app.auth.api_key_auth import key_has_scope
from app.auth.cognito import AccessTokenVerifier, ProfileSource
from app.auth.dependencies import build_current_principal, build_current_user
from app.auth.pepper import PepperSource
from app.auth.principal import Principal
from app.models.api_key import Scope
from app.models.authorization_context import AuthorizationContext
from app.models.enums import MembershipRole, OrganizationStatus
from app.models.ids import ActorId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services.authorization import (
    AccessOutcome,
    audit_denial,
    classify_access,
)
from app.services.identity import ResolvedIdentity
from app.storage.contract import EntityNotFoundError, Storage
from app.auth.session import SessionManager

#: The one fixed 403 message for every denial shape (decision 4: uniform,
#: existence-oracle-free, identical body for unknown/inactive org, missing/
#: inactive membership, insufficient role, and the Phase 05 key denials).
ORGANIZATION_FORBIDDEN_MESSAGE: Final = "you do not have permission to access this organization"


@dataclass(frozen=True)
class OrganizationAccess:
    """The granted access a protected handler receives: who, where, as what.

    ``identity`` is the full identity resolution (user + context) so handlers
    can reach the actor id; ``organization`` and ``membership`` are the
    already-authorized tenancy rows — handlers must not re-check them. This
    type stays **human-only** (design choice 6): ``membership`` is non-optional by
    the frozen organization shape, API-key actors never receive it, and
    :class:`PrincipalAccess` is the key-carrying type.
    """

    identity: ResolvedIdentity
    organization: Organization
    membership: Membership


@dataclass(frozen=True)
class PrincipalAccess:
    """Granted access from the scope dependency: actor + organization.

    The DynamoDB and AWS and securityhandoff type (design choice 6): ``principal`` is the
    dispatching :class:`~app.auth.principal.Principal` — human (with its
    unchanged authorization-context contract context) or API-key (``roles == []``, stored scopes) — and
    ``organization`` is the already-authorized path row. No ``membership``
    field: API-key actors have none, and product handlers authorize through
    the principal's context, not a human role.
    """

    principal: Principal
    organization: Organization


def _forbidden() -> NoReturn:
    """Raise the one uniform 403 every denial shape renders (design choice 4)."""
    raise HTTPException(status_code=403, detail=ORGANIZATION_FORBIDDEN_MESSAGE)


def _require_organization(storage: Storage, organization_id: OrganizationId) -> Organization:
    """Fetch the path organization or answer the uniform 403.

    Unknown organization: the same 403, provably no audit row — the
    audit→organization FK has no target (design choice 4, escalated to audit contract).
    Every denial audit in this module runs **after** this fetch, which is the
    pinned ordering for the API-key ``human_only`` refusal (design choice 6).
    """
    try:
        return storage.get_organization(organization_id)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=403, detail=ORGANIZATION_FORBIDDEN_MESSAGE) from exc


def _deny(
    storage: Storage,
    actor_id: ActorId,
    organization: Organization,
    reason: AccessOutcome,
    operation_id: str,
) -> NoReturn:
    """Audit one denial (the org row exists by construction) then raise 403.

    ``actor_id`` is any authorization-context contract actor (``usr_`` or ``key_`` — design choice 7); the
    append failure propagates (fail-closed 500, never a silent 403).
    """
    audit_denial(storage, actor_id, organization.id, reason, operation_id)
    _forbidden()


def _authorize_human(
    storage: Storage,
    user: User,
    context: AuthorizationContext,
    organization: Organization,
    min_role: MembershipRole,
    operation_id: str,
) -> OrganizationAccess:
    """The organization member-rank rules for a human actor — unchanged logic.

    Organization status was already fetched; ``classify_access`` applies the
    fixed precedence (org status, presence, membership status, role rank).
    Grants rebuild the :class:`~app.services.identity.ResolvedIdentity` from
    the principal's (unchanged) user and context — value-identical to what
    ``build_current_user`` produced.
    """
    actor_user_id = context.actor_id  # UserId (caller-checked)
    try:
        membership: Membership | None = storage.get_membership(
            organization_id=organization.id, user_id=actor_user_id
        )
    except EntityNotFoundError:
        membership = None  # absent pair: a classification input, not an error
    decision = classify_access(organization, membership, min_role)
    if decision.is_granted and membership is not None:
        identity = ResolvedIdentity(user=user, context=context)
        return OrganizationAccess(
            identity=identity, organization=organization, membership=membership
        )
    # Denial with an existing org row is always audited first; an append
    # failure propagates (fail-closed 500, never a silent 403).
    return _deny(storage, actor_user_id, organization, decision.outcome, operation_id)


def _authorize_principal(
    storage: Storage,
    principal: Principal,
    organization_id: OrganizationId,
    min_role: MembershipRole,
    operation_id: str,
) -> OrganizationAccess:
    """Shared member/admin pipeline for a human-or-key principal (design choice 6).

    Ordering pinned: the organization fetch runs **before** the ``human_only``
    refusal so the denial audit has its FK target; an unknown organization
    still answers the same 403 with provably no audit row (the audit contract
    structural exception, unchanged for key actors). The non-``user`` branch
    is unreachable when ``pepper_source`` is not wired (the identity chain
    never yields a key principal), so the ``None`` default stays byte-stable.
    """
    context = principal.context
    organization = _require_organization(storage, organization_id)
    if principal.user is None or not isinstance(context.actor_id, UserId):
        # API-key actor on a human-only management route: the uniform 403,
        # audited ``human_only`` under the ``key_`` actor (AC 4's escalation
        # proof — keys never borrow human role checks).
        return _deny(
            storage, context.actor_id, organization, AccessOutcome.HUMAN_ONLY, operation_id
        )
    return _authorize_human(storage, principal.user, context, organization, min_role, operation_id)


def _build_organization_access_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    operation_id: str,
    min_role: MembershipRole,
    pepper_source: PepperSource | None,
    profile_source: ProfileSource | None,
    session_manager: SessionManager | None = None,
) -> Callable[..., OrganizationAccess]:
    """Return the access dependency enforcing ``min_role`` (design choice 3 rank).

    A pure wiring factory (no I/O at construction), like
    :func:`~app.auth.dependencies.build_current_user`. ``operation_id`` is
    the frozen manifest entry the route registered from — it is the only
    ``operation`` value that may enter a denial audit. With
    ``pepper_source=None`` the dependency composes exactly the identity
    chain (byte-stable regression); with one provided it composes
    :func:`~app.auth.dependencies.build_current_principal` and API-key
    bearers are refused with the audited ``human_only`` denial.
    ``profile_source`` (session) is forwarded to whichever chain is
    composed; it only ever matters for a first-login human miss.
    """
    if pepper_source is None:
        current_user = build_current_user(storage, verifier, profile_source, session_manager)

        def human_only_route_access(
            organization_id: OrganizationId,
            identity: Annotated[ResolvedIdentity, Depends(current_user)],
        ) -> OrganizationAccess:
            """Authorize one organization-scoped human request."""
            principal = Principal(user=identity.user, api_key=None, context=identity.context)
            return _authorize_principal(storage, principal, organization_id, min_role, operation_id)

        return human_only_route_access

    current_principal = build_current_principal(storage, verifier, pepper_source, profile_source, session_manager)

    def principal_route_access(
        organization_id: OrganizationId,
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> OrganizationAccess:
        """Authorize one organization-scoped request (keys refused 403)."""
        return _authorize_principal(storage, principal, organization_id, min_role, operation_id)

    return principal_route_access


def build_organization_member_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    operation_id: str,
    *,
    pepper_source: PepperSource | None = None,
    profile_source: ProfileSource | None = None,
    session_manager: SessionManager | None = None,
) -> Callable[..., OrganizationAccess]:
    """Read access: any **active** membership (rank >= ``viewer``).

    ``pepper_source`` (design choice 6): ``None`` keeps the exact identity and organizationchain; wiring one makes API-key bearers answer the uniform 403 audited
    ``human_only`` (management routes are human-only, design choice 8).
    ``profile_source`` (session) forwards the verified user-info
    seam to the human authentication chain.
    """
    return _build_organization_access_dependency(
        storage, verifier, operation_id, MembershipRole.VIEWER, pepper_source, profile_source, session_manager
    )


def build_organization_admin_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    operation_id: str,
    *,
    pepper_source: PepperSource | None = None,
    profile_source: ProfileSource | None = None,
    session_manager: SessionManager | None = None,
) -> Callable[..., OrganizationAccess]:
    """Mutation access: rank >= ``admin`` (owner or admin only, design choice 3).

    ``pepper_source`` and ``profile_source`` behave exactly as in
    :func:`build_organization_member_dependency`.
    """
    return _build_organization_access_dependency(
        storage, verifier, operation_id, MembershipRole.ADMIN, pepper_source, profile_source, session_manager
    )


def build_organization_scope_dependency(
    storage: Storage,
    verifier: AccessTokenVerifier,
    pepper_source: PepperSource,
    required_scope: Scope,
    operation_id: str,
) -> Callable[..., PrincipalAccess]:
    """Return the scope-enforcing access dependency (design choice 6, implementation).

    **The DynamoDB and AWS and securityhandoff seam** for product operations: composes
    :func:`~app.auth.dependencies.build_current_principal` and yields a
    :class:`PrincipalAccess` for either actor kind.

    - Human branch: the organization member-rank rules (rank >= ``viewer``,
      roles govern). ``required_scope`` **never applies to humans** —
      product permissions are API-key scopes only (AGENTS.md), and human
      contexts carry an empty scope list by construction.
    - API-key branch: the fixed precedence org status → ``organization_mismatch``
      (the key's organization must equal the path organization) →
      ``insufficient_scope`` (exact-string membership of ``required_scope``
      in the context's scopes — design choice 7: no wildcards, no hierarchy).

    Every denial is the same uniform 403 body with its deterministic audit
    reason, appended whenever the organization row exists (unknown org: the
    audit contract exception, no audit row).
    """
    current_principal = build_current_principal(storage, verifier, pepper_source)

    def scope_access(
        organization_id: OrganizationId,
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> PrincipalAccess:
        """Authorize one scope-gated organization request."""
        context = principal.context
        organization = _require_organization(storage, organization_id)
        if principal.user is not None:
            # Human branch: member-rank rules decide; the required scope is
            # never consulted (roles govern for people, decision 6).
            access = _authorize_human(
                storage,
                principal.user,
                context,
                organization,
                MembershipRole.VIEWER,
                operation_id,
            )
            return PrincipalAccess(principal=principal, organization=access.organization)
        # API-key branch, fixed precedence (decision 6): organization status
        # -> tenancy -> scope. The actor for every audit is the ``key_``
        # identity (decision 7).
        if organization.status is not OrganizationStatus.ACTIVE:
            _deny(
                storage,
                context.actor_id,
                organization,
                AccessOutcome.INACTIVE_ORGANIZATION,
                operation_id,
            )
        if context.organization_id != organization.id:
            _deny(
                storage,
                context.actor_id,
                organization,
                AccessOutcome.ORGANIZATION_MISMATCH,
                operation_id,
            )
        if not key_has_scope(context, required_scope):
            _deny(
                storage,
                context.actor_id,
                organization,
                AccessOutcome.INSUFFICIENT_SCOPE,
                operation_id,
            )
        return PrincipalAccess(principal=principal, organization=organization)

    return scope_access


__all__ = [
    "ORGANIZATION_FORBIDDEN_MESSAGE",
    "OrganizationAccess",
    "PrincipalAccess",
    "build_organization_admin_dependency",
    "build_organization_member_dependency",
    "build_organization_scope_dependency",
]
