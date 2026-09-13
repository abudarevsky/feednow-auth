"""Organization tenancy authorization rules and audit builders (Phase 04 task 2).

Pure business rules for spec §9/§14 tenancy: the documented role policy
(breakdown decision 3), the uniform denial classification (decision 4), the
mutation/denial audit-event builders (decisions 4/7), and the service-layer
domain errors whose HTTP translation the routers own (decision 6). This
module imports **no FastAPI** — the credential wiring lives in
``app.auth.organization_access`` (task 3) and the routers (tasks 4/5).

Role policy (decision 3): rank is ``viewer < member < admin < owner``
(:data:`ROLE_RANK`). Reads require an **active** membership at rank >=
viewer (any role); mutations require rank >= admin (owner or admin). The
``owner`` role is not grantable, not removable, and not changeable through
the membership API — enforced by these guards plus the deliberate absence of
any update method in the storage contract.

Denial classification (decision 4): :func:`classify_access` checks in fixed
precedence — organization status, then membership presence, then membership
status, then role rank — so when several conditions hold at once the audit
``reason`` is deterministic while HTTP stays one uniform 403 (no existence
oracle; mirrors Phase 03 decision 9). The :class:`AccessOutcome` denial
strings are the *only* reason vocabulary that may enter an
``authorization.denied`` audit.

Audit discipline (decisions 4/7): every builder is a pure function of
injected ``ids``/``now`` (storage mints nothing; AGENTS.md). Metadata is
exactly the pinned key sets — ``{"reason", "operation"``} for denials,
``{"type"}`` for organization creation, ``{"role"}`` for membership
create/remove — and never carries email, provider ``sub``, tokens, or
secret material. :func:`audit_denial` propagates append failures
(fail-closed: a denial that cannot be audited is a 500, never a silent 403).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final

from app.models.audit_event import AuditEvent
from app.models.enums import MembershipRole, MembershipStatus, OrganizationStatus, OrganizationType
from app.models.ids import AuditEventId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.timestamps import utc_now
from app.services.idgen import new_audit_event_id
from app.storage.contract import Storage

# ---------------------------------------------------------------------------
# Role policy and access classification (decisions 3/4)
# ---------------------------------------------------------------------------


class AccessOutcome(StrEnum):
    """Result vocabulary of :func:`classify_access` (decision 4).

    The four denial strings are exactly the ``reason`` values permitted in
    ``authorization.denied`` audit metadata; ``granted`` is never audited.
    """

    GRANTED = "granted"
    NO_MEMBERSHIP = "no_membership"
    INACTIVE_MEMBERSHIP = "inactive_membership"
    INACTIVE_ORGANIZATION = "inactive_organization"
    INSUFFICIENT_ROLE = "insufficient_role"


#: The auditable denial reasons (everything :class:`AccessOutcome` except
#: ``granted``). ``reason`` strings outside this set are a programming error.
DENIAL_REASONS: Final[frozenset[AccessOutcome]] = frozenset(
    {
        AccessOutcome.NO_MEMBERSHIP,
        AccessOutcome.INACTIVE_MEMBERSHIP,
        AccessOutcome.INACTIVE_ORGANIZATION,
        AccessOutcome.INSUFFICIENT_ROLE,
    }
)

#: Role rank (decision 3): ``viewer < member < admin < owner``.
ROLE_RANK: Final[dict[MembershipRole, int]] = {
    MembershipRole.VIEWER: 0,
    MembershipRole.MEMBER: 1,
    MembershipRole.ADMIN: 2,
    MembershipRole.OWNER: 3,
}


@dataclass(frozen=True)
class AccessDecision:
    """The pure outcome of one organization-access check."""

    outcome: AccessOutcome

    @property
    def is_granted(self) -> bool:
        """True only for :attr:`AccessOutcome.GRANTED`."""
        return self.outcome is AccessOutcome.GRANTED


def classify_access(
    organization: Organization,
    membership: Membership | None,
    min_role: MembershipRole,
) -> AccessDecision:
    """Classify one organization access — **pure**, fixed precedence (decision 4).

    Checks run in order: organization status, membership presence, membership
    status, role rank. ``membership=None`` means "no row for this user". The
    precedence makes the denial reason deterministic when several conditions
    hold at once (e.g. a disabled organization *and* an absent membership
    classify as ``inactive_organization``); the caller renders every denial
    as the same 403, so only the audit distinguishes them.
    """
    if organization.status is not OrganizationStatus.ACTIVE:
        return AccessDecision(AccessOutcome.INACTIVE_ORGANIZATION)
    if membership is None:
        return AccessDecision(AccessOutcome.NO_MEMBERSHIP)
    if membership.status is not MembershipStatus.ACTIVE:
        return AccessDecision(AccessOutcome.INACTIVE_MEMBERSHIP)
    if ROLE_RANK[membership.role] < ROLE_RANK[min_role]:
        return AccessDecision(AccessOutcome.INSUFFICIENT_ROLE)
    return AccessDecision(AccessOutcome.GRANTED)


# ---------------------------------------------------------------------------
# Service domain errors (decision 6 — routers own the HTTP translation)
# ---------------------------------------------------------------------------


class OrganizationTypeNotSelectableError(Exception):
    """Only ``customer`` organizations are creatable through the API (400)."""

    def __init__(
        self,
        message: str = "only customer organizations can be created through this API",
    ) -> None:
        super().__init__(message)


class OwnerRoleNotAssignableError(Exception):
    """The ``owner`` role is not grantable through the membership API (400)."""

    def __init__(
        self,
        message: str = "the owner role cannot be granted through the membership API",
    ) -> None:
        super().__init__(message)


class MemberNotFoundError(Exception):
    """The target user holds no membership in this organization (404)."""

    def __init__(self, message: str = "user is not a member of this organization") -> None:
        super().__init__(message)


class TargetUserNotFoundError(Exception):
    """The target ``usr_`` application identity does not exist (404)."""

    def __init__(self, message: str = "target user does not exist") -> None:
        super().__init__(message)


class OrganizationSlugConflictError(Exception):
    """The organization slug is already taken (409; never a converge)."""

    def __init__(self, message: str = "organization slug is already taken") -> None:
        super().__init__(message)


class MembershipConflictError(Exception):
    """The (organization, user) pair already has a membership (409)."""

    def __init__(
        self,
        message: str = "user is already a member of this organization",
    ) -> None:
        super().__init__(message)


class OwnerMembershipImmutableError(Exception):
    """Owner memberships are not removable through the API (409, decision 3)."""

    def __init__(self, message: str = "owner membership cannot be removed") -> None:
        super().__init__(message)


# ---------------------------------------------------------------------------
# Policy guards (decision 3)
# ---------------------------------------------------------------------------


def require_selectable_organization_type(organization_type: OrganizationType) -> None:
    """Allow only :attr:`~app.models.enums.OrganizationType.CUSTOMER`.

    ``personal`` organizations are auto-created by provisioning (spec §7) and
    ``internal`` organizations are operator-managed; neither is selectable
    through ``POST /v1/organizations`` (frozen request-schema rationale).
    """
    if organization_type is not OrganizationType.CUSTOMER:
        raise OrganizationTypeNotSelectableError()


def require_assignable_member_role(role: MembershipRole) -> None:
    """Reject ``owner`` grants (decision 3: the owner role is not grantable)."""
    if role is MembershipRole.OWNER:
        raise OwnerRoleNotAssignableError()


# ---------------------------------------------------------------------------
# Audit-event builders (decisions 4/7 — pure in injected ids/now)
# ---------------------------------------------------------------------------


def build_organization_created_audit(
    *,
    audit_id: AuditEventId,
    organization_id: OrganizationId,
    actor_user_id: UserId,
    organization_type: OrganizationType,
    now: datetime,
) -> AuditEvent:
    """``organization.created`` — metadata exactly ``{"type": ...}``, target the
    new ``org_`` (decision 7; written inside the ``provision_organization``
    batch with the creator as actor)."""
    return AuditEvent(
        id=audit_id,
        organization_id=organization_id,
        actor_type="user",
        actor_id=actor_user_id,
        action="organization.created",
        target_type="organization",
        target_id=str(organization_id),
        metadata={"type": organization_type.value},
        created_at=now,
    )


def build_membership_created_audit(
    *,
    audit_id: AuditEventId,
    organization_id: OrganizationId,
    actor_user_id: UserId,
    membership_id: MembershipId,
    role: MembershipRole,
    now: datetime,
) -> AuditEvent:
    """``membership.created`` — metadata exactly ``{"role": ...}`` (the granted
    role), target the new ``mem_`` record id (decision 7; appended **after**
    the successful write)."""
    return AuditEvent(
        id=audit_id,
        organization_id=organization_id,
        actor_type="user",
        actor_id=actor_user_id,
        action="membership.created",
        target_type="membership",
        target_id=str(membership_id),
        metadata={"role": role.value},
        created_at=now,
    )


def build_membership_removed_audit(
    *,
    audit_id: AuditEventId,
    organization_id: OrganizationId,
    actor_user_id: UserId,
    membership_id: MembershipId,
    role: MembershipRole,
    now: datetime,
) -> AuditEvent:
    """``membership.removed`` — metadata exactly ``{"role": ...}`` (the role
    **at removal**), target the removed ``mem_`` id (a plain string, no FK;
    decision 7; appended after the delete commits)."""
    return AuditEvent(
        id=audit_id,
        organization_id=organization_id,
        actor_type="user",
        actor_id=actor_user_id,
        action="membership.removed",
        target_type="membership",
        target_id=str(membership_id),
        metadata={"role": role.value},
        created_at=now,
    )


def build_denial_audit(
    *,
    audit_id: AuditEventId,
    organization_id: OrganizationId,
    actor_user_id: UserId,
    reason: AccessOutcome,
    operation: str,
    now: datetime,
) -> AuditEvent:
    """``authorization.denied`` — metadata exactly ``{"reason", "operation"}``
    (decision 4): the :class:`AccessOutcome` denial string and the manifest
    ``operation_id``. No target (the model pins denial as a broad action),
    no email, no ``sub``, no token, no caller role beyond what the reason
    implies. Raises ``ValueError`` for a non-denial reason — ``granted``
    accesses are never audited here."""
    if reason not in DENIAL_REASONS:
        raise ValueError(f"not an auditable denial reason: {reason!r}")
    return AuditEvent(
        id=audit_id,
        organization_id=organization_id,
        actor_type="user",
        actor_id=actor_user_id,
        action="authorization.denied",
        metadata={"reason": reason.value, "operation": operation},
        created_at=now,
    )


def audit_denial(
    storage: Storage,
    actor_user_id: UserId,
    organization_id: OrganizationId,
    reason: AccessOutcome,
    operation: str,
    *,
    now: datetime | None = None,
) -> None:
    """Append one ``authorization.denied`` through ``append_audit_event``.

    Called **only when the organization row exists** (the audit→organization
    FK; decision 4 documents unknown-organization denials as structurally
    unauditable). ``now`` defaults to one clock read; the ``aud_`` id is
    minted here — the only minting in this module, and still outside storage.
    Append failures propagate (fail-closed: a denial that cannot be audited
    must surface as a 500, never a silent 403).
    """
    event = build_denial_audit(
        audit_id=new_audit_event_id(),
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        reason=reason,
        operation=operation,
        now=now if now is not None else utc_now(),
    )
    storage.append_audit_event(event)


__all__ = [
    "DENIAL_REASONS",
    "ROLE_RANK",
    "AccessDecision",
    "AccessOutcome",
    "MemberNotFoundError",
    "MembershipConflictError",
    "OrganizationSlugConflictError",
    "OrganizationTypeNotSelectableError",
    "OwnerMembershipImmutableError",
    "OwnerRoleNotAssignableError",
    "TargetUserNotFoundError",
    "audit_denial",
    "build_denial_audit",
    "build_membership_created_audit",
    "build_membership_removed_audit",
    "build_organization_created_audit",
    "classify_access",
    "require_assignable_member_role",
    "require_selectable_organization_type",
]
