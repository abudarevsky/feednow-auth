"""Membership add/remove rules (Phase 04 task 5).

Mutation rules for ``POST``/``DELETE .../members`` (breakdown decisions
3/6/7), functions-with-injected-storage like :mod:`app.services.organization`
(the abandoned class scaffold was replaced wholesale, decision 0). The
caller's right to mutate (rank >= admin) is enforced by the shared access
dependency *before* these functions run; what is enforced here is the role
policy of decision 3: ``owner`` is not grantable (guard) and not removable
(immutability check), and the (organization, user) pair stays unique through
the storage constraint.

Audit ordering (decision 7): ``membership.created``/``membership.removed``
are appended **after** the successful write — a mutation that failed must
never audit as success. The accepted, documented limitation: a committed
mutation whose audit append fails returns 500 with the mutation persisted
(SQLite has no cross-call transaction; the compound batch is the only
atomic unit, and membership add/remove has no invariant that would need
one).

Error translation (decision 6): the adapter's ``ReferenceNotFoundError`` on
an unknown target ``usr_`` becomes :class:`TargetUserNotFoundError` (404 —
the organization FK is already proven by the dependency, so the only parent
that can be missing is the user), and ``kind="membership"`` duplicates
become :class:`MembershipConflictError` (409). A delete that races another
removal (the contract pins delete as non-idempotent) also surfaces as
:class:`MemberNotFoundError` (404): the pair is simply gone.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.models.enums import MembershipRole, MembershipStatus
from app.models.ids import AuditEventId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.pagination import Page, PageParams
from app.models.timestamps import utc_now
from app.services.authorization import (
    MemberNotFoundError,
    MembershipConflictError,
    OwnerMembershipImmutableError,
    TargetUserNotFoundError,
    build_membership_created_audit,
    build_membership_removed_audit,
    require_assignable_member_role,
)
from app.services.idgen import new_audit_event_id, new_membership_id
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    EntityNotFoundError,
    ReferenceNotFoundError,
    Storage,
)


@dataclass(frozen=True)
class MemberGrantIds:
    """Record IDs one add-member operation needs (membership + its audit)."""

    membership_id: MembershipId
    audit_id: AuditEventId


def new_member_grant_ids() -> MemberGrantIds:
    """Mint the membership record id and its creation-audit id together."""
    return MemberGrantIds(
        membership_id=new_membership_id(),
        audit_id=new_audit_event_id(),
    )


def add_member(
    storage: Storage,
    actor_user_id: UserId,
    organization_id: OrganizationId,
    user_id: UserId,
    role: MembershipRole,
    *,
    now: datetime | None = None,
    ids: MemberGrantIds | None = None,
) -> Membership:
    """Grant ``user_id`` a role in ``organization_id`` and audit the grant.

    Order: owner-role guard (zero writes when refused) → single
    ``create_membership`` → ``membership.created`` audit **after** the
    successful write (decision 7). ``now``/``ids`` are injectable;
    production reads the clock once per grant.

    Raises:
        OwnerRoleNotAssignableError: ``role=owner`` (router → 400).
        TargetUserNotFoundError: the target ``usr_`` does not exist
            (router → 404).
        MembershipConflictError: the (organization, user) pair already has a
            membership, any status (router → 409).
    """
    require_assignable_member_role(role)
    minted = ids if ids is not None else new_member_grant_ids()
    timestamp = now if now is not None else utc_now()
    membership = Membership(
        id=minted.membership_id,
        organization_id=organization_id,
        user_id=user_id,
        role=role,
        status=MembershipStatus.ACTIVE,
        created_at=timestamp,
    )
    try:
        stored = storage.create_membership(membership)
    except ReferenceNotFoundError as exc:
        raise TargetUserNotFoundError() from exc
    except DuplicateEntityError as exc:
        if exc.kind is DuplicateEntityKind.MEMBERSHIP:
            raise MembershipConflictError() from exc
        raise
    storage.append_audit_event(
        build_membership_created_audit(
            audit_id=minted.audit_id,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            membership_id=stored.id,
            role=stored.role,
            now=timestamp,
        )
    )
    return stored


def remove_member(
    storage: Storage,
    actor_user_id: UserId,
    organization_id: OrganizationId,
    user_id: UserId,
    *,
    now: datetime | None = None,
) -> None:
    """Physically remove a membership, preserving the owner invariant.

    ``get_membership`` first (miss → 404), then the owner immutability guard
    (decision 3: nobody — including owners — may delete an owner membership
    through this API; there is deliberately no update path either), then
    ``delete_membership``, then the ``membership.removed`` audit **after**
    the delete commits (decision 7) carrying the role *at removal*.

    Raises:
        MemberNotFoundError: no such membership (including a delete that
            raced a concurrent removal) — router → 404.
        OwnerMembershipImmutableError: target holds ``owner`` — router → 409.
    """
    try:
        membership = storage.get_membership(organization_id=organization_id, user_id=user_id)
    except EntityNotFoundError as exc:
        raise MemberNotFoundError() from exc
    if membership.role is MembershipRole.OWNER:
        raise OwnerMembershipImmutableError()
    try:
        storage.delete_membership(organization_id=organization_id, user_id=user_id)
    except EntityNotFoundError as exc:  # raced a concurrent removal
        raise MemberNotFoundError() from exc
    storage.append_audit_event(
        build_membership_removed_audit(
            audit_id=new_audit_event_id(),
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            membership_id=membership.id,
            role=membership.role,
            now=now if now is not None else utc_now(),
        )
    )


def list_members(
    storage: Storage, organization_id: OrganizationId, page: PageParams
) -> Page[Membership]:
    """Pass-through of the contract's org-scoped membership page.

    The contract returns **all statuses** (``disabled`` is suspension and
    stays visible; ``MemberResponse`` carries ``status`` — decision 8, no
    filter invented here).
    """
    return storage.list_memberships(organization_id, page)


__all__ = [
    "MemberGrantIds",
    "add_member",
    "list_members",
    "new_member_grant_ids",
    "remove_member",
]
