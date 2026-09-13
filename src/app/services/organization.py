"""Organization creation and listing rules (Phase 04 task 4).

Mutation rules for ``POST /v1/organizations`` and the pass-through list for
``GET /v1/organizations`` (breakdown decisions 3/6/7), following the Phase 03
``identity.py`` pattern: plain functions with injected ``storage`` and
injectable ``now``/``ids`` — the class-based scaffold from the abandoned
prior session was replaced wholesale (decision 0). HTTP translation of the
domain errors raised here happens in :mod:`app.api.organizations`.

Creation is exactly one ``provision_organization`` batch (decision 2): the
new **active** organization, the creator's **owner** ``active`` membership,
and the two creation audits ``organization.created`` / ``membership.created``
share one clock read and one ID set (``{"type": ...}`` / ``{"role": "owner"}``
metadata per decision 7). There is deliberately no sequential
create-then-grant path: a crash between those writes would burn the slug
forever with no repair route.

Slug conflicts are plain 409-level conflicts, never converges (unlike
``provision_user``'s race): :class:`OrganizationSlugConflictError` translates
the adapter's ``kind="organization_slug"`` and the batch is already fully
rolled back by storage, so the failed attempt consumes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.models.audit_event import AuditEvent
from app.models.enums import (
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
)
from app.models.ids import AuditEventId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization, OrganizationName, OrganizationSlug
from app.models.pagination import Page, PageParams
from app.models.timestamps import utc_now
from app.services.authorization import (
    OrganizationSlugConflictError,
    build_membership_created_audit,
    build_organization_created_audit,
    require_selectable_organization_type,
)
from app.services.idgen import new_audit_event_id, new_membership_id, new_organization_id
from app.storage.contract import DuplicateEntityError, DuplicateEntityKind, Storage


@dataclass(frozen=True)
class OrganizationCreationIds:
    """Every record ID one creation batch needs, minted together.

    A pure data bag so :func:`build_organization_batch` stays a total,
    deterministic function of ``(creator, name, slug, type, now, ids)``;
    production callers get one fresh instance per request.
    """

    organization_id: OrganizationId
    membership_id: MembershipId
    organization_created_audit_id: AuditEventId
    membership_created_audit_id: AuditEventId


def new_organization_creation_ids() -> OrganizationCreationIds:
    """Mint one complete set of prefix-valid IDs for a single creation batch."""
    return OrganizationCreationIds(
        organization_id=new_organization_id(),
        membership_id=new_membership_id(),
        organization_created_audit_id=new_audit_event_id(),
        membership_created_audit_id=new_audit_event_id(),
    )


@dataclass(frozen=True)
class OrganizationBatch:
    """The organization + owner membership + two audits, fully formed.

    Field names match ``Storage.provision_organization``'s keyword-only
    signature so the batch hands off without reshaping.
    """

    organization: Organization
    membership: Membership
    audit_events: tuple[AuditEvent, ...]


def build_organization_batch(
    *,
    creator_user_id: UserId,
    name: OrganizationName,
    slug: OrganizationSlug,
    organization_type: OrganizationType,
    now: datetime,
    ids: OrganizationCreationIds,
) -> OrganizationBatch:
    """Build the atomic creation batch — **pure** (no clock, no entropy).

    The creator always receives the ``owner`` role (decision 3: the only
    way to become an owner is to create the organization); the audits share
    the single injected ``now`` and are ordered by spec §6 creation order
    (organization, then membership).
    """
    organization = Organization(
        id=ids.organization_id,
        name=name,
        slug=slug,
        type=organization_type,
        status=OrganizationStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    membership = Membership(
        id=ids.membership_id,
        organization_id=ids.organization_id,
        user_id=creator_user_id,
        role=MembershipRole.OWNER,
        status=MembershipStatus.ACTIVE,
        created_at=now,
    )
    audit_events = (
        build_organization_created_audit(
            audit_id=ids.organization_created_audit_id,
            organization_id=ids.organization_id,
            actor_user_id=creator_user_id,
            organization_type=organization_type,
            now=now,
        ),
        build_membership_created_audit(
            audit_id=ids.membership_created_audit_id,
            organization_id=ids.organization_id,
            actor_user_id=creator_user_id,
            membership_id=ids.membership_id,
            role=MembershipRole.OWNER,
            now=now,
        ),
    )
    return OrganizationBatch(
        organization=organization,
        membership=membership,
        audit_events=audit_events,
    )


def create_organization(
    storage: Storage,
    creator_user_id: UserId,
    name: OrganizationName,
    slug: OrganizationSlug,
    organization_type: OrganizationType,
    *,
    now: datetime | None = None,
    ids: OrganizationCreationIds | None = None,
) -> Organization:
    """Create one organization with its owner membership, atomically.

    Order (decision 6): the type guard runs **before** any storage touch, so
    a non-selectable type provably writes zero rows. Exactly one clock read
    and one ID mint per request (both injectable for deterministic tests).

    Raises:
        OrganizationTypeNotSelectableError: ``personal``/``internal`` types
            (router → 400 validation_error; zero writes).
        OrganizationSlugConflictError: the slug is taken (router → 409
            conflict; the batch is fully rolled back by storage).
    """
    require_selectable_organization_type(organization_type)
    batch = build_organization_batch(
        creator_user_id=creator_user_id,
        name=name,
        slug=slug,
        organization_type=organization_type,
        now=now if now is not None else utc_now(),
        ids=ids if ids is not None else new_organization_creation_ids(),
    )
    try:
        stored = storage.provision_organization(
            organization=batch.organization,
            membership=batch.membership,
            audit_events=batch.audit_events,
        )
    except DuplicateEntityError as exc:
        if exc.kind is DuplicateEntityKind.ORGANIZATION_SLUG:
            raise OrganizationSlugConflictError() from exc
        raise
    return stored.organization


def list_organizations(storage: Storage, user_id: UserId, page: PageParams) -> Page[Organization]:
    """Pass-through of the contract's active-membership-scoped organization page.

    The scoping is storage-contract truth (``list_user_organizations`` returns
    only organizations where the user holds an **active** membership, ordered
    by ``(created_at, id)``); this function adds no filter and invents no
    policy — the router projects the domain page onto the frozen response
    schema verbatim (decision 8).
    """
    return storage.list_user_organizations(user_id, page)


__all__ = [
    "OrganizationBatch",
    "OrganizationCreationIds",
    "build_organization_batch",
    "create_organization",
    "list_organizations",
    "new_organization_creation_ids",
]
