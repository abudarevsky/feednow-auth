"""Identity resolution and safe provisioning (Phase 03 task 4).

Implements spec §5/§6/§7/§10 as the provider-facing half of the service
layer: verified :class:`~app.auth.cognito.CognitoClaims` become an internal
:class:`~app.models.user.User` plus a resolved
:class:`~app.models.authorization_context.AuthorizationContext`, with Cognito
fields never treated as product identity (AGENTS.md).

Flow (spec §6, breakdown decisions 4—9):

1. :func:`resolve_or_provision` converts the claims into the identity tuple
   ``provider=cognito``, ``provider_subject=sub``, ``provider_tenant=None``
   (decision 4 — cognito carries no tenant dimension; the storage contract
   normalizes ``None`` internally) and performs the §6 lookup.
2. A lookup miss builds one fully formed batch with
   :func:`build_provisioning_batch` — pure in ``(claims, now, ids)`` so every
   value is deterministic under test — and hands it to the single atomic
   ``provision_user`` call (User ``active``, ExternalIdentity, personal
   ``active`` organization, ``owner`` ``active`` membership, and the three
   creation audits ``user.created`` / ``organization.created`` /
   ``membership.created``).
3. A :class:`~app.storage.contract.DuplicateExternalIdentityError` is spec §6's
   concurrent-first-login race *or* a genuine email collision. The service
   re-reads the identity tuple: found → converge on the winner's user; absent
   → :class:`ProvisioningConflictError` (409-mapped in task 5). **Convergence
   happens only via that re-read** — ``error.existing_user_id`` is resolved by
   the adapter through an email fallback and is therefore a *stranger's* id in
   the email-collision case; it serves only as a post-convergence cross-check
   (decision 7).
4. After any resolution, a non-``active`` user raises :class:`DisabledUserError`
   with no storage mutation (reads only; provisioning already happened or was
   skipped).
5. :func:`build_user_context` derives the §10 human context (decision 9):
   default = the **earliest active** organization
   (``list_user_organizations(user_id, PageParams(limit=1))``; storage pins
   ``(created_at, id)`` ascending, so page 1 item 1 is deterministic) with
   ``roles = [get_membership(org, user).role]`` and ``scopes = []``; an
   explicit ``organization_id`` (Phase 04's org-selection seam) requires the
   membership **and** the organization to be active, else
   :class:`NoActiveOrganizationError` (403). Zero active organizations raises
   the same error.

Clock and entropy (decision 5): exactly **one** :func:`~app.models.timestamps.utc_now`
read and one :func:`new_provisioning_ids` mint per provisioning request
(both injectable for tests), shared by all five entities and the three audit
events; storage mints nothing.

Audit metadata is JSON-safe and secret-free (decision 8): no ``sub``, no
token, no email — only ``{"provider": "cognito"}``, ``{"type": "personal"}``,
``{"role": "owner"}``. Self-provisioning actors are
``actor_type="user"``/``actor_id=`` the new ``usr_`` inside the same
``provision_user`` transaction, so the audit→organization FK is satisfied.

These three service errors are domain outcomes, not storage leaks: HTTP
mapping (401/403/409/503) is task 5's job in ``app/api``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.auth.cognito import CognitoClaims
from app.models.audit_event import AuditEvent
from app.models.authorization_context import AuthorizationContext
from app.models.enums import (
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity
from app.models.ids import (
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    UserId,
)
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.pagination import PageParams
from app.models.timestamps import utc_now
from app.models.user import User
from app.services.idgen import (
    new_audit_event_id,
    new_external_identity_id,
    new_membership_id,
    new_organization_id,
    new_user_id,
)
from app.storage.contract import (
    DuplicateExternalIdentityError,
    EntityNotFoundError,
    Storage,
)


class DisabledUserError(Exception):
    """The resolved user is authenticated but not ``active`` (task 5 → 403).

    The message is fixed and carries no user, email, or provider material;
    account state must not leak through error text.
    """

    def __init__(self, message: str = "user account is disabled") -> None:
        super().__init__(message)


class NoActiveOrganizationError(Exception):
    """No usable tenancy context for the user (task 5 → 403).

    Covers both §10 branches of :func:`build_user_context`: zero active
    organizations under the earliest-active rule, and an explicit
    ``organization_id`` whose membership or organization is missing or
    inactive. The default reason is fixed and organization-free.
    """

    def __init__(self, message: str = "no active organization for this user") -> None:
        super().__init__(message)


class ProvisioningConflictError(Exception):
    """Provisioning raced a *different* account (task 5 → 409).

    The identity-tuple re-read after a :class:`~app.storage.contract.
    DuplicateExternalIdentityError` found no winner, so the batch conflicted
    on the email constraint without sharing the identity — a genuine email
    collision, not spec §6's same-user race. Fixed safe message (no email).
    """

    def __init__(
        self,
        message: str = "account provisioning conflicts with an existing user",
    ) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class ProvisioningIds:
    """Every record ID a provisioning batch needs, minted together (decision 5).

    A pure data bag so :func:`build_provisioning_batch` stays a total,
    deterministic function of ``(claims, now, ids)``; production callers get
    one fresh instance per request from :func:`new_provisioning_ids`.
    """

    user_id: UserId
    organization_id: OrganizationId
    external_identity_id: ExternalIdentityId
    membership_id: MembershipId
    user_created_audit_id: AuditEventId
    organization_created_audit_id: AuditEventId
    membership_created_audit_id: AuditEventId


def new_provisioning_ids() -> ProvisioningIds:
    """Mint one complete set of prefix-valid IDs for a single provisioning batch."""
    return ProvisioningIds(
        user_id=new_user_id(),
        organization_id=new_organization_id(),
        external_identity_id=new_external_identity_id(),
        membership_id=new_membership_id(),
        user_created_audit_id=new_audit_event_id(),
        organization_created_audit_id=new_audit_event_id(),
        membership_created_audit_id=new_audit_event_id(),
    )


@dataclass(frozen=True)
class ProvisioningBatch:
    """The five entities + three audits for one first-login, fully formed.

    Field names match ``Storage.provision_user``'s keyword-only signature so
    the batch hands off without reshaping; storage mints nothing, so every
    member is complete before the call.
    """

    user: User
    identity: ExternalIdentity
    organization: Organization
    membership: Membership
    audit_events: tuple[AuditEvent, ...]


@dataclass(frozen=True)
class ResolvedIdentity:
    """The §6/§10 outcome of one authenticated request: user + context."""

    user: User
    context: AuthorizationContext


def _lookup_external_identity(storage: Storage, claims: CognitoClaims) -> User:
    """The §6 identity-tuple read — one call site for lookup and re-read.

    Cognito carries no tenant dimension (decision 4): ``provider_tenant`` is
    pinned to ``None`` here and at write time, so lookups and batches can
    never drift apart.
    """
    return storage.get_user_by_external_identity(
        provider=IdentityProvider.COGNITO,
        provider_subject=claims.sub,
        provider_tenant=None,
    )


def build_provisioning_batch(
    claims: CognitoClaims,
    now: datetime,
    ids: ProvisioningIds,
) -> ProvisioningBatch:
    """Build the atomic first-login batch — **pure** (no clock, no entropy).

    Values are pinned by breakdown decisions 5—8: display name is the
    ``username`` claim when non-empty else ``sub`` (the verifier normalizes
    empty/absent to ``None``); the default workspace is
    ``"{display_name}'s Workspace"`` with the unique-by-construction slug
    ``personal-{user_id}`` (decision 6 — never derived from email); all five
    entities and three audits share the single injected ``now``; audit
    metadata is exactly ``{"provider": "cognito"}`` / ``{"type": "personal"}``
    / ``{"role": "owner"}`` with targets and self-provisioning actor pinned
    per decision 8; event order is the spec §6 creation order.
    """
    display_name = claims.username or claims.sub
    user = User(
        id=ids.user_id,
        display_name=display_name,
        email=claims.email,
        status=UserStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    identity = ExternalIdentity(
        id=ids.external_identity_id,
        user_id=ids.user_id,
        provider=IdentityProvider.COGNITO,
        provider_subject=claims.sub,
        provider_tenant=None,
        created_at=now,
    )
    organization = Organization(
        id=ids.organization_id,
        name=f"{display_name}'s Workspace",
        slug=f"personal-{ids.user_id}",
        type=OrganizationType.PERSONAL,
        status=OrganizationStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    membership = Membership(
        id=ids.membership_id,
        organization_id=ids.organization_id,
        user_id=ids.user_id,
        role=MembershipRole.OWNER,
        status=MembershipStatus.ACTIVE,
        created_at=now,
    )
    audit_events = (
        AuditEvent(
            id=ids.user_created_audit_id,
            organization_id=ids.organization_id,
            actor_type="user",
            actor_id=ids.user_id,
            action="user.created",
            target_type="user",
            target_id=str(ids.user_id),
            metadata={"provider": "cognito"},
            created_at=now,
        ),
        AuditEvent(
            id=ids.organization_created_audit_id,
            organization_id=ids.organization_id,
            actor_type="user",
            actor_id=ids.user_id,
            action="organization.created",
            target_type="organization",
            target_id=str(ids.organization_id),
            metadata={"type": "personal"},
            created_at=now,
        ),
        AuditEvent(
            id=ids.membership_created_audit_id,
            organization_id=ids.organization_id,
            actor_type="user",
            actor_id=ids.user_id,
            action="membership.created",
            target_type="membership",
            target_id=str(ids.membership_id),
            metadata={"role": "owner"},
            created_at=now,
        ),
    )
    return ProvisioningBatch(
        user=user,
        identity=identity,
        organization=organization,
        membership=membership,
        audit_events=audit_events,
    )


def resolve_or_provision(
    storage: Storage,
    claims: CognitoClaims,
    *,
    now: datetime | None = None,
    ids: ProvisioningIds | None = None,
) -> ResolvedIdentity:
    """Resolve ``claims`` to an active user + §10 context, provisioning on first sight.

    Exactly one identity read on the hit path; at most one ``provision_user``
    call on the miss path (never a second one after a race — convergence is a
    re-read). ``now``/``ids`` are injectable for deterministic tests and
    default to one clock read and one ID mint per request (decision 5).

    Raises:
        DisabledUserError: the resolved user is not ``active`` (no mutation).
        ProvisioningConflictError: the race re-read found no identity — a
            genuine email collision with a different account.
        NoActiveOrganizationError: the user has no usable organization
            (unreachable right after provisioning; reachable once Phase 04
            can disable orgs).
    """
    try:
        user = _lookup_external_identity(storage, claims)
    except EntityNotFoundError:
        user = _provision_or_converge(storage, claims, now=now, ids=ids)
    if user.status is not UserStatus.ACTIVE:
        raise DisabledUserError()
    context = build_user_context(storage, user)
    return ResolvedIdentity(user=user, context=context)


def _provision_or_converge(
    storage: Storage,
    claims: CognitoClaims,
    *,
    now: datetime | None,
    ids: ProvisioningIds | None,
) -> User:
    """Run the single atomic batch, converging on the race winner if there was one.

    Decision 7's rule is absolute: convergence is driven **only** by the
    identity-tuple re-read (same ``sub`` → the winner's user). The adapter's
    ``existing_user_id`` is email-fallback-resolved and may name a stranger,
    so after a successful re-read it is consulted only to cross-check the
    winner — a disagreement means storage told us two different users and is
    refused as a conflict rather than silently trusted.
    """
    batch = build_provisioning_batch(
        claims,
        now if now is not None else utc_now(),
        ids if ids is not None else new_provisioning_ids(),
    )
    try:
        stored = storage.provision_user(
            user=batch.user,
            identity=batch.identity,
            organization=batch.organization,
            membership=batch.membership,
            audit_events=batch.audit_events,
        )
        return stored.user
    except DuplicateExternalIdentityError as error:
        try:
            winner = _lookup_external_identity(storage, claims)
        except EntityNotFoundError:
            raise ProvisioningConflictError() from error
        if error.existing_user_id is not None and error.existing_user_id != winner.id:
            raise ProvisioningConflictError() from error
        return winner


def build_user_context(
    storage: Storage,
    user: User,
    organization_id: OrganizationId | None = None,
) -> AuthorizationContext:
    """Derive the §10 human AuthorizationContext (decision 9, both branches).

    Default branch: the **earliest active** organization —
    ``list_user_organizations(user_id, PageParams(limit=1))`` returns only
    active memberships ordered by ``(created_at, id)``, so item 1 is stable.
    Explicit branch (Phase 04's seam, semantics pinned here): the given
    ``organization_id`` must resolve to an **active** organization in which
    the user holds an **active** membership, else
    :class:`NoActiveOrganizationError` — a disabled or nonexistent
    organization is refused identically to a missing membership (403, no
    existence oracle). Both branches then read the role via
    ``get_membership`` and build ``roles=[role]``, ``scopes=[]``,
    ``actor_type="user"``, ``actor_id=user.id``.
    """
    if organization_id is None:
        page = storage.list_user_organizations(user.id, PageParams(limit=1))
        if not page.items:
            raise NoActiveOrganizationError()
        organization = page.items[0]
    else:
        try:
            organization = storage.get_organization(organization_id)
        except EntityNotFoundError as exc:
            raise NoActiveOrganizationError() from exc
        if organization.status is not OrganizationStatus.ACTIVE:
            raise NoActiveOrganizationError()
    try:
        membership = storage.get_membership(organization_id=organization.id, user_id=user.id)
    except EntityNotFoundError as exc:
        raise NoActiveOrganizationError() from exc
    if membership.status is not MembershipStatus.ACTIVE:
        raise NoActiveOrganizationError()
    return AuthorizationContext(
        actor_type="user",
        actor_id=user.id,
        organization_id=organization.id,
        roles=[membership.role],
        scopes=[],
    )


__all__ = [
    "DisabledUserError",
    "NoActiveOrganizationError",
    "ProvisioningBatch",
    "ProvisioningConflictError",
    "ProvisioningIds",
    "ResolvedIdentity",
    "build_provisioning_batch",
    "build_user_context",
    "new_provisioning_ids",
    "resolve_or_provision",
]
